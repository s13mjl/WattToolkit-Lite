//! DNS resolution, mirroring the original DnsAnalysisService / DomainResolver.
//!
//! Supports DNS-over-HTTPS (DoH) and plain local/UDP DNS, with a switch that
//! picks the strategy based on proxy mode (mirrors DnsAnalysisServiceSwitchImpl).

use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;
#[cfg(windows)]
use std::os::windows::io::AsRawSocket;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Read the DNS servers currently configured on every network adapter
/// (HKLM\...\Tcpip\Parameters\Interfaces\<guid>\{NameServer, DhcpNameServer}).
pub fn system_dns_servers() -> Vec<IpAddr> {
    use winreg::enums::HKEY_LOCAL_MACHINE;
    use winreg::RegKey;
    let mut out: Vec<IpAddr> = Vec::new();
    let ifaces = match RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey(r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces")
    {
        Ok(k) => k,
        Err(_) => return out,
    };
    for name in ifaces.enum_keys().filter_map(|r| r.ok()) {
        if let Ok(sub) = ifaces.open_subkey(&name) {
            for val in ["NameServer", "DhcpNameServer"] {
                if let Ok(s) = sub.get_value::<String, _>(val) {
                    for part in s.split(|c: char| c == ',' || c == ' ' || c == ';') {
                        if let Ok(ip) = part.trim().parse::<IpAddr>() {
                            if !out.contains(&ip) {
                                out.push(ip);
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// Public DNS constants (copied from original IDnsAnalysisService.Constants).
pub mod dns_const {
    pub const DNS_ALI_DOH: &str = "https://dns.alidns.com/resolve";
    pub const DNS_ALI_DOH2: &str = "https://223.6.6.6/resolve";
    pub const DNS_ALI_DOH3: &str = "https://223.5.5.5/resolve";

    pub const DNSPOD_DOH: &str = "https://1.12.12.12/resolve";
    pub const DNSPOD_DOH2: &str = "https://doh.pub/resolve";
    pub const DNSPOD_DOH3: &str = "https://120.53.53.53/resolve";

    pub const GOOGLE_DOH: &str = "https://dns.google/resolve";
    pub const CLOUDFLARE_DOH: &str = "https://cloudflare-dns.com/resolve";
    pub const DOH_360: &str = "https://doh.360.cn/resolve";
    pub const TUNA_DOH: &str = "https://101.6.6.6:8443/resolve";

    pub const PRIMARY_ALI: &str = "223.5.5.5";
    pub const SECONDARY_ALI: &str = "223.6.6.6";
    pub const PRIMARY_DNSPOD: &str = "119.29.29.29";
    pub const SECONDARY_DNSPOD: &str = "182.254.116.116";
    pub const PRIMARY_114: &str = "114.114.114.114";
    pub const SECONDARY_114: &str = "114.114.115.115";
    pub const PRIMARY_GOOGLE: &str = "8.8.8.8";
    pub const SECONDARY_GOOGLE: &str = "8.8.4.4";
    pub const PRIMARY_CLOUDFLARE: &str = "1.1.1.1";
    pub const SECONDARY_CLOUDFLARE: &str = "1.0.0.1";
    pub const PRIMARY_BAIDU: &str = "180.76.76.76";

    /// IPv6-only DNS server and the test record that prove a dual-stack network
    /// is usable (original `PrimaryDNS_IPV6_Ali`, `IPV6_TESTDOMAIN` and
    /// `IPV6_TESTDOMAIN_SUCCESS`, where the success value *is* the server
    /// address): a query sent to `PRIMARY_IPV6_ALI` for the AAAA record of
    /// `IPV6_TEST_DOMAIN` only arrives and only answers like that when IPv6
    /// actually works.
    pub const PRIMARY_IPV6_ALI: &str = "2400:3200::1";
    pub const IPV6_TEST_DOMAIN: &str = "ipv6.rmbgame.net";
}

/// DoH address choices offered in the proxy settings.
pub fn doh_addresses() -> Vec<&'static str> {
    vec![
        dns_const::DNSPOD_DOH,
        dns_const::DNSPOD_DOH2,
        dns_const::DNSPOD_DOH3,
        dns_const::DNS_ALI_DOH,
        dns_const::DNS_ALI_DOH2,
        dns_const::DNS_ALI_DOH3,
        dns_const::GOOGLE_DOH,
        dns_const::CLOUDFLARE_DOH,
        dns_const::DOH_360,
        dns_const::TUNA_DOH,
    ]
}

/// Plain DNS server choices (mirrors ProxySettingsWindowViewModel.ProxyDNSs).
pub fn dns_servers() -> Vec<&'static str> {
    vec![
        "System Default",
        dns_const::PRIMARY_114,
        dns_const::PRIMARY_ALI,
        dns_const::PRIMARY_DNSPOD,
        dns_const::PRIMARY_BAIDU,
        dns_const::PRIMARY_GOOGLE,
        dns_const::PRIMARY_CLOUDFLARE,
    ]
}

/// Upper bound for how long an answer may stay fresh, mirroring the original
/// DoH cache (`DnsDohAnalysisService.TTL = TimeSpan.FromMinutes(9.9)`): the
/// response TTL is honoured, but never beyond this cap, so a flapping or
/// compromised resolver cannot pin a poisoned address for an unbounded time.
const CACHE_TTL_CAP: Duration = Duration::from_secs(594);

/// Hard bound on live entries. Nothing evicts on its own (there is no
/// background task), so a long-running proxy would otherwise grow this map
/// until the process exits; once the bound is hit, expired entries are dropped.
const CACHE_MAX_ENTRIES: usize = 1024;

/// Which record type a query asks for. The original picks between the two with
/// its `isIPv6` flag and keys its DoH cache by `host:queryType`.
#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub enum QType {
    A,
    Aaaa,
}

impl QType {
    /// On-the-wire TYPE value (A = 1, AAAA = 28).
    fn code(self) -> u16 {
        match self {
            QType::A => 1,
            QType::Aaaa => 28,
        }
    }

    /// The `type=` value of the DoH JSON API.
    fn url_name(self) -> &'static str {
        match self {
            QType::A => "A",
            QType::Aaaa => "AAAA",
        }
    }
}

/// Which resolver produced an answer. Part of the cache key, so an answer from
/// one server is never served to a lookup that asked another one - the original
/// keys its cache by `(DoH address, host:query type)` for the same reason.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
enum CacheSource {
    /// Plain UDP/DNS (the `None` case is the system resolver).
    Udp(Option<IpAddr>),
    /// DNS-over-HTTPS endpoint URL.
    Doh(String),
}

type CacheKey = (String, CacheSource, QType);
type CacheEntry = (Vec<IpAddr>, Instant, Duration);

static DNS_CACHE: OnceLock<Mutex<HashMap<CacheKey, CacheEntry>>> = OnceLock::new();

fn cache_table() -> &'static Mutex<HashMap<CacheKey, CacheEntry>> {
    DNS_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// `min_ttl_secs` is the smallest TTL the response carried; `0` means the
/// resolver did not report one (the system resolver never does), which falls
/// back to the cap - the same effective lifetime the original gives every DoH
/// answer.
fn cache_ttl(min_ttl_secs: u32) -> Duration {
    if min_ttl_secs == 0 {
        CACHE_TTL_CAP
    } else {
        Duration::from_secs(u64::from(min_ttl_secs)).min(CACHE_TTL_CAP)
    }
}

/// The cached answer while it is still fresh; expired entries are dropped on
/// the way out.
fn cache_get(key: &CacheKey) -> Option<Vec<IpAddr>> {
    let mut table = cache_table().lock().unwrap();
    match table.get(key) {
        Some((ips, stored_at, ttl)) if stored_at.elapsed() < *ttl => Some(ips.clone()),
        Some(_) => {
            table.remove(key);
            None
        }
        None => None,
    }
}

/// Store a successful answer. An empty answer is deliberately not cached: a
/// resolver that is momentarily unreachable must not become a multi-minute
/// blackhole, which would be a regression the original never had (its cache is
/// written but never consulted before querying).
fn cache_put(key: CacheKey, ips: &[IpAddr], ttl: Duration) {
    if ips.is_empty() {
        return;
    }
    let mut table = cache_table().lock().unwrap();
    if table.len() >= CACHE_MAX_ENTRIES {
        let expired: Vec<CacheKey> = table
            .iter()
            .filter(|(_, (_, stored_at, ttl))| stored_at.elapsed() >= *ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            table.remove(&k);
        }
    }
    table.insert(key, (ips.to_vec(), Instant::now(), ttl));
}

/// Resolve a hostname to the addresses acceleration may dial (IPv4, plus IPv6
/// when the dual-stack probe says the network can carry it).
///
/// `use_doh` mirrors the original `UseDoh` switch, in that order too: DoH first,
/// the plain-DNS legs only behind it. An unset `doh_address` falls back to the
/// original's own default (`DnsDohAnalysisService.DefaultDohAddres =
/// Dnspod_DohAddres2`), not to plain DNS.
///
/// Deliberate deviation from the original: with `UseDoh` on, the original
/// resolves through DoH alone (`DnsAnalysisServiceSwitchImpl` ignores
/// `dnsServers`), so "every DoH endpoint blocked" yields no address at all and
/// acceleration is dead rather than degraded. Here the remaining known DoH
/// endpoints are raced first and plain DNS is the last resort - and that
/// downgrade is always warn logged, so it can never be silent.
///
/// Endpoints are probed against the real hostname (the original resolves the
/// actual host too); probing a fixed test domain instead would misjudge the
/// whole DoH set whenever that one name happens to fail. The dual-stack probe
/// below is the deliberate exception - it asks the original's own test domain,
/// because that is exactly how the original decides `isIPv6`.
pub async fn resolve_a(host: &str, dns: &str, use_doh: bool, doh_address: &str) -> Vec<IpAddr> {
    let configured: Option<IpAddr> = dns
        .trim()
        .parse::<IpAddr>()
        .ok()
        .filter(|_| dns.trim() != "System Default");
    // One dual-stack probe gates every query, IPv6 first (the original decides
    // the same way through `DomainResolver.isIpv6`, filled once by
    // `CheckIpv6SupportAsync`).
    let v6 = is_support_ipv6().await;
    let qtype = if v6 { QType::Aaaa } else { QType::A };
    if use_doh {
        let doh = if doh_address.trim().is_empty() {
            dns_const::DNSPOD_DOH2
        } else {
            doh_address
        };
        // One log line per leg, with its elapsed time: on a real machine the
        // whole resolution used to be silent until the final "every DoH
        // endpoint failed" warn, so the ~10 s burned by a dead configured
        // endpoint and the 5 s race were invisible.
        let t0 = Instant::now();
        let ips = resolve_doh_typed(host, doh, qtype).await;
        if !ips.is_empty() {
            log::info!(
                "[dns] {host} -> {} addrs via DoH {doh} in {:?}",
                ips.len(),
                t0.elapsed()
            );
            return ips;
        }
        log::warn!(
            "[dns] DoH {doh} gave nothing for {host} in {:?}; racing the other endpoints",
            t0.elapsed()
        );
        // The configured endpoint did not answer: race the endpoints that have
        // not been tried yet before giving up on DoH entirely.
        let t1 = Instant::now();
        let ips = race_doh(host, doh, qtype).await;
        if !ips.is_empty() {
            log::info!(
                "[dns] {host} -> {} addrs via raced DoH in {:?}",
                ips.len(),
                t1.elapsed()
            );
            return ips;
        }
        log::warn!(
            "[dns] every DoH endpoint failed for {host} (configured {doh}, {:?}); falling back to plain DNS",
            t1.elapsed()
        );
        let ips = plain_then_system(host, configured, v6).await;
        log::warn!("[dns] plain-DNS fallback for {host} -> {} addrs", ips.len());
        return ips;
    }
    let ips = plain_then_system(host, configured, v6).await;
    log::info!("[dns] {host} -> {} addrs via plain DNS", ips.len());
    ips
}

/// Extra answers for an accelerated host whose first endpoint did not answer.
///
/// A single DoH resolver returns a single edge for `github.com`, and from a
/// censored network that edge is often blackholed *after* the TCP/TLS handshake:
/// the connect succeeds, the request is sent, and no response ever arrives. The
/// configured resolver therefore cannot be the only candidate source. This asks
/// the other Chinese DoH endpoints in parallel (each answer is cached, so this
/// costs one round trip per host and resolver) and returns the distinct
/// addresses that were not tried yet. It is called only after a real failure,
/// never on the happy path.
pub async fn resolve_alternatives(
    host: &str,
    dns: &str,
    use_doh: bool,
    doh_address: &str,
    exclude: &[IpAddr],
) -> Vec<IpAddr> {
    let v6 = is_support_ipv6().await;
    let qtype = if v6 { QType::Aaaa } else { QType::A };
    let mut out: Vec<IpAddr> = Vec::new();
    if use_doh {
        let configured = if doh_address.trim().is_empty() {
            dns_const::DNSPOD_DOH2
        } else {
            doh_address
        };
        // Two independent Chinese resolvers: their answers are usually different
        // edge addresses, which is exactly what the fallback needs.
        let extra: Vec<&'static str> = [dns_const::DNS_ALI_DOH, dns_const::DNSPOD_DOH]
            .into_iter()
            .filter(|endpoint| *endpoint != configured)
            .collect();
        let mut tasks = Vec::new();
        for endpoint in extra {
            let host = host.to_string();
            tasks.push(tokio::spawn(async move {
                resolve_doh_typed(&host, endpoint, qtype).await
            }));
        }
        for task in tasks {
            if let Ok(ips) = task.await {
                for ip in ips {
                    if !exclude.contains(&ip) && !out.contains(&ip) {
                        out.push(ip);
                    }
                }
            }
        }
    } else {
        // Plain DNS: ask the system resolvers directly as well. The configured
        // server was already used by `resolve_a`, so it is skipped here.
        let configured = dns.trim().parse::<IpAddr>().ok();
        for srv in system_dns_servers() {
            if Some(srv) == configured {
                continue;
            }
            for ip in resolve_udp_typed(host, Some(srv), qtype).await {
                if !exclude.contains(&ip) && !out.contains(&ip) {
                    out.push(ip);
                }
            }
        }
    }
    if !out.is_empty() {
        log::info!("[dns] {host} alternative answers: {out:?}");
    }
    out
}

/// The plain-DNS legs, in the order the original yields them: AAAA first (only
/// when the probe says the network is dual-stack), then A - both families land
/// in the candidate list, so an unreachable IPv6 endpoint still falls through
/// to IPv4 instead of failing the whole request. The system resolver is the
/// last resort (original `dnsServers == null` branch).
async fn plain_then_system(host: &str, configured: Option<IpAddr>, v6: bool) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    if v6 {
        ips.extend(
            plain_lookup(host, configured, QType::Aaaa)
                .await
                .unwrap_or_default(),
        );
    }
    ips.extend(
        plain_lookup(host, configured, QType::A)
            .await
            .unwrap_or_default(),
    );
    if !ips.is_empty() {
        return ips;
    }
    if v6 {
        ips.extend(resolve_udp_typed(host, None, QType::Aaaa).await);
    }
    ips.extend(resolve_udp_typed(host, None, QType::A).await);
    ips
}

/// Probe whether this network can actually use IPv6, mirroring the original
/// `DnsAnalysisServiceImpl.GetIsIpv6SupportAsync`: ask the IPv6-only server
/// `PRIMARY_IPV6_ALI` for the AAAA record of `IPV6_TEST_DOMAIN` and require the
/// answer to be the server address itself. A network without IPv6 has no route
/// to that server, so the query fails; a v6-broken resolver returns another
/// address or nothing. The answer is cached for the process (the original
/// caches it in `DomainResolver.isIpv6` for the lifetime of that resolver), so
/// the probe costs one query per run.
pub async fn is_support_ipv6() -> bool {
    static PROBE: OnceLock<Mutex<Option<bool>>> = OnceLock::new();
    let table = || PROBE.get_or_init(|| Mutex::new(None));
    if let Some(known) = *table().lock().unwrap() {
        return known;
    }
    let ok = tokio::task::spawn_blocking(|| {
        let Some(server) = dns_const::PRIMARY_IPV6_ALI.parse::<IpAddr>().ok() else {
            return false;
        };
        match dns_query(dns_const::IPV6_TEST_DOMAIN, server, QType::Aaaa) {
            Ok((ips, _)) => ips.contains(&server),
            Err(e) => {
                log::debug!("[dns] IPv6 support probe failed: {e}");
                false
            }
        }
    })
    .await
    .unwrap_or(false);
    *table().lock().unwrap() = Some(ok);
    ok
}

/// Plain-DNS lookup that always uses the exempted fixed source port: the
/// configured resolver first, then the machine's own DNS servers.
async fn plain_lookup(host: &str, configured: Option<IpAddr>, qtype: QType) -> Option<Vec<IpAddr>> {
    if let Some(srv) = configured {
        let ips = resolve_udp_typed(host, Some(srv), qtype).await;
        log::debug!(
            "[dns] plain lookup {host} ({}) via configured {srv} -> {ips:?}",
            qtype.url_name()
        );
        if !ips.is_empty() {
            return Some(ips);
        }
    }
    for srv in system_dns_servers() {
        if Some(srv) == configured {
            continue;
        }
        let ips = resolve_udp_typed(host, Some(srv), qtype).await;
        log::debug!(
            "[dns] plain lookup {host} ({}) via system {srv} -> {ips:?}",
            qtype.url_name()
        );
        if !ips.is_empty() {
            return Some(ips);
        }
    }
    None
}

/// Race the known DoH endpoints other than `skip` - the configured one, which
/// was already tried on its own - against `host`, and take the first non-empty
/// answer.
async fn race_doh(host: &str, skip: &str, qtype: QType) -> Vec<IpAddr> {
    // Race every DoH endpoint concurrently, but cap the whole thing at 5s:
    // if none has answered by then (all blocked/timeout in CN), give up so the
    // caller can fall through to plain DNS instead of blocking for up to 50s
    // (10 endpoints x 5s timeout each, awaited sequentially).
    let timeout = Duration::from_secs(5);
    tokio::time::timeout(timeout, async {
        let mut tasks = Vec::new();
        for addr in doh_addresses() {
            if addr == skip {
                continue;
            }
            let host = host.to_string();
            tasks.push(tokio::spawn(async move {
                resolve_doh_typed(&host, addr, qtype).await
            }));
        }
        for t in tasks {
            if let Ok(ips) = t.await {
                if !ips.is_empty() {
                    return ips;
                }
            }
        }
        Vec::new()
    })
    .await
    .unwrap_or_default()
}

/// DNS servers tried for TCP fallback, in order:
/// 1. the system's current DNS servers (always reachable on this LAN)
/// 2. the configured server (if it's a literal IP)
/// 3. well-known CN-friendly public resolvers
pub fn tcp_dns_servers(configured: &str) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for ip in system_dns_servers() {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    if let Ok(ip) = configured.trim().parse() {
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    for s in [
        dns_const::PRIMARY_ALI,
        dns_const::PRIMARY_DNSPOD,
        dns_const::PRIMARY_114,
    ] {
        if let Ok(ip) = s.parse() {
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// Resolve via DNS-over-HTTPS (JSON API), mirroring DnsDohAnalysisService.
///
/// Stays IPv4-only for callers that only want an A answer; `resolve_a` uses the
/// typed variant below so the dual-stack probe can select AAAA.
pub async fn resolve_doh(host: &str, doh_address: &str) -> Vec<IpAddr> {
    resolve_doh_typed(host, doh_address, QType::A).await
}

/// `qtype` mirrors the original's `isIPv6` choice, including its fallback: an
/// empty AAAA answer is retried as an A query on the same endpoint
/// (`DnsDohAnalysisDomainIpAsync`).
pub async fn resolve_doh_typed(host: &str, doh_address: &str, qtype: QType) -> Vec<IpAddr> {
    let ips = doh_query_once(host, doh_address, qtype).await;
    if !ips.is_empty() || qtype == QType::A {
        return ips;
    }
    doh_query_once(host, doh_address, QType::A).await
}

/// One cached DoH query on a single endpoint.
async fn doh_query_once(host: &str, doh_address: &str, qtype: QType) -> Vec<IpAddr> {
    let key: CacheKey = (
        host.to_string(),
        CacheSource::Doh(doh_address.to_string()),
        qtype,
    );
    if let Some(ips) = cache_get(&key) {
        return ips;
    }
    let url = format!(
        "{}?name={}&type={}",
        doh_address.trim_end_matches('/'),
        urlencoding(host),
        qtype.url_name()
    );
    // `ureq` is blocking: running it directly inside a task would occupy a
    // runtime worker for the whole request (up to the 5s timeout), and the
    // concurrent DoH probe below launches several at once - that starves the
    // runtime and stalls unrelated connections (including CONNECT replies).
    let body: Result<Value, String> = tokio::task::spawn_blocking(move || {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(5)))
            .build();
        let agent: ureq::Agent = config.into();
        let mut resp = agent.get(&url).call().map_err(|e| e.to_string())?;
        let text = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| e.to_string())?;
        serde_json::from_str(&text).map_err(|e| e.to_string())
    })
    .await
    .unwrap_or_else(|e| Err(format!("doh task failed: {e}")));
    let (ips, min_ttl) = match body {
        Ok(v) => parse_doh_answer(&v, qtype),
        Err(e) => {
            log::warn!("DoH resolve failed for {}: {}", host, e);
            (Vec::new(), 0)
        }
    };
    cache_put(key, &ips, cache_ttl(min_ttl));
    ips
}

/// Answers of the requested family plus the smallest TTL they carry, from a DoH
/// JSON response.
fn parse_doh_answer(v: &Value, qtype: QType) -> (Vec<IpAddr>, u32) {
    let Some(answers) = v.get("Answer").and_then(|a| a.as_array()) else {
        return (Vec::new(), 0);
    };
    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;
    for a in answers {
        if a.get("type").and_then(|t| t.as_i64()) != Some(i64::from(qtype.code())) {
            continue;
        }
        if let Some(ip) = a
            .get("data")
            .and_then(|d| d.as_str())
            .and_then(|d| d.parse::<IpAddr>().ok())
        {
            ips.push(ip);
        }
        if let Some(ttl) = a.get("TTL").and_then(|t| t.as_u64()) {
            min_ttl = min_ttl.min(u32::try_from(ttl).unwrap_or(u32::MAX));
        }
    }
    let min_ttl = if min_ttl == u32::MAX { 0 } else { min_ttl };
    (ips, min_ttl)
}

/// Resolve via plain UDP DNS query (or system resolver when no server).
pub async fn resolve_udp(host: &str, server: Option<IpAddr>) -> Vec<IpAddr> {
    resolve_udp_typed(host, server, QType::A).await
}

/// `qtype` selects the family asked of the server; the system-resolver branch
/// (`server == None`) filters the OS answers down to the same family, so one
/// cache entry never mixes record types - and the previously hardcoded
/// IPv4-only filter is lifted once IPv6 is usable.
async fn resolve_udp_typed(host: &str, server: Option<IpAddr>, qtype: QType) -> Vec<IpAddr> {
    let key: CacheKey = (host.to_string(), CacheSource::Udp(server), qtype);
    if let Some(ips) = cache_get(&key) {
        return ips;
    }
    let host = host.to_string();
    let (ips, min_ttl) = tokio::task::spawn_blocking(move || -> (Vec<IpAddr>, u32) {
        if let Some(srv) = server {
            match dns_query(&host, srv, qtype) {
                Ok(answer) => answer,
                Err(e) => {
                    log::warn!("UDP DNS resolve failed for {} via {}: {}", host, srv, e);
                    (Vec::new(), 0)
                }
            }
        } else {
            match std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 443u16)) {
                // The system resolver reports no TTL, hence the `0`.
                Ok(addrs) => (
                    addrs
                        .map(|a| a.ip())
                        .filter(|ip| family_matches(*ip, qtype))
                        .collect(),
                    0,
                ),
                Err(e) => {
                    log::warn!("System resolve failed for {}: {}", host, e);
                    (Vec::new(), 0)
                }
            }
        }
    })
    .await
    .unwrap_or_default();
    cache_put(key, &ips, cache_ttl(min_ttl));
    ips
}

/// An A query only yields IPv4 addresses and an AAAA query only IPv6 ones, so
/// filtering by family keeps every cache entry single-family.
fn family_matches(ip: IpAddr, qtype: QType) -> bool {
    match qtype {
        QType::A => matches!(ip, IpAddr::V4(_)),
        QType::Aaaa => matches!(ip, IpAddr::V6(_)),
    }
}

/// Minimal DNS query over UDP.
/// Source port used by our own DNS queries. The WinDivert interceptor filter
/// excludes this port (`udp.SrcPort != 53453`), so our own lookups bypass the
/// hook even for intercepted domains (UDP would otherwise be answered with
/// 127.0.0.1 and the proxy would connect to itself). Mirrors how the original
/// analysis service talks to its DNS servers directly.
pub const OURS_DNS_SRC_PORT: u16 = 53453;

static DNS_ID: AtomicU16 = AtomicU16::new(0x1234);

#[link(name = "ws2_32")]
extern "system" {
    fn setsockopt(s: usize, level: i32, name: i32, val: *const i32, len: i32) -> i32;
}
const SO_REUSEADDR: i32 = 0x0004;
const SOL_SOCKET: i32 = 0xFFFF;

fn dns_query(host: &str, server: IpAddr, qtype: QType) -> Result<(Vec<IpAddr>, u32), String> {
    // Per-query socket: no shared state, no Mutex, full concurrency. Each query
    // gets its own socket so responses can never be cross-stolen. Try to bind
    // OURS_DNS_SRC_PORT with SO_REUSEADDR (lets multiple sockets share the port
    // for the WinDivert exemption); fall back to an ephemeral port.
    use std::net::UdpSocket;
    // Bind in the target's own family: an IPv4 socket cannot send to the IPv6
    // probe server, and binding `[::]` would break IPv4 servers instead (Windows
    // keeps IPV6_V6ONLY on by default), so each family gets its own socket.
    let bind_addr = if server.is_ipv4() { "0.0.0.0" } else { "::" };
    let sock = UdpSocket::bind((bind_addr, OURS_DNS_SRC_PORT))
        .or_else(|_| UdpSocket::bind((bind_addr, 0)))
        .map_err(|e| e.to_string())?;
    // Enable SO_REUSEADDR so concurrent queries can all use port 53453.
    unsafe {
        let val: i32 = 1;
        setsockopt(
            sock.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_REUSEADDR,
            &val,
            std::mem::size_of::<i32>() as i32,
        );
    }
    let _ = sock.set_read_timeout(Some(Duration::from_millis(1500)));

    let mut buf = [0u8; 4096];
    let id = DNS_ID.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    let packet = build_a_query_with_id(host, id, qtype, &mut buf)?;
    let target = std::net::SocketAddr::new(server, 53);
    sock.send_to(&packet, target).map_err(|e| e.to_string())?;
    let id_bytes = id.to_be_bytes();
    let deadline = Instant::now() + Duration::from_millis(1500);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("dns timeout".into());
        }
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if n >= 2 && buf[0] == id_bytes[0] && buf[1] == id_bytes[1] {
                    return parse_a_response(&buf[..n], qtype);
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// Build a DNS query packet for the requested record type.
fn build_a_query_with_id<'a>(
    host: &str,
    id: u16,
    qtype: QType,
    buf: &'a mut [u8],
) -> Result<&'a [u8], String> {
    let mut w = 0usize;
    buf[w] = (id >> 8) as u8;
    w += 1;
    buf[w] = (id & 0xff) as u8;
    w += 1;
    buf[w] = 0x01;
    w += 1; // RD
    buf[w] = 0x00;
    w += 1;
    buf[w] = 0x00;
    w += 1;
    buf[w] = 0x01;
    w += 1; // QDCOUNT=1
    buf[w] = 0x00;
    w += 1;
    buf[w] = 0x00;
    w += 1; // ANCOUNT
    buf[w] = 0x00;
    w += 1;
    buf[w] = 0x00;
    w += 1; // NSCOUNT
    buf[w] = 0x00;
    w += 1;
    buf[w] = 0x00;
    w += 1; // ARCOUNT
    for label in host.split('.') {
        if w >= buf.len() {
            return Err("packet too large".into());
        }
        buf[w] = label.len() as u8;
        w += 1;
        for b in label.bytes() {
            if w >= buf.len() {
                return Err("packet too large".into());
            }
            buf[w] = b;
            w += 1;
        }
    }
    if w >= buf.len() {
        return Err("packet too large".into());
    }
    buf[w] = 0x00;
    w += 1;
    let ty = qtype.code().to_be_bytes();
    buf[w] = ty[0];
    w += 1;
    buf[w] = ty[1];
    w += 1; // QTYPE
    buf[w] = 0x00;
    w += 1;
    buf[w] = 0x01;
    w += 1; // QCLASS=IN
    Ok(&buf[..w])
}

/// Resolve via DNS-over-TCP (port 53). TCP is NOT matched by the WinDivert
/// `udp.DstPort == 53` interceptor, so this works even for intercepted domains
/// (the UDP path would be answered with 127.0.0.1 and loop back to ourselves).
/// Mirrors DnsClient's TCP-mode support used by the original DnsAnalysisService.
pub async fn resolve_tcp(host: &str, server: IpAddr) -> Vec<IpAddr> {
    let host = host.to_string();
    tokio::task::spawn_blocking(move || -> Vec<IpAddr> {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        let mut buf = [0u8; 512];
        let q = match build_a_query_with_id(&host, 0x2222, QType::A, &mut buf) {
            Ok(q) => q.to_vec(),
            Err(_) => return Vec::new(),
        };
        let mut sock = match TcpStream::connect((server, 53)) {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));
        let mut pkt = Vec::with_capacity(q.len() + 2);
        pkt.extend_from_slice(&(q.len() as u16).to_be_bytes());
        pkt.extend_from_slice(&q);
        if sock.write_all(&pkt).is_err() {
            return Vec::new();
        }
        let mut lenb = [0u8; 2];
        if sock.read_exact(&mut lenb).is_err() {
            return Vec::new();
        }
        let rlen = u16::from_be_bytes(lenb) as usize;
        if rlen == 0 || rlen > 512 {
            return Vec::new();
        }
        let mut resp = vec![0u8; rlen];
        if sock.read_exact(&mut resp).is_err() {
            return Vec::new();
        }
        parse_a_response(&resp, QType::A)
            .map(|(ips, _)| ips)
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default()
}

/// Parse the records of `qtype` and the smallest TTL they carry from a DNS
/// response. Records of other types (e.g. the CNAME chain) are skipped entirely,
/// so neither addresses nor TTLs leak across families.
fn parse_a_response(buf: &[u8], qtype: QType) -> Result<(Vec<IpAddr>, u32), String> {
    if buf.len() < 12 {
        return Err("short packet".into());
    }
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut i = 12usize;
    while i < buf.len() && buf[i] != 0 {
        let len = buf[i] as usize;
        i += 1 + len;
    }
    i += 5;
    let mut out = Vec::new();
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        if i >= buf.len() {
            break;
        }
        if buf[i] & 0xC0 == 0xC0 {
            i += 2;
        } else {
            while i < buf.len() && buf[i] != 0 {
                let len = buf[i] as usize;
                i += 1 + len;
            }
            i += 1;
        }
        if i + 10 > buf.len() {
            break;
        }
        let rtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
        // NAME(已跳过) TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) -> TTL 在 i+4..i+8。
        let ttl = u32::from_be_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
        let rdlen = u16::from_be_bytes([buf[i + 8], buf[i + 9]]) as usize;
        i += 10;
        if rtype == qtype.code() {
            min_ttl = min_ttl.min(ttl);
            if qtype == QType::A && rdlen == 4 && i + 4 <= buf.len() {
                out.push(IpAddr::from([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]));
            } else if qtype == QType::Aaaa && rdlen == 16 && i + 16 <= buf.len() {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[i..i + 16]);
                out.push(IpAddr::from(octets));
            }
        }
        i += rdlen;
    }
    // 没有记录时 min_ttl 仍是 MAX，用 0 表示"响应未给出 TTL"。
    Ok((out, if min_ttl == u32::MAX { 0 } else { min_ttl }))
}

/// Percent-encode a hostname for a DoH URL query.
fn urlencoding(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Measure latency of resolving a host via the given DoH endpoint.
pub async fn doh_latency(host: &str, doh_address: &str) -> Option<u128> {
    let start = Instant::now();
    let _ = resolve_doh(host, doh_address).await;
    Some(start.elapsed().as_millis())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 手工拼一个 DNS 响应：问题区 + 指针压缩的回答（NAME 用 `0xC0 0x0C` 指回问题区）。
    /// 每条记录给出 (`TTL`, `TYPE`, `RDATA`)，RDLENGTH 取 RDATA 长度，因此 A/AAAA
    /// 之外的记录类型也能拼出来。
    fn response_with(records: &[(u32, u16, &[u8])]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0x12, 0x34]); // ID
        b.extend_from_slice(&[0x81, 0x80]); // 标准响应
        b.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
        b.extend_from_slice(&(records.len() as u16).to_be_bytes()); // ANCOUNT
        b.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT / ARCOUNT
        for label in ["www", "example", "com"] {
            b.push(label.len() as u8);
            b.extend_from_slice(label.as_bytes());
        }
        b.push(0);
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        for (ttl, rtype, rdata) in records {
            b.extend_from_slice(&[0xC0, 0x0C]); // NAME 指针
            b.extend_from_slice(&rtype.to_be_bytes()); // TYPE
            b.extend_from_slice(&[0x00, 0x01]); // CLASS=IN
            b.extend_from_slice(&ttl.to_be_bytes());
            b.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
            b.extend_from_slice(rdata);
        }
        b
    }

    #[test]
    fn parse_a_response_reports_the_lowest_ttl() {
        let buf = response_with(&[(300, 1, &[1, 2, 3, 4]), (60, 1, &[5, 6, 7, 8])]);
        let (ips, ttl) = parse_a_response(&buf, QType::A).unwrap();
        assert_eq!(
            ips,
            vec![IpAddr::from([1, 2, 3, 4]), IpAddr::from([5, 6, 7, 8])]
        );
        assert_eq!(ttl, 60);

        // 没有任何回答时不报错，TTL 用 0 表示"未给出"。
        let empty = response_with(&[]);
        assert_eq!(parse_a_response(&empty, QType::A).unwrap(), (Vec::new(), 0));
    }

    #[test]
    fn a_response_yields_only_the_family_that_was_asked_for() {
        let v6 = [0x24, 0x00, 0x32, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let buf = response_with(&[(300, 1, &[1, 2, 3, 4]), (60, 28, &v6)]);
        // A 查询只拿 v4、TTL 也只取 v4 记录的；AAAA 查询反之（原项目按
        // host:queryType 分键，两族结果不得互相顶替）。
        assert_eq!(
            parse_a_response(&buf, QType::A).unwrap(),
            (vec![IpAddr::from([1, 2, 3, 4])], 300)
        );
        assert_eq!(
            parse_a_response(&buf, QType::Aaaa).unwrap(),
            (vec!["2400:3200::1".parse::<IpAddr>().unwrap()], 60)
        );
        // 其它类型（如 CNAME）既不产出地址也不参与最小 TTL。
        let cname = response_with(&[(10, 5, b"target.example.com")]);
        assert_eq!(parse_a_response(&cname, QType::A).unwrap(), (Vec::new(), 0));
    }

    #[test]
    fn a_query_packet_carries_the_requested_type() {
        let mut buf = [0u8; 256];
        let a = build_a_query_with_id("www.example.com", 1, QType::A, &mut buf).unwrap();
        assert_eq!(&a[a.len() - 4..], &[0x00, 0x01, 0x00, 0x01]);
        let mut buf = [0u8; 256];
        let aaaa = build_a_query_with_id("www.example.com", 1, QType::Aaaa, &mut buf).unwrap();
        assert_eq!(&aaaa[aaaa.len() - 4..], &[0x00, 0x1C, 0x00, 0x01]);
    }

    #[test]
    fn cache_ttl_uses_the_response_ttl_capped_by_the_original_nine_minutes() {
        assert_eq!(cache_ttl(60), Duration::from_secs(60));
        assert_eq!(cache_ttl(3600), CACHE_TTL_CAP);
        assert_eq!(cache_ttl(0), CACHE_TTL_CAP);
    }

    #[test]
    fn a_fresh_answer_is_served_and_an_empty_one_is_not_stored() {
        let key: CacheKey = (
            "a-fresh.test".to_string(),
            CacheSource::Udp(Some("1.2.3.4".parse().unwrap())),
            QType::A,
        );
        assert!(cache_get(&key).is_none());
        cache_put(
            key.clone(),
            &[IpAddr::from([9, 9, 9, 9])],
            Duration::from_secs(60),
        );
        assert_eq!(cache_get(&key), Some(vec![IpAddr::from([9, 9, 9, 9])]));

        // 空回答（解析失败）不进缓存，避免把一次超时变成数分钟的解析黑洞。
        let empty: CacheKey = ("a-empty.test".to_string(), CacheSource::Udp(None), QType::A);
        cache_put(empty.clone(), &[], Duration::from_secs(60));
        assert!(cache_get(&empty).is_none());
    }

    #[test]
    fn an_expired_answer_and_another_source_both_miss() {
        let expired: CacheKey = (
            "expired.test".to_string(),
            CacheSource::Doh("https://doh.test/resolve".to_string()),
            QType::A,
        );
        cache_put(
            expired.clone(),
            &[IpAddr::from([1, 1, 1, 1])],
            Duration::ZERO,
        );
        assert!(cache_get(&expired).is_none());

        // 同一个 host 由不同解析器给出，互不顶替（原项目按 (DoH 地址, host:类型) 分键）。
        let udp: CacheKey = (
            "src.test".to_string(),
            CacheSource::Udp(Some("5.6.7.8".parse().unwrap())),
            QType::A,
        );
        cache_put(
            udp.clone(),
            &[IpAddr::from([2, 2, 2, 2])],
            Duration::from_secs(60),
        );
        let doh: CacheKey = (
            "src.test".to_string(),
            CacheSource::Doh("https://doh.test/resolve".to_string()),
            QType::A,
        );
        assert_eq!(cache_get(&udp), Some(vec![IpAddr::from([2, 2, 2, 2])]));
        assert!(cache_get(&doh).is_none());

        // 同一个 host、同一个解析器，但查询族不同也不得顶替（DoH 地址, host:类型）。
        let aaaa: CacheKey = (
            "src.test".to_string(),
            CacheSource::Udp(Some("5.6.7.8".parse().unwrap())),
            QType::Aaaa,
        );
        assert!(cache_get(&aaaa).is_none());
    }

    #[test]
    fn parse_doh_answer_takes_the_lowest_a_record_ttl() {
        let v: Value = serde_json::from_str(
            r#"{"Status":0,"Answer":[
                {"name":"a.test","type":1,"TTL":300,"data":"1.2.3.4"},
                {"name":"a.test","type":28,"TTL":10,"data":"::1"},
                {"name":"a.test","type":1,"TTL":90,"data":"5.6.7.8"}]}"#,
        )
        .unwrap();
        // 只取 A 记录（type=1）：AAAA 既不计入地址，也不参与最小 TTL。
        assert_eq!(
            parse_doh_answer(&v, QType::A),
            (
                vec![IpAddr::from([1, 2, 3, 4]), IpAddr::from([5, 6, 7, 8])],
                90
            )
        );
        // 同一份报文按 AAAA 解析只取 type=28 的记录（DoH 响应按端点缓存，
        // 键含查询类型，两族结果不得互相顶替）。
        assert_eq!(
            parse_doh_answer(&v, QType::Aaaa),
            (vec!["::1".parse::<IpAddr>().unwrap()], 10)
        );

        let no_answer: Value = serde_json::from_str(r#"{"Status":2}"#).unwrap();
        assert_eq!(parse_doh_answer(&no_answer, QType::A), (Vec::new(), 0));
        assert_eq!(parse_doh_answer(&no_answer, QType::Aaaa), (Vec::new(), 0));
    }

    /// 进程内日志捕获：“DoH 全失败回落明文时必须打 warn”这条要求的可验证出口。
    static CAPTURED: Mutex<Vec<String>> = Mutex::new(Vec::new());
    static LOGGER: CaptureLogger = CaptureLogger;

    struct CaptureLogger;

    impl log::Log for CaptureLogger {
        fn enabled(&self, _metadata: &log::Metadata) -> bool {
            true
        }

        fn log(&self, record: &log::Record) {
            if record.level() <= log::Level::Warn {
                CAPTURED.lock().unwrap().push(record.args().to_string());
            }
        }

        fn flush(&self) {}
    }

    fn install_capture() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            let _ = log::set_logger(&LOGGER);
            log::set_max_level(log::LevelFilter::Warn);
        });
    }

    /// 一次性本地 DoH stub（HTTP + JSON），返回它的地址；每个测试用随机端口，
    /// 故两个测试的缓存键互不干扰。
    async fn doh_stub(answer: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let body = answer.as_bytes();
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body).await;
                let _ = sock.flush().await;
            }
        });
        format!("http://{addr}")
    }

    /// `use_doh=true` 时 DoH 在明文之前被采用：`System Default` 一定能把
    /// `localhost` 解析成 127.0.0.1，所以返回 stub 给的 TEST-NET 地址即证明
    /// DoH 优先（旧的“明文优先”实现会返回 127.0.0.1）。
    #[tokio::test]
    async fn doh_answers_first_even_when_plain_dns_could_answer() {
        let doh = doh_stub(
            r#"{"Status":0,"Answer":[{"name":"localhost","type":1,"TTL":60,"data":"203.0.113.7"}]}"#,
        )
        .await;
        let ips = resolve_a("localhost", "System Default", true, &doh).await;
        assert_eq!(ips, vec![IpAddr::from([203, 0, 113, 7])]);
    }

    /// 配置端点返回空、其余端点也答不出来（`.invalid` 是 RFC 2606 保留域名）
    /// 时必须落到明文腿，并且留下 warn：断言“结果等于关掉 DoH 的明文结果”
    /// 直接证明确实走了明文，而不是恰好返回空。
    #[tokio::test]
    async fn every_doh_endpoint_failing_falls_back_to_plain_dns_with_a_warning() {
        install_capture();
        let host = "no-such-host-for-dns-a6f3.invalid";
        let doh = doh_stub(r#"{"Status":2}"#).await;
        let ips = resolve_a(host, "System Default", true, &doh).await;
        let logged = CAPTURED.lock().unwrap().clone();
        assert!(
            logged
                .iter()
                .any(|l| l.contains(host) && l.contains("falling back to plain DNS")),
            "missing the plain-DNS fallback warning; captured: {logged:?}"
        );
        assert_eq!(ips, resolve_a(host, "System Default", false, "").await);
    }
}
