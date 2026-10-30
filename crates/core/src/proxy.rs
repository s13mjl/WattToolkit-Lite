//! Proxy manager: orchestrates the per-mode listeners, Hosts file edits,
//! system proxy / PAC registry writes, and the WinDivert DNS interceptor.

use crate::cert::CertificateManager;
use crate::fwd::{
    run_forward_proxy_on, run_steered_tunnel_on, ConfiguredIps, FakeNames, FwdRuntime,
};
use crate::hosts;
use crate::mitm::{run_mitm_on, MitmRuntime};
use crate::model::{AccelerateProject, AccelerateProjectGroup, ProxyMode, ProxyType};
use crate::settings::ProxySettings;
use crate::sysproxy;
use crate::windivert::DnsInterceptRuntime;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;
use tokio::task::JoinHandle;

/// Per-domain flow statistics.
#[derive(Default)]
pub struct FlowStats {
    pub total_bytes: u64,
    pub by_domain: std::collections::HashMap<String, u64>,
}

/// The address the forward proxy listens on, mirroring `ProxyService.Operate`
/// (System and PAC branches), which narrows a wildcard `ProxyIp` to loopback on
/// Windows *before* both listening and advertising the proxy to the system:
///
/// ```text
/// if (OperatingSystem.IsWindows() && proxyIp_.Value.Equals(IPAddress.Any))
///     SetProxyIp(IPAddress.Loopback);
/// ```
///
/// So an install that never touched the setting (its default is `0.0.0.0`) does
/// not expose an unauthenticated forward proxy to the LAN: the narrowed value
/// is what the original's Kestrel listener binds too, because `proxyIp` and
/// `proxyIp_` are also what it hands to `ReverseProxySettings` (whose
/// `ProxyIp` is copied onto the service, and `ListenHttpProxy` binds that).
///
/// Two deliberate deviations from the original: the wildcard test is
/// `is_unspecified`, which also covers IPv6 `::` (the original compares
/// `IPAddress.Any` only), and an unparsable value falls back to loopback on
/// every platform. The original's fallback for a value that does not parse is
/// `IPAddress.Any` (`ReverseProxySettings.GetProxyIp(string?)`), which on
/// Windows its own branch then narrows to loopback anyway - so both agree
/// there; only off Windows does this differ, on the safe side.
fn proxy_bind_ip(configured: &str) -> IpAddr {
    let text = configured.trim();
    let loopback = IpAddr::from([127, 0, 0, 1]);
    match text.parse::<IpAddr>() {
        Ok(ip) if cfg!(windows) && ip.is_unspecified() => {
            log::warn!(
                target: "wtlite_core::proxy",
                "监听地址 {text} 在 Windows 上收窄为 {loopback}（与原项目一致：不向局域网暴露无鉴权正向代理）"
            );
            loopback
        }
        Ok(ip) => ip,
        Err(_) => {
            log::warn!(
                target: "wtlite_core::proxy",
                "监听地址 {text:?} 不是合法的 IP，已回退 {loopback}"
            );
            loopback
        }
    }
}

/// Whether any enabled leaf of the manifest asks for the upstream certificate
/// verification to be relaxed (the original `TlsIgnoreNameMismatch`).
///
/// This is the judgement the startup warning applies, verbatim: a group that is not
/// explicitly enabled is skipped, and inside it a leaf counts only when it is itself
/// enabled and carries the field. Nothing else consumes the flag - the relaxation is
/// not implemented.
fn manifest_asks_to_ignore_cert(groups: &[AccelerateProjectGroup]) -> bool {
    let mut asks_to_ignore_cert = false;
    for grp in groups {
        if grp.three_state_enable != Some(true) {
            continue;
        }
        for proj in &grp.items {
            for leaf in proj.all_leaves() {
                if leaf.three_state_enable == Some(true) && leaf.ignore_ssl_cert_verification {
                    asks_to_ignore_cert = true;
                }
            }
        }
    }
    asks_to_ignore_cert
}

/// The manifest's substitute upstream names (original `FakeServerName`): one entry
/// per `MatchDomainNames` pattern, in manifest order.
///
/// Lifted verbatim out of the manifest loop in `start` (which also collects the
/// domains, the configured addresses and the hosts entries): the same
/// `three_state_enable` gates, the same per-pattern trimming and lowercasing, and
/// the same "an empty value is not a name" test.
/// The upstream addresses a manifest leaf pins for local acceleration.
///
/// The original `AccelerateProjectDTO` maps `ForwardDomainNames` to
/// `IDomainConfig.IPAddress` when the value parses as an IP and the project is
/// `ProxyType.Local`; Lite's separate `ip_address` field carries the same
/// information in its built-in/JSON manifest. Both shapes are accepted here so
/// an official cache that puts an IP in `ForwardDomainNames` is not treated as
/// a hostname alias.
fn leaf_local_ips(leaf: &AccelerateProject) -> Vec<IpAddr> {
    if leaf.proxy_type != ProxyType::Normal {
        return Vec::new();
    }
    let mut ips = leaf.ip_address.clone();
    if let Some(ip) = leaf
        .forward_domain_names
        .as_deref()
        .and_then(|value| value.trim().parse::<IpAddr>().ok())
    {
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    ips
}

/// The substitute hostname (`ForwardDestination`) of a local project, or `None`
/// when the value is an IP (handled by `leaf_local_ips`) or the project is
/// server-accelerated (where `ForwardDomainNames` is the server URI, which Lite
/// cannot use).
fn leaf_local_alias(leaf: &AccelerateProject) -> Option<String> {
    if leaf.proxy_type != ProxyType::Normal {
        return None;
    }
    let aliases = leaf.forward_domain_names.as_deref()?.trim();
    if aliases.is_empty() || aliases.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(aliases.to_lowercase())
}

fn collect_fake_names(groups: &[AccelerateProjectGroup]) -> Vec<(String, String)> {
    let mut fake_names: Vec<(String, String)> = Vec::new();
    for grp in groups {
        if grp.three_state_enable != Some(true) {
            continue;
        }
        for proj in &grp.items {
            for leaf in proj.all_leaves() {
                if leaf.three_state_enable != Some(true) {
                    continue;
                }
                for d in leaf.match_domain_names.split(';') {
                    let d = d.trim().to_lowercase();
                    if d.is_empty() {
                        continue;
                    }
                    // Every pattern of a project carries the same substitute
                    // name, mirroring `AddDomainConfigs` in the original, which
                    // keys each pattern to the same `FakeServerName`.
                    if let Some(name) = &leaf.fake_server_name {
                        let name = name.trim().to_lowercase();
                        if !name.is_empty() {
                            fake_names.push((d.clone(), name));
                        }
                    }
                }
            }
        }
    }
    fake_names
}

/// Which listener fell back to a bare tunnel. The warning differs per listener,
/// and, more importantly, per reason - see `local_decryption_fallback_warning`.
#[derive(Clone, Copy, Debug)]
enum DecryptionSite {
    /// The forward proxy `System` / `Pac` mode listens with.
    SystemOrPacForward,
    /// The forward proxy `DnsIntercept` runs beside its 443 listener.
    DnsInterceptForward,
    /// The 443 listener of `DnsIntercept` mode.
    DnsIntercept443,
}

/// Whether `mode` listens through one of the decryption-capable listeners: the
/// forward proxies of `System` / `Pac` / `DnsIntercept` and the interceptor's 443
/// listener. This is the mode set the gate has always been read with.
///
/// `Hosts` is deliberately not in it: its mechanism is "name -> 127.0.0.1 ->
/// decrypt", so a client that reaches its 443 listener can only be served by
/// decrypting. That listener decrypts unconditionally and is outside the switch
/// (registered legacy, recorded in the C-6 entry of the review report).
fn is_decrypting_mode(mode: ProxyMode) -> bool {
    matches!(
        mode,
        ProxyMode::System | ProxyMode::Pac | ProxyMode::DnsIntercept
    )
}

/// The single judgement behind every local TLS-termination point.
///
/// Every decryption decision point asks this one function, so that turning local
/// decryption off cannot leave a listener still decrypting: a point the switch
/// missed would make the setting lie about the behavior (the failure mode the
/// C-6 constraints rule out). The three conditions:
///
/// - the mode listens through a decryption-capable listener (`is_decrypting_mode`);
/// - local decryption is not switched off by the user - the setting is read once
///   at startup, so a change applies from the next start, not to a running proxy;
/// - the system trusts our root certificate. With an untrusted CA every decrypted
///   connection would fail with a certificate error instead of working through
///   the tunnel, so the probe is part of the judgement and not the listeners' own
///   logic.
///
/// With `decrypt_enabled` true this is the pre-switch judgement verbatim: the same
/// modes decrypt exactly when the trust-store probe succeeds.
fn should_decrypt_locally(mode: ProxyMode, decrypt_enabled: bool, cert_installed: bool) -> bool {
    is_decrypting_mode(mode) && decrypt_enabled && cert_installed
}

/// The warning for a listener that fell back to a bare tunnel.
///
/// Two reasons have to be told apart. A certificate the system does not trust
/// keeps the wording it had before the switch existed, verbatim - it is what the
/// user sees after installing the certificate without restarting (and it must not
/// change, a user's log line is what they search for). A switch the user turned
/// off themselves gets new wording, and must not claim the certificate is
/// untrusted; both also say that the setting is read at startup, so the user knows
/// a change needs a restart.
fn local_decryption_fallback_warning(site: DecryptionSite, decrypt_enabled: bool) -> &'static str {
    match (site, decrypt_enabled) {
        (DecryptionSite::SystemOrPacForward, true) => {
            "根证书未被系统信任：PAC / 系统代理模式的 TLS 不再本地解密，退回裸隧道（加速域名的 SNI 指定与上游证书校验不可用）。若刚刚安装证书，请重启本程序后生效。"
        }
        (DecryptionSite::SystemOrPacForward, false) => {
            "已在设置中关闭本地 TLS 解密：PAC / 系统代理模式的 TLS 不再本地解密，退回裸隧道（加速域名的 SNI 指定与上游证书校验不可用）。该开关在启动时读取，修改后需重启本程序生效。"
        }
        (DecryptionSite::DnsInterceptForward, true) => {
            "根证书未被系统信任：DNS 拦截模式的转发监听不再本地解密，退回裸隧道（加速域名的 SNI 指定与上游证书校验不可用）。若刚刚安装证书，请重启本程序后生效。"
        }
        (DecryptionSite::DnsInterceptForward, false) => {
            "已在设置中关闭本地 TLS 解密：DNS 拦截模式的转发监听不再本地解密，退回裸隧道（加速域名的 SNI 指定与上游证书校验不可用）。该开关在启动时读取，修改后需重启本程序生效。"
        }
        (DecryptionSite::DnsIntercept443, true) => {
            "根证书未被系统信任：DNS 拦截模式的 443 不再本地解密，退回裸中继（按 ClientHello 的 SNI 拨号，端到端 TLS）。若刚刚安装证书，请重启本程序后生效。"
        }
        (DecryptionSite::DnsIntercept443, false) => {
            "已在设置中关闭本地 TLS 解密：DNS 拦截模式的 443 不再本地解密，退回裸中继（按 ClientHello 的 SNI 拨号，端到端 TLS）。该开关在启动时读取，修改后需重启本程序生效。"
        }
    }
}

/// The proxy manager (mirrors the original ProxyService + ReverseProxy).
#[derive(Clone)]
pub struct ProxyManager {
    inner: Arc<Mutex<Inner>>,
    pub cert: Arc<CertificateManager>,
    /// Sender kept for all proxy log lines.
    log_tx: tokio::sync::mpsc::UnboundedSender<String>,
    /// Receiver taken once by the UI.
    log_rx: Arc<Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<String>>>>,
}

struct Inner {
    running: bool,
    mode: Option<ProxyMode>,
    /// Runtime owned by the manager. It must outlive `start()`: the listeners
    /// are `tokio::spawn`ed tasks, so dropping the caller's temporary runtime
    /// would silently cancel every listener (UI shows "running" while nothing
    /// is actually bound).
    runtime: Option<Arc<tokio::runtime::Runtime>>,
    tasks: Vec<JoinHandle<()>>,
    windivert_stop: Option<Arc<std::sync::atomic::AtomicBool>>,
    log_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    pub stats: Arc<Mutex<FlowStats>>,
    pub config: Arc<RwLock<ProxySettings>>,
    pub domains: Arc<RwLock<HashSet<String>>>,
    /// Blocked host -> reachable substitute hostname to dial upstream
    /// (the original `ForwardDestination`/`TlsSni` mechanism).
    pub forward: Arc<RwLock<std::collections::HashMap<String, String>>>,
    /// Host pattern -> manifest-configured upstream addresses (original
    /// `ReverseProxyConfig.IPAddress`). A list, not a map, because the manifest
    /// order decides which entry wins when several patterns match one host.
    pub configured_ips: ConfiguredIps,
    /// Host pattern -> manifest-configured substitute upstream name (original
    /// `ReverseProxyConfig.FakeServerName`), the SNI the MITM upstream presents.
    /// Same list/order reasoning as `configured_ips`.
    pub fake_names: FakeNames,
    pub started_at: Option<SystemTime>,
}

impl ProxyManager {
    pub fn new() -> Self {
        let stats = Arc::new(Mutex::new(FlowStats::default()));
        let config = Arc::new(RwLock::new(ProxySettings::default()));
        let domains = Arc::new(RwLock::new(HashSet::new()));
        let forward = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let configured_ips = Arc::new(RwLock::new(Vec::new()));
        let fake_names = Arc::new(RwLock::new(Vec::new()));
        let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        Self {
            inner: Arc::new(Mutex::new(Inner {
                running: false,
                mode: None,
                runtime: None,
                tasks: Vec::new(),
                windivert_stop: None,
                log_tx: None,
                stats,
                config,
                domains,
                forward,
                configured_ips,
                fake_names,
                started_at: None,
            })),
            cert: Arc::new(CertificateManager::new()),
            log_tx,
            log_rx: Arc::new(Mutex::new(Some(log_rx))),
        }
    }

    pub fn stats(&self) -> Arc<Mutex<FlowStats>> {
        self.inner.lock().unwrap().stats.clone()
    }

    pub fn is_running(&self) -> bool {
        self.inner.lock().unwrap().running
    }

    pub fn current_mode(&self) -> Option<ProxyMode> {
        self.inner.lock().unwrap().mode
    }

    /// The current log sender (cloned for subscribers before start).
    pub fn log_sender(&self) -> Option<tokio::sync::mpsc::UnboundedSender<String>> {
        self.inner.lock().unwrap().log_tx.clone()
    }

    /// Take the log receiver (once) for the UI to drain.
    pub fn take_log_rx(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<String>> {
        self.log_rx.lock().unwrap().take()
    }

    /// Start the proxy on a runtime owned by this manager.
    ///
    /// This is the entry point used by the UI. The spawned listener tasks need
    /// a runtime that outlives the call, otherwise they are cancelled the moment
    /// the caller's temporary runtime is dropped.
    pub fn start_blocking(
        &self,
        mode: ProxyMode,
        settings: &ProxySettings,
        groups: &[AccelerateProjectGroup],
    ) -> Result<(), String> {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|e| format!("create tokio runtime failed: {e}"))?,
        );
        {
            let mut g = self.inner.lock().unwrap();
            g.runtime = Some(rt.clone());
        }
        let res = rt.block_on(async { self.start(mode, settings, groups).await });
        if res.is_err() {
            // Roll back: drop the runtime and its listeners.
            let mut g = self.inner.lock().unwrap();
            g.runtime = None;
        }
        res
    }

    /// Start the proxy in the given mode.
    pub async fn start(
        &self,
        mode: ProxyMode,
        settings: &ProxySettings,
        groups: &[AccelerateProjectGroup],
    ) -> Result<(), String> {
        let mut g = self.inner.lock().unwrap();
        if g.running {
            return Err("proxy already running".into());
        }

        // The original probes IPv6 support when its listener starts
        // (`DomainResolver.CheckIpv6SupportAsync`), not on the first request.
        // Warming it here keeps the first page's DNS resolution from paying the
        // probe's ~1.5 s timeout; the probe result is process-wide.
        tokio::spawn(async {
            let _ = crate::dns::is_support_ipv6().await;
        });

        // Compute acceleration domains from `MatchDomainNames` of the enabled
        // projects (the original `ReverseProxyConfig.AddDomainConfigs` keys and
        // `GetDomainPatterns`, which feed both matching and the PAC). Patterns
        // keep their leading `*`: `*.example.com` covers the bare domain and
        // every sub-domain. Official data uses `*.st.dl.eccdnx.com`,
        // `*.steamcommunity.com`.
        let mut domains = HashSet::new();
        // `ListenDomainNames` feeds the hosts file only. An entry may pin a
        // host to an explicit IP (`"1.2.3.4 example.com"`, mirroring
        // `ProxyService.Operate`'s `host.Split(' ')`); the first entry for a
        // host wins, mirroring `ToDictionaryIgnoreRepeat(x => x.Key, ...)`.
        // A `*.` prefix is dropped because a hosts line cannot contain `*`.
        let mut hosts_hosts: HashSet<String> = HashSet::new();
        let mut hosts_entries: Vec<(String, String)> = Vec::new();
        // The original Hosts branch points entries at the configured proxy IP
        // (`IPAddress.Any` means loopback) and binds the 443 listener to that
        // same IP. The previous code hard-coded 127.0.0.1 for both.
        let configured_proxy_ip = settings.system_proxy_ip.trim().parse::<IpAddr>().ok();
        let hosts_default_ip = match configured_proxy_ip {
            Some(ip) if !ip.is_unspecified() => ip.to_string(),
            _ => "127.0.0.1".to_string(),
        };
        let hosts_bind_ip = configured_proxy_ip.unwrap_or(IpAddr::from([0, 0, 0, 0]));
        // Manifest-configured upstream addresses (original
        // `ReverseProxyConfig.IPAddress`), tried ahead of the resolved DNS
        // answers. Kept as a list so the manifest order survives: at lookup time
        // the first pattern matching the host wins.
        let mut configured_ips: Vec<(String, Vec<IpAddr>)> = Vec::new();
        for grp in groups {
            if grp.three_state_enable != Some(true) {
                continue;
            }
            for proj in &grp.items {
                for leaf in proj.all_leaves() {
                    if leaf.three_state_enable != Some(true) {
                        continue;
                    }
                    if leaf.proxy_type == ProxyType::ServerAccelerate {
                        log::warn!(
                            target: "wtlite_core::proxy",
                            "加速项目 {} 使用服务器加速（ServerAccelerate），本程序未实现该后端，按本地直连处理",
                            leaf.name
                        );
                    }
                    let leaf_ips = leaf_local_ips(leaf);
                    for d in leaf.match_domain_names.split(';') {
                        let d = d.trim().to_lowercase();
                        if d.is_empty() {
                            continue;
                        }
                        // Every pattern of a project carries the same configured
                        // addresses, mirroring `AddDomainConfigs` in the original,
                        // which keys each pattern to the same `IPAddress`.
                        if !leaf_ips.is_empty() {
                            configured_ips.push((d.clone(), leaf_ips.clone()));
                        }
                        domains.insert(d);
                    }
                    for h in leaf.listen_domain_names.split(';') {
                        let h = h.trim().to_lowercase();
                        if h.is_empty() {
                            continue;
                        }
                        let (host, ip) = match h.split_once(' ') {
                            Some((ip, host)) => (host.trim().to_string(), ip.trim().to_string()),
                            None => (h, hosts_default_ip.clone()),
                        };
                        let host = host.strip_prefix("*.").unwrap_or(&host).to_string();
                        if !host.is_empty() && hosts_hosts.insert(host.clone()) {
                            hosts_entries.push((host, ip));
                        }
                    }
                }
            }
        }
        let fake_names = collect_fake_names(groups);
        // Blocked host -> reachable substitute hostname (original
        // `ForwardDestination` + `TlsSni`). Mirrors the official data, where
        // sites are aliased onto their CDN hostnames.
        let mut forward: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for grp in groups {
            if grp.three_state_enable != Some(true) {
                continue;
            }
            for proj in &grp.items {
                for leaf in proj.all_leaves() {
                    if leaf.three_state_enable != Some(true) {
                        continue;
                    }
                    if let Some(fwd) = leaf_local_alias(leaf) {
                        for host in leaf.match_domain_names.split(';') {
                            let host = host.trim().to_lowercase();
                            if !host.is_empty() {
                                forward.insert(host, fwd.clone());
                            }
                        }
                    }
                }
            }
        }
        // Forward targets are connect aliases, not intercept entries: they
        // must resolve to their real IPs for the MITM upstream, so keep them
        // out of the interception set (otherwise the hook would answer them
        // with 127.0.0.1 and the proxy would connect to itself).
        for target in forward.values() {
            domains.remove(target);
            domains.remove(&format!("*.{target}"));
            let bare = target.strip_prefix("*.").unwrap_or(target);
            hosts_entries.retain(|(h, _)| h.as_str() != target && h.as_str() != bare);
        }
        *g.domains.write().unwrap() = domains.clone();
        *g.forward.write().unwrap() = forward.clone();
        *g.configured_ips.write().unwrap() = configured_ips.clone();
        *g.fake_names.write().unwrap() = fake_names.clone();
        *g.config.write().unwrap() = settings.clone();
        log::info!(
            target: "wtlite_core::proxy",
            "starting proxy: mode={mode:?} port={} domains={} forward={} configured_ips={} fake_names={}",
            settings.system_proxy_port,
            domains.len(),
            forward.len(),
            configured_ips.len(),
            fake_names.len()
        );
        if domains.is_empty() {
            log::warn!(
                target: "wtlite_core::proxy",
                "no acceleration domains selected - the PAC will proxy nothing"
            );
        }

        let log_tx = self.log_tx.clone();
        g.log_tx = Some(log_tx.clone());
        // The manifest's `IgnoreSSLCertVerification` (the original's
        // `TlsIgnoreNameMismatch`) has no consumer here: the upstream certificate
        // is always verified. Say so once at startup, so a manifest that asks for
        // the relaxation cannot look like it is in effect.
        if manifest_asks_to_ignore_cert(groups) {
            let msg = "清单要求忽略上游证书校验（ignore_ssl_cert_verification / 原项目 TlsIgnoreNameMismatch）：本程序未实现该校验放宽，上游证书仍按 webpki 根校验。";
            log::warn!(target: "wtlite_core::proxy", "{msg}");
            let _ = log_tx.send(msg.to_string());
        }
        let stats = g.stats.clone();
        let config = g.config.clone();
        let domains_arc = g.domains.clone();
        let forward_arc = g.forward.clone();
        let configured_ips_arc = g.configured_ips.clone();
        let fake_names_arc = g.fake_names.clone();
        let cert = self.cert.clone();
        // Root cert is needed by the MITM path (Hosts + DnsIntercept modes).
        let root_for_mitm = cert.root().ok();

        g.running = true;
        g.mode = Some(mode);
        g.started_at = Some(SystemTime::now());

        drop(g);

        // Shared TLS-termination runtime for the forward-proxy modes: a TLS
        // CONNECT is decrypted here (mirrors the original, whose proxy always
        // terminates TLS with its own certificate) so the upstream can be dialled
        // with a different SNI and a failing endpoint can be retried.
        //
        // Terminating TLS is only sound while the system actually trusts our root
        // certificate: with an untrusted CA every decrypted connection would fail
        // with a certificate error instead of working through the tunnel, so this
        // runtime is armed only when the trust-store probe succeeds.
        //
        // The judgement is `should_decrypt_locally` - the mode, the user's
        // local-decryption setting and that probe in one place - so a listener
        // cannot be left decrypting while the setting says otherwise. That setting
        // is read here, once per start: it applies from the next start, never to a
        // proxy that is already running.
        //
        // Every mode that listens as a forward proxy is judged by that single
        // judgement - `System` and `Pac`, and the `DnsIntercept` forward listener as
        // well (it serves manually pointed clients; the `DnsIntercept` 443 listener
        // branches on it separately). With the gate closed `FwdRuntime.mitm` is
        // `None`, so a TLS CONNECT falls back to the plain tunnel - the very path
        // `System` / `Pac` take with their gate closed.
        let forward_proxy_mode = matches!(mode, ProxyMode::System | ProxyMode::Pac);
        let mitm_listening_mode = is_decrypting_mode(mode);
        let decrypt_enabled = settings.enable_tls_decryption;
        let mitm_armed = should_decrypt_locally(mode, decrypt_enabled, cert.is_installed());
        if mitm_listening_mode && !mitm_armed {
            // Either reason; the warning says which one it was.
            let site = if forward_proxy_mode {
                DecryptionSite::SystemOrPacForward
            } else {
                DecryptionSite::DnsInterceptForward
            };
            let msg = local_decryption_fallback_warning(site, decrypt_enabled);
            log::warn!(target: "wtlite_core::proxy", "{msg}");
            let _ = log_tx.send(msg.to_string());
        }
        let mitm_rt: Option<Arc<MitmRuntime>> = if mitm_armed {
            cert.root().ok().map(|root| {
                Arc::new(MitmRuntime {
                    cm: cert.clone(),
                    cache: Arc::new(crate::cert::LeafCache::default()),
                    root,
                    config: config.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                    forward: forward_arc.clone(),
                    configured_ips: configured_ips_arc.clone(),
                    fake_names: fake_names_arc.clone(),
                    domains: domains_arc.clone(),
                })
            })
        } else {
            None
        };

        match mode {
            ProxyMode::Hosts => {
                // 1. Ensure root certificate exists.
                let root = cert.root().map_err(|e| {
                    self.stop_inner();
                    e
                })?;
                // 2. Write hosts entries.
                if !hosts_entries.is_empty() {
                    if let Err(e) = hosts::update_hosts(&hosts_entries) {
                        self.stop_inner();
                        return Err(format!("update hosts failed: {e}"));
                    }
                }
                // 3. Start MITM listener on 443 (bind first so failures surface).
                let mitm_bind: SocketAddr = (hosts_bind_ip, 443u16).into();
                let mitm_listener = match tokio::net::TcpListener::bind(mitm_bind).await {
                    Ok(l) => l,
                    Err(e) => {
                        self.stop_inner();
                        let _ = hosts::remove_by_tag();
                        return Err(format!(
                            "端口 443 被占用或无法绑定（可能需要管理员权限）: {e}"
                        ));
                    }
                };
                let rt = MitmRuntime {
                    cm: cert.clone(),
                    cache: Arc::new(crate::cert::LeafCache::default()),
                    root: root.clone(),
                    config: config.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                    forward: forward_arc.clone(),
                    configured_ips: configured_ips_arc.clone(),
                    fake_names: fake_names_arc.clone(),
                    domains: domains_arc.clone(),
                };
                let task = tokio::spawn(async move {
                    let _ = run_mitm_on(mitm_listener, rt).await;
                });
                let mut g = self.inner.lock().unwrap();
                g.tasks.push(task);
            }
            ProxyMode::System => {
                let ip = proxy_bind_ip(&settings.system_proxy_ip);
                let bind: SocketAddr = (ip, settings.system_proxy_port).into();
                let listener = match tokio::net::TcpListener::bind(bind).await {
                    Ok(l) => l,
                    Err(e) => {
                        self.stop_inner();
                        return Err(format!(
                            "端口 {} 被占用或无法绑定，请检查是否已有其他程序在监听: {e}",
                            settings.system_proxy_port
                        ));
                    }
                };
                let rt = FwdRuntime {
                    config: config.clone(),
                    domains: domains_arc.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                    mitm: mitm_rt.clone(),
                    forward: forward_arc.clone(),
                    configured_ips: configured_ips_arc.clone(),
                };
                let task = tokio::spawn(async move {
                    let _ = run_forward_proxy_on(listener, rt).await;
                });
                // Set the Windows system proxy (no elevation needed, HKCU).
                if let Err(e) =
                    sysproxy::set_system_proxy(true, &ip.to_string(), settings.system_proxy_port)
                {
                    // Roll back the whole start, not just the `running` flag: the
                    // listener spawned just above must be released (otherwise the
                    // immediate retry fails with "port in use") and the recorded
                    // mode must not survive, so `is_running() == false` and
                    // `current_mode()` agree. The original configures the system
                    // proxy *before* starting its service (`ProxyService.Operate`,
                    // System branch), so a failure there leaves nothing running.
                    let mut g = self.inner.lock().unwrap();
                    g.tasks.push(task);
                    drop(g);
                    self.stop_inner();
                    return Err(format!("set system proxy failed: {e}"));
                }
                log::info!(
                    target: "wtlite_core::proxy",
                    "system proxy = {}:{}",
                    ip,
                    settings.system_proxy_port
                );
                log::info!(
                    target: "wtlite_core::proxy",
                    "WinINET sees: {}",
                    sysproxy::describe_effective_proxy()
                );
                let mut g = self.inner.lock().unwrap();
                g.tasks.push(task);
            }
            ProxyMode::Pac => {
                let ip = proxy_bind_ip(&settings.system_proxy_ip);
                let bind: SocketAddr = (ip, settings.system_proxy_port).into();
                let listener = match tokio::net::TcpListener::bind(bind).await {
                    Ok(l) => l,
                    Err(e) => {
                        self.stop_inner();
                        return Err(format!(
                            "端口 {} 被占用或无法绑定，请检查是否已有其他程序在监听: {e}",
                            settings.system_proxy_port
                        ));
                    }
                };
                let rt = FwdRuntime {
                    config: config.clone(),
                    domains: domains_arc.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                    mitm: mitm_rt.clone(),
                    forward: forward_arc.clone(),
                    configured_ips: configured_ips_arc.clone(),
                };
                let task = tokio::spawn(async move {
                    let _ = run_forward_proxy_on(listener, rt).await;
                });
                // Mirrors the original PAC branch: `http://{ip}:{port}/pac`.
                // IPv6 literals need brackets in a URL; the original's plain
                // `{ip}:{port}` interpolation only produced valid IPV4 URLs.
                let pac_url = format!(
                    "http://{}/pac",
                    sysproxy::format_host_port(&ip.to_string(), settings.system_proxy_port)
                );
                if let Err(e) = sysproxy::set_pac_proxy(true, &pac_url) {
                    // Same rollback as the System branch: release the listener and
                    // clear `running` / `mode` together, so a failed start leaves no
                    // bound port behind and no stale mode (`ProxyService.Operate`,
                    // PAC branch, sets the PAC URL before starting its service).
                    let mut g = self.inner.lock().unwrap();
                    g.tasks.push(task);
                    drop(g);
                    self.stop_inner();
                    return Err(format!("set PAC proxy failed: {e}"));
                }
                log::info!(
                    target: "wtlite_core::proxy",
                    "AutoConfigURL = {pac_url}"
                );
                log::info!(
                    target: "wtlite_core::proxy",
                    "WinINET sees: {}",
                    sysproxy::describe_effective_proxy()
                );
                let mut g = self.inner.lock().unwrap();
                g.tasks.push(task);
            }
            ProxyMode::DnsIntercept => {
                // DNS interception steers accelerated domains to 127.0.0.1, so a
                // listener on 443 is required to handle that traffic (mirrors the
                // original, which starts both a MITM and a forward proxy in
                // DNSIntercept mode).
                //
                // Decrypting that traffic is only sound while the system trusts our
                // root certificate and local decryption is switched on - the same
                // judgement `System` / `Pac` mode makes, see `should_decrypt_locally`.
                // With an untrusted CA every decrypted connection would fail with a
                // certificate error, so the listener falls back to a bare end-to-end
                // tunnel. It stays bound either way: an OS cache can still hold
                // the `127.0.0.1` answer from a previous run and keep steering
                // clients here.
                let mitm_bind: SocketAddr = (IpAddr::from([127, 0, 0, 1]), 443u16).into();
                let mitm_listener = match tokio::net::TcpListener::bind(mitm_bind).await {
                    Ok(l) => l,
                    Err(e) => {
                        self.stop_inner();
                        return Err(format!(
                            "端口 443 被占用或无法绑定（可能需要管理员权限）: {e}"
                        ));
                    }
                };
                // Forward proxy on the configured port for non-accelerated HTTP
                // (same address rule as System / PAC: a wildcard is narrowed to
                // loopback on Windows, so this listener - which is not
                // authenticated either - is not exposed to the LAN).
                let ip = proxy_bind_ip(&settings.system_proxy_ip);
                let fwd_bind: SocketAddr = (ip, settings.system_proxy_port).into();
                let fwd_listener = match tokio::net::TcpListener::bind(fwd_bind).await {
                    Ok(l) => l,
                    Err(e) => {
                        self.stop_inner();
                        return Err(format!(
                            "端口 {} 被占用或无法绑定: {e}",
                            settings.system_proxy_port
                        ));
                    }
                };
                // The interceptor owns UDP:53, so the MITM's own upstream lookup
                // must go through DoH — a plain UDP query would be intercepted back
                // to 127.0.0.1 and the proxy would connect to itself.
                let mut intercept_cfg = config.read().unwrap().clone();
                intercept_cfg.use_doh = true;
                let intercept_cfg = Arc::new(RwLock::new(intercept_cfg));
                // AAAA answers point at ::1, so the 443 listener must exist on
                // both loopback families (the original Kestrel socket is
                // dual-stack). Failure to bind IPv6 is logged and does not abort
                // IPv4 acceleration.
                let mut listeners_443 = vec![mitm_listener];
                match tokio::net::TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 443u16)).await {
                    Ok(listener) => listeners_443.push(listener),
                    Err(e) => log::warn!(
                        target: "wtlite_core::proxy",
                        "IPv6 443 监听绑定失败（IPv6 加速可能不可用）: {e}"
                    ),
                }
                let decrypt_443 =
                    should_decrypt_locally(mode, decrypt_enabled, cert.is_installed());
                if !decrypt_443 {
                    // The gate above is closed - the root certificate is not trusted,
                    // or local decryption is switched off: decrypting here would hand
                    // every client a certificate it rejects, so the listener relays the
                    // connection end to end instead and dials the SNI it reads from the
                    // ClientHello (its own upstream lookup needs no plaintext DNS - the
                    // config above forces DoH).
                    let msg = local_decryption_fallback_warning(
                        DecryptionSite::DnsIntercept443,
                        decrypt_enabled,
                    );
                    log::warn!(target: "wtlite_core::proxy", "{msg}");
                    let _ = log_tx.send(msg.to_string());
                }
                let leaf_cache = Arc::new(crate::cert::LeafCache::default());
                let mut tasks_443 = Vec::new();
                for mitm_listener in listeners_443 {
                    let task = if decrypt_443 {
                        let rt = MitmRuntime {
                            cm: cert.clone(),
                            cache: leaf_cache.clone(),
                            root: root_for_mitm.clone().unwrap_or_else(|| {
                                Arc::new(crate::cert::RootCertificate {
                                    der: Vec::new(),
                                    key_pkcs8: Vec::new(),
                                    not_after: std::time::SystemTime::UNIX_EPOCH,
                                })
                            }),
                            config: intercept_cfg.clone(),
                            stats: stats.clone(),
                            log_tx: log_tx.clone(),
                            forward: forward_arc.clone(),
                            configured_ips: configured_ips_arc.clone(),
                            fake_names: fake_names_arc.clone(),
                            domains: domains_arc.clone(),
                        };
                        tokio::spawn(async move {
                            let _ = run_mitm_on(mitm_listener, rt).await;
                        })
                    } else {
                        let rt = FwdRuntime {
                            config: intercept_cfg.clone(),
                            domains: domains_arc.clone(),
                            stats: stats.clone(),
                            log_tx: log_tx.clone(),
                            mitm: None,
                            forward: forward_arc.clone(),
                            configured_ips: configured_ips_arc.clone(),
                        };
                        tokio::spawn(async move {
                            let _ = run_steered_tunnel_on(mitm_listener, rt).await;
                        })
                    };
                    tasks_443.push(task);
                }
                let fwd_rt = FwdRuntime {
                    config: intercept_cfg,
                    domains: domains_arc.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                    mitm: mitm_rt.clone(),
                    forward: forward_arc.clone(),
                    configured_ips: configured_ips_arc.clone(),
                };
                let task_fwd = tokio::spawn(async move {
                    let _ = run_forward_proxy_on(fwd_listener, fwd_rt).await;
                });
                // Start the WinDivert DNS interceptor on a blocking thread.
                let wd = Arc::new(DnsInterceptRuntime::new(
                    domains_arc.clone(),
                    log_tx.clone(),
                ));
                let stop_flag = wd.stop_flag();
                tokio::task::spawn_blocking({
                    let wd = wd.clone();
                    move || wd.run()
                });
                let mut g = self.inner.lock().unwrap();
                g.tasks.extend(tasks_443);
                g.tasks.push(task_fwd);
                g.windivert_stop = Some(stop_flag);
            }
        }
        Ok(())
    }

    /// Stop the proxy and clean up any side effects.
    pub fn stop(&self) {
        let (mode, _) = {
            let g = self.inner.lock().unwrap();
            (g.mode, g.running)
        };
        self.stop_inner();
        // Clean up per-mode side effects.
        match mode {
            Some(ProxyMode::Hosts) => {
                let _ = hosts::remove_by_tag();
            }
            Some(ProxyMode::System) => {
                let _ = sysproxy::set_system_proxy(false, "", 0);
            }
            Some(ProxyMode::Pac) => {
                let _ = sysproxy::set_pac_proxy(false, "");
            }
            _ => {}
        }
    }

    fn stop_inner(&self) {
        let mut g = self.inner.lock().unwrap();
        if let Some(f) = g.windivert_stop.take() {
            f.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        for t in g.tasks.drain(..) {
            t.abort();
        }
        g.log_tx = None;
        g.running = false;
        g.mode = None;
        g.started_at = None;
        // Drop the manager-owned runtime so its listeners are released too.
        if let Some(rt) = g.runtime.take() {
            Arc::try_unwrap(rt).map(|rt| rt.shutdown_background()).ok();
        }
    }
}

impl Default for ProxyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        collect_fake_names, is_decrypting_mode, leaf_local_alias, leaf_local_ips,
        local_decryption_fallback_warning, manifest_asks_to_ignore_cert, proxy_bind_ip,
        should_decrypt_locally, DecryptionSite,
    };
    use crate::model::{AccelerateProject, AccelerateProjectGroup, ProxyMode, ProxyType};
    use std::net::IpAddr;

    fn loopback() -> IpAddr {
        IpAddr::from([127, 0, 0, 1])
    }

    /// Mirrors `ProxyService.Operate`: the default `0.0.0.0` must not leave the
    /// unauthenticated forward proxy reachable from the LAN on Windows.
    #[test]
    fn a_wildcard_listen_address_is_narrowed_to_loopback() {
        let ip = proxy_bind_ip("0.0.0.0");
        if cfg!(windows) {
            assert_eq!(ip, loopback());
        } else {
            assert!(ip.is_unspecified());
        }
    }

    /// The wildcard test is `is_unspecified`, so IPv6 `::` is narrowed too (the
    /// original only compares `IPAddress.Any`).
    #[test]
    fn an_ipv6_wildcard_listen_address_is_narrowed_to_loopback_too() {
        let ip = proxy_bind_ip("::");
        if cfg!(windows) {
            assert_eq!(ip, loopback());
        } else {
            assert_eq!(ip, IpAddr::from([0u16, 0, 0, 0, 0, 0, 0, 0]));
        }
    }

    /// An explicit address is used as-is (surrounding whitespace is ignored).
    #[test]
    fn an_explicit_listen_address_is_kept() {
        assert_eq!(proxy_bind_ip(" 127.0.0.1 "), loopback());
        assert_eq!(
            proxy_bind_ip("192.168.1.10"),
            IpAddr::from([192, 168, 1, 10])
        );
    }

    /// The setting is free text here (the original binds it to an `IPAddress`),
    /// so an unusable value must fall back to the safe side.
    #[test]
    fn an_unusable_listen_address_falls_back_to_loopback() {
        for text in ["", "   ", "not an ip", "127.0.0.1:26561", "256.0.0.1"] {
            assert_eq!(proxy_bind_ip(text), loopback(), "{text:?}");
        }
    }

    /// A leaf that carries only the fields the manifest lookups read.
    fn leaf(
        pattern: &str,
        fake: Option<&str>,
        enabled: bool,
        ignore_cert: bool,
    ) -> AccelerateProject {
        AccelerateProject {
            three_state_enable: Some(enabled),
            match_domain_names: pattern.to_string(),
            fake_server_name: fake.map(str::to_string),
            ignore_ssl_cert_verification: ignore_cert,
            ..Default::default()
        }
    }

    fn group(enabled: bool, items: Vec<AccelerateProject>) -> AccelerateProjectGroup {
        AccelerateProjectGroup {
            three_state_enable: Some(enabled),
            items,
            ..Default::default()
        }
    }

    /// A local project's `ForwardDomainNames` is an IP when it parses as one,
    /// exactly like the original `IDomainConfig.IPAddress`; otherwise it is the
    /// substitute hostname. A server-accelerated project's value is neither
    /// (Lite cannot use the server backend).
    #[test]
    fn forward_domain_names_are_classified_like_the_original_dto() {
        let mut pinned = leaf("a.com", None, true, false);
        pinned.forward_domain_names = Some(" 1.2.3.4 ".to_string());
        assert_eq!(leaf_local_ips(&pinned), vec![IpAddr::from([1, 2, 3, 4])]);
        assert_eq!(leaf_local_alias(&pinned), None);

        let mut alias = leaf("a.com", None, true, false);
        alias.forward_domain_names = Some(" CDN.Example.NET ".to_string());
        assert!(leaf_local_ips(&alias).is_empty());
        assert_eq!(
            leaf_local_alias(&alias),
            Some("cdn.example.net".to_string())
        );

        let mut both = leaf("a.com", None, true, false);
        both.forward_domain_names = Some("1.2.3.4".to_string());
        both.ip_address = vec![IpAddr::from([1, 2, 3, 4])];
        assert_eq!(
            leaf_local_ips(&both),
            vec![IpAddr::from([1, 2, 3, 4])],
            "the same IP from both manifest shapes must not be duplicated"
        );

        let mut server = leaf("a.com", None, true, false);
        server.proxy_type = ProxyType::ServerAccelerate;
        server.forward_domain_names = Some("https://accelerator.example.net".to_string());
        assert!(leaf_local_ips(&server).is_empty());
        assert_eq!(leaf_local_alias(&server), None);
    }

    /// The startup warning's judgement, now that it is a function of its own:
    /// **any** enabled leaf carrying the flag makes it true; a group or leaf that is
    /// not explicitly enabled is not looked at (`!= Some(true)` rules out both
    /// `None` and `Some(false)`), and the flag is read nowhere else.
    #[test]
    fn the_ignore_certificate_verification_flag_is_read_from_enabled_leaves_only() {
        assert!(!manifest_asks_to_ignore_cert(&[]));
        assert!(!manifest_asks_to_ignore_cert(&[group(
            true,
            vec![leaf("a.com", None, true, false)]
        )]));
        assert!(manifest_asks_to_ignore_cert(&[group(
            true,
            vec![leaf("a.com", None, true, true)]
        )]));
        // The judgement is "any", not "the first one".
        assert!(manifest_asks_to_ignore_cert(&[group(
            true,
            vec![
                leaf("a.com", None, true, false),
                leaf("b.com", None, true, true)
            ]
        )]));
        // An unenabled group, and an unenabled leaf, are both skipped even when the
        // flag is set.
        assert!(!manifest_asks_to_ignore_cert(&[group(
            false,
            vec![leaf("a.com", None, true, true)]
        )]));
        assert!(!manifest_asks_to_ignore_cert(&[group(
            true,
            vec![leaf("a.com", None, false, true)]
        )]));
    }

    /// `collect_fake_names` keeps the manifest loop's aggregation, verbatim - what
    /// the assertion pins is the *existing* behavior, including the parts that are
    /// incidental rather than designed:
    ///
    /// - one entry per `MatchDomainNames` pattern, in manifest order (a group's
    ///   order, then its projects' `all_leaves()` order, then the pattern order);
    /// - `all_leaves()` never yields a project that has children, so a parent's own
    ///   pattern is not collected (only its leaves are);
    /// - pattern and value are trimmed and lowercased, and an empty pattern or an
    ///   empty value is dropped;
    /// - **a repeated pattern yields a repeated entry** (no de-duplication), and
    ///   `only_enable_proxy_script` is not consulted here at all - it gates the
    ///   *read* (`manifest_fake_name_for`), not the build.
    #[test]
    fn collect_fake_names_keeps_the_manifest_loop_aggregation() {
        let groups = vec![
            group(
                true,
                vec![
                    // A project with children contributes only through them.
                    AccelerateProject {
                        three_state_enable: Some(true),
                        match_domain_names: "parent.example.com".to_string(),
                        fake_server_name: Some("parent-cdn.example.net".to_string()),
                        items: vec![leaf(
                            " A.com ;*.B.com",
                            Some(" CDN.Example.NET "),
                            true,
                            false,
                        )],
                        ..Default::default()
                    },
                    leaf("", Some("empty-pattern.example.net"), true, false),
                    leaf("c.com", Some("   "), true, false),
                    leaf("d.com", None, true, false),
                    leaf("e.com", Some("dup.example.net"), true, false),
                    leaf("e.com", Some("dup.example.net"), true, false),
                    leaf("f.com", Some("off-leaf.example.net"), false, false),
                ],
            ),
            group(
                false,
                vec![leaf("g.com", Some("off-group.example.net"), true, false)],
            ),
        ];
        assert_eq!(
            collect_fake_names(&groups),
            vec![
                ("a.com".to_string(), "cdn.example.net".to_string()),
                ("*.b.com".to_string(), "cdn.example.net".to_string()),
                ("e.com".to_string(), "dup.example.net".to_string()),
                ("e.com".to_string(), "dup.example.net".to_string()),
            ]
        );
    }

    /// The judgement every decryption decision point asks, over its whole input
    /// space: mode x local-decryption setting x trust-store probe, all sixteen
    /// combinations spelled out. Two halves matter:
    ///
    /// - with the switch on, `System` / `Pac` / `DnsIntercept` decrypt exactly when
    ///   the probe succeeds - the pre-switch judgement, mode for mode and verbatim,
    ///   so an install that never touches the setting behaves as it did before;
    /// - with the switch off, nothing decrypts, trusted certificate or not.
    #[test]
    fn the_decryption_gate_is_the_mode_the_switch_and_the_trust_store() {
        let table = [
            (ProxyMode::System, true, true, true),
            (ProxyMode::Pac, true, true, true),
            (ProxyMode::DnsIntercept, true, true, true),
            (ProxyMode::System, true, false, false),
            (ProxyMode::Pac, true, false, false),
            (ProxyMode::DnsIntercept, true, false, false),
            (ProxyMode::System, false, true, false),
            (ProxyMode::Pac, false, true, false),
            (ProxyMode::DnsIntercept, false, true, false),
            (ProxyMode::System, false, false, false),
            (ProxyMode::Pac, false, false, false),
            (ProxyMode::DnsIntercept, false, false, false),
            (ProxyMode::Hosts, true, true, false),
            (ProxyMode::Hosts, true, false, false),
            (ProxyMode::Hosts, false, true, false),
            (ProxyMode::Hosts, false, false, false),
        ];
        for (mode, decrypt_enabled, cert_installed, expected) in table {
            assert_eq!(
                should_decrypt_locally(mode, decrypt_enabled, cert_installed),
                expected,
                "{mode:?} / switch={decrypt_enabled} / cert trusted={cert_installed}"
            );
        }
    }

    /// The listener set the gate is read with, pinned including the mode that is
    /// **not** in it: `Hosts` decrypts its 443 listener unconditionally, so the
    /// switch cannot reach it (registered legacy, unchanged by this round).
    #[test]
    fn the_decrypting_listener_set_excludes_hosts_mode() {
        assert!(is_decrypting_mode(ProxyMode::System));
        assert!(is_decrypting_mode(ProxyMode::Pac));
        assert!(is_decrypting_mode(ProxyMode::DnsIntercept));
        assert!(!is_decrypting_mode(ProxyMode::Hosts));
    }

    /// The warning must name the reason it fell back, per listener. With the
    /// switch on it is the wording that existed before the switch did - asserted
    /// verbatim here, not merely "some message", because that text is what a user
    /// with an installed-but-untrusted root sees today. With the switch off the
    /// text must not blame the certificate, and must say that the setting is read
    /// at startup (so a change needs a restart).
    #[test]
    fn the_fallback_warning_tells_a_certificate_problem_from_a_disabled_switch() {
        let certificate_untrusted = [
            (
                DecryptionSite::SystemOrPacForward,
                "根证书未被系统信任：PAC / 系统代理模式的 TLS 不再本地解密，退回裸隧道（加速域名的 SNI 指定与上游证书校验不可用）。若刚刚安装证书，请重启本程序后生效。",
            ),
            (
                DecryptionSite::DnsInterceptForward,
                "根证书未被系统信任：DNS 拦截模式的转发监听不再本地解密，退回裸隧道（加速域名的 SNI 指定与上游证书校验不可用）。若刚刚安装证书，请重启本程序后生效。",
            ),
            (
                DecryptionSite::DnsIntercept443,
                "根证书未被系统信任：DNS 拦截模式的 443 不再本地解密，退回裸中继（按 ClientHello 的 SNI 拨号，端到端 TLS）。若刚刚安装证书，请重启本程序后生效。",
            ),
        ];
        for (site, wording) in certificate_untrusted {
            assert_eq!(
                local_decryption_fallback_warning(site, true),
                wording,
                "{site:?}"
            );
            let disabled = local_decryption_fallback_warning(site, false);
            assert_ne!(disabled, wording, "{site:?}");
            assert!(
                disabled.contains("已在设置中关闭本地 TLS 解密"),
                "{site:?}: {disabled}"
            );
            assert!(
                !disabled.contains("根证书未被系统信任"),
                "{site:?}: {disabled}"
            );
            assert!(
                disabled.contains("该开关在启动时读取，修改后需重启本程序生效"),
                "{site:?}: {disabled}"
            );
        }
    }
}
