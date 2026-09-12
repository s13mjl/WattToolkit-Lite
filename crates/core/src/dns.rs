//! DNS resolution, mirroring the original DnsAnalysisService / DomainResolver.
//!
//! Supports DNS-over-HTTPS (DoH) and plain local/UDP DNS, with a switch that
//! picks the strategy based on proxy mode (mirrors DnsAnalysisServiceSwitchImpl).

use serde_json::Value;
use std::net::IpAddr;
use std::time::{Duration, Instant};

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

/// Resolve a hostname to IPv4 addresses.
pub async fn resolve_a(host: &str, dns: &str, use_doh: bool, doh_address: &str) -> Vec<IpAddr> {
    if use_doh && !doh_address.is_empty() {
        return resolve_doh(host, doh_address).await;
    }
    let server: Option<IpAddr> = dns
        .trim()
        .parse::<IpAddr>()
        .ok()
        .filter(|_| dns.trim() != "System Default");
    resolve_udp(host, server).await
}

/// Resolve via DNS-over-HTTPS (JSON API), mirroring DnsDohAnalysisService.
pub async fn resolve_doh(host: &str, doh_address: &str) -> Vec<IpAddr> {
    let url = format!(
        "{}?name={}&type=A",
        doh_address.trim_end_matches('/'),
        urlencoding(host)
    );
    let config = ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(5)))
        .build();
    let agent: ureq::Agent = config.into();
    let body: Result<Value, String> = (|| {
        let mut resp = agent.get(&url).call().map_err(|e| e.to_string())?;
        let text = resp.body_mut().read_to_string().map_err(|e| e.to_string())?;
        serde_json::from_str(&text).map_err(|e| e.to_string())
    })();
    match body {
        Ok(v) => v
            .get("Answer")
            .and_then(|a| a.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|a| a.get("type").and_then(|t| t.as_i64()) == Some(1))
                    .filter_map(|a| a.get("data").and_then(|d| d.as_str()))
                    .filter_map(|d| d.parse::<IpAddr>().ok())
                    .collect::<Vec<IpAddr>>()
            })
            .unwrap_or_default(),
        Err(e) => {
            log::warn!("DoH resolve failed for {}: {}", host, e);
            Vec::new()
        }
    }
}

/// Resolve via plain UDP DNS query (or system resolver when no server).
pub async fn resolve_udp(host: &str, server: Option<IpAddr>) -> Vec<IpAddr> {
    let host = host.to_string();
    let result = tokio::task::spawn_blocking(move || -> Vec<IpAddr> {
        if let Some(srv) = server {
            match dns_query_a(&host, srv) {
                Ok(ips) => ips,
                Err(e) => {
                    log::warn!("UDP DNS resolve failed for {} via {}: {}", host, srv, e);
                    Vec::new()
                }
            }
        } else {
            match std::net::ToSocketAddrs::to_socket_addrs(&(host.as_str(), 443u16)) {
                Ok(addrs) => addrs
                    .map(|a| a.ip())
                    .filter(|ip| matches!(ip, IpAddr::V4(_)))
                    .collect(),
                Err(e) => {
                    log::warn!("System resolve failed for {}: {}", host, e);
                    Vec::new()
                }
            }
        }
    })
    .await
    .unwrap_or_default();
    result
}

/// Minimal DNS A-record query over UDP.
fn dns_query_a(host: &str, server: IpAddr) -> Result<Vec<IpAddr>, String> {
    use std::net::UdpSocket;

    let mut buf = [0u8; 512];
    let packet = build_a_query(host, &mut buf)?;

    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    let target = match server {
        IpAddr::V4(v4) => std::net::SocketAddr::new(std::net::IpAddr::V4(v4), 53),
        IpAddr::V6(v6) => std::net::SocketAddr::new(std::net::IpAddr::V6(v6), 53),
    };
    sock.send_to(packet, target).map_err(|e| e.to_string())?;
    let (n, _) = sock.recv_from(&mut buf).map_err(|e| e.to_string())?;
    parse_a_response(&buf[..n])
}

/// Build a DNS A query packet.
fn build_a_query<'a>(host: &str, buf: &'a mut [u8]) -> Result<&'a [u8], String> {
    let mut w = 0usize;
    let id: u16 = 0x1234;
    buf[w] = (id >> 8) as u8; w += 1;
    buf[w] = (id & 0xff) as u8; w += 1;
    buf[w] = 0x01; w += 1; // RD
    buf[w] = 0x00; w += 1;
    buf[w] = 0x00; w += 1; buf[w] = 0x01; w += 1; // QDCOUNT=1
    buf[w] = 0x00; w += 1; buf[w] = 0x00; w += 1; // ANCOUNT
    buf[w] = 0x00; w += 1; buf[w] = 0x00; w += 1; // NSCOUNT
    buf[w] = 0x00; w += 1; buf[w] = 0x00; w += 1; // ARCOUNT
    for label in host.split('.') {
        if w >= buf.len() { return Err("packet too large".into()); }
        buf[w] = label.len() as u8; w += 1;
        for b in label.bytes() {
            if w >= buf.len() { return Err("packet too large".into()); }
            buf[w] = b; w += 1;
        }
    }
    if w >= buf.len() { return Err("packet too large".into()); }
    buf[w] = 0x00; w += 1;
    buf[w] = 0x00; w += 1; buf[w] = 0x01; w += 1; // QTYPE=A
    buf[w] = 0x00; w += 1; buf[w] = 0x01; w += 1; // QCLASS=IN
    Ok(&buf[..w])
}

/// Parse A records from a DNS response.
fn parse_a_response(buf: &[u8]) -> Result<Vec<IpAddr>, String> {
    if buf.len() < 12 { return Err("short packet".into()); }
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut i = 12usize;
    while i < buf.len() && buf[i] != 0 {
        let len = buf[i] as usize;
        i += 1 + len;
    }
    i += 5;
    let mut out = Vec::new();
    for _ in 0..ancount {
        if i >= buf.len() { break; }
        if buf[i] & 0xC0 == 0xC0 {
            i += 2;
        } else {
            while i < buf.len() && buf[i] != 0 {
                let len = buf[i] as usize;
                i += 1 + len;
            }
            i += 1;
        }
        if i + 10 > buf.len() { break; }
        let rtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let rdlen = u16::from_be_bytes([buf[i + 8], buf[i + 9]]) as usize;
        i += 10;
        if rtype == 1 && rdlen == 4 && i + 4 <= buf.len() {
            out.push(IpAddr::from([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]));
        }
        i += rdlen;
    }
    Ok(out)
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
