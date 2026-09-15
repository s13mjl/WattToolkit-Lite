//! Forward proxy (System / PAC mode), mirroring the original forward-proxy
//! behavior: CONNECT tunneling to the (accelerated-resolved) upstream,
//! absolute-URI HTTP forwarding, and a PAC endpoint at /proxy.pac.

use crate::dns;
use crate::http1;
use crate::settings::ProxySettings;
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Shared runtime state for the forward proxy.
#[derive(Clone)]
pub struct FwdRuntime {
    pub config: Arc<RwLock<ProxySettings>>,
    /// Acceleration domains (lowercase). If a CONNECT target is in this set,
    /// the upstream is resolved via the configured DNS strategy.
    pub domains: Arc<RwLock<HashSet<String>>>,
    pub stats: Arc<Mutex<crate::proxy::FlowStats>>,
    pub log_tx: tokio::sync::mpsc::UnboundedSender<String>,
    /// Present when TLS termination is available (certificate ready). CONNECT
    /// requests for hosts with a substitute hostname are then MITM'd instead of
    /// being tunnelled, so the upstream SNI can differ from the requested host.
    pub mitm: Option<Arc<crate::mitm::MitmRuntime>>,
    /// Hosts dialled through a substitute hostname.
    pub forward: Arc<RwLock<std::collections::HashMap<String, String>>>,
}

impl FwdRuntime {
    pub fn send_log(&self, msg: String) {
        // Mirror to the terminal as well as the in-app log panel, so the same
        // events are visible from a console run.
        log::info!(target: "wtlite_core::proxy", "{msg}");
        let _ = self.log_tx.send(msg);
    }
}

/// Start the forward proxy listener.
pub async fn run_forward_proxy(bind: SocketAddr, rt: FwdRuntime) -> Result<(), String> {
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|e| format!("bind {bind} failed: {e}"))?;
    run_forward_proxy_on(listener, rt).await
}

/// Run the accept loop on an already-bound listener (binding is done by the
/// caller so startup errors surface before the UI reports "running").
pub async fn run_forward_proxy_on(listener: TcpListener, rt: FwdRuntime) -> Result<(), String> {
    let local = listener
        .local_addr()
        .map_err(|e| format!("local_addr failed: {e}"))?;
    rt.send_log(format!("Forward proxy listening on {local}"));
    loop {
        match listener.accept().await {
            Ok((tcp, _peer)) => {
                let rt = rt.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(tcp, rt).await {
                        log::debug!("forward conn error: {e}");
                    }
                });
            }
            Err(e) => rt.send_log(format!("listener error: {e}")),
        }
    }
}

/// Read the request head exactly once and dispatch.
///
/// The request head must be consumed here (not merely peeked) and handed to the
/// handler: re-reading it later would block whenever a client pipelines another
/// request or delivers the head in several TCP segments, which makes browsers
/// retry the PAC fetch forever.
async fn handle_conn(mut tcp: TcpStream, rt: FwdRuntime) -> Result<(), String> {
    let req = match http1::read_request(&mut tcp).await {
        Some(r) => r,
        None => return Ok(()),
    };
    let method = req.method.clone();
    let target = req.path.clone();

    if method.eq_ignore_ascii_case("CONNECT") {
        return handle_connect(tcp, &target, &rt).await;
    }
    if method.eq_ignore_ascii_case("GET")
        && (target.starts_with("/proxy.pac")
            || target == "/"
            || target.starts_with("/pac")
            || is_pac_absolute_path(&target))
    {
        return serve_pac(&mut tcp, &req, &rt).await;
    }
    if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("POST") {
        return handle_http(&mut tcp, req, &rt).await;
    }
    let _ = tcp
        .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await;
    Ok(())
}

/// CONNECT tunnel: reply 200, then relay bytes to the upstream.
async fn handle_connect(mut tcp: TcpStream, target: &str, rt: &FwdRuntime) -> Result<(), String> {
    let (host, port) = match parse_host_port(target) {
        Some(v) => v,
        None => {
            let _ = tcp
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Ok(());
        }
    };
    // Answer the CONNECT immediately, exactly like the original
    // HttpProxyMiddleware does (`AdvanceTo(consumed)` then write 200) before
    // TunnelMiddleware connects upstream. Connecting first would leave the
    // browser waiting for the CONNECT response while DNS resolution and the
    // per-candidate connect timeouts run, so it would give up and the tunnel
    // would never be established.
    tcp.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|e| e.to_string())?;
    // Hosts that must be dialled through a substitute hostname are decrypted
    // here instead of tunnelled: the browser only trusts a certificate for the
    // host it requested, so TLS has to end locally before we can reach upstream
    // with a different SNI (the original `ForwardDestination` + `TlsSni`).
    let needs_substitution = port == 443
        && rt
            .forward
            .read()
            .unwrap()
            .contains_key(&host.to_lowercase());
    if needs_substitution {
        if let Some(mitm) = rt.mitm.clone() {
            rt.send_log(format!("[TUNNEL] CONNECT {host}:{port} (mitm/subst)"));
            return crate::mitm::handle_tunnel(tcp, (*mitm).clone()).await;
        }
    }
    rt.send_log(format!("[TUNNEL] CONNECT {host}:{port}"));

    let cfg = rt.config.read().unwrap().clone();
    let domains = rt.domains.read().unwrap().clone();
    let accelerated = is_accelerated(&host, &domains);
    // Accelerated domains resolve through the configured DoH/plain DNS; the
    // rest keep using the system resolver (mirrors DomainResolver.ResolveAsync).
    let ips = if accelerated {
        dns::resolve_a(&host, &cfg.proxy_master_dns, cfg.use_doh, &cfg.custom_doh_address).await
    } else {
        Vec::new()
    };
    let upstream = match http1::connect_upstream(&host, port, &ips).await {
        Some(s) => s,
        None => {
            rt.send_log(format!("[TUNNEL] upstream connect failed: {host}:{port}"));
            return Ok(());
        }
    };
    let (mut c_r, mut c_w) = tcp.into_split();
    let (mut u_r, mut u_w) = upstream.into_split();
    relay(&mut c_r, &mut c_w, &mut u_r, &mut u_w).await;
    Ok(())
}

/// Relay bytes between two (read, write) stream pairs until either side closes.
async fn relay<
    R1: AsyncReadExt + Unpin,
    W1: AsyncWriteExt + Unpin,
    R2: AsyncReadExt + Unpin,
    W2: AsyncWriteExt + Unpin,
>(
    r1: &mut R1,
    w1: &mut W1,
    r2: &mut R2,
    w2: &mut W2,
) {
    let mut buf1 = vec![0u8; 16 * 1024];
    let mut buf2 = vec![0u8; 16 * 1024];
    loop {
        let (n, from_client) = tokio::select! {
            a = r1.read(&mut buf1) => match a {
                Ok(0) => return,
                Ok(n) => (n, true),
                Err(_) => return,
            },
            b = r2.read(&mut buf2) => match b {
                Ok(0) => return,
                Ok(n) => (n, false),
                Err(_) => return,
            },
        };
        if from_client {
            if w2.write_all(&buf1[..n]).await.is_err() {
                return;
            }
        } else {
            if w1.write_all(&buf2[..n]).await.is_err() {
                return;
            }
        }
    }
}

/// Domain match mirroring the original
/// `ReverseProxyHttpClientHandler.IsMatch(dnsName, domain)`: exact match, or
/// a leading `*` wildcard matching any sub-domain suffix.
fn domain_matches(pattern: &str, host: &str) -> bool {
    let p = pattern.trim().to_lowercase();
    let h = host.trim().to_lowercase();
    if p.is_empty() || h.is_empty() {
        return false;
    }
    if p == h {
        return true;
    }
    if p.starts_with('*') {
        // Mirror the original ReverseProxyHttpClientHandler.IsMatch:
        // domain.EndsWith(dnsName[1..]) — no length restriction, so
        // `*.example.com` matches both `example.com` and any subdomain.
        let suffix = p[1..].trim_start_matches('.');
        return h.ends_with(suffix);
    }
    false
}

/// True when the host matches any enabled acceleration domain pattern.
fn is_accelerated(host: &str, domains: &HashSet<String>) -> bool {
    let host = host.to_lowercase();
    domains.iter().any(|d| domain_matches(d, &host))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn wildcard_matching() {
        let mut domains = HashSet::new();
        domains.insert("*.pdx01.abs.hls.ttvnw.net".to_string());
        domains.insert("store.steampowered.com".to_string());
        assert!(is_accelerated("video-edge-1.pdx01.abs.hls.ttvnw.net", &domains));
        assert!(is_accelerated("store.steampowered.com", &domains));
        assert!(!is_accelerated("store.steamstatic.com", &domains));
        assert!(!is_accelerated("example.com", &domains));
        assert!(domain_matches("*.st.dl.eccdnx.com", "a.b.st.dl.eccdnx.com"));
        assert!(domain_matches("*.st.dl.eccdnx.com", "st.dl.eccdnx.com"));
        assert!(!domain_matches("*.st.dl.eccdnx.com", "st.dl.eccdnx.org"));
    }
}

/// True when an absolute-URI request targets the PAC endpoint
/// (e.g. `GET http://127.0.0.1:{port}/pac HTTP/1.1`).
fn is_pac_absolute_path(target: &str) -> bool {
    if let Some(rest) = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))
    {
        if let Some(i) = rest.find('/') {
            let path = &rest[i..];
            return path.starts_with("/pac") || path.starts_with("/proxy.pac");
        }
    }
    false
}

fn parse_host_port(target: &str) -> Option<(String, u16)> {
    let t = target.trim().trim_end_matches('/');
    match t.rsplit_once(':') {
        Some((host, port)) => {
            let p: u16 = port.trim().parse().ok()?;
            Some((host.to_string(), p))
        }
        None => Some((t.to_string(), 443)),
    }
}

/// Serve the PAC file.
///
/// The PROXY host in the PAC mirrors the original
/// `HttpProxyPacMiddleware.CreateProxyPac`, which uses the client-facing
/// request Host (`context.Request.Host`) so the browser can reach the local
/// forward proxy. Fall back to `127.0.0.1:{port}` when no Host header is
/// present (the PAC URL always points at 127.0.0.1).
async fn serve_pac(
    tcp: &mut TcpStream,
    req: &http1::HttpRequest,
    rt: &FwdRuntime,
) -> Result<(), String> {
    let cfg = rt.config.read().unwrap().clone();
    let domains = rt.domains.read().unwrap().clone();
    let host_hdr = req.header("Host").unwrap_or("").trim().to_string();
    let proxy_host = if host_hdr.is_empty() {
        format!("127.0.0.1:{}", cfg.system_proxy_port)
    } else {
        host_hdr
    };
    let pac = crate::sysproxy::create_pac(
        &proxy_host,
        &domains.iter().cloned().collect::<Vec<_>>(),
    );
    let body = pac.as_bytes();
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Disposition: attachment;filename=proxy.pac\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tcp.write_all(head.as_bytes()).await.map_err(|e| e.to_string())?;
    tcp.write_all(body).await.map_err(|e| e.to_string())?;
    tcp.flush().await.ok();
    Ok(())
}

/// Absolute-URI HTTP request: read the full request, forward to the origin.
async fn handle_http(
    tcp: &mut TcpStream,
    req: http1::HttpRequest,
    rt: &FwdRuntime,
) -> Result<(), String> {
    let uri = req.path.trim();
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"));
    let (host, port) = match rest {
        Some(r) => {
            let hostpart = r.split('/').next().unwrap_or("").to_string();
            parse_host_port(&hostpart).unwrap_or_else(|| (hostpart.clone(), 80))
        }
        None => return Ok(()),
    };
    let path = match rest {
        Some(r) => match r.find('/') {
            Some(i) => r[i..].to_string(),
            None => "/".to_string(),
        },
        None => return Ok(()),
    };
    let mut req2 = req.clone();
    req2.path = path;

    let cfg = rt.config.read().unwrap().clone();
    let domains = rt.domains.read().unwrap().clone();
    let ips = if is_accelerated(&host, &domains) {
        dns::resolve_a(&host, &cfg.proxy_master_dns, cfg.use_doh, &cfg.custom_doh_address).await
    } else {
        Vec::new()
    };
    let upstream = match http1::connect_upstream(&host, port, &ips).await {
        Some(s) => s,
        None => {
            let _ = tcp
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return Ok(());
        }
    };
    let (mut u_r, mut u_w) = upstream.into_split();
    let wire = http1::write_request(&req2, &host, port, false);
    if u_w.write_all(&wire).await.is_err() || u_w.flush().await.is_err() {
        return Ok(());
    }
    let head = match http1::read_response_head(&mut u_r).await {
        Some(h) => h,
        None => return Ok(()),
    };
    rt.send_log(format!("[HTTP] {} {host}:{port} -> {}", req.method, head.status));
    let _keep = http1::stream_response_body(&mut u_r, tcp, &head).await.unwrap_or(false);
    Ok(())
}
