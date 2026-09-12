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
}

impl FwdRuntime {
    pub fn send_log(&self, msg: String) {
        let _ = self.log_tx.send(msg);
    }
}

/// Start the forward proxy listener.
pub async fn run_forward_proxy(bind: SocketAddr, rt: FwdRuntime) -> Result<(), String> {
    let listener = TcpListener::bind(bind).await.map_err(|e| format!("bind {bind} failed: {e}"))?;
    rt.send_log(format!("Forward proxy listening on {bind}"));
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

async fn handle_conn(mut tcp: TcpStream, rt: FwdRuntime) -> Result<(), String> {
    let mut buf = [0u8; 4096];
    let n = tcp.peek(&mut buf).await.map_err(|e| e.to_string())?;
    if n < 4 {
        return Ok(());
    }
    let head = String::from_utf8_lossy(&buf[..n]).to_string();
    let first_line = head.lines().next().unwrap_or("").to_string();
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();

    if method.eq_ignore_ascii_case("CONNECT") {
        return handle_connect(tcp, &target, &rt).await;
    }
    if method.eq_ignore_ascii_case("GET")
        && (target.starts_with("/proxy.pac") || target == "/" || target.starts_with("/pac"))
    {
        return serve_pac(&mut tcp, &rt).await;
    }
    if (method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("POST"))
        && target.starts_with("http")
    {
        return handle_http(&mut tcp, &target, &rt).await;
    }
    let _ = tcp
        .write_all(b"HTTP/1.1 400 Bad Request
Content-Length: 0
Connection: close

")
        .await;
    Ok(())
}

/// CONNECT tunnel: reply 200, then relay bytes to the upstream.
async fn handle_connect(mut tcp: TcpStream, target: &str, rt: &FwdRuntime) -> Result<(), String> {
    let (host, port) = match parse_host_port(target) {
        Some(v) => v,
        None => {
            let _ = tcp
                .write_all(b"HTTP/1.1 400 Bad Request
Content-Length: 0

")
                .await;
            return Ok(());
        }
    };
    let cfg = rt.config.read().unwrap().clone();
    let domains = rt.domains.read().unwrap().clone();
    let ips = if domains.contains(&host.to_lowercase()) {
        dns::resolve_a(&host, &cfg.proxy_master_dns, cfg.use_doh, &cfg.custom_doh_address).await
    } else {
        Vec::new()
    };
    let upstream = match http1::connect_upstream(&host, port, &ips).await {
        Some(s) => s,
        None => {
            let _ = tcp
                .write_all(b"HTTP/1.1 502 Bad Gateway
Content-Length: 0

")
                .await;
            return Ok(());
        }
    };
    tcp.write_all(b"HTTP/1.1 200 Connection Established

")
        .await
        .map_err(|e| e.to_string())?;
    rt.send_log(format!("[TUNNEL] CONNECT {host}:{port}"));
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
async fn serve_pac(tcp: &mut TcpStream, rt: &FwdRuntime) -> Result<(), String> {
    let cfg = rt.config.read().unwrap().clone();
    let domains = rt.domains.read().unwrap().clone();
    let pac = crate::sysproxy::create_pac(
        &format!("{}:{}", cfg.system_proxy_ip, cfg.system_proxy_port),
        &domains.iter().cloned().collect::<Vec<_>>(),
    );
    let body = pac.as_bytes();
    let head = format!(
        "HTTP/1.1 200 OK
Content-Type: application/x-ns-proxy-autoconfig
Content-Length: {}
Connection: close

",
        body.len()
    );
    tcp.write_all(head.as_bytes()).await.map_err(|e| e.to_string())?;
    tcp.write_all(body).await.map_err(|e| e.to_string())?;
    tcp.flush().await.ok();
    Ok(())
}

/// Absolute-URI HTTP request: read the full request, forward to the origin.
async fn handle_http(tcp: &mut TcpStream, _target: &str, rt: &FwdRuntime) -> Result<(), String> {
    let req = match http1::read_request(tcp).await {
        Some(r) => r,
        None => return Ok(()),
    };
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
    let ips = if domains.contains(&host.to_lowercase()) {
        dns::resolve_a(&host, &cfg.proxy_master_dns, cfg.use_doh, &cfg.custom_doh_address).await
    } else {
        Vec::new()
    };
    let upstream = match http1::connect_upstream(&host, port, &ips).await {
        Some(s) => s,
        None => {
            let _ = tcp
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway
Content-Length: 0
Connection: close

",
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
