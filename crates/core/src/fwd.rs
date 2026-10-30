//! Forward proxy (System / PAC mode), mirroring the original forward-proxy
//! behavior: CONNECT tunneling to the (accelerated-resolved) upstream,
//! absolute-URI HTTP forwarding, and a PAC endpoint at /proxy.pac.

use crate::dns;
use crate::http1;
use crate::model::ExternalProxyType;
use crate::settings::ProxySettings;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Manifest-configured upstream addresses (original
/// `ReverseProxyConfig.IPAddress`): host pattern -> addresses, in manifest order.
pub type ConfiguredIps = Arc<RwLock<Vec<(String, Vec<IpAddr>)>>>;

/// Manifest-configured substitute upstream names (original
/// `ReverseProxyConfig.FakeServerName`): host pattern -> name, in manifest order
/// (the first pattern matching the host wins, exactly like `ConfiguredIps`).
///
/// When one is configured it is the name presented to the upstream as the TLS SNI
/// instead of the requested host - the explicit form of the substitution that the
/// `ForwardDestination` alias only implies.
pub type FakeNames = Arc<RwLock<Vec<(String, String)>>>;

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
    /// Manifest-configured upstream addresses (original
    /// `ReverseProxyConfig.IPAddress`), kept in manifest order: the first pattern
    /// matching the requested host wins (`domain_matches`, so `*.x.com` keys are
    /// honoured). They lead the candidate sequence, but the TLS handshake still
    /// decides whether an address is usable.
    pub configured_ips: ConfiguredIps,
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
                // Disable Nagle on the client side too: the relay writes whole
                // buffers, and Nagle only added latency here (see http1.rs).
                let _ = tcp.set_nodelay(true);
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

/// Start the DNS-interception 443 listener in bare-tunnel mode.
///
/// `DnsIntercept` steers accelerated domains to `127.0.0.1`, so this listener
/// serves the clients the hook sent here. Decrypting them is only sound while the
/// system trusts the root certificate; with the gate closed the connection is
/// relayed end to end instead - the same trade-off PAC / System mode makes. The
/// listener stays bound either way, because an OS cache can still hold the
/// `127.0.0.1` answer from a previous run and keep steering clients here.
///
/// Binding is done by the caller so startup failures surface before the UI reports
/// "running".
pub async fn run_steered_tunnel_on(listener: TcpListener, rt: FwdRuntime) -> Result<(), String> {
    let local = listener
        .local_addr()
        .map_err(|e| format!("local_addr failed: {e}"))?;
    rt.send_log(format!(
        "443 裸中继监听 {local}（根证书未被系统信任：按 ClientHello 的 SNI 拨号，端到端 TLS）"
    ));
    loop {
        match listener.accept().await {
            Ok((tcp, _peer)) => {
                // Disable Nagle on the client side too, like the forward proxy:
                // the relay writes whole buffers (see http1.rs).
                let _ = tcp.set_nodelay(true);
                let rt = rt.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_steered_tunnel(tcp, rt).await {
                        log::debug!("steered tunnel error: {e}");
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
    // The original `HttpProxyPacMiddleware` answers **every** request whose
    // target is not an absolute URI (`ProxyProtocol.None`) with the PAC file -
    // it tests neither the path nor the method - while a proxied absolute PAC
    // fetch keeps its own branch below. Everything absolute is forwarded.
    if !is_absolute_http_target(&target) || is_pac_absolute_path(&target) {
        return serve_pac(&mut tcp, &req, &rt).await;
    }
    // Every absolute-form request is forwarded, whatever its method: the
    // original Kestrel/YARP pipeline has no method allowlist, and a proxy that
    // answered PUT/PATCH/DELETE/OPTIONS with 400 would break APIs that use them.
    handle_http(&mut tcp, req, &rt).await
}

/// CONNECT tunnel: reply 200, then either terminate TLS locally or relay bytes
/// to the upstream (the original `HttpProxyMiddleware → UseTls →
/// TunnelMiddleware` chain).
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
    // `0x16 0x03` is the TLS handshake record the original `TlsInvadeMiddleware`
    // looks for: such a connection is decrypted here instead of tunnelled, which
    // is what gives the upstream SNI control, upstream certificate verification
    // and endpoint fallback. Only a non-TLS tunnel is relayed verbatim, exactly
    // as `TunnelMiddleware` does.
    let head = peek_client_head(&tcp).await;
    if head.len() == 2 && head[0] == 0x16 && head[1] == 0x03 {
        match rt.mitm.clone() {
            Some(mitm) => {
                rt.send_log(format!("[TUNNEL] CONNECT {host}:{port} (mitm/tls)"));
                return crate::mitm::handle_tunnel(tcp, port, (*mitm).clone()).await;
            }
            // No trusted certificate: decrypting here would hand the browser a
            // certificate it rejects, so the tunnel stays end to end.
            None => rt.send_log(format!(
                "[TUNNEL] CONNECT {host}:{port} (tls, root cert not trusted -> tunnel)"
            )),
        }
    }
    rt.send_log(format!("[TUNNEL] CONNECT {host}:{port}"));

    let upstream = match dial_tunnel_upstream(&host, port, rt).await {
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

/// The upstream dial sequence both TLS entry points share: the CONNECT tunnel
/// (`handle_connect`) and the DNS-interception bare tunnel (`handle_steered_tunnel`).
///
/// Moved here verbatim from `handle_connect` so the two paths cannot drift apart:
/// the acceptance for this change is "identical to PAC with the gate closed", and
/// this is the sequence the later SNI/agent items touch. `host` arrives as a
/// borrow and is shadowed as an owned name, which is the only shim the move needs.
/// `None` means every candidate failed.
async fn dial_tunnel_upstream(host: &str, port: u16, rt: &FwdRuntime) -> Option<TcpStream> {
    let host = host.to_string();
    let cfg = rt.config.read().unwrap().clone();
    let domains = rt.domains.read().unwrap().clone();
    let accelerated = is_accelerated(&host, &domains);
    // Manifest-configured addresses of the *requested* host (the original looks
    // `ReverseProxyConfig.IPAddress` up by the request host, not by the alias):
    // the first segment of `GetIPEndPointsAsync`, ahead of the alias answers.
    let preferred: Vec<IpAddr> =
        manifest_ips_for(&cfg, &rt.configured_ips.read().unwrap(), &host).to_vec();
    // `ForwardDestination`: a host that must be dialled through a substitute
    // hostname keeps doing so on this path too. The alias is only a dial target -
    // the TLS session still runs between the browser and the alias (the browser's
    // SNI is the requested host, which is what the alias serves) - so a host whose
    // certificate is not trusted is tunnelled through its alias rather than
    // straight to the poisoned IP of the blocked name.
    let alias: Option<String> = {
        let table = rt.forward.read().unwrap();
        manifest_forward_for(&cfg, &table, &host).map(str::to_string)
    };
    let dial_host = alias.clone().unwrap_or_else(|| host.clone());
    // Accelerated domains resolve through the configured DoH/plain DNS; the rest
    // keep using the system resolver (mirrors DomainResolver.ResolveAsync).
    let mut addrs = Vec::new();
    if accelerated || alias.is_some() {
        let ips = dns::resolve_a(
            &dial_host,
            &cfg.proxy_master_dns,
            cfg.use_doh,
            &cfg.custom_doh_address,
        )
        .await;
        rt.send_log(format!("[TUNNEL] {dial_host}:{port} resolved to {ips:?}"));
        addrs = http1::candidate_endpoints(&preferred, port, &ips);
    }
    // Ordered endpoint sequence, tried one by one (each under its own timeout)
    // until one accepts the connection. With the second-level agent on, that
    // sequence is not dialled at all: the tunnel is established through the agent
    // (mirroring `ConnectCallback`, which hands every dial to the proxy), and the
    // alias fallback below then offers the host's own name as the target.
    if let Some(agent) = agent_config(&cfg) {
        rt.send_log(format!(
            "[TUNNEL] {dial_host}:{port} via agent {}://{}:{}",
            agent.proxy_type.as_scheme(),
            agent.host,
            agent.port
        ));
    }
    let mut upstream = dial_upstream(&cfg, &addrs, &dial_host, port).await;
    if upstream.is_none() && alias.is_some() && accelerated {
        // The alias endpoints are exhausted: fall back to the host's own
        // endpoints, in the order `GetIPEndPointsAsync` yields them (alias first,
        // then the name itself) and matching the fallback the MITM path performs.
        // The configured addresses are not repeated here: they were already the
        // head of the attempt above, exactly as the original yields `IPAddress`
        // once for the whole sequence.
        let ips = dns::resolve_a(
            &host,
            &cfg.proxy_master_dns,
            cfg.use_doh,
            &cfg.custom_doh_address,
        )
        .await;
        rt.send_log(format!(
            "[TUNNEL] {dial_host} failed, retrying {host}: {ips:?}"
        ));
        let fallback: Vec<SocketAddr> = http1::candidate_endpoints(&[], port, &ips)
            .into_iter()
            .filter(|a| !addrs.contains(a))
            .collect();
        upstream = dial_upstream(&cfg, &fallback, &host, port).await;
    }
    // The manifest knows nothing about this host: the original `TunnelMiddleware`
    // hands such a `ConnectHost` to `TcpClient.ConnectAsync(new DnsEndPoint(host,
    // port))`, i.e. the OS resolver - the same branch that covers an IP literal
    // (`IPAddress.TryParse` -> `IPEndPoint`), which `ToSocketAddrs` also handles
    // without a lookup. Only reached when the manifest is silent, the host has no
    // alias and the agent is off: an accelerated host keeps the DoH-first
    // resolver, and with the agent on every dial goes through it (P1-7b).
    if upstream.is_none() && !accelerated && alias.is_none() && agent_config(&cfg).is_none() {
        rt.send_log(format!(
            "[TUNNEL] {host}:{port} is not in the manifest, dialling it by name"
        ));
        upstream = dial_by_name(&host, port).await;
    }
    upstream
}

/// Handle one connection the DNS hook steered to `127.0.0.1:443` while the root
/// certificate is not trusted by the system.
///
/// The dial target is the `ClientHello` SNI, read with `peek` so the bytes stay
/// queued and reach the upstream untouched: TLS then runs between the client and
/// the real server, whose certificate the client itself verifies. Nothing is
/// decrypted here, so an untrusted root CA - which would make every decrypted
/// connection fail with a certificate error - cannot break the connection.
async fn handle_steered_tunnel(tcp: TcpStream, rt: FwdRuntime) -> Result<(), String> {
    // A peer that opens the connection and stalls must not hold the task open
    // forever: the same connect budget every dial uses bounds the peek.
    let sni = tokio::time::timeout(http1::CONNECT_TIMEOUT, peek_client_sni(&tcp))
        .await
        .ok()
        .flatten();
    let Some(host) = sni else {
        rt.send_log(
            "443 裸中继：未取到 ClientHello 的 SNI，无法确定拨号目标，关闭连接".to_string(),
        );
        return Ok(());
    };
    rt.send_log(format!(
        "[TUNNEL] 443 (tls, root cert not trusted -> bare tunnel) sni={host}"
    ));
    relay_bare(tcp, &host, 443, &rt).await;
    Ok(())
}

/// Dial `host:port` through the shared sequence and relay the bytes verbatim.
///
/// Split out of `handle_steered_tunnel` so the port is an argument: the listener
/// passes 443 (what the steered client connected to), which is also what an
/// offline test needs to point at a loopback stand-in upstream.
async fn relay_bare(tcp: TcpStream, host: &str, port: u16, rt: &FwdRuntime) {
    let Some(upstream) = dial_tunnel_upstream(host, port, rt).await else {
        rt.send_log(format!("[TUNNEL] upstream connect failed: {host}:{port}"));
        return;
    };
    let (mut c_r, mut c_w) = tcp.into_split();
    let (mut u_r, mut u_w) = upstream.into_split();
    relay(&mut c_r, &mut c_w, &mut u_r, &mut u_w).await;
}

/// Poll interval while waiting for a client head that arrives in pieces (a
/// `ClientHello` normally arrives as a single segment, in which case the first
/// peek already sees both bytes).
const CLIENT_HEAD_POLL: std::time::Duration = std::time::Duration::from_millis(5);

/// The first two bytes the client sent after the CONNECT reply, read with
/// `peek` so they stay in the socket for whatever consumes them next.
///
/// Mirrors `TlsInvadeMiddleware.IsTlsConnectionAsync`, which awaits two readable
/// bytes and then rewinds them (`AdvanceTo(result.Buffer.Start)`). An empty
/// vector means the peer closed or errored before sending anything.
async fn peek_client_head(tcp: &TcpStream) -> Vec<u8> {
    let mut buf = [0u8; 2];
    loop {
        match tcp.peek(&mut buf).await {
            Ok(0) => return Vec::new(),
            Ok(n) if n >= 2 => return buf.to_vec(),
            // Only the first byte is buffered so far; the rest is still in flight.
            Ok(_) => tokio::time::sleep(CLIENT_HEAD_POLL).await,
            Err(_) => return Vec::new(),
        }
    }
}

/// Upper bound on a peeked `ClientHello`.
///
/// A real one is well under 2 KiB; the cap only stops a hostile peer from making
/// the peek loop buffer without end (past it the peer simply gets no tunnel).
const CLIENT_HELLO_MAX: usize = 16 * 1024;

/// The SNI of the peer's `ClientHello`, read with `peek` so the bytes stay in the
/// socket for the verbatim relay that follows.
///
/// rustls cannot be reused for this: the `ClientHello` it hands to a
/// `ResolvesServerCert` is only reachable from inside a handshake, and a handshake
/// consumes the bytes - nothing would be left to relay. `None` for a non-TLS peer
/// (no `0x16 0x03` record header), a message that never completes, or a
/// `ClientHello` without a `server_name` extension.
async fn peek_client_sni(tcp: &TcpStream) -> Option<String> {
    let mut buf = vec![0u8; CLIENT_HELLO_MAX];
    // TLS record header: type(1) + version(2) + length(2).
    let mut want = 5usize;
    loop {
        let have = match tcp.peek(&mut buf).await {
            // The peer closed before a whole `ClientHello` arrived.
            Ok(0) => return None,
            Err(_) => return None,
            // `peek` does not consume, so `n` is everything buffered so far.
            Ok(n) => n,
        };
        if have >= 5 {
            if buf[0] != 0x16 || buf[1] != 0x03 {
                return None;
            }
            want = 5 + u16::from_be_bytes([buf[3], buf[4]]) as usize;
            if want > CLIENT_HELLO_MAX {
                return None;
            }
        }
        if have >= want {
            return sni_from_client_hello(&buf[..have]);
        }
        // Like `peek_client_head`: only part of the message is buffered so far.
        tokio::time::sleep(CLIENT_HEAD_POLL).await;
    }
}

/// The `server_name` extension of a TLS `ClientHello`, or `None` when there is
/// none.
///
/// A minimal reader over the framing rustls would otherwise parse for us: record
/// header, handshake header, the fixed `ClientHello` prefix (version, random,
/// session id, cipher suites, compression methods) and then the extensions. Every
/// length is bounds checked, so a truncated or malformed message yields `None`
/// instead of a panic.
fn sni_from_client_hello(record: &[u8]) -> Option<String> {
    if record.len() < 5 || record[0] != 0x16 || record[1] != 0x03 {
        return None;
    }
    // Handshake message: msg_type(1) + length(3).
    let body = record.get(5..)?;
    if *body.first()? != 0x01 {
        return None;
    }
    let ch_len = ((*body.get(1)? as usize) << 16)
        | ((*body.get(2)? as usize) << 8)
        | (*body.get(3)? as usize);
    let ch = body.get(4..4 + ch_len)?;
    // ClientHello: version(2) random(32) session_id(1+n) cipher_suites(2+n)
    //              compression_methods(1+n) extensions(2+n).
    let mut i = 2 + 32;
    let sid = *ch.get(i)? as usize;
    i += 1 + sid;
    let suites = u16::from_be_bytes([*ch.get(i)?, *ch.get(i + 1)?]) as usize;
    i += 2 + suites;
    let methods = *ch.get(i)? as usize;
    i += 1 + methods;
    let exts_total = u16::from_be_bytes([*ch.get(i)?, *ch.get(i + 1)?]) as usize;
    i += 2;
    let exts = ch.get(i..i + exts_total)?;
    let mut j = 0usize;
    while j + 4 <= exts.len() {
        let ext_type = u16::from_be_bytes([exts[j], exts[j + 1]]);
        let ext_len = u16::from_be_bytes([exts[j + 2], exts[j + 3]]) as usize;
        let ext = exts.get(j + 4..j + 4 + ext_len)?;
        if ext_type == 0x0000 {
            // server_name: list length(2), then name_type(1) + length(2) + name.
            if *ext.get(2)? != 0 {
                return None;
            }
            let name_len = u16::from_be_bytes([*ext.get(3)?, *ext.get(4)?]) as usize;
            let name = std::str::from_utf8(ext.get(5..5 + name_len)?).ok()?;
            if name.is_empty() {
                return None;
            }
            return Some(name.to_string());
        }
        j += 4 + ext_len;
    }
    None
}

/// Relay bytes between two (read, write) stream pairs, one direction per pump.
///
/// The end of one direction is not the end of the tunnel: that direction half
/// closes the peer's write side, so the peer reads a FIN while whatever it still
/// sends keeps travelling the other way (a client that finished uploading must
/// still receive the whole answer). The tunnel is over once both directions are.
/// A read or write *error* is not a clean end: it wakes the other pump, so a
/// broken connection is still dropped on both sides at once, exactly as the
/// previous single loop did. The two pumps and their half closures mirror the
/// original `TunnelMiddleware`, which hands each direction to its own copy
/// (`CopyToAsync`), so that direction ends on its own EOF (P2-10b).
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
    let abort = tokio::sync::Notify::new();
    tokio::join!(pump(r1, w2, &abort), pump(r2, w1, &abort));
}

/// One direction of `relay`: copy `r` into `w` until `r` ends cleanly, then half
/// close `w` (a FIN on the peer's read side) instead of tearing the tunnel down.
async fn pump<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    r: &mut R,
    w: &mut W,
    abort: &tokio::sync::Notify,
) {
    let mut buf = vec![0u8; 16 * 1024];
    loop {
        let n = tokio::select! {
            biased;
            // The other direction failed: this connection is broken, so drop it
            // without a half close.
            _ = abort.notified() => return,
            read = r.read(&mut buf) => match read {
                Ok(0) => break,
                Ok(n) => n,
                Err(_) => {
                    abort.notify_one();
                    return;
                }
            },
        };
        if w.write_all(&buf[..n]).await.is_err() {
            abort.notify_one();
            return;
        }
    }
    let _ = w.shutdown().await;
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
///
/// Bare patterns cover their sub-domains too, exactly like the PAC expands them
/// (`shExpMatch(host, 'github.com') || shExpMatch(host, '*.github.com')`).
/// Without that expansion a PAC-routed host such as
/// `avatars.githubusercontent.com` (bare manifest pattern
/// `githubusercontent.com`) would be treated as unmatched here and dialled
/// through the system resolver instead of the DoH chain.
pub(crate) fn is_accelerated(host: &str, domains: &HashSet<String>) -> bool {
    let host = host.trim().to_lowercase();
    domains.iter().any(|d| {
        let d = d.trim();
        if d.starts_with('*') {
            domain_matches(d, &host)
        } else {
            !d.is_empty() && (host == d || host.ends_with(&format!(".{d}")))
        }
    })
}

/// The manifest addresses configured for `host` (original
/// `ReverseProxyConfig.IPAddress`).
///
/// The lookup reuses `domain_matches`, so a `*.example.com` key covers the bare
/// domain and every sub-domain, and the entry order of the manifest decides: the
/// first matching entry wins. An empty slice means nothing is configured.
pub(crate) fn configured_ips_for<'a>(
    table: &'a [(String, Vec<IpAddr>)],
    host: &str,
) -> &'a [IpAddr] {
    for (pattern, ips) in table {
        if domain_matches(pattern, host) {
            return ips.as_slice();
        }
    }
    &[]
}

/// The manifest addresses to offer for `host`, or none at all while the
/// original's `OnlyEnableProxyScript` is on.
///
/// That option makes `TryGetDomainConfig` skip the manifest lookup entirely, so
/// every domain-like host falls back to the default domain config and
/// `ReverseProxyConfig.IPAddress` never applies. The DNS strategy is untouched
/// (`match_domain_names` still decides whether the DoH chain is used); in PAC
/// mode only accelerated hosts reach this proxy, so both are equivalent there.
pub(crate) fn manifest_ips_for<'a>(
    cfg: &ProxySettings,
    table: &'a [(String, Vec<IpAddr>)],
    host: &str,
) -> &'a [IpAddr] {
    if cfg.only_enable_proxy_script {
        return &[];
    }
    configured_ips_for(table, host)
}

/// The substitute hostname configured for `host` (original
/// `ForwardDestination`), or `None` to dial the host itself.
///
/// The lookup reuses `domain_matches`, so a `*.example.com` key covers the bare
/// domain and every sub-domain. The table is a map and therefore carries no
/// manifest order: when several keys match one host the most specific one wins
/// (an exact key beats a wildcard, a longer wildcard beats a shorter one), which
/// keeps the result reproducible instead of depending on the iteration order.
pub(crate) fn forward_for<'a>(
    table: &'a std::collections::HashMap<String, String>,
    host: &str,
) -> Option<&'a str> {
    let mut best: Option<(&String, &String)> = None;
    for (pattern, alias) in table {
        if !domain_matches(pattern, host) {
            continue;
        }
        let score = ((!pattern.starts_with('*')) as u8, pattern.len());
        let better = match best {
            None => true,
            Some((p, _)) => score > ((!p.starts_with('*')) as u8, p.len()),
        };
        if better {
            best = Some((pattern, alias));
        }
    }
    best.map(|(_, alias)| alias.as_str())
}

/// The substitute hostname to dial `host` through, or `None` while the original's
/// `OnlyEnableProxyScript` is on: the same manifest lookup as
/// `manifest_ips_for`, so `ForwardDestination` never applies either.
pub(crate) fn manifest_forward_for<'a>(
    cfg: &ProxySettings,
    table: &'a std::collections::HashMap<String, String>,
    host: &str,
) -> Option<&'a str> {
    if cfg.only_enable_proxy_script {
        return None;
    }
    forward_for(table, host)
}

/// The substitute upstream name configured for `host` (original
/// `ReverseProxyConfig.FakeServerName`), or `None` to present the requested host.
///
/// Kept as a list rather than a map so the manifest order survives: the first
/// pattern matching the host wins, exactly like `configured_ips_for`. The lookup
/// reuses `domain_matches`, so a `*.example.com` key covers the bare domain and
/// every sub-domain.
pub(crate) fn fake_name_for<'a>(table: &'a [(String, String)], host: &str) -> Option<&'a str> {
    for (pattern, name) in table {
        if domain_matches(pattern, host) {
            return Some(name.as_str());
        }
    }
    None
}

/// The substitute upstream name to present for `host`, or `None` while the
/// original's `OnlyEnableProxyScript` is on: the same manifest lookup as
/// `manifest_ips_for`, so `FakeServerName` never applies either.
pub(crate) fn manifest_fake_name_for<'a>(
    cfg: &ProxySettings,
    table: &'a [(String, String)],
    host: &str,
) -> Option<&'a str> {
    if cfg.only_enable_proxy_script {
        return None;
    }
    fake_name_for(table, host)
}

/// The second-level agent as configured, or `None` while the feature is off.
///
/// Mirrors the `WebProxy` the original `ReverseProxyHttpClientFactory` builds from
/// `TwoLevelAgentEnable` (L36-L45): the type selects the scheme, the address and
/// port come from the same settings, and credentials are attached only when the
/// user name or the password is set (`!string.IsNullOrEmpty(...)` of either).
pub(crate) struct AgentConfig {
    pub proxy_type: ExternalProxyType,
    pub host: String,
    pub port: u16,
    pub credentials: Option<(String, String)>,
}

/// Read the agent settings, or `None` while the agent is off or unusable.
///
/// Deliberate deviation: an empty address is treated as "no agent" and warned
/// about, instead of building a `WebProxy` on an empty host that fails every
/// dial the way the original would - the address is free text in B's UI, and a
/// stray character there must not take the whole proxy down.
pub(crate) fn agent_config(cfg: &ProxySettings) -> Option<AgentConfig> {
    if !cfg.two_level_agent_enable {
        return None;
    }
    let host = cfg.two_level_agent_ip.trim().to_string();
    if host.is_empty() {
        log::warn!(
            target: "wtlite_core::proxy",
            "[AGENT] 二级代理已启用但地址为空，本次按未启用处理"
        );
        return None;
    }
    let credentials =
        if cfg.two_level_agent_user.is_empty() && cfg.two_level_agent_password.is_empty() {
            None
        } else {
            Some((
                cfg.two_level_agent_user.clone(),
                cfg.two_level_agent_password.clone(),
            ))
        };
    Some(AgentConfig {
        proxy_type: cfg.two_level_agent_type,
        host,
        port: cfg.two_level_agent_port,
        credentials,
    })
}

/// The agent endpoint as addresses to dial.
///
/// A literal is used as it is; a configured name goes through `dns::resolve_a`,
/// i.e. the same DoH-first chain (with its TTL cache) every other upstream uses -
/// never a separate plaintext lookup. The original hands `DnsEndPoint` to
/// `Socket.ConnectAsync` (L81-L83) and thus resolves the agent with the system
/// resolver: deliberate deviation, so the agent name cannot leak a plaintext
/// query.
async fn agent_addrs(cfg: &ProxySettings, agent: &AgentConfig) -> Vec<SocketAddr> {
    match agent.host.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, agent.port)],
        Err(_) => dns::resolve_a(
            &agent.host,
            &cfg.proxy_master_dns,
            cfg.use_doh,
            &cfg.custom_doh_address,
        )
        .await
        .into_iter()
        .map(|ip| SocketAddr::new(ip, agent.port))
        .collect(),
    }
}

/// Turn a fresh connection to the agent into a tunnel to `target_host:target_port`.
///
/// The target is handed over as a **name** whenever there is one, so the agent
/// resolves it with its own resolver (HTTP `CONNECT`, SOCKS4a, SOCKS5 ATYP 3) and
/// no address B guessed is ever pasted in. One `CONNECT_TIMEOUT` covers the
/// connect *and* the handshake per endpoint, the per-attempt budget
/// `ConnectCallback` applies on the direct path. `None` means every agent
/// endpoint failed.
async fn connect_agent(
    cfg: &ProxySettings,
    agent: &AgentConfig,
    target_host: &str,
    target_port: u16,
) -> Option<TcpStream> {
    let addrs = agent_addrs(cfg, agent).await;
    let credentials = agent
        .credentials
        .as_ref()
        .map(|(user, password)| (user.as_str(), password.as_str()));
    for addr in &addrs {
        let attempt = async {
            let mut stream = http1::tune(TcpStream::connect(addr).await.ok()?);
            crate::agent::handshake(
                &mut stream,
                agent.proxy_type,
                target_host,
                target_port,
                credentials,
            )
            .await
            .ok()?;
            Some(stream)
        };
        if let Ok(Some(stream)) = tokio::time::timeout(http1::CONNECT_TIMEOUT, attempt).await {
            return Some(stream);
        }
    }
    None
}

/// Dial the upstream TCP leg: through the second-level agent when one is
/// configured, through the candidate sequence otherwise.
///
/// Mirrors the original `ConnectCallback` (L258-L263): as soon as the web proxy is
/// not `NoProxy`, **every** dial goes to `ConnectThroughProxyAsync`, so an
/// accelerated host uses the agent exactly like an unmatched one. While the agent
/// is on, `addrs` (the manifest addresses plus B's own DNS answers) is not dialled
/// at all - the original never reaches `GetIPEndPointsAsync` on that path either.
///
/// `target_host` follows the caller's dial name, and the two callers differ:
///
/// - The MITM upstream leg passes the current SNI candidate, whose first entry is
///   the requested host (or the manifest's `fake_server_name`). That is the name
///   the original hands over (`context.DnsEndPoint.Host`, its
///   `ConnectThroughProxyAsync` sends `CONNECT {DnsEndPoint.Host}:{port}`), so that
///   leg matches the original.
/// - The bare tunnel leg (`dial_tunnel_upstream`) passes the `ForwardDestination`
///   alias where one applies. Deliberate deviation from the original, which asks
///   for the request host and skips its own name resolution entirely
///   (`context.DnsEndPoint`): the alias is the only name B knows to be reachable
///   there, and the agent is used as the transport only.
pub(crate) async fn dial_upstream(
    cfg: &ProxySettings,
    addrs: &[SocketAddr],
    target_host: &str,
    target_port: u16,
) -> Option<TcpStream> {
    match agent_config(cfg) {
        None => http1::connect_upstream(addrs).await,
        Some(agent) => connect_agent(cfg, &agent, target_host, target_port).await,
    }
}

/// Resolve `host` through the OS resolver - the same source `dial_by_name` dials
/// through, and therefore the source `handle_http`'s pollution guard has to judge.
///
/// The guard's question is "which address would this request reach?", so it must
/// read the answer the dial itself would get; asking a different resolver would
/// let the guard refuse an address nobody was going to dial. Only this unmatched
/// leg moves: an accelerated host is resolved through B's DoH-first chain before
/// and after, and that source is untouched. A name the OS cannot answer - or no
/// resolver at all - yields an empty list, which `is_dns_poisoned` counts as
/// poisoned.
async fn system_addrs(host: &str, port: u16) -> Vec<IpAddr> {
    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => addrs.map(|a| a.ip()).collect(),
        Err(_) => Vec::new(),
    }
}

/// Dial a host the manifest does not cover through the system resolver.
///
/// Mirrors the original `TunnelMiddleware` branch that hands an unmatched
/// `ConnectHost` to `TcpClient.ConnectAsync(new DnsEndPoint(host, port))`: the
/// name is resolved by the OS, and an IP literal passes through `ToSocketAddrs`
/// without a lookup, covering the `IPEndPoint` branch too. One `CONNECT_TIMEOUT`
/// bounds the connect, like every other dial on this path.
///
/// `handle_http`'s unmatched leg only falls back to this dial when the name has
/// no system answer in hand: `system_addrs` hands the guard the addresses, and
/// the leg then dials exactly those (`connect_upstream`) instead of asking the OS
/// a second time - the second answer could differ, and the guard would have
/// judged an address that is not the one dialled. What is left here is the cases
/// the guard never resolves: an IP literal or a dotless name (`is_domain_form`
/// keeps those out of it) and `OnlyEnableProxyScript`, which skips it. Same
/// source either way - both dial through the OS resolver.
///
/// Deliberately used only for hosts the manifest does not know (see the gate in
/// `handle_connect`): resolving an accelerated host through the system resolver
/// would be answered by B's own hook in DNS-interception mode (see the note in
/// http1.rs), and with the second-level agent on every dial goes through the
/// agent instead (`dial_upstream`).
async fn dial_by_name(host: &str, port: u16) -> Option<TcpStream> {
    let attempt = async {
        let stream = TcpStream::connect((host, port)).await.ok()?;
        Some(http1::tune(stream))
    };
    tokio::time::timeout(http1::CONNECT_TIMEOUT, attempt)
        .await
        .ok()
        .flatten()
}

/// `dial_upstream`, plus the upstream TLS handshake on top of the tunnel.
///
/// `host` is both the tunnel target and the TLS SNI: every B call site verifies
/// exactly the name it dials. The certificate is checked by B's own connector
/// (webpki roots) - deliberate deviation from the original, which turns
/// verification off on the proxy path (`RemoteCertificateValidationCallback =
/// (…) => true`, L103-L114) and would thereby punch a hole in the TLS-failure
/// fallback P0-1 / P0-2a depend on.
pub(crate) async fn dial_upstream_tls(
    cfg: &ProxySettings,
    addrs: &[SocketAddr],
    host: &str,
    port: u16,
    connector: &tokio_rustls::TlsConnector,
) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
    match agent_config(cfg) {
        None => http1::connect_upstream_tls(addrs, host, connector).await,
        Some(agent) => {
            let stream = connect_agent(cfg, &agent, host, port).await?;
            let dns_name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
            // One connect budget for the TLS step as well, so a stalled handshake
            // cannot hold a request open (the original applies no connect budget
            // at all on this path).
            tokio::time::timeout(http1::CONNECT_TIMEOUT, connector.connect(dns_name, stream))
                .await
                .ok()?
                .ok()
        }
    }
}

/// `dial_upstream_tls`, but without sending SNI (original `TlsSniPattern.None`).
///
/// The certificate is still verified - by the connector's custom verifier,
/// against `verify_host` (the requested domain). `target_host` is what the
/// second-level agent is asked to connect to; SNI is never sent on the TLS leg,
/// whether direct or through the agent.
pub(crate) async fn dial_upstream_tls_no_sni(
    cfg: &ProxySettings,
    addrs: &[SocketAddr],
    _verify_host: &str,
    target_host: &str,
    port: u16,
    connector: &tokio_rustls::TlsConnector,
) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
    match agent_config(cfg) {
        None => http1::connect_upstream_tls_no_sni(addrs, connector).await,
        Some(agent) => {
            let stream = connect_agent(cfg, &agent, target_host, port).await?;
            // The agent is a TCP endpoint; an IP ServerName suppresses SNI, and
            // the connector verifies the certificate against `verify_host`.
            let ip = stream.peer_addr().ok()?.ip();
            let dns_name = rustls::pki_types::ServerName::IpAddress(ip.into());
            tokio::time::timeout(http1::CONNECT_TIMEOUT, connector.connect(dns_name, stream))
                .await
                .ok()?
                .ok()
        }
    }
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
        assert!(is_accelerated(
            "video-edge-1.pdx01.abs.hls.ttvnw.net",
            &domains
        ));
        assert!(is_accelerated("store.steampowered.com", &domains));
        assert!(!is_accelerated("store.steamstatic.com", &domains));
        assert!(!is_accelerated("example.com", &domains));
        assert!(domain_matches("*.st.dl.eccdnx.com", "a.b.st.dl.eccdnx.com"));
        assert!(domain_matches("*.st.dl.eccdnx.com", "st.dl.eccdnx.com"));
        assert!(!domain_matches("*.st.dl.eccdnx.com", "st.dl.eccdnx.org"));
        // A bare manifest pattern covers its sub-domains, matching the PAC's
        // `github.com || *.github.com` expansion (GitHub's asset hosts hang off
        // the bare `githubusercontent.com` entry).
        let mut bare = HashSet::new();
        bare.insert("githubusercontent.com".to_string());
        assert!(is_accelerated("avatars.githubusercontent.com", &bare));
        assert!(is_accelerated("githubusercontent.com", &bare));
        assert!(!is_accelerated("notgithubusercontent.com", &bare));
        assert!(!is_accelerated("githubusercontent.com.evil.test", &bare));
    }

    /// CONNECT targets default to 443, but an absolute-form HTTP target must
    /// default per scheme (80) - the old shared default sent `http://host/path`
    /// to the TLS port.
    #[test]
    fn absolute_targets_use_the_scheme_default_port() {
        assert_eq!(
            parse_host_port_default("example.com", 80),
            Some(("example.com".to_string(), 80))
        );
        assert_eq!(
            parse_host_port_default("example.com", 443),
            Some(("example.com".to_string(), 443))
        );
        assert_eq!(
            parse_host_port_default("example.com:8080", 80),
            Some(("example.com".to_string(), 8080))
        );
        assert_eq!(
            parse_host_port("example.com"),
            Some(("example.com".to_string(), 443))
        );
        // Bracketed IPv6 literals carry colons that are not port separators.
        assert_eq!(
            parse_host_port_default("[::1]", 443),
            Some(("::1".to_string(), 443))
        );
        assert_eq!(
            parse_host_port_default("[::1]:8443", 443),
            Some(("::1".to_string(), 8443))
        );
    }

    #[test]
    fn configured_ips_use_pattern_matching_and_manifest_order() {
        let table = vec![
            (
                "*.example.com".to_string(),
                vec![IpAddr::from([1, 1, 1, 1])],
            ),
            (
                "sub.example.com".to_string(),
                vec![IpAddr::from([2, 2, 2, 2])],
            ),
        ];
        // A wildcard key covers the bare domain and every sub-domain, and the
        // manifest order decides: the first matching entry wins even when a more
        // specific pattern follows it.
        assert_eq!(
            configured_ips_for(&table, "example.com").to_vec(),
            vec![IpAddr::from([1, 1, 1, 1])]
        );
        assert_eq!(
            configured_ips_for(&table, "sub.example.com").to_vec(),
            vec![IpAddr::from([1, 1, 1, 1])]
        );
        assert!(configured_ips_for(&table, "other.test").is_empty());
    }

    #[test]
    fn forward_alias_lookup_uses_pattern_matching() {
        let table: std::collections::HashMap<String, String> = [
            ("*.example.com".to_string(), "cdn.example.net".to_string()),
            ("api.example.com".to_string(), "api.example.net".to_string()),
        ]
        .into_iter()
        .collect();
        // A wildcard key covers the bare domain and every sub-domain ...
        assert_eq!(forward_for(&table, "example.com"), Some("cdn.example.net"));
        assert_eq!(
            forward_for(&table, "www.example.com"),
            Some("cdn.example.net")
        );
        // ... and an exact key wins over the wildcard that also matches it.
        assert_eq!(
            forward_for(&table, "api.example.com"),
            Some("api.example.net")
        );
        // Hosts without a configured alias are dialled directly.
        assert_eq!(forward_for(&table, "other.test"), None);
    }

    #[test]
    fn only_plain_http_targets_are_redirect_candidates() {
        assert!(is_plain_http("http://example.com/a?b=1"));
        assert!(is_plain_http("HTTP://example.com/"));
        assert!(!is_plain_http("https://example.com/"));
        assert!(!is_plain_http("example.com/"));
        // A target whose first seven bytes are not a char boundary must not panic.
        assert!(!is_plain_http("日本語.example.com"));
    }

    #[test]
    fn the_pollution_guard_mirrors_the_original_is_domain_and_loopback_test() {
        // `IsDomain`: a dotted name needs a lookup and is guarded; an IP literal or
        // a dotless name is not - `localhost` is exactly the case a local
        // developer hits, and the original never guard-refuses it.
        assert!(is_domain_form("poisoned.test"));
        assert!(!is_domain_form("127.0.0.1"));
        assert!(!is_domain_form("::1"));
        assert!(!is_domain_form("localhost"));
        // The guard's offline fixtures (C-3) are names the OS resolver answers
        // without a network: `localhost.` (the hosts file, so loopback) and the
        // machine's own name (the adapter addresses, so public). Both carry a dot
        // and neither parses as an IP, which is what puts them in front of the
        // guard.
        assert!(is_domain_form("localhost."));
        // `ip == null || IPAddress.IsLoopback(ip)`: an empty answer is poisoned
        // (the chain could not resolve, or every endpoint failed).
        assert!(is_dns_poisoned(&[]));
        assert!(is_dns_poisoned(&[IpAddr::from([127, 0, 0, 1])]));
        assert!(is_dns_poisoned(&["::1".parse::<IpAddr>().unwrap()]));
        // The whole 127.0.0.0/8 counts, like `IPAddress.IsLoopback`.
        assert!(is_dns_poisoned(&[IpAddr::from([127, 5, 6, 7])]));
        // A public answer passes ...
        assert!(!is_dns_poisoned(&[IpAddr::from([203, 0, 113, 7])]));
        // ... and only the *first* answer decides, exactly as `FirstOrDefaultAsync`
        // does: of `203.0.113.7` then `127.0.0.1`, the leading public address wins.
        assert!(!is_dns_poisoned(&[
            IpAddr::from([203, 0, 113, 7]),
            IpAddr::from([127, 0, 0, 1])
        ]));
    }

    /// Drive the forward proxy over a real loopback socket pair and return the
    /// raw response bytes (the redirect, the forwarded answer and the 502 path
    /// all end offline).
    async fn proxy_response(
        accelerated: bool,
        enable_redirect: bool,
        only_enable_proxy_script: bool,
        configured: Vec<(String, Vec<IpAddr>)>,
        target: &str,
    ) -> String {
        let cfg = ProxySettings {
            enable_http_proxy_to_https: enable_redirect,
            only_enable_proxy_script,
            ..Default::default()
        };
        let mut domains = HashSet::new();
        if accelerated {
            domains.insert("store.steampowered.com".to_string());
        }
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        let rt = FwdRuntime {
            config: Arc::new(RwLock::new(cfg)),
            domains: Arc::new(RwLock::new(domains)),
            stats: Arc::new(Mutex::new(crate::proxy::FlowStats::default())),
            log_tx,
            mitm: None,
            forward: Arc::new(RwLock::new(std::collections::HashMap::new())),
            configured_ips: Arc::new(RwLock::new(configured)),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(handle_conn(server, rt));
        client
            .write_all(format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_end(&mut buf),
        )
        .await
        .expect("the proxy did not answer within 5s")
        .unwrap();
        task.await.unwrap().unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }

    #[tokio::test]
    async fn an_accelerated_plain_http_request_is_redirected_to_https() {
        // The port is dropped and the path + query are kept, like
        // `Redirect("https://" + Request.Host.Host + RawUrl())`.
        let answer = proxy_response(
            true,
            true,
            false,
            Vec::new(),
            "http://store.steampowered.com:8080/foo?x=1",
        )
        .await;
        assert!(
            answer.starts_with("HTTP/1.1 302 Found\r\n"),
            "unexpected answer: {answer}"
        );
        assert!(
            answer.contains("\r\nLocation: https://store.steampowered.com/foo?x=1\r\n"),
            "unexpected answer: {answer}"
        );
    }

    #[tokio::test]
    async fn an_unmatched_host_is_not_redirected() {
        // Only accelerated hosts are redirected (deviation from the original
        // middleware, which redirects every domain-like host). The target is a
        // local port with nothing listening, so the unmatched request takes the
        // dial-by-name branch (P2-9b) and is answered offline: the dial is refused
        // and the answer is the 502. `localhost` is resolved by the system
        // resolver itself, so the test touches no network.
        let answer = proxy_response(false, true, false, Vec::new(), "http://localhost:1/foo").await;
        assert!(
            answer.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "unexpected answer: {answer}"
        );
        assert!(!answer.contains("Location:"), "unexpected answer: {answer}");
    }

    #[tokio::test]
    async fn an_unmatched_domain_answered_with_loopback_is_refused_with_500() {
        // The pollution guard (P2-9b's second deviation is dropped here): a
        // domain-like host the manifest does not know and whose analysis answers a
        // loopback address is refused with 500 before anything is dialled, exactly
        // as `HttpReverseProxyMiddleware` L100-L111 does. The target is a name, not
        // an IP literal, so `is_domain_form` applies - the trailing dot keeps
        // `localhost` out of `Ipv4Addr::from_str` while the OS resolver still
        // answers it from the hosts file (`::1`, `127.0.0.1`), so the guard's answer
        // stays offline. The DoH endpoint is a decoy answering a public TEST-NET-3
        // address: the guard now reads the OS resolver, the very source the
        // unmatched dial uses (C-3), so the 500 proves it judged that answer rather
        // than the DoH one.
        let doh = doh_stub("localhost.", "203.0.113.7").await;
        let cfg = ProxySettings {
            use_doh: true,
            custom_doh_address: doh,
            ..Default::default()
        };
        let answer = handle_http_answer(cfg, "http://localhost./foo").await;
        assert!(
            answer.starts_with("HTTP/1.1 500 Internal Server Error\r\n"),
            "unexpected answer: {answer}"
        );
        assert!(answer.contains("DNS 污染"), "unexpected answer: {answer}");
    }

    #[tokio::test]
    async fn an_unmatched_domain_answered_with_a_public_address_is_not_guard_refused() {
        // The guard must not over-block: a domain-like host outside the manifest
        // whose first answer is public passes it and is forwarded as usual. The
        // target is the machine's own name with a trailing dot: the OS resolver
        // answers it offline, with the local adapter addresses and nothing loopback,
        // while the dot keeps it out of `Ipv4Addr::from_str` - so it is domain-like
        // *and* resolvable, the only way to drive the guard through the OS resolver
        // (C-3) without a network. (The fixture needs the machine to have a
        // non-loopback address, which is the normal case; any adapter address
        // counts.) The second-level agent is what makes the forwarding observable
        // offline: it is handed the name and relays to the loopback marker upstream,
        // so nothing is dialled at the machine's own addresses. The DoH endpoint is
        // a decoy answering `127.0.0.1`, which the guard's old source would have
        // refused.
        let name = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .expect("no machine name in the environment");
        let (agent_addr, _captured) = fake_http_agent(marker_upstream().await).await;
        let doh = doh_stub("localhost.", "127.0.0.1").await;
        let cfg = ProxySettings {
            use_doh: true,
            custom_doh_address: doh,
            ..agent_enabled(agent_addr)
        };
        let answer = handle_http_answer(cfg, &format!("http://{name}.:8080/foo")).await;
        assert!(
            !answer.starts_with("HTTP/1.1 500 "),
            "the guard refused a publicly answered name: {answer}"
        );
        assert!(answer.contains("via-agent"), "unexpected answer: {answer}");
    }

    #[tokio::test]
    async fn an_unmatched_domain_the_system_answers_is_forwarded() {
        // P2-9b ①, and the case the offline suite could not reach until C-3: a host
        // the manifest does not know that *is* domain-like (so it stands in front of
        // the pollution guard) and whose system answer is a real, non-loopback
        // address is forwarded to that origin instead of being refused with 500 or
        // answered 502. The target is the machine's own name with a trailing dot:
        // the OS answers it offline, with the local adapter addresses, while the dot
        // keeps it out of `Ipv4Addr::from_str` (the same shape the guard cases use,
        // except those want the loopback answer). The stand-in origin listens on
        // `0.0.0.0:{port}`, so whichever of the addresses the OS yields is reachable
        // accepts - the dial here is the unmatched leg itself, with no second-level
        // agent to intercept it. The budget is 20s: the dial spends one connect
        // attempt per endpoint, and the unreachable link-local ones cost ~2s each,
        // which puts the measured ~4s uncomfortably close to the usual five.
        let name = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .expect("no machine name in the environment");
        let upstream = TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = upstream.local_addr().unwrap().port();
        let fake = tokio::spawn(async move {
            while let Ok((mut sock, _)) = upstream.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\nvia-system-answer",
                    )
                    .await;
                let _ = sock.flush().await;
            }
        });
        let answer = handle_http_with(
            ProxySettings::default(),
            HashSet::new(),
            Vec::new(),
            &format!("http://{name}.:{port}/foo"),
            std::time::Duration::from_secs(20),
        )
        .await;
        assert!(
            answer.starts_with("HTTP/1.1 200 OK\r\n"),
            "unexpected answer: {answer}"
        );
        assert!(
            answer.contains("via-system-answer"),
            "unexpected answer: {answer}"
        );
        fake.abort();
    }

    #[tokio::test]
    async fn an_accelerated_domain_is_not_guard_refused() {
        // The guard's first gate factor (`!accelerated`): an accelerated host is
        // resolved through B's own DoH chain and never reaches the guard, so even an
        // answer the guard refuses for an unmatched name (`127.0.0.1` here) is
        // forwarded as usual. The accelerated set is seeded with `localhost.` on
        // purpose: the system answer for that name *is* loopback, so a guard that
        // wrongly applied to it would answer 500 and this case would fail - which
        // keeps it offline and discriminating, unlike a real accelerator name whose
        // system answer is unknown and would have to be looked up for real. The
        // plain-http -> https redirect is switched off (it defaults on, and an
        // accelerated plain-http target would be answered with 302 *before* any
        // lookup); the redirect has its own case.
        let doh = doh_stub("localhost.", "127.0.0.1").await;
        let cfg = ProxySettings {
            use_doh: true,
            custom_doh_address: doh,
            enable_http_proxy_to_https: false,
            ..Default::default()
        };
        let mut domains = HashSet::new();
        domains.insert("localhost.".to_string());
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = upstream.local_addr().unwrap().port();
        let fake = tokio::spawn(async move {
            while let Ok((mut sock, _)) = upstream.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nvia-accelerated",
                    )
                    .await;
                let _ = sock.flush().await;
            }
        });
        let answer = handle_http_with(
            cfg,
            domains,
            Vec::new(),
            &format!("http://localhost.:{port}/foo"),
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(
            answer.starts_with("HTTP/1.1 200 OK\r\n"),
            "unexpected answer: {answer}"
        );
        assert!(
            answer.contains("via-accelerated"),
            "unexpected answer: {answer}"
        );
        fake.abort();
    }

    #[tokio::test]
    async fn a_configured_address_keeps_the_guard_out_of_the_way() {
        // The guard's second gate factor (`addrs.is_empty()`): a name the manifest
        // does configure yields a candidate address, so the guard does not apply.
        // The name is `localhost.` - the very target the 500 case above refuses,
        // because its system answer is loopback - so a guard that applied anyway
        // would answer 500 here rather than reach the configured origin. No lookup
        // happens on this path at all (`!accelerated` keeps B's DoH chain out, and
        // the configured address is the whole candidate sequence).
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = upstream.local_addr().unwrap().port();
        let fake = tokio::spawn(async move {
            while let Ok((mut sock, _)) = upstream.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 14\r\nConnection: close\r\n\r\nvia-configured",
                    )
                    .await;
                let _ = sock.flush().await;
            }
        });
        let configured = vec![("localhost.".to_string(), vec![IpAddr::from([127, 0, 0, 1])])];
        let answer = handle_http_with(
            ProxySettings::default(),
            HashSet::new(),
            configured,
            &format!("http://localhost.:{port}/foo"),
            std::time::Duration::from_secs(5),
        )
        .await;
        assert!(
            answer.starts_with("HTTP/1.1 200 OK\r\n"),
            "unexpected answer: {answer}"
        );
        assert!(
            answer.contains("via-configured"),
            "unexpected answer: {answer}"
        );
        fake.abort();
    }

    #[tokio::test]
    async fn an_agent_does_not_bypass_the_pollution_guard() {
        // The guard runs *before* the agent branch, as the original reaches its
        // guard for a domain-like host whatever its agent setting is (only a
        // non-domain host takes its agent branch). The name resolves to loopback,
        // so the guard refuses it and the agent is never handed anything - a
        // second-level agent must not make a poisoned name reachable.
        let (agent_addr, _captured) = fake_http_agent(marker_upstream().await).await;
        let cfg = agent_enabled(agent_addr);
        let answer = handle_http_answer(cfg, "http://localhost.:8080/foo").await;
        assert!(
            answer.starts_with("HTTP/1.1 500 Internal Server Error\r\n"),
            "unexpected answer: {answer}"
        );
        assert!(
            !answer.contains("via-agent"),
            "the agent was used: {answer}"
        );
    }

    #[tokio::test]
    async fn an_unmatched_ip_literal_target_is_forwarded_upstream() {
        // P2-9b: the manifest knows nothing about this host, which used to mean an
        // empty candidate sequence and a 502 for every http request. An IP literal
        // needs no lookup at all (`ToSocketAddrs` passes it straight through), so
        // the request now reaches the origin - checked against a loopback upstream,
        // entirely offline.
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let fake = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nvia-ip-addr",
            )
            .await
            .unwrap();
        });
        let target = format!("http://127.0.0.1:{upstream_port}/foo");
        let answer = handle_http_answer(ProxySettings::default(), &target).await;
        assert!(
            answer.starts_with("HTTP/1.1 200 OK\r\n"),
            "unexpected answer: {answer}"
        );
        assert!(
            answer.contains("via-ip-addr"),
            "unexpected answer: {answer}"
        );
        fake.await.unwrap();
    }

    /// Drive `handle_http` directly under a configuration of the test's choosing
    /// and return the answer (`proxy_response` fixes the settings, this does not).
    async fn handle_http_answer(cfg: ProxySettings, target: &str) -> String {
        handle_http_with(
            cfg,
            HashSet::new(),
            Vec::new(),
            target,
            std::time::Duration::from_secs(5),
        )
        .await
    }

    /// `handle_http_answer` with the manifest tables and the answer budget as
    /// arguments: `domains` seeds the accelerated set and `configured` the manifest
    /// addresses (`handle_http_answer` leaves both empty, and `proxy_response` sets
    /// neither settings nor tables). The budget is a parameter because a test that
    /// dials the *system* answer of a name spends one connect attempt per endpoint
    /// the OS yields, and an unreachable link-local endpoint costs about two
    /// seconds - enough to sit uncomfortably close to the fixed five.
    async fn handle_http_with(
        cfg: ProxySettings,
        domains: HashSet<String>,
        configured: Vec<(String, Vec<IpAddr>)>,
        target: &str,
        limit: std::time::Duration,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        let rt = FwdRuntime {
            config: Arc::new(RwLock::new(cfg)),
            domains: Arc::new(RwLock::new(domains)),
            stats: Arc::new(Mutex::new(crate::proxy::FlowStats::default())),
            log_tx,
            mitm: None,
            forward: Arc::new(RwLock::new(std::collections::HashMap::new())),
            configured_ips: Arc::new(RwLock::new(configured)),
        };
        let req = http1::HttpRequest {
            method: "GET".to_string(),
            path: target.to_string(),
            headers: vec![("Host".to_string(), "127.0.0.1".to_string())],
            body: Vec::new(),
        };
        let task = tokio::spawn(async move {
            handle_http(&mut server, req, &rt).await.unwrap();
        });
        let mut buf = Vec::new();
        tokio::time::timeout(limit, client.read_to_end(&mut buf))
            .await
            .expect("the handler did not answer within its budget")
            .unwrap();
        task.await.unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }

    /// Drive the forward proxy with a raw request line and return the answer.
    /// `proxy_response` always sends `GET`, so a test that needs another method
    /// or an origin-form target uses this instead.
    async fn proxy_answer(request_line: &str) -> String {
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        let rt = FwdRuntime {
            config: Arc::new(RwLock::new(ProxySettings::default())),
            domains: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(Mutex::new(crate::proxy::FlowStats::default())),
            log_tx,
            mitm: None,
            forward: Arc::new(RwLock::new(std::collections::HashMap::new())),
            configured_ips: Arc::new(RwLock::new(Vec::new())),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(handle_conn(server, rt));
        client
            .write_all(format!("{request_line}\r\nHost: 127.0.0.1\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_end(&mut buf),
        )
        .await
        .expect("the proxy did not answer within 5s")
        .unwrap();
        task.await.unwrap().unwrap();
        String::from_utf8_lossy(&buf).to_string()
    }

    #[tokio::test]
    async fn an_origin_form_request_is_answered_with_the_pac_file() {
        // The original `HttpProxyPacMiddleware` answers **every** request whose
        // target is not an absolute URI with the PAC file - `ProxyProtocol.None`
        // is the whole condition, with no path or method test - so an origin-form
        // GET *and* an origin-form POST are PAC fetches, not 400s or a socket
        // closed with nothing written.
        for line in ["GET /foo HTTP/1.1", "POST /bar HTTP/1.1"] {
            let answer = proxy_answer(line).await;
            assert!(
                answer.starts_with("HTTP/1.1 200 OK\r\n"),
                "unexpected answer for {line}: {answer}"
            );
            assert!(
                answer.contains("Content-Type: application/x-ns-proxy-autoconfig"),
                "unexpected answer for {line}: {answer}"
            );
            assert!(
                answer.contains("FindProxyForURL"),
                "unexpected answer for {line}: {answer}"
            );
        }
    }

    #[tokio::test]
    async fn an_https_absolute_target_is_forwarded_instead_of_being_closed() {
        // An absolute-URI target is forwarded whatever its scheme: the redirect
        // applies to plain-HTTP targets only (see the deviation note in
        // `handle_http`), so an `https://` target reaches the origin rather than
        // the connection being closed with no response at all.
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let fake = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nvia-ip-addr",
            )
            .await
            .unwrap();
        });
        let configured = vec![("other.test".to_string(), vec![IpAddr::from([127, 0, 0, 1])])];
        let target = format!("https://other.test:{upstream_port}/foo");
        let answer = proxy_response(false, false, false, configured, &target).await;
        assert!(
            answer.contains("via-ip-addr"),
            "unexpected answer: {answer}"
        );
        fake.await.unwrap();
    }

    #[tokio::test]
    async fn an_origin_form_target_gets_an_explicit_400_from_the_absolute_uri_handler() {
        // `handle_conn` never routes an origin-form target here (it is answered
        // with the PAC file), so the branch is only reachable if the dispatch
        // changes. Driving `handle_http` directly keeps it honest: it must still
        // answer rather than close the connection with nothing written.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        let rt = FwdRuntime {
            config: Arc::new(RwLock::new(ProxySettings::default())),
            domains: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(Mutex::new(crate::proxy::FlowStats::default())),
            log_tx,
            mitm: None,
            forward: Arc::new(RwLock::new(std::collections::HashMap::new())),
            configured_ips: Arc::new(RwLock::new(Vec::new())),
        };
        let req = http1::HttpRequest {
            method: "GET".to_string(),
            path: "/foo".to_string(),
            headers: vec![("Host".to_string(), "127.0.0.1".to_string())],
            body: Vec::new(),
        };
        let task = tokio::spawn(async move {
            handle_http(&mut server, req, &rt).await.unwrap();
        });
        let mut buf = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_to_end(&mut buf),
        )
        .await
        .expect("the handler did not answer within 5s")
        .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&buf),
            "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        task.await.unwrap();
    }

    #[tokio::test]
    async fn a_connect_to_a_host_outside_the_manifest_is_dialled_by_name() {
        // `TunnelMiddleware` reaches an unmatched host through the system resolver
        // (`DnsEndPoint`), which is what this checks. A loopback echo upstream
        // stands in for it, and `127.0.0.1` is an IP literal, so `ToSocketAddrs`
        // resolves it without touching any resolver: the test stays offline.
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let echo = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        let rt = FwdRuntime {
            config: Arc::new(RwLock::new(ProxySettings::default())),
            domains: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(Mutex::new(crate::proxy::FlowStats::default())),
            log_tx,
            mitm: None,
            forward: Arc::new(RwLock::new(std::collections::HashMap::new())),
            configured_ips: Arc::new(RwLock::new(Vec::new())),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = tokio::spawn(handle_conn(server, rt));
        client
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:{upstream_port} HTTP/1.1\r\nHost: 127.0.0.1:{upstream_port}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        // The CONNECT reply comes first: the original `HttpProxyMiddleware`
        // answers before the tunnel is dialled.
        let mut head = [0u8; 39];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_exact(&mut head),
        )
        .await
        .expect("the CONNECT was never answered")
        .unwrap();
        assert_eq!(&head, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        // The payload is `0x68 0x65`, not a TLS record, so the tunnel is relayed
        // verbatim - which only gets that far once the host was dialled by name.
        client.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_exact(&mut back),
        )
        .await
        .expect("the tunnel was not established")
        .unwrap();
        assert_eq!(&back, b"hello");
        // The tunnel now lives until *both* directions are ended (P2-10b), so the
        // client has to close its own end for `handle_conn` to return - exactly
        // what a browser does once it sees the FIN the relay forwards from the
        // upstream. Leaving it open would keep the task (and both sockets) alive
        // with nothing left to relay.
        client.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
        echo.await.unwrap();
    }

    /// Drive `relay` over two loopback socket pairs and hand back the two peer
    /// ends (`browser`, `origin`) plus the relay task; the relay owns the other
    /// end of each pair. Nothing is dialled by name here, so the test is offline.
    async fn relay_pair() -> (TcpStream, TcpStream, tokio::task::JoinHandle<()>) {
        let browser_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(browser_listener.local_addr().unwrap())
            .await
            .unwrap();
        let upstream = TcpStream::connect(origin_listener.local_addr().unwrap())
            .await
            .unwrap();
        let (browser, _) = browser_listener.accept().await.unwrap();
        let (origin, _) = origin_listener.accept().await.unwrap();
        let (mut c_r, mut c_w) = client.into_split();
        let (mut u_r, mut u_w) = upstream.into_split();
        let task = tokio::spawn(async move {
            relay(&mut c_r, &mut c_w, &mut u_r, &mut u_w).await;
        });
        (browser, origin, task)
    }

    #[tokio::test]
    async fn a_client_half_close_half_closes_the_upstream_write_and_the_answer_still_arrives() {
        // A browser that finished uploading sends a FIN. The relay must pass that
        // end on to the upstream write side (so the origin sees the end of the
        // request) and still carry the answer the origin writes afterwards. The
        // previous single loop returned on the first EOF, dropped both sockets and
        // lost that answer (P2-10b, acceptance 1).
        let (mut browser, mut origin, task) = relay_pair().await;

        browser.write_all(b"upload").await.unwrap();
        browser.shutdown().await.unwrap();

        // The origin reads the upload and then the FIN the relay wrote for it.
        let mut seen = Vec::new();
        origin.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, b"upload");

        origin.write_all(b"answer-after-fin").await.unwrap();
        origin.shutdown().await.unwrap();

        let mut answer = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            browser.read_to_end(&mut answer),
        )
        .await
        .expect("the answer written after the client's FIN never arrived")
        .unwrap();
        assert_eq!(answer, b"answer-after-fin");

        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the relay did not finish after both sides closed")
            .unwrap();
    }

    #[tokio::test]
    async fn an_upstream_half_close_half_closes_the_client_write_and_the_upload_still_arrives() {
        // The mirror image: the origin answers and half closes its own write side
        // first. The relay must pass that end on to the client write side and keep
        // reading whatever the browser sends afterwards (P2-10b, acceptance 2).
        let (mut browser, mut origin, task) = relay_pair().await;

        origin.write_all(b"early-fin").await.unwrap();
        origin.shutdown().await.unwrap();

        // The browser reads the whole answer and then the FIN the relay wrote.
        let mut answer = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            browser.read_to_end(&mut answer),
        )
        .await
        .expect("the answer written before the upstream's FIN never arrived")
        .unwrap();
        assert_eq!(answer, b"early-fin");

        browser.write_all(b"upload-after-fin").await.unwrap();
        browser.shutdown().await.unwrap();

        // The origin still reads that upload: only its write side was closed.
        let mut seen = Vec::new();
        origin.read_to_end(&mut seen).await.unwrap();
        assert_eq!(seen, b"upload-after-fin");

        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the relay did not finish after both sides closed")
            .unwrap();
    }

    /// A minimal TLS `ClientHello` record carrying `sni`, or no `server_name`
    /// extension at all when it is `None`.
    fn client_hello_record(sni: Option<&str>) -> Vec<u8> {
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // legacy_version
        ch.extend_from_slice(&[0u8; 32]); // random
        ch.push(0); // session_id
        ch.extend_from_slice(&[0x00, 0x02]); // cipher_suites length
        ch.extend_from_slice(&[0x13, 0x01]); // one suite
        ch.push(1); // compression_methods length
        ch.push(0); // null compression
        let mut exts = Vec::new();
        if let Some(name) = sni {
            let mut server_name = Vec::new();
            server_name.extend_from_slice(&((3 + name.len()) as u16).to_be_bytes());
            server_name.push(0); // name_type = host_name
            server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
            server_name.extend_from_slice(name.as_bytes());
            exts.extend_from_slice(&0x0000u16.to_be_bytes()); // server_name
            exts.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
            exts.extend_from_slice(&server_name);
        }
        ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        ch.extend_from_slice(&exts);

        let mut handshake = Vec::new();
        handshake.push(0x01); // client_hello
        handshake.extend_from_slice(&(ch.len() as u32).to_be_bytes()[1..]); // 3-byte length
        handshake.extend_from_slice(&ch);

        let mut record = Vec::new();
        record.push(0x16); // handshake record
        record.extend_from_slice(&[0x03, 0x01]); // legacy record version
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[test]
    fn the_client_hello_sni_is_extracted() {
        let record = client_hello_record(Some("steamcommunity.com"));
        assert_eq!(
            sni_from_client_hello(&record).as_deref(),
            Some("steamcommunity.com")
        );
    }

    #[test]
    fn a_client_hello_without_a_server_name_extension_has_no_sni() {
        // A `ClientHello` that omits the extension carries no name at all.
        assert_eq!(sni_from_client_hello(&client_hello_record(None)), None);
    }

    #[test]
    fn a_non_tls_peer_or_a_truncated_client_hello_has_no_sni() {
        // A plain HTTP request is not a TLS record; an empty buffer and a record
        // that lost its last byte are not readable as a name either.
        assert_eq!(sni_from_client_hello(b"GET / HTTP/1.1\r\n"), None);
        assert_eq!(sni_from_client_hello(&[]), None);
        let record = client_hello_record(Some("example.test"));
        assert_eq!(sni_from_client_hello(&record[..record.len() - 1]), None);
    }

    #[tokio::test]
    async fn the_sni_peek_leaves_the_client_hello_in_the_socket() {
        // The gate-closed tunnel reads the SNI with `peek` precisely so that the
        // bytes are still queued for the relay that follows: consuming them here
        // would break the end-to-end handshake the client performs.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        let hello = client_hello_record(Some("steamcommunity.com"));
        client.write_all(&hello).await.unwrap();
        assert_eq!(
            peek_client_sni(&server).await.as_deref(),
            Some("steamcommunity.com")
        );
        let mut seen = vec![0u8; hello.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            server.read_exact(&mut seen),
        )
        .await
        .expect("the peeked ClientHello was consumed instead of staying in the socket")
        .unwrap();
        assert_eq!(seen, hello);
    }

    #[tokio::test]
    async fn a_steered_client_hello_reaches_the_upstream_undecrypted() {
        // Gate-closed DNS-interception path: the hook steered the client to
        // `127.0.0.1:443` and the root certificate is not trusted, so the listener
        // relays instead of decrypting. The stand-in upstream is addressed as an IP
        // literal, so `dial_by_name` resolves it without any lookup (offline).
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let hello = client_hello_record(Some("steamcommunity.com"));
        let expected = hello.clone();
        let origin = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            // Echoing what arrived proves the upstream saw the real ClientHello.
            let mut seen = vec![0u8; expected.len()];
            sock.read_exact(&mut seen).await.unwrap();
            sock.write_all(&seen).await.unwrap();
        });
        let (log_tx, _log_rx) = tokio::sync::mpsc::unbounded_channel();
        let rt = FwdRuntime {
            config: Arc::new(RwLock::new(ProxySettings::default())),
            domains: Arc::new(RwLock::new(HashSet::new())),
            stats: Arc::new(Mutex::new(crate::proxy::FlowStats::default())),
            log_tx,
            mitm: None,
            forward: Arc::new(RwLock::new(std::collections::HashMap::new())),
            configured_ips: Arc::new(RwLock::new(Vec::new())),
        };
        // The browser end of a loopback pair; the accepted end stands in for the
        // socket `run_steered_tunnel_on` would have handed to the handler.
        let browser_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut browser = TcpStream::connect(browser_listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = browser_listener.accept().await.unwrap();
        let task = {
            let rt = rt.clone();
            tokio::spawn(async move {
                relay_bare(server, "127.0.0.1", upstream_port, &rt).await;
            })
        };
        browser.write_all(&hello).await.unwrap();
        let mut back = vec![0u8; hello.len()];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            browser.read_exact(&mut back),
        )
        .await
        .expect("the steered ClientHello was not relayed")
        .unwrap();
        // Byte for byte: nothing was terminated locally and no request was
        // decrypted on the way through.
        assert_eq!(back, hello);
        browser.shutdown().await.unwrap();
        origin.await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .expect("the bare tunnel did not finish after both sides closed")
            .unwrap();
    }

    #[test]
    fn manifest_lookups_are_gated_by_only_enable_proxy_script() {
        let ips: Vec<(String, Vec<IpAddr>)> = vec![(
            "*.example.com".to_string(),
            vec![IpAddr::from([1, 1, 1, 1])],
        )];
        let forward: std::collections::HashMap<String, String> =
            [("*.example.com".to_string(), "cdn.example.net".to_string())]
                .into_iter()
                .collect();
        // Default: the manifest drives the upstream lookups.
        let manifest_on = ProxySettings::default();
        assert_eq!(
            manifest_ips_for(&manifest_on, &ips, "www.example.com").to_vec(),
            vec![IpAddr::from([1, 1, 1, 1])]
        );
        assert_eq!(
            manifest_forward_for(&manifest_on, &forward, "www.example.com"),
            Some("cdn.example.net")
        );
        // `OnlyEnableProxyScript` on: the original skips the whole manifest lookup
        // (`TryGetDomainConfig` returns the default domain config), so neither the
        // configured addresses nor the substitute hostname applies.
        let script_only = ProxySettings {
            only_enable_proxy_script: true,
            ..Default::default()
        };
        assert!(manifest_ips_for(&script_only, &ips, "www.example.com").is_empty());
        assert_eq!(
            manifest_forward_for(&script_only, &forward, "www.example.com"),
            None
        );
    }

    #[test]
    fn the_fake_server_name_lookup_is_pattern_matched_and_gated() {
        let names: Vec<(String, String)> = vec![
            ("other.example.com".to_string(), "cdn.other.net".to_string()),
            ("*.example.com".to_string(), "cdn.example.net".to_string()),
        ];
        // The first pattern matching the host wins, so the exact entry covers its
        // own host while the wildcard entry covers the sub-domains.
        assert_eq!(
            fake_name_for(&names, "other.example.com"),
            Some("cdn.other.net")
        );
        assert_eq!(
            fake_name_for(&names, "www.example.com"),
            Some("cdn.example.net")
        );
        assert_eq!(fake_name_for(&names, "unrelated.test"), None);
        // `OnlyEnableProxyScript` skips the whole manifest lookup, exactly like the
        // configured addresses and the substitute hostname.
        let script_only = ProxySettings {
            only_enable_proxy_script: true,
            ..Default::default()
        };
        assert_eq!(
            manifest_fake_name_for(&script_only, &names, "www.example.com"),
            None
        );
        assert_eq!(
            manifest_fake_name_for(&ProxySettings::default(), &names, "www.example.com"),
            Some("cdn.example.net")
        );
    }

    #[tokio::test]
    async fn only_enable_proxy_script_ignores_configured_addresses() {
        // A live loopback upstream stands in for the manifest-configured address of
        // the target host. The target is an IP literal, so neither branch needs a
        // lookup and the whole test stays offline: the configured address is the
        // only way of reaching the upstream, and the host's own address is a
        // loopback port with nothing listening.
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let fake = tokio::spawn(async move {
            let (mut sock, _) = upstream.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            sock.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nvia-ip-addr",
            )
            .await
            .unwrap();
        });
        let configured = vec![("127.0.0.2".to_string(), vec![IpAddr::from([127, 0, 0, 1])])];
        let target = format!("http://127.0.0.2:{upstream_port}/foo");

        // Default: `ReverseProxyConfig.IPAddress` applies and the request is
        // forwarded to the configured address.
        let answer = proxy_response(false, false, false, configured.clone(), &target).await;
        assert!(
            answer.contains("via-ip-addr"),
            "unexpected answer: {answer}"
        );
        fake.await.unwrap();

        // `OnlyEnableProxyScript` on: the manifest lookup is skipped, so the
        // configured address is not dialled - the request falls through to the
        // dial-by-name branch (P2-9b) and the host's own address refuses it.
        let answer = proxy_response(false, false, true, configured, &target).await;
        assert!(
            answer.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "unexpected answer: {answer}"
        );
    }

    /// Proxy settings with the agent enabled and pointed at a loopback agent.
    fn agent_enabled(agent_addr: SocketAddr) -> ProxySettings {
        ProxySettings {
            two_level_agent_enable: true,
            two_level_agent_type: ExternalProxyType::Http,
            two_level_agent_ip: agent_addr.ip().to_string(),
            two_level_agent_port: agent_addr.port(),
            ..Default::default()
        }
    }

    /// Loopback stand-in for the second-level agent: answers an HTTP `CONNECT`,
    /// hands back the request head it was asked for, then relays to `upstream`.
    /// Relaying to a fixed local address stands in for the resolution the real
    /// agent performs on the name it was handed.
    async fn fake_http_agent(
        upstream: SocketAddr,
    ) -> (SocketAddr, tokio::sync::oneshot::Receiver<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, captured) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut client, _) = listener.accept().await.unwrap();
            let mut head: Vec<u8> = Vec::new();
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                if client.read_exact(&mut byte).await.is_err() {
                    return;
                }
                head.push(byte[0]);
            }
            let _ = tx.send(head);
            let _ = client
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await;
            let Ok(mut origin) = TcpStream::connect(upstream).await else {
                return;
            };
            let _ = tokio::io::copy_bidirectional(&mut client, &mut origin).await;
        });
        (addr, captured)
    }

    /// The upstream a fake agent relays to: answers one request with a marker body
    /// so a test can tell "reached through the agent" from "reached directly".
    async fn marker_upstream() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nvia-agent",
                    )
                    .await;
                let _ = sock.flush().await;
            }
        });
        addr
    }

    /// Send one request over a dialled stream and return the answer.
    async fn exchange(stream: &mut TcpStream) -> String {
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: target.test\r\n\r\n")
            .await
            .unwrap();
        let mut answer = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_to_end(&mut answer),
        )
        .await
        .expect("the tunnel never answered")
        .unwrap();
        String::from_utf8_lossy(&answer).to_string()
    }

    /// A loopback DoH endpoint that answers every query for `host` with `ip`.
    async fn doh_stub(host: &'static str, ip: &'static str) -> String {
        let body = format!(
            r#"{{"Status":0,"Answer":[{{"name":"{host}","type":1,"TTL":60,"data":"{ip}"}}]}}"#
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(body.as_bytes()).await;
                let _ = sock.flush().await;
            }
        });
        format!("http://{addr}")
    }

    /// A loopback TLS upstream presenting a self-signed certificate, i.e. one the
    /// webpki roots cannot know.
    async fn untrusted_tls_upstream() -> SocketAddr {
        crate::mitm::ensure_crypto_provider();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec!["upstream.test".to_string()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls::pki_types::PrivateKeyDer::Pkcs8(
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()),
                ),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(sock).await;
                });
            }
        });
        addr
    }

    #[test]
    fn the_agent_settings_are_read_into_a_usable_agent() {
        // Off by default: the original builds `HttpNoProxy.Instance` in that case.
        assert!(agent_config(&ProxySettings::default()).is_none());

        let cfg = ProxySettings {
            two_level_agent_enable: true,
            two_level_agent_type: ExternalProxyType::Socks4,
            two_level_agent_ip: "  agent.example.com  ".to_string(),
            two_level_agent_port: 1080,
            ..Default::default()
        };
        let agent = agent_config(&cfg).expect("the agent should be configured");
        assert_eq!(agent.proxy_type, ExternalProxyType::Socks4);
        assert_eq!(agent.host, "agent.example.com");
        assert_eq!(agent.port, 1080);
        // Neither field set: the original leaves `Credentials` unset.
        assert_eq!(agent.credentials, None);

        // The original attaches credentials when either field is non-empty.
        let with_user = ProxySettings {
            two_level_agent_user: "Aladdin".to_string(),
            ..cfg.clone()
        };
        assert_eq!(
            agent_config(&with_user).unwrap().credentials,
            Some(("Aladdin".to_string(), String::new()))
        );
        let with_password = ProxySettings {
            two_level_agent_password: "open sesame".to_string(),
            ..cfg.clone()
        };
        assert_eq!(
            agent_config(&with_password).unwrap().credentials,
            Some((String::new(), "open sesame".to_string()))
        );

        // An empty address is treated as "no agent" instead of an empty target.
        let empty = ProxySettings {
            two_level_agent_ip: "   ".to_string(),
            ..cfg
        };
        assert!(agent_config(&empty).is_none());
    }

    #[tokio::test]
    async fn a_literal_agent_address_is_dialled_without_a_lookup() {
        let cfg = ProxySettings {
            two_level_agent_enable: true,
            two_level_agent_ip: "127.0.0.1".to_string(),
            two_level_agent_port: 1080,
            ..Default::default()
        };
        let agent = agent_config(&cfg).unwrap();
        assert_eq!(
            agent_addrs(&cfg, &agent).await,
            vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 1080)]
        );
    }

    /// A name goes through the very same `resolve_a` chain as any other upstream:
    /// `.invalid` (RFC 2606) can never be answered by plain DNS, so an answer can
    /// only have come from the configured DoH endpoint.
    #[tokio::test]
    async fn a_named_agent_endpoint_is_resolved_through_the_dns_chain() {
        let doh = doh_stub("agent.wtlite.invalid", "127.0.0.1").await;
        let cfg = ProxySettings {
            two_level_agent_enable: true,
            two_level_agent_ip: "agent.wtlite.invalid".to_string(),
            two_level_agent_port: 7890,
            use_doh: true,
            custom_doh_address: doh,
            ..Default::default()
        };
        let agent = agent_config(&cfg).expect("the agent should be configured");
        assert_eq!(
            agent_addrs(&cfg, &agent).await,
            vec![SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 7890)]
        );
    }

    #[tokio::test]
    async fn an_enabled_agent_carries_the_dial_instead_of_the_candidate_sequence() {
        let upstream = marker_upstream().await;
        let (agent_addr, captured) = fake_http_agent(upstream).await;
        let cfg = agent_enabled(agent_addr);
        // No direct candidate at all: only the agent can reach an upstream, so an
        // answer proves the tunnel went through it (`ConnectCallback` hands every
        // dial to the proxy in the same way).
        let mut stream = dial_upstream(&cfg, &[], "target.test", 443)
            .await
            .expect("the agent tunnel was not used");
        assert!(exchange(&mut stream).await.contains("via-agent"));
        // The target was handed over as a name, never as an address B resolved.
        let head = String::from_utf8_lossy(&captured.await.unwrap()).to_string();
        assert!(
            head.starts_with("CONNECT target.test:443 HTTP/1.1\r\n"),
            "unexpected agent request: {head}"
        );
    }

    #[tokio::test]
    async fn a_disabled_agent_leaves_the_direct_dial_in_place() {
        let upstream = marker_upstream().await;
        let (agent_addr, captured) = fake_http_agent(upstream).await;
        let mut cfg = agent_enabled(agent_addr);
        cfg.two_level_agent_enable = false;
        // The candidate sequence is what is dialled, exactly as before: an empty
        // sequence still fails ...
        assert!(dial_upstream(&cfg, &[], "target.test", 443).await.is_none());
        // ... and the live candidate is the one that reaches the upstream.
        let mut stream = dial_upstream(&cfg, &[upstream], "target.test", 443)
            .await
            .expect("the direct dial was not used");
        assert!(exchange(&mut stream).await.contains("via-agent"));
        // The agent was never dialled.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), captured)
                .await
                .is_err(),
            "the agent was dialled although the feature is off"
        );
    }

    /// The agent tunnel is established, yet the upstream certificate is still
    /// refused: B's own connector verifies it against the webpki roots, so the
    /// certificate has to fail and the fallback to the next SNI candidate stays
    /// meaningful. The original disables verification on this path
    /// (`ReverseProxyHttpClientHandler.cs` L103-L114) and would keep the stream.
    #[tokio::test]
    async fn an_upstream_certificate_outside_the_webpki_roots_is_still_refused_over_the_agent() {
        let tls = untrusted_tls_upstream().await;
        let (agent_addr, captured) = fake_http_agent(tls).await;
        let cfg = agent_enabled(agent_addr);
        assert!(
            dial_upstream_tls(
                &cfg,
                &[],
                "upstream.test",
                443,
                &crate::mitm::tls_connector()
            )
            .await
            .is_none(),
            "an upstream certificate outside the webpki roots was accepted over the agent"
        );
        // The tunnel itself was established, so the failure above is the
        // certificate check and not a missing agent path.
        let head = String::from_utf8_lossy(&captured.await.unwrap()).to_string();
        assert!(
            head.starts_with("CONNECT upstream.test:443 HTTP/1.1\r\n"),
            "unexpected agent request: {head}"
        );

        // Unchanged for a disabled agent: the same untrusted upstream is dialled
        // directly and refused there too.
        let off = ProxySettings::default();
        assert!(dial_upstream_tls(
            &off,
            &[tls],
            "upstream.test",
            443,
            &crate::mitm::tls_connector()
        )
        .await
        .is_none());
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
            // Exact endpoint (optionally with a query), not a prefix: a
            // `/package` request is not a PAC fetch.
            let path = path.split('?').next().unwrap_or(path);
            return path == "/pac" || path == "/proxy.pac";
        }
    }
    false
}

/// True for an absolute-URI request whose scheme is plain HTTP
/// (case-insensitive, like the original `Request.Scheme == Uri.UriSchemeHttp`).
fn is_plain_http(target: &str) -> bool {
    matches!(target.get(..7), Some(p) if p.eq_ignore_ascii_case("http://"))
}

/// True for an absolute-URI request target (`http://…` or `https://…`, scheme
/// matched case-insensitively): the requests the original `HttpProxyMiddleware`
/// recognises as proxied (`ProxyProtocol.Proxy`) instead of answering with the
/// PAC file.
fn is_absolute_http_target(target: &str) -> bool {
    is_plain_http(target)
        || matches!(target.get(..8), Some(p) if p.eq_ignore_ascii_case("https://"))
}

/// The original's `IsDomain` (`HttpReverseProxyMiddleware` L223):
/// `!IPAddress.TryParse(host, out _) && host.Contains('.')`. Only a name that
/// needs a DNS lookup is the pollution guard's business - an IP literal, or a
/// dotless name such as `localhost`, never is (the original hands those to
/// `next(context)` / its agent instead of the guard).
fn is_domain_form(host: &str) -> bool {
    host.parse::<IpAddr>().is_err() && host.contains('.')
}

/// The original's pollution test (`HttpReverseProxyMiddleware` L105):
/// `ip == null || IPAddress.IsLoopback(ip)`, where `ip` is the *first* address
/// the analysis yields. An empty answer counts as poisoned, so a name the chain
/// cannot resolve is refused rather than forwarded.
fn is_dns_poisoned(ips: &[IpAddr]) -> bool {
    match ips.first() {
        Some(ip) => ip.is_loopback(),
        None => true,
    }
}

/// Split `host:port`, falling back to `default_port` when no port is present.
///
/// CONNECT targets default to 443 (`parse_host_port`); absolute-form request
/// targets default per scheme - an `http://host/path` request without an
/// explicit port must reach port 80, not 443. IPv6 literals are accepted in
/// their bracketed URL form (`[::1]:8080`).
fn parse_host_port_default(target: &str, default_port: u16) -> Option<(String, u16)> {
    let t = target.trim().trim_end_matches('/');
    if let Some(rest) = t.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = rest[..end].to_string();
        let after = &rest[end + 1..];
        let port = match after.strip_prefix(':') {
            Some(p) => p.trim().parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };
        return Some((host, port));
    }
    match t.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => {
            Some((host.to_string(), port.parse().ok()?))
        }
        _ => Some((t.to_string(), default_port)),
    }
}

fn parse_host_port(target: &str) -> Option<(String, u16)> {
    parse_host_port_default(target, 443)
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
    let pac =
        crate::sysproxy::create_pac(&proxy_host, &domains.iter().cloned().collect::<Vec<_>>());
    let body = pac.as_bytes();
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Disposition: attachment;filename=proxy.pac\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tcp.write_all(head.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
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
    // Scheme matching is case-insensitive (the original compares
    // `Request.Scheme`, which Kestrel normalizes to lower case).
    let rest = if is_plain_http(uri) {
        uri.get(7..)
    } else if matches!(uri.get(..8), Some(p) if p.eq_ignore_ascii_case("https://")) {
        uri.get(8..)
    } else {
        None
    };
    // Only an absolute URI reaches this handler (`handle_conn` answers everything
    // else with the PAC file, mirroring `HttpProxyPacMiddleware`). The branch is
    // kept explicit so a non-absolute target gets a definite answer instead of
    // the connection being closed with nothing written.
    let Some(r) = rest else {
        let _ = tcp
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            .await;
        return Ok(());
    };
    let hostpart = r.split('/').next().unwrap_or("").to_string();
    // The scheme decides the default port: http://host/path is port 80, and an
    // https:// absolute target is port 443. The old default of 443 made every
    // portless plain-HTTP proxy request dial the TLS port and fail.
    let default_port = if is_plain_http(uri) { 80 } else { 443 };
    let (host, port) = parse_host_port_default(&hostpart, default_port)
        .unwrap_or_else(|| (hostpart.clone(), default_port));
    let path = match r.find('/') {
        Some(i) => r[i..].to_string(),
        None => "/".to_string(),
    };
    let mut req2 = req.clone();
    req2.path = path;

    let cfg = rt.config.read().unwrap().clone();
    let domains = rt.domains.read().unwrap().clone();
    let accelerated = is_accelerated(&host, &domains);

    // Plain-HTTP requests are answered with a redirect before any upstream work,
    // mirroring the original `HttpReverseProxyMiddleware`: for an http request to
    // a proxied host it replies
    // `Redirect("https://" + Request.Host.Host + RawUrl())`, i.e. the scheme is
    // swapped, the port is dropped and the path + query are preserved. The scope
    // here is narrowed to accelerated hosts (the original redirects every
    // domain-like host, matched or not) - deviation note in the review report
    // (P1-7). The predicate itself is a second deviation, recorded there as P2-9:
    // the original tests `Request.Scheme == Uri.UriSchemeHttp`, and that is the
    // *connection* scheme - Kestrel drops the `https://` of an absolute request
    // line (`HttpProtocol.cs` L402-L408) - so the original redirects an
    // `https://` absolute target on a plain connection too, while B reads the
    // target's own scheme and forwards it. The deviation direction favours B: the
    // original would 302 an absolute-form `https://` target to the very same URL,
    // and a client that keeps using absolute form over the plain proxy would loop
    // there; no real client sends that shape (browsers CONNECT for https).
    if cfg.enable_http_proxy_to_https && is_plain_http(uri) && accelerated {
        let location = format!("https://{host}{}", req2.path);
        let head = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        tcp.write_all(head.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        rt.send_log(format!(
            "[HTTP] {} {host}:{port} -> 302 {location}",
            req.method
        ));
        return Ok(());
    }

    let preferred: Vec<IpAddr> =
        manifest_ips_for(&cfg, &rt.configured_ips.read().unwrap(), &host).to_vec();
    // Only an accelerated host is resolved through B's own DoH-first chain. Every
    // other host is dialled by name below (P2-9b), the same way the CONNECT path
    // answers an unmatched host, so the two paths finally agree.
    let ips = if accelerated {
        dns::resolve_a(
            &host,
            &cfg.proxy_master_dns,
            cfg.use_doh,
            &cfg.custom_doh_address,
        )
        .await
    } else {
        Vec::new()
    };
    rt.send_log(format!("[MITM] {host}:{port} resolved to {ips:?}"));
    let addrs = http1::candidate_endpoints(&preferred, port, &ips);
    // The original refuses a domain-like host the manifest does not know when its
    // own DNS analysis answers nothing or a loopback address
    // (`HttpReverseProxyMiddleware` L100-L111: `ip == null ||
    // IPAddress.IsLoopback(ip)` -> 500, the shape an ISP-poisoned name takes -
    // it points back at the machine). The guard reuses the manifest-miss
    // condition ("nothing accelerated, no configured address") and is skipped
    // while `OnlyEnableProxyScript` is on, which is the original's own second
    // half of that condition. It runs before any dial, so a second-level agent
    // does not make a poisoned name reachable either - the original reaches the
    // guard for a domain-like host whatever its agent setting is, because only a
    // non-domain host takes its agent branch.
    //
    // The answer it judges is the one the unmatched dial below would reach:
    // `system_addrs` is the OS resolver, i.e. exactly the source `dial_by_name`
    // dials through (C-3). The original resolves this leg through its own
    // `DomainResolver` instead, so this stays a deliberate deviation - B's
    // de-pollution is scoped to the manifest-covered hosts, and an unmatched name
    // takes the OS answer, which is also what the CONNECT path already does
    // (P2-9b). The resolved list is kept: the dial leg below spends it rather
    // than letting the OS answer a second time.
    let mut system_ips: Vec<IpAddr> = Vec::new();
    if !accelerated && addrs.is_empty() && is_domain_form(&host) && !cfg.only_enable_proxy_script {
        system_ips = system_addrs(&host, port).await;
        if is_dns_poisoned(&system_ips) {
            rt.send_log(format!(
                "[HTTP] {host}:{port} resolved to {system_ips:?}, answering 500 (DNS pollution guard)"
            ));
            // Same message (and same UTF-8 body) the original writes.
            let body =
                format!("域名 {host} 可能已经被 DNS 污染，如果域名为本机域名，请解析为非回环 IP。");
            let head = format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain; charset=utf-8\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            tcp.write_all(head.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            tcp.write_all(body.as_bytes())
                .await
                .map_err(|e| e.to_string())?;
            return Ok(());
        }
    }
    // Same rule as the CONNECT tunnel: with the agent on, the candidate sequence
    // is bypassed and the agent is asked to reach the target itself.
    if let Some(agent) = agent_config(&cfg) {
        rt.send_log(format!(
            "[HTTP] {host}:{port} via agent {}://{}:{}",
            agent.proxy_type.as_scheme(),
            agent.host,
            agent.port
        ));
    }
    let mut upstream = dial_upstream(&cfg, &addrs, &host, port).await;
    if upstream.is_none() && !accelerated && addrs.is_empty() && agent_config(&cfg).is_none() {
        // The manifest knows nothing about this host. The original
        // `HttpReverseProxyMiddleware` hands such a request to its
        // `defaultDomainConfig` and forwards it anyway, resolving the name through
        // `DomainResolver`. B mirrors its own CONNECT path instead - the gate above
        // is the one in `handle_connect` - so an unmatched host is dialled by name
        // rather than answered with 502 (P2-9b).
        if system_ips.is_empty() {
            // No system answer in hand: an IP literal or a dotless name, which the
            // guard never resolves, and `OnlyEnableProxyScript`, which skips it.
            rt.send_log(format!(
                "[HTTP] {host}:{port} is not in the manifest, dialling it by name"
            ));
            upstream = dial_by_name(&host, port).await;
        } else {
            // The guard already resolved this name through the OS resolver, so the
            // very addresses it judged are the ones dialled: asking the OS again
            // could yield a different answer, and a name that passed the guard
            // would then be dialled somewhere the guard never saw.
            rt.send_log(format!(
                "[HTTP] {host}:{port} is not in the manifest, dialling the system answer {system_ips:?}"
            ));
            upstream = dial_upstream(
                &cfg,
                &http1::candidate_endpoints(&system_ips, port, &[]),
                &host,
                port,
            )
            .await;
        }
    }
    let upstream = match upstream {
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
    let head = match http1::read_response_head(&mut u_r, http1::RESPONSE_HEAD_TIMEOUT).await {
        Some(h) => h,
        None => {
            // An upstream that accepts the request but stalls must not leave the
            // client hanging either: answer 502 and close.
            rt.send_log(format!("[HTTP] no response from {host}:{port}"));
            let _ = tcp
                .write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await;
            return Ok(());
        }
    };
    rt.send_log(format!(
        "[HTTP] {} {host}:{port} -> {}",
        req.method, head.status
    ));
    let _keep = http1::stream_response_body(&mut u_r, tcp, &head, &req.method)
        .await
        .unwrap_or(false);
    Ok(())
}
