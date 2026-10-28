//! MITM TLS server for Hosts mode.
//!
//! Listens on port 443, terminates TLS with dynamically generated per-SNI
//! leaf certificates (signed by our root CA), then forwards decrypted HTTP
//! requests to the real upstream. Mirrors the original HttpReverseProxyMiddleware
//! + UseTls (ListenOptionsExtensions) behavior.

use crate::cert::{CertificateManager, LeafCache, RootCertificate};
use crate::dns;
use crate::http1;
use crate::settings::ProxySettings;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

/// Dynamic SNI certificate resolver (rustls ResolvesServerCert).
struct DynCertResolver {
    cm: Arc<CertificateManager>,
    cache: Arc<LeafCache>,
    root: Arc<RootCertificate>,
}

impl fmt::Debug for DynCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DynCertResolver").finish()
    }
}

/// Install the process-wide crypto provider exactly once.
///
/// `CertifiedKey::from_der` needs a provider; without one it silently fails and
/// every TLS handshake is aborted, which looks like a network error.
pub fn ensure_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
    });
}

impl rustls::server::ResolvesServerCert for DynCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        ensure_crypto_provider();
        let Some(sni) = client_hello.server_name() else {
            log::warn!(target: "wtlite_core::proxy", "[mitm-resolver] no SNI in ClientHello");
            return None;
        };
        let Some((cert_der, key_der)) = self.cache.get_or_create(sni, &self.cm, &self.root) else {
            log::warn!(target: "wtlite_core::proxy", "[mitm-resolver] leaf cert generation failed for {sni}");
            return None;
        };
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
        );
        let Some(provider) = rustls::crypto::CryptoProvider::get_default() else {
            log::warn!(target: "wtlite_core::proxy", "[mitm-resolver] no CryptoProvider installed");
            return None;
        };
        rustls::sign::CertifiedKey::from_der(
            vec![rustls::pki_types::CertificateDer::from(cert_der)],
            key,
            &provider,
        )
        .ok()
        .map(Arc::new)
    }
}

/// Shared runtime state for the MITM server.
#[derive(Clone)]
pub struct MitmRuntime {
    pub cm: Arc<CertificateManager>,
    pub cache: Arc<LeafCache>,
    pub root: Arc<RootCertificate>,
    pub config: Arc<RwLock<ProxySettings>>,
    pub stats: Arc<Mutex<crate::proxy::FlowStats>>,
    pub log_tx: tokio::sync::mpsc::UnboundedSender<String>,
    /// Intercept set (listen domains). Upstream hosts NOT in this set may be
    /// resolved via the system resolver when DoH fails (they are not answered
    /// with 127.0.0.1, so no self-connect loop).
    pub domains: Arc<RwLock<std::collections::HashSet<String>>>,
    /// Host -> alternate hostname to dial upstream (mirrors the original
    /// `ForwardDestination`: the request keeps its original Host header while
    /// the TCP/TLS connection targets a different, reachable name).
    pub forward: Arc<RwLock<std::collections::HashMap<String, String>>>,
    /// Manifest-configured upstream addresses (original
    /// `ReverseProxyConfig.IPAddress`), in manifest order: the first pattern
    /// matching the requested host wins (`domain_matches`, so `*.x.com` keys are
    /// honoured). Offered ahead of the resolved answers; the TLS handshake still
    /// decides whether an address is usable.
    pub configured_ips: crate::fwd::ConfiguredIps,
    /// Manifest-configured substitute upstream names (original
    /// `ReverseProxyConfig.FakeServerName`), in manifest order: the name presented
    /// to the upstream as the TLS SNI for the first pattern matching the requested
    /// host. Absent means the requested host itself is presented (see
    /// `sni_candidates`).
    pub fake_names: crate::fwd::FakeNames,
}

/// Build the rustls server config.
fn build_server_config(rt: &MitmRuntime) -> Result<Arc<rustls::ServerConfig>, String> {
    ensure_crypto_provider();
    let resolver = DynCertResolver {
        cm: rt.cm.clone(),
        cache: rt.cache.clone(),
        root: rt.root.clone(),
    };
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    // The original Kestrel listener negotiates HTTP/2 (and HTTP/1.1 as a
    // fallback); advertising h2 here lets the browser multiplex all requests of
    // a host over the single CONNECT tunnel.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Start the MITM listener loop.
pub async fn run_mitm(bind_ip: std::net::IpAddr, rt: MitmRuntime) -> Result<(), String> {
    let addr: SocketAddr = (bind_ip, 443).into();
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind 443 failed (need admin): {e}"))?;
    run_mitm_on(listener, rt).await
}

/// Run the accept loop on an already-bound listener.
pub async fn run_mitm_on(listener: tokio::net::TcpListener, rt: MitmRuntime) -> Result<(), String> {
    let config = build_server_config(&rt)?;
    let acceptor = TlsAcceptor::from(config);
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr failed: {e}"))?;
    rt.send_log(format!("MITM HTTPS reverse proxy listening on {addr}"));
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                // The forward-proxy listener already does this for PAC/System
                // CONNECTs; the Hosts/DNS-intercept 443 listener needs it for the
                // same Nagle/delayed-ACK reason (see http1::tune).
                let _ = tcp.set_nodelay(true);
                let acceptor = acceptor.clone();
                let rt = rt.clone();
                let _ = peer;
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(acceptor, tcp, 443, rt).await {
                        log::debug!("MITM conn error: {e}");
                    }
                });
            }
            Err(e) => {
                rt.send_log(format!("listener error: {e}"));
            }
        }
    }
}

impl MitmRuntime {
    pub fn send_log(&self, msg: String) {
        log::info!(target: "wtlite_core::proxy", "{msg}");
        let _ = self.log_tx.send(msg);
    }
}

/// Terminate TLS on a client stream that was already accepted (an HTTP CONNECT
/// tunnel) and reverse-proxy the decrypted requests.
///
/// Used for hosts that must be dialled through a substitute hostname: the
/// browser only accepts a certificate for the host it asked for, so the TLS
/// session has to end here before we can redial upstream with a different SNI.
pub async fn handle_tunnel(tcp: TcpStream, port: u16, rt: MitmRuntime) -> Result<(), String> {
    let config = build_server_config(&rt)?;
    let acceptor = TlsAcceptor::from(config);
    match handle_conn(acceptor, tcp, port, rt).await {
        Ok(()) => Ok(()),
        Err(e) => {
            log::warn!(target: "wtlite_core::proxy", "[mitm] tunnel handling failed: {e}");
            Err(e)
        }
    }
}

/// Handle one accepted TCP connection: TLS handshake, then HTTP/1.1 loop.
async fn handle_conn(
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    port: u16,
    rt: MitmRuntime,
) -> Result<(), String> {
    let mut tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
    if tls.get_ref().1.alpn_protocol() == Some(b"h2") {
        return handle_h2_conn(tls, port, rt).await;
    }
    // Process-wide upstream pool, like the original's pooled HttpClient.
    let pool = upstream_pool();

    loop {
        // One stream for both directions: `read_request` may have to answer
        // `Expect: 100-continue` while reading the head.
        let req = match http1::read_request(&mut tls).await {
            Some(r) => r,
            None => break,
        };
        let host = match req.host() {
            Some(h) => h,
            None => {
                write_400(&mut tls).await;
                break;
            }
        };
        // Dial a substitute hostname when one is configured for this host
        // (the original `ForwardDestination` + `TlsSni` pair).
        let connect_host = {
            let cfg = rt.config.read().unwrap();
            let table = rt.forward.read().unwrap();
            crate::fwd::manifest_forward_for(&cfg, &table, &host)
                .map(str::to_string)
                .unwrap_or_else(|| host.clone())
        };
        rt.send_log(format!("[MITM] {} {host} -> {connect_host}", req.method));
        let keep_alive = forward_one(&mut tls, &req, &host, &connect_host, port, &rt, &pool).await;
        if !keep_alive {
            break;
        }
    }
    Ok(())
}

/// Serve a client connection that negotiated HTTP/2 (ALPN h2).
async fn handle_h2_conn(
    tls: tokio_rustls::server::TlsStream<TcpStream>,
    port: u16,
    rt: MitmRuntime,
) -> Result<(), String> {
    let mut conn = h2::server::handshake(tls)
        .await
        .map_err(|e| format!("h2 server handshake failed: {e}"))?;
    rt.send_log(format!("[MITM] HTTP/2 connection on port {port}"));
    while let Some(result) = conn.accept().await {
        let (request, respond) = result.map_err(|e| e.to_string())?;
        let rt = rt.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_h2_request(request, respond, port, rt).await {
                log::warn!(target: "wtlite_core::proxy", "[h2] request failed: {e}");
            }
        });
    }
    Ok(())
}

/// AsyncWrite sink for an h2 stream: discards the HTTP/1.1 response head (the h2
/// head is built from the parsed `ResponseHead`) and streams the decoded body
/// with h2 flow-control backpressure.
struct H2StreamWriter {
    head_skipped: bool,
    send: h2::SendStream<bytes::Bytes>,
}

impl H2StreamWriter {
    fn finish(&mut self) {
        let _ = self.send.send_data(bytes::Bytes::new(), true);
    }

    fn reset(&mut self) {
        self.send.send_reset(h2::Reason::INTERNAL_ERROR);
    }
}

impl AsyncWrite for H2StreamWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.as_mut().get_mut();
        if !this.head_skipped {
            this.head_skipped = true;
            return Poll::Ready(Ok(buf.len()));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // h2 capacity starts at zero: reserve before polling, otherwise
        // poll_capacity waits forever even though the window is open.
        this.send.reserve_capacity(buf.len());
        loop {
            let capacity = this.send.capacity();
            if capacity > 0 {
                let n = capacity.min(buf.len());
                if let Err(e) = this
                    .send
                    .send_data(bytes::Bytes::copy_from_slice(&buf[..n]), false)
                {
                    log::warn!(target: "wtlite_core::proxy", "[h2-writer] send_data failed: {e:?}");
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
                return Poll::Ready(Ok(n));
            }
            match this.send.poll_capacity(cx) {
                Poll::Ready(Some(Ok(_))) => continue,
                Poll::Ready(Some(Err(e))) => {
                    log::warn!(target: "wtlite_core::proxy", "[h2-writer] capacity error: {e:?}");
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
                Poll::Ready(None) => {
                    log::warn!(target: "wtlite_core::proxy", "[h2-writer] stream closed while waiting for capacity");
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "h2 stream closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.finish();
        Poll::Ready(Ok(()))
    }
}

/// Forward one HTTP/2 request through the same hardened upstream path used by
/// HTTP/1.1. The upstream leg writes an HTTP/1.1 response into a duplex pipe;
/// this function de-chunks it and returns the body to the h2 stream.
async fn handle_h2_request(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    port: u16,
    rt: MitmRuntime,
) -> Result<(), String> {
    let (parts, mut body_stream) = request.into_parts();
    let method = parts.method.as_str().to_string();
    let path = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let authority = parts.uri.authority().map(|a| a.as_str().to_string());
    let request_port = parts.uri.port_u16().unwrap_or(port);
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut has_host = false;
    for (name, value) in parts.headers.iter() {
        if name.as_str().eq_ignore_ascii_case("host") {
            has_host = true;
        }
        headers.push((
            name.as_str().to_string(),
            String::from_utf8_lossy(value.as_bytes()).into_owned(),
        ));
    }
    if !has_host {
        if let Some(authority) = &authority {
            headers.push(("Host".to_string(), authority.clone()));
        }
    }
    let mut body = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        body.extend_from_slice(&chunk);
        let _ = body_stream.flow_control().release_capacity(chunk.len());
    }
    let req = http1::HttpRequest {
        method: method.clone(),
        path,
        headers,
        body,
    };
    let host = match req.host() {
        Some(host) => host,
        None => return send_h2_error(respond, 400).await,
    };
    let connect_host = {
        let cfg = rt.config.read().unwrap();
        let table = rt.forward.read().unwrap();
        crate::fwd::manifest_forward_for(&cfg, &table, &host)
            .map(str::to_string)
            .unwrap_or_else(|| host.clone())
    };
    rt.send_log(format!("[MITM:h2] {} {host} -> {connect_host}", req.method));

    let (mut response_reader, response_writer) = tokio::io::duplex(64 * 1024);
    let task_req = req.clone();
    let task_rt = rt.clone();
    let task_host = host.clone();
    let task_connect = connect_host.clone();
    let task = tokio::spawn(async move {
        let mut response_writer = response_writer;
        let pool = upstream_pool();
        forward_one(
            &mut response_writer,
            &task_req,
            &task_host,
            &task_connect,
            request_port,
            &task_rt,
            &pool,
        )
        .await
    });

    let head = match http1::read_response_head(
        &mut response_reader,
        UPSTREAM_BUDGET + std::time::Duration::from_secs(5),
    )
    .await
    {
        Some(head) => head,
        None => {
            task.abort();
            return send_h2_error(respond, 502).await;
        }
    };
    let interesting: Vec<String> = head
        .headers
        .iter()
        .filter(|(k, _)| {
            matches!(
                k.to_ascii_lowercase().as_str(),
                "content-length"
                    | "content-encoding"
                    | "content-type"
                    | "transfer-encoding"
                    | "connection"
            )
        })
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    rt.send_log(format!(
        "[MITM:h2] response {host} status={} headers={interesting:?}",
        head.status
    ));
    let send = match send_h2_response_head(&mut respond, &head, &req.method).await {
        Ok(send) => send,
        Err(e) => {
            rt.send_log(format!("[MITM:h2] response head failed for {host}: {e}"));
            task.abort();
            return Err(e);
        }
    };
    if let Some(send) = send {
        let mut writer = H2StreamWriter {
            head_skipped: false,
            send,
        };
        match http1::stream_response_body_decoded(
            &mut response_reader,
            &mut writer,
            &head,
            &req.method,
        )
        .await
        {
            Ok(_) => writer.finish(),
            Err(_) => {
                rt.send_log(format!("[MITM:h2] body stream failed for {host}"));
                writer.reset();
            }
        }
    }
    let _ = task.await;
    Ok(())
}

async fn send_h2_error(
    mut respond: h2::server::SendResponse<bytes::Bytes>,
    status: u16,
) -> Result<(), String> {
    let response = http::Response::builder()
        .status(status)
        .header("content-length", "0")
        .body(())
        .map_err(|e| e.to_string())?;
    respond
        .send_response(response, true)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Send the h2 response head. Returns `Some(send_stream)` when a body follows,
/// `None` for HEAD/1xx/204/304 (end-of-stream already set).
async fn send_h2_response_head(
    respond: &mut h2::server::SendResponse<bytes::Bytes>,
    head: &http1::ResponseHead,
    method: &str,
) -> Result<Option<h2::SendStream<bytes::Bytes>>, String> {
    let bodyless = method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&head.status)
        || head.status == 204
        || head.status == 304;
    let mut builder = http::Response::builder().status(head.status);
    let mut content_length: Option<String> = None;
    for (name, value) in &head.headers {
        let lower = name.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "connection"
                | "keep-alive"
                | "proxy-connection"
                | "transfer-encoding"
                | "upgrade"
                | "trailer"
                | "content-length"
        ) {
            if lower == "content-length" {
                content_length = Some(value.clone());
            }
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }
    if bodyless {
        if let Some(cl) = content_length {
            builder = builder.header("content-length", cl);
        }
    }
    let response = builder.body(()).map_err(|e| e.to_string())?;
    let send = respond
        .send_response(response, bodyless)
        .map_err(|e| e.to_string())?;
    Ok(if bodyless { None } else { Some(send) })
}

/// Overall budget for one request's upstream phase (resolve + dial + send +
/// response head). Every stage has its own timeout, but their sum was
/// unbounded before: on a blackholed path "[MITM] GET …" was followed by tens
/// of seconds of silence while the browser had long timed out. The budget
/// gives up and answers 502 instead. Streaming the response body after the
/// head is deliberately outside this budget - a long transfer is legitimate.
const UPSTREAM_BUDGET: std::time::Duration = std::time::Duration::from_secs(45);

/// How long one accelerated-host attempt may wait for the response head while
/// another endpoint is still available.
///
/// A censored GitHub edge often accepts TCP and completes TLS, then forwards no
/// data at all. Waiting the full 15 s `RESPONSE_HEAD_TIMEOUT` on such an edge
/// makes the browser give up before the working edge is ever tried; 6 s covers
/// a normal trans-Pacific TTFB and leaves room for two more candidates inside
/// the overall budget.
const FAST_HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// Connect+TLS budget for a non-final accelerated attempt. A censored edge can
/// also blackhole the TCP/TLS phase, and the original 10 s per-endpoint budget
/// would then consume the whole upstream budget before the fallback edges are
/// reached. Healthy GitHub edges handshake in 0.2-0.8 s here.
const FAST_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(4);

/// Response-head budget for the parallel fallback race (below). Longer than the
/// sequential budget because several edges are dialled at once and the winner
/// is the first to answer, not the first to connect.
const FALLBACK_RACE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// GitHub's published `meta.web` edge addresses.
///
/// `github.com`'s DNS answer is one anycast edge, and from a censored network
/// that single edge is frequently blackholed after the TLS handshake. The other
/// edges in the same published range are often reachable at the same time
/// (measured on this machine: `20.27.177.113` and `20.200.245.247` answered a
/// full page while `20.205.243.166` and every `140.82.*` edge forwarded
/// nothing). Racing a handful of them finds a working edge in about a second.
/// Source: `https://api.github.com/meta` (`web`), IPv4 entries; update this list
/// when GitHub publishes new edges.
const GITHUB_WEB_FALLBACK_IPS: &[&str] = &[
    "20.27.177.113",
    "20.200.245.247",
    "20.233.83.145",
    "20.205.243.166",
    "20.201.28.151",
    "20.207.73.82",
    "20.248.137.48",
    "20.26.156.215",
    "140.82.113.4",
    "140.82.121.4",
    "140.82.112.4",
    "140.82.114.4",
];

/// Fallback edges for a host served by GitHub's web frontend. Asset hosts use
/// different certificates/frontends (Fastly) and are not included.
fn github_fallback_ips(host: &str) -> Vec<IpAddr> {
    if host == "github.com" || host.ends_with(".github.com") {
        GITHUB_WEB_FALLBACK_IPS
            .iter()
            .filter_map(|ip| ip.parse().ok())
            .collect()
    } else {
        Vec::new()
    }
}

/// Whether racing the same request to several edges is safe.
///
/// Only bodyless, read-only methods are raced. A Git clone's initial
/// `GET /info/refs` is raced and the winning edge is then reused through the
/// last-good cache for the follow-up `POST /git-upload-pack`, so the body is
/// never duplicated across edges; pushes (`git-receive-pack`) keep the
/// sequential path.
fn race_safe(method: &str, _path: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "GET" | "HEAD" | "OPTIONS" | "TRACE"
    )
}

/// The last endpoint that returned a response head for a host.
///
/// `github.com` rotates among many edge addresses, and only some of them are
/// reachable from a censored network at any moment. Remembering the edge that
/// answered makes the rest of a page's requests (and the next page load) go
/// straight to it instead of re-running the whole stall/fallback sequence.
static LAST_GOOD: OnceLock<Mutex<HashMap<String, IpAddr>>> = OnceLock::new();

fn last_good_table() -> &'static Mutex<HashMap<String, IpAddr>> {
    LAST_GOOD.get_or_init(|| Mutex::new(HashMap::new()))
}

fn last_good_for(host: &str) -> Option<IpAddr> {
    last_good_table().lock().ok()?.get(host).copied()
}

fn remember_last_good(host: &str, ip: IpAddr) {
    if let Ok(mut table) = last_good_table().lock() {
        table.insert(host.to_string(), ip);
    }
}

/// Drop a cached edge after a request for the host failed end to end. Keeping it
/// would make every later request pay its connect/head timeout before falling
/// back to a healthy edge.
fn forget_last_good(host: &str) {
    if let Ok(mut table) = last_good_table().lock() {
        table.remove(host);
    }
}

/// Why the upstream phase gave up. The specific cause is logged where it is
/// detected; the caller answers 502 for every variant.
enum UpstreamFailure {
    Connect,
    NoResponse,
}

/// Why one endpoint attempt failed. Only the phase matters: the caller decides
/// whether another endpoint is worth trying.
#[derive(Debug, Clone, Copy)]
enum AttemptFailure {
    Connect,
    Write,
    NoResponse,
}

/// Whether a request may be retried on another endpoint after the request was
/// already written and the response head did not arrive.
///
/// Idempotent methods are always safe. `POST`/`PATCH` are not in general, but
/// Git's smart-HTTP endpoints are: a retried `git-upload-pack` is read-only and
/// a retried `git-receive-pack` is rejected or completes, never silently
/// duplicated. Retrying web form submissions is left out.
fn retryable_response(method: &str, path: &str) -> bool {
    let method = method.to_ascii_uppercase();
    if method != "POST" && method != "PATCH" {
        return true;
    }
    path.starts_with("/git-upload-pack")
        || path.starts_with("/git-receive-pack")
        || path.contains("/info/refs")
}

/// Gateway-style failures returned by an edge: another edge may serve the same
/// request. Only retried for `retryable_response` requests; the body has not
/// been streamed yet, so the request can be abandoned safely.
fn retryable_status(status: u16) -> bool {
    // 500 is included because an individual GitHub edge can return its generic
    // error page while another edge serves the request; only idempotent
    // requests are retried (the caller controls that).
    status == 500 || matches!(status, 502..=504)
}

/// One upstream connection plus the identity it was established with, kept
/// between requests of one client connection (the HTTP/1.1 analogue of the
/// original `SocketsHttpHandler`'s connection pool).
struct PooledUpstream {
    host: String,
    port: u16,
    sni: String,
    /// Established without SNI (`TlsSniPattern.None`).
    no_sni: bool,
    /// When the previous response completed. An upstream idle longer than
    /// `POOL_IDLE_TIMEOUT` is not reused: GitHub/edge keep-alive timeouts are
    /// shorter than a user's think time, and a dead socket must not turn into a
    /// failed POST (which cannot be replayed safely).
    returned_at: std::time::Instant,
    stream: tokio_rustls::client::TlsStream<TcpStream>,
}

const POOL_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Process-wide pool of idle upstream connections.
///
/// The original `SocketsHttpHandler` pools per origin across every client
/// connection; the previous per-client `Option` could not be shared by
/// concurrent HTTP/2 streams. A short critical section (no await) guards the
/// vector.
#[derive(Clone)]
struct UpstreamPool {
    inner: Arc<Mutex<Vec<PooledUpstream>>>,
}

impl UpstreamPool {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn take(
        &self,
        host: &str,
        port: u16,
        allowed: impl Fn(&PooledUpstream) -> bool,
    ) -> Option<PooledUpstream> {
        let mut connections = self.inner.lock().unwrap();
        connections.retain(|p| p.returned_at.elapsed() < POOL_IDLE_TIMEOUT);
        let index = connections
            .iter()
            .position(|p| p.host == host && p.port == port && allowed(p))?;
        Some(connections.remove(index))
    }

    fn put(&self, connection: PooledUpstream) {
        let mut connections = self.inner.lock().unwrap();
        connections.retain(|p| p.returned_at.elapsed() < POOL_IDLE_TIMEOUT);
        const POOL_MAX: usize = 64;
        if connections.len() < POOL_MAX {
            connections.push(connection);
        }
    }
}

fn upstream_pool() -> UpstreamPool {
    static POOL: OnceLock<UpstreamPool> = OnceLock::new();
    POOL.get_or_init(UpstreamPool::new).clone()
}

/// Upstream stream, response head and the body byte(s) already read by the
/// body-start probe (`stream_response_body` serves them before the stream).
type UpstreamAnswer = (
    tokio_rustls::client::TlsStream<TcpStream>,
    http1::ResponseHead,
    Vec<u8>,
);

/// A winning hedged answer: stream, head, probed body prefix, endpoint, SNI
/// label and whether SNI was omitted.
type HedgeAnswer = (
    tokio_rustls::client::TlsStream<TcpStream>,
    http1::ResponseHead,
    Vec<u8>,
    SocketAddr,
    String,
    bool,
);

/// Reader that serves the probed body prefix before the upstream stream.
struct PrefixedReader<R> {
    prefix: Vec<u8>,
    pos: usize,
    inner: R,
}

impl<R> PrefixedReader<R> {
    fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for PrefixedReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.as_mut().get_mut();
        if this.pos < this.prefix.len() {
            let n = (this.prefix.len() - this.pos).min(buf.remaining());
            buf.put_slice(&this.prefix[this.pos..this.pos + n]);
            this.pos += n;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

/// Whether this response carries a body (a gateway error is retried before any
/// body is read).
fn response_has_body(head: &http1::ResponseHead, method: &str) -> bool {
    if method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&head.status)
        || head.status == 204
        || head.status == 304
    {
        return false;
    }
    let content_length = head
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .and_then(|(_, v)| v.trim().parse::<u64>().ok());
    !matches!(content_length, Some(0))
}

/// Wait for the first body byte before adopting an endpoint.
///
/// A censored GitHub edge can answer the request head (`200 OK`) and then send
/// no body at all. Without this probe that edge wins the race, the browser gets
/// a head with zero bytes and waits out the body idle timeout. One byte is
/// enough to tell a live body from a blackholed one; it is handed to
/// `stream_response_body` through `PrefixedReader`.
async fn probe_body(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    head: &http1::ResponseHead,
    method: &str,
) -> Result<Vec<u8>, AttemptFailure> {
    if retryable_status(head.status) || !response_has_body(head, method) {
        return Ok(Vec::new());
    }
    let mut byte = [0u8; 1];
    match tokio::time::timeout(FAST_HEAD_TIMEOUT, stream.read(&mut byte)).await {
        Ok(Ok(1)) => Ok(vec![byte[0]]),
        _ => Err(AttemptFailure::NoResponse),
    }
}

/// Send the request on an established TLS stream and read the response head.
async fn exchange(
    stream: &mut tokio_rustls::client::TlsStream<TcpStream>,
    req: &http1::HttpRequest,
    host: &str,
    port: u16,
    head_timeout: std::time::Duration,
) -> Result<http1::ResponseHead, AttemptFailure> {
    let wire = http1::write_request(req, host, port, false);
    let write = async {
        stream.write_all(&wire).await.ok()?;
        stream.flush().await.ok()?;
        Some(())
    };
    if tokio::time::timeout(http1::CONNECT_TIMEOUT, write)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return Err(AttemptFailure::Write);
    }
    match http1::read_response_head(stream, head_timeout).await {
        Some(head) => Ok(head),
        None => Err(AttemptFailure::NoResponse),
    }
}

/// Connect (directly or through the second-level agent), complete the TLS
/// handshake with certificate verification, send the request and read the
/// response head. Every endpoint is verified end to end, so a blackholed edge
/// cannot be adopted just because it answered TCP.
#[allow(clippy::too_many_arguments)]
async fn attempt_upstream(
    cfg: &ProxySettings,
    connector: &tokio_rustls::TlsConnector,
    sni: &str,
    addr: SocketAddr,
    port: u16,
    req: &http1::HttpRequest,
    host: &str,
    head_timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
) -> Result<UpstreamAnswer, AttemptFailure> {
    ensure_crypto_provider();
    let mut stream = match tokio::time::timeout(
        connect_timeout,
        crate::fwd::dial_upstream_tls(cfg, &[addr], sni, port, connector),
    )
    .await
    {
        Ok(Some(stream)) => stream,
        Ok(None) | Err(_) => return Err(AttemptFailure::Connect),
    };
    let head = exchange(&mut stream, req, host, port, head_timeout).await?;
    let prefix = probe_body(&mut stream, &head, &req.method).await?;
    Ok((stream, head, prefix))
}

/// `attempt_upstream` with the SNI extension suppressed. The connector must be
/// a `no_sni_connector` built for `verify_host`.
#[allow(clippy::too_many_arguments)]
async fn attempt_upstream_no_sni(
    cfg: &ProxySettings,
    connector: &tokio_rustls::TlsConnector,
    addr: SocketAddr,
    verify_host: &str,
    target_host: &str,
    port: u16,
    req: &http1::HttpRequest,
    host: &str,
    head_timeout: std::time::Duration,
    connect_timeout: std::time::Duration,
) -> Result<UpstreamAnswer, AttemptFailure> {
    ensure_crypto_provider();
    let mut stream = match tokio::time::timeout(
        connect_timeout,
        crate::fwd::dial_upstream_tls_no_sni(
            cfg,
            &[addr],
            verify_host,
            target_host,
            port,
            connector,
        ),
    )
    .await
    {
        Ok(Some(stream)) => stream,
        Ok(None) | Err(_) => return Err(AttemptFailure::Connect),
    };
    let head = exchange(&mut stream, req, host, port, head_timeout).await?;
    let prefix = probe_body(&mut stream, &head, &req.method).await?;
    Ok((stream, head, prefix))
}

/// One hedged candidate: a TLS mode against one endpoint.
#[derive(Clone)]
enum HedgeMode {
    /// No SNI (the original default when `FakeServerName` is absent).
    NoSni(tokio_rustls::TlsConnector),
    /// SNI with the given name.
    Sni {
        sni: String,
        connector: tokio_rustls::TlsConnector,
    },
}

#[derive(Clone)]
struct HedgeCandidate {
    mode: HedgeMode,
    addr: SocketAddr,
}

const HEDGE_DELAY: std::time::Duration = std::time::Duration::from_millis(600);
const HEDGE_FALLBACK_AFTER: std::time::Duration = std::time::Duration::from_millis(1500);
const HEDGE_BUDGET: std::time::Duration = std::time::Duration::from_secs(32);

fn spawn_hedge(
    set: &mut tokio::task::JoinSet<(
        SocketAddr,
        String,
        bool,
        Result<UpstreamAnswer, AttemptFailure>,
    )>,
    candidate: HedgeCandidate,
    cfg: &ProxySettings,
    req: &Arc<http1::HttpRequest>,
    host: &str,
    target: &str,
    port: u16,
) {
    let cfg = cfg.clone();
    let req = req.clone();
    let host = host.to_string();
    let target = target.to_string();
    set.spawn(async move {
        let (sni, no_sni, outcome) = match candidate.mode {
            HedgeMode::NoSni(connector) => {
                let outcome = attempt_upstream_no_sni(
                    &cfg,
                    &connector,
                    candidate.addr,
                    &host,
                    &target,
                    port,
                    &req,
                    &host,
                    FAST_HEAD_TIMEOUT,
                    FAST_CONNECT_TIMEOUT,
                )
                .await;
                (String::new(), true, outcome)
            }
            HedgeMode::Sni { sni, connector } => {
                let outcome = attempt_upstream(
                    &cfg,
                    &connector,
                    &sni,
                    candidate.addr,
                    port,
                    &req,
                    &host,
                    FAST_HEAD_TIMEOUT,
                    FAST_CONNECT_TIMEOUT,
                )
                .await;
                (sni, false, outcome)
            }
        };
        (candidate.addr, sni, no_sni, outcome)
    });
}

/// Happy-eyeballs-style race for one request.
///
/// The first `initial` candidate starts immediately and the next starts every
/// `HEDGE_DELAY`; if none has answered after `HEDGE_FALLBACK_AFTER`, every
/// `fallback` candidate (the published GitHub edges, already both no-SNI and
/// SNI) is started at once. The first non-gateway response wins and the rest are
/// aborted. A healthy primary therefore causes one request; a blocked one is
/// bypassed in ~2 s instead of waiting out every sequential timeout.
#[allow(clippy::too_many_arguments)]
async fn hedged_attempts(
    cfg: &ProxySettings,
    req: &http1::HttpRequest,
    host: &str,
    connect_host: &str,
    port: u16,
    initial: Vec<HedgeCandidate>,
    fallback: Vec<HedgeCandidate>,
    rt: &MitmRuntime,
) -> Option<HedgeAnswer> {
    let shared_req = Arc::new(req.clone());
    let deadline = tokio::time::Instant::now() + HEDGE_BUDGET;
    let mut set = tokio::task::JoinSet::new();
    let mut next = 0usize;
    let mut fallback_started = fallback.is_empty();
    let mut hedge_timer = tokio::time::interval(HEDGE_DELAY);
    hedge_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let fallback_timer = tokio::time::sleep(HEDGE_FALLBACK_AFTER);
    tokio::pin!(fallback_timer);

    while next < initial.len() || !set.is_empty() || !fallback_started {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline) => {
                set.abort_all();
                return None;
            }
            _ = hedge_timer.tick(), if next < initial.len() => {
                let candidate = initial[next].clone();
                next += 1;
                spawn_hedge(&mut set, candidate, cfg, &shared_req, host, connect_host, port);
            }
            _ = &mut fallback_timer, if !fallback_started => {
                fallback_started = true;
                rt.send_log(format!(
                    "[MITM] hedge fallback: {} published candidates for {host}",
                    fallback.len()
                ));
                for candidate in fallback.iter().cloned() {
                    spawn_hedge(&mut set, candidate, cfg, &shared_req, host, connect_host, port);
                }
            }
            joined = set.join_next(), if !set.is_empty() => {
                if let Some(Ok((addr, sni, no_sni, Ok((stream, head, prefix))))) = joined {
                    if retryable_status(head.status) {
                        rt.send_log(format!(
                            "[MITM] hedge {host} via {addr} returned {}, continuing",
                            head.status
                        ));
                        continue;
                    }
                    set.abort_all();
                    rt.send_log(format!(
                        "[MITM] hedge won by {addr} sni={} for {host}",
                        if no_sni { "<none>" } else { &sni }
                    ));
                    return Some((stream, head, prefix, addr, sni, no_sni));
                }
            }
        }
    }
    None
}

/// Forward one request to the upstream and stream the response back.
///
/// For an accelerated host the fallback is request-level, not connect-level: an
/// edge that completes TCP/TLS and then never answers is abandoned and the next
/// endpoint (including addresses from the other DoH resolvers, fetched only
/// after a failure) is tried with the same request. This is what makes a
/// partially blackholed GitHub reachable; a connect-only fallback keeps the
/// first blackholed edge forever.
async fn forward_one<W: AsyncWrite + Unpin>(
    write_half: &mut W,
    req: &http1::HttpRequest,
    host: &str,
    connect_host: &str,
    port: u16,
    rt: &MitmRuntime,
    pool: &UpstreamPool,
) -> bool {
    let cfg = rt.config.read().unwrap().clone();
    let accelerated = crate::fwd::is_accelerated(host, &rt.domains.read().unwrap());
    let retry_response = accelerated && retryable_response(&req.method, &req.path);
    let agent_on = crate::fwd::agent_config(&cfg).is_some();
    let connector = tls_connector();
    // Computed before the budget so a pooled connection can be matched and used
    // without re-running DNS or the endpoint sequence.
    let fake_name = crate::fwd::manifest_fake_name_for(&cfg, &rt.fake_names.read().unwrap(), host)
        .map(str::to_string);
    let sni_primary = fake_name.clone().unwrap_or_else(|| host.to_string());
    let sni_list: Vec<String> = sni_candidates(&sni_primary, connect_host)
        .into_iter()
        .map(str::to_string)
        .collect();
    // The original `AccelerateProjectDTO` sets `TlsSni = false` unless a
    // `FakeServerName` is configured, so an ordinary accelerated project sends
    // **no SNI**. GitHub serves its normal certificate without SNI, and this
    // avoids SNI-based filtering. The verifier still checks the certificate
    // against the requested host; a host whose default certificate does not
    // cover it (e.g. api.github.com) falls through to the SNI attempts below.
    let no_sni_allowed = accelerated && fake_name.is_none();
    let no_sni_tls = if no_sni_allowed {
        no_sni_connector(host)
    } else {
        None
    };

    // Reuse an idle upstream connection for the same target, exactly like the
    // original's pooled HttpClient. The pool is process-wide so concurrent
    // client connections (and HTTP/2 streams) can share it. A pooled connection
    // that went stale is dropped and the normal dial sequence below takes over
    // (only for a retry-safe request; a POST that may already have been received
    // upstream is not replayed).
    let reusable = |previous: &PooledUpstream| {
        let reusable_identity = if previous.no_sni {
            no_sni_allowed
        } else {
            sni_list
                .iter()
                .any(|sni| sni.as_str() == previous.sni.as_str())
        };
        let fresh_enough = previous.returned_at.elapsed() < POOL_IDLE_TIMEOUT
            && (retry_response
                || previous.returned_at.elapsed() < std::time::Duration::from_secs(2));
        reusable_identity && fresh_enough
    };
    if let Some(previous) = pool.take(connect_host, port, reusable) {
        let mut stream = previous.stream;
        let head_timeout = if retry_response {
            FAST_HEAD_TIMEOUT
        } else {
            http1::RESPONSE_HEAD_TIMEOUT
        };
        let peer = stream
            .get_ref()
            .0
            .peer_addr()
            .unwrap_or_else(|_| SocketAddr::new(IpAddr::from([0, 0, 0, 0]), port));
        rt.send_log(format!(
            "[MITM] reuse {host}:{port} via {peer} sni={}",
            if previous.no_sni {
                "<none>"
            } else {
                &previous.sni
            }
        ));
        match exchange(&mut stream, req, host, port, head_timeout).await {
            Ok(head) if retry_response && retryable_status(head.status) => {
                rt.send_log(format!(
                    "[MITM] reused upstream for {host} returned {}, dialling another endpoint",
                    head.status
                ));
            }
            Ok(head) => {
                let prefix = match probe_body(&mut stream, &head, &req.method).await {
                    Ok(prefix) => prefix,
                    Err(_) => {
                        rt.send_log(format!(
                                "[MITM] reused upstream for {host} sent headers but no body; dialling again"
                            ));
                        Vec::new()
                    }
                };
                if !prefix.is_empty() || !response_has_body(&head, &req.method) {
                    let outcome = Ok((
                        stream,
                        head,
                        prefix,
                        peer,
                        previous.sni.clone(),
                        previous.no_sni,
                    ));
                    return finish_response(
                        write_half,
                        req,
                        host,
                        connect_host,
                        port,
                        rt,
                        pool,
                        agent_on,
                        outcome,
                    )
                    .await;
                }
            }
            Err(failure) => {
                rt.send_log(format!(
                    "[MITM] reused upstream for {host} failed: {failure:?}; dialling again"
                ));
                if !retry_response
                    && matches!(failure, AttemptFailure::Write | AttemptFailure::NoResponse)
                {
                    write_502(write_half).await;
                    return false;
                }
            }
        }
    }

    // Everything up to and including the response head runs under one budget:
    // DNS, the endpoint sequence, the alternate answers and the head reads. The
    // body streaming below is outside it on purpose.
    let outcome = tokio::time::timeout(UPSTREAM_BUDGET, async {
        // Resolve and dial `connect_host`, but keep `host` for the Host header.
        // A blocked domain resolves to poisoned IPs, while its CDN alias resolves
        // correctly and accepts the handshake only when SNI matches the alias.
        let mut ips = dns::resolve_a(
            connect_host,
            &cfg.proxy_master_dns,
            cfg.use_doh,
            &cfg.custom_doh_address,
        )
        .await;
        // Last resort: DNS-over-TCP (TCP:53 is not matched by the UDP interceptor).
        if ips.is_empty() {
            for srv in dns::tcp_dns_servers(&cfg.proxy_master_dns) {
                ips = dns::resolve_tcp(connect_host, srv).await;
                if !ips.is_empty() {
                    rt.send_log(format!("[MITM] TCP DNS {srv} -> {connect_host}: {ips:?}"));
                    break;
                }
            }
        }
        // Manifest-configured addresses of the requested host (original
        // `IPAddress`), offered ahead of the alias answers exactly like
        // `GetIPEndPointsAsync` - and still subject to the TLS verification below.
        let preferred: Vec<IpAddr> =
            crate::fwd::manifest_ips_for(&cfg, &rt.configured_ips.read().unwrap(), host).to_vec();
        let mut addrs = http1::candidate_endpoints(&preferred, port, &ips);
        if accelerated {
            // The edge that answered last time goes first, even if DNS has since
            // rotated to a different (possibly blackholed) address.
            if let Some(good) = last_good_for(host) {
                addrs.retain(|addr| addr.ip() != good);
                addrs.insert(0, SocketAddr::new(good, port));
            }
        }
        if agent_on {
            // The agent chooses the actual endpoint; one attempt per SNI is all
            // that is meaningful.
            addrs = vec![SocketAddr::new(IpAddr::from([0, 0, 0, 0]), port)];
        }
        // An authenticated request must not be sent twice to different edges:
        // duplicate requests can rotate session cookies and cause an
        // intermittent logged-out page. Such requests skip the hedged race and
        // instead try the published edges sequentially below.
        let stateful = req
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("cookie"))
            .any(|(_, cookie)| {
                let cookie = cookie.to_ascii_lowercase();
                cookie.contains("logged_in=yes") || cookie.contains("user_session=")
            });
        if stateful && accelerated && !agent_on {
            for ip in github_fallback_ips(host) {
                if !addrs.iter().any(|addr| addr.ip() == ip) {
                    addrs.push(SocketAddr::new(ip, port));
                }
            }
        }
        let mut tried_ips: Vec<IpAddr> = ips.clone();
        for addr in &addrs {
            if !tried_ips.contains(&addr.ip()) {
                tried_ips.push(addr.ip());
            }
        }
        // Idempotent accelerated requests go straight to the hedged race below;
        // the sequential no-SNI/SNI stages are only for POST-like or
        // authenticated requests.
        let hedge_path =
            accelerated && !agent_on && !stateful && race_safe(&req.method, &req.path);
        if !hedge_path {
        if let Some(no_sni) = &no_sni_tls {
            // Try the original's no-SNI mode first: for GitHub this is the
            // normal certificate (CN=github.com) and it is not subject to
            // SNI-based filtering. Certificate failures (for example
            // api.github.com, whose default vhost is github.com) fall through
            // to the SNI attempts rather than failing the request.
            for addr in &addrs {
                let head_timeout = if retry_response {
                    FAST_HEAD_TIMEOUT
                } else {
                    http1::RESPONSE_HEAD_TIMEOUT
                };
                rt.send_log(format!(
                    "[MITM] try {host}:{port} via {} no-sni",
                    if agent_on { "agent".to_string() } else { addr.to_string() }
                ));
                let connect_timeout = if retry_response {
                    FAST_CONNECT_TIMEOUT
                } else {
                    http1::CONNECT_TIMEOUT
                };
                match attempt_upstream_no_sni(
                    &cfg,
                    no_sni,
                    *addr,
                    host,
                    connect_host,
                    port,
                    req,
                    host,
                    head_timeout,
                    connect_timeout,
                )
                .await
                {
                    Ok((stream, head, prefix)) => {
                        if retry_response && retryable_status(head.status) {
                            rt.send_log(format!(
                                "[MITM] try {host} via {addr} no-sni returned {}, trying another endpoint",
                                head.status
                            ));
                            continue;
                        }
                        return Ok((stream, head, prefix, *addr, String::new(), true));
                    }
                    Err(failure) => {
                        rt.send_log(format!(
                            "[MITM] try {host} via {addr} no-sni failed: {failure:?}"
                        ));
                        let response_phase = matches!(
                            failure,
                            AttemptFailure::Write | AttemptFailure::NoResponse
                        );
                        if response_phase && !retry_response {
                            return Err(UpstreamFailure::NoResponse);
                        }
                    }
                }
            }
        }
        }
        if hedge_path {
            // Idempotent accelerated request: hedge the known endpoints and
            // publish-edge fallback instead of waiting out each sequential
            // timeout. This is the path real page loads take.
            let mut initial: Vec<HedgeCandidate> = Vec::new();
            for addr in &addrs {
                if let Some(conn) = no_sni_tls.as_ref() {
                    initial.push(HedgeCandidate {
                        mode: HedgeMode::NoSni(conn.clone()),
                        addr: *addr,
                    });
                }
                for sni in &sni_list {
                    initial.push(HedgeCandidate {
                        mode: HedgeMode::Sni {
                            sni: sni.clone(),
                            connector: connector.clone(),
                        },
                        addr: *addr,
                    });
                }
            }
            let mut fallback: Vec<HedgeCandidate> = Vec::new();
            for ip in github_fallback_ips(host) {
                if tried_ips.contains(&ip) {
                    continue;
                }
                let addr = SocketAddr::new(ip, port);
                if let Some(conn) = no_sni_tls.as_ref() {
                    fallback.push(HedgeCandidate {
                        mode: HedgeMode::NoSni(conn.clone()),
                        addr,
                    });
                }
                for sni in &sni_list {
                    fallback.push(HedgeCandidate {
                        mode: HedgeMode::Sni {
                            sni: sni.clone(),
                            connector: connector.clone(),
                        },
                        addr,
                    });
                }
            }
            if let Some(answer) =
                hedged_attempts(&cfg, req, host, connect_host, port, initial, fallback, rt).await
            {
                return Ok(answer);
            }
            return Err(UpstreamFailure::Connect);
        }
        let mut attempts: Vec<(String, SocketAddr)> = Vec::new();
        for sni in &sni_list {
            for addr in &addrs {
                attempts.push((sni.clone(), *addr));
            }
        }
        let mut host_fallback_done = agent_on || connect_host == host;
        let mut fallback_race_done =
            agent_on || !accelerated || stateful || !race_safe(&req.method, &req.path);
        let mut alias_alts_done = agent_on || !accelerated;
        let mut host_alts_done = agent_on || !accelerated || connect_host == host;
        let mut index = 0usize;

        loop {
            if index < attempts.len() {
                let (sni, addr) = attempts[index].clone();
                index += 1;
                let no_more_fallbacks =
                    host_fallback_done && fallback_race_done && alias_alts_done && host_alts_done;
                let is_last = index == attempts.len() && no_more_fallbacks;
                let head_timeout = if !retry_response || is_last {
                    http1::RESPONSE_HEAD_TIMEOUT
                } else {
                    FAST_HEAD_TIMEOUT
                };
                let connect_timeout = if retry_response && !is_last {
                    FAST_CONNECT_TIMEOUT
                } else {
                    http1::CONNECT_TIMEOUT
                };
                rt.send_log(format!(
                    "[MITM] try {host}:{port} via {} sni={sni}",
                    if agent_on { "agent".to_string() } else { addr.to_string() }
                ));
                match attempt_upstream(
                    &cfg,
                    &connector,
                    &sni,
                    addr,
                    port,
                    req,
                    host,
                    head_timeout,
                    connect_timeout,
                )
                .await
                {
                    Ok(answer) => {
                        if retry_response && retryable_status(answer.1.status) {
                            rt.send_log(format!(
                                "[MITM] try {host} via {addr} sni={sni} returned {}, trying another endpoint",
                                answer.1.status
                            ));
                            continue;
                        }
                        // Remembered only after the body completes, not here:
                        // an edge that sends headers/first bytes and then stalls
                        // must not become the preferred edge for the next request.
                        return Ok((answer.0, answer.1, answer.2, addr, sni, false));
                    }
                    Err(failure) => {
                        rt.send_log(format!(
                            "[MITM] try {host} via {addr} sni={sni} failed: {failure:?}"
                        ));
                        let response_phase = matches!(
                            failure,
                            AttemptFailure::Write | AttemptFailure::NoResponse
                        );
                        if response_phase && !retry_response {
                            return Err(UpstreamFailure::NoResponse);
                        }
                    }
                }
                continue;
            }
            if !host_fallback_done {
                // Fall back to the original host's own endpoints, mirroring
                // `GetIPEndPointsAsync`, which yields `resolve(dnsEndPoint)` only
                // after `resolve(ForwardDestination)` is exhausted.
                host_fallback_done = true;
                let host_ips = dns::resolve_a(
                    host,
                    &cfg.proxy_master_dns,
                    cfg.use_doh,
                    &cfg.custom_doh_address,
                )
                .await;
                let mut added = 0;
                for ip in host_ips {
                    if !tried_ips.contains(&ip) {
                        tried_ips.push(ip);
                        attempts.push((sni_primary.clone(), SocketAddr::new(ip, port)));
                        added += 1;
                    }
                }
                rt.send_log(format!(
                    "[MITM] alias {connect_host} failed, retrying {host} ({added} new endpoints)"
                ));
                if added > 0 {
                    continue;
                }
            }
            if !fallback_race_done {
                // Every sequential endpoint failed. GitHub's DNS answer is a
                // single edge that a censored network often blackholes; race the
                // other published edges at once and take the first that answers.
                fallback_race_done = true;
                let mut fallback: Vec<SocketAddr> = Vec::new();
                for ip in github_fallback_ips(host) {
                    if !tried_ips.contains(&ip) {
                        tried_ips.push(ip);
                        fallback.push(SocketAddr::new(ip, port));
                    }
                }
                if !fallback.is_empty() {
                    let per_edge = sni_list.len() + usize::from(no_sni_tls.is_some());
                    rt.send_log(format!(
                        "[MITM] racing {} published GitHub edges for {host}",
                        fallback.len() * per_edge
                    ));
                    let shared_req = Arc::new(req.clone());
                    let mut set = tokio::task::JoinSet::new();
                    for addr in fallback {
                        if let Some(no_sni) = no_sni_tls.clone() {
                            let cfg = cfg.clone();
                            let req = shared_req.clone();
                            let host = host.to_string();
                            let target = connect_host.to_string();
                            set.spawn(async move {
                                let outcome = attempt_upstream_no_sni(
                                    &cfg,
                                    &no_sni,
                                    addr,
                                    &host,
                                    &target,
                                    port,
                                    &req,
                                    &host,
                                    FALLBACK_RACE_TIMEOUT,
                                    FAST_CONNECT_TIMEOUT,
                                )
                                .await;
                                (addr, String::new(), true, outcome)
                            });
                        }
                        for sni in &sni_list {
                            let cfg = cfg.clone();
                            let connector = connector.clone();
                            let req = shared_req.clone();
                            let host = host.to_string();
                            let sni = sni.clone();
                            set.spawn(async move {
                                let outcome = attempt_upstream(
                                    &cfg,
                                    &connector,
                                    &sni,
                                    addr,
                                    port,
                                    &req,
                                    &host,
                                    FALLBACK_RACE_TIMEOUT,
                                    FAST_CONNECT_TIMEOUT,
                                )
                                .await;
                                (addr, sni, false, outcome)
                            });
                        }
                    }
                    while let Some(joined) = set.join_next().await {
                        if let Ok((addr, sni, no_sni, Ok(answer))) = joined {
                            if retry_response && retryable_status(answer.1.status) {
                                rt.send_log(format!(
                                    "[MITM] fallback edge {addr} returned {}, trying others",
                                    answer.1.status
                                ));
                                continue;
                            }
                            set.abort_all();
                            rt.send_log(format!(
                                "[MITM] fallback edge {addr} answered {host}{}",
                                if no_sni { " (no-sni)" } else { "" }
                            ));
                            return Ok((answer.0, answer.1, answer.2, addr, sni, no_sni));
                        }
                    }
                    set.abort_all();
                }
            }
            if !alias_alts_done {
                // The configured DoH resolver gave one edge; ask the other
                // resolvers for different ones only after a real failure.
                alias_alts_done = true;
                let alts = dns::resolve_alternatives(
                    connect_host,
                    &cfg.proxy_master_dns,
                    cfg.use_doh,
                    &cfg.custom_doh_address,
                    &tried_ips,
                )
                .await;
                let mut added = 0;
                for ip in alts {
                    tried_ips.push(ip);
                    for sni in &sni_list {
                        attempts.push((sni.clone(), SocketAddr::new(ip, port)));
                        added += 1;
                    }
                }
                if added > 0 {
                    continue;
                }
            }
            if !host_alts_done {
                host_alts_done = true;
                let alts = dns::resolve_alternatives(
                    host,
                    &cfg.proxy_master_dns,
                    cfg.use_doh,
                    &cfg.custom_doh_address,
                    &tried_ips,
                )
                .await;
                for ip in alts {
                    tried_ips.push(ip);
                    attempts.push((sni_primary.clone(), SocketAddr::new(ip, port)));
                }
                if index < attempts.len() {
                    continue;
                }
            }
            break;
        }
        rt.send_log(format!("[MITM] connect upstream {host} failed: no endpoint answered"));
        Err(UpstreamFailure::Connect)
    })
    .await;

    let outcome = match outcome {
        Ok(inner) => inner,
        Err(_) => {
            rt.send_log(format!(
                "[MITM] upstream for {host} exceeded {UPSTREAM_BUDGET:?}, giving up"
            ));
            Err(UpstreamFailure::Connect)
        }
    };
    finish_response(
        write_half,
        req,
        host,
        connect_host,
        port,
        rt,
        pool,
        agent_on,
        outcome,
    )
    .await
}

/// Stream the response to the client and decide whether the upstream connection
/// can be kept for the next request.
#[allow(clippy::too_many_arguments)]
async fn finish_response<W: AsyncWrite + Unpin>(
    write_half: &mut W,
    req: &http1::HttpRequest,
    host: &str,
    connect_host: &str,
    port: u16,
    rt: &MitmRuntime,
    pool: &UpstreamPool,
    agent_on: bool,
    outcome: Result<HedgeAnswer, UpstreamFailure>,
) -> bool {
    let (stream, head, prefix, winner, sni, no_sni) = match outcome {
        Ok(answer) => answer,
        Err(_) => {
            // The specific cause was logged where it was detected; what matters
            // for the client is an explicit 502 instead of a hung connection.
            if !agent_on {
                forget_last_good(host);
            }
            write_502(write_half).await;
            return false;
        }
    };
    let bytes = (head.headers.len() as u64) + req.body.len() as u64;
    {
        let mut s = rt.stats.lock().unwrap();
        s.total_bytes += bytes;
        *s.by_domain.entry(host.to_string()).or_insert(0) += bytes;
    }
    rt.send_log(format!("[MITM] {} {} -> {}", req.method, host, head.status));
    let mut reader = PrefixedReader {
        prefix,
        pos: 0,
        inner: stream,
    };
    match http1::stream_response_body(&mut reader, write_half, &head, &req.method).await {
        Ok(keep) => {
            if !agent_on && !winner.ip().is_unspecified() {
                // The whole response arrived: this edge is healthy, so the next
                // request for the host can start with it.
                remember_last_good(host, winner.ip());
            }
            if keep {
                pool.put(PooledUpstream {
                    host: connect_host.to_string(),
                    port,
                    sni,
                    no_sni,
                    returned_at: std::time::Instant::now(),
                    stream: reader.into_inner(),
                });
            }
            keep
        }
        Err(_) => false,
    }
}

fn webpki_roots() -> Arc<rustls::RootCertStore> {
    static ROOTS: OnceLock<Arc<rustls::RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            Arc::new(rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            ))
        })
        .clone()
}

/// TLS client connector for upstream dialling, with standard certificate
/// verification.
///
/// Built once: `RootCertStore::from_iter` parses the whole webpki bundle, and
/// doing that per request was pure CPU on the page's critical path. The
/// connector is cheap to clone (an `Arc` inside).
pub(crate) fn tls_connector() -> tokio_rustls::TlsConnector {
    static CONNECTOR: OnceLock<tokio_rustls::TlsConnector> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            ensure_crypto_provider();
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(webpki_roots())
                .with_no_client_auth();
            tokio_rustls::TlsConnector::from(Arc::new(config))
        })
        .clone()
}

/// Certificate verifier for a no-SNI handshake.
///
/// The TLS leg is given an IP `ServerName` so rustls omits the SNI extension,
/// but the certificate is still validated against `host` - the same name the
/// original `RemoteCertificateValidationCallback` checks when `TlsSni` is off.
#[derive(Debug)]
struct NoSniVerifier {
    host: String,
    inner: Arc<WebPkiServerVerifier>,
}

impl ServerCertVerifier for NoSniVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let name = ServerName::try_from(self.host.clone())
            .map_err(|_| rustls::Error::General("invalid no-SNI verify host".into()))?;
        self.inner
            .verify_server_cert(end_entity, intermediates, &name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Connector that sends no SNI but verifies the upstream certificate against
/// `verify_host` (the requested domain).
fn no_sni_connector(verify_host: &str) -> Option<tokio_rustls::TlsConnector> {
    ensure_crypto_provider();
    let inner = WebPkiServerVerifier::builder(webpki_roots()).build().ok()?;
    let verifier = Arc::new(NoSniVerifier {
        host: verify_host.to_string(),
        inner,
    });
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Some(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

async fn write_400<W: tokio::io::AsyncWrite + Unpin>(w: &mut W) {
    let _ = w
        .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await;
}

async fn write_502<W: tokio::io::AsyncWrite + Unpin>(w: &mut W) {
    let _ = w
        .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await;
}

/// The upstream SNI candidates for one request, in the order they are offered.
///
/// `primary` is the requested host, or the manifest's `fake_server_name` where one
/// is configured - what the original presents to the upstream. `fallback` is the
/// name B is about to dial (the `ForwardDestination` alias, or the requested host
/// itself); it is dropped when it repeats the primary, so a host with neither an
/// alias nor a substitute name keeps dialling with one single candidate exactly as
/// before.
fn sni_candidates<'a>(primary: &'a str, fallback: &'a str) -> Vec<&'a str> {
    let mut candidates = vec![primary];
    if fallback != primary {
        candidates.push(fallback);
    }
    candidates
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    /// A `MitmRuntime` for tests.
    ///
    /// The certificate fields are filled with a freshly generated rcgen root that is
    /// never written or installed anywhere: the upstream leg under test does not read
    /// them, but the struct requires them - and the client side does use them, because
    /// the leaf for the requested host is signed by this very root.
    fn runtime(
        cfg: ProxySettings,
        forward: &[(&str, &str)],
        fake_names: &[(&str, &str)],
    ) -> MitmRuntime {
        ensure_crypto_provider();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["wtlite-test-root".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).unwrap();
        let root = Arc::new(RootCertificate {
            der: cert.der().to_vec(),
            key_pkcs8: key.serialize_der(),
            not_after: std::time::SystemTime::now() + std::time::Duration::from_secs(86_400),
        });
        let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel();
        drop(log_rx);
        MitmRuntime {
            cm: Arc::new(CertificateManager::new()),
            cache: Arc::new(LeafCache::default()),
            root,
            config: Arc::new(RwLock::new(cfg)),
            stats: Arc::new(Mutex::new(crate::proxy::FlowStats::default())),
            log_tx,
            domains: Arc::new(RwLock::new(std::collections::HashSet::new())),
            forward: Arc::new(RwLock::new(
                forward
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )),
            configured_ips: Arc::new(RwLock::new(Vec::new())),
            fake_names: Arc::new(RwLock::new(
                fake_names
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )),
        }
    }

    /// A loopback DoH endpoint answering every query with `127.0.0.1` (the `name`
    /// field of a DoH answer is ignored by `parse_doh_answer`, only its type
    /// matters), so the upstream leg dials the test's own listener and never asks a
    /// real resolver.
    async fn doh_stub() -> String {
        let body = r#"{"Status":0,"Answer":[{"name":"x","type":1,"TTL":60,"data":"127.0.0.1"}]}"#;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let mut buf = [0u8; 2048];
                let _ = tokio::io::AsyncReadExt::read(&mut sock, &mut buf).await;
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

    /// Records the SNI of every ClientHello and serves no certificate, so each
    /// candidate fails the handshake immediately (the SNI is read before the failure).
    #[derive(Debug)]
    struct RecordingResolver {
        seen: Arc<Mutex<Vec<String>>>,
    }

    impl rustls::server::ResolvesServerCert for RecordingResolver {
        fn resolve(
            &self,
            client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            if let Some(name) = client_hello.server_name() {
                self.seen.lock().unwrap().push(name.to_string());
            }
            None
        }
    }

    /// The stand-in upstream, on the port the upstream leg hardcodes
    /// (`forward_one` dials 443, `connect_verified` builds `…:443` endpoints).
    /// Binding it here is what makes the dial land on the test rather than on
    /// whatever else the machine may have on 443.
    async fn recording_upstream(seen: Arc<Mutex<Vec<String>>>) {
        // The rustls builders need the process-wide provider, exactly like the
        // production path (`build_server_config`).
        ensure_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:443")
            .await
            .expect("the upstream leg dials 443: the test must own it on loopback");
        let acceptor = TlsAcceptor::from(Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_cert_resolver(Arc::new(RecordingResolver { seen })),
        ));
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    // The handshake always fails (no certificate is served); the SNI
                    // was recorded by the resolver above.
                    let _ = acceptor.accept(tcp).await;
                });
            }
        });
    }

    /// Drive the MITM tunnel exactly as `handle_connect` does, with a client that
    /// trusts the runtime's own root, and return what the upstream leg answers.
    async fn fetch_through_mitm(rt: &MitmRuntime, host: &str) -> String {
        ensure_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(rt.root.der.clone()))
            .unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let task = {
            let rt = rt.clone();
            tokio::spawn(async move {
                let _ = handle_tunnel(server, 443, rt).await;
            })
        };
        let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
        let mut tls = connector.connect(name, client).await.unwrap();
        tls.write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        // Read the response head. rustls reports the server's plain close as
        // `UnexpectedEof` (no `close_notify`), so both ends of a read are treated as
        // "nothing more to read": what the test needs is the status line it already
        // got.
        let mut answer = Vec::new();
        let mut chunk = [0u8; 512];
        let read = async {
            loop {
                match tls.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        answer.extend_from_slice(&chunk[..n]);
                        if answer.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                }
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(5), read)
            .await
            .expect("the tunnel never answered");
        task.await.unwrap();
        String::from_utf8_lossy(&answer).to_string()
    }

    #[tokio::test]
    async fn the_upstream_sni_candidates_are_attempted_end_to_end() {
        // The MITM tunnel - the entry `fwd.rs` calls for a decrypted CONNECT - is
        // driven with a client that trusts the runtime's root, so the request really
        // is decrypted and forwarded, and every ClientHello the upstream leg offers
        // is recorded on the test's own listener.
        //
        // What the recording proves is the *sequence*: the requested host is offered
        // first, the `ForwardDestination` alias follows it (the self-correcting
        // fallback), and the alias' endpoints are exhausted before the host's own
        // endpoints are tried again - the order `GetIPEndPointsAsync` yields. Adoption
        // cannot be shown: a loopback certificate can never satisfy the webpki
        // verification B deliberately keeps on, so every candidate is rejected and the
        // client reads 502.
        //
        // The substitute name (`FakeServerName`) is the second phase: it replaces the
        // requested host as the *first* candidate while the requested host stays the
        // fallback, and with no forward alias `connect_host == host`, so the
        // alias-endpoint leg does not run and exactly two candidates are offered.
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        recording_upstream(seen.clone()).await;
        let doh = doh_stub().await;
        let cfg = || ProxySettings {
            use_doh: true,
            custom_doh_address: doh.clone(),
            ..Default::default()
        };

        let rt = runtime(
            cfg(),
            &[("store.steamcommunity.com", "steamcommunity-a.akamaihd.net")],
            &[],
        );
        let answer = fetch_through_mitm(&rt, "store.steamcommunity.com").await;
        assert!(
            answer.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "unexpected answer: {answer}"
        );
        assert_eq!(
            seen.lock().unwrap().clone(),
            vec![
                "store.steamcommunity.com".to_string(),
                "steamcommunity-a.akamaihd.net".to_string()
            ],
            "the requested host must lead and the alias follow; the host's own \
             endpoint here is the same 127.0.0.1 the stub returns for both names, \
             so the already-tried endpoint is not dialled a third time"
        );

        seen.lock().unwrap().clear();
        let rt = runtime(
            cfg(),
            &[],
            &[("store.steamcommunity.com", "cdn.example.net")],
        );
        let answer = fetch_through_mitm(&rt, "store.steamcommunity.com").await;
        assert!(
            answer.starts_with("HTTP/1.1 502 Bad Gateway\r\n"),
            "unexpected answer: {answer}"
        );
        assert_eq!(
            seen.lock().unwrap().clone(),
            vec![
                "cdn.example.net".to_string(),
                "store.steamcommunity.com".to_string()
            ],
            "a substitute name must lead the candidates and the requested host follow"
        );
    }

    #[test]
    fn the_sni_candidates_lead_with_the_requested_host_and_keep_the_alias_as_fallback() {
        // No substitute name: the requested host is presented first, the alias
        // follows.
        assert_eq!(
            sni_candidates("store.steamcommunity.com", "steamcommunity-a.akamaihd.net"),
            vec!["store.steamcommunity.com", "steamcommunity-a.akamaihd.net"]
        );
        // A substitute name replaces the requested host; the alias stays the
        // fallback.
        assert_eq!(
            sni_candidates("cdn.example.net", "steamcommunity-a.akamaihd.net"),
            vec!["cdn.example.net", "steamcommunity-a.akamaihd.net"]
        );
        // No alias: one candidate, so a host without an alias keeps the previous
        // single-candidate behavior.
        assert_eq!(
            sni_candidates("store.steampowered.com", "store.steampowered.com"),
            vec!["store.steampowered.com"]
        );
        // A substitute name equal to the alias is not dialled twice.
        assert_eq!(
            sni_candidates("cdn.example.net", "cdn.example.net"),
            vec!["cdn.example.net"]
        );
    }
}
