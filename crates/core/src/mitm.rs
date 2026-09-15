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
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use tokio::io::{AsyncWrite, AsyncWriteExt};
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
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key_der));
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
    /// Host -> alternate hostname to dial upstream (mirrors the original
    /// `ForwardDestination`: the request keeps its original Host header while
    /// the TCP/TLS connection targets a different, reachable name).
    pub forward: Arc<RwLock<std::collections::HashMap<String, String>>>,
}

/// Build the rustls server config.
fn build_server_config(rt: &MitmRuntime) -> Result<Arc<rustls::ServerConfig>, String> {
    ensure_crypto_provider();
    let resolver = DynCertResolver {
        cm: rt.cm.clone(),
        cache: rt.cache.clone(),
        root: rt.root.clone(),
    };
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
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
pub async fn run_mitm_on(
    listener: tokio::net::TcpListener,
    rt: MitmRuntime,
) -> Result<(), String> {
    let config = build_server_config(&rt)?;
    let acceptor = TlsAcceptor::from(config);
    let addr = listener
        .local_addr()
        .map_err(|e| format!("local_addr failed: {e}"))?;
    rt.send_log(format!("MITM HTTPS reverse proxy listening on {addr}"));
    loop {
        match listener.accept().await {
            Ok((tcp, peer)) => {
                let acceptor = acceptor.clone();
                let rt = rt.clone();
                let _ = peer;
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(acceptor, tcp, rt).await {
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
pub async fn handle_tunnel(tcp: TcpStream, rt: MitmRuntime) -> Result<(), String> {
    let config = build_server_config(&rt)?;
    let acceptor = TlsAcceptor::from(config);
    match handle_conn(acceptor, tcp, rt).await {
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
    rt: MitmRuntime,
) -> Result<(), String> {
    let tls = acceptor.accept(tcp).await.map_err(|e| e.to_string())?;
    let (mut read_half, mut write_half) = tokio::io::split(tls);

    loop {
        let req = match http1::read_request(&mut read_half).await {
            Some(r) => r,
            None => break,
        };
        let host = match req.host() {
            Some(h) => h,
            None => {
                write_400(&mut write_half).await;
                break;
            }
        };
        // Dial a substitute hostname when one is configured for this host
        // (the original `ForwardDestination` + `TlsSni` pair).
        let connect_host = rt
            .forward
            .read()
            .unwrap()
            .get(&host.to_lowercase())
            .cloned()
            .unwrap_or_else(|| host.clone());
        rt.send_log(format!("[MITM] {} {host} -> {connect_host}", req.method));
        let keep_alive =
            forward_one(&mut read_half, &mut write_half, &req, &host, &connect_host, &rt).await;
        if !keep_alive {
            break;
        }
    }
    Ok(())
}

/// Forward one request to the upstream and stream the response back.
async fn forward_one<R: tokio::io::AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    _read_half: &mut R,
    write_half: &mut W,
    req: &http1::HttpRequest,
    host: &str,
    connect_host: &str,
    rt: &MitmRuntime,
) -> bool {
    let port = 443u16;
    let cfg = rt.config.read().unwrap().clone();
    // Resolve and dial `connect_host`, but keep `host` for the Host header.
    // A blocked domain resolves to poisoned IPs, while its CDN alias resolves
    // correctly and accepts the handshake only when SNI matches the alias.
    let ips = dns::resolve_a(
        connect_host,
        &cfg.proxy_master_dns,
        cfg.use_doh,
        &cfg.custom_doh_address,
    )
    .await;
    let upstream = match http1::connect_upstream(connect_host, port, &ips).await {
        Some(s) => s,
        None => {
            rt.send_log(format!("[MITM] connect upstream {connect_host} failed"));
            write_502(write_half).await;
            return false;
        }
    };
    let upstream = match connect_tls(upstream, connect_host).await {
        Some(s) => s,
        None => {
            rt.send_log(format!("[MITM] upstream TLS {connect_host} failed"));
            write_502(write_half).await;
            return false;
        }
    };
    let (mut u_read, mut u_write) = tokio::io::split(upstream);

    let wire = http1::write_request(req, host, port, false);
    if u_write.write_all(&wire).await.is_err() {
        return false;
    }
    if u_write.flush().await.is_err() {
        return false;
    }

    let head = match http1::read_response_head(&mut u_read).await {
        Some(h) => h,
        None => {
            rt.send_log(format!("[MITM] no response from {host}"));
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
    match http1::stream_response_body(&mut u_read, write_half, &head).await {
        Ok(keep) => keep,
        Err(_) => false,
    }
}

/// Establish TLS to the upstream host with standard certificate verification.
async fn connect_tls(tcp: TcpStream, host: &str) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
    ensure_crypto_provider();
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
        )
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let dns_name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
    let stream = connector.connect(dns_name, tcp).await.ok()?;
    Some(stream)
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
