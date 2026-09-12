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

impl rustls::server::ResolvesServerCert for DynCertResolver {
    fn resolve(
        &self,
        client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni = client_hello.server_name()?;
        let (cert_der, key_der) = self.cache.get_or_create(sni, &self.cm, &self.root)?;
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(key_der));
        let provider = rustls::crypto::CryptoProvider::get_default()?;
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
}

/// Build the rustls server config.
fn build_server_config(rt: &MitmRuntime) -> Result<Arc<rustls::ServerConfig>, String> {
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
    let config = build_server_config(&rt)?;
    let acceptor = TlsAcceptor::from(config);
    let addr: SocketAddr = (bind_ip, 443).into();
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind 443 failed (need admin): {e}"))?;
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
        let _ = self.log_tx.send(msg);
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
        rt.send_log(format!("[MITM] {} {}", req.method, host));
        let keep_alive = forward_one(&mut read_half, &mut write_half, &req, &host, &rt).await;
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
    rt: &MitmRuntime,
) -> bool {
    let port = 443u16;
    let cfg = rt.config.read().unwrap().clone();
    let ips =
        dns::resolve_a(host, &cfg.proxy_master_dns, cfg.use_doh, &cfg.custom_doh_address).await;
    let upstream = match http1::connect_upstream(host, port, &ips).await {
        Some(s) => s,
        None => {
            rt.send_log(format!("[MITM] connect upstream {host} failed"));
            write_502(write_half).await;
            return false;
        }
    };
    let upstream = match connect_tls(upstream, host).await {
        Some(s) => s,
        None => {
            rt.send_log(format!("[MITM] upstream TLS {host} failed"));
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
        .write_all(b"HTTP/1.1 400 Bad Request
Content-Length: 0
Connection: close

")
        .await;
}

async fn write_502<W: tokio::io::AsyncWrite + Unpin>(w: &mut W) {
    let _ = w
        .write_all(b"HTTP/1.1 502 Bad Gateway
Content-Length: 0
Connection: close

")
        .await;
}
