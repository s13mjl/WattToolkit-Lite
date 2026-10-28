//! Second-level agent (upstream proxy) handshake: HTTP CONNECT / SOCKS4 /
//! SOCKS4a / SOCKS5, with optional username/password authentication.
//!
//! Mirrors `ConnectThroughProxyAsync` in the original
//! `BD.WTTS.Client.Plugins.Accelerator.ReverseProxy/Services.Implementation/Http/ReverseProxyHttpClientHandler.cs`
//! (L69-L250): the socket is already connected to the agent, and this module only
//! performs the protocol exchange that turns that socket into a tunnel to
//! `target_host:target_port`.
//!
//! Three deliberate departures from the original are recorded here, because
//! callers depend on them:
//!
//! * the tunnel is requested by **host name** whenever the target is not an IPv4
//!   literal, which for SOCKS4 means the SOCKS4a form. The original resolves the
//!   target itself and pastes the first IPv4 answer into the request (L161), so
//!   the agent dials an address B never verified; here B hands the name over and
//!   keeps its own SNI/certificate verification.
//! * replies are read with exact lengths, and the SOCKS5 reply with an
//!   address-type-aware length. The original reads a fixed-size buffer with a
//!   single `ReadAsync` (L147, L175, L192, L243), which can under-read a
//!   segmented answer.
//! * an IPv6 literal is bracketed in the `CONNECT` request line (the original
//!   pastes `DnsEndPoint.Host` in as-is, L139) and, for SOCKS4, is refused
//!   outright instead of emitting a malformed 16-byte address.
//!
//! Nothing dials through here yet: this round (P1-7b1) ships the handshake layer
//! only, so `fwd.rs`, `mitm.rs` and `http1.rs` are untouched.

use std::fmt;
use std::net::IpAddr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::model::ExternalProxyType;

/// Why the agent handshake failed.
#[derive(Debug)]
pub enum AgentError {
    /// The agent answered with a protocol-level rejection: an HTTP status other
    /// than `200`, a SOCKS4 reply other than `0x5A`, a SOCKS5 reply other than
    /// `0x00`, or a refused SOCKS5 username/password exchange.
    Refused(String),
    /// The agent's bytes did not form a valid answer for its protocol.
    Protocol(String),
    /// The agent offered nothing B can perform, or the request cannot be encoded
    /// in the chosen protocol at all.
    Unsupported(String),
    /// The handshake could not be written or read.
    Io(std::io::Error),
}

impl fmt::Display for AgentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AgentError::Refused(why) => write!(f, "second-level agent refused the tunnel: {why}"),
            AgentError::Protocol(why) => write!(f, "second-level agent broke its protocol: {why}"),
            AgentError::Unsupported(why) => {
                write!(f, "second-level agent handshake not possible: {why}")
            }
            AgentError::Io(err) => write!(f, "second-level agent handshake I/O error: {err}"),
        }
    }
}

impl std::error::Error for AgentError {}

/// Complete the agent handshake on an already-connected socket.
///
/// On success the stream is a tunnel to `target_host:target_port`: for an `https`
/// upstream the caller continues with its own TLS handshake (SNI and certificate
/// verification stay B's), for a plaintext one the stream carries bytes.
///
/// `credentials` mirrors the original's `webProxy.Credentials` (L134, L158, L185):
/// `None` means the agent is never asked to authenticate, `Some` enables HTTP
/// basic auth and the SOCKS5 `0x02` method.
///
/// The call is not timed: like the dial helpers in `http1.rs`, callers wrap it in
/// their own per-endpoint connect budget.
pub async fn handshake<S>(
    stream: &mut S,
    proxy_type: ExternalProxyType,
    target_host: &str,
    target_port: u16,
    credentials: Option<(&str, &str)>,
) -> Result<(), AgentError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    match proxy_type {
        ExternalProxyType::Http => connect_http(stream, target_host, target_port, credentials).await,
        ExternalProxyType::Socks4 => {
            connect_socks4(stream, target_host, target_port, credentials).await
        }
        ExternalProxyType::Socks5 => {
            connect_socks5(stream, target_host, target_port, credentials).await
        }
    }
}

/// `CONNECT` mode of an HTTP agent (original L132-L154).
async fn connect_http<S>(
    stream: &mut S,
    target_host: &str,
    target_port: u16,
    credentials: Option<(&str, &str)>,
) -> Result<(), AgentError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let authority = connect_authority(target_host, target_port);
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
    if let Some((user, password)) = credentials {
        request.push_str("Proxy-Authorization: Basic ");
        request.push_str(&basic_auth(user, password));
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(AgentError::Io)?;

    let answer = read_http_head(stream).await?;
    let head = String::from_utf8_lossy(&answer);
    if head.is_empty() {
        return Err(AgentError::Protocol("agent sent an empty answer".into()));
    }
    // The original accepts only `response.StartsWith("HTTP/1.1 200")` (L150).
    if !head.starts_with("HTTP/1.1 200") {
        let status = head.lines().next().unwrap_or_default();
        return Err(AgentError::Refused(status.to_string()));
    }
    Ok(())
}

/// SOCKS4 `CONNECT`, falling back to the SOCKS4a host-name form for a name
/// target (original L156-L181, which only implements the IPv4 form).
async fn connect_socks4<S>(
    stream: &mut S,
    target_host: &str,
    target_port: u16,
    credentials: Option<(&str, &str)>,
) -> Result<(), AgentError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let user_id = credentials.map(|(user, _)| user).unwrap_or("");
    let user_id = ascii(user_id, "agent user name")?;

    let mut request = vec![0x04, 0x01];
    request.extend_from_slice(&target_port.to_be_bytes());
    match target_host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.extend_from_slice(&ip.octets());
            request.extend_from_slice(user_id);
            request.push(0x00);
        }
        Ok(IpAddr::V6(_)) => {
            return Err(AgentError::Unsupported(format!(
                "SOCKS4 cannot reach the IPv6 literal {target_host}"
            )));
        }
        Err(_) => {
            // SOCKS4a: the 0.0.0.1 marker tells the agent the name follows the
            // user id, so B never has to resolve the target itself.
            request.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]);
            request.extend_from_slice(user_id);
            request.push(0x00);
            request.extend_from_slice(ascii(target_host, "target host")?);
            request.push(0x00);
        }
    }
    stream.write_all(&request).await.map_err(AgentError::Io)?;

    let mut answer = [0u8; 8];
    stream
        .read_exact(&mut answer)
        .await
        .map_err(AgentError::Io)?;
    // Byte 1 is the reply code, byte 0 the (unused) version.
    let code = answer[1];
    if code != 0x5A {
        return Err(AgentError::Refused(format!("SOCKS4 reply code 0x{code:02X}")));
    }
    Ok(())
}

/// SOCKS5 `CONNECT` with the optional username/password method (original
/// L183-L250).
async fn connect_socks5<S>(
    stream: &mut S,
    target_host: &str,
    target_port: u16,
    credentials: Option<(&str, &str)>,
) -> Result<(), AgentError>
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    // Method negotiation: offer `0x02` (username/password) only when credentials
    // exist, otherwise `0x00` (no authentication) - original L188.
    let method = if credentials.is_some() { 0x02 } else { 0x00 };
    stream
        .write_all(&[0x05, 0x01, method])
        .await
        .map_err(AgentError::Io)?;
    let mut greeting = [0u8; 2];
    stream
        .read_exact(&mut greeting)
        .await
        .map_err(AgentError::Io)?;
    let version = greeting[0];
    if version != 0x05 {
        return Err(AgentError::Protocol(format!(
            "SOCKS5 greeting version 0x{version:02X}"
        )));
    }
    match greeting[1] {
        0x00 => {}
        0x02 => {
            let (user, password) = credentials.ok_or_else(|| {
                AgentError::Unsupported(
                    "agent requires username/password but none is configured".into(),
                )
            })?;
            let user = ascii(user, "agent user name")?;
            let password = ascii(password, "agent password")?;
            // RFC 1929 carries each length in one byte; the original casts to
            // `byte` and silently truncates (L204, L206).
            if user.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
                return Err(AgentError::Unsupported(
                    "agent user name or password exceeds 255 bytes".into(),
                ));
            }
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(user);
            auth.push(password.len() as u8);
            auth.extend_from_slice(password);
            stream.write_all(&auth).await.map_err(AgentError::Io)?;

            let mut answer = [0u8; 2];
            stream
                .read_exact(&mut answer)
                .await
                .map_err(AgentError::Io)?;
            let (version, status) = (answer[0], answer[1]);
            if version != 0x01 {
                return Err(AgentError::Protocol(format!(
                    "SOCKS5 authentication version 0x{version:02X}"
                )));
            }
            if status != 0x00 {
                return Err(AgentError::Refused(format!(
                    "SOCKS5 authentication status 0x{status:02X}"
                )));
            }
        }
        0xFF => {
            return Err(AgentError::Unsupported(
                "agent accepts none of the offered authentication methods".into(),
            ));
        }
        other => {
            return Err(AgentError::Unsupported(format!(
                "agent selected authentication method 0x{other:02X}"
            )));
        }
    }

    // Connect request: the target is passed as given, so a name stays a name
    // (RFC 1928 ATYP 3) and only a literal is encoded as an address.
    let mut request = vec![0x05, 0x01, 0x00];
    match target_host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            let host = ascii(target_host, "target host")?;
            if host.len() > u8::MAX as usize {
                return Err(AgentError::Unsupported(format!(
                    "target host name exceeds 255 bytes: {target_host}"
                )));
            }
            request.push(0x03);
            request.push(host.len() as u8);
            request.extend_from_slice(host);
        }
    }
    request.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&request)
        .await
        .map_err(AgentError::Io)?;

    // Reply head plus the bound address, whose length its ATYP announces - the
    // original reads a fixed 10 bytes (L243) and mis-parses other forms.
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.map_err(AgentError::Io)?;
    let version = reply[0];
    if version != 0x05 {
        return Err(AgentError::Protocol(format!(
            "SOCKS5 reply version 0x{version:02X}"
        )));
    }
    let code = reply[1];
    if code != 0x00 {
        return Err(AgentError::Refused(format!("SOCKS5 reply code 0x{code:02X}")));
    }
    let bound_len = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await.map_err(AgentError::Io)?;
            len[0] as usize
        }
        other => {
            return Err(AgentError::Protocol(format!(
                "SOCKS5 reply address type 0x{other:02X}"
            )));
        }
    };
    // Neither the bound address nor the bound port is used, but both must be
    // drained so the tunnel starts at the payload.
    let mut bound = vec![0u8; bound_len + 2];
    stream.read_exact(&mut bound).await.map_err(AgentError::Io)?;
    Ok(())
}

/// Read an HTTP answer up to and including the terminating empty line.
///
/// The original reads one fixed 1024-byte buffer (L146-L148); reading to the
/// terminator keeps the status line intact when it arrives split across segments.
/// Bounded at 8 KiB so a chatty agent cannot grow the buffer.
async fn read_http_head<S>(stream: &mut S) -> Result<Vec<u8>, AgentError>
where
    S: AsyncReadExt + Unpin,
{
    const MAX_HEAD: usize = 8 * 1024;
    let mut head: Vec<u8> = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte).await.map_err(AgentError::Io)?;
        if read == 0 {
            return Err(AgentError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "agent closed before its answer head was complete",
            )));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
        if head.len() >= MAX_HEAD {
            return Err(AgentError::Protocol("agent answer head is oversized".into()));
        }
    }
}

/// `Proxy-Authorization: Basic` payload (original L136).
fn basic_auth(user: &str, password: &str) -> String {
    STANDARD.encode(format!("{user}:{password}"))
}

/// `host:port` for the HTTP request line. An IPv6 literal must be bracketed, so
/// the authority is unambiguous (original L139 pastes the host in as-is).
fn connect_authority(host: &str, port: u16) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

/// Protocol fields carrying host names are ASCII (SOCKS4a, RFC 1928 section 4),
/// so a non-ASCII name cannot be encoded: it is reported instead of being sent
/// mangled.
fn ascii<'a>(text: &'a str, what: &str) -> Result<&'a [u8], AgentError> {
    if text.is_ascii() {
        Ok(text.as_bytes())
    } else {
        Err(AgentError::Unsupported(format!(
            "{what} is not ASCII: {text}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::oneshot;

    /// A SOCKS5 success reply carrying an IPv4 bound address.
    const SOCKS5_OK_IPV4: &[u8] = &[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x01, 0xBB];
    /// A SOCKS5 success reply carrying a domain bound address.
    const SOCKS5_OK_DOMAIN: &[u8] = &[
        0x05, 0x00, 0x00, 0x03, 5, b'a', b'b', b'c', b'd', b'e', 0x01, 0xBB,
    ];
    /// A SOCKS5 success reply carrying an IPv6 bound address.
    const SOCKS5_OK_IPV6: &[u8] = &[
        0x05, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xBB,
    ];
    /// A SOCKS4 success reply (version byte unused, `0x5A` = granted).
    const SOCKS4_OK: &[u8] = &[0x00, 0x5A, 0, 0, 0, 0, 0, 0];

    /// One exchange of the conversation the fake agent plays back.
    enum Step {
        /// Read exactly this many bytes, then write the given reply.
        Exact(usize, &'static [u8]),
        /// Read the client's HTTP head, then write the given reply.
        HttpHead(&'static str),
        /// Read a SOCKS4/SOCKS4a request in full, then write the given reply.
        Socks4Request(&'static [u8]),
        /// Read a SOCKS5 connect request (head plus its announced address form),
        /// then write the given reply.
        Socks5Request(&'static [u8]),
    }

    /// A loopback stand-in for the second-level agent: replays `steps` on the
    /// first accepted connection and hands back every byte the client sent, so a
    /// test can assert the exact wire format without leaving the machine.
    struct FakeAgent {
        addr: SocketAddr,
        captured: oneshot::Receiver<Vec<u8>>,
    }

    impl FakeAgent {
        async fn start(steps: Vec<Step>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (tx, captured) = oneshot::channel();
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut sent = Vec::new();
                for step in steps {
                    match step {
                        Step::Exact(n, reply) => {
                            let mut buf = vec![0u8; n];
                            stream.read_exact(&mut buf).await.unwrap();
                            sent.extend_from_slice(&buf);
                            stream.write_all(reply).await.unwrap();
                        }
                        Step::HttpHead(reply) => {
                            sent.extend_from_slice(&read_http_head(&mut stream).await.unwrap());
                            stream.write_all(reply.as_bytes()).await.unwrap();
                        }
                        Step::Socks4Request(reply) => {
                            sent.extend_from_slice(&read_socks4_request(&mut stream).await);
                            stream.write_all(reply).await.unwrap();
                        }
                        Step::Socks5Request(reply) => {
                            sent.extend_from_slice(&read_socks5_request(&mut stream).await);
                            stream.write_all(reply).await.unwrap();
                        }
                    }
                    stream.flush().await.unwrap();
                }
                let _ = tx.send(sent);
            });
            Self { addr, captured }
        }

        async fn connect(&self) -> TcpStream {
            TcpStream::connect(self.addr).await.unwrap()
        }

        /// Every byte the client wrote, once the script has run out.
        async fn sent(self) -> Vec<u8> {
            tokio::time::timeout(Duration::from_secs(5), self.captured)
                .await
                .expect("the fake agent never finished its script")
                .unwrap()
        }
    }

    /// Server-side counterpart of the client's SOCKS4/SOCKS4a request: the fixed
    /// head, the null-terminated user id and - when the head carries the 0.0.0.1
    /// marker - the null-terminated host name.
    async fn read_socks4_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut head = [0u8; 8];
        stream.read_exact(&mut head).await.unwrap();
        let mut out = head.to_vec();
        out.extend_from_slice(&read_nul_terminated(stream).await);
        if head[4..8] == [0x00, 0x00, 0x00, 0x01] {
            out.extend_from_slice(&read_nul_terminated(stream).await);
        }
        out
    }

    /// Read a null-terminated field, terminator included.
    async fn read_nul_terminated(stream: &mut TcpStream) -> Vec<u8> {
        let mut out = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).await.unwrap();
            out.push(byte[0]);
            if byte[0] == 0x00 {
                return out;
            }
        }
    }

    /// Server-side counterpart of the client's SOCKS5 connect request: the fixed
    /// head plus the address form its ATYP announces.
    async fn read_socks5_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut head = [0u8; 4];
        stream.read_exact(&mut head).await.unwrap();
        let mut out = head.to_vec();
        match head[3] {
            0x01 => {
                let mut rest = [0u8; 4];
                stream.read_exact(&mut rest).await.unwrap();
                out.extend_from_slice(&rest);
            }
            0x04 => {
                let mut rest = [0u8; 16];
                stream.read_exact(&mut rest).await.unwrap();
                out.extend_from_slice(&rest);
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await.unwrap();
                out.push(len[0]);
                let mut host = vec![0u8; len[0] as usize];
                stream.read_exact(&mut host).await.unwrap();
                out.extend_from_slice(&host);
            }
            other => panic!("unexpected ATYP 0x{other:02X} in a SOCKS5 request"),
        }
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await.unwrap();
        out.extend_from_slice(&port);
        out
    }

    /// Run one client-side handshake under a test budget, so a wire-format bug
    /// fails instead of hanging the suite.
    async fn run(
        stream: &mut TcpStream,
        proxy_type: ExternalProxyType,
        host: &str,
        port: u16,
        credentials: Option<(&str, &str)>,
    ) -> Result<(), AgentError> {
        tokio::time::timeout(
            Duration::from_secs(5),
            handshake(stream, proxy_type, host, port, credentials),
        )
        .await
        .expect("the handshake never finished")
    }

    /// Concatenate wire fragments for an expected-byte assertion.
    fn wire(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[tokio::test]
    async fn http_agent_gets_a_connect_request_with_basic_auth() {
        let agent = FakeAgent::start(vec![Step::HttpHead(
            "HTTP/1.1 200 Connection established\r\n\r\n",
        )])
        .await;
        let mut stream = agent.connect().await;
        let result = run(
            &mut stream,
            ExternalProxyType::Http,
            "steamcommunity.com",
            443,
            Some(("Aladdin", "open sesame")),
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            agent.sent().await,
            wire(&[
                b"CONNECT steamcommunity.com:443 HTTP/1.1\r\n",
                b"Host: steamcommunity.com:443\r\n",
                b"Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==\r\n",
                b"\r\n",
            ])
        );
    }

    #[tokio::test]
    async fn http_agent_brackets_an_ipv6_literal_target() {
        let agent = FakeAgent::start(vec![Step::HttpHead(
            "HTTP/1.1 200 Connection established\r\n\r\n",
        )])
        .await;
        let mut stream = agent.connect().await;
        let result = run(
            &mut stream,
            ExternalProxyType::Http,
            "2400:3200::1",
            443,
            None,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            agent.sent().await,
            wire(&[
                b"CONNECT [2400:3200::1]:443 HTTP/1.1\r\n",
                b"Host: [2400:3200::1]:443\r\n",
                b"\r\n",
            ])
        );
    }

    #[tokio::test]
    async fn http_agent_rejection_is_refused() {
        let agent = FakeAgent::start(vec![Step::HttpHead(
            "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n",
        )])
        .await;
        let mut stream = agent.connect().await;
        let err = run(
            &mut stream,
            ExternalProxyType::Http,
            "example.com",
            443,
            Some(("Aladdin", "open sesame")),
        )
        .await
        .expect_err("a 407 answer must not be accepted");
        assert!(matches!(err, AgentError::Refused(_)), "{err:?}");
    }

    #[tokio::test]
    async fn socks4_sends_the_ipv4_form() {
        let agent = FakeAgent::start(vec![Step::Socks4Request(SOCKS4_OK)]).await;
        let mut stream = agent.connect().await;
        let result = run(
            &mut stream,
            ExternalProxyType::Socks4,
            "140.82.112.4",
            443,
            None,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            agent.sent().await,
            wire(&[&[0x04, 0x01, 0x01, 0xBB], &[140, 82, 112, 4], &[0x00]])
        );
    }

    #[tokio::test]
    async fn socks4a_sends_the_host_name_after_the_user_id() {
        let agent = FakeAgent::start(vec![Step::Socks4Request(SOCKS4_OK)]).await;
        let mut stream = agent.connect().await;
        let result = run(
            &mut stream,
            ExternalProxyType::Socks4,
            "steamcommunity.com",
            443,
            Some(("alice", "secret")),
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            agent.sent().await,
            wire(&[
                &[0x04, 0x01, 0x01, 0xBB, 0x00, 0x00, 0x00, 0x01],
                b"alice",
                &[0x00],
                b"steamcommunity.com",
                &[0x00],
            ])
        );
    }

    #[tokio::test]
    async fn socks4_denied_reply_is_refused() {
        let agent = FakeAgent::start(vec![Step::Socks4Request(
            &[0x00, 0x5B, 0, 0, 0, 0, 0, 0],
        )])
        .await;
        let mut stream = agent.connect().await;
        let err = run(
            &mut stream,
            ExternalProxyType::Socks4,
            "140.82.112.4",
            443,
            None,
        )
        .await
        .expect_err("reply code 0x5B is a rejection");
        assert!(matches!(err, AgentError::Refused(_)), "{err:?}");
    }

    #[tokio::test]
    async fn socks4_refuses_an_ipv6_literal_target() {
        let agent = FakeAgent::start(Vec::new()).await;
        let mut stream = agent.connect().await;
        let err = run(
            &mut stream,
            ExternalProxyType::Socks4,
            "2400:3200::1",
            443,
            None,
        )
        .await
        .expect_err("SOCKS4 has no IPv6 address form");
        assert!(matches!(err, AgentError::Unsupported(_)), "{err:?}");
    }

    #[tokio::test]
    async fn socks5_offers_no_authentication_and_sends_the_host_name() {
        let agent = FakeAgent::start(vec![
            Step::Exact(3, &[0x05, 0x00]),
            Step::Socks5Request(SOCKS5_OK_IPV4),
        ])
        .await;
        let mut stream = agent.connect().await;
        let result = run(
            &mut stream,
            ExternalProxyType::Socks5,
            "steamcommunity.com",
            443,
            None,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            agent.sent().await,
            wire(&[
                &[0x05, 0x01, 0x00],
                &[0x05, 0x01, 0x00, 0x03, b"steamcommunity.com".len() as u8],
                b"steamcommunity.com",
                &[0x01, 0xBB],
            ])
        );
    }

    #[tokio::test]
    async fn socks5_completes_the_username_password_exchange() {
        // 1 + 1 + len("Aladdin") + 1 + len("open sesame") per RFC 1929.
        let agent = FakeAgent::start(vec![
            Step::Exact(3, &[0x05, 0x02]),
            Step::Exact(21, &[0x01, 0x00]),
            Step::Socks5Request(SOCKS5_OK_DOMAIN),
        ])
        .await;
        let mut stream = agent.connect().await;
        let result = run(
            &mut stream,
            ExternalProxyType::Socks5,
            "steamcommunity.com",
            443,
            Some(("Aladdin", "open sesame")),
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        assert_eq!(
            agent.sent().await,
            wire(&[
                &[0x05, 0x01, 0x02],
                &[0x01, 7],
                b"Aladdin",
                &[11],
                b"open sesame",
                &[0x05, 0x01, 0x00, 0x03, b"steamcommunity.com".len() as u8],
                b"steamcommunity.com",
                &[0x01, 0xBB],
            ])
        );
    }

    #[tokio::test]
    async fn socks5_rejects_a_failed_authentication() {
        let agent = FakeAgent::start(vec![
            Step::Exact(3, &[0x05, 0x02]),
            Step::Exact(21, &[0x01, 0x01]),
        ])
        .await;
        let mut stream = agent.connect().await;
        let err = run(
            &mut stream,
            ExternalProxyType::Socks5,
            "steamcommunity.com",
            443,
            Some(("Aladdin", "open sesame")),
        )
        .await
        .expect_err("authentication status 0x01 is a rejection");
        assert!(matches!(err, AgentError::Refused(_)), "{err:?}");
    }

    #[tokio::test]
    async fn socks5_rejects_a_refused_connect_reply() {
        let agent = FakeAgent::start(vec![
            Step::Exact(3, &[0x05, 0x00]),
            Step::Socks5Request(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0x01, 0xBB]),
        ])
        .await;
        let mut stream = agent.connect().await;
        let err = run(
            &mut stream,
            ExternalProxyType::Socks5,
            "steamcommunity.com",
            443,
            None,
        )
        .await
        .expect_err("reply code 0x05 is a rejection");
        assert!(matches!(err, AgentError::Refused(_)), "{err:?}");
    }

    #[tokio::test]
    async fn socks5_reports_missing_authentication_methods() {
        let agent = FakeAgent::start(vec![Step::Exact(3, &[0x05, 0xFF])]).await;
        let mut stream = agent.connect().await;
        let err = run(
            &mut stream,
            ExternalProxyType::Socks5,
            "steamcommunity.com",
            443,
            None,
        )
        .await
        .expect_err("0xFF means no offered method was accepted");
        assert!(matches!(err, AgentError::Unsupported(_)), "{err:?}");
    }

    #[tokio::test]
    async fn socks5_reports_a_required_but_unconfigured_authentication() {
        let agent = FakeAgent::start(vec![Step::Exact(3, &[0x05, 0x02])]).await;
        let mut stream = agent.connect().await;
        let err = run(
            &mut stream,
            ExternalProxyType::Socks5,
            "steamcommunity.com",
            443,
            None,
        )
        .await
        .expect_err("a required username/password with no credentials cannot proceed");
        assert!(matches!(err, AgentError::Unsupported(_)), "{err:?}");
    }

    #[tokio::test]
    async fn socks5_encodes_an_ipv6_literal_target() {
        let agent = FakeAgent::start(vec![
            Step::Exact(3, &[0x05, 0x00]),
            Step::Socks5Request(SOCKS5_OK_IPV6),
        ])
        .await;
        let mut stream = agent.connect().await;
        let result = run(
            &mut stream,
            ExternalProxyType::Socks5,
            "2400:3200::1",
            443,
            None,
        )
        .await;
        assert!(result.is_ok(), "{result:?}");
        let mut expected = wire(&[&[0x05, 0x01, 0x00], &[0x05, 0x01, 0x00, 0x04]]);
        expected.extend_from_slice(
            &"2400:3200::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        expected.extend_from_slice(&[0x01, 0xBB]);
        assert_eq!(agent.sent().await, expected);
    }
}
