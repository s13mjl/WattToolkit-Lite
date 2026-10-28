//! Minimal HTTP/1.1 request parsing and request/response forwarding.
//!
//! Used by the MITM reverse proxy (Hosts mode) to decrypt client requests,
//! forward them to the real upstream, and stream responses back.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    /// Origin-form path (may include query) as sent by the client.
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn host(&self) -> Option<String> {
        self.header("Host").map(|h| {
            // `[::1]:443` is an IPv6 literal, not a host named `[`
            if let Some(rest) = h.strip_prefix('[') {
                if let Some(end) = rest.find(']') {
                    return rest[..end].to_string();
                }
            }
            h.split(':').next().unwrap_or(h).to_string()
        })
    }

    pub fn host_port(&self) -> Option<(String, u16)> {
        self.header("Host").map(|h| {
            if let Some(rest) = h.strip_prefix('[') {
                if let Some(end) = rest.find(']') {
                    let host = rest[..end].to_string();
                    let port = rest[end + 1..]
                        .strip_prefix(':')
                        .and_then(|p| p.trim().parse().ok())
                        .unwrap_or(443);
                    return (host, port);
                }
            }
            match h.rsplit_once(':') {
                Some((host, port)) => {
                    let p: u16 = port.trim().parse().unwrap_or(443);
                    (host.to_string(), p)
                }
                None => (h.to_string(), 443),
            }
        })
    }
}

/// Read one HTTP/1.1 request from a stream (headers + full body).
///
/// The stream must be readable *and* writable because of `Expect:
/// 100-continue`: a client that sends it waits for an interim response before
/// transmitting the body (`git push` over HTTPS does this for large packs), so
/// reading the body first would deadlock.
pub async fn read_request<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
) -> Option<HttpRequest> {
    // Read until end of headers.
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte).await {
            Ok(0) => return None,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
                if buf.len() > 65536 {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
    let header_text = String::from_utf8_lossy(&buf).to_string();
    let mut lines = header_text.lines();
    let request_line = lines.next()?.to_string();
    let mut rl = request_line.split_whitespace();
    let method = rl.next()?.to_string();
    let path = rl.next()?.to_string();
    // version = third token (ignored)
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    // Answer the interim expectation before touching the body. The header is
    // not forwarded upstream (see `write_request`): the body is already in
    // hand by then, so a second exchange would only confuse the response read.
    let expects_continue = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("Expect") && v.to_lowercase().contains("100-continue")
    });
    if expects_continue {
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .ok()?;
        stream.flush().await.ok()?;
    }
    // Determine body length.
    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let is_chunked = headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("Transfer-Encoding") && v.to_lowercase().contains("chunked")
    });
    let mut body: Vec<u8> = Vec::new();
    if is_chunked {
        // Read chunks.
        loop {
            let size_line = read_line(stream, 4096).await.ok()?;
            let size = parse_chunk_size(&size_line).ok()?;
            if size == 0 {
                // The trailer section ends with an empty line; skipping only the
                // two bytes of an assumed empty trailer would leave a real
                // trailer in the stream and corrupt a keep-alive request.
                loop {
                    let line = read_line(stream, 8192).await.ok()?;
                    if line == b"\r\n" {
                        break;
                    }
                }
                break;
            }
            let chunk = read_n(stream, size).await?;
            body.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf).await.ok()?;
            if crlf != *b"\r\n" {
                return None;
            }
        }
    } else if content_length > 0 {
        // No artificial cap: the original runs Kestrel with
        // `MaxRequestBodySize = null` and streams the body, so truncating at
        // 16 MiB (the previous behavior) silently corrupted large `git push`
        // packs. `try_reserve` reports allocation failure instead of aborting.
        body.try_reserve_exact(content_length).ok()?;
        body.resize(content_length, 0);
        stream.read_exact(&mut body).await.ok()?;
    }
    Some(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

/// Read exactly `n` bytes into a new vector.
async fn read_n<R: AsyncReadExt + Unpin>(reader: &mut R, n: usize) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    buf.try_reserve_exact(n).ok()?;
    buf.resize(n, 0);
    reader.read_exact(&mut buf).await.ok()?;
    Some(buf)
}

/// Serialize a request to wire format (origin-form or absolute-form).
pub fn write_request(req: &HttpRequest, host: &str, port: u16, absolute: bool) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(req.method.as_bytes());
    out.push(b' ');
    if absolute {
        let scheme = if port == 443 { "https" } else { "http" };
        out.extend_from_slice(format!("{scheme}://{host}{}", req.path).as_bytes());
    } else {
        out.extend_from_slice(req.path.as_bytes());
    }
    out.extend_from_slice(b" HTTP/1.1\r\n");
    // RFC 7230 §5.4: the default port may be omitted from Host. Some upstreams
    // and CDNs treat a non-canonical Host ("github.com:443") as a different
    // site or reject it, so the port is only sent when it is not the default
    // for the scheme implied by the port itself.
    let host_value = if port == 80 || port == 443 {
        host.to_string()
    } else {
        format!("{host}:{port}")
    };
    // `read_request` de-chunks a chunked body before returning. Forwarding the
    // original `Transfer-Encoding: chunked` alongside that decoded body would
    // make the upstream parse the body as chunk framing (GitHub answers every
    // page chunked, so every POST would break). The decoded body is re-framed
    // with a Content-Length instead.
    let mut has_host = false;
    let mut has_conn = false;
    let mut body_was_framed = false;
    // HTTP/2 clients may split the cookie jar across several `cookie` headers;
    // HTTP/1.1 upstreams expect one. Merge them (RFC 6265 §5.4).
    let mut cookies: Vec<&str> = Vec::new();
    for (k, v) in &req.headers {
        let kl = k.to_lowercase();
        // Hop-by-hop headers must not be forwarded.
        if kl == "proxy-connection"
            || kl == "proxy-authorization"
            || kl == "proxy-authenticate"
            || kl == "keep-alive"
            || kl == "upgrade"
            || kl == "expect"
        {
            continue;
        }
        if kl == "transfer-encoding" || kl == "content-length" {
            body_was_framed = true;
            continue;
        }
        if kl == "cookie" {
            if !v.trim().is_empty() {
                cookies.push(v.trim());
            }
            continue;
        }
        if kl == "host" {
            has_host = true;
            out.extend_from_slice(format!("Host: {host_value}\r\n").as_bytes());
            continue;
        }
        if kl == "connection" {
            has_conn = true;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !has_host {
        out.extend_from_slice(format!("Host: {host_value}\r\n").as_bytes());
    }
    if !cookies.is_empty() {
        out.extend_from_slice(b"Cookie: ");
        out.extend_from_slice(cookies.join("; ").as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if body_was_framed {
        out.extend_from_slice(format!("Content-Length: {}\r\n", req.body.len()).as_bytes());
    }
    if !has_conn {
        out.extend_from_slice(b"Connection: keep-alive\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&req.body);
    out
}

/// Read a response head (status line + headers) from a stream.
pub struct ResponseHead {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
}

pub async fn read_response_head<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    timeout: std::time::Duration,
) -> Option<ResponseHead> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let head = tokio::time::timeout(left, read_one_response_head(reader))
            .await
            .ok()
            .flatten()?;
        // Interim responses (100 Continue, 102 Processing, 103 Early Hints) are
        // not the final answer. They used to be returned as if they were, which
        // made a `100 Continue` look like an empty final response while the real
        // response was still in flight.
        if matches!(head.status, 100 | 102 | 103) {
            continue;
        }
        return Some(head);
    }
}

async fn read_one_response_head<R: AsyncReadExt + Unpin>(reader: &mut R) -> Option<ResponseHead> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte).await {
            Ok(0) => return None,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
                if buf.len() > 65536 {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let mut lines = text.lines();
    let status_line = lines.next()?;
    let mut sl = status_line.splitn(3, ' ');
    let _version = sl.next()?;
    let status: u16 = sl.next()?.parse().ok()?;
    let reason = sl.next().unwrap_or("").to_string();
    let mut headers = Vec::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Some(ResponseHead {
        status,
        reason,
        headers,
    })
}

/// Stream the response (head already read) back to the client.
///
/// The body is relayed in the same framing the upstream used. A chunked body is
/// **not** de-chunked while its `Transfer-Encoding: chunked` header is kept -
/// that combination tells the client to parse raw entity bytes as chunk
/// headers, so every chunked response (GitHub's HTML/JSON among them) gets
/// corrupted and the page never finishes loading. Chunk sizes, extensions,
/// chunk data and trailers are forwarded verbatim instead.
///
/// `request_method` only decides whether a body can exist at all: a `HEAD`
/// answer (and `1xx`/`204`/`304`) carries no body even though it may advertise a
/// `Content-Length`, and reading one would block until the upstream closes.
pub async fn stream_response_body<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
    head: &ResponseHead,
    request_method: &str,
) -> Result<bool, ()> {
    stream_response_body_inner(reader, writer, head, request_method, false).await
}

/// Like `stream_response_body`, but a chunked body is **decoded**: only the
/// chunk data is written, without chunk sizes, CRLFs or trailers.
///
/// HTTP/2 has no chunked transfer coding; a relayed h1 chunk frame would be
/// handed to the browser as entity bytes and corrupt gzip/brotli pages. This is
/// the variant the h2 stream writer uses.
#[allow(clippy::result_unit_err)]
pub async fn stream_response_body_decoded<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
    head: &ResponseHead,
    request_method: &str,
) -> Result<bool, ()> {
    stream_response_body_inner(reader, writer, head, request_method, true).await
}

async fn stream_response_body_inner<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    mut reader: &mut R,
    mut writer: &mut W,
    head: &ResponseHead,
    request_method: &str,
    decode_chunked: bool,
) -> Result<bool, ()> {
    let connection = head
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Connection"))
        .map(|(_, v)| v.to_lowercase())
        .unwrap_or_default();
    let keep_alive = !connection.contains("close");
    let bodyless = request_method.eq_ignore_ascii_case("HEAD")
        || (100..200).contains(&head.status)
        || head.status == 204
        || head.status == 304;
    let content_length: Option<usize> = head
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .and_then(|(_, v)| v.trim().parse().ok());
    let chunked = head.headers.iter().any(|(k, v)| {
        k.eq_ignore_ascii_case("Transfer-Encoding") && v.to_lowercase().contains("chunked")
    });

    // Write the response head to the client.
    let mut out = Vec::new();
    out.extend_from_slice(format!("HTTP/1.1 {} {}\r\n", head.status, head.reason).as_bytes());
    for (k, v) in &head.headers {
        let kl = k.to_lowercase();
        if kl == "transfer-encoding" && !chunked {
            continue;
        }
        // Chunked framing wins; forwarding a stale Content-Length next to it
        // would contradict the body we relay verbatim.
        if kl == "content-length" && chunked {
            continue;
        }
        // Hop-by-hop headers are meaningful for this leg only.
        if kl == "connection" || kl == "keep-alive" || kl == "proxy-connection" || kl == "upgrade" {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !keep_alive {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    writer.write_all(&out).await.map_err(|_| ())?;

    if bodyless {
        writer.flush().await.map_err(|_| ())?;
        return Ok(keep_alive);
    }

    if chunked {
        if decode_chunked {
            relay_chunked_decoded(&mut reader, &mut writer).await?;
        } else {
            relay_chunked(&mut reader, &mut writer).await?;
        }
    } else if let Some(len) = content_length {
        if len > 0 {
            stream_exact_n(&mut reader, &mut writer, len).await?;
        }
    } else {
        // No framing: the body runs until the upstream closes.
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = read_body(&mut reader, &mut buf).await?;
            if n == 0 {
                break;
            }
            writer.write_all(&buf[..n]).await.map_err(|_| ())?;
        }
        return Ok(false);
    }
    writer.flush().await.map_err(|_| ())?;
    Ok(keep_alive)
}

/// Relay one chunked body verbatim, including chunk extensions and trailers.
async fn relay_chunked<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), ()> {
    loop {
        let size_line = read_line(reader, 4096).await?;
        let size = parse_chunk_size(&size_line)?;
        writer.write_all(&size_line).await.map_err(|_| ())?;
        if size == 0 {
            // Trailer section, terminated by an empty line (which is forwarded
            // too, so the client sees a complete message).
            loop {
                let line = read_line(reader, 8192).await?;
                writer.write_all(&line).await.map_err(|_| ())?;
                if line == b"\r\n" {
                    return Ok(());
                }
            }
        }
        stream_exact_n(reader, writer, size).await?;
        let mut crlf = [0u8; 2];
        read_full(reader, &mut crlf).await?;
        writer.write_all(&crlf).await.map_err(|_| ())?;
    }
}

/// Relay one chunked body as decoded entity bytes: chunk sizes, CRLFs and
/// trailers are consumed but not forwarded.
async fn relay_chunked_decoded<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), ()> {
    loop {
        let size_line = read_line(reader, 4096).await?;
        let size = parse_chunk_size(&size_line)?;
        if size == 0 {
            // Consume the trailer section (or its empty terminator).
            loop {
                let line = read_line(reader, 8192).await?;
                if line == b"\r\n" {
                    return Ok(());
                }
            }
        }
        stream_exact_n(reader, writer, size).await?;
        let mut crlf = [0u8; 2];
        read_full(reader, &mut crlf).await?;
    }
}

/// A response body that produces no bytes for this long is treated as dead.
///
/// A censored GitHub edge can send the response head (and sometimes a first
/// 32 KiB) and then stop forwarding. Without an idle bound the client hangs
/// until its own timeout and the proxy never re-races another edge; closing the
/// connection lets the client retry, and the retry goes through the endpoint
/// fallback again.
const BODY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

async fn read_body<R: AsyncReadExt + Unpin>(reader: &mut R, buf: &mut [u8]) -> Result<usize, ()> {
    tokio::time::timeout(BODY_IDLE_TIMEOUT, reader.read(buf))
        .await
        .map_err(|_| ())?
        .map_err(|_| ())
}

async fn read_full<R: AsyncReadExt + Unpin>(reader: &mut R, buf: &mut [u8]) -> Result<(), ()> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = read_body(reader, &mut buf[offset..]).await?;
        if n == 0 {
            return Err(());
        }
        offset += n;
    }
    Ok(())
}

/// Read one CRLF-terminated line including the terminator.
async fn read_line<R: AsyncReadExt + Unpin>(reader: &mut R, max: usize) -> Result<Vec<u8>, ()> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if read_body(reader, &mut byte).await? == 0 {
            return Err(());
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n") {
            return Ok(buf);
        }
        if buf.len() > max {
            return Err(());
        }
    }
}

fn parse_chunk_size(line: &[u8]) -> Result<usize, ()> {
    let size_str = String::from_utf8_lossy(line)
        .trim()
        .split(';')
        .next()
        .unwrap_or("0")
        .trim()
        .to_string();
    u64::from_str_radix(&size_str, 16)
        .map(|v| v as usize)
        .map_err(|_| ())
}

async fn stream_exact_n<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
    mut n: usize,
) -> Result<(), ()> {
    let mut buf = vec![0u8; 64 * 1024];
    while n > 0 {
        let to_read = n.min(buf.len());
        let r = read_body(reader, &mut buf[..to_read]).await?;
        if r == 0 {
            return Err(());
        }
        writer.write_all(&buf[..r]).await.map_err(|_| ())?;
        n -= r;
    }
    Ok(())
}

/// Per-endpoint connect budget, matching the original `TunnelMiddleware`
/// (`connectTimeout = TimeSpan.FromSeconds(10d)`). Endpoints are tried one at a
/// time, so the total wait grows with the number of failing endpoints, exactly
/// like the original `ConnectCallback`.
pub(crate) const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// How long an upstream may take to produce the first response bytes after the
/// request was written. Generous on purpose - trans-Pacific RTT plus server
/// think time has to fit - but bounded: an upstream that accepts the request
/// and then stalls used to hold the connection open forever, which showed up
/// on real machines as "[MITM] GET …" followed by silence while the browser
/// had already timed out.
pub(crate) const RESPONSE_HEAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Build the ordered upstream endpoint sequence.
///
/// Mirrors the original `GetIPEndPointsAsync`: the manifest-configured addresses
/// first (original `ReverseProxyConfig.IPAddress`), then the caller-resolved DNS
/// answers. `preferred` only changes the order - it grants no trust, so an
/// address that answers the TCP handshake but cannot serve the host is skipped
/// by the TLS verification in `connect_upstream_tls` like any other failing
/// endpoint. Duplicates are dropped, order is preserved.
pub fn candidate_endpoints(
    preferred: &[std::net::IpAddr],
    port: u16,
    ips: &[std::net::IpAddr],
) -> Vec<std::net::SocketAddr> {
    let mut out: Vec<std::net::SocketAddr> = Vec::new();
    for ip in preferred.iter().chain(ips.iter()) {
        let sa = std::net::SocketAddr::new(*ip, port);
        if !out.contains(&sa) {
            out.push(sa);
        }
    }
    out
}

/// Connect to the first endpoint of `addrs` that accepts a TCP connection.
///
/// Endpoints are tried in order, each under its own timeout, and a failing one
/// is abandoned in favour of the next - the original `ConnectCallback` semantics
/// (`await foreach` over the endpoint sequence plus one `connectTimeout` per
/// endpoint). `None` means every endpoint failed.
pub async fn connect_upstream(addrs: &[std::net::SocketAddr]) -> Option<TcpStream> {
    let total = addrs.len();
    for (i, addr) in addrs.iter().enumerate() {
        let started = std::time::Instant::now();
        log::info!(target: "wtlite_core::proxy", "[dial] {}/{total} {addr}", i + 1);
        if let Ok(Ok(stream)) =
            tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await
        {
            log::info!(target: "wtlite_core::proxy", "[dial] {addr} ok in {:?}", started.elapsed());
            return Some(tune(stream));
        }
        log::warn!(target: "wtlite_core::proxy", "[dial] {addr} failed after {:?}", started.elapsed());
    }
    None
}

/// Connect **and** complete the TLS handshake for the first endpoint that does
/// both, moving on whenever either step fails.
///
/// The original runs `ConnectAsync` (socket connect, `AuthenticateAsClientAsync`,
/// certificate validation) under a single per-endpoint `connectTimeout` and keeps
/// the first endpoint that succeeds end to end, so an endpoint that answers the
/// TCP handshake but cannot complete TLS is skipped instead of being adopted.
pub async fn connect_upstream_tls(
    addrs: &[std::net::SocketAddr],
    sni: &str,
    connector: &tokio_rustls::TlsConnector,
) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
    let dns_name = rustls::pki_types::ServerName::try_from(sni.to_string()).ok()?;
    let total = addrs.len();
    for (i, addr) in addrs.iter().enumerate() {
        let started = std::time::Instant::now();
        log::info!(target: "wtlite_core::proxy", "[dial] {}/{total} {addr} sni={sni}", i + 1);
        // `stage` records how the attempt ended when the timeout above fires or
        // the attempt returns None, so the failure line says whether the TCP
        // connect or the TLS handshake was the step that did not complete.
        let mut stage = "timeout";
        let attempt = async {
            let stream = match TcpStream::connect(addr).await {
                Ok(s) => tune(s),
                Err(_) => {
                    stage = "tcp-failed";
                    return None;
                }
            };
            match connector.connect(dns_name.clone(), stream).await {
                Ok(t) => Some(t),
                Err(_) => {
                    stage = "tls-failed";
                    None
                }
            }
        };
        if let Ok(Some(stream)) = tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
            log::info!(target: "wtlite_core::proxy", "[dial] {addr} ok in {:?}", started.elapsed());
            return Some(stream);
        }
        log::warn!(target: "wtlite_core::proxy", "[dial] {addr} {stage} after {:?}", started.elapsed());
    }
    None
}

/// Connect **and** complete the TLS handshake without sending SNI, moving on
/// whenever either step fails.
///
/// Mirrors the original `TlsSniPattern.None` path: a manifest project without
/// `FakeServerName` has `TlsSni == false`, so `SslStream` is given an empty
/// target host and no `server_name` extension is sent. The connector passed in
/// must verify the certificate against the *requested* host instead of the
/// (absent) SNI; `crate::mitm::no_sni_connector` builds it that way.
pub async fn connect_upstream_tls_no_sni(
    addrs: &[std::net::SocketAddr],
    connector: &tokio_rustls::TlsConnector,
) -> Option<tokio_rustls::client::TlsStream<TcpStream>> {
    let total = addrs.len();
    for (i, addr) in addrs.iter().enumerate() {
        let started = std::time::Instant::now();
        log::info!(target: "wtlite_core::proxy", "[dial] {}/{total} {addr} sni=<none>", i + 1);
        let mut stage = "timeout";
        let attempt = async {
            let stream = match TcpStream::connect(addr).await {
                Ok(s) => tune(s),
                Err(_) => {
                    stage = "tcp-failed";
                    return None;
                }
            };
            // An IP `ServerName` makes rustls omit the SNI extension.
            let name = rustls::pki_types::ServerName::IpAddress(addr.ip().into());
            match connector.connect(name, stream).await {
                Ok(t) => Some(t),
                Err(_) => {
                    stage = "tls-failed";
                    None
                }
            }
        };
        if let Ok(Some(stream)) = tokio::time::timeout(CONNECT_TIMEOUT, attempt).await {
            log::info!(target: "wtlite_core::proxy", "[dial] {addr} ok in {:?} (no sni)", started.elapsed());
            return Some(stream);
        }
        log::warn!(target: "wtlite_core::proxy", "[dial] {addr} {stage} after {:?} (no sni)", started.elapsed());
    }
    None
}

/// Nagle + delayed ACK cost real throughput on high-latency links (GitHub is
/// reached over a trans-Pacific path here): partial segments were held back
/// waiting for an ACK, which showed up as ~1.7s of extra transfer time per
/// page. The proxy relays whole buffers, so coalescing buys us nothing.
pub(crate) fn tune(stream: TcpStream) -> TcpStream {
    let _ = stream.set_nodelay(true);
    stream
}

// Note for callers: do NOT resolve the host through the system resolver before
// dialling it. In DNS-interception mode a lookup for an accelerated host is
// answered 127.0.0.1 by our own hook, and 127.0.0.1 is the fastest to connect
// (loopback) - the proxy would dial its own 443 listener and fail the TLS
// handshake. Callers pass in the DNS answers they resolved themselves.

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, SocketAddr};

    fn ip(o: [u8; 4]) -> IpAddr {
        IpAddr::from(o)
    }

    #[test]
    fn configured_addresses_lead_the_candidate_sequence() {
        let configured = [ip([140, 82, 112, 4]), ip([140, 82, 113, 4])];
        let answers = [ip([140, 82, 112, 4]), ip([20, 205, 243, 166])];
        assert_eq!(
            candidate_endpoints(&configured, 443, &answers),
            vec![
                SocketAddr::new(ip([140, 82, 112, 4]), 443),
                SocketAddr::new(ip([140, 82, 113, 4]), 443),
                SocketAddr::new(ip([20, 205, 243, 166]), 443),
            ]
        );
    }

    #[test]
    fn dns_answers_keep_their_order_without_configured_addresses() {
        let ips = [ip([1, 1, 1, 1]), ip([2, 2, 2, 2])];
        assert_eq!(
            candidate_endpoints(&[], 80, &ips),
            vec![
                SocketAddr::new(ip([1, 1, 1, 1]), 80),
                SocketAddr::new(ip([2, 2, 2, 2]), 80),
            ]
        );
    }

    #[tokio::test]
    async fn an_unreachable_configured_address_is_skipped_in_favour_of_the_answers() {
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let Ok(good) = listener.local_addr() else {
            return;
        };
        // 127.0.0.2 on the same port has no listener, so the configured address
        // has to be abandoned and the DNS answer adopted instead.
        let configured = [std::net::IpAddr::from([127, 0, 0, 2])];
        let answers = [good.ip()];
        let addrs = candidate_endpoints(&configured, good.port(), &answers);
        let stream = connect_upstream(&addrs).await;
        assert!(stream.is_some(), "reachable answer was not adopted");
        if let Some(s) = stream {
            assert_eq!(s.peer_addr().ok(), Some(good));
        }
    }

    #[tokio::test]
    async fn a_configured_address_that_cannot_complete_tls_is_not_adopted() {
        // A listener that accepts and closes without answering the handshake:
        // the TCP handshake succeeds, yet the endpoint must still be rejected
        // because the TLS handshake and its certificate check never complete.
        crate::mitm::ensure_crypto_provider();
        let Ok(listener) = tokio::net::TcpListener::bind("127.0.0.1:0").await else {
            return;
        };
        let Ok(plain) = listener.local_addr() else {
            return;
        };
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                drop(sock);
            }
        });
        let addrs = candidate_endpoints(&[plain.ip()], plain.port(), &[]);
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            ))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
        assert!(
            connect_upstream_tls(&addrs, "github.com", &connector)
                .await
                .is_none(),
            "an endpoint without a completed TLS handshake was adopted"
        );
    }

    #[test]
    fn the_host_header_omits_default_ports() {
        let req = HttpRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![("Host".into(), "github.com".into())],
            body: Vec::new(),
        };
        // 443 is the default for the scheme the upstream leg dials, so the
        // port must not appear in Host.
        let wire = String::from_utf8(write_request(&req, "github.com", 443, false)).unwrap();
        assert!(wire.contains("Host: github.com\r\n"), "{wire}");
        assert!(!wire.contains(":443"), "{wire}");
        // Same for plain HTTP.
        let wire = String::from_utf8(write_request(&req, "example.com", 80, false)).unwrap();
        assert!(wire.contains("Host: example.com\r\n"), "{wire}");
        // A non-default port stays in Host.
        let wire = String::from_utf8(write_request(&req, "example.com", 8443, false)).unwrap();
        assert!(wire.contains("Host: example.com:8443\r\n"), "{wire}");
    }

    #[test]
    fn a_missing_host_header_is_added_without_the_default_port() {
        let req = HttpRequest {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![],
            body: Vec::new(),
        };
        let wire = String::from_utf8(write_request(&req, "github.com", 443, false)).unwrap();
        assert!(wire.contains("Host: github.com\r\n"), "{wire}");
        assert!(!wire.contains(":443"), "{wire}");
    }

    fn response_head(status: u16, headers: &[(&str, &str)]) -> ResponseHead {
        ResponseHead {
            status,
            reason: "OK".to_string(),
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    /// A chunked upstream response must reach the client with the **same**
    /// framing: the `Transfer-Encoding: chunked` header stays, so the body has
    /// to keep its chunk sizes and trailers. Sending a de-chunked body under
    /// that header (the previous behavior) made every chunked page - GitHub's
    /// HTML among them - unparsable.
    #[tokio::test]
    async fn a_chunked_response_keeps_its_framing_and_trailers() {
        let body: &[u8] = b"4\r\nWiki\r\n5;name=value\r\npedia\r\n0\r\nX-Trailer: yes\r\n\r\n";
        let mut reader = body;
        let mut writer: Vec<u8> = Vec::new();
        let head = response_head(200, &[("Transfer-Encoding", "chunked")]);
        let keep = stream_response_body(&mut reader, &mut writer, &head, "GET")
            .await
            .unwrap();
        assert!(keep);
        let text = String::from_utf8_lossy(&writer);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.contains("Transfer-Encoding: chunked\r\n"), "{text}");
        assert!(text.ends_with(std::str::from_utf8(body).unwrap()), "{text}");
    }

    /// The h2 path must receive entity bytes only: chunk framing (and trailers)
    /// are consumed, never written. Relaying them corrupts gzip/brotli pages.
    #[tokio::test]
    async fn a_decoded_chunked_response_drops_framing_and_trailers() {
        let body: &[u8] = b"4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: yes\r\n\r\n";
        let mut reader = body;
        let mut writer: Vec<u8> = Vec::new();
        let head = response_head(200, &[("Transfer-Encoding", "chunked")]);
        let keep = stream_response_body_decoded(&mut reader, &mut writer, &head, "GET")
            .await
            .unwrap();
        assert!(keep);
        let text = String::from_utf8_lossy(&writer);
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.ends_with("Wikipedia"), "{text}");
        assert!(!text.contains("4\r\nWiki"), "{text}");
        assert!(!text.contains("X-Trailer"), "{text}");
    }

    /// A plain `Content-Length` body is copied byte for byte.
    #[tokio::test]
    async fn a_content_length_response_body_is_forwarded_verbatim() {
        let mut reader: &[u8] = b"hello world";
        let mut writer: Vec<u8> = Vec::new();
        let head = response_head(200, &[("Content-Length", "11")]);
        let keep = stream_response_body(&mut reader, &mut writer, &head, "GET")
            .await
            .unwrap();
        assert!(keep);
        assert!(writer.ends_with(b"hello world"));
    }

    /// `HEAD` and bodyless statuses may advertise a `Content-Length` but never
    /// carry a body; reading one would block on a live upstream forever.
    #[tokio::test]
    async fn bodyless_responses_are_not_read_past_the_head() {
        for (method, status) in [("HEAD", 200u16), ("GET", 204), ("GET", 304)] {
            let mut reader: &[u8] = b"";
            let mut writer: Vec<u8> = Vec::new();
            let head = response_head(status, &[("Content-Length", "1234")]);
            let keep = stream_response_body(&mut reader, &mut writer, &head, method)
                .await
                .unwrap();
            assert!(keep, "{method} {status}");
            assert!(writer.ends_with(b"\r\n\r\n"), "{method} {status}");
        }
    }

    /// HTTP/2 may split cookies over several `cookie` headers; the h1 upstream
    /// must receive a single merged `Cookie` header, otherwise the server sees
    /// only one part of the jar and can treat the client as logged out.
    #[test]
    fn split_cookie_headers_are_merged_for_the_upstream() {
        let req = HttpRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: vec![
                ("Host".to_string(), "github.com".to_string()),
                ("cookie".to_string(), "logged_in=yes; _octo=abc".to_string()),
                ("Cookie".to_string(), "user_session=xyz".to_string()),
            ],
            body: Vec::new(),
        };
        let wire = String::from_utf8(write_request(&req, "github.com", 443, false)).unwrap();
        assert_eq!(
            wire.matches("Cookie: ").count(),
            1,
            "cookies were not merged: {wire}"
        );
        assert!(
            wire.contains("Cookie: logged_in=yes; _octo=abc; user_session=xyz\r\n"),
            "{wire}"
        );
    }

    /// `read_request` hands back a decoded body. The forwarded request must then
    /// use a matching `Content-Length` and must not repeat
    /// `Transfer-Encoding: chunked`, or the upstream would parse the entity as
    /// chunk framing.
    #[test]
    fn a_dechunked_request_body_is_reframed_with_content_length() {
        let req = HttpRequest {
            method: "POST".to_string(),
            path: "/submit".to_string(),
            headers: vec![
                ("Host".to_string(), "example.com".to_string()),
                ("Transfer-Encoding".to_string(), "chunked".to_string()),
            ],
            body: b"hello".to_vec(),
        };
        let wire = String::from_utf8(write_request(&req, "example.com", 443, false)).unwrap();
        assert!(!wire.to_lowercase().contains("transfer-encoding"), "{wire}");
        assert!(wire.contains("Content-Length: 5\r\n"), "{wire}");
        assert!(wire.contains("Host: example.com\r\n"), "{wire}");
        assert!(wire.ends_with("hello"), "{wire}");
    }

    /// `git push` sends `Expect: 100-continue` with a large body. The proxy must
    /// answer the interim expectation before waiting for the body, otherwise
    /// both sides wait forever.
    #[tokio::test]
    async fn expect_continue_is_answered_before_the_body_is_read() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move { read_request(&mut server).await });
        client
            .write_all(
                b"POST /git-receive-pack HTTP/1.1\r\nHost: github.com\r\n\
                  Content-Length: 5\r\nExpect: 100-continue\r\n\r\n",
            )
            .await
            .unwrap();
        let mut interim = [0u8; 25];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.read_exact(&mut interim),
        )
        .await
        .expect("the proxy never answered Expect: 100-continue")
        .unwrap();
        assert_eq!(&interim, b"HTTP/1.1 100 Continue\r\n\r\n");
        client.write_all(b"hello").await.unwrap();
        let req = task.await.unwrap().unwrap();
        assert_eq!(req.body, b"hello");
        assert_eq!(req.header("Expect"), Some("100-continue"));
    }

    /// Interim responses are skipped until the final response head.
    #[tokio::test]
    async fn interim_responses_are_skipped() {
        let wire: &[u8] = b"HTTP/1.1 100 Continue\r\n\r\n\
                             HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n\
                             HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let mut reader = wire;
        let head = read_response_head(&mut reader, std::time::Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(head.status, 200);
    }

    #[tokio::test]
    async fn a_silent_upstream_is_abandoned_after_the_head_timeout() {
        // An upstream that accepts the connection and then never sends a byte
        // must be abandoned by the timeout, not waited on forever - this is the
        // real-machine PAC hang behind the silent 30 s gap in the log.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            // Keep the accepted socket alive without ever answering.
            std::mem::forget(sock);
        });
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let started = std::time::Instant::now();
        let head = read_response_head(&mut stream, std::time::Duration::from_millis(300)).await;
        assert!(head.is_none(), "a silent upstream must yield no head");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the head read waited {:?}, the timeout did not fire",
            started.elapsed()
        );
    }
}
