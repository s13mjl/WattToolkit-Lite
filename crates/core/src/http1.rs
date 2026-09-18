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
        self.header("Host").map(|h| h.split(':').next().unwrap_or(h).to_string())
    }

    pub fn host_port(&self) -> Option<(String, u16)> {
        self.header("Host").map(|h| match h.rsplit_once(':') {
            Some((host, port)) => {
                let p: u16 = port.trim().parse().unwrap_or(443);
                (host.to_string(), p)
            }
            None => (h.to_string(), 443),
        })
    }
}

/// Read one HTTP/1.1 request from a stream (headers + full body).
pub async fn read_request<R: AsyncReadExt + Unpin>(mut reader: &mut R) -> Option<HttpRequest> {
    // Read until end of headers.
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
    // Determine body length.
    let content_length = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .and_then(|(_, v)| v.trim().parse::<usize>().ok())
        .unwrap_or(0);
    let is_chunked = headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("Transfer-Encoding") && v.to_lowercase().contains("chunked"));
    let mut body: Vec<u8> = Vec::new();
    if is_chunked {
        // Read chunks.
        loop {
            // Read size line.
            let mut size_buf = Vec::new();
            loop {
                match reader.read(&mut byte).await {
                    Ok(0) => return None,
                    Ok(_) => {
                        size_buf.push(byte[0]);
                        if size_buf.ends_with(b"\r\n") {
                            break;
                        }
                        if size_buf.len() > 32 {
                            return None;
                        }
                    }
                    Err(_) => return None,
                }
            }
            let size_str = String::from_utf8_lossy(&size_buf)
                .trim()
                .split(';')
                .next()
                .unwrap_or("0")
                .trim()
                .to_string();
            let size = u64::from_str_radix(&size_str, 16).ok()?;
            if size == 0 {
                // consume trailing CRLF
                let _ = read_exact_n(&mut reader, &mut [0u8; 2]).await;
                break;
            }
            let mut chunk = vec![0u8; size as usize];
            if reader.read_exact(&mut chunk).await.is_err() {
                return None;
            }
            body.extend_from_slice(&chunk);
            let _ = read_exact_n(&mut reader, &mut [0u8; 2]).await;
        }
    } else if content_length > 0 {
        let mut chunk = vec![0u8; content_length.min(16 * 1024 * 1024)];
        if reader.read_exact(&mut chunk).await.is_err() {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    Some(HttpRequest {
        method,
        path,
        headers,
        body,
    })
}

async fn read_exact_n<R: AsyncReadExt + Unpin>(r: &mut R, buf: &mut [u8]) -> Result<usize, ()> {
    r.read_exact(buf).await.map_err(|_| ())
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
    let mut has_host = false;
    let mut has_conn = false;
    for (k, v) in &req.headers {
        let kl = k.to_lowercase();
        // Hop-by-hop headers must not be forwarded.
        if kl == "proxy-connection" || kl == "proxy-authorization" || kl == "proxy-authenticate"
        {
            continue;
        }
        if kl == "host" {
            has_host = true;
            out.extend_from_slice(format!("Host: {host}:{port}\r\n").as_bytes());
            continue;
        }
        if kl == "connection" {
            has_conn = true;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !has_host {
        out.extend_from_slice(format!("Host: {host}:{port}\r\n").as_bytes());
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

pub async fn read_response_head<R: AsyncReadExt + Unpin>(reader: &mut R) -> Option<ResponseHead> {
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
    let status_line = lines.next()?.to_string();
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
    Some(ResponseHead { status, reason, headers })
}

/// Stream the response (head already read) back to the client.
pub async fn stream_response_body<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    mut reader: &mut R,
    mut writer: &mut W,
    head: &ResponseHead,
) -> Result<bool, ()> {
    let connection = head
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Connection"))
        .map(|(_, v)| v.to_lowercase())
        .unwrap_or_default();
    let keep_alive = !connection.contains("close");
    let content_length: Option<usize> = head
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
        .and_then(|(_, v)| v.trim().parse().ok());
    let chunked = head
        .headers
        .iter()
        .any(|(k, v)| {
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
        if kl == "connection" {
            continue;
        }
        out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
    }
    if !keep_alive {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"\r\n");
    writer.write_all(&out).await.map_err(|_| ())?;

    if chunked {
        // De-chunk while streaming.
        loop {
            let size = read_chunk_size(&mut reader).await?;
            if size == 0 {
                let _ = read_exact_n(&mut reader, &mut [0u8; 2]).await;
                break;
            }
            stream_exact_n(&mut reader, &mut writer, size).await?;
            let _ = read_exact_n(&mut reader, &mut [0u8; 2]).await;
        }
    } else if let Some(len) = content_length {
        if len > 0 {
            stream_exact_n(&mut reader, &mut writer, len).await?;
        }
    } else {
        // Read until EOF.
        tokio::io::copy(&mut reader, &mut writer).await.map_err(|_| ())?;
        return Ok(false);
    }
    writer.flush().await.map_err(|_| ())?;
    Ok(keep_alive)
}

async fn read_chunk_size<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<usize, ()> {
    let mut size_buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte).await {
            Ok(0) => return Err(()),
            Ok(_) => {
                size_buf.push(byte[0]);
                if size_buf.ends_with(b"\r\n") {
                    break;
                }
                if size_buf.len() > 32 {
                    return Err(());
                }
            }
            Err(_) => return Err(()),
        }
    }
    let size_str = String::from_utf8_lossy(&size_buf)
        .trim()
        .split(';')
        .next()
        .unwrap_or("0")
        .trim()
        .to_string();
    u64::from_str_radix(&size_str, 16).map(|v| v as usize).map_err(|_| ())
}

async fn stream_exact_n<R: AsyncReadExt + Unpin, W: AsyncWriteExt + Unpin>(
    reader: &mut R,
    writer: &mut W,
    mut n: usize,
) -> Result<(), ()> {
    let mut buf = vec![0u8; 64 * 1024];
    while n > 0 {
        let to_read = n.min(buf.len());
        let r = reader.read(&mut buf[..to_read]).await.map_err(|_| ())?;
        if r == 0 {
            return Err(());
        }
        writer.write_all(&buf[..r]).await.map_err(|_| ())?;
        n -= r;
    }
    Ok(())
}

/// Per-candidate connect budget, matching the original `TunnelMiddleware`
/// (`connectTimeout = TimeSpan.FromSeconds(10d)`). Candidates are raced, so the
/// total wait is one timeout, not one per address.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Try every candidate concurrently and return the first connection that wins.
async fn race_connect(
    addrs: &[std::net::SocketAddr],
    timeout: std::time::Duration,
) -> Option<TcpStream> {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<TcpStream>(1);
    let mut spawned = 0usize;
    for addr in addrs.iter().take(8) {
        let tx = tx.clone();
        let addr = *addr;
        tokio::spawn(async move {
            if let Ok(Ok(stream)) = tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
                let _ = tx.send(stream).await;
            }
        });
        spawned += 1;
    }
    drop(tx);
    if spawned == 0 {
        return None;
    }
    rx.recv().await
}

/// Establish an upstream TCP connection to host:port.
///
/// Every candidate is raced together: the accelerated-DNS answers *and* the
/// system-resolved ones. Trying the custom DNS first and only falling back on
/// failure wasted the full timeout whenever that answer was unreachable (e.g.
/// a DoH endpoint returning a blocked region IP while the system resolver has a
/// reachable one) - the original streams all endpoints and keeps the first that
/// connects.
pub async fn connect_upstream(host: &str, port: u16, ips: &[std::net::IpAddr]) -> Option<TcpStream> {
    // Do NOT call the system resolver here: in DNS-interception mode a lookup for
    // an accelerated host is answered 127.0.0.1 by our own hook, and 127.0.0.1 is
    // the fastest to connect (localhost) - the proxy would race-connect to its own
    // 443 listener and the TLS handshake fails. `host` is kept only for logging.
    let _ = host;
    let candidates: Vec<std::net::SocketAddr> = ips
        .iter()
        .map(|ip| std::net::SocketAddr::new(*ip, port))
        .collect();
    race_connect(&candidates, CONNECT_TIMEOUT).await
}
