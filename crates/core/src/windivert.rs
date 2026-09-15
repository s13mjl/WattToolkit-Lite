//! WinDivert-based DNS interception, mirroring the original
//! DnsIntercept / WinDivertServiceImpl behavior: answer DNS queries for the
//! accelerated domains with 127.0.0.1 so traffic is steered to the local
//! proxy.
//!
//! Uses libloading to open WinDivert.dll at runtime so the app degrades
//! gracefully (with a clear status) when the driver binaries are absent.

use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::Arc;
use libloading::{Library, Symbol};

type WinDivertOpenFn =
    unsafe extern "system" fn(*const i8, i32, i32, u32) -> *mut c_void;
type WinDivertRecvFn = unsafe extern "system" fn(*mut c_void, *mut c_void, u32) -> i32;
type WinDivertSendFn = unsafe extern "system" fn(*mut c_void, *const c_void, u32) -> i32;
type WinDivertCloseFn = unsafe extern "system" fn(*mut c_void);

const WIN_DIVERT_VERSION: u32 = 6;
const HEADER_LEN: usize = 40;

pub struct DnsInterceptRuntime {
    /// Domains to intercept (lowercase, no leading dot).
    pub domains: Arc<RwLock<HashSet<String>>>,
    pub log_tx: tokio::sync::mpsc::UnboundedSender<String>,
    stop: Arc<AtomicBool>,
}

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

impl DnsInterceptRuntime {
    pub fn new(domains: Arc<RwLock<HashSet<String>>>, log_tx: tokio::sync::mpsc::UnboundedSender<String>) -> Self {
        Self {
            domains,
            log_tx,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    fn send_log(&self, msg: String) {
        log::info!(target: "wtlite_core::proxy", "{msg}");
        let _ = self.log_tx.send(msg);
    }

    /// Run the interception loop on a blocking thread.
    pub fn run(self: &Arc<Self>) {
        // Load WinDivert.dll.
        let lib: Library = match unsafe { Library::new("WinDivert.dll") } {
            Ok(l) => l,
            Err(e) => {
                self.send_log(format!("[WinDivert] WinDivert.dll not found: {e}. DNS 拦截不可用。"));
                return;
            }
        };
        let win_divert_open: Symbol<WinDivertOpenFn> = match unsafe { lib.get(b"WinDivertOpen") } {
            Ok(s) => s,
            Err(e) => {
                self.send_log(format!("[WinDivert] WinDivertOpen symbol missing: {e}"));
                return;
            }
        };
        let win_divert_recv: Symbol<WinDivertRecvFn> = match unsafe { lib.get(b"WinDivertRecv") } {
            Ok(s) => s,
            Err(e) => {
                self.send_log(format!("[WinDivert] WinDivertRecv symbol missing: {e}"));
                return;
            }
        };
        let win_divert_send: Symbol<WinDivertSendFn> = match unsafe { lib.get(b"WinDivertSend") } {
            Ok(s) => s,
            Err(e) => {
                self.send_log(format!("[WinDivert] WinDivertSend symbol missing: {e}"));
                return;
            }
        };
        let win_divert_close: Symbol<WinDivertCloseFn> = match unsafe { lib.get(b"WinDivertClose") } {
            Ok(s) => s,
            Err(e) => {
                self.send_log(format!("[WinDivert] WinDivertClose symbol missing: {e}"));
                return;
            }
        };

        // Open: IPv4, L3, block.
        let filter = std::ffi::CString::new("udp and DstPort == 53").unwrap();
        let handle = unsafe { win_divert_open(filter.as_ptr(), 0, 1, 0) };
        if handle.is_null() {
            self.send_log("[WinDivert] WinDivertOpen failed (need admin / driver). DNS 拦截不可用。".to_string());
            return;
        }
        self.send_log("[WinDivert] DNS 拦截已启动".to_string());

        let mut buf = vec![0u8; 65536];
        while !self.stop.load(Ordering::Relaxed) {
            let n = unsafe { win_divert_recv(handle, buf.as_mut_ptr() as *mut c_void, buf.len() as u32) };
            if n <= 0 {
                // Error (e.g. handle closed).
                break;
            }
            let n = n as usize;
            if let Some(resp) = build_dns_response_if_match(&buf[..n], &self.domains.read().unwrap()) {
                unsafe {
                    win_divert_send(handle, resp.as_ptr() as *const c_void, resp.len() as u32);
                }
            } else {
                // Forward unmatched packets unchanged.
                unsafe {
                    win_divert_send(handle, buf.as_ptr() as *const c_void, n as u32);
                }
            }
        }
        unsafe { win_divert_close(handle) };
        self.send_log("[WinDivert] DNS 拦截已停止".to_string());
    }
}

/// If the DNS query matches one of our domains, build a response packet.
fn build_dns_response_if_match(packet: &[u8], domains: &HashSet<String>) -> Option<Vec<u8>> {
    if packet.len() < HEADER_LEN + 20 + 8 + 12 {
        return None;
    }
    let ver = u32::from_le_bytes(packet[0..4].try_into().ok()?);
    if ver != WIN_DIVERT_VERSION {
        return None;
    }
    let ip_hdr = &packet[HEADER_LEN..];
    let ihl = ((ip_hdr[0] & 0x0f) as usize) * 4;
    if ip_hdr[9] != 17 {
        return None; // not UDP
    }
    let udp = &ip_hdr[ihl..];
    if udp.len() < 8 + 12 {
        return None;
    }
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if dst_port != 53 {
        return None;
    }
    let dns = &udp[8..];
    let id = &dns[0..2];
    let qname = parse_qname(dns)?;
    let qname_l = qname.to_lowercase();
    // Match exact domain or subdomain.
    let matched = domains.iter().any(|d| {
        qname_l == d.as_str() || qname_l.ends_with(&format!(".{d}"))
    });
    if !matched {
        return None;
    }
    build_dns_response_packet(packet, id, qname.as_str())
}

/// Parse the query name from a DNS payload.
fn parse_qname(dns: &[u8]) -> Option<String> {
    if dns.len() < 16 {
        return None;
    }
    let mut i = 12usize;
    let mut labels = Vec::new();
    while i < dns.len() {
        let len = dns[i] as usize;
        if len == 0 {
            break;
        }
        i += 1;
        if i + len > dns.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&dns[i..i + len]).to_string());
        i += len;
    }
    Some(labels.join("."))
}

/// Build a full WinDivert response packet answering the query with 127.0.0.1.
fn build_dns_response_packet(packet: &[u8], id: &[u8], qname: &str) -> Option<Vec<u8>> {
    let ip_hdr = &packet[HEADER_LEN..];
    let ihl = ((ip_hdr[0] & 0x0f) as usize) * 4;
    let udp = &ip_hdr[ihl..];
    let src_ip = ip_hdr[12..16].to_vec(); // client
    let dst_ip = ip_hdr[16..20].to_vec(); // dns server
    let src_port = u16::from_be_bytes([udp[0], udp[1]]); // client port
    let dns_port = u16::from_be_bytes([udp[2], udp[3]]); // 53

    // DNS payload: header + question + 1 A answer (127.0.0.1).
    let mut dns = Vec::new();
    dns.extend_from_slice(id);
    dns.extend_from_slice(&[0x81, 0x80]); // response, AA
    dns.extend_from_slice(&[0x00, 0x01]); // qdcount
    dns.extend_from_slice(&[0x00, 0x01]); // ancount
    dns.extend_from_slice(&[0x00, 0x00]); // nscount
    dns.extend_from_slice(&[0x00, 0x00]); // arcount
    // Question.
    for label in qname.split('.') {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.push(0);
    dns.extend_from_slice(&[0x00, 0x01]); // A
    dns.extend_from_slice(&[0x00, 0x01]); // IN
    // Answer: name pointer to question, A, IN, ttl 60, rdlen 4, 127.0.0.1.
    dns.extend_from_slice(&[0xC0, 0x0C]);
    dns.extend_from_slice(&[0x00, 0x01]);
    dns.extend_from_slice(&[0x00, 0x01]);
    dns.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]);
    dns.extend_from_slice(&[0x00, 0x04]);
    dns.extend_from_slice(&[127, 0, 0, 1]);

    // UDP header.
    let mut udp_out = Vec::new();
    udp_out.extend_from_slice(&dns_port.to_be_bytes());
    udp_out.extend_from_slice(&src_port.to_be_bytes());
    udp_out.extend_from_slice(&((8 + dns.len()) as u16).to_be_bytes());
    udp_out.extend_from_slice(&[0, 0]); // checksum (0 = not computed)
    udp_out.extend_from_slice(&dns);

    // IP header.
    let ip_total = (ihl + udp_out.len()) as u16;
    let mut ip_out = vec![0u8; ihl];
    ip_out[0] = 0x45; // v4, IHL 5 (copy original ihl/4 for options)
    ip_out[0] = 0x40 | (ip_hdr[0] & 0x0f);
    ip_out[1] = 0;
    ip_out[2..4].copy_from_slice(&ip_total.to_be_bytes());
    ip_out[4..6].copy_from_slice(&ip_hdr[4..6]); // id
    ip_out[6..8].copy_from_slice(&ip_hdr[6..8]); // flags/frag
    ip_out[8] = 64; // ttl
    ip_out[9] = 17; // udp
    ip_out[12..16].copy_from_slice(&dst_ip); // src = dns server
    ip_out[16..20].copy_from_slice(&src_ip); // dst = client
    let csum = checksum(&ip_out);
    ip_out[10..12].copy_from_slice(&csum.to_be_bytes());

    // WinDivert header (zeroed, version 6).
    let mut header = vec![0u8; HEADER_LEN];
    header[0..4].copy_from_slice(&WIN_DIVERT_VERSION.to_le_bytes());

    let mut out = Vec::with_capacity(header.len() + ip_out.len() + udp_out.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ip_out);
    out.extend_from_slice(&udp_out);
    Some(out)
}

/// Standard Internet checksum.
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    !sum as u16
}
