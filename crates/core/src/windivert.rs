//! WinDivert DNS interception — mirrors the original DnsInterceptor.cs
//! (FastGithub-style): intercept UDP/53, rewrite the payload in place to answer
//! with the loopback address, swap IP/UDP addresses, then send the same packet
//! back. The DNS cache is flushed on start/stop so the OS actually re-queries.

use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use libloading::{Library, Symbol};

type WinDivertOpenFn = unsafe extern "system" fn(*const i8, u32, i32, u64) -> *mut c_void;
// WinDivert 1.4 ABI (proved by probe): (handle, pPacket, packetLen, pAddr, pLen).
// The address struct comes BEFORE the length out-parameter.
type WinDivertRecvFn = unsafe extern "system" fn(
    *mut c_void,   // handle
    *mut u8,       // pPacket (raw packet data)
    u32,           // packetLen (buffer size)
    *mut u8,       // pAddr (WINDIVERT_ADDRESS)
    *mut u32,      // pRecvLen [out]
) -> i32;
type WinDivertSendFn = unsafe extern "system" fn(
    *mut c_void,   // handle
    *const u8,     // pPacket
    u32,           // packetLen
    *const u8,     // pAddr
    *mut u32,      // pSendLen [out]
) -> i32;
type WinDivertCloseFn = unsafe extern "system" fn(*mut c_void);
type WinDivertCalcChecksumsFn = unsafe extern "system" fn(
    *mut u8,
    u32,
    *const u8,
    u64,
) -> i32;

/// The original uses "udp.DstPort == 53" (no direction): the packet is modified
/// in place and sent back, so both directions are captured.
// Our own DNS lookups bind source port 53453 (see dns::OURS_DNS_SRC_PORT);
// exclude it so the hook never answers our own queries with 127.0.0.1.
const DNS_FILTER: &str = "udp.DstPort == 53 and udp.SrcPort != 53453";
const LAYER_NETWORK: u32 = 0;
/// WINDIVERT_ADDRESS layout: byte 8 = Layer(4b)+Event(4b); byte 9 = flags
/// (Sniffed=0x01, Outbound=0x02, Loopback=0x04, Impostor=0x08, IPv6=0x10, ...).
/// Mirrors WinDivertSharp's WinDivertAddress marshalled struct exactly.
const FLAG_OUTBOUND: u8 = 0x02;
const FLAG_LOOPBACK: u8 = 0x04;
const FLAG_IMPOSTOR: u8 = 0x08;
const ADDR_FLAGS_OFF: usize = 9;

#[link(name = "dnsapi")]
extern "system" {
    fn DnsFlushResolverCache();
}
#[link(name = "kernel32")]
extern "system" {
    fn GetLastError() -> u32;
}

pub struct DnsInterceptRuntime {
    pub domains: Arc<RwLock<HashSet<String>>>,
    pub log_tx: tokio::sync::mpsc::UnboundedSender<String>,
    stop: Arc<AtomicBool>,
}

impl DnsInterceptRuntime {
    pub fn new(
        domains: Arc<RwLock<HashSet<String>>>,
        log_tx: tokio::sync::mpsc::UnboundedSender<String>,
    ) -> Self {
        Self { domains, log_tx, stop: Arc::new(AtomicBool::new(false)) }
    }

    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        self.stop.clone()
    }

    fn send_log(&self, msg: String) {
        log::info!(target: "wtlite_core::proxy", "{msg}");
        let _ = self.log_tx.send(msg);
    }

    pub fn run(self: &Arc<Self>) {
        let lib = match unsafe { Library::new("WinDivert.dll") } {
            Ok(l) => l,
            Err(e) => {
                self.send_log(format!("[WinDivert] WinDivert.dll not found: {e}. DNS 拦截不可用。"));
                return;
            }
        };
        let open: Symbol<WinDivertOpenFn> = match unsafe { lib.get(b"WinDivertOpen") } {
            Ok(s) => s,
            Err(e) => { self.send_log(format!("[WinDivert] WinDivertOpen symbol missing: {e}")); return; }
        };
        let recv: Symbol<WinDivertRecvFn> = match unsafe { lib.get(b"WinDivertRecv") } {
            Ok(s) => s,
            Err(e) => { self.send_log(format!("[WinDivert] WinDivertRecv symbol missing: {e}")); return; }
        };
        let send: Symbol<WinDivertSendFn> = match unsafe { lib.get(b"WinDivertSend") } {
            Ok(s) => s,
            Err(e) => { self.send_log(format!("[WinDivert] WinDivertSend symbol missing: {e}")); return; }
        };
        let close: Symbol<WinDivertCloseFn> = match unsafe { lib.get(b"WinDivertClose") } {
            Ok(s) => s,
            Err(e) => { self.send_log(format!("[WinDivert] WinDivertClose symbol missing: {e}")); return; }
        };
        let calc_checksums: Symbol<WinDivertCalcChecksumsFn> = match unsafe { lib.get(b"WinDivertHelperCalcChecksums") } {
            Ok(s) => s,
            Err(e) => { self.send_log(format!("[WinDivert] WinDivertHelperCalcChecksums symbol missing: {e}")); return; }
        };

        // The original pre-loads the driver with "false" because the first load
        // often throws; doing it here keeps the real open clean.
        unsafe {
            let pre = std::ffi::CString::new("false").unwrap();
            let h = open(pre.as_ptr(), LAYER_NETWORK, 0, 0);
            if !(h.is_null() || (h as isize) == -1) {
                close(h);
            }
        }

        let filter = match std::ffi::CString::new(DNS_FILTER) { Ok(f) => f, Err(_) => return };
        let handle = unsafe { open(filter.as_ptr(), LAYER_NETWORK, 0, 0) };
        if handle.is_null() || (handle as isize) == -1 {
            let err = unsafe { GetLastError() };
            self.send_log(format!(
                "[WinDivert] WinDivertOpen 失败 GetLastError={err:#x} (需要管理员权限 / WinDivert 驱动未安装)"
            ));
            return;
        }
        self.send_log("[WinDivert] DNS 拦截已启动".to_string());
        unsafe { DnsFlushResolverCache() };

        let mut buf = vec![0u8; 65535];
        let mut addr = vec![0u8; 64];
        let mut len: u32 = 0;

        while !self.stop.load(Ordering::Relaxed) {
            let ok = unsafe { recv(handle, buf.as_mut_ptr(), buf.len() as u32, addr.as_mut_ptr(), &mut len) };
            if ok == 0 {
                let err = unsafe { GetLastError() };
                self.send_log(format!("[WinDivert] WinDivertRecv 失败 GetLastError={err:#x}"));
                break;
            }
            let n = len as usize;
            if n == 0 || n > buf.len() {
                continue;
            }
            // Modify in place (mirrors ModifyDnsPacket).
            // Pass the whole buffer (not a slice trimmed to the packet length):
            // the DNS response is longer than the query, so it must be able to
            // grow into the spare room.
            let intercepted = match modify_dns_packet(&mut buf, &mut len, &mut addr, &self.domains.read().unwrap()) {
                Some(domain) => {
                    // Mirror the original: recompute all checksums after rewriting.
                    // WinDivertSharp: All = 0 (calculate everything); 0xF would skip all.
                    unsafe {
                        calc_checksums(buf.as_mut_ptr(), len, addr.as_ptr(), 0);
                    }
                    self.send_log(format!(
                        "[DNS] 拦截 {domain} -> 127.0.0.1 | len={} addr[8..16]={:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
                        len,
                        addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], addr[14], addr[15]
                    ));
                    true
                }
                None => {
                    // Diagnostic: name the query so we can see what traffic reaches the hook.
                    match peek_query_name(&buf[..len as usize]) {
                        Some(qname) => self.send_log(format!("[DNS] 放行 {qname}")),
                        None => self.send_log(format!("[DNS] 收到非DNS包 len={}", len)),
                    }
                    false
                }
            };
            let _ = intercepted;
            unsafe {
                let mut sent: u32 = 0;
                let r = send(handle, buf.as_ptr(), len, addr.as_ptr(), &mut sent);
                if r == 0 {
                    let err = unsafe { GetLastError() };
                    self.send_log(format!("[WinDivert] WinDivertSend 失败 GetLastError={err:#x}"));
                }
            }
        }
        unsafe { close(handle); DnsFlushResolverCache() };
        self.send_log("[WinDivert] DNS 拦截已停止".to_string());
    }
}

/// Rewrite a DNS query packet in place so it becomes a response pointing at the
/// loopback address. Returns the intercepted domain when rewritten.
/// Test-only entry point so the rewrite logic can be checked without a driver.
pub fn windivert_modify_dns_packet(
    packet: &mut [u8],
    len: &mut u32,
    addr: &mut [u8],
    domains: &HashSet<String>,
) -> Option<String> {
    modify_dns_packet(packet, len, addr, domains)
}

fn modify_dns_packet(
    packet: &mut [u8],
    len: &mut u32,
    addr: &mut [u8],
    domains: &HashSet<String>,
) -> Option<String> {
    let n = *len as usize;
    if n < 28 || packet[0] >> 4 != 4 {
        return None; // IPv4 only (matches the original's main path)
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if packet[9] != 17 || n < ihl + 8 + 12 {
        return None;
    }
    let udp = ihl;
    let dns = ihl + 8;
    // Only answer standard queries.
    if packet[dns + 2] & 0x80 != 0 {
        return None;
    }
    // Parse the question name.
    let mut i = dns + 12;
    let mut labels: Vec<String> = Vec::new();
    while i < n {
        let l = packet[i] as usize;
        if l == 0 { i += 1; break; }
        i += 1;
        if i + l > n { return None; }
        labels.push(String::from_utf8_lossy(&packet[i..i + l]).to_string());
        i += l;
    }
    if labels.is_empty() || i + 4 > n { return None; }
    let qtype = u16::from_be_bytes([packet[i], packet[i + 1]]);
    if qtype != 1 && qtype != 28 { return None; } // A / AAAA
    let qend = i + 4;
    let domain = labels.join(".");
    let dl = domain.to_lowercase();
    // `*.x.com` patterns must cover sub-domains too, mirroring the proxy
    // matcher (`domain_matches`); bare hostnames keep the suffix rule.
    let matched = domains.iter().any(|d| {
        let d = d.trim().to_lowercase();
        let base = d.strip_prefix("*.").unwrap_or(&d);
        !base.is_empty() && (dl == base || dl.ends_with(&format!(".{base}")))
    });
    if !matched {
        return None;
    }

    // Build the response payload: header + question, plus one answer record for an
    // A query. An AAAA query is answered with an empty NOERROR response (NODATA)
    // instead of `::1`: the 443 listener has no IPv6 socket, so `::1` would be a
    // dead end, while passing the query through would defeat the interception. The
    // cost of that rule is that a v6-only client is pushed back to v4.
    let mut resp = Vec::new();
    resp.extend_from_slice(&packet[dns..dns + 2]); // transaction id
    resp.extend_from_slice(&[0x81, 0x80]);         // response, recursion available
    resp.extend_from_slice(&[0x00, 0x01]);         // qdcount
    let ancount: [u8; 2] = if qtype == 1 { [0x00, 0x01] } else { [0x00, 0x00] };
    resp.extend_from_slice(&ancount);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&[0x00, 0x00]);
    resp.extend_from_slice(&packet[dns + 12..qend]); // question
    if qtype == 1 {
        resp.extend_from_slice(&[0xC0, 0x0C]);          // name pointer
        resp.extend_from_slice(&qtype.to_be_bytes());
        resp.extend_from_slice(&[0x00, 0x01]);          // class IN
        resp.extend_from_slice(&300u32.to_be_bytes());  // ttl 5 min (original)
        resp.extend_from_slice(&4u16.to_be_bytes());    // rdlength
        resp.extend_from_slice(&[127, 0, 0, 1]);        // 127.0.0.1
    }

    if dns + resp.len() > packet.len() { return None; }
    packet[dns..dns + resp.len()].copy_from_slice(&resp);
    let new_len = dns + resp.len();
    *len = new_len as u32;

    // Swap IPv4 src/dst and fix the total length.
    let mut src = [0u8; 4];
    let mut dst = [0u8; 4];
    src.copy_from_slice(&packet[12..16]);
    dst.copy_from_slice(&packet[16..20]);
    packet[12..16].copy_from_slice(&dst);
    packet[16..20].copy_from_slice(&src);
    packet[2..4].copy_from_slice(&(new_len as u16).to_be_bytes());
    packet[10..12].copy_from_slice(&[0, 0]);
    let csum = ip_checksum(&packet[..ihl]);
    packet[10..12].copy_from_slice(&csum.to_be_bytes());

    // Swap UDP ports and fix the length (checksum 0 = not computed, valid IPv4).
    let sp = [packet[udp], packet[udp + 1]];
    packet[udp] = packet[udp + 2];
    packet[udp + 1] = packet[udp + 3];
    packet[udp + 2] = sp[0];
    packet[udp + 3] = sp[1];
    packet[udp + 4..udp + 6].copy_from_slice(&(resp.len() as u16 + 8).to_be_bytes());
    packet[udp + 6..udp + 8].copy_from_slice(&[0, 0]);

    // Mark as impostor and set the direction like the original
    // (WinDivertSharp: winDivertAddress.Impostor = true;
    //  Direction = Loopback ? Outbound : Inbound).
    if addr.len() > ADDR_FLAGS_OFF {
        let flags = addr[ADDR_FLAGS_OFF];
        addr[ADDR_FLAGS_OFF] = flags | FLAG_IMPOSTOR;
        if flags & FLAG_LOOPBACK != 0 {
            addr[ADDR_FLAGS_OFF] |= FLAG_OUTBOUND;
        } else {
            addr[ADDR_FLAGS_OFF] &= !FLAG_OUTBOUND;
        }
    }
    Some(domain)
}

/// Read-only query-name peek for diagnostics (returns None for non-DNS).
fn peek_query_name(packet: &[u8]) -> Option<String> {
    let n = packet.len();
    if n < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    let dns = ihl + 8;
    if n < dns + 14 || packet[dns + 2] & 0x80 != 0 {
        return None;
    }
    let mut i = dns + 12;
    let mut labels = Vec::new();
    while i < n {
        let l = packet[i] as usize;
        if l == 0 {
            break;
        }
        i += 1;
        if i + l > n {
            return None;
        }
        labels.push(String::from_utf8_lossy(&packet[i..i + l]).to_string());
        i += l;
    }
    if labels.is_empty() {
        return None;
    }
    Some(labels.join("."))
}

fn ip_checksum(data: &[u8]) -> u16 {
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
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An IPv4 + UDP DNS query for `name` of type `qtype`, laid out like a captured
    /// packet. The returned length is the packet length; the buffer has spare room
    /// behind it, exactly like the receive buffer the hook rewrites in place.
    fn dns_query(name: &str, qtype: u16) -> (Vec<u8>, u32, Vec<u8>) {
        let mut question = Vec::new();
        for label in name.split('.') {
            question.push(label.len() as u8);
            question.extend_from_slice(label.as_bytes());
        }
        question.push(0);
        question.extend_from_slice(&qtype.to_be_bytes());
        question.extend_from_slice(&1u16.to_be_bytes()); // class IN

        let udp_len = 8 + 12 + question.len();
        let total = 20 + udp_len;
        let mut packet = vec![0u8; total + 512];
        packet[0] = 0x45; // IPv4, 5-word header
        packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        packet[8] = 64; // ttl
        packet[9] = 17; // UDP
        packet[12..16].copy_from_slice(&[192, 168, 0, 2]); // source address
        packet[16..20].copy_from_slice(&[8, 8, 8, 8]); // destination address
        let udp = 20;
        packet[udp..udp + 2].copy_from_slice(&51000u16.to_be_bytes()); // source port
        packet[udp + 2..udp + 4].copy_from_slice(&53u16.to_be_bytes()); // destination
        packet[udp + 4..udp + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        let dns = udp + 8;
        packet[dns..dns + 2].copy_from_slice(&0x1234u16.to_be_bytes()); // transaction id
        packet[dns + 2..dns + 4].copy_from_slice(&[0x01, 0x00]); // standard query, RD
        packet[dns + 4..dns + 6].copy_from_slice(&1u16.to_be_bytes()); // qdcount
        packet[dns + 12..dns + 12 + question.len()].copy_from_slice(&question);
        (packet, total as u32, vec![0u8; 64])
    }

    fn intercept_set() -> HashSet<String> {
        ["*.steamcommunity.com".to_string()].into_iter().collect()
    }

    #[test]
    fn an_a_query_is_answered_with_the_loopback_address() {
        let domains = intercept_set();
        let (mut packet, mut len, mut addr) = dns_query("store.steamcommunity.com", 1);
        assert_eq!(
            windivert_modify_dns_packet(&mut packet, &mut len, &mut addr, &domains).as_deref(),
            Some("store.steamcommunity.com")
        );
        let payload = &packet[28..len as usize];
        assert_eq!(&payload[2..4], &[0x81, 0x80]); // NOERROR response, RA set
        assert_eq!(&payload[6..8], &[0x00, 0x01]); // ancount = 1
        assert_eq!(&payload[payload.len() - 4..], &[127, 0, 0, 1]); // the A record
    }

    #[test]
    fn an_aaaa_query_is_answered_with_nodata() {
        let domains = intercept_set();
        let (mut packet, query_len, mut addr) = dns_query("store.steamcommunity.com", 28);
        let mut len = query_len;
        assert_eq!(
            windivert_modify_dns_packet(&mut packet, &mut len, &mut addr, &domains).as_deref(),
            Some("store.steamcommunity.com")
        );
        let payload = &packet[28..len as usize];
        assert_eq!(&payload[2..4], &[0x81, 0x80]); // NOERROR response, RA set
        assert_eq!(&payload[6..8], &[0x00, 0x00]); // ancount = 0: NODATA, not `::1`
        assert_eq!(&payload[8..12], &[0x00, 0x00, 0x00, 0x00]); // no authority/additional
        // The empty answer is exactly the question echoed back, so the rewritten
        // length matches the query it replaced.
        assert_eq!(len, query_len);
    }

    #[test]
    fn a_query_outside_the_intercept_set_is_left_alone() {
        let domains = intercept_set();
        let (mut packet, mut len, mut addr) = dns_query("example.test", 1);
        let before = packet.clone();
        let before_len = len;
        assert_eq!(
            windivert_modify_dns_packet(&mut packet, &mut len, &mut addr, &domains),
            None
        );
        assert_eq!(packet, before);
        assert_eq!(len, before_len);
    }
}
