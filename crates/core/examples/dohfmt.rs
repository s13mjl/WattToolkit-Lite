//! TEMP: DoH JSON API vs RFC8484 wire format (application/dns-message).
use std::time::Duration;

fn b64url(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut s = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        s.push(T[((n >> 18) & 63) as usize] as char);
        s.push(T[((n >> 12) & 63) as usize] as char);
        if c.len() > 1 { s.push(T[((n >> 6) & 63) as usize] as char) }
        if c.len() > 2 { s.push(T[(n & 63) as usize] as char) }
    }
    s
}

fn dns_query(host: &str) -> Vec<u8> {
    let mut q = vec![0x12u8, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for part in host.split('.') { q.push(part.len() as u8); q.extend_from_slice(part.as_bytes()); }
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    q
}

fn parse_ips(resp: &[u8]) -> Vec<String> {
    let mut ips = Vec::new();
    if resp.len() < 12 { return ips }
    let qd = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let an = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let mut i = 12usize;
    for _ in 0..qd {
        while i < resp.len() && resp[i] != 0 { i += resp[i] as usize + 1 }
        i += 5;
    }
    for _ in 0..an {
        if i + 12 > resp.len() { break }
        if resp[i] & 0xc0 == 0xc0 { i += 2 } else { while i < resp.len() && resp[i] != 0 { i += resp[i] as usize + 1 } i += 1 }
        if i + 10 > resp.len() { break }
        let t = u16::from_be_bytes([resp[i], resp[i + 1]]);
        let rdlen = u16::from_be_bytes([resp[i + 8], resp[i + 9]]) as usize;
        i += 10;
        if t == 1 && rdlen == 4 && i + 4 <= resp.len() {
            ips.push(format!("{}.{}.{}.{}", resp[i], resp[i + 1], resp[i + 2], resp[i + 3]));
        }
        i += rdlen;
    }
    ips
}

fn main() {
    let host = "steamcommunity.com";
    let q = dns_query(host);
    let target = "2.19.198.160/168 (official uses these)";
    println!("target from official proxy: {target}\n");

    // RFC8484 via GET ?dns=<base64url>
    for base in ["https://223.5.5.5/dns-query", "https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"] {
        let url = format!("{base}?dns={}", b64url(&q));
        let body = tokio::task::block_in_place(|| {
            let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(6))).build().into();
            let mut r = match agent.get(&url).header("accept", "application/dns-message").call() { Ok(r) => r, Err(e) => return format!("ERR {e}") };
            match r.body_mut().read_to_vec() { Ok(v) => format!("{:?}", parse_ips(&v)), Err(e) => format!("ERR {e}") }
        });
        println!("  RFC8484 {base:<34} -> {body}");
    }
    // JSON API (what my code currently uses)
    for base in ["https://223.5.5.5/resolve", "https://dns.alidns.com/resolve"] {
        let url = format!("{base}?name={host}&type=A");
        let body = tokio::task::block_in_place(|| {
            let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(6))).build().into();
            let mut r = match agent.get(&url).call() { Ok(r) => r, Err(e) => return format!("ERR {e}") };
            match r.body_mut().read_to_string() { Ok(t) => t.chars().filter(|c| !c.is_whitespace()).collect::<String>(), Err(e) => format!("ERR {e}") }
        });
        println!("  JSON    {base:<34} -> {}", &body[..body.len().min(150)]);
    }
}