//! TEMP: does any DoH give the Akamai IP the official proxy uses?
use std::time::Duration;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let host = "steamcommunity.com";
    println!("target: 2.19.198.160 / 2.19.198.168 (what the official proxy connects to)");
    println!();
    // 1. all DoH endpoints my code knows
    for d in wtlite_core::dns::doh_addresses() {
        let ips = wtlite_core::dns::resolve_doh(host, d).await;
        let s = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        println!("  doh {d:<40} -> {s}");
    }
    // 2. plain UDP DNS servers
    for s in wtlite_core::dns::dns_servers() {
        if s == "System Default" { continue }
        let ips = wtlite_core::dns::resolve_udp(host, s.parse().ok()).await;
        let t = ips.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        println!("  udp {s:<40} -> {t}");
    }
    // 3. system
    if let Ok(a) = tokio::net::lookup_host((host, 443u16)).await {
        let ips: Vec<String> = a.map(|s| s.ip().to_string()).collect();
        println!("  system                                    -> {}", ips.join(","));
    }
    // 4. is the Akamai IP reachable from here?
    for ip in ["2.19.198.160", "2.19.198.168"] {
        let a: std::net::SocketAddr = format!("{ip}:443").parse().unwrap();
        let ok = matches!(tokio::time::timeout(Duration::from_secs(6), tokio::net::TcpStream::connect(a)).await, Ok(Ok(_)));
        println!("  reach {ip}:443 -> {ok}");
    }
}