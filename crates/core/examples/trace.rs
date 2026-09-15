//! TEMP: trace my proxy's resolution + connection for the disputed domain.
use std::time::{Duration, Instant};

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let host = "steamcommunity.com";
    let settings = wtlite_core::settings::Settings::load();
    let s = &settings.proxy;
    println!("config: use_doh={} doh=[{}] master_dns={}", s.use_doh, s.custom_doh_address, s.proxy_master_dns);
    let t = Instant::now();
    let ips = wtlite_core::dns::resolve_a(host, &s.proxy_master_dns, s.use_doh, &s.custom_doh_address).await;
    println!("resolve_a -> {:?}  ({} ms)", ips.iter().map(|i| i.to_string()).collect::<Vec<_>>(), t.elapsed().as_millis());
    for ip in &ips {
        let a = std::net::SocketAddr::new(*ip, 443);
        let tt = Instant::now();
        let ok = matches!(tokio::time::timeout(Duration::from_secs(6), tokio::net::TcpStream::connect(a)).await, Ok(Ok(_)));
        println!("  connect {a} -> {} ({} ms)", if ok { "OK" } else { "FAIL" }, tt.elapsed().as_millis());
    }
    // also: does the Akamai IP work from here?
    for ip in ["2.19.198.160", "2.19.198.168"] {
        let a: std::net::SocketAddr = format!("{ip}:443").parse().unwrap();
        let ok = matches!(tokio::time::timeout(Duration::from_secs(6), tokio::net::TcpStream::connect(a)).await, Ok(Ok(_)));
        println!("  akamai {a} -> {}", if ok { "OK" } else { "FAIL" });
    }
}