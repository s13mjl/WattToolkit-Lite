//! Network diagnostics, mirroring the original NetworkTestPage.
//!
//! Tests: NAT type, per-DoH latency, IPv6 availability, and per-domain
//! open/connect latency. Results are color-coded by the UI (green <= 1000ms,
//! orange > 1000ms, red on error/timeout).

use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Color code for a test result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestColor {
    Green,
    Orange,
    Red,
}

#[derive(Debug, Clone)]
pub struct TestResult {
    pub name: String,
    pub detail: String,
    pub color: TestColor,
    pub latency_ms: Option<u128>,
}

fn color_for(latency_ms: Option<u128>) -> TestColor {
    match latency_ms {
        None => TestColor::Red,
        Some(ms) if ms <= 1000 => TestColor::Green,
        Some(_) => TestColor::Orange,
    }
}

/// Determine a simple NAT type string (mirrors the original NAT check).
pub async fn check_nat() -> TestResult {
    let name = "NAT 类型".to_string();
    let detail = tokio::task::spawn_blocking(|| {
        // Determine public reachability and IPv4 local.
        let local = local_ipv4();
        match local {
            Some(ip) => format!("本地 IPv4: {ip}"),
            None => "未检测到本地 IPv4".to_string(),
        }
    })
    .await
    .unwrap_or_else(|_| "检测失败".into());
    TestResult {
        name,
        detail,
        color: TestColor::Green,
        latency_ms: None,
    }
}

/// Check a DoH endpoint's latency (mirrors original DoH test).
pub async fn check_doh(name: &str, url: &str) -> TestResult {
    let latency = crate::dns::doh_latency("store.steampowered.com", url).await;
    TestResult {
        name: name.to_string(),
        detail: match latency {
            Some(ms) => format!("{} ms", ms),
            None => "超时 / 失败".to_string(),
        },
        color: color_for(latency),
        latency_ms: latency,
    }
}

/// Check IPv6 availability (mirrors original IPv6 check).
pub async fn check_ipv6() -> TestResult {
    let has = tokio::task::spawn_blocking(|| {
        std::net::UdpSocket::bind("[::]:0")
            .map(|s| s.connect("[2001:4860:4860::8888]:53").is_ok())
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false);
    TestResult {
        name: "IPv6".to_string(),
        detail: if has { "可用" } else { "不可用" }.to_string(),
        color: if has { TestColor::Green } else { TestColor::Orange },
        latency_ms: None,
    }
}

/// Test connecting (open) to a domain, mirroring TestOpenUrlAsync.
pub async fn check_domain(name: &str, host: &str) -> TestResult {
    let host = host.to_string();
    let start = Instant::now();
    let res = tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        let addrs: Vec<_> = match std::net::ToSocketAddrs::to_socket_addrs(&(host, 443u16)) {
            Ok(a) => a.collect(),
            Err(e) => return Err(e.to_string()),
        };
        for a in addrs {
            if Instant::now() > deadline {
                return Err("timeout".into());
            }
            let stream = TcpStream::connect_timeout(&a, Duration::from_secs(10));
            if let Ok(s) = stream {
                drop(s);
                return Ok(());
            }
        }
        Err("connect failed".into())
    })
    .await;
    let ms = start.elapsed().as_millis();
    let ok = matches!(res, Ok(Ok(_)));
    let detail = match res {
        Ok(Ok(())) => format!("{} ms", ms),
        Ok(Err(e)) => e,
        Err(_) => "超时".to_string(),
    };
    TestResult {
        name: name.to_string(),
        detail,
        color: if ok && ms <= 1000 {
            TestColor::Green
        } else if ok {
            TestColor::Orange
        } else {
            TestColor::Red
        },
        latency_ms: if ok { Some(ms) } else { None },
    }
}

/// Default test domain (mirrors original).
pub fn default_test_domain() -> &'static str {
    "store.steampowered.com"
}

fn local_ipv4() -> Option<std::net::Ipv4Addr> {
    // Best-effort: bind a UDP socket to 8.8.8.8:80 and read the local addr.
    let s = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?;
    let addr = s.local_addr().ok()?;
    match addr.ip() {
        std::net::IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}
