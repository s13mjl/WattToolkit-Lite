//! Proxy manager: orchestrates the per-mode listeners, Hosts file edits,
//! system proxy / PAC registry writes, and the WinDivert DNS interceptor.

use crate::cert::CertificateManager;
use crate::fwd::{run_forward_proxy, FwdRuntime};
use crate::hosts;
use crate::mitm::{run_mitm, MitmRuntime};
use crate::model::{AccelerateProjectGroup, ProxyMode};
use crate::settings::ProxySettings;
use crate::sysproxy;
use crate::windivert::DnsInterceptRuntime;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;
use tokio::task::JoinHandle;

/// Per-domain flow statistics.
#[derive(Default)]
pub struct FlowStats {
    pub total_bytes: u64,
    pub by_domain: std::collections::HashMap<String, u64>,
}

/// The proxy manager (mirrors the original ProxyService + ReverseProxy).
#[derive(Clone)]
pub struct ProxyManager {
    inner: Arc<Mutex<Inner>>,
    pub cert: Arc<CertificateManager>,
    /// Sender kept for all proxy log lines.
    log_tx: tokio::sync::mpsc::UnboundedSender<String>,
    /// Receiver taken once by the UI.
    log_rx: Arc<Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<String>>>>,
}

struct Inner {
    running: bool,
    mode: Option<ProxyMode>,
    tasks: Vec<JoinHandle<()>>,
    windivert_stop: Option<Arc<std::sync::atomic::AtomicBool>>,
    log_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    pub stats: Arc<Mutex<FlowStats>>,
    pub config: Arc<RwLock<ProxySettings>>,
    pub domains: Arc<RwLock<HashSet<String>>>,
    pub started_at: Option<SystemTime>,
}

impl ProxyManager {
    pub fn new() -> Self {
        let stats = Arc::new(Mutex::new(FlowStats::default()));
        let config = Arc::new(RwLock::new(ProxySettings::default()));
        let domains = Arc::new(RwLock::new(HashSet::new()));
        let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        Self {
            inner: Arc::new(Mutex::new(Inner {
                running: false,
                mode: None,
                tasks: Vec::new(),
                windivert_stop: None,
                log_tx: None,
                stats,
                config,
                domains,
                started_at: None,
            })),
            cert: Arc::new(CertificateManager::new()),
            log_tx,
            log_rx: Arc::new(Mutex::new(Some(log_rx))),
        }
    }

    pub fn stats(&self) -> Arc<Mutex<FlowStats>> {
        self.inner.lock().unwrap().stats.clone()
    }

    pub fn is_running(&self) -> bool {
        self.inner.lock().unwrap().running
    }

    pub fn current_mode(&self) -> Option<ProxyMode> {
        self.inner.lock().unwrap().mode
    }

    /// The current log sender (cloned for subscribers before start).
    pub fn log_sender(&self) -> Option<tokio::sync::mpsc::UnboundedSender<String>> {
        self.inner.lock().unwrap().log_tx.clone()
    }

    /// Take the log receiver (once) for the UI to drain.
    pub fn take_log_rx(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<String>> {
        self.log_rx.lock().unwrap().take()
    }

    /// Start the proxy in the given mode.
    pub async fn start(
        &self,
        mode: ProxyMode,
        settings: &ProxySettings,
        groups: &[AccelerateProjectGroup],
    ) -> Result<(), String> {
        let mut g = self.inner.lock().unwrap();
        if g.running {
            return Err("proxy already running".into());
        }

        // Compute acceleration domains (listen domains of enabled projects).
        let mut domains = HashSet::new();
        for grp in groups {
            if grp.three_state_enable != Some(true) {
                continue;
            }
            for proj in &grp.items {
                for leaf in proj.all_leaves() {
                    if leaf.three_state_enable == Some(true) {
                        for d in leaf.listen_domain_names.split(';') {
                            let d = d.trim().to_lowercase();
                            if !d.is_empty() {
                                domains.insert(d);
                            }
                        }
                    }
                }
            }
        }
        *g.domains.write().unwrap() = domains.clone();
        *g.config.write().unwrap() = settings.clone();

        let log_tx = self.log_tx.clone();
        g.log_tx = Some(log_tx.clone());
        let stats = g.stats.clone();
        let config = g.config.clone();
        let domains_arc = g.domains.clone();
        let cert = self.cert.clone();

        g.running = true;
        g.mode = Some(mode);
        g.started_at = Some(SystemTime::now());

        drop(g);

        match mode {
            ProxyMode::Hosts => {
                // 1. Ensure root certificate exists.
                let root = cert.root().map_err(|e| {
                    self.stop_inner();
                    e
                })?;
                // 2. Write hosts entries.
                let entries: Vec<(String, String)> = domains
                    .iter()
                    .map(|d| (d.clone(), "127.0.0.1".to_string()))
                    .collect();
                if !entries.is_empty() {
                    if let Err(e) = hosts::update_hosts(&entries) {
                        self.stop_inner();
                        return Err(format!("update hosts failed: {e}"));
                    }
                }
                // 3. Start MITM listener on 443.
                let rt = MitmRuntime {
                    cm: cert.clone(),
                    cache: Arc::new(crate::cert::LeafCache::default()),
                    root: root.clone(),
                    config: config.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                };
                let task = tokio::spawn(async move {
                    let _ = run_mitm(IpAddr::from([127, 0, 0, 1]), rt).await;
                });
                let mut g = self.inner.lock().unwrap();
                g.tasks.push(task);
            }
            ProxyMode::System => {
                let ip: IpAddr = "0.0.0.0".parse().unwrap();
                let bind: SocketAddr = (ip, settings.system_proxy_port).into();
                let rt = FwdRuntime {
                    config: config.clone(),
                    domains: domains_arc.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                };
                let task = tokio::spawn(async move {
                    let _ = run_forward_proxy(bind, rt).await;
                });
                // Set the Windows system proxy (no elevation needed, HKCU).
                if let Err(e) = sysproxy::set_system_proxy(true, "127.0.0.1", settings.system_proxy_port) {
                    let mut g = self.inner.lock().unwrap();
                    g.running = false;
                    g.tasks.push(task);
                    return Err(format!("set system proxy failed: {e}"));
                }
                let mut g = self.inner.lock().unwrap();
                g.tasks.push(task);
            }
            ProxyMode::Pac => {
                let ip: IpAddr = "0.0.0.0".parse().unwrap();
                let bind: SocketAddr = (ip, settings.system_proxy_port).into();
                let rt = FwdRuntime {
                    config: config.clone(),
                    domains: domains_arc.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                };
                let task = tokio::spawn(async move {
                    let _ = run_forward_proxy(bind, rt).await;
                });
                let pac_url = format!(
                    "http://127.0.0.1:{}/proxy.pac",
                    settings.system_proxy_port
                );
                if let Err(e) = sysproxy::set_pac_proxy(true, &pac_url) {
                    let mut g = self.inner.lock().unwrap();
                    g.running = false;
                    g.tasks.push(task);
                    return Err(format!("set PAC proxy failed: {e}"));
                }
                let mut g = self.inner.lock().unwrap();
                g.tasks.push(task);
            }
            ProxyMode::DnsIntercept => {
                // Start the forward proxy to receive redirected traffic.
                let ip: IpAddr = "0.0.0.0".parse().unwrap();
                let bind: SocketAddr = (ip, settings.system_proxy_port).into();
                let rt = FwdRuntime {
                    config: config.clone(),
                    domains: domains_arc.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                };
                let task = tokio::spawn(async move {
                    let _ = run_forward_proxy(bind, rt).await;
                });
                // Start the WinDivert DNS interceptor on a blocking thread.
                let wd = Arc::new(DnsInterceptRuntime::new(
                    domains_arc.clone(),
                    log_tx.clone(),
                ));
                let stop_flag = wd.stop_flag();
                tokio::task::spawn_blocking({
                    let wd = wd.clone();
                    move || wd.run()
                });
                let mut g = self.inner.lock().unwrap();
                g.tasks.push(task);
                g.windivert_stop = Some(stop_flag);
            }
        }
        Ok(())
    }

    /// Stop the proxy and clean up any side effects.
    pub fn stop(&self) {
        let (mode, _) = {
            let g = self.inner.lock().unwrap();
            (g.mode, g.running)
        };
        self.stop_inner();
        // Clean up per-mode side effects.
        match mode {
            Some(ProxyMode::Hosts) => {
                let _ = hosts::remove_by_tag();
            }
            Some(ProxyMode::System) => {
                let _ = sysproxy::set_system_proxy(false, "", 0);
            }
            Some(ProxyMode::Pac) => {
                let _ = sysproxy::set_pac_proxy(false, "");
            }
            _ => {}
        }
    }

    fn stop_inner(&self) {
        let mut g = self.inner.lock().unwrap();
        if let Some(f) = g.windivert_stop.take() {
            f.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        for t in g.tasks.drain(..) {
            t.abort();
        }
        g.log_tx = None;
        g.running = false;
        g.mode = None;
        g.started_at = None;
    }
}

impl Default for ProxyManager {
    fn default() -> Self {
        Self::new()
    }
}
