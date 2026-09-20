//! Proxy manager: orchestrates the per-mode listeners, Hosts file edits,
//! system proxy / PAC registry writes, and the WinDivert DNS interceptor.

use crate::cert::CertificateManager;
use crate::fwd::{run_forward_proxy_on, FwdRuntime};
use crate::hosts;
use crate::mitm::{run_mitm_on, MitmRuntime};
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
    /// Runtime owned by the manager. It must outlive `start()`: the listeners
    /// are `tokio::spawn`ed tasks, so dropping the caller's temporary runtime
    /// would silently cancel every listener (UI shows "running" while nothing
    /// is actually bound).
    runtime: Option<Arc<tokio::runtime::Runtime>>,
    tasks: Vec<JoinHandle<()>>,
    windivert_stop: Option<Arc<std::sync::atomic::AtomicBool>>,
    log_tx: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    pub stats: Arc<Mutex<FlowStats>>,
    pub config: Arc<RwLock<ProxySettings>>,
    pub domains: Arc<RwLock<HashSet<String>>>,
    /// Blocked host -> reachable substitute hostname to dial upstream
    /// (the original `ForwardDestination`/`TlsSni` mechanism).
    pub forward: Arc<RwLock<std::collections::HashMap<String, String>>>,
    pub started_at: Option<SystemTime>,
}

impl ProxyManager {
    pub fn new() -> Self {
        let stats = Arc::new(Mutex::new(FlowStats::default()));
        let config = Arc::new(RwLock::new(ProxySettings::default()));
        let domains = Arc::new(RwLock::new(HashSet::new()));
        let forward = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let (log_tx, log_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        Self {
            inner: Arc::new(Mutex::new(Inner {
                running: false,
                mode: None,
                runtime: None,
                tasks: Vec::new(),
                windivert_stop: None,
                log_tx: None,
                stats,
                config,
                domains,
                forward,
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

    /// Start the proxy on a runtime owned by this manager.
    ///
    /// This is the entry point used by the UI. The spawned listener tasks need
    /// a runtime that outlives the call, otherwise they are cancelled the moment
    /// the caller's temporary runtime is dropped.
    pub fn start_blocking(
        &self,
        mode: ProxyMode,
        settings: &ProxySettings,
        groups: &[AccelerateProjectGroup],
    ) -> Result<(), String> {
        let rt = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|e| format!("create tokio runtime failed: {e}"))?,
        );
        {
            let mut g = self.inner.lock().unwrap();
            g.runtime = Some(rt.clone());
        }
        let res = rt.block_on(async { self.start(mode, settings, groups).await });
        if res.is_err() {
            // Roll back: drop the runtime and its listeners.
            let mut g = self.inner.lock().unwrap();
            g.runtime = None;
        }
        res
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
                            // `*.example.com` matches the bare domain and every
                            // subdomain: strip the wildcard so the matcher's
                            // `ends_with(".<domain>")` rule covers both (official
                            // data uses `*.st.dl.eccdnx.com`, `*.steamcommunity.com`).
                            let d = d.strip_prefix("*.").unwrap_or(&d).to_string();
                            if !d.is_empty() {
                                domains.insert(d);
                            }
                        }
                    }
                }
            }
        }
        // Blocked host -> reachable substitute hostname (original
        // `ForwardDestination` + `TlsSni`). Mirrors the official data, where
        // sites are aliased onto their CDN hostnames.
        let mut forward: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for grp in groups {
            if grp.three_state_enable != Some(true) {
                continue;
            }
            for proj in &grp.items {
                for leaf in proj.all_leaves() {
                    if leaf.three_state_enable != Some(true) {
                        continue;
                    }
                    if let Some(fwd) = &leaf.forward_domain_names {
                        for host in leaf.listen_domain_names.split(';') {
                            let host = host.trim().to_lowercase();
                            if !host.is_empty() && !fwd.trim().is_empty() {
                                forward.insert(host, fwd.trim().to_lowercase());
                            }
                        }
                    }
                }
            }
        }
        // Forward targets are connect aliases, not intercept entries: they
        // must resolve to their real IPs for the MITM upstream, so keep them
        // out of the interception set (otherwise the hook would answer them
        // with 127.0.0.1 and the proxy would connect to itself).
        for target in forward.values() {
            domains.remove(target);
        }
        *g.domains.write().unwrap() = domains.clone();
        *g.forward.write().unwrap() = forward.clone();
        *g.config.write().unwrap() = settings.clone();
        log::info!(
            target: "wtlite_core::proxy",
            "starting proxy: mode={mode:?} port={} domains={} forward={}",
            settings.system_proxy_port,
            domains.len(),
            forward.len()
        );
        if domains.is_empty() {
            log::warn!(
                target: "wtlite_core::proxy",
                "no acceleration domains selected - the PAC will proxy nothing"
            );
        }

        let log_tx = self.log_tx.clone();
        g.log_tx = Some(log_tx.clone());
        let stats = g.stats.clone();
        let config = g.config.clone();
        let domains_arc = g.domains.clone();
        let forward_arc = g.forward.clone();
        let cert = self.cert.clone();
        // Root cert is needed by the MITM path (Hosts + DnsIntercept modes).
        let root_for_mitm = cert.root().ok();


        g.running = true;
        g.mode = Some(mode);
        g.started_at = Some(SystemTime::now());

        drop(g);

        // Shared TLS-termination runtime for the forward-proxy modes: a CONNECT
        // for a host that needs a substitute upstream hostname is decrypted here
        // (mirrors the original, whose proxy always terminates TLS with its own
        // certificate). Missing root cert just disables substitution.
        let mitm_rt: Option<Arc<MitmRuntime>> = if mode == ProxyMode::Hosts {
            None
        } else {
            cert.root().ok().map(|root| {
                Arc::new(MitmRuntime {
                    cm: cert.clone(),
                    cache: Arc::new(crate::cert::LeafCache::default()),
                    root,
                    config: config.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                    forward: forward_arc.clone(),
                    domains: domains_arc.clone(),
                })
            })
        };

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
                // 3. Start MITM listener on 443 (bind first so failures surface).
                let mitm_bind: SocketAddr =
                    (IpAddr::from([127, 0, 0, 1]), 443u16).into();
                let mitm_listener = match tokio::net::TcpListener::bind(mitm_bind).await {
                    Ok(l) => l,
                    Err(e) => {
                        self.stop_inner();
                        let _ = hosts::remove_by_tag();
                        return Err(format!(
                            "端口 443 被占用或无法绑定（可能需要管理员权限）: {e}"
                        ));
                    }
                };
                let rt = MitmRuntime {
                    cm: cert.clone(),
                    cache: Arc::new(crate::cert::LeafCache::default()),
                    root: root.clone(),
                    config: config.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                    forward: forward_arc.clone(),
                    domains: domains_arc.clone(),
                };
                let task = tokio::spawn(async move {
                    let _ = run_mitm_on(mitm_listener, rt).await;
                });
                let mut g = self.inner.lock().unwrap();
                g.tasks.push(task);
            }
            ProxyMode::System => {
                let ip: IpAddr = "0.0.0.0".parse().unwrap();
                let bind: SocketAddr = (ip, settings.system_proxy_port).into();
                let listener = match tokio::net::TcpListener::bind(bind).await {
                    Ok(l) => l,
                    Err(e) => {
                        self.stop_inner();
                        return Err(format!(
                            "端口 {} 被占用或无法绑定，请检查是否已有其他程序在监听: {e}",
                            settings.system_proxy_port
                        ));
                    }
                };
                let rt = FwdRuntime {
                    config: config.clone(),
                    domains: domains_arc.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                    mitm: mitm_rt.clone(),
                    forward: forward_arc.clone(),
                };
                let task = tokio::spawn(async move {
                    let _ = run_forward_proxy_on(listener, rt).await;
                });
                // Set the Windows system proxy (no elevation needed, HKCU).
                if let Err(e) = sysproxy::set_system_proxy(true, "127.0.0.1", settings.system_proxy_port) {
                    let mut g = self.inner.lock().unwrap();
                    g.running = false;
                    g.tasks.push(task);
                    return Err(format!("set system proxy failed: {e}"));
                }
                log::info!(
                    target: "wtlite_core::proxy",
                    "system proxy = 127.0.0.1:{}",
                    settings.system_proxy_port
                );
                log::info!(
                    target: "wtlite_core::proxy",
                    "WinINET sees: {}",
                    sysproxy::describe_effective_proxy()
                );
                let mut g = self.inner.lock().unwrap();
                g.tasks.push(task);
            }
            ProxyMode::Pac => {
                let ip: IpAddr = "0.0.0.0".parse().unwrap();
                let bind: SocketAddr = (ip, settings.system_proxy_port).into();
                let listener = match tokio::net::TcpListener::bind(bind).await {
                    Ok(l) => l,
                    Err(e) => {
                        self.stop_inner();
                        return Err(format!(
                            "端口 {} 被占用或无法绑定，请检查是否已有其他程序在监听: {e}",
                            settings.system_proxy_port
                        ));
                    }
                };
                let rt = FwdRuntime {
                    config: config.clone(),
                    domains: domains_arc.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                    mitm: mitm_rt.clone(),
                    forward: forward_arc.clone(),
                };
                let task = tokio::spawn(async move {
                    let _ = run_forward_proxy_on(listener, rt).await;
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
                log::info!(
                    target: "wtlite_core::proxy",
                    "AutoConfigURL = {pac_url}"
                );
                log::info!(
                    target: "wtlite_core::proxy",
                    "WinINET sees: {}",
                    sysproxy::describe_effective_proxy()
                );
                let mut g = self.inner.lock().unwrap();
                g.tasks.push(task);
            }
            ProxyMode::DnsIntercept => {
                // DNS interception steers accelerated domains to 127.0.0.1, so a
                // MITM listener on 443 is required to handle that traffic
                // (mirrors the original, which starts both a MITM and a forward
                // proxy in DNSIntercept mode).
                let mitm_bind: SocketAddr = (IpAddr::from([127, 0, 0, 1]), 443u16).into();
                let mitm_listener = match tokio::net::TcpListener::bind(mitm_bind).await {
                    Ok(l) => l,
                    Err(e) => {
                        self.stop_inner();
                        return Err(format!(
                            "端口 443 被占用或无法绑定（可能需要管理员权限）: {e}"
                        ));
                    }
                };
                // Forward proxy on the configured port for non-accelerated HTTP.
                let ip: IpAddr = "0.0.0.0".parse().unwrap();
                let fwd_bind: SocketAddr = (ip, settings.system_proxy_port).into();
                let fwd_listener = match tokio::net::TcpListener::bind(fwd_bind).await {
                    Ok(l) => l,
                    Err(e) => {
                        self.stop_inner();
                        return Err(format!(
                            "端口 {} 被占用或无法绑定: {e}",
                            settings.system_proxy_port
                        ));
                    }
                };
                // The interceptor owns UDP:53, so the MITM's own upstream lookup
                // must go through DoH — a plain UDP query would be intercepted back
                // to 127.0.0.1 and the proxy would connect to itself.
                let mut intercept_cfg = config.read().unwrap().clone();
                intercept_cfg.use_doh = true;
                let intercept_cfg = Arc::new(RwLock::new(intercept_cfg));
                let rt = MitmRuntime {
                    cm: cert.clone(),
                    cache: Arc::new(crate::cert::LeafCache::default()),
                    root: root_for_mitm.clone().unwrap_or_else(|| Arc::new(crate::cert::RootCertificate {
                        der: Vec::new(),
                        key_pkcs8: Vec::new(),
                        not_after: std::time::SystemTime::UNIX_EPOCH,
                    })),
                    config: intercept_cfg.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                    forward: forward_arc.clone(),
                    domains: domains_arc.clone(),
                };
                let fwd_rt = FwdRuntime {
                    config: intercept_cfg,
                    domains: domains_arc.clone(),
                    stats: stats.clone(),
                    log_tx: log_tx.clone(),
                    mitm: mitm_rt.clone(),
                    forward: forward_arc.clone(),
                };
                let task_mitm = tokio::spawn(async move {
                    let _ = run_mitm_on(mitm_listener, rt).await;
                });
                let task_fwd = tokio::spawn(async move {
                    let _ = run_forward_proxy_on(fwd_listener, fwd_rt).await;
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
                g.tasks.push(task_mitm);
                g.tasks.push(task_fwd);
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
        // Drop the manager-owned runtime so its listeners are released too.
        if let Some(rt) = g.runtime.take() {
            Arc::try_unwrap(rt)
                .map(|rt| rt.shutdown_background())
                .ok();
        }
    }
}

impl Default for ProxyManager {
    fn default() -> Self {
        Self::new()
    }
}
