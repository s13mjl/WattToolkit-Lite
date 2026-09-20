//! WattToolkit-Lite UI (egui/eframe), mirroring the original Avalonia
//! MainFramePage + SettingsPage + AcceleratorPage2 structure.

mod pages;
#[cfg(windows)]
pub mod win32;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui;
use wtlite_core::model::ProxyMode;
use wtlite_core::{AccelerateService, ProxyManager, Settings};

/// Main window pages.
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum MainTab {
    Accelerator,
    Settings,
}

/// Shared state that can be touched from the tray thread.
pub struct TrayState {
    pub show_window: bool,
    pub exit: bool,
}

/// Global tray state, set by the loader before the app is created.
static TRAY_STATE: std::sync::OnceLock<Arc<Mutex<TrayState>>> = std::sync::OnceLock::new();

/// Set the shared tray state (called by the loader binary).
pub fn set_tray_state(t: Arc<Mutex<TrayState>>) {
    let _ = TRAY_STATE.set(t);
}

/// The running ProxyManager, kept here so the tray thread can stop the proxy
/// before exiting (the UI loop is not guaranteed to run while hidden).
static EXIT_PROXY: std::sync::OnceLock<ProxyManager> = std::sync::OnceLock::new();

/// Register the proxy manager used by [`shutdown`].
pub fn set_exit_proxy(p: ProxyManager) {
    let _ = EXIT_PROXY.set(p);
}

/// Stop the proxy and quit - the tray menu's 退出 action.
pub fn shutdown() -> ! {
    if let Some(p) = EXIT_PROXY.get() {
        p.stop();
    }
    std::process::exit(0);
}



/// Main application.
pub struct App {
    pub settings: Settings,
    pub proxy: ProxyManager,
    pub accel: AccelerateService,
    pub main_tab: MainTab,
    /// Proxy log lines (capped at 1000).
    pub logs: VecDeque<String>,
    pub log_rx: Option<tokio::sync::mpsc::UnboundedReceiver<String>>,
    pub tray: Arc<Mutex<TrayState>>,
    pub proxy_dialog: Option<ProxySettingsDialog>,
    pub cert_dialog: Option<String>,
    pub toast: Option<(String, Instant)>,
    pub accel_loaded: bool,
    /// Window/about icon texture (loaded once from APP_ICON).
    pub icon: Option<egui::TextureHandle>,
    /// True while the window is hidden in the tray (the X button hides instead
    /// of exiting; the tray menu's 退出 is what really quits).
    pub hidden_to_tray: bool,
    /// Set once the Win32 HWND has been captured for direct show/hide control.
    pub hwnd_known: bool,
    /// Frame counter + last heartbeat time (diagnostics for the tray loop).
    pub frames: u64,
    pub last_beat: Option<Instant>,
}

/// Proxy settings dialog state (mirrors ProxySettingsWindow).
#[derive(Clone)]
pub struct ProxySettingsDialog {
    pub mode: ProxyMode,
    pub port: u16,
    pub dns: String,
    pub use_doh: bool,
    pub doh_address: String,
    pub enable_http_to_https: bool,
    pub two_level_enable: bool,
    pub two_level_type: wtlite_core::model::ExternalProxyType,
    pub two_level_ip: String,
    pub two_level_port: u16,
    pub two_level_user: String,
    pub two_level_password: String,
}

impl ProxySettingsDialog {
    pub fn from_settings(s: &wtlite_core::settings::ProxySettings) -> Self {
        Self {
            mode: s.proxy_mode,
            port: s.system_proxy_port,
            dns: s.proxy_master_dns.clone(),
            use_doh: s.use_doh,
            doh_address: s.custom_doh_address.clone(),
            enable_http_to_https: s.enable_http_proxy_to_https,
            two_level_enable: s.two_level_agent_enable,
            two_level_type: s.two_level_agent_type,
            two_level_ip: s.two_level_agent_ip.clone(),
            two_level_port: s.two_level_agent_port,
            two_level_user: s.two_level_agent_user.clone(),
            two_level_password: s.two_level_agent_password.clone(),
        }
    }
}

/// Load a CJK-capable system font (egui's bundled fonts contain no
/// Chinese glyphs, which makes every Chinese label render as blank).
fn setup_fonts(ctx: &egui::Context) {
    const CANDIDATES: [&str; 5] = [
        r"C:\Windows\Fonts\msyh.ttc", // Microsoft YaHei (TTC, index 0)
        r"C:\Windows\Fonts\msyhbd.ttc",
        r"C:\Windows\Fonts\simhei.ttf", // SimHei
        r"C:\Windows\Fonts\simsun.ttc", // SimSun
        r"C:\Windows\Fonts\Deng.ttf",   // DengXian
    ];
    for path in CANDIDATES {
        if let Ok(bytes) = std::fs::read(path) {
            let mut fonts = egui::FontDefinitions::default();
            fonts
                .font_data
                .insert("cjk".to_owned(), egui::FontData::from_owned(bytes));
            fonts
                .families
                .get_mut(&egui::FontFamily::Proportional)
                .unwrap()
                .push("cjk".to_owned());
            fonts
                .families
                .get_mut(&egui::FontFamily::Monospace)
                .unwrap()
                .push("cjk".to_owned());
            ctx.set_fonts(fonts);
            log::info!("UI font loaded: {path}");
            return;
        }
    }
    log::warn!("no CJK font found on this system; Chinese text may not render");
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        setup_fonts(&cc.egui_ctx);
        let settings = Settings::load();
        let proxy = ProxyManager::new();
        let accel = AccelerateService::new();
        let tray = TRAY_STATE
            .get()
            .cloned()
            .unwrap_or_else(|| Arc::new(Mutex::new(TrayState {
                show_window: false,
                exit: false,
            })));
        let ids = settings.proxy.support_proxy_services_status.clone();
        // Attach the proxy log receiver; without this every internal proxy log
        // line (listener start, CONNECT tunnels, errors) is silently dropped.
        let log_rx = proxy.take_log_rx();
        // Let the tray thread stop the proxy when it exits the app.
        set_exit_proxy(proxy.clone());

        let icon = pages::settings_page::APP_ICON
            .clone()
            .map(|img| cc.egui_ctx.load_texture("app_icon", img, egui::TextureOptions::default()));
        let app = Self {
            settings,
            proxy,
            accel,
            main_tab: MainTab::Accelerator,
            logs: VecDeque::with_capacity(1000),
            log_rx,
            tray,
            proxy_dialog: None,
            cert_dialog: None,
            toast: None,
            accel_loaded: false,
            icon,
            hidden_to_tray: false,
            hwnd_known: false,
            frames: 0,
            last_beat: None,
        };
        // Load acceleration projects (local cache or built-in) and restore the
        // enabled state: on first run nothing is checked by default; on later
        // runs the previously saved IDs (support_proxy_services_status) are
        // restored automatically.
        let _ = app.accel.load_sync();
        let enabled = ids; // empty on first run = nothing selected
        app.accel.apply_enabled(&enabled);
        // Collapse all platform groups by default at startup.
        {
            let mut st = crate::pages::GLOBAL_ACC.lock().unwrap();
            for grp in app.accel.groups() {
                st.collapsed.insert(grp.name);
            }
        }
        app
    }

    /// Switch the acceleration mode (persisted). If the proxy is running,
    /// restart it immediately so the new mode takes effect.
    pub fn switch_proxy_mode(&mut self, mode: ProxyMode) {
        if self.settings.proxy.proxy_mode == mode {
            return;
        }
        let was_running = self.proxy.is_running();
        self.settings.proxy.proxy_mode = mode;
        let _ = self.settings.save();
        if was_running {
            self.proxy.stop();
            let groups = self.accel.groups();
            let settings = self.settings.proxy.clone();
            crate::pages::accelerator::start_async(self, mode, settings, groups);
        } else {
            self.set_toast(format!("加速模式: {}", mode.display_name()));
        }
    }

    pub fn push_log(&mut self, line: String) {
        self.logs.push_back(line);
        while self.logs.len() > 1000 {
            self.logs.pop_front();
        }
    }

    pub fn set_toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    /// Drain tray / menu events into the shared state flags.
    fn poll_tray_events(&mut self) {
        let mut t = self.tray.lock().unwrap();
        loop {
            match tray_icon::TrayIconEvent::receiver().try_recv() {
                Ok(tray_icon::TrayIconEvent::Click { button, .. }) => {
                    if button == tray_icon::MouseButton::Left {
                        log::info!("[tray] left click -> show window");
                        t.show_window = true;
                    }
                }
                // Windows-only: double click also restores the window.
                Ok(tray_icon::TrayIconEvent::DoubleClick { button, .. }) => {
                    if button == tray_icon::MouseButton::Left {
                        log::info!("[tray] double click -> show window");
                        t.show_window = true;
                    }
                }
                Ok(other) => {
                    log::debug!("[tray] event: {other:?}");
                }
                Err(_) => break,
            }
        }
        loop {
            match tray_icon::menu::MenuEvent::receiver().try_recv() {
                Ok(ev) => {
                    log::info!("[tray] menu event: {}", ev.id.as_ref());
                    match ev.id.as_ref() {
                        "show" => t.show_window = true,
                        "exit" => t.exit = true,
                        _ => {}
                    }
                }
                Err(_) => break,
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Heartbeat: proves the render loop keeps running while hidden (the tray
        // channels can only be drained from here).
        self.frames = self.frames.wrapping_add(1);
        if self.last_beat.map_or(true, |t| t.elapsed() > Duration::from_secs(2)) {
            self.last_beat = Some(Instant::now());
            log::info!(
                "[beat] frames={} hidden={} window_visible={}",
                self.frames,
                self.hidden_to_tray,
                {
                    #[cfg(windows)]
                    { win32::is_visible() }
                    #[cfg(not(windows))]
                    { true }
                }
            );
        }
        // Surface any proxy start failure reported by the background thread.
        if let Some(err) = pages::accelerator::START_ERROR.lock().unwrap().take() {
            self.push_log(format!("[ERROR] 启动加速失败: {err}"));
            self.set_toast(format!("启动加速失败: {err}"));
        }
        // Drain incoming proxy logs.
        let mut drained = Vec::new();
        if let Some(rx) = self.log_rx.as_mut() {
            while let Ok(line) = rx.try_recv() {
                drained.push(line);
            }
        }
        for line in drained {
            self.push_log(line);
        }
        // Tray events.
        self.poll_tray_events();
        // Clicking the window's X hides to the tray instead of quitting; the
        // tray menu's 退出 is the only way out (mirrors the original client,
        // which keeps accelerating in the background).
        // Remember the HWND once so we can drive ShowWindow directly (the
        // egui ViewportCommand path could hide but never restore the window).
        #[cfg(windows)]
        if !self.hwnd_known {
            use raw_window_handle::{HasWindowHandle as _, RawWindowHandle};
            if let Ok(h) = _frame.window_handle() {
                if let RawWindowHandle::Win32(w) = h.as_raw() {
                    win32::remember(w.hwnd.get() as usize);
                    self.hwnd_known = true;
                    log::info!("[tray] captured hwnd={}", w.hwnd.get());
                }
            }
        }
        // X button -> hide to the tray; the process keeps accelerating. The close
        // is always cancelled here (only the tray menu's 退出 may really exit).
        let close_requested = ctx.input(|i| i.viewport().close_requested());
        if close_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            #[cfg(windows)]
            {
                win32::hide();
            }
            #[cfg(not(windows))]
            {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
            // No toast here: the window is gone the moment we hide it, so a
            // message rendered into it would never be seen.
            self.hidden_to_tray = true;
        } else if self.hidden_to_tray {
            // The window was restored from the tray (the loader's tray thread
            // drives Win32 directly). Clear the flag so the next X hides again.
            #[cfg(windows)]
            let visible = win32::is_visible();
            #[cfg(not(windows))]
            let visible = ctx.input(|i| i.viewport().focused).unwrap_or(false);
            if visible {
                self.hidden_to_tray = false;
            }
        }
        {
            let mut t = self.tray.lock().unwrap();
            if t.show_window {
                t.show_window = false;
                self.hidden_to_tray = false;
                #[cfg(windows)]
                {
                    let ok = win32::show();
                    log::info!("[tray] restore window -> visible={ok}");
                }
                #[cfg(not(windows))]
                {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
            }
            if t.exit {
                self.hidden_to_tray = false;
                self.proxy.stop();
                std::process::exit(0);
            }
        }
        // Expire toast.
        if let Some((_, t)) = self.toast {
            if t.elapsed() > Duration::from_secs(3) {
                self.toast = None;
            }
        }

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            pages::hrow(ui, |ui| {
                ui.heading("WattToolkit-Lite");
                ui.separator();
                if pages::tab_btn(ui, self.main_tab == MainTab::Accelerator, "网络加速") {
                    self.main_tab = MainTab::Accelerator;
                }
                if pages::tab_btn(ui, self.main_tab == MainTab::Settings, "设置") {
                    self.main_tab = MainTab::Settings;
                }
            });
            pages::hrow_right(ui, |ui| {
                let running = self.proxy.is_running();
                let text = if running { "运行中" } else { "已停止" };
                let color = if running {
                    egui::Color32::from_rgb(80, 200, 80)
                } else {
                    egui::Color32::from_rgb(160, 160, 160)
                };
                ui.label(egui::RichText::new(text).color(color));
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| match self.main_tab {
            MainTab::Accelerator => pages::accelerator::show(self, ui),
            MainTab::Settings => pages::settings_page::show(self, ui),
        });

        // Toast.
        if let Some((msg, _)) = self.toast.clone() {
            egui::Area::new("toast".into())
                .fixed_pos([
                    ctx.screen_rect().center().x - 120.0,
                    ctx.screen_rect().max.y - 40.0,
                ])
                .interactable(false)
                .show(ctx, |ui| {
                    ui.strong(&msg);
                });
        }

        // Proxy settings dialog (as a window).
        if self.proxy_dialog.is_some() {
            let mut open = true;
            pages::dialogs::show_proxy_settings(self, ctx, &mut open);
            if !open {
                self.proxy_dialog = None;
            }
        }

        // Certificate info dialog.
        let cert_open = self.cert_dialog.is_some();
        if cert_open {
            let mut open = true;
            let info = self.cert_dialog.clone().unwrap_or_default();
            egui::Window::new("证书信息")
                .open(&mut open)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.monospace(&info);
                });
            if !open {
                self.cert_dialog = None;
            }
        }
    }
}
