//! UI state machine: all control events are handled here, and every page is
//! populated from this single `App`.

use std::cell::Cell;
use std::collections::{HashMap, VecDeque};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::UI::Controls;
use windows_sys::Win32::UI::WindowsAndMessaging as wm;

use wtlite_core::model::ProxyMode;
use wtlite_core::nettest::TestResult;
use wtlite_core::{AccelerateService, ProxyManager, Settings};

use crate::actions::Action;
use crate::pages;
use crate::pages::accelerator::NodeRef;
use crate::state::{self, ProxyDialogData};
use crate::types::{AccTab, MainTab, SettingsTab};
use crate::ui::Ui;
use crate::win32::{self, controls, Fonts, Icons};
use crate::{ids, tray};

thread_local! {
    static STATUS_RUNNING: Cell<bool> = const { Cell::new(false) };
}

pub fn status_running() -> bool {
    STATUS_RUNNING.with(|s| s.get())
}

pub struct App {
    pub hwnd: HWND,
    pub dpi: u32,
    pub fonts: Fonts,
    pub icons: Icons,
    pub ui: Ui,
    pub settings: Settings,
    pub proxy: ProxyManager,
    pub accel: AccelerateService,
    pub groups: Vec<wtlite_core::AccelerateProjectGroup>,
    pub logs: VecDeque<String>,
    pub log_rx: Option<tokio::sync::mpsc::UnboundedReceiver<String>>,
    pub start_error: Arc<Mutex<Option<String>>>,
    pub main_tab: MainTab,
    pub acc_tab: AccTab,
    pub settings_tab: SettingsTab,
    pub toast: Option<(String, Instant)>,
    pub running: bool,
    pub tray_enabled: bool,
    pub hidden_to_tray: bool,
    pub testing: bool,
    pub net_results: Vec<TestResult>,
    pub test_rx: Option<mpsc::Receiver<Vec<TestResult>>>,
    pub traffic_total: u64,
    pub traffic_rows: Vec<(String, u64)>,
    pub last_traffic: Instant,
    pub last_logs: Instant,
    pub logs_dirty: bool,
    pub platform_nodes: HashMap<isize, NodeRef>,
    pub platform_groups: HashMap<String, isize>,
    pub platform_leaves: HashMap<String, isize>,
    pub services_leaves: HashMap<String, isize>,
    pub actions: Vec<Action>,
}

impl Drop for App {
    fn drop(&mut self) {
        unsafe {
            self.icons.destroy();
            self.fonts.destroy();
        }
    }
}

impl App {
    pub fn new(icon: crate::IconData) -> Result<Self, String> {
        let dpi = win32::dpi();
        let fonts = unsafe { Fonts::new(dpi) };
        let icons = match unsafe { Icons::from_rgba(&icon.rgba, icon.width, icon.height) } {
            Ok(i) => i,
            Err(e) => {
                unsafe { fonts.destroy() };
                return Err(e);
            }
        };

        let settings = Settings::load();
        let proxy = ProxyManager::new();
        let log_rx = proxy.take_log_rx();
        let accel = AccelerateService::new();
        let _ = accel.load_sync();
        let saved = settings.proxy.support_proxy_services_status.clone();
        accel.apply_enabled(&saved);
        let groups = accel.groups();

        Ok(Self {
            hwnd: std::ptr::null_mut(),
            dpi,
            fonts,
            icons,
            ui: Ui::default(),
            settings,
            proxy,
            accel,
            groups,
            logs: VecDeque::with_capacity(1000),
            log_rx,
            start_error: Arc::new(Mutex::new(None)),
            main_tab: MainTab::Accelerator,
            acc_tab: AccTab::Platform,
            settings_tab: SettingsTab::General,
            toast: None,
            running: false,
            tray_enabled: false,
            hidden_to_tray: false,
            testing: false,
            net_results: Vec::new(),
            test_rx: None,
            traffic_total: 0,
            traffic_rows: Vec::new(),
            last_traffic: Instant::now(),
            last_logs: Instant::now(),
            logs_dirty: false,
            platform_nodes: HashMap::new(),
            platform_groups: HashMap::new(),
            platform_leaves: HashMap::new(),
            services_leaves: HashMap::new(),
            actions: Vec::new(),
        })
    }

    pub unsafe fn build_ui(&mut self) {
        let h = self.hwnd;
        let ss_title = windows_sys::Win32::System::SystemServices::SS_LEFT
            | windows_sys::Win32::System::SystemServices::SS_CENTERIMAGE;
        let ss_status = windows_sys::Win32::System::SystemServices::SS_RIGHT
            | windows_sys::Win32::System::SystemServices::SS_CENTERIMAGE;
        self.ui.title = pages::label(
            h,
            "WattToolkit-Lite",
            ss_title,
            ids::TITLE,
            self.fonts.title,
        );
        self.ui.status = pages::label(h, "已停止", ss_status, ids::STATUS, self.fonts.ui);
        self.ui.main_tabs =
            controls::make_tabs(h, ids::MAIN_TABS, win32::Rect::default(), self.fonts.ui);
        controls::tabs_add(self.ui.main_tabs, &["网络加速", "设置"]);
        controls::tabs_set_sel(self.ui.main_tabs, 0);

        pages::accelerator::build(self);
        pages::settings::build(self);
        win32::set_text(self.ui.logs_edit, "(空)");
        self.refresh_status();
        self.layout();
        self.refresh_active_acc_page();
    }

    pub unsafe fn layout(&mut self) {
        self.ui.layout(
            self.hwnd,
            self.dpi,
            self.main_tab,
            self.acc_tab,
            self.settings_tab,
        );
        self.ui
            .apply_visibility(self.main_tab, self.acc_tab, self.settings_tab);
    }

    pub unsafe fn refresh_status(&mut self) {
        let running = self.proxy.is_running();
        self.running = running;
        STATUS_RUNNING.with(|s| s.set(running));
        win32::set_text(self.ui.status, if running { "运行中" } else { "已停止" });
        win32::set_text(
            self.ui.start,
            if running {
                "停止加速"
            } else {
                "启动加速"
            },
        );
        win32::invalidate(self.ui.status);
        win32::invalidate(self.ui.start);
    }

    pub fn push_log(&mut self, line: String) {
        self.logs.push_back(line);
        while self.logs.len() > 1000 {
            self.logs.pop_front();
        }
        self.logs_dirty = true;
    }

    pub unsafe fn toast(&mut self, msg: impl Into<String>) {
        let msg = msg.into();
        self.toast = Some((msg.clone(), Instant::now()));
        log::info!("[toast] {msg}");
        if !self.hidden_to_tray {
            crate::toast::show(self.hwnd, self.ui.toast, &msg, self.fonts.toast, self.dpi);
        }
    }

    pub fn queue(&mut self, action: Action) {
        self.actions.push(action);
    }

    pub unsafe fn tick(&mut self) {
        let mut drained = Vec::new();
        if let Some(rx) = self.log_rx.as_mut() {
            while let Ok(line) = rx.try_recv() {
                drained.push(line);
                if drained.len() >= 2000 {
                    break;
                }
            }
        }
        for line in drained {
            self.push_log(line);
        }

        let start_err = self.start_error.lock().unwrap().take();
        if let Some(err) = start_err {
            self.push_log(format!("[ERROR] 启动加速失败: {err}"));
            self.toast(format!("启动加速失败: {err}"));
        }

        if self.main_tab == MainTab::Accelerator
            && self.acc_tab == AccTab::Logs
            && self.logs_dirty
            && self.last_logs.elapsed() >= Duration::from_millis(400)
        {
            pages::accelerator::refresh_logs(self);
            self.last_logs = Instant::now();
        }

        if let Some(rx) = self.test_rx.take() {
            match rx.try_recv() {
                Ok(results) => {
                    self.net_results = results;
                    self.testing = false;
                    pages::accelerator::refresh_nettest(self);
                }
                Err(mpsc::TryRecvError::Empty) => {
                    self.test_rx = Some(rx);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.testing = false;
                    pages::accelerator::refresh_nettest_button(self);
                }
            }
        }

        if self.proxy.is_running() != self.running {
            self.refresh_status();
        }

        if self.main_tab == MainTab::Accelerator
            && self.acc_tab == AccTab::Traffic
            && self.last_traffic.elapsed() >= Duration::from_secs(1)
        {
            pages::accelerator::refresh_traffic(self);
            self.last_traffic = Instant::now();
        }

        let expired = self
            .toast
            .as_ref()
            .is_some_and(|(_, t)| t.elapsed() > Duration::from_secs(3));
        if expired {
            self.toast = None;
        }
    }

    pub unsafe fn on_command(&mut self, wparam: WPARAM, _lparam: LPARAM) {
        let id = win32::wparam_id(wparam);
        let code = win32::wparam_code(wparam);
        match id {
            ids::START => {
                if self.proxy.is_running() {
                    self.stop_accel();
                } else {
                    self.start_accel();
                }
            }
            ids::MODE_COMBO if code == wm::CBN_SELCHANGE => {
                let mode = state::mode_from_index(win32::combo_sel(self.ui.mode_combo));
                self.switch_proxy_mode(mode);
            }
            ids::PROXY_SETTINGS => {
                let data = ProxyDialogData::from_settings(&self.settings.proxy);
                self.queue(Action::OpenProxyDialog(data));
            }
            ids::CERT_INSTALL => self.queue(Action::CertInstall),
            ids::CERT_REMOVE => self.queue(Action::CertRemove),
            ids::CERT_VIEW => {
                let info = self.proxy.cert.info();
                self.queue(Action::OpenCertDialog(info));
            }
            ids::CERT_OPEN_DIR => {
                self.queue(Action::ShellOpen(
                    wtlite_core::paths::cert_dir()
                        .to_string_lossy()
                        .into_owned(),
                ));
            }
            ids::HOSTS_EDIT => self.queue(Action::OpenHostsEditor),
            ids::HOSTS_OPEN => self.queue(Action::RevealHosts),
            ids::HOSTS_RESET => self.queue(Action::HostsReset),
            ids::OPEN_LOG_DIR => {
                self.queue(Action::ShellOpen(
                    wtlite_core::paths::log_dir().to_string_lossy().into_owned(),
                ));
            }
            ids::LOGS_CLEAR => {
                self.logs.clear();
                self.logs_dirty = false;
                pages::accelerator::refresh_logs(self);
            }
            ids::NETTEST_START => pages::accelerator::start_nettest(self),
            ids::SCRIPT_ENABLE | ids::ACCEL_SCRIPT => {
                let on = if id == ids::SCRIPT_ENABLE {
                    win32::get_check(self.ui.script_enable)
                } else {
                    win32::get_check(self.ui.accel_script)
                };
                self.settings.proxy.is_enable_script = on;
                pages::settings::sync_script(self);
            }
            ids::GEN_AUTORUN => {
                let on = win32::get_check(self.ui.gen_autorun);
                self.settings.general.auto_run_on_startup = on;
                match wtlite_core::settings::set_auto_run_on_startup(on) {
                    Ok(()) => self.toast("开机自启动设置已更新"),
                    Err(e) => self.toast(format!("开机自启动设置失败: {e}")),
                }
            }
            ids::GEN_MINIMIZE => {
                self.settings.general.minimize_on_startup = win32::get_check(self.ui.gen_minimize);
            }
            ids::GEN_TRAY => {
                self.settings.general.tray_icon = win32::get_check(self.ui.gen_tray);
            }
            ids::GEN_GPU => {
                self.settings.general.gpu = win32::get_check(self.ui.gen_gpu);
            }
            ids::GEN_SAVE => {
                let r = self.settings.save();
                self.apply_tray_pref();
                self.toast(match r {
                    Ok(()) => "设置已保存".to_string(),
                    Err(e) => format!("保存失败: {e}"),
                });
            }
            ids::ACCEL_MODE_COMBO if code == wm::CBN_SELCHANGE => {
                self.settings.proxy.proxy_mode =
                    state::mode_from_index(win32::combo_sel(self.ui.accel_mode_combo));
                pages::accelerator::update_mode_combo(self);
            }
            ids::ACCEL_STARTUP_RUN => {
                self.settings.proxy.program_startup_run_proxy =
                    win32::get_check(self.ui.accel_startup_run);
            }
            ids::ACCEL_HTTP_HTTPS => {
                self.settings.proxy.enable_http_proxy_to_https =
                    win32::get_check(self.ui.accel_http_https);
            }
            ids::ACCEL_SAVE => {
                let r = self.settings.save();
                self.toast(match r {
                    Ok(()) => "设置已保存".to_string(),
                    Err(e) => format!("保存失败: {e}"),
                });
            }
            ids::ABOUT_UPSTREAM => {
                self.queue(Action::ShellOpen(pages::settings::UPSTREAM_REPO_URL.into()));
            }
            ids::ABOUT_SECONDARY => {
                self.queue(Action::ShellOpen(
                    pages::settings::SECONDARY_REPO_URL.into(),
                ));
            }
            _ => {}
        }
    }

    pub unsafe fn on_notify(&mut self, lparam: LPARAM) -> LRESULT {
        let code = controls::notify_code(lparam);
        let id = controls::notify_id(lparam);
        if id == ids::MAIN_TABS && code == Controls::TCN_SELCHANGE {
            let tab = controls::tabs_sel(self.ui.main_tabs);
            self.main_tab = if tab == 1 {
                MainTab::Settings
            } else {
                MainTab::Accelerator
            };
            if self.main_tab == MainTab::Settings {
                pages::settings::sync(self);
                self.layout();
            } else {
                pages::accelerator::update_mode_combo(self);
                self.refresh_status();
                self.layout();
                self.refresh_active_acc_page();
            }
            return 0;
        }
        if id == ids::ACC_TABS && code == Controls::TCN_SELCHANGE {
            self.acc_tab = AccTab::from_index(controls::tabs_sel(self.ui.acc_tabs));
            self.layout();
            self.refresh_active_acc_page();
            return 0;
        }
        if id == ids::SETTINGS_TABS && code == Controls::TCN_SELCHANGE {
            self.settings_tab = SettingsTab::from_index(controls::tabs_sel(self.ui.settings_tabs));
            pages::settings::sync(self);
            self.layout();
            return 0;
        }
        if id == ids::PLATFORM_TREE && code == Controls::TVN_ITEMCHANGEDW {
            let (item, _, _) = controls::tv_item_change(lparam);
            pages::accelerator::on_platform_check(self, item);
            return 0;
        }
        if id == ids::SERVICES_TREE && code == Controls::TVN_ITEMCHANGEDW {
            let (item, _, _) = controls::tv_item_change(lparam);
            pages::accelerator::on_service_check(self, item);
            return 0;
        }
        if id == ids::NETTEST_LIST && code == Controls::NM_CUSTOMDRAW {
            let cd = &mut *(lparam as *mut Controls::NMLVCUSTOMDRAW);
            if cd.nmcd.dwDrawStage == Controls::CDDS_PREPAINT {
                return Controls::CDRF_NOTIFYITEMDRAW as LRESULT;
            }
            if cd.nmcd.dwDrawStage == Controls::CDDS_ITEMPREPAINT {
                cd.clrText = pages::accelerator::test_result_color(cd.nmcd.lItemlParam);
                return Controls::CDRF_NEWFONT as LRESULT;
            }
        }
        0
    }

    unsafe fn refresh_active_acc_page(&mut self) {
        match self.acc_tab {
            AccTab::Platform | AccTab::Services => {
                pages::accelerator::sync_checks(self);
            }
            AccTab::Logs => {
                pages::accelerator::refresh_logs(self);
                self.last_logs = Instant::now();
            }
            AccTab::Traffic => {
                pages::accelerator::refresh_traffic(self);
                self.last_traffic = Instant::now();
            }
            AccTab::NetTest => {
                pages::accelerator::refresh_nettest(self);
            }
            _ => {}
        }
    }

    fn start_blocking_thread(&mut self, mode: ProxyMode) {
        let proxy = self.proxy.clone();
        let settings = self.settings.proxy.clone();
        let groups = self.groups.clone();
        let err = self.start_error.clone();
        std::thread::spawn(
            move || match proxy.start_blocking(mode, &settings, &groups) {
                Ok(()) => log::info!("proxy started ({mode:?})"),
                Err(e) => {
                    log::error!("proxy start failed: {e}");
                    *err.lock().unwrap() = Some(e);
                }
            },
        );
    }

    pub unsafe fn start_accel(&mut self) {
        if self.proxy.is_running() {
            return;
        }
        let ids = state::enabled_ids(&self.groups);
        self.settings.proxy.support_proxy_services_status = ids;
        let _ = self.settings.save();
        let mode = self.settings.proxy.proxy_mode;
        self.start_blocking_thread(mode);
        self.toast(format!("正在启动加速…（{}）", mode.display_name()));
    }

    pub unsafe fn stop_accel(&mut self) {
        self.proxy.stop();
        self.toast("加速已停止");
        self.refresh_status();
    }

    pub unsafe fn switch_proxy_mode(&mut self, mode: ProxyMode) {
        if self.settings.proxy.proxy_mode == mode {
            return;
        }
        let was_running = self.proxy.is_running();
        self.settings.proxy.proxy_mode = mode;
        let _ = self.settings.save();
        pages::accelerator::update_mode_combo(self);
        if was_running {
            self.proxy.stop();
            self.start_accel();
        } else {
            self.toast(format!("加速模式: {}", mode.display_name()));
        }
    }

    pub unsafe fn apply_proxy_dialog(&mut self, data: ProxyDialogData) {
        data.apply_to(&mut self.settings.proxy);
        let _ = self.settings.save();
        pages::accelerator::update_mode_combo(self);
        pages::settings::sync(self);
        self.toast("代理设置已保存");
    }

    fn apply_tray_pref(&mut self) {
        let want = self.settings.general.tray_icon;
        if want == self.tray_enabled {
            return;
        }
        let actual = unsafe { tray::set_enabled(want) };
        self.tray_enabled = actual;
        if want && !actual {
            unsafe { self.toast("托盘图标创建失败，关闭窗口将退出程序") };
        }
    }

    pub fn on_close(&mut self) {
        if self.tray_enabled {
            self.queue(Action::HideToTray);
        } else {
            self.queue(Action::Exit);
        }
    }
}
