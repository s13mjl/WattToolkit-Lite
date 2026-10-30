//! Handles for every child control plus the pure layout/visibility pass.

use windows_sys::Win32::Foundation::HWND;

use crate::types::{AccTab, MainTab, SettingsTab};
use crate::win32::{self, controls, Rect};

#[derive(Clone, Copy)]
pub struct Ui {
    pub title: HWND,
    pub status: HWND,
    pub main_tabs: HWND,

    pub accel_heading: HWND,
    pub start: HWND,
    pub mode_label: HWND,
    pub mode_combo: HWND,
    pub proxy_settings: HWND,
    pub cert_heading: HWND,
    pub cert_install: HWND,
    pub cert_remove: HWND,
    pub cert_view: HWND,
    pub cert_open_dir: HWND,
    pub hosts_heading: HWND,
    pub hosts_edit: HWND,
    pub hosts_reset: HWND,
    pub hosts_open: HWND,
    pub open_log_dir: HWND,

    pub acc_tabs: HWND,
    pub platform_tree: HWND,
    pub services_tree: HWND,
    pub script_enable: HWND,
    pub script_desc: HWND,
    pub logs_clear: HWND,
    pub logs_label: HWND,
    pub logs_edit: HWND,
    pub traffic_total: HWND,
    pub traffic_list: HWND,
    pub nettest_start: HWND,
    pub nettest_hint: HWND,
    pub nettest_list: HWND,

    pub settings_tabs: HWND,
    pub gen_autorun: HWND,
    pub gen_minimize: HWND,
    pub gen_tray: HWND,
    pub gen_gpu: HWND,
    pub gen_save: HWND,
    pub accel_mode_label: HWND,
    pub accel_mode_combo: HWND,
    pub accel_startup_run: HWND,
    pub accel_http_https: HWND,
    pub accel_script: HWND,
    pub accel_save: HWND,
    pub about_icon: HWND,
    pub about_name: HWND,
    pub about_version: HWND,
    pub about_license_label: HWND,
    pub about_license: HWND,
    pub about_upstream_label: HWND,
    pub about_upstream: HWND,
    pub about_secondary_label: HWND,
    pub about_secondary: HWND,
    pub about_desc: HWND,

    pub toast: HWND,
}

impl Default for Ui {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

impl Ui {
    pub fn right_panel(&self) -> impl Iterator<Item = HWND> {
        [
            self.accel_heading,
            self.start,
            self.mode_label,
            self.mode_combo,
            self.proxy_settings,
            self.cert_heading,
            self.cert_install,
            self.cert_remove,
            self.cert_view,
            self.cert_open_dir,
            self.hosts_heading,
            self.hosts_edit,
            self.hosts_reset,
            self.hosts_open,
            self.open_log_dir,
        ]
        .into_iter()
    }

    pub unsafe fn layout(
        &self,
        main: HWND,
        dpi: u32,
        _main_tab: MainTab,
        _acc_tab: AccTab,
        _settings_tab: SettingsTab,
    ) {
        let s = |v: i32| win32::scale(dpi, v);
        let c = win32::client_rect(main);
        win32::place(
            self.title,
            Rect::new(s(16), s(10), (c.w / 2).max(s(200)), s(28)),
        );
        win32::place(self.status, Rect::new(c.w - s(136), s(10), s(120), s(28)));
        let main_tabs = Rect::new(s(12), s(44), (c.w - s(24)).max(0), (c.h - s(52)).max(0));
        win32::place(self.main_tabs, main_tabs);

        let display = Rect::new(
            s(16),
            s(44 + 26 + 4),
            (c.w - s(32)).max(0),
            (c.h - s(74 + 8)).max(0),
        );
        if display.w <= 0 || display.h <= 0 {
            return;
        }

        let panel_w = s(280);
        let panel_x = display.right() - panel_w;
        let panel_y = display.y;
        self.place_right_panel(s, panel_x, panel_y);

        let left = Rect::new(display.x, display.y, (display.w - s(288)).max(0), display.h);
        win32::place(self.acc_tabs, left);
        let acc_page = Rect::new(
            left.x + s(4),
            left.y + s(28),
            (left.w - s(8)).max(0),
            (left.h - s(32)).max(0),
        );
        self.place_acc_pages(s, acc_page);

        win32::place(self.settings_tabs, display);
        let set_page = Rect::new(
            display.x + s(4),
            display.y + s(28),
            (display.w - s(8)).max(0),
            (display.h - s(32)).max(0),
        );
        self.place_settings_pages(s, set_page, display);

        // Leave room for the vertical scrollbar so a full-width column pair does
        // not force a horizontal scrollbar.
        let traffic_w = self.traffic_list;
        if !traffic_w.is_null() && acc_page.w > 0 {
            let w = (acc_page.w - s(16) - s(24)).max(0);
            let c0 = w * 3 / 4;
            controls::list_set_column_width(traffic_w, 0, c0);
            controls::list_set_column_width(traffic_w, 1, w - c0);
        }
        let net_w = self.nettest_list;
        if !net_w.is_null() && acc_page.w > 0 {
            let w = (acc_page.w - s(16) - s(24)).max(0);
            let c0 = w * 2 / 5;
            controls::list_set_column_width(net_w, 0, c0);
            controls::list_set_column_width(net_w, 1, w - c0);
        }

        // Tab controls paint a frame and a client area; every page control must
        // be above them. Sending the tabs to the bottom keeps the right panel,
        // sub-tabs and pages on top without relying on creation order.
        for tab in [self.settings_tabs, self.acc_tabs, self.main_tabs] {
            win32::send_to_bottom(tab);
        }
    }

    unsafe fn place_right_panel(&self, s: impl Fn(i32) -> i32, x: i32, y: i32) {
        let w = s(280);
        win32::place(
            self.accel_heading,
            Rect::new(x + s(8), y + s(8), w - s(16), s(22)),
        );
        win32::place(
            self.start,
            Rect::new(x + s(20), y + s(36), w - s(40), s(38)),
        );
        win32::place(
            self.mode_label,
            Rect::new(x + s(8), y + s(90), s(70), s(24)),
        );
        win32::place(
            self.mode_combo,
            Rect::new(x + s(80), y + s(88), w - s(96), s(200)),
        );
        win32::place(
            self.proxy_settings,
            Rect::new(x + s(20), y + s(124), w - s(40), s(28)),
        );
        win32::place(
            self.cert_heading,
            Rect::new(x + s(8), y + s(164), w - s(16), s(22)),
        );
        win32::place(
            self.cert_install,
            Rect::new(x + s(8), y + s(190), s(128), s(26)),
        );
        win32::place(
            self.cert_remove,
            Rect::new(x + s(144), y + s(190), s(128), s(26)),
        );
        win32::place(
            self.cert_view,
            Rect::new(x + s(8), y + s(222), s(128), s(26)),
        );
        win32::place(
            self.cert_open_dir,
            Rect::new(x + s(144), y + s(222), s(128), s(26)),
        );
        win32::place(
            self.hosts_heading,
            Rect::new(x + s(8), y + s(260), w - s(16), s(22)),
        );
        win32::place(
            self.hosts_edit,
            Rect::new(x + s(8), y + s(286), s(80), s(26)),
        );
        win32::place(
            self.hosts_reset,
            Rect::new(x + s(96), y + s(286), s(80), s(26)),
        );
        win32::place(
            self.hosts_open,
            Rect::new(x + s(184), y + s(286), s(80), s(26)),
        );
        win32::place(
            self.open_log_dir,
            Rect::new(x + s(20), y + s(324), w - s(40), s(28)),
        );
    }

    unsafe fn place_acc_pages(&self, s: impl Fn(i32) -> i32, r: Rect) {
        win32::place(self.platform_tree, r.inset(s(4)));
        win32::place(self.services_tree, r.inset(s(4)));

        win32::place(
            self.script_enable,
            Rect::new(r.x + s(16), r.y + s(16), s(260), s(26)),
        );
        win32::place(
            self.script_desc,
            Rect::new(r.x + s(16), r.y + s(48), (r.w - s(32)).max(0), s(60)),
        );

        win32::place(
            self.logs_clear,
            Rect::new(r.x + s(8), r.y + s(8), s(90), s(28)),
        );
        win32::place(
            self.logs_label,
            Rect::new(r.x + s(110), r.y + s(12), (r.w - s(120)).max(0), s(22)),
        );
        win32::place(
            self.logs_edit,
            Rect::new(
                r.x + s(8),
                r.y + s(42),
                (r.w - s(16)).max(0),
                (r.h - s(50)).max(0),
            ),
        );
        win32::set_round_region(self.logs_edit, s(10));
        win32::set_edit_padding(self.logs_edit, s(12), s(10), s(12), s(10));

        win32::place(
            self.traffic_total,
            Rect::new(r.x + s(8), r.y + s(10), (r.w - s(16)).max(0), s(22)),
        );
        win32::place(
            self.traffic_list,
            Rect::new(
                r.x + s(8),
                r.y + s(38),
                (r.w - s(16)).max(0),
                (r.h - s(46)).max(0),
            ),
        );

        win32::place(
            self.nettest_start,
            Rect::new(r.x + s(8), r.y + s(8), s(120), s(28)),
        );
        win32::place(
            self.nettest_hint,
            Rect::new(r.x + s(136), r.y + s(12), (r.w - s(144)).max(0), s(22)),
        );
        win32::place(
            self.nettest_list,
            Rect::new(
                r.x + s(8),
                r.y + s(44),
                (r.w - s(16)).max(0),
                (r.h - s(52)).max(0),
            ),
        );
    }

    unsafe fn place_settings_pages(&self, s: impl Fn(i32) -> i32, r: Rect, display: Rect) {
        let w = (r.w - s(40)).max(s(180));
        win32::place(
            self.gen_autorun,
            Rect::new(r.x + s(20), r.y + s(20), w, s(26)),
        );
        win32::place(
            self.gen_minimize,
            Rect::new(r.x + s(20), r.y + s(52), w, s(26)),
        );
        win32::place(self.gen_tray, Rect::new(r.x + s(20), r.y + s(84), w, s(26)));
        win32::place(self.gen_gpu, Rect::new(r.x + s(20), r.y + s(116), w, s(26)));
        win32::place(
            self.gen_save,
            Rect::new(r.x + s(20), r.y + s(160), s(90), s(30)),
        );

        win32::place(
            self.accel_mode_label,
            Rect::new(r.x + s(20), r.y + s(22), s(120), s(24)),
        );
        win32::place(
            self.accel_mode_combo,
            Rect::new(r.x + s(146), r.y + s(20), s(190), s(200)),
        );
        win32::place(
            self.accel_startup_run,
            Rect::new(r.x + s(20), r.y + s(60), w, s(26)),
        );
        win32::place(
            self.accel_http_https,
            Rect::new(r.x + s(20), r.y + s(92), w, s(26)),
        );
        win32::place(
            self.accel_script,
            Rect::new(r.x + s(20), r.y + s(124), w, s(26)),
        );
        win32::place(
            self.accel_save,
            Rect::new(r.x + s(20), r.y + s(168), s(90), s(30)),
        );

        let cx = display.x + display.w / 2;
        win32::place(
            self.about_icon,
            Rect::new(cx - s(32), r.y + s(16), s(64), s(64)),
        );
        win32::place(
            self.about_name,
            Rect::new(cx - s(150), r.y + s(92), s(300), s(26)),
        );
        win32::place(
            self.about_version,
            Rect::new(cx - s(150), r.y + s(120), s(300), s(22)),
        );
        let row_x = r.x + s(20);
        let row_w = (r.w - s(40)).max(s(180));
        win32::place(
            self.about_license_label,
            Rect::new(row_x, r.y + s(156), s(110), s(22)),
        );
        win32::place(
            self.about_license,
            Rect::new(row_x + s(110), r.y + s(156), row_w - s(110), s(22)),
        );
        win32::place(
            self.about_upstream_label,
            Rect::new(row_x, r.y + s(184), s(110), s(22)),
        );
        win32::place(
            self.about_upstream,
            Rect::new(row_x + s(110), r.y + s(184), row_w - s(110), s(22)),
        );
        win32::place(
            self.about_secondary_label,
            Rect::new(row_x, r.y + s(212), s(110), s(22)),
        );
        win32::place(
            self.about_secondary,
            Rect::new(row_x + s(110), r.y + s(212), row_w - s(110), s(22)),
        );
        win32::place(
            self.about_desc,
            Rect::new(
                row_x,
                r.y + s(248),
                row_w,
                (r.h - s(256)).clamp(s(40), s(80)),
            ),
        );
    }

    pub unsafe fn apply_visibility(
        &self,
        main_tab: MainTab,
        acc_tab: AccTab,
        settings_tab: SettingsTab,
    ) {
        for h in [self.title, self.status, self.main_tabs] {
            win32::set_visible(h, true);
        }
        let acc = main_tab == MainTab::Accelerator;
        let set = main_tab == MainTab::Settings;

        for h in self.right_panel() {
            win32::set_visible(h, acc);
        }
        win32::set_visible(self.acc_tabs, acc);
        win32::set_visible(self.platform_tree, acc && acc_tab == AccTab::Platform);
        win32::set_visible(self.services_tree, acc && acc_tab == AccTab::Services);
        win32::set_visible(self.script_enable, acc && acc_tab == AccTab::Scripts);
        win32::set_visible(self.script_desc, acc && acc_tab == AccTab::Scripts);
        let logs = acc && acc_tab == AccTab::Logs;
        win32::set_visible(self.logs_clear, logs);
        win32::set_visible(self.logs_label, logs);
        win32::set_visible(self.logs_edit, logs);
        let traffic = acc && acc_tab == AccTab::Traffic;
        win32::set_visible(self.traffic_total, traffic);
        win32::set_visible(self.traffic_list, traffic);
        let nettest = acc && acc_tab == AccTab::NetTest;
        win32::set_visible(self.nettest_start, nettest);
        win32::set_visible(self.nettest_hint, nettest);
        win32::set_visible(self.nettest_list, nettest);

        win32::set_visible(self.settings_tabs, set);
        let general = set && settings_tab == SettingsTab::General;
        win32::set_visible(self.gen_autorun, general);
        win32::set_visible(self.gen_minimize, general);
        win32::set_visible(self.gen_tray, general);
        win32::set_visible(self.gen_gpu, general);
        win32::set_visible(self.gen_save, general);
        let accel = set && settings_tab == SettingsTab::Accelerate;
        win32::set_visible(self.accel_mode_label, accel);
        win32::set_visible(self.accel_mode_combo, accel);
        win32::set_visible(self.accel_startup_run, accel);
        win32::set_visible(self.accel_http_https, accel);
        win32::set_visible(self.accel_script, accel);
        win32::set_visible(self.accel_save, accel);
        let about = set && settings_tab == SettingsTab::About;
        win32::set_visible(self.about_icon, about);
        win32::set_visible(self.about_name, about);
        win32::set_visible(self.about_version, about);
        win32::set_visible(self.about_license_label, about);
        win32::set_visible(self.about_license, about);
        win32::set_visible(self.about_upstream_label, about);
        win32::set_visible(self.about_upstream, about);
        win32::set_visible(self.about_secondary_label, about);
        win32::set_visible(self.about_secondary, about);
        win32::set_visible(self.about_desc, about);
    }
}
