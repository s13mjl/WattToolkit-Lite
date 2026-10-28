//! Settings page: 通用 / 加速 / 关于.

use windows_sys::Win32::System::SystemServices::{SS_CENTERIMAGE, SS_ICON};
use windows_sys::Win32::UI::WindowsAndMessaging as wm;

use wtlite_core::model::ProxyMode;

use crate::win32::{self, controls, Rect};
use crate::{ids, state, App};

pub const SECONDARY_REPO_URL: &str = "https://github.com/s13mjl/WattToolkit-Lite";
pub const UPSTREAM_REPO_URL: &str = "https://github.com/BeyondDimension/SteamTools";

pub unsafe fn build(app: &mut App) {
    let h = app.hwnd;
    let ui = app.fonts.ui;
    let title = app.fonts.title;
    let link = app.fonts.link;

    app.ui.settings_tabs = controls::make_tabs(h, ids::SETTINGS_TABS, Rect::default(), ui);
    controls::tabs_add(app.ui.settings_tabs, &["通用", "加速", "关于"]);
    controls::tabs_set_sel(app.ui.settings_tabs, app.settings_tab.index() as i32);

    app.ui.gen_autorun = crate::pages::checkbox(h, "开机自动启动", ids::GEN_AUTORUN, ui);
    app.ui.gen_minimize = crate::pages::checkbox(h, "启动时最小化到托盘", ids::GEN_MINIMIZE, ui);
    app.ui.gen_tray = crate::pages::checkbox(h, "显示托盘图标", ids::GEN_TRAY, ui);
    app.ui.gen_gpu = crate::pages::checkbox(h, "使用 GPU 加速渲染", ids::GEN_GPU, ui);
    app.ui.gen_save = crate::pages::button(h, "保存", ids::GEN_SAVE, ui);

    app.ui.accel_mode_label = crate::pages::left_label(h, "默认加速模式:", ids::ACCEL_MODE_LABEL, ui);
    app.ui.accel_mode_combo = crate::pages::combo(h, ids::ACCEL_MODE_COMBO, ui, false);
    let modes: Vec<&str> = ProxyMode::available().iter().map(|m| m.display_name()).collect();
    win32::combo_fill(app.ui.accel_mode_combo, &modes);
    app.ui.accel_startup_run =
        crate::pages::checkbox(h, "程序启动时自动运行加速", ids::ACCEL_STARTUP_RUN, ui);
    app.ui.accel_http_https =
        crate::pages::checkbox(h, "允许 HTTP 请求转发为 HTTPS", ids::ACCEL_HTTP_HTTPS, ui);
    app.ui.accel_script = crate::pages::checkbox(h, "启用加速脚本", ids::ACCEL_SCRIPT, ui);
    app.ui.accel_save = crate::pages::button(h, "保存", ids::ACCEL_SAVE, ui);

    app.ui.about_icon = crate::pages::label(h, "", SS_ICON | SS_CENTERIMAGE, ids::ABOUT_ICON, ui);
    wm::SendMessageW(
        app.ui.about_icon,
        wm::STM_SETICON,
        app.icons.about as usize,
        app.icons.about as isize,
    );
    app.ui.about_name = crate::pages::center_label(h, "WattToolkit-Lite", ids::ABOUT_NAME, title);
    app.ui.about_version = crate::pages::center_label(
        h,
        &format!("版本 {}", wtlite_core::APP_VERSION),
        ids::ABOUT_VERSION,
        ui,
    );
    app.ui.about_license_label = crate::pages::left_label(h, "许可证:", ids::ABOUT_LICENSE_LABEL, ui);
    app.ui.about_license = crate::pages::left_label(h, "GPL-3.0-or-later", ids::ABOUT_LICENSE, ui);
    app.ui.about_upstream_label = crate::pages::left_label(h, "上游项目:", ids::ABOUT_UPSTREAM_LABEL, ui);
    app.ui.about_upstream = crate::pages::link_label(h, UPSTREAM_REPO_URL, ids::ABOUT_UPSTREAM, link);
    app.ui.about_secondary_label =
        crate::pages::left_label(h, "二次开发:", ids::ABOUT_SECONDARY_LABEL, ui);
    app.ui.about_secondary =
        crate::pages::link_label(h, SECONDARY_REPO_URL, ids::ABOUT_SECONDARY, link);
    app.ui.about_desc = crate::pages::wrap_label(
        h,
        "WattToolkit-Lite 是一个仅复现 WattToolkit 网络加速与设置功能的二次开发项目（Windows）。",
        ids::ABOUT_DESC,
        ui,
    );

    sync(app);
}

pub unsafe fn sync(app: &mut App) {
    let g = &app.settings.general;
    win32::set_check(app.ui.gen_autorun, g.auto_run_on_startup);
    win32::set_check(app.ui.gen_minimize, g.minimize_on_startup);
    win32::set_check(app.ui.gen_tray, g.tray_icon);
    win32::set_check(app.ui.gen_gpu, g.gpu);

    let p = &app.settings.proxy;
    win32::set_combo_sel(app.ui.accel_mode_combo, state::mode_index(p.proxy_mode));
    win32::set_check(app.ui.accel_startup_run, p.program_startup_run_proxy);
    win32::set_check(app.ui.accel_http_https, p.enable_http_proxy_to_https);
    win32::set_check(app.ui.accel_script, p.is_enable_script);
    win32::set_check(app.ui.script_enable, p.is_enable_script);
}

pub unsafe fn sync_script(app: &mut App) {
    let on = app.settings.proxy.is_enable_script;
    win32::set_check(app.ui.script_enable, on);
    win32::set_check(app.ui.accel_script, on);
}
