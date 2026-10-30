//! Proxy-settings and certificate-info windows.
//!
//! They are owned, non-modal windows (the main window stays interactive), the
//! same interaction model as the previous egui windows.

use std::cell::{Cell, RefCell};
use std::ffi::c_void;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi;
use windows_sys::Win32::UI::Controls;
use windows_sys::Win32::UI::WindowsAndMessaging as wm;

use wtlite_core::model::ProxyMode;

use crate::pages;
use crate::state::{self, ProxyDialogData};
use crate::win32::{self, wide, Fonts, Rect};
use crate::{ids, with_app};

const PROXY_CLASS: windows_sys::core::PCWSTR = windows_sys::core::w!("WtliteProxyDialog");
const CERT_CLASS: windows_sys::core::PCWSTR = windows_sys::core::w!("WtliteCertDialog");

thread_local! {
    static DIALOGS: RefCell<Vec<HWND>> = const { RefCell::new(Vec::new()) };
    static PROXY: Cell<HWND> = const { Cell::new(std::ptr::null_mut()) };
    static CERT: Cell<HWND> = const { Cell::new(std::ptr::null_mut()) };
}

pub unsafe fn register() -> bool {
    win32::register_class(
        PROXY_CLASS,
        Some(proxy_proc),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    ) && win32::register_class(
        CERT_CLASS,
        Some(cert_proc),
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
}

pub fn all() -> Vec<HWND> {
    DIALOGS.with(|d| d.borrow().clone())
}

pub unsafe fn hide_all() {
    for h in all() {
        if win32::is_window(h) {
            wm::ShowWindow(h, wm::SW_HIDE);
        }
    }
}

pub unsafe fn show_all() {
    for h in all() {
        if win32::is_window(h) {
            wm::ShowWindow(h, wm::SW_SHOW);
        }
    }
}

fn register_dialog(hwnd: HWND) {
    DIALOGS.with(|d| d.borrow_mut().push(hwnd));
}

fn unregister_dialog(hwnd: HWND) {
    DIALOGS.with(|d| d.borrow_mut().retain(|h| *h != hwnd));
}

struct ProxyInit {
    data: ProxyDialogData,
    fonts: Fonts,
    dpi: u32,
}

struct ProxyState {
    initial: ProxyDialogData,
    mode: HWND,
    port: HWND,
    dns: HWND,
    use_doh: HWND,
    doh: HWND,
    http_https: HWND,
    tls: HWND,
    two_level: HWND,
    two_type: HWND,
    two_ip: HWND,
    two_port: HWND,
    two_user: HWND,
    two_pass: HWND,
    labels: [HWND; 6],
}

pub unsafe fn open_proxy(main: HWND, fonts: Fonts, dpi: u32, data: ProxyDialogData) {
    let existing = PROXY.with(|p| p.get());
    if !existing.is_null() && win32::is_window(existing) {
        wm::ShowWindow(existing, wm::SW_SHOW);
        wm::SetForegroundWindow(existing);
        return;
    }
    let (cw, ch) = (win32::scale(dpi, 560), win32::scale(dpi, 560));
    let (ow, oh) = dialog_outer_size(dpi, cw, ch);
    let (x, y) = centered(main, ow, oh);
    let title = wide("代理设置");
    let init = Box::into_raw(Box::new(ProxyInit { data, fonts, dpi }));
    let hwnd = wm::CreateWindowExW(
        wm::WS_EX_DLGMODALFRAME | wm::WS_EX_CONTROLPARENT,
        PROXY_CLASS,
        title.as_ptr(),
        wm::WS_POPUP | wm::WS_CAPTION | wm::WS_SYSMENU | wm::WS_CLIPCHILDREN,
        x,
        y,
        ow,
        oh,
        main,
        std::ptr::null_mut(),
        win32::hinstance(),
        init as *const c_void,
    );
    if hwnd.is_null() {
        log::error!(
            "failed to create proxy dialog (err={})",
            std::io::Error::last_os_error()
        );
        return;
    }
    wm::ShowWindow(hwnd, wm::SW_SHOW);
    wm::SetForegroundWindow(hwnd);
    let mode = wm::GetDlgItem(hwnd, ids::proxy::MODE);
    if !mode.is_null() {
        windows_sys::Win32::UI::Input::KeyboardAndMouse::SetFocus(mode);
    }
}

pub unsafe fn open_cert(main: HWND, fonts: Fonts, dpi: u32, info: String) {
    let existing = CERT.with(|c| c.get());
    if !existing.is_null() && win32::is_window(existing) {
        wm::ShowWindow(existing, wm::SW_SHOW);
        wm::SetForegroundWindow(existing);
        return;
    }
    let (cw, ch) = (win32::scale(dpi, 520), win32::scale(dpi, 380));
    let (ow, oh) = dialog_outer_size(dpi, cw, ch);
    let (x, y) = centered(main, ow, oh);
    let title = wide("证书信息");
    let init = Box::into_raw(Box::new(CertInit { info, fonts, dpi }));
    let hwnd = wm::CreateWindowExW(
        wm::WS_EX_DLGMODALFRAME | wm::WS_EX_CONTROLPARENT,
        CERT_CLASS,
        title.as_ptr(),
        wm::WS_POPUP | wm::WS_CAPTION | wm::WS_SYSMENU | wm::WS_CLIPCHILDREN,
        x,
        y,
        ow,
        oh,
        main,
        std::ptr::null_mut(),
        win32::hinstance(),
        init as *const c_void,
    );
    if hwnd.is_null() {
        log::error!("failed to create certificate dialog");
        return;
    }
    wm::ShowWindow(hwnd, wm::SW_SHOW);
    wm::SetForegroundWindow(hwnd);
}

unsafe fn dialog_outer_size(dpi: u32, cw: i32, ch: i32) -> (i32, i32) {
    let mut rc = RECT {
        left: 0,
        top: 0,
        right: cw,
        bottom: ch,
    };
    windows_sys::Win32::UI::HiDpi::AdjustWindowRectExForDpi(
        &mut rc,
        wm::WS_POPUP | wm::WS_CAPTION | wm::WS_SYSMENU,
        0,
        wm::WS_EX_DLGMODALFRAME | wm::WS_EX_CONTROLPARENT,
        dpi,
    );
    (rc.right - rc.left, rc.bottom - rc.top)
}

unsafe fn centered(main: HWND, w: i32, h: i32) -> (i32, i32) {
    let mut rc: RECT = std::mem::zeroed();
    wm::GetWindowRect(main, &mut rc);
    let mw = rc.right - rc.left;
    let mh = rc.bottom - rc.top;
    (rc.left + (mw - w) / 2, rc.top + (mh - h) / 2)
}

struct CertInit {
    info: String,
    fonts: Fonts,
    dpi: u32,
}

struct CertState {
    _fonts: Fonts,
}

unsafe extern "system" fn proxy_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        wm::WM_CREATE => {
            let cs = &*(lparam as *const wm::CREATESTRUCTW);
            let init = Box::from_raw(cs.lpCreateParams as *mut ProxyInit);
            let state = create_proxy_ui(hwnd, init);
            wm::SetWindowLongPtrW(
                hwnd,
                wm::GWLP_USERDATA,
                Box::into_raw(Box::new(state)) as isize,
            );
            PROXY.with(|p| p.set(hwnd));
            register_dialog(hwnd);
            0
        }
        wm::WM_COMMAND => {
            let id = win32::wparam_id(wparam);
            let code = win32::wparam_code(wparam);
            match id {
                ids::proxy::TWO_LEVEL if code == wm::BN_CLICKED => {
                    if let Some(state) = proxy_state(hwnd) {
                        toggle_two_level(state);
                    }
                }
                wm::IDOK => {
                    if let Some(state) = proxy_state(hwnd) {
                        let data = read_proxy(state);
                        with_app(|app| app.apply_proxy_dialog(data));
                    }
                    wm::DestroyWindow(hwnd);
                }
                wm::IDCANCEL => {
                    wm::DestroyWindow(hwnd);
                }
                _ => {}
            }
            0
        }
        wm::WM_CLOSE => {
            wm::DestroyWindow(hwnd);
            0
        }
        wm::WM_CTLCOLORSTATIC => {
            let hdc = wparam as Gdi::HDC;
            Gdi::SetTextColor(hdc, 0);
            Gdi::GetSysColorBrush(Gdi::COLOR_BTNFACE) as LRESULT
        }
        wm::WM_CTLCOLOREDIT => {
            let hdc = wparam as Gdi::HDC;
            Gdi::SetTextColor(hdc, 0);
            Gdi::SetBkColor(hdc, 0x00FF_FFFF);
            Gdi::GetSysColorBrush(Gdi::COLOR_WINDOW) as LRESULT
        }
        wm::WM_NCDESTROY => {
            let ptr = wm::GetWindowLongPtrW(hwnd, wm::GWLP_USERDATA) as *mut ProxyState;
            if !ptr.is_null() {
                drop(Box::from_raw(ptr));
                wm::SetWindowLongPtrW(hwnd, wm::GWLP_USERDATA, 0);
            }
            PROXY.with(|p| {
                if p.get() == hwnd {
                    p.set(std::ptr::null_mut());
                }
            });
            unregister_dialog(hwnd);
            wm::DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        _ => wm::DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

unsafe fn proxy_state(hwnd: HWND) -> Option<&'static mut ProxyState> {
    let ptr = wm::GetWindowLongPtrW(hwnd, wm::GWLP_USERDATA) as *mut ProxyState;
    ptr.as_mut()
}

unsafe fn create_proxy_ui(hwnd: HWND, init: Box<ProxyInit>) -> ProxyState {
    let ProxyInit { data, fonts, dpi } = *init;
    let ui = fonts.ui;
    let s = |v: i32| win32::scale(dpi, v);
    let y = |v: i32| win32::scale(dpi, v);

    let mode_label = pages::left_label(hwnd, "加速模式:", ids::proxy::MODE_LABEL, ui);
    let mode = pages::combo(hwnd, ids::proxy::MODE, ui, false);
    let modes: Vec<&str> = ProxyMode::available()
        .iter()
        .map(|m| m.display_name())
        .collect();
    win32::combo_fill(mode, &modes);
    win32::set_combo_sel(mode, state::mode_index(data.mode));
    let hint = pages::wrap_label(
        hwnd,
        "提示: DNS 拦截模式需要 WinDivert 驱动，若驱动缺失将提示不可用。",
        ids::proxy::HINT,
        ui,
    );
    let port_label = pages::left_label(hwnd, "代理端口:", ids::proxy::PORT_LABEL, ui);
    let port = pages::edit(
        hwnd,
        &data.port.to_string(),
        ids::proxy::PORT,
        ui,
        false,
        false,
    );
    wm::SendMessageW(port, win32::EM_SETLIMITTEXT, 5, 0);

    let dns_label = pages::left_label(hwnd, "DNS 服务器:", ids::proxy::DNS_LABEL, ui);
    let dns = pages::combo(hwnd, ids::proxy::DNS, ui, true);
    let servers = wtlite_core::dns::dns_servers();
    win32::combo_fill(dns, &servers);
    win32::combo_set_text(dns, &data.dns);

    let use_doh = pages::checkbox(hwnd, "使用 DNS-over-HTTPS (DoH)", ids::proxy::USE_DOH, ui);
    win32::set_check(use_doh, data.use_doh);
    let doh_label = pages::left_label(hwnd, "DoH 地址:", ids::proxy::DOH_LABEL, ui);
    let doh = pages::combo(hwnd, ids::proxy::DOH, ui, true);
    let dohs = wtlite_core::dns::doh_addresses();
    win32::combo_fill(doh, &dohs);
    win32::combo_set_text(doh, &data.doh_address);

    let http_https = pages::checkbox(
        hwnd,
        "允许 HTTP 请求转发为 HTTPS",
        ids::proxy::HTTP_HTTPS,
        ui,
    );
    win32::set_check(http_https, data.enable_http_to_https);
    let tls = pages::checkbox(
        hwnd,
        "允许本地解密 HTTPS 流量（需系统信任本程序的根证书）",
        ids::proxy::TLS_DECRYPT,
        ui,
    );
    win32::set_check(tls, data.enable_tls_decryption);
    let tls_hint = pages::wrap_label(
        hwnd,
        "提示: 关闭后本程序不再解密被代理的 HTTPS，只做端到端转发；Hosts 文件模式不受此开关影响。该开关在重启本程序后生效。",
        ids::proxy::TLS_HINT,
        ui,
    );

    let two_level = pages::checkbox(hwnd, "启用二级代理（外部代理）", ids::proxy::TWO_LEVEL, ui);
    win32::set_check(two_level, data.two_level_enable);
    let type_label = pages::left_label(hwnd, "类型:", ids::proxy::TWO_TYPE_LABEL, ui);
    let type_combo = pages::combo(hwnd, ids::proxy::TWO_TYPE, ui, false);
    win32::combo_fill(type_combo, &["HTTP", "SOCKS4", "SOCKS5"]);
    win32::set_combo_sel(type_combo, state::external_proxy_index(data.two_level_type));
    let ip_label = pages::left_label(hwnd, "地址:", ids::proxy::TWO_IP_LABEL, ui);
    let ip = pages::edit(
        hwnd,
        &data.two_level_ip,
        ids::proxy::TWO_IP,
        ui,
        false,
        false,
    );
    let port2_label = pages::left_label(hwnd, "端口:", ids::proxy::TWO_PORT_LABEL, ui);
    let port2 = pages::edit(
        hwnd,
        &data.two_level_port.to_string(),
        ids::proxy::TWO_PORT,
        ui,
        false,
        false,
    );
    wm::SendMessageW(port2, win32::EM_SETLIMITTEXT, 5, 0);
    let user_label = pages::left_label(hwnd, "用户名:", ids::proxy::TWO_USER_LABEL, ui);
    let user = pages::edit(
        hwnd,
        &data.two_level_user,
        ids::proxy::TWO_USER,
        ui,
        false,
        false,
    );
    let pass_label = pages::left_label(hwnd, "密码:", ids::proxy::TWO_PASS_LABEL, ui);
    let pass = pages::edit(
        hwnd,
        &data.two_level_password,
        ids::proxy::TWO_PASS,
        ui,
        false,
        false,
    );
    wm::SendMessageW(pass, Controls::EM_SETPASSWORDCHAR, 0x2022, 0);

    let ok = create_dialog_button(hwnd, "确定", wm::IDOK, ui, true);
    let cancel = create_dialog_button(hwnd, "取消", wm::IDCANCEL, ui, false);

    win32::place(mode_label, Rect::new(s(16), y(18), s(112), s(24)));
    win32::place(mode, Rect::new(s(136), y(16), s(390), s(200)));
    win32::place(hint, Rect::new(s(16), y(50), s(510), s(34)));
    win32::place(port_label, Rect::new(s(16), y(94), s(112), s(24)));
    win32::place(port, Rect::new(s(136), y(92), s(140), s(26)));
    win32::place(dns_label, Rect::new(s(16), y(128), s(112), s(24)));
    win32::place(dns, Rect::new(s(136), y(126), s(390), s(200)));
    win32::place(use_doh, Rect::new(s(136), y(160), s(390), s(24)));
    win32::place(doh_label, Rect::new(s(16), y(192), s(112), s(24)));
    win32::place(doh, Rect::new(s(136), y(190), s(390), s(200)));
    win32::place(http_https, Rect::new(s(16), y(228), s(510), s(24)));
    win32::place(tls, Rect::new(s(16), y(256), s(510), s(24)));
    win32::place(tls_hint, Rect::new(s(16), y(286), s(510), s(52)));
    win32::place(two_level, Rect::new(s(16), y(348), s(510), s(24)));
    win32::place(type_label, Rect::new(s(16), y(382), s(112), s(24)));
    win32::place(type_combo, Rect::new(s(136), y(380), s(150), s(200)));
    win32::place(ip_label, Rect::new(s(16), y(414), s(112), s(24)));
    win32::place(ip, Rect::new(s(136), y(412), s(228), s(26)));
    win32::place(port2_label, Rect::new(s(372), y(414), s(52), s(24)));
    win32::place(port2, Rect::new(s(426), y(412), s(100), s(26)));
    win32::place(user_label, Rect::new(s(16), y(446), s(112), s(24)));
    win32::place(user, Rect::new(s(136), y(444), s(150), s(26)));
    win32::place(pass_label, Rect::new(s(294), y(446), s(44), s(24)));
    win32::place(pass, Rect::new(s(342), y(444), s(184), s(26)));
    win32::place(
        ok,
        Rect::new(s(560) - s(16) - s(90) - s(10) - s(90), y(500), s(90), s(30)),
    );
    win32::place(
        cancel,
        Rect::new(s(560) - s(16) - s(90), y(500), s(90), s(30)),
    );

    win32::show_all_children(hwnd);
    let state = ProxyState {
        initial: data,
        mode,
        port,
        dns,
        use_doh,
        doh,
        http_https,
        tls,
        two_level,
        two_type: type_combo,
        two_ip: ip,
        two_port: port2,
        two_user: user,
        two_pass: pass,
        labels: [
            type_label,
            ip_label,
            port2_label,
            user_label,
            pass_label,
            tls_hint,
        ],
    };
    toggle_two_level(&state);
    state
}

unsafe fn create_dialog_button(
    hwnd: HWND,
    text: &str,
    id: i32,
    font: Gdi::HFONT,
    default: bool,
) -> HWND {
    let style = if default {
        wm::BS_DEFPUSHBUTTON as u32
    } else {
        wm::BS_PUSHBUTTON as u32
    } | wm::WS_TABSTOP;
    win32::create_control(
        hwnd,
        Controls::WC_BUTTONW,
        text,
        style,
        0,
        id,
        Rect::default(),
        font,
    )
}

unsafe fn toggle_two_level(state: &ProxyState) {
    let on = win32::get_check(state.two_level);
    for h in [
        state.two_type,
        state.two_ip,
        state.two_port,
        state.two_user,
        state.two_pass,
        state.labels[0],
        state.labels[1],
        state.labels[2],
        state.labels[3],
        state.labels[4],
    ] {
        win32::set_visible(h, on);
        win32::set_enabled(h, on);
    }
}

unsafe fn read_proxy(state: &ProxyState) -> ProxyDialogData {
    let mut data = state.initial.clone();
    data.mode = state::mode_from_index(win32::combo_sel(state.mode));
    data.port = state::parse_port(&win32::text(state.port), state.initial.port);
    data.dns = win32::combo_text(state.dns);
    data.use_doh = win32::get_check(state.use_doh);
    data.doh_address = win32::combo_text(state.doh);
    data.enable_http_to_https = win32::get_check(state.http_https);
    data.enable_tls_decryption = win32::get_check(state.tls);
    data.two_level_enable = win32::get_check(state.two_level);
    data.two_level_type = state::external_proxy_from_index(win32::combo_sel(state.two_type));
    data.two_level_ip = win32::text(state.two_ip);
    data.two_level_port =
        state::parse_port(&win32::text(state.two_port), state.initial.two_level_port);
    data.two_level_user = win32::text(state.two_user);
    data.two_level_password = win32::text(state.two_pass);
    data
}

unsafe extern "system" fn cert_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        wm::WM_CREATE => {
            let cs = &*(lparam as *const wm::CREATESTRUCTW);
            let init = Box::from_raw(cs.lpCreateParams as *mut CertInit);
            let CertInit { info, fonts, dpi } = *init;
            let info = info.replace("\r\n", "\n").replace('\n', "\r\n");
            let s = |v: i32| win32::scale(dpi, v);
            let edit = pages::edit(hwnd, &info, ids::cert::INFO, fonts.mono, true, true);
            let close = create_dialog_button(hwnd, "关闭", wm::IDOK, fonts.ui, true);
            win32::place(edit, Rect::new(s(16), s(16), s(488), s(300)));
            win32::place(
                close,
                Rect::new(s(520) - s(16) - s(90), s(330), s(90), s(30)),
            );
            win32::show_all_children(hwnd);
            let state = Box::new(CertState { _fonts: fonts });
            wm::SetWindowLongPtrW(hwnd, wm::GWLP_USERDATA, Box::into_raw(state) as isize);
            CERT.with(|c| c.set(hwnd));
            register_dialog(hwnd);
            0
        }
        wm::WM_COMMAND => {
            let id = win32::wparam_id(wparam);
            if id == wm::IDOK || id == wm::IDCANCEL {
                wm::DestroyWindow(hwnd);
            }
            0
        }
        wm::WM_CLOSE => {
            wm::DestroyWindow(hwnd);
            0
        }
        wm::WM_CTLCOLORSTATIC => {
            let hdc = wparam as Gdi::HDC;
            let child = lparam as HWND;
            if win32::is_ctrl_id(child, ids::cert::INFO) {
                Gdi::SetTextColor(hdc, 0);
                Gdi::SetBkColor(hdc, 0x00FF_FFFF);
                Gdi::GetSysColorBrush(Gdi::COLOR_WINDOW) as LRESULT
            } else {
                Gdi::SetTextColor(hdc, 0);
                Gdi::GetSysColorBrush(Gdi::COLOR_BTNFACE) as LRESULT
            }
        }
        wm::WM_NCDESTROY => {
            let ptr = wm::GetWindowLongPtrW(hwnd, wm::GWLP_USERDATA) as *mut CertState;
            if !ptr.is_null() {
                drop(Box::from_raw(ptr));
                wm::SetWindowLongPtrW(hwnd, wm::GWLP_USERDATA, 0);
            }
            CERT.with(|c| {
                if c.get() == hwnd {
                    c.set(std::ptr::null_mut());
                }
            });
            unregister_dialog(hwnd);
            wm::DefWindowProcW(hwnd, msg, wparam, lparam)
        }
        _ => wm::DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}
