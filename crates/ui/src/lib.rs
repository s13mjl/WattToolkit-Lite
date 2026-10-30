//! WattToolkit-Lite native Win32 frontend.
//!
//! A single UI thread owns every window, control and GDI object. Background
//! work is limited to the proxy engine (which owns its own runtime) and the
//! transient network-test runtime. No UI framework, GPU context, webview or
//! font file is loaded, which is what keeps the footprint small.

#![cfg(windows)]

mod actions;
mod app;
mod dialogs;
mod ids;
mod pages;
mod state;
mod toast;
mod tray;
mod types;
mod ui;
mod win32;

use std::cell::{Cell, RefCell};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::Graphics::Gdi;
use windows_sys::Win32::UI::Controls;
use windows_sys::Win32::UI::WindowsAndMessaging as wm;

use app::App;

pub struct IconData {
    pub rgba: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

const WM_APP_INIT_SYNC: u32 = wm::WM_APP + 3;

thread_local! {
    static APP: RefCell<Option<Box<App>>> = const { RefCell::new(None) };
    static DARK_BRUSH: Cell<Gdi::HBRUSH> = const { Cell::new(std::ptr::null_mut()) };
    static LAST_MOUSE_DOWN: Cell<(usize, Instant)> =
        Cell::new((0, Instant::now()));
}

/// Record the target of a real (posted) mouse-down. Tree check notifications
/// caused by TVM_SETITEM are indistinguishable from user clicks except for this
/// provenance, so only a notification following a click on that tree is applied.
pub(crate) fn note_mouse_down(hwnd: HWND) {
    LAST_MOUSE_DOWN.with(|c| c.set((hwnd as usize, Instant::now())));
}

pub(crate) fn take_tree_click(hwnd: HWND) -> bool {
    LAST_MOUSE_DOWN.with(|c| {
        let (last, at) = c.get();
        if last == hwnd as usize && at.elapsed() < Duration::from_secs(2) {
            c.set((0, Instant::now()));
            true
        } else {
            false
        }
    })
}

pub(crate) fn with_app<R>(f: impl FnOnce(&mut App) -> R) -> Option<R> {
    APP.with(|cell| {
        let mut guard = cell.try_borrow_mut().ok()?;
        let app = guard.as_mut()?;
        Some(f(app))
    })
}

pub(crate) fn drain_actions() {
    for _ in 0..64 {
        let batch = with_app(|a| {
            if a.actions.is_empty() {
                None
            } else {
                Some(std::mem::take(&mut a.actions))
            }
        });
        let Some(Some(batch)) = batch else {
            break;
        };
        for action in batch {
            actions::execute(action);
        }
    }
}

pub(crate) fn hide_to_tray() {
    let Some((main, toast)) = with_app(|a| {
        a.hidden_to_tray = true;
        (a.hwnd, a.ui.toast)
    }) else {
        return;
    };
    unsafe {
        toast::hide(toast);
        dialogs::hide_all();
        wm::ShowWindow(main, wm::SW_HIDE);
    }
    log::info!("window hidden to tray");
}

pub(crate) fn restore_window() {
    let Some((main, toast)) = with_app(|a| {
        a.hidden_to_tray = false;
        (a.hwnd, a.ui.toast)
    }) else {
        return;
    };
    unsafe {
        wm::ShowWindow(main, wm::SW_RESTORE);
        wm::ShowWindow(main, wm::SW_SHOW);
        wm::SetForegroundWindow(main);
        toast::hide(toast);
    }
    unsafe {
        dialogs::show_all();
    }
    with_app(|a| unsafe { a.layout() });
    unsafe { wm::PostMessageW(main, WM_APP_INIT_SYNC, 0, 0) };
    log::info!("window restored from tray");
}

pub(crate) fn request_exit() {
    let proxy = with_app(|a| a.proxy.clone());
    if let Some(proxy) = proxy {
        proxy.stop();
    }
    unsafe {
        tray::cleanup();
    }
    let main = with_app(|a| a.hwnd).unwrap_or(std::ptr::null_mut());
    if !main.is_null() {
        unsafe {
            wm::KillTimer(main, win32::TIMER_UI);
            wm::DestroyWindow(main);
        }
    }
    log::info!("exiting");
}

unsafe fn force_repaint_all(hwnd: HWND) {
    Gdi::RedrawWindow(
        hwnd,
        std::ptr::null(),
        std::ptr::null_mut(),
        Gdi::RDW_INVALIDATE | Gdi::RDW_UPDATENOW | Gdi::RDW_ALLCHILDREN,
    );
}

unsafe fn ctl_color_static(wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let hdc = wparam as Gdi::HDC;
    let child = lparam as HWND;
    let id = wm::GetDlgCtrlID(child);
    if id == ids::LOGS_EDIT {
        Gdi::SetTextColor(hdc, win32::rgb(222, 226, 232));
        Gdi::SetBkColor(hdc, win32::rgb(33, 36, 43));
        return DARK_BRUSH.with(|b| b.get()) as LRESULT;
    }
    if id == ids::STATUS {
        Gdi::SetTextColor(
            hdc,
            if app::status_running() {
                win32::COLOR_RUNNING
            } else {
                win32::COLOR_STOPPED
            },
        );
    } else if id == ids::ABOUT_UPSTREAM || id == ids::ABOUT_SECONDARY {
        Gdi::SetTextColor(hdc, win32::COLOR_LINK);
    } else {
        Gdi::SetTextColor(hdc, 0);
    }
    // Title/status sit on the window background; every other label sits on the
    // white tab page.
    if id == ids::TITLE || id == ids::STATUS {
        Gdi::SetBkColor(hdc, Gdi::GetSysColor(Gdi::COLOR_BTNFACE));
        Gdi::GetSysColorBrush(Gdi::COLOR_BTNFACE) as LRESULT
    } else {
        Gdi::SetBkColor(hdc, 0x00FF_FFFF);
        Gdi::GetSysColorBrush(Gdi::COLOR_WINDOW) as LRESULT
    }
}

unsafe fn ctl_color_edit(wparam: WPARAM) -> LRESULT {
    let hdc = wparam as Gdi::HDC;
    Gdi::SetTextColor(hdc, 0);
    Gdi::SetBkColor(hdc, 0x00FF_FFFF);
    Gdi::GetSysColorBrush(Gdi::COLOR_WINDOW) as LRESULT
}

unsafe extern "system" fn main_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        wm::WM_CREATE => {
            with_app(|app| {
                app.hwnd = hwnd;
                app.build_ui();
            });
            0
        }
        wm::WM_SIZE => {
            with_app(|app| app.layout());
            0
        }
        wm::WM_TIMER if wparam == win32::TIMER_UI => {
            with_app(|app| app.tick());
            0
        }
        wm::WM_COMMAND => {
            if win32::controls::is_suppressed() {
                return 0;
            }
            with_app(|app| app.on_command(wparam, lparam));
            0
        }
        wm::WM_NOTIFY => {
            if win32::controls::is_suppressed() {
                return 0;
            }
            with_app(|app| app.on_notify(lparam)).unwrap_or(0)
        }
        wm::WM_CTLCOLORSTATIC => ctl_color_static(wparam, lparam),
        wm::WM_CTLCOLOREDIT => ctl_color_edit(wparam),
        wm::WM_CLOSE => {
            with_app(|app| app.on_close());
            0
        }
        wm::WM_GETMINMAXINFO => {
            let info = &mut *(lparam as *mut wm::MINMAXINFO);
            let (w, h) = win32::min_track_size(win32::dpi());
            info.ptMinTrackSize.x = w;
            info.ptMinTrackSize.y = h;
            0
        }
        WM_APP_INIT_SYNC => {
            // First paint initialises the tree state image list and discards
            // check images set while the window was hidden; paint once, apply
            // the model, then paint again.
            force_repaint_all(hwnd);
            with_app(|a| unsafe {
                pages::accelerator::sync_checks(a);
                win32::invalidate(a.ui.platform_tree);
                win32::invalidate(a.ui.services_tree);
            });
            force_repaint_all(hwnd);
            0
        }
        win32::WM_APP_TRAY => {
            let event = (lparam as u32) & 0xffff;
            if event == wm::WM_LBUTTONUP || event == wm::WM_LBUTTONDBLCLK {
                with_app(|app| app.queue(actions::Action::RestoreWindow));
            } else if event == wm::WM_RBUTTONUP {
                with_app(|app| app.queue(actions::Action::TrayMenu));
            }
            0
        }
        wm::WM_DESTROY => {
            tray::cleanup();
            wm::KillTimer(hwnd, win32::TIMER_UI);
            wm::PostQuitMessage(0);
            0
        }
        _ => {
            if msg == tray::taskbar_created_message() && msg != 0 {
                tray::readd_if_enabled();
                0
            } else {
                wm::DefWindowProcW(hwnd, msg, wparam, lparam)
            }
        }
    }
}

pub fn run(icon: IconData) -> Result<(), String> {
    unsafe {
        let icc = Controls::ICC_WIN95_CLASSES
            | Controls::ICC_TAB_CLASSES
            | Controls::ICC_LISTVIEW_CLASSES
            | Controls::ICC_TREEVIEW_CLASSES
            | Controls::ICC_STANDARD_CLASSES;
        let init = Controls::INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<Controls::INITCOMMONCONTROLSEX>() as u32,
            dwICC: icc,
        };
        Controls::InitCommonControlsEx(&init);

        let app = Box::new(App::new(icon)?);
        let icon_big = app.icons.window;
        let icon_small = app.icons.small;
        let icon_tray = app.icons.tray;
        let main_class = windows_sys::core::w!("WtliteMain");
        if !win32::register_class(main_class, Some(main_proc), icon_big, icon_small) {
            return Err("RegisterClassExW(WtliteMain) failed".into());
        }
        if !toast::register() {
            return Err("RegisterClassExW(WtliteToast) failed".into());
        }
        if !dialogs::register() {
            return Err("RegisterClassExW(dialog) failed".into());
        }

        let dpi = app.dpi;
        APP.with(|cell| *cell.borrow_mut() = Some(app));
        DARK_BRUSH.with(|b| b.set(Gdi::CreateSolidBrush(win32::rgb(33, 36, 43))));

        let (ow, oh) = win32::adjusted_window_size(960, 680, dpi);
        let (sw, sh) = win32::screen_size();
        let title = win32::wide("WattToolkit-Lite");
        let hwnd = wm::CreateWindowExW(
            wm::WS_EX_CONTROLPARENT,
            main_class,
            title.as_ptr(),
            wm::WS_OVERLAPPEDWINDOW | wm::WS_CLIPCHILDREN,
            (sw - ow) / 2,
            (sh - oh) / 2,
            ow,
            oh,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            win32::hinstance(),
            std::ptr::null(),
        );
        if hwnd.is_null() {
            let _ = APP.with(|cell| cell.borrow_mut().take());
            return Err("CreateWindowExW(WtliteMain) failed".into());
        }
        win32::set_window_icons(hwnd, icon_big, icon_small);

        let toast_hwnd = toast::create(hwnd);
        with_app(|a| a.ui.toast = toast_hwnd);

        let want_tray = with_app(|a| a.settings.general.tray_icon).unwrap_or(true);
        let tray_enabled = tray::init(hwnd, icon_tray, want_tray);
        with_app(|a| a.tray_enabled = tray_enabled);

        with_app(|a| a.layout());
        wm::SetTimer(hwnd, win32::TIMER_UI, 300, None);

        let minimize =
            with_app(|a| a.settings.general.minimize_on_startup && a.tray_enabled).unwrap_or(false);
        if minimize {
            with_app(|a| a.hidden_to_tray = true);
        } else {
            wm::ShowWindow(hwnd, wm::SW_SHOW);
            wm::SetForegroundWindow(hwnd);
            // The tree's first paint can reset check-state images set while the
            // window was hidden; reapply them as soon as the window is visible.
            wm::PostMessageW(hwnd, WM_APP_INIT_SYNC, 0, 0);
        }
        drain_actions();

        let mut msg: wm::MSG = std::mem::zeroed();
        loop {
            let r = wm::GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0);
            if r == 0 {
                break;
            }
            if r == -1 {
                log::error!("GetMessageW failed");
                break;
            }
            if msg.message == wm::WM_LBUTTONDOWN {
                note_mouse_down(msg.hwnd);
            }
            let mut handled = 0;
            for d in dialogs::all() {
                if !d.is_null()
                    && wm::IsWindow(d) != 0
                    && (msg.hwnd == d || wm::IsChild(d, msg.hwnd) != 0)
                {
                    handled = wm::IsDialogMessageW(d, &msg);
                    break;
                }
            }
            if handled == 0 {
                handled = wm::IsDialogMessageW(hwnd, &msg);
            }
            if handled == 0 {
                wm::TranslateMessage(&msg);
                wm::DispatchMessageW(&msg);
            }
            drain_actions();
        }

        tray::cleanup();
        let app = APP.with(|cell| cell.borrow_mut().take());
        drop(app);
        toast::cleanup();
        DARK_BRUSH.with(|b| {
            let brush = b.replace(std::ptr::null_mut());
            if !brush.is_null() {
                Gdi::DeleteObject(brush as Gdi::HGDIOBJ);
            }
        });
        Ok(())
    }
}
