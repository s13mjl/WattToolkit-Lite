//! System tray icon via Shell_NotifyIconW (no extra thread, no crate).

use std::cell::RefCell;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Shell;
use windows_sys::Win32::UI::WindowsAndMessaging as wm;

use crate::ids;
use crate::win32::{self, wide};

const TRAY_ID: u32 = 1;
const TOOLTIP: &str = "WattToolkit-Lite";

struct TrayState {
    hwnd: HWND,
    icon: wm::HICON,
    menu: wm::HMENU,
    taskbar_created: u32,
    enabled: bool,
}

thread_local! {
    static TRAY: RefCell<Option<TrayState>> = const { RefCell::new(None) };
}

fn notify_data(hwnd: HWND, icon: wm::HICON) -> Shell::NOTIFYICONDATAW {
    let mut nid: Shell::NOTIFYICONDATAW = unsafe { std::mem::zeroed() };
    nid.cbSize = std::mem::size_of::<Shell::NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = TRAY_ID;
    nid.uFlags = Shell::NIF_MESSAGE | Shell::NIF_ICON | Shell::NIF_TIP;
    nid.uCallbackMessage = win32::WM_APP_TRAY;
    nid.hIcon = icon;
    let tip = wide(TOOLTIP);
    let n = tip.len().min(nid.szTip.len());
    nid.szTip[..n].copy_from_slice(&tip[..n]);
    nid
}

unsafe fn add_icon(hwnd: HWND, icon: wm::HICON) -> bool {
    let nid = notify_data(hwnd, icon);
    Shell::Shell_NotifyIconW(Shell::NIM_ADD, &nid) != 0
}

unsafe fn remove_icon(hwnd: HWND, icon: wm::HICON) {
    let mut nid = notify_data(hwnd, icon);
    nid.uFlags = 0;
    Shell::Shell_NotifyIconW(Shell::NIM_DELETE, &nid);
}

pub unsafe fn init(hwnd: HWND, icon: wm::HICON, want_enabled: bool) -> bool {
    let menu = wm::CreatePopupMenu();
    if !menu.is_null() {
        let show = wide("显示主窗口");
        let exit = wide("退出");
        wm::AppendMenuW(menu, wm::MF_STRING, ids::TRAY_SHOW, show.as_ptr());
        wm::AppendMenuW(menu, wm::MF_SEPARATOR, 0, std::ptr::null());
        wm::AppendMenuW(menu, wm::MF_STRING, ids::TRAY_EXIT, exit.as_ptr());
    }
    let taskbar_created = wm::RegisterWindowMessageW(windows_sys::core::w!("TaskbarCreated"));
    let enabled = want_enabled && add_icon(hwnd, icon);
    TRAY.with(|t| {
        *t.borrow_mut() = Some(TrayState {
            hwnd,
            icon,
            menu,
            taskbar_created,
            enabled,
        })
    });
    enabled
}

pub unsafe fn set_enabled(want: bool) -> bool {
    TRAY.with(|t| {
        let mut guard = t.borrow_mut();
        let Some(state) = guard.as_mut() else {
            return false;
        };
        if want {
            if !state.enabled {
                state.enabled = add_icon(state.hwnd, state.icon);
            }
        } else if state.enabled {
            remove_icon(state.hwnd, state.icon);
            state.enabled = false;
        }
        state.enabled
    })
}

pub unsafe fn readd_if_enabled() {
    TRAY.with(|t| {
        let mut guard = t.borrow_mut();
        if let Some(state) = guard.as_mut() {
            if state.enabled {
                add_icon(state.hwnd, state.icon);
            }
        }
    });
}

pub fn taskbar_created_message() -> u32 {
    TRAY.with(|t| t.borrow().as_ref().map_or(0, |s| s.taskbar_created))
}

/// Show the right-click menu; returns the chosen command ID (0 = none).
pub unsafe fn show_menu() -> usize {
    let (hwnd, menu) = TRAY.with(|t| {
        t.borrow()
            .as_ref()
            .map_or((std::ptr::null_mut(), std::ptr::null_mut()), |s| (s.hwnd, s.menu))
    });
    if hwnd.is_null() || menu.is_null() {
        return 0;
    }
    let mut pt = windows_sys::Win32::Foundation::POINT { x: 0, y: 0 };
    wm::GetCursorPos(&mut pt);
    wm::SetForegroundWindow(hwnd);
    let cmd = wm::TrackPopupMenu(
        menu,
        wm::TPM_RIGHTBUTTON | wm::TPM_RETURNCMD | wm::TPM_NONOTIFY,
        pt.x,
        pt.y,
        0,
        hwnd,
        std::ptr::null(),
    );
    wm::PostMessageW(hwnd, wm::WM_NULL, 0, 0);
    cmd as usize
}

pub unsafe fn cleanup() {
    TRAY.with(|t| {
        let Some(state) = t.borrow_mut().take() else {
            return;
        };
        if state.enabled {
            remove_icon(state.hwnd, state.icon);
        }
        if !state.menu.is_null() {
            wm::DestroyMenu(state.menu);
        }
    });
}
