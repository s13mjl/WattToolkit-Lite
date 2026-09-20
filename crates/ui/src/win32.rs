//! Minimal Win32 window show/hide helpers.
//!
//! `SW_HIDE` gives a real tray-style hide (no taskbar button, no Alt+Tab entry),
//! but it also stops winit from delivering events - eframe then never calls
//! `App::update` again, so the tray channels cannot be drained from the UI
//! (verified with a frame heartbeat: frames froze at 6 while hidden and the
//! window could never be restored). The tray event loop therefore lives on its
//! own thread (see the loader), which calls back into these helpers.

#![cfg(windows)]

use std::sync::OnceLock;

#[link(name = "user32")]
extern "system" {
    fn ShowWindow(hwnd: *mut core::ffi::c_void, cmd: i32) -> i32;
    fn SetForegroundWindow(hwnd: *mut core::ffi::c_void) -> i32;
    fn IsWindowVisible(hwnd: *mut core::ffi::c_void) -> i32;
    fn BringWindowToTop(hwnd: *mut core::ffi::c_void) -> i32;
}

const SW_HIDE: i32 = 0;
const SW_SHOW: i32 = 5;
const SW_RESTORE: i32 = 9;

static HWND: OnceLock<usize> = OnceLock::new();

/// Remember the main window handle (called once, from the first update frame).
pub fn remember(hwnd: usize) {
    let _ = HWND.set(hwnd);
}

/// The captured handle, if any (shared with the tray thread).
pub fn handle() -> Option<usize> {
    HWND.get().copied()
}

/// True once the HWND has been captured.
pub fn has_handle() -> bool {
    HWND.get().is_some()
}

fn hwnd() -> Option<*mut core::ffi::c_void> {
    HWND.get().map(|h| *h as *mut core::ffi::c_void)
}

/// Hide the window to the tray (X button).
pub fn hide() -> bool {
    match hwnd() {
        Some(h) => unsafe {
            ShowWindow(h, SW_HIDE);
            IsWindowVisible(h) == 0
        },
        None => false,
    }
}

/// Restore + focus the window from the tray.
pub fn show() -> bool {
    match hwnd() {
        Some(h) => unsafe {
            ShowWindow(h, SW_RESTORE);
            ShowWindow(h, SW_SHOW);
            BringWindowToTop(h);
            SetForegroundWindow(h);
            IsWindowVisible(h) != 0
        },
        None => false,
    }
}

/// Is the main window currently on screen?
pub fn is_visible() -> bool {
    match hwnd() {
        Some(h) => unsafe { IsWindowVisible(h) != 0 },
        None => false,
    }
}
