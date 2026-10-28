//! Bottom-centre transient message: a rounded dark card with a coloured
//! accent, wrapping long text, hidden after three seconds.

use std::cell::Cell;

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi;
use windows_sys::Win32::UI::WindowsAndMessaging as wm;

use crate::win32::{self, wide};

const CLASS: windows_sys::core::PCWSTR = windows_sys::core::w!("WtliteToast");
const TIMER_TOAST: usize = 1;
const BG: u32 = win32::rgb(42, 45, 51);
const ACCENT: u32 = win32::rgb(78, 186, 126);
const TEXT: u32 = win32::rgb(245, 247, 250);

thread_local! {
    static DARK_BRUSH: Cell<Gdi::HBRUSH> = const { Cell::new(std::ptr::null_mut()) };
    static TOAST_FONT: Cell<Gdi::HFONT> = const { Cell::new(std::ptr::null_mut()) };
    // (bar x, bar width, left text padding, right text padding)
    static GEOM: Cell<(i32, i32, i32, i32)> = const { Cell::new((10, 4, 24, 14)) };
}

unsafe extern "system" fn toast_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        wm::WM_PAINT => {
            let (hdc, ps) = win32::begin_paint(hwnd);
            let r = win32::client_rect(hwnd);
            let text = win32::text(hwnd);
            let accent_color = if text.contains("失败") || text.contains("错误") {
                win32::rgb(226, 94, 94)
            } else if text.contains("停止") {
                win32::rgb(232, 160, 72)
            } else {
                ACCENT
            };
            let (bar_x, bar_w, pad_left, pad_right) = GEOM.with(|g| g.get());

            let bar_y = (r.h / 5).max(8);
            let bar_h = (r.h - bar_y * 2).max(1);
            let accent = Gdi::CreateSolidBrush(accent_color);
            let bar = RECT {
                left: bar_x,
                top: bar_y,
                right: bar_x + bar_w,
                bottom: bar_y + bar_h,
            };
            Gdi::FillRect(hdc, &bar, accent);
            Gdi::DeleteObject(accent as Gdi::HGDIOBJ);

            let font = wm::SendMessageW(hwnd, wm::WM_GETFONT, 0, 0) as Gdi::HFONT;
            let old_font = if font.is_null() {
                std::ptr::null_mut()
            } else {
                Gdi::SelectObject(hdc, font as Gdi::HGDIOBJ)
            };
            let text_w = wide(&text);
            let right = (r.w - pad_right).max(pad_left + 10);
            let mut calc = RECT {
                left: pad_left,
                top: 0,
                right,
                bottom: 0,
            };
            Gdi::DrawTextW(
                hdc,
                text_w.as_ptr(),
                -1,
                &mut calc,
                Gdi::DT_CALCRECT | Gdi::DT_WORDBREAK,
            );
            let text_h = (calc.bottom - calc.top).max(1);
            let top = ((r.h - text_h) / 2).max(6);
            let mut rc = RECT {
                left: pad_left,
                top,
                right,
                bottom: (r.h - 6).max(top + 1),
            };
            Gdi::SetBkMode(hdc, Gdi::OPAQUE as i32);
            Gdi::SetBkColor(hdc, BG);
            Gdi::SetTextColor(hdc, TEXT);
            Gdi::DrawTextW(
                hdc,
                text_w.as_ptr(),
                -1,
                &mut rc,
                Gdi::DT_LEFT | Gdi::DT_WORDBREAK | Gdi::DT_END_ELLIPSIS,
            );
            if !old_font.is_null() {
                Gdi::SelectObject(hdc, old_font);
            }
            win32::end_paint(hwnd, &ps);
            0
        }
        wm::WM_SETFONT => {
            TOAST_FONT.with(|f| f.set(wparam as Gdi::HFONT));
            Gdi::InvalidateRect(hwnd, std::ptr::null(), 1);
            0
        }
        wm::WM_GETFONT => TOAST_FONT.with(|f| f.get()) as LRESULT,
        wm::WM_TIMER => {
            wm::KillTimer(hwnd, TIMER_TOAST);
            wm::ShowWindow(hwnd, wm::SW_HIDE);
            0
        }
        wm::WM_NCHITTEST => wm::HTTRANSPARENT as LRESULT,
        wm::WM_ERASEBKGND => {
            let hdc = wparam as Gdi::HDC;
            let r = win32::client_rect(hwnd);
            let brush = DARK_BRUSH.with(|b| b.get());
            if !brush.is_null() {
                win32::fill(hdc, &r, brush);
            }
            1
        }
        wm::WM_DESTROY => {
            wm::KillTimer(hwnd, TIMER_TOAST);
            0
        }
        _ => wm::DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

pub unsafe fn register() -> bool {
    let brush = Gdi::CreateSolidBrush(BG);
    DARK_BRUSH.with(|b| b.set(brush));
    let mut wc: wm::WNDCLASSEXW = std::mem::zeroed();
    wc.cbSize = std::mem::size_of::<wm::WNDCLASSEXW>() as u32;
    wc.lpfnWndProc = Some(toast_proc);
    wc.hInstance = win32::hinstance();
    wc.hCursor = wm::LoadCursorW(std::ptr::null_mut(), wm::IDC_ARROW);
    wc.hbrBackground = brush;
    wc.lpszClassName = CLASS;
    wm::RegisterClassExW(&wc) != 0
}

pub unsafe fn create(owner: HWND) -> HWND {
    let hwnd = wm::CreateWindowExW(
        wm::WS_EX_TOOLWINDOW | wm::WS_EX_NOACTIVATE | wm::WS_EX_TRANSPARENT,
        CLASS,
        std::ptr::null(),
        wm::WS_POPUP,
        0,
        0,
        10,
        10,
        owner,
        std::ptr::null_mut(),
        win32::hinstance(),
        std::ptr::null(),
    );
    if !hwnd.is_null() {
        // Let DWM round top-level popups with anti-aliased corners. On systems
        // without corner support this is a no-op and the card keeps square
        // (still crisp) corners.
        let pref: i32 = windows_sys::Win32::Graphics::Dwm::DWMWCP_ROUND;
        windows_sys::Win32::Graphics::Dwm::DwmSetWindowAttribute(
            hwnd,
            windows_sys::Win32::Graphics::Dwm::DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            &pref as *const i32 as *const core::ffi::c_void,
            std::mem::size_of::<i32>() as u32,
        );
    }
    hwnd
}

pub unsafe fn show(main: HWND, toast: HWND, text: &str, font: Gdi::HFONT, dpi: u32) {
    if toast.is_null() {
        return;
    }
    win32::set_text(toast, text);
    wm::SendMessageW(toast, win32::WM_SETFONT, font as usize, 1);

    let bar_x = win32::scale(dpi, 10);
    let bar_w = win32::scale(dpi, 4);
    let pad_left = bar_x + bar_w + win32::scale(dpi, 10);
    let pad_right = win32::scale(dpi, 14);
    GEOM.with(|g| g.set((bar_x, bar_w, pad_left, pad_right)));

    let hdc = Gdi::GetDC(toast);
    let old = Gdi::SelectObject(hdc, font as Gdi::HGDIOBJ);
    let text_w = win32::text_width(hdc, text);

    let client = win32::client_rect(main);
    let max_w = (client.w - win32::scale(dpi, 40))
        .min(win32::scale(dpi, 560))
        .max(win32::scale(dpi, 260));
    let min_w = win32::scale(dpi, 260).min(max_w);
    let desired = text_w + pad_left + pad_right;
    let (w, h) = if desired <= max_w {
        (desired.max(min_w), win32::scale(dpi, 42))
    } else {
        let w = max_w;
        let text_area = (w - pad_left - pad_right).max(40);
        let text_u16 = wide(text);
        let mut calc = RECT {
            left: 0,
            top: 0,
            right: text_area,
            bottom: 0,
        };
        Gdi::DrawTextW(
            hdc,
            text_u16.as_ptr(),
            -1,
            &mut calc,
            Gdi::DT_CALCRECT | Gdi::DT_WORDBREAK,
        );
        let h = ((calc.bottom - calc.top) + win32::scale(dpi, 20))
            .clamp(win32::scale(dpi, 42), win32::scale(dpi, 96));
        (w, h)
    };
    Gdi::SelectObject(hdc, old);
    Gdi::ReleaseDC(toast, hdc);

    let mut origin = windows_sys::Win32::Foundation::POINT { x: 0, y: 0 };
    Gdi::ClientToScreen(main, &mut origin);
    let x = origin.x + (client.w - w) / 2;
    let y = origin.y + client.h - h - win32::scale(dpi, 44);
    wm::SetWindowPos(
        toast,
        std::ptr::null_mut(),
        x,
        y,
        w.min(client.w),
        h,
        wm::SWP_NOZORDER | wm::SWP_NOACTIVATE | wm::SWP_SHOWWINDOW,
    );
    Gdi::InvalidateRect(toast, std::ptr::null(), 1);
    wm::ShowWindow(toast, wm::SW_SHOWNOACTIVATE);
    wm::SetTimer(toast, TIMER_TOAST, 3000, None);
}

pub unsafe fn hide(toast: HWND) {
    if !toast.is_null() {
        wm::KillTimer(toast, TIMER_TOAST);
        wm::ShowWindow(toast, wm::SW_HIDE);
    }
}

pub unsafe fn cleanup() {
    TOAST_FONT.with(|f| f.set(std::ptr::null_mut()));
    DARK_BRUSH.with(|b| {
        let brush = b.replace(std::ptr::null_mut());
        if !brush.is_null() {
            Gdi::DeleteObject(brush as Gdi::HGDIOBJ);
        }
    });
}
