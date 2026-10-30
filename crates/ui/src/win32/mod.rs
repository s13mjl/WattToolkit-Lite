//! Thin, allocation-light wrappers over the Win32 APIs used by the UI.
//!
//! Everything here is unsafe FFI; callers are the single UI thread.

#![allow(non_snake_case)]

pub mod controls;

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{HWND, LPARAM, RECT, WPARAM};
use windows_sys::Win32::Graphics::Gdi;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::Shell;
use windows_sys::Win32::UI::WindowsAndMessaging as wm;

pub const WM_SETFONT: u32 = 0x0030;
pub const EM_SETLIMITTEXT: u32 = 0x00C5;

pub const COLOR_BTNFACE_IDX: i32 = Gdi::COLOR_BTNFACE;

pub const WM_APP_TRAY: u32 = wm::WM_APP + 2;
pub const TIMER_UI: usize = 1;

#[inline]
pub const fn rgb(r: u8, g: u8, b: u8) -> u32 {
    r as u32 | ((g as u32) << 8) | ((b as u32) << 16)
}

pub const COLOR_RUNNING: u32 = 0x0000_8C00; // rgb(0,140,0)
pub const COLOR_STOPPED: u32 = 0x0078_7878; // rgb(120,120,120)
pub const COLOR_LINK: u32 = 0x00A0_5A00; // rgb(0,90,160)

pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[inline]
pub fn scale(dpi: u32, v: i32) -> i32 {
    (v as i64 * dpi as i64 / 96) as i32
}

#[inline]
fn pt_px(pt: i32, dpi: u32) -> i32 {
    -((pt as i64 * dpi as i64 + 36) / 72) as i32
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub w: i32,
    pub h: i32,
}

impl Rect {
    pub const fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self { x, y, w, h }
    }

    pub fn right(&self) -> i32 {
        self.x + self.w
    }

    pub fn bottom(&self) -> i32 {
        self.y + self.h
    }

    pub fn inset(&self, d: i32) -> Self {
        Self::new(
            self.x + d,
            self.y + d,
            (self.w - d * 2).max(0),
            (self.h - d * 2).max(0),
        )
    }

    pub fn to_win_rect(&self) -> RECT {
        RECT {
            left: self.x,
            top: self.y,
            right: self.right(),
            bottom: self.bottom(),
        }
    }
}

impl From<Rect> for RECT {
    fn from(r: Rect) -> Self {
        r.to_win_rect()
    }
}

pub unsafe fn hinstance() -> *mut c_void {
    GetModuleHandleW(std::ptr::null())
}

pub unsafe fn class_background() -> Gdi::HBRUSH {
    (COLOR_BTNFACE_IDX + 1) as usize as Gdi::HBRUSH
}

pub unsafe fn register_class(
    name: windows_sys::core::PCWSTR,
    proc_: wm::WNDPROC,
    icon: wm::HICON,
    icon_small: wm::HICON,
) -> bool {
    let mut wc: wm::WNDCLASSEXW = std::mem::zeroed();
    wc.cbSize = std::mem::size_of::<wm::WNDCLASSEXW>() as u32;
    wc.style = wm::CS_HREDRAW | wm::CS_VREDRAW;
    wc.lpfnWndProc = proc_;
    wc.hInstance = hinstance();
    wc.hIcon = icon;
    wc.hIconSm = icon_small;
    wc.hCursor = wm::LoadCursorW(std::ptr::null_mut(), wm::IDC_ARROW);
    wc.hbrBackground = class_background();
    wc.lpszClassName = name;
    wm::RegisterClassExW(&wc) != 0
}

pub unsafe fn create_control(
    parent: HWND,
    class: windows_sys::core::PCWSTR,
    text: &str,
    style: u32,
    ex_style: u32,
    id: i32,
    r: Rect,
    font: Gdi::HFONT,
) -> HWND {
    let text_w = wide(text);
    let h = wm::CreateWindowExW(
        ex_style,
        class,
        text_w.as_ptr(),
        wm::WS_CHILD | wm::WS_CLIPSIBLINGS | style,
        r.x,
        r.y,
        r.w,
        r.h,
        parent,
        id as usize as wm::HMENU,
        hinstance(),
        std::ptr::null(),
    );
    if !h.is_null() && !font.is_null() {
        wm::SendMessageW(h, WM_SETFONT, font as usize, 1);
    }
    h
}

pub unsafe fn set_font(hwnd: HWND, font: Gdi::HFONT) {
    wm::SendMessageW(hwnd, WM_SETFONT, font as usize, 1);
}

pub unsafe fn send_to_bottom(hwnd: HWND) {
    if hwnd.is_null() {
        return;
    }
    // HWND_BOTTOM == (HWND)1
    wm::SetWindowPos(
        hwnd,
        1 as HWND,
        0,
        0,
        0,
        0,
        wm::SWP_NOMOVE | wm::SWP_NOSIZE | wm::SWP_NOACTIVATE,
    );
}

pub unsafe fn place(hwnd: HWND, r: Rect) {
    wm::SetWindowPos(
        hwnd,
        std::ptr::null_mut(),
        r.x,
        r.y,
        r.w.max(0),
        r.h.max(0),
        wm::SWP_NOZORDER | wm::SWP_NOACTIVATE,
    );
}

pub unsafe fn set_round_region(hwnd: HWND, radius: i32) {
    if hwnd.is_null() || radius <= 0 {
        return;
    }
    let r = client_rect(hwnd);
    if r.w <= 0 || r.h <= 0 {
        return;
    }
    let region = Gdi::CreateRoundRectRgn(0, 0, r.w + 1, r.h + 1, radius * 2, radius * 2);
    if region.is_null() {
        return;
    }
    if Gdi::SetWindowRgn(hwnd, region, 1) == 0 {
        Gdi::DeleteObject(region as Gdi::HGDIOBJ);
    }
}

pub unsafe fn set_edit_padding(hwnd: HWND, left: i32, top: i32, right: i32, bottom: i32) {
    if hwnd.is_null() {
        return;
    }
    let r = client_rect(hwnd);
    let mut rc = RECT {
        left,
        top,
        right: (r.w - right).max(left),
        bottom: (r.h - bottom).max(top),
    };
    wm::SendMessageW(hwnd, Controls::EM_SETRECT, 0, &mut rc as *mut _ as LPARAM);
}

pub unsafe fn set_visible(hwnd: HWND, visible: bool) {
    wm::ShowWindow(hwnd, if visible { wm::SW_SHOWNA } else { wm::SW_HIDE });
}

unsafe extern "system" fn show_child(hwnd: HWND, _lparam: LPARAM) -> i32 {
    wm::ShowWindow(hwnd, wm::SW_SHOWNA);
    1
}

pub unsafe fn show_all_children(parent: HWND) {
    wm::EnumChildWindows(parent, Some(show_child), 0);
}

pub unsafe fn set_enabled(hwnd: HWND, enabled: bool) {
    EnableWindow(hwnd, enabled as i32);
}

pub unsafe fn set_text(hwnd: HWND, text: &str) {
    let w = wide(text);
    wm::SetWindowTextW(hwnd, w.as_ptr());
}

pub unsafe fn text(hwnd: HWND) -> String {
    let len = wm::GetWindowTextLengthW(hwnd);
    if len <= 0 {
        return String::new();
    }
    let mut buf = vec![0u16; len as usize + 1];
    let n = wm::GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

pub unsafe fn set_check(hwnd: HWND, on: bool) {
    wm::SendMessageW(
        hwnd,
        wm::BM_SETCHECK,
        if on {
            Controls::BST_CHECKED as usize
        } else {
            0
        },
        0,
    );
}

pub unsafe fn get_check(hwnd: HWND) -> bool {
    wm::SendMessageW(hwnd, wm::BM_GETCHECK, 0, 0) == Controls::BST_CHECKED as isize
}

pub unsafe fn set_combo_sel(hwnd: HWND, index: i32) {
    wm::SendMessageW(hwnd, wm::CB_SETCURSEL, index as usize, 0);
}

pub unsafe fn combo_sel(hwnd: HWND) -> i32 {
    wm::SendMessageW(hwnd, wm::CB_GETCURSEL, 0, 0) as i32
}

pub unsafe fn combo_set_text(hwnd: HWND, text: &str) {
    set_text(hwnd, text);
}

pub unsafe fn combo_text(hwnd: HWND) -> String {
    text(hwnd)
}

pub unsafe fn combo_fill(hwnd: HWND, items: &[&str]) {
    wm::SendMessageW(hwnd, wm::CB_RESETCONTENT, 0, 0);
    for item in items {
        let w = wide(item);
        wm::SendMessageW(hwnd, wm::CB_ADDSTRING, 0, w.as_ptr() as isize);
    }
}

pub unsafe fn invalidate(hwnd: HWND) {
    Gdi::InvalidateRect(hwnd, std::ptr::null(), 0);
}

pub unsafe fn is_window(hwnd: HWND) -> bool {
    wm::IsWindow(hwnd) != 0
}

pub unsafe fn shell_open(target: &str) -> bool {
    let op = wide("open");
    let file = wide(target);
    let r = Shell::ShellExecuteW(
        std::ptr::null_mut(),
        op.as_ptr(),
        file.as_ptr(),
        std::ptr::null(),
        std::ptr::null(),
        wm::SW_SHOWNORMAL,
    );
    r as isize > 32
}

pub unsafe fn begin_paint(hwnd: HWND) -> (Gdi::HDC, Gdi::PAINTSTRUCT) {
    let mut ps: Gdi::PAINTSTRUCT = std::mem::zeroed();
    let hdc = Gdi::BeginPaint(hwnd, &mut ps);
    (hdc, ps)
}

pub unsafe fn end_paint(hwnd: HWND, ps: &Gdi::PAINTSTRUCT) {
    Gdi::EndPaint(hwnd, ps);
}

pub unsafe fn fill(hdc: Gdi::HDC, r: &Rect, brush: Gdi::HBRUSH) {
    let rc: RECT = (*r).into();
    Gdi::FillRect(hdc, &rc, brush);
}

pub unsafe fn text_width(hdc: Gdi::HDC, text: &str) -> i32 {
    let w = wide(text);
    let mut size = windows_sys::Win32::Foundation::SIZE { cx: 0, cy: 0 };
    Gdi::GetTextExtentPoint32W(hdc, w.as_ptr(), w.len() as i32 - 1, &mut size);
    size.cx
}

pub unsafe fn delete_object(obj: *mut c_void) {
    if !obj.is_null() {
        Gdi::DeleteObject(obj as Gdi::HGDIOBJ);
    }
}

#[derive(Clone, Copy)]
pub struct Fonts {
    pub ui: Gdi::HFONT,
    pub bold: Gdi::HFONT,
    pub button: Gdi::HFONT,
    pub title: Gdi::HFONT,
    pub mono: Gdi::HFONT,
    pub log: Gdi::HFONT,
    pub toast: Gdi::HFONT,
    pub link: Gdi::HFONT,
}

impl Fonts {
    pub unsafe fn new(dpi: u32) -> Self {
        Self {
            ui: make_font(pt_px(9, dpi), 400, "Microsoft YaHei UI", false, false),
            bold: make_font(pt_px(9, dpi), 700, "Microsoft YaHei UI", false, false),
            button: make_font(pt_px(10, dpi), 600, "Microsoft YaHei UI", false, false),
            title: make_font(pt_px(14, dpi), 700, "Microsoft YaHei UI", false, false),
            mono: make_font(pt_px(9, dpi), 400, "Consolas", false, false),
            log: make_font(pt_px(11, dpi), 400, "Microsoft YaHei UI", false, false),
            toast: make_font(pt_px(11, dpi), 400, "Microsoft YaHei UI", false, false),
            link: make_font(pt_px(9, dpi), 400, "Microsoft YaHei UI", true, false),
        }
    }

    pub unsafe fn destroy(&self) {
        for f in [
            self.ui,
            self.bold,
            self.button,
            self.title,
            self.mono,
            self.log,
            self.toast,
            self.link,
        ] {
            delete_object(f);
        }
    }
}

unsafe fn make_font(
    height: i32,
    weight: i32,
    face: &str,
    underline: bool,
    italic: bool,
) -> Gdi::HFONT {
    make_font_quality(
        height,
        weight,
        face,
        underline,
        italic,
        Gdi::CLEARTYPE_QUALITY,
    )
}

unsafe fn make_font_quality(
    height: i32,
    weight: i32,
    face: &str,
    underline: bool,
    italic: bool,
    quality: u8,
) -> Gdi::HFONT {
    let face_w = wide(face);
    Gdi::CreateFontW(
        height,
        0,
        0,
        0,
        weight,
        italic as u32,
        underline as u32,
        0,
        Gdi::DEFAULT_CHARSET as u32,
        Gdi::OUT_DEFAULT_PRECIS as u32,
        Gdi::CLIP_DEFAULT_PRECIS as u32,
        quality as u32,
        0,
        face_w.as_ptr(),
    )
}

pub struct Icons {
    pub window: wm::HICON,
    pub small: wm::HICON,
    pub about: wm::HICON,
    pub tray: wm::HICON,
}

impl Icons {
    pub unsafe fn from_rgba(rgba: &[u8], w: u32, h: u32) -> Result<Self, String> {
        if rgba.len() < (w as usize) * (h as usize) * 4 {
            return Err("icon data is too short".into());
        }
        Ok(Self {
            window: make_hicon(rgba, w, h, 32).ok_or("CreateIconIndirect(32) failed")?,
            small: make_hicon(rgba, w, h, 16).ok_or("CreateIconIndirect(16) failed")?,
            about: make_hicon(rgba, w, h, 64).ok_or("CreateIconIndirect(64) failed")?,
            tray: make_hicon(rgba, w, h, 32).ok_or("CreateIconIndirect(tray) failed")?,
        })
    }

    pub unsafe fn destroy(&self) {
        for h in [self.window, self.small, self.about, self.tray] {
            if !h.is_null() {
                wm::DestroyIcon(h);
            }
        }
    }
}

unsafe fn make_hicon(rgba: &[u8], sw: u32, sh: u32, size: u32) -> Option<wm::HICON> {
    let size = size.max(1);
    let mut pixels = vec![0u8; (size * size * 4) as usize];
    // Box filter down to the requested size.
    for y in 0..size {
        let sy0 = y * sh / size;
        let sy1 = ((y + 1) * sh / size).max(sy0 + 1);
        for x in 0..size {
            let sx0 = x * sw / size;
            let sx1 = ((x + 1) * sw / size).max(sx0 + 1);
            let mut acc = [0u64; 4];
            let mut n = 0u64;
            for sy in sy0..sy1 {
                for sx in sx0..sx1 {
                    let idx = ((sy * sw + sx) * 4) as usize;
                    for c in 0..4 {
                        acc[c] += rgba[idx + c] as u64;
                    }
                    n += 1;
                }
            }
            let n = n.max(1);
            let di = ((y * size + x) * 4) as usize;
            // DIB 32bpp is BGRA.
            pixels[di] = (acc[2] / n) as u8;
            pixels[di + 1] = (acc[1] / n) as u8;
            pixels[di + 2] = (acc[0] / n) as u8;
            pixels[di + 3] = (acc[3] / n) as u8;
        }
    }

    let mut bmi: Gdi::BITMAPINFO = std::mem::zeroed();
    bmi.bmiHeader.biSize = std::mem::size_of::<Gdi::BITMAPINFOHEADER>() as u32;
    bmi.bmiHeader.biWidth = size as i32;
    bmi.bmiHeader.biHeight = -(size as i32);
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = 0; // BI_RGB
    let mut bits: *mut c_void = std::ptr::null_mut();
    let color = Gdi::CreateDIBSection(
        std::ptr::null_mut(),
        &bmi,
        0,
        &mut bits,
        std::ptr::null_mut(),
        0,
    );
    if color.is_null() || bits.is_null() {
        return None;
    }
    std::ptr::copy_nonoverlapping(pixels.as_ptr(), bits as *mut u8, pixels.len());

    let mask = Gdi::CreateBitmap(size as i32, size as i32, 1, 1, std::ptr::null());
    if mask.is_null() {
        Gdi::DeleteObject(color as Gdi::HGDIOBJ);
        return None;
    }
    // All-zero mask: 32bpp alpha decides transparency.
    let mem = Gdi::CreateCompatibleDC(std::ptr::null_mut());
    if !mem.is_null() {
        let old = Gdi::SelectObject(mem, mask as Gdi::HGDIOBJ);
        let black = Gdi::CreateSolidBrush(0);
        let rc = RECT {
            left: 0,
            top: 0,
            right: size as i32,
            bottom: size as i32,
        };
        Gdi::FillRect(mem, &rc, black);
        Gdi::DeleteObject(black as Gdi::HGDIOBJ);
        Gdi::SelectObject(mem, old);
        Gdi::DeleteDC(mem);
    }

    let info = wm::ICONINFO {
        fIcon: 1,
        xHotspot: 0,
        yHotspot: 0,
        hbmMask: mask,
        hbmColor: color,
    };
    let icon = wm::CreateIconIndirect(&info);
    Gdi::DeleteObject(mask as Gdi::HGDIOBJ);
    Gdi::DeleteObject(color as Gdi::HGDIOBJ);
    if icon.is_null() {
        None
    } else {
        Some(icon)
    }
}

pub fn screen_size() -> (i32, i32) {
    unsafe {
        (
            wm::GetSystemMetrics(wm::SM_CXSCREEN),
            wm::GetSystemMetrics(wm::SM_CYSCREEN),
        )
    }
}

pub fn dpi() -> u32 {
    unsafe { windows_sys::Win32::UI::HiDpi::GetDpiForSystem() }
}

pub fn min_track_size(dpi: u32) -> (i32, i32) {
    let mut rc = RECT {
        left: 0,
        top: 0,
        right: scale(dpi, 528),
        bottom: scale(dpi, 508),
    };
    unsafe {
        windows_sys::Win32::UI::HiDpi::AdjustWindowRectExForDpi(
            &mut rc,
            wm::WS_OVERLAPPEDWINDOW,
            0,
            wm::WS_EX_CONTROLPARENT,
            dpi,
        );
    }
    (rc.right - rc.left, rc.bottom - rc.top)
}

pub fn adjusted_window_size(client_w: i32, client_h: i32, dpi: u32) -> (i32, i32) {
    let mut rc = RECT {
        left: 0,
        top: 0,
        right: scale(dpi, client_w),
        bottom: scale(dpi, client_h),
    };
    unsafe {
        windows_sys::Win32::UI::HiDpi::AdjustWindowRectExForDpi(
            &mut rc,
            wm::WS_OVERLAPPEDWINDOW,
            0,
            wm::WS_EX_CONTROLPARENT,
            dpi,
        );
    }
    (rc.right - rc.left, rc.bottom - rc.top)
}

pub unsafe fn client_rect(hwnd: HWND) -> Rect {
    let mut rc: RECT = std::mem::zeroed();
    wm::GetClientRect(hwnd, &mut rc);
    Rect::new(rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top)
}

pub unsafe fn set_window_icons(hwnd: HWND, big: wm::HICON, small: wm::HICON) {
    wm::SendMessageW(hwnd, wm::WM_SETICON, wm::ICON_BIG as usize, big as isize);
    wm::SendMessageW(
        hwnd,
        wm::WM_SETICON,
        wm::ICON_SMALL as usize,
        small as isize,
    );
}

pub fn is_ctrl_id(hwnd: HWND, id: i32) -> bool {
    unsafe { wm::GetDlgCtrlID(hwnd) == id }
}

pub fn wparam_id(wparam: WPARAM) -> i32 {
    (wparam & 0xffff) as i32
}

pub fn wparam_code(wparam: WPARAM) -> u32 {
    ((wparam >> 16) & 0xffff) as u32
}
