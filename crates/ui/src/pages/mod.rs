//! Page build helpers and the two top-level pages.

pub mod accelerator;
pub mod settings;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::Graphics::Gdi::HFONT;
use windows_sys::Win32::System::SystemServices::{
    SS_CENTER, SS_CENTERIMAGE, SS_LEFT, SS_NOTIFY,
};
use windows_sys::Win32::UI::Controls;
use windows_sys::Win32::UI::WindowsAndMessaging as wm;

use crate::win32::{create_control, Rect};

pub unsafe fn label(
    parent: HWND,
    text: &str,
    style: u32,
    id: i32,
    font: HFONT,
) -> HWND {
    create_control(
        parent,
        Controls::WC_STATICW,
        text,
        style,
        0,
        id,
        Rect::default(),
        font,
    )
}

pub unsafe fn left_label(parent: HWND, text: &str, id: i32, font: HFONT) -> HWND {
    label(parent, text, SS_LEFT | SS_CENTERIMAGE, id, font)
}

pub unsafe fn center_label(parent: HWND, text: &str, id: i32, font: HFONT) -> HWND {
    label(parent, text, SS_CENTER | SS_CENTERIMAGE, id, font)
}

pub unsafe fn wrap_label(parent: HWND, text: &str, id: i32, font: HFONT) -> HWND {
    label(parent, text, SS_LEFT, id, font)
}

pub unsafe fn link_label(parent: HWND, text: &str, id: i32, font: HFONT) -> HWND {
    label(parent, text, SS_LEFT | SS_NOTIFY | SS_CENTERIMAGE, id, font)
}

pub unsafe fn button(parent: HWND, text: &str, id: i32, font: HFONT) -> HWND {
    create_control(
        parent,
        Controls::WC_BUTTONW,
        text,
        wm::BS_PUSHBUTTON as u32 | wm::WS_TABSTOP,
        0,
        id,
        Rect::default(),
        font,
    )
}

pub unsafe fn checkbox(parent: HWND, text: &str, id: i32, font: HFONT) -> HWND {
    create_control(
        parent,
        Controls::WC_BUTTONW,
        text,
        wm::BS_AUTOCHECKBOX as u32 | wm::WS_TABSTOP,
        0,
        id,
        Rect::default(),
        font,
    )
}

pub unsafe fn combo(parent: HWND, id: i32, font: HFONT, editable: bool) -> HWND {
    let style = (if editable {
        wm::CBS_DROPDOWN | wm::CBS_AUTOHSCROLL
    } else {
        wm::CBS_DROPDOWNLIST
    } as u32)
        | wm::WS_VSCROLL
        | wm::WS_TABSTOP;
    create_control(
        parent,
        Controls::WC_COMBOBOXW,
        "",
        style,
        0,
        id,
        Rect::default(),
        font,
    )
}

pub unsafe fn edit(parent: HWND, text: &str, id: i32, font: HFONT, multiline: bool, read_only: bool) -> HWND {
    let mut style = wm::ES_AUTOHSCROLL as u32 | wm::WS_TABSTOP;
    if multiline {
        style = wm::ES_MULTILINE as u32 | wm::ES_AUTOVSCROLL as u32 | wm::WS_VSCROLL;
    }
    if read_only {
        style |= wm::ES_READONLY as u32;
    }
    create_control(
        parent,
        Controls::WC_EDITW,
        text,
        style,
        wm::WS_EX_CLIENTEDGE,
        id,
        Rect::default(),
        font,
    )
}
