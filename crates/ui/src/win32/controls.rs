//! Common-control helpers: TreeView (checkboxes), ListView (report) and Tab.

use std::cell::Cell;

use windows_sys::Win32::Foundation::{HWND, LPARAM};
use windows_sys::Win32::Graphics::Gdi::HFONT;
use windows_sys::Win32::UI::Controls;
use windows_sys::Win32::UI::WindowsAndMessaging as wm;

use super::{create_control, set_font, wide, Rect};

thread_local! {
    static SUPPRESS: Cell<u32> = const { Cell::new(0) };
}

pub struct SuppressGuard;

impl Drop for SuppressGuard {
    fn drop(&mut self) {
        SUPPRESS.with(|s| s.set(s.get().saturating_sub(1)));
    }
}

pub fn suppress() -> SuppressGuard {
    SUPPRESS.with(|s| s.set(s.get() + 1));
    SuppressGuard
}

pub fn is_suppressed() -> bool {
    SUPPRESS.with(|s| s.get() > 0)
}

#[inline]
fn state_image(index: u32) -> u32 {
    index << 12
}

fn parent_mask(expand: bool) -> u32 {
    Controls::TVIS_STATEIMAGEMASK | if expand { Controls::TVIS_EXPANDED } else { 0 }
}

pub unsafe fn make_tree(parent: HWND, id: i32, r: Rect, font: HFONT, flat: bool) -> HWND {
    let mut style = Controls::TVS_CHECKBOXES | Controls::TVS_SHOWSELALWAYS;
    if !flat {
        style |= Controls::TVS_HASBUTTONS | Controls::TVS_HASLINES | Controls::TVS_LINESATROOT;
    }
    create_control(
        parent,
        Controls::WC_TREEVIEWW,
        "",
        style,
        wm::WS_EX_CLIENTEDGE,
        id,
        r,
        font,
    )
}

/// Insert a node. `checked` = None renders no checkbox (containers/group headers
/// in the flat services tree); Some(true/false) renders a checkbox.
pub unsafe fn tree_insert(
    hwnd: HWND,
    parent_item: Controls::HTREEITEM,
    text: &str,
    checked: Option<bool>,
    expanded: bool,
) -> Controls::HTREEITEM {
    let _g = suppress();
    let text_w = wide(text);
    let mut item: Controls::TVITEMW = std::mem::zeroed();
    item.mask = Controls::TVIF_TEXT | Controls::TVIF_STATE;
    item.pszText = text_w.as_ptr() as windows_sys::core::PWSTR;
    item.cchTextMax = text_w.len() as i32;
    item.state = match checked {
        Some(on) => state_image(if on { 2 } else { 1 }),
        None => 0,
    };
    if expanded {
        item.state |= Controls::TVIS_EXPANDED;
    }
    item.stateMask = parent_mask(expanded) | if checked.is_none() { Controls::TVIS_STATEIMAGEMASK } else { 0 };

    let mut ins: Controls::TVINSERTSTRUCTW = std::mem::zeroed();
    ins.hParent = parent_item;
    ins.hInsertAfter = Controls::TVI_LAST;
    ins.Anonymous.item = item;

    let h = wm::SendMessageW(
        hwnd,
        Controls::TVM_INSERTITEMW,
        0,
        &ins as *const _ as LPARAM,
    ) as Controls::HTREEITEM;
    if expanded && h != 0 {
        wm::SendMessageW(hwnd, Controls::TVM_EXPAND, Controls::TVE_EXPAND as usize, h);
    }
    h
}

pub unsafe fn tree_clear(hwnd: HWND) {
    let _g = suppress();
    wm::SendMessageW(hwnd, Controls::TVM_DELETEITEM, 0, Controls::TVI_ROOT);
}

pub unsafe fn tree_set_check(hwnd: HWND, item: Controls::HTREEITEM, on: bool) {
    if item == 0 {
        return;
    }
    let _g = suppress();
    let mut tvi: Controls::TVITEMW = std::mem::zeroed();
    tvi.mask = Controls::TVIF_STATE;
    tvi.hItem = item;
    tvi.state = state_image(if on { 2 } else { 1 });
    tvi.stateMask = Controls::TVIS_STATEIMAGEMASK;
    wm::SendMessageW(hwnd, Controls::TVM_SETITEMW, 0, &tvi as *const _ as LPARAM);
}

pub unsafe fn tree_check(hwnd: HWND, item: Controls::HTREEITEM) -> Option<bool> {
    if item == 0 {
        return None;
    }
    let mut tvi: Controls::TVITEMW = std::mem::zeroed();
    tvi.mask = Controls::TVIF_STATE;
    tvi.hItem = item;
    tvi.stateMask = Controls::TVIS_STATEIMAGEMASK;
    if wm::SendMessageW(hwnd, Controls::TVM_GETITEMW, 0, &mut tvi as *mut _ as LPARAM) == 0 {
        return None;
    }
    let idx = (tvi.state & Controls::TVIS_STATEIMAGEMASK) >> 12;
    if idx == 2 {
        Some(true)
    } else if idx == 1 {
        Some(false)
    } else {
        None
    }
}

pub unsafe fn make_list(parent: HWND, id: i32, r: Rect, font: HFONT) -> HWND {
    let h = create_control(
        parent,
        Controls::WC_LISTVIEWW,
        "",
        Controls::LVS_REPORT | Controls::LVS_SINGLESEL | Controls::LVS_SHOWSELALWAYS,
        wm::WS_EX_CLIENTEDGE,
        id,
        r,
        font,
    );
    if !h.is_null() {
        let ex = Controls::LVS_EX_FULLROWSELECT | Controls::LVS_EX_DOUBLEBUFFER;
        wm::SendMessageW(
            h,
            Controls::LVM_SETEXTENDEDLISTVIEWSTYLE,
            ex as usize,
            ex as isize,
        );
        let header = wm::SendMessageW(h, Controls::LVM_GETHEADER, 0, 0) as HWND;
        if !header.is_null() {
            set_font(header, font);
        }
    }
    h
}

pub unsafe fn list_columns(hwnd: HWND, cols: &[(&str, i32)]) {
    let _g = suppress();
    for (i, (name, width)) in cols.iter().enumerate() {
        let name_w = wide(name);
        let mut col: Controls::LVCOLUMNW = std::mem::zeroed();
        col.mask = Controls::LVCF_TEXT | Controls::LVCF_WIDTH | Controls::LVCF_SUBITEM;
        col.pszText = name_w.as_ptr() as windows_sys::core::PWSTR;
        col.cx = *width;
        col.iSubItem = i as i32;
        wm::SendMessageW(
            hwnd,
            Controls::LVM_INSERTCOLUMNW,
            i,
            &col as *const _ as LPARAM,
        );
    }
}

pub unsafe fn list_clear(hwnd: HWND) {
    let _g = suppress();
    wm::SendMessageW(hwnd, Controls::LVM_DELETEALLITEMS, 0, 0);
}

pub unsafe fn list_count(hwnd: HWND) -> i32 {
    wm::SendMessageW(hwnd, Controls::LVM_GETITEMCOUNT, 0, 0) as i32
}

pub unsafe fn list_set_column_width(hwnd: HWND, index: i32, width: i32) {
    let _g = suppress();
    wm::SendMessageW(
        hwnd,
        Controls::LVM_SETCOLUMNWIDTH,
        index as usize,
        width.max(0) as isize,
    );
}

pub unsafe fn list_add(hwnd: HWND, row: &[String], lparam: isize) {
    let _g = suppress();
    let index = list_count(hwnd);
    let first_w = row.first().map(|s| wide(s)).unwrap_or_else(|| wide(""));
    let mut item: Controls::LVITEMW = std::mem::zeroed();
    item.mask = Controls::LVIF_TEXT | Controls::LVIF_PARAM;
    item.iItem = index;
    item.pszText = first_w.as_ptr() as windows_sys::core::PWSTR;
    item.lParam = lparam;
    wm::SendMessageW(hwnd, Controls::LVM_INSERTITEMW, 0, &item as *const _ as LPARAM);
    for (sub, text) in row.iter().enumerate().skip(1) {
        let sub_w = wide(text);
        let mut item: Controls::LVITEMW = std::mem::zeroed();
        item.mask = Controls::LVIF_TEXT;
        item.iItem = index;
        item.iSubItem = sub as i32;
        item.pszText = sub_w.as_ptr() as windows_sys::core::PWSTR;
        wm::SendMessageW(hwnd, Controls::LVM_SETITEMW, 0, &item as *const _ as LPARAM);
    }
}

pub unsafe fn make_tabs(parent: HWND, id: i32, r: Rect, font: HFONT) -> HWND {
    create_control(
        parent,
        Controls::WC_TABCONTROLW,
        "",
        Controls::TCS_FOCUSNEVER | wm::WS_TABSTOP,
        wm::WS_EX_CONTROLPARENT,
        id,
        r,
        font,
    )
}

pub unsafe fn tabs_add(hwnd: HWND, labels: &[&str]) {
    let _g = suppress();
    for (i, label) in labels.iter().enumerate() {
        let label_w = wide(label);
        let mut item: Controls::TCITEMW = std::mem::zeroed();
        item.mask = Controls::TCIF_TEXT;
        item.pszText = label_w.as_ptr() as windows_sys::core::PWSTR;
        wm::SendMessageW(
            hwnd,
            Controls::TCM_INSERTITEMW,
            i,
            &item as *const _ as LPARAM,
        );
    }
}

pub unsafe fn tabs_sel(hwnd: HWND) -> i32 {
    wm::SendMessageW(hwnd, Controls::TCM_GETCURSEL, 0, 0) as i32
}

pub unsafe fn tabs_set_sel(hwnd: HWND, index: i32) {
    let _g = suppress();
    wm::SendMessageW(hwnd, Controls::TCM_SETCURSEL, index as usize, 0);
}

pub fn notify_code(lparam: LPARAM) -> u32 {
    unsafe { (*(lparam as *const Controls::NMHDR)).code }
}

pub fn notify_id(lparam: LPARAM) -> i32 {
    unsafe { (*(lparam as *const Controls::NMHDR)).idFrom as i32 }
}

pub unsafe fn tv_item_change(lparam: LPARAM) -> (Controls::HTREEITEM, u32, u32) {
    let n = &*(lparam as *const Controls::NMTVITEMCHANGE);
    (n.hItem, n.uStateNew, n.uStateOld)
}

