//! Side effects that must run without holding the `App` RefCell borrow
//! (modal loops, process/network calls, window creation/destruction).

use crate::dialogs;
use crate::state::ProxyDialogData;
use crate::tray;
use crate::win32;
use crate::{ids, with_app};

pub enum Action {
    ShellOpen(String),
    TrayMenu,
    RestoreWindow,
    HideToTray,
    Exit,
    CertInstall,
    CertRemove,
    HostsReset,
    OpenProxyDialog(ProxyDialogData),
    OpenCertDialog(String),
}

pub fn execute(action: Action) {
    match action {
        Action::ShellOpen(target) => {
            if !unsafe { win32::shell_open(&target) } {
                log::warn!("failed to open {target}");
            }
        }
        Action::TrayMenu => {
            let cmd = unsafe { tray::show_menu() };
            match cmd {
                ids::TRAY_SHOW => crate::restore_window(),
                ids::TRAY_EXIT => crate::request_exit(),
                _ => {}
            }
        }
        Action::RestoreWindow => crate::restore_window(),
        Action::HideToTray => crate::hide_to_tray(),
        Action::Exit => crate::request_exit(),
        Action::CertInstall => {
            let cert = with_app(|a| a.proxy.cert.clone());
            let Some(cert) = cert else { return };
            let msg = cert.install().unwrap_or_else(|e| format!("失败: {e}"));
            with_app(|a| unsafe {
                a.push_log(format!("[cert] install: {msg}"));
                a.toast(format!("证书: {msg}"));
            });
        }
        Action::CertRemove => {
            let cert = with_app(|a| a.proxy.cert.clone());
            let Some(cert) = cert else { return };
            let msg = cert.remove().unwrap_or_else(|e| format!("失败: {e}"));
            with_app(|a| unsafe {
                a.push_log(format!("[cert] remove: {msg}"));
                a.toast(format!("证书: {msg}"));
            });
        }
        Action::HostsReset => {
            let r = wtlite_core::hosts::reset_file();
            with_app(|a| unsafe {
                let msg = match r {
                    Ok(()) => "Hosts 已重置".to_string(),
                    Err(e) => format!("重置失败: {e}"),
                };
                a.push_log(format!("[hosts] {msg}"));
                a.toast(msg);
            });
        }
        Action::OpenProxyDialog(data) => {
            if let Some((main, fonts, dpi)) = with_app(|a| (a.hwnd, a.fonts, a.dpi)) {
                unsafe { dialogs::open_proxy(main, fonts, dpi, data) };
            }
        }
        Action::OpenCertDialog(info) => {
            if let Some((main, fonts, dpi)) = with_app(|a| (a.hwnd, a.fonts, a.dpi)) {
                unsafe { dialogs::open_cert(main, fonts, dpi, info) };
            }
        }
    }
}
