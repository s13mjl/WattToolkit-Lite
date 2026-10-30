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
    OpenHostsEditor,
    RevealHosts,
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
        Action::OpenHostsEditor => open_hosts_editor(),
        Action::RevealHosts => reveal_hosts(),
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

/// Mirrors the original `OpenFileByTextReader`: VS Code from Program Files
/// (x64, then x86), falling back to Notepad. Opening an extensionless file with
/// ShellExecute would otherwise make Windows show the "choose an app" dialog.
fn open_hosts_editor() {
    let path = wtlite_core::hosts::hosts_file_path();
    let mut editors = Vec::new();
    for env in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Some(dir) = std::env::var_os(env) {
            editors.push(
                std::path::PathBuf::from(dir)
                    .join("Microsoft VS Code")
                    .join("Code.exe"),
            );
        }
    }
    editors.push(std::path::PathBuf::from("notepad.exe"));
    for editor in editors {
        if !editor.is_absolute() || editor.exists() {
            if std::process::Command::new(&editor)
                .arg(&path)
                .spawn()
                .is_ok()
            {
                return;
            }
        }
    }
    if !unsafe { win32::shell_open(&path.to_string_lossy()) } {
        log::warn!("failed to open hosts file {path:?}");
    }
}

/// Mirrors the original `OpenFileDir` (`OpenFolder(hosts path)`), which selects
/// the hosts file in Explorer.
fn reveal_hosts() {
    let path = wtlite_core::hosts::hosts_file_path();
    if std::process::Command::new("explorer.exe")
        .arg(format!("/select,{}", path.display()))
        .spawn()
        .is_err()
    {
        if let Some(dir) = path.parent() {
            let _ = unsafe { win32::shell_open(&dir.to_string_lossy()) };
        }
    }
}
