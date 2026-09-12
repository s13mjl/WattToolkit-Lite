//! Windows system proxy / PAC management via the registry.
//! Mirrors original WindowsPlatformServiceImpl.SetAsSystemProxyAsync /
//! SetAsSystemPACProxyAsync (which wrote a .reg file; here we write the
//! same HKCU values directly, no elevation needed).

use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;

const INTERNET_SETTINGS: &str = r"SoftwareMicrosoftWindowsCurrentVersionInternet Settings";

/// No-proxy list (mirrors original IPlatformService.GetNoProxyHostName).
pub fn no_proxy_list() -> String {
    [
        "10.*",
        "172.16.*",
        "172.17.*",
        "172.18.*",
        "172.19.*",
        "172.20.*",
        "172.21.*",
        "172.22.*",
        "172.23.*",
        "172.24.*",
        "172.25.*",
        "172.26.*",
        "172.27.*",
        "172.28.*",
        "172.29.*",
        "172.30.*",
        "172.31.*",
        "192.168.*",
    ]
    .join(";")
}

fn open_settings() -> Result<RegKey, String> {
    let hkey_local_machine = RegKey::predef(HKEY_CURRENT_USER);
    hkey_local_machine
        .open_subkey_with_flags(INTERNET_SETTINGS, KEY_READ | KEY_WRITE)
        .map_err(|e| e.to_string())
}

/// Enable or disable the Windows system proxy.
pub fn set_system_proxy(enable: bool, ip: &str, port: u16) -> Result<(), String> {
    let settings = open_settings()?;
    if enable {
        settings
            .set_value("ProxyEnable", &1u32)
            .map_err(|e| e.to_string())?;
        settings
            .set_value("ProxyServer", &format!("{}:{}", ip, port))
            .map_err(|e| e.to_string())?;
        settings
            .set_value("ProxyOverride", &no_proxy_list())
            .map_err(|e| e.to_string())?;
    } else {
        settings.set_value("ProxyEnable", &0u32).map_err(|e| e.to_string())?;
        let _ = settings.delete_value("ProxyServer");
        let _ = settings.delete_value("ProxyOverride");
    }
    Ok(())
}

/// Enable or disable the Windows PAC (auto-config) proxy.
pub fn set_pac_proxy(enable: bool, url: &str) -> Result<(), String> {
    let settings = open_settings()?;
    if enable && !url.is_empty() {
        settings
            .set_value("AutoConfigURL", &url.to_string())
            .map_err(|e| e.to_string())?;
    } else {
        settings
            .set_value("AutoConfigURL", &String::new())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Read the current ProxyEnable state.
pub fn is_system_proxy_enabled() -> bool {
    if let Ok(settings) = open_settings() {
        if let Ok(v) = settings.get_value::<u32, _>("ProxyEnable") {
            return v != 0;
        }
    }
    false
}

/// Generate a PAC file content (mirrors original HttpProxyPacMiddleware.CreateProxyPac).
pub fn create_pac(proxy_host: &str, domains: &[String]) -> String {
    let mut sb = String::new();
    sb.push_str("function FindProxyForURL(url, host){
");
    sb.push_str(&format!("    var pac = 'PROXY {}';
", proxy_host));
    for d in domains {
        let d = d.trim();
        if d.is_empty() {
            continue;
        }
        sb.push_str(&format!("    if (shExpMatch(host, '{}')) return pac;
", d));
    }
    sb.push_str("    return 'DIRECT';
");
    sb.push_str("}
");
    sb
}
