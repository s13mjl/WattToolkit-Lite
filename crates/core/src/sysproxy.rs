//! Windows system proxy / PAC management via the registry.
//! Mirrors original WindowsPlatformServiceImpl.SetAsSystemProxyAsync /
//! SetAsSystemPACProxyAsync (which wrote a .reg file; here we write the
//! same HKCU values directly, no elevation needed).

use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
use winreg::RegKey;

const INTERNET_SETTINGS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const INTERNET_CONNECTIONS: &str =
    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";

// Bit flags of byte 8 in the WinINET `DefaultConnectionSettings` blob
// (INTERNET_OPTION_PER_CONN_FLAGS). Browsers read this blob rather than the
// plain string values, so it must be kept in sync or the proxy is silently
// ignored. Note the two auto flags are easy to swap:
//   PROXY_TYPE_DIRECT         = 0x01
//   PROXY_TYPE_PROXY          = 0x02  (manual proxy server)
//   PROXY_TYPE_AUTO_PROXY_URL = 0x04  (PAC script from AutoConfigURL)
//   PROXY_TYPE_AUTO_DETECT    = 0x08  (WPAD auto-discovery)
const FLAG_DIRECT: u8 = 0x01;
const FLAG_MANUAL_PROXY: u8 = 0x02;
const FLAG_AUTO_PROXY_URL: u8 = 0x04;
const FLAG_AUTO_DETECT: u8 = 0x08;

/// Read the WinINET connection blob (or a default skeleton when absent).
fn read_connection_blob() -> Vec<u8> {
    if let Ok(key) = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_CONNECTIONS, KEY_READ | KEY_WRITE)
    {
        if let Ok(v) = key.get_raw_value("DefaultConnectionSettings") {
            if v.bytes.len() >= 24 {
                return v.bytes.into_owned();
            }
        }
    }
    // 88-byte skeleton: version, counter, flags, then empty strings.
    let mut blob = vec![0u8; 88];
    blob[0] = 0x46;
    blob[4] = 0x03;
    blob[8] = FLAG_DIRECT;
    blob[16] = 0x00;
    blob[20] = 0x00;
    blob
}

/// Persist the blob and refresh WinINET so running browsers pick the change up.
fn write_connection_blob(blob: &[u8]) -> Result<(), String> {
    let key = RegKey::predef(HKEY_CURRENT_USER)
        .open_subkey_with_flags(INTERNET_CONNECTIONS, KEY_READ | KEY_WRITE)
        .map_err(|e| e.to_string())?;
    let raw = winreg::RegValue {
        bytes: blob.to_vec().into(),
        vtype: winreg::enums::RegType::REG_BINARY,
    };
    key.set_raw_value("DefaultConnectionSettings", &raw)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Rewrite `DefaultConnectionSettings` with the given proxy endpoint and/or PAC
/// URL. Layout: version, counter, flags, then three length-prefixed strings
/// (proxy server, bypass list, auto-config URL).
fn update_blob(endpoint: Option<&str>, auto_url: Option<&str>) -> Result<(), String> {
    let old = read_connection_blob();
    let mut out: Vec<u8> = Vec::with_capacity(128);
    out.extend_from_slice(&old[..4]); // version stays 0x46
    let counter = if old.len() >= 8 {
        u32::from_le_bytes([old[4], old[5], old[6], old[7]]).wrapping_add(1)
    } else {
        1
    };
    out.extend_from_slice(&counter.to_le_bytes());
    // PROXY_TYPE_DIRECT stays set so non-proxied traffic still works.
    let mut flags = FLAG_DIRECT;
    if auto_url.is_some() {
        flags |= FLAG_AUTO_PROXY_URL;
    }
    if endpoint.is_some() {
        flags |= FLAG_MANUAL_PROXY;
    }
    // Never enable WPAD auto-detect: it would make browsers try to discover a
    // proxy on the network and ignore the PAC URL we just configured.
    flags &= !FLAG_AUTO_DETECT;
    out.extend_from_slice(&(flags as u32).to_le_bytes());
    for value in [endpoint, Some(no_proxy_list().as_str()), auto_url] {
        match value {
            Some(s) if !s.is_empty() => {
                let bytes = s.as_bytes();
                out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(bytes);
            }
            _ => out.extend_from_slice(&0u32.to_le_bytes()),
        }
    }
    write_connection_blob(&out)
}

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
    drop(settings);
    // Keep the WinINET blob (what browsers actually read) in sync.
    let auto = read_auto_config_url();
    let endpoint = if enable {
        Some(format!("{ip}:{port}"))
    } else {
        None
    };
    update_blob(endpoint.as_deref(), auto.as_deref())?;
    notify_proxy_change();
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
    drop(settings);
    // Keep the WinINET blob (what browsers actually read) in sync, otherwise the
    // PAC URL is stored but the "direct connection" flag stays set and every
    // browser silently ignores the proxy.
    let manual = if is_system_proxy_enabled() {
        read_proxy_server()
    } else {
        None
    };
    update_blob(
        manual.as_deref(),
        if enable && !url.is_empty() { Some(url) } else { None },
    )?;
    notify_proxy_change();
    Ok(())
}

/// Read the configured PAC/auto-config URL, if any.
fn read_auto_config_url() -> Option<String> {
    open_settings()
        .ok()
        .and_then(|k| k.get_value::<String, _>("AutoConfigURL").ok())
        .filter(|s| !s.is_empty())
}

/// Read the configured manual proxy server, if any.
fn read_proxy_server() -> Option<String> {
    open_settings()
        .ok()
        .and_then(|k| k.get_value::<String, _>("ProxyServer").ok())
        .filter(|s| !s.is_empty())
}

/// Tell WinINET that the proxy configuration changed so already-running
/// browsers reload it (without this they keep using the previous settings).
fn notify_proxy_change() {
    #[link(name = "wininet")]
    extern "system" {
        fn InternetSetOptionW(
            h: *mut core::ffi::c_void,
            option: u32,
            buffer: *mut core::ffi::c_void,
            len: u32,
        ) -> i32;
    }
    #[link(name = "user32")]
    extern "system" {
        fn SendMessageTimeoutW(
            hwnd: *mut core::ffi::c_void,
            msg: u32,
            wparam: usize,
            lparam: isize,
            flags: u32,
            timeout: u32,
            result: *mut usize,
        ) -> isize;
    }
    const INTERNET_OPTION_SETTINGS_CHANGED: u32 = 39;
    const INTERNET_OPTION_REFRESH: u32 = 37;
    const HWND_BROADCAST: *mut core::ffi::c_void = 0xffffusize as *mut core::ffi::c_void;
    const WM_SETTINGCHANGE: u32 = 0x001A;
    const SMTO_ABORTIFHUNG: u32 = 0x0002;
    unsafe {
        InternetSetOptionW(
            core::ptr::null_mut(),
            INTERNET_OPTION_SETTINGS_CHANGED,
            core::ptr::null_mut(),
            0,
        );
        InternetSetOptionW(
            core::ptr::null_mut(),
            INTERNET_OPTION_REFRESH,
            core::ptr::null_mut(),
            0,
        );
        // WinINET notifications only affect the calling process. Broadcasting
        // WM_SETTINGCHANGE is what makes an already-running browser re-read the
        // proxy configuration instead of keeping its cached (stale) settings.
        let mut result: usize = 0;
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            0,
            SMTO_ABORTIFHUNG,
            1000,
            &mut result,
        );
    }
}

/// Report what WinINET currently thinks the system proxy configuration is.
/// Mirrors `WinHttpGetIEProxyConfigForCurrentUser` so the running app can log
/// whether the PAC URL was actually accepted by Windows.
pub fn describe_effective_proxy() -> String {
    #[repr(C)]
    struct IeProxyConfig {
        auto_detect: i32,
        auto_config_url: *mut u16,
        proxy: *mut u16,
        proxy_bypass: *mut u16,
    }
    #[link(name = "winhttp")]
    extern "system" {
        fn WinHttpGetIEProxyConfigForCurrentUser(config: *mut IeProxyConfig) -> i32;
    }
    unsafe {
        let mut cfg = IeProxyConfig {
            auto_detect: 0,
            auto_config_url: core::ptr::null_mut(),
            proxy: core::ptr::null_mut(),
            proxy_bypass: core::ptr::null_mut(),
        };
        if WinHttpGetIEProxyConfigForCurrentUser(&mut cfg) == 0 {
            return "WinHTTP query failed".to_string();
        }
        let to_string = |p: *mut u16| -> String {
            if p.is_null() {
                String::new()
            } else {
                let mut len = 0usize;
                while *p.add(len) != 0 {
                    len += 1;
                }
                String::from_utf16_lossy(core::slice::from_raw_parts(p, len))
            }
        };
        format!(
            "autoDetect={} pac=[{}] proxy=[{}]",
            cfg.auto_detect != 0,
            to_string(cfg.auto_config_url),
            to_string(cfg.proxy)
        )
    }
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
