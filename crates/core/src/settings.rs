//! Application settings, mirroring the original GeneralSettings and ProxySettings.

use crate::model::{ExternalProxyType, ProxyMode};
use crate::paths;
use serde::{Deserialize, Serialize};

/// General application settings (mirrors original GeneralSettings).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralSettings {
    pub auto_run_on_startup: bool,
    pub minimize_on_startup: bool,
    pub tray_icon: bool,
    pub gpu: bool,
}

impl Default for GeneralSettings {
    fn default() -> Self {
        Self {
            auto_run_on_startup: false,
            minimize_on_startup: false,
            tray_icon: true,
            gpu: true,
        }
    }
}

/// Proxy/acceleration settings (mirrors original ProxySettings).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxySettings {
    pub proxy_mode: ProxyMode,
    pub system_proxy_ip: String,
    pub system_proxy_port: u16,
    pub proxy_master_dns: String,
    pub use_doh: bool,
    pub custom_doh_address: String,
    pub enable_http_proxy_to_https: bool,
    pub only_enable_proxy_script: bool,
    pub program_startup_run_proxy: bool,
    pub is_enable_script: bool,
    pub two_level_agent_enable: bool,
    pub two_level_agent_type: ExternalProxyType,
    pub two_level_agent_ip: String,
    pub two_level_agent_port: u16,
    pub two_level_agent_user: String,
    pub two_level_agent_password: String,
    /// Enabled acceleration project IDs.
    pub support_proxy_services_status: Vec<String>,
}

impl Default for ProxySettings {
    fn default() -> Self {
        Self {
            proxy_mode: ProxyMode::default(),
            system_proxy_ip: "0.0.0.0".to_string(),
            system_proxy_port: 26561,
            proxy_master_dns: "223.5.5.5".to_string(),
            use_doh: true,
            custom_doh_address: String::new(),
            enable_http_proxy_to_https: true,
            only_enable_proxy_script: false,
            program_startup_run_proxy: false,
            is_enable_script: true,
            two_level_agent_enable: false,
            two_level_agent_type: ExternalProxyType::default(),
            two_level_agent_ip: "127.0.0.1".to_string(),
            two_level_agent_port: 7890,
            two_level_agent_user: String::new(),
            two_level_agent_password: String::new(),
            support_proxy_services_status: Vec::new(),
        }
    }
}

/// Combined settings root persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub general: GeneralSettings,
    pub proxy: ProxySettings,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            general: GeneralSettings::default(),
            proxy: ProxySettings::default(),
        }
    }
}

impl Settings {
    fn file_path() -> std::path::PathBuf {
        paths::settings_dir().join("settings.json")
    }

    pub fn load() -> Self {
        let p = Self::file_path();
        if let Ok(bytes) = std::fs::read(&p) {
            if let Ok(s) = serde_json::from_slice::<Settings>(&bytes) {
                return s;
            }
        }
        Self::default()
    }

    pub fn save(&self) -> Result<(), String> {
        let p = Self::file_path();
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&p, json).map_err(|e| e.to_string())
    }
}

/// Registry value name for the auto-run entry (HKCU Run key).
const AUTO_RUN_VALUE: &str = "WattToolkit-Lite";

/// Enable or disable auto-run at startup via the HKCU Run key
/// (mirrors the original startup setting behavior).
pub fn set_auto_run_on_startup(enable: bool) -> Result<(), String> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (run, _) = hkcu
        .create_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run")
        .map_err(|e| e.to_string())?;
    if enable {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        run.set_value(AUTO_RUN_VALUE, &format!(r#""{}""#, exe.display()))
            .map_err(|e| e.to_string())?;
    } else {
        let _ = run.delete_value(AUTO_RUN_VALUE);
    }
    Ok(())
}
