//! Data models mirroring the original WattToolkit accelerator project DTOs.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Proxy acceleration modes (mirrors original ProxyMode enum, Windows subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProxyMode {
    /// Modify Hosts file to proxy (default).
    Hosts,
    /// Inject WinDivert driver to intercept DNS (Windows only).
    DnsIntercept,
    /// PAC proxy mode.
    Pac,
    /// System proxy mode.
    System,
}

impl ProxyMode {
    pub fn available() -> &'static [ProxyMode] {
        &[
            ProxyMode::Hosts,
            ProxyMode::DnsIntercept,
            ProxyMode::Pac,
            ProxyMode::System,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ProxyMode::Hosts => "Hosts",
            ProxyMode::DnsIntercept => "DNSIntercept",
            ProxyMode::Pac => "PAC",
            ProxyMode::System => "System",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            ProxyMode::Hosts => "Hosts 文件",
            ProxyMode::DnsIntercept => "DNS 拦截",
            ProxyMode::Pac => "PAC 代理",
            ProxyMode::System => "系统代理",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "Hosts" | "hosts" => Some(ProxyMode::Hosts),
            "DnsIntercept" | "dnsIntercept" => Some(ProxyMode::DnsIntercept),
            "Pac" | "pac" => Some(ProxyMode::Pac),
            "System" | "system" => Some(ProxyMode::System),
            _ => None,
        }
    }
}

impl Default for ProxyMode {
    fn default() -> Self {
        ProxyMode::Hosts
    }
}

impl fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Acceleration project proxy type (mirrors original ProxyType).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub enum ProxyType {
    #[default]
    /// Normal local reverse proxy.
    Normal,
    /// Server-side (remote) acceleration, Beta.
    ServerAccelerate,
}

/// External two-level agent proxy type (mirrors original ExternalProxyType).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExternalProxyType {
    Http,
    Socks4,
    Socks5,
}

impl ExternalProxyType {
    pub fn as_scheme(&self) -> &'static str {
        match self {
            ExternalProxyType::Http => "http",
            ExternalProxyType::Socks4 => "socks4",
            ExternalProxyType::Socks5 => "socks5",
        }
    }
}

impl Default for ExternalProxyType {
    fn default() -> Self {
        ExternalProxyType::Socks5
    }
}

/// A single acceleration project (mirrors AccelerateProjectDTO).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AccelerateProject {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub order: i32,
    #[serde(default)]
    pub proxy_type: ProxyType,
    /// Matched domain names, semicolon-separated.
    pub match_domain_names: String,
    /// Forward/destination domain (optional).
    #[serde(default)]
    pub forward_domain_names: Option<String>,
    #[serde(default)]
    pub ignore_ssl_cert_verification: bool,
    /// Fake TLS SNI (optional).
    #[serde(default)]
    pub fake_server_name: Option<String>,
    /// Listened domain names (semicolon-separated) written to hosts.
    pub listen_domain_names: String,
    #[serde(default)]
    pub checked: bool,
    /// Three-state enable: None = indeterminate, Some(true)=on, Some(false)=off.
    #[serde(default)]
    pub three_state_enable: Option<bool>,
    /// Nested child projects.
    #[serde(default)]
    pub items: Vec<AccelerateProject>,
}

impl Default for AccelerateProject {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            order: 0,
            proxy_type: ProxyType::Normal,
            match_domain_names: String::new(),
            forward_domain_names: None,
            ignore_ssl_cert_verification: false,
            fake_server_name: None,
            listen_domain_names: String::new(),
            checked: false,
            three_state_enable: None,
            items: Vec::new(),
        }
    }
}

impl AccelerateProject {
    /// Recursively flatten all leaf projects.
    pub fn all_leaves(&self) -> Vec<&AccelerateProject> {
        let mut out = Vec::new();
        if self.items.is_empty() {
            out.push(self);
        } else {
            for c in &self.items {
                out.extend(c.all_leaves());
            }
        }
        out
    }

    /// Recursively collect the enabled IDs that are persisted.
    ///
    /// Only leaves are collected: a parent node is a container whose state is
    /// derived from its children, so persisting it would let a stale parent ID
    /// silently disable every child on the next start (the original project
    /// persists leaf nodes only - see ProxyService.GetAccelerateEnableAllIds).
    pub fn enabled_ids(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.items.is_empty() {
            if self.three_state_enable == Some(true) {
                out.push(self.id.clone());
            }
        } else {
            for c in &self.items {
                out.extend(c.enabled_ids());
            }
        }
        out
    }

    /// Restore three-state from a set of persisted (leaf) IDs.
    ///
    /// Children are restored first and a container's own state is then derived
    /// from them, so an expanded subtree keeps a consistent three-state value.
    pub fn restore_enable(&mut self, enabled: &std::collections::HashSet<String>) {
        if self.items.is_empty() {
            self.three_state_enable = Some(enabled.contains(&self.id));
        } else {
            for c in self.items.iter_mut() {
                c.restore_enable(enabled);
            }
            // Derive the container state from its children.
            let leaves = self.all_leaves();
            let on = leaves.iter().filter(|l| l.three_state_enable == Some(true)).count();
            self.three_state_enable = if on == 0 {
                Some(false)
            } else if on == leaves.len() {
                Some(true)
            } else {
                None // indeterminate
            };
        }
    }
}

/// A group of acceleration projects (mirrors AccelerateProjectGroupDTO).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AccelerateProjectGroup {
    pub name: String,
    #[serde(default)]
    pub icon_url: Option<String>,
    #[serde(default)]
    pub order: i32,
    #[serde(default)]
    pub three_state_enable: Option<bool>,
    #[serde(default)]
    pub items: Vec<AccelerateProject>,
}

impl Default for AccelerateProjectGroup {
    fn default() -> Self {
        Self {
            name: String::new(),
            icon_url: None,
            order: 0,
            three_state_enable: None,
            items: Vec::new(),
        }
    }
}
