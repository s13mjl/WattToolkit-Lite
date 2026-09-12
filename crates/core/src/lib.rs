//! WattToolkit-Lite core: network acceleration proxy engine for Windows.
//!
//! Mirrors the original WattToolkit (Steam++) "网络加速" logic in Rust:
//! a local reverse proxy (MITM) for Hosts mode, a forward proxy for
//! System/PAC modes, WinDivert DNS interception, certificate management,
//! Hosts file and system-proxy registry control, and network diagnostics.

pub mod cert;
pub mod data;
pub mod dns;
pub mod fwd;
pub mod hosts;
pub mod http1;
pub mod mitm;
pub mod model;
pub mod nettest;
pub mod paths;
pub mod proxy;
pub mod service;
pub mod settings;
pub mod sysproxy;
pub mod windivert;

pub use model::{
    AccelerateProject, AccelerateProjectGroup, ExternalProxyType, ProxyMode, ProxyType,
};
pub use proxy::ProxyManager;
pub use service::AccelerateService;
pub use settings::Settings;

/// Application version (mirrors the original versioning).
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
