//! File-system paths (mirrors original IOPath concepts).

pub const APP_NAME: &str = "WattToolkit-Lite";

pub fn local_app_data() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().to_string());
    let p = std::path::Path::new(&base).join(APP_NAME);
    let _ = std::fs::create_dir_all(&p);
    p
}

pub fn cache_dir() -> std::path::PathBuf {
    let p = local_app_data().join("cache");
    let _ = std::fs::create_dir_all(&p);
    p
}

pub fn log_dir() -> std::path::PathBuf {
    let p = local_app_data().join("logs");
    let _ = std::fs::create_dir_all(&p);
    p
}

pub fn cert_dir() -> std::path::PathBuf {
    let p = local_app_data().join("cert");
    let _ = std::fs::create_dir_all(&p);
    p
}

pub fn settings_dir() -> std::path::PathBuf {
    let p = local_app_data().join("settings");
    let _ = std::fs::create_dir_all(&p);
    p
}

/// LOCAL_ACCELERATE cache file path.
pub fn local_accelerate_path() -> std::path::PathBuf {
    cache_dir().join("LOCAL_ACCELERATE.json")
}
