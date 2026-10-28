//! Acceleration data service: load the acceleration project groups from the
//! local cache, falling back to the built-in list. Mirrors the original
//! AcceleratorService (local cache LOCAL_ACCELERATE first, then API, then
//! default). The API is unavailable in this secondary development, so the
//! chain is: local cache -> built-in.

use crate::data;
use crate::model::AccelerateProjectGroup;
use crate::paths;
use std::sync::{Arc, Mutex, RwLock};
use std::time::SystemTime;

/// Holds the loaded acceleration groups and restore/enable helpers.
#[derive(Clone)]
pub struct AccelerateService {
    inner: Arc<RwLock<GroupsState>>,
    pub enabled_ids: Arc<Mutex<Vec<String>>>,
}

struct GroupsState {
    groups: Vec<AccelerateProjectGroup>,
    source: String,
    loaded_at: Option<SystemTime>,
}

impl AccelerateService {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(GroupsState {
                groups: Vec::new(),
                source: "none".into(),
                loaded_at: None,
            })),
            enabled_ids: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn store(&self, groups: Vec<AccelerateProjectGroup>, source: &str) {
        let mut g = self.inner.write().unwrap();
        g.groups = groups.clone();
        g.source = source.to_string();
        g.loaded_at = Some(SystemTime::now());
    }

    /// Load groups: local cache first, then built-in.
    ///
    /// Every reason the cache is not used is logged: a cache that cannot be read,
    /// cannot be parsed, or parses to nothing used to be dropped without a trace,
    /// which left the user with the built-in list and no hint about why the
    /// manifest had no effect.
    pub async fn load(&self) -> Result<Vec<AccelerateProjectGroup>, String> {
        // 1. Local cache.
        let path = paths::local_accelerate_path();
        if path.exists() {
            match tokio::fs::read(&path).await {
                Ok(bytes) => match serde_json::from_slice::<Vec<AccelerateProjectGroup>>(&bytes) {
                    Ok(groups) if !groups.is_empty() => {
                        self.store(groups.clone(), "local cache");
                        return Ok(groups);
                    }
                    Ok(_) => log::warn!(
                        target: "wtlite_core::service",
                        "加速清单 {} 解析结果为空，改用内置清单",
                        path.display()
                    ),
                    Err(e) => log::warn!(
                        target: "wtlite_core::service",
                        "加速清单 {} 解析失败（{e}），改用内置清单",
                        path.display()
                    ),
                },
                Err(e) => log::warn!(
                    target: "wtlite_core::service",
                    "加速清单 {} 读取失败（{e}），改用内置清单",
                    path.display()
                ),
            }
        }
        // 2. Built-in fallback.
        let groups = data::built_in_groups();
        self.store(groups.clone(), "built-in");
        Ok(groups)
    }

    /// Synchronous variant used by the UI at startup (std::fs read). Logs the
    /// same three failures as [`Self::load`].
    pub fn load_sync(&self) -> Result<Vec<AccelerateProjectGroup>, String> {
        let path = paths::local_accelerate_path();
        if path.exists() {
            match std::fs::read(&path) {
                Ok(bytes) => match serde_json::from_slice::<Vec<AccelerateProjectGroup>>(&bytes) {
                    Ok(groups) if !groups.is_empty() => {
                        self.store(groups.clone(), "local cache");
                        return Ok(groups);
                    }
                    Ok(_) => log::warn!(
                        target: "wtlite_core::service",
                        "加速清单 {} 解析结果为空，改用内置清单",
                        path.display()
                    ),
                    Err(e) => log::warn!(
                        target: "wtlite_core::service",
                        "加速清单 {} 解析失败（{e}），改用内置清单",
                        path.display()
                    ),
                },
                Err(e) => log::warn!(
                    target: "wtlite_core::service",
                    "加速清单 {} 读取失败（{e}），改用内置清单",
                    path.display()
                ),
            }
        }
        let groups = data::built_in_groups();
        self.store(groups.clone(), "built-in");
        Ok(groups)
    }

    pub fn groups(&self) -> Vec<AccelerateProjectGroup> {
        self.inner.read().unwrap().groups.clone()
    }

    pub fn source(&self) -> String {
        self.inner.read().unwrap().source.clone()
    }

    /// Restore the three-state enable flags from the enabled IDs.
    pub fn apply_enabled(&self, ids: &[String]) {
        let set: std::collections::HashSet<String> = ids.iter().cloned().collect();
        let mut g = self.inner.write().unwrap();
        for grp in g.groups.iter_mut() {
            for proj in grp.items.iter_mut() {
                proj.restore_enable(&set);
            }
        }
        *self.enabled_ids.lock().unwrap() = ids.to_vec();
    }
}

impl Default for AccelerateService {
    fn default() -> Self {
        Self::new()
    }
}
