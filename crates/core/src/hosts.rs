//! Hosts file management, mirroring the original HostsFileServiceImpl.
//!
//! Uses marker blocks in the system hosts file so entries can be added and
//! removed atomically. The original uses "Steam++" markers; this secondary
//! development uses its own "WattToolkit-Lite" markers to avoid clobbering
//! the upstream app's entries.

use std::io::Read;

const MARK_START: &str = "# WattToolkit-Lite Start";
const MARK_END: &str = "# WattToolkit-Lite End";
const BACKUP_MARK_START: &str = "# WattToolkit-Lite Backup Start";
const BACKUP_MARK_END: &str = "# WattToolkit-Lite Backup End";

/// Path of the Windows hosts file.
pub fn hosts_file_path() -> std::path::PathBuf {
    std::path::PathBuf::from(r"C:WindowsSystem32driversetchosts")
}

/// Read the hosts file content (best effort).
pub fn read_hosts() -> Option<String> {
    let mut file = std::fs::File::open(hosts_file_path()).ok()?;
    let mut buf = String::new();
    file.read_to_string(&mut buf).ok()?;
    Some(buf)
}

/// Whether our marker block is present in the hosts file.
pub fn contains_by_tag() -> bool {
    match read_hosts() {
        Some(content) => {
            content
                .lines()
                .rev()
                .any(|l| l.trim_start().starts_with(MARK_END))
        }
        None => false,
    }
}

/// Write a new hosts entry mapping (domain -> ip) inside our marker block.
/// Mirrors UpdateHosts: replace existing block, keeping a backup block.
pub fn update_hosts(entries: &[(String, String)]) -> Result<(), String> {
    let content = read_hosts().unwrap_or_default();
    let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();

    // Separate into: pre-marker, our block, backup block, post-marker.
    let mut pre: Vec<String> = Vec::new();
    let mut backup: Vec<String> = Vec::new();
    let mut post: Vec<String> = Vec::new();
    enum Phase { Before, InBlock, InBackup, After }
    let mut phase = Phase::Before;
    for line in lines {
        let t = line.trim_end();
        match phase {
            Phase::Before => {
                if t.starts_with(MARK_START) {
                    phase = Phase::InBlock;
                } else if t.starts_with(BACKUP_MARK_START) {
                    phase = Phase::InBackup;
                } else {
                    pre.push(line);
                }
            }
            Phase::InBlock => {
                if t.starts_with(MARK_END) {
                    phase = Phase::After;
                }
                // drop old block content
            }
            Phase::InBackup => {
                if t.starts_with(BACKUP_MARK_END) {
                    phase = Phase::After;
                } else {
                    backup.push(line);
                }
            }
            Phase::After => post.push(line),
        }
    }

    // Build the new content.
    let mut out: Vec<String> = Vec::new();
    // Trim trailing blank lines from pre for cleanliness.
    while out_is_blank_tail(&pre) {
        let _ = pre.pop();
    }
    if !pre.is_empty() {
        out.push(String::new());
    }
    out.push(MARK_START.to_string());
    for (domain, ip) in entries {
        out.push(format!("{} {}", ip, domain));
    }
    out.push(MARK_END.to_string());
    if !backup.is_empty() {
        out.push(BACKUP_MARK_START.to_string());
        out.extend(backup);
        out.push(BACKUP_MARK_END.to_string());
    }
    out.push(String::new());
    out.extend(post);

    let text = out.join("
") + "
";
    std::fs::write(hosts_file_path(), text).map_err(|e| e.to_string())
}

fn out_is_blank_tail(v: &[String]) -> bool {
    match v.last() {
        Some(l) => l.trim().is_empty() && v.len() > 1,
        None => false,
    }
}

/// Remove our marker block from the hosts file. Mirrors RemoveHostsByTag.
pub fn remove_by_tag() -> Result<(), String> {
    let content = read_hosts().unwrap_or_default();
    let lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut out: Vec<String> = Vec::new();
    enum Phase { Before, InBlock, InBackup, After }
    let mut phase = Phase::Before;
    for line in lines {
        let t = line.trim_end();
        match phase {
            Phase::Before => {
                if t.starts_with(MARK_START) {
                    phase = Phase::InBlock;
                } else if t.starts_with(BACKUP_MARK_START) {
                    phase = Phase::InBackup;
                } else {
                    out.push(line);
                }
            }
            Phase::InBlock => {
                if t.starts_with(MARK_END) {
                    phase = Phase::After;
                }
            }
            Phase::InBackup => {
                if t.starts_with(BACKUP_MARK_END) {
                    phase = Phase::After;
                }
            }
            Phase::After => out.push(line),
        }
    }
    let text = out.join("
") + "
";
    std::fs::write(hosts_file_path(), text).map_err(|e| e.to_string())
}

/// Reset the hosts file to a minimal default (mirrors ResetFile).
pub fn reset_file() -> Result<(), String> {
    let default_content = "#
# This is a sample hosts file for WattToolkit-Lite.
# https://learn.microsoft.com/previous-versions//cc786524
#
127.0.0.1       localhost
::1             localhost
";
    std::fs::write(hosts_file_path(), default_content).map_err(|e| e.to_string())
}
