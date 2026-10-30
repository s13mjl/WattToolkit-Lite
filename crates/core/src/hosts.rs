//! Hosts file management, mirroring the original HostsFileServiceImpl.
//!
//! Uses marker blocks in the system hosts file so entries can be added and
//! removed atomically. The original uses "Steam++" markers; this secondary
//! development uses its own "WattToolkit-Lite" markers to avoid clobbering
//! the upstream app's entries.
//!
//! Entries that already existed for a managed domain are moved into a backup
//! block (like the original) and restored when acceleration stops, so starting
//! and stopping the proxy does not destroy the user's own hosts mappings.

use std::collections::HashSet;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

const MARK_START: &str = "# WattToolkit-Lite Start";
const MARK_END: &str = "# WattToolkit-Lite End";
const BACKUP_MARK_START: &str = "# WattToolkit-Lite Backup Start";
const BACKUP_MARK_END: &str = "# WattToolkit-Lite Backup End";

/// The original uses `Environment.SystemDirectory` (normally
/// `C:\Windows\System32`); `%SystemRoot%` is the equivalent without a Win32
/// call. The previous literal lost its backslashes and wrote a drive-relative
/// file named `C:WindowsSystem32driversetchosts` in the current directory.
pub fn hosts_file_path() -> PathBuf {
    let windows = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    windows
        .join("System32")
        .join("drivers")
        .join("etc")
        .join("hosts")
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

fn decode_hosts(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        String::from_utf8_lossy(rest).into_owned()
    } else if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        decode_utf16(rest, true)
    } else if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        decode_utf16(rest, false)
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn read_hosts_at(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    Some(decode_hosts(&bytes))
}

/// Read the hosts file content (best effort).
pub fn read_hosts() -> Option<String> {
    read_hosts_at(&hosts_file_path())
}

fn is_mark(line: &str, mark: &str) -> bool {
    // The original normalizes whitespace before comparing markers.
    let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.eq_ignore_ascii_case(mark)
}

fn is_blank_or_comment(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.is_empty() || trimmed.starts_with('#')
}

/// The domains of a hosts line, lowercased. A line with an invalid address or
/// no host names yields `None` (comments, blanks and malformed lines are kept
/// verbatim by the caller).
fn line_domains(line: &str) -> Option<Vec<String>> {
    if is_blank_or_comment(line) {
        return None;
    }
    let mut parts = line.trim().split_whitespace();
    let ip = parts.next()?;
    if ip.parse::<IpAddr>().is_err() {
        return None;
    }
    let mut domains = Vec::new();
    for token in parts {
        if token.starts_with('#') {
            break;
        }
        domains.push(token.to_lowercase());
    }
    if domains.is_empty() {
        None
    } else {
        Some(domains)
    }
}

fn push_unique(lines: &mut Vec<String>, seen: &mut HashSet<String>, line: String) {
    if line.trim().is_empty() {
        return;
    }
    if seen.insert(line.clone()) {
        lines.push(line);
    }
}

fn join_hosts(lines: &[String]) -> String {
    let mut text = lines.join("\r\n");
    if !text.is_empty() {
        text.push_str("\r\n");
    }
    text
}

fn write_hosts_at(path: &Path, text: &str) -> Result<(), String> {
    const MAX_FILE_LENGTH: usize = 50 * 1024 * 1024;
    if text.len() > MAX_FILE_LENGTH {
        return Err("hosts 文件超过 50MB 上限".to_string());
    }
    let was_readonly = std::fs::metadata(path)
        .map(|meta| meta.permissions().readonly())
        .unwrap_or(false);
    if was_readonly {
        let mut permissions = std::fs::metadata(path)
            .map_err(|e| e.to_string())?
            .permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(path, permissions).map_err(|e| e.to_string())?;
    }
    let result = std::fs::write(path, text.as_bytes()).map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            format!("拒绝访问：修改 hosts 需要管理员权限（请以管理员身份运行本程序）: {e}")
        } else {
            e.to_string()
        }
    });
    if was_readonly {
        if let Ok(meta) = std::fs::metadata(path) {
            let mut permissions = meta.permissions();
            permissions.set_readonly(true);
            let _ = std::fs::set_permissions(path, permissions);
        }
    }
    result
}

/// Whether our marker block is present in the hosts file.
pub fn contains_by_tag() -> bool {
    match read_hosts() {
        Some(content) => content
            .lines()
            .any(|line| is_mark(line, MARK_START) || is_mark(line, MARK_END)),
        None => false,
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Phase {
    Main,
    Block,
    Backup,
}

/// Replace our block with `entries`, preserving unrelated lines and moving
/// conflicting user entries into the backup block.
fn update_hosts_at(path: &Path, entries: &[(String, String)]) -> Result<(), String> {
    let content = read_hosts_at(path).unwrap_or_default();
    let managed: HashSet<String> = entries
        .iter()
        .map(|(domain, _)| domain.trim().to_lowercase())
        .filter(|domain| !domain.is_empty())
        .collect();
    let mut main_lines: Vec<String> = Vec::new();
    let mut backup_lines: Vec<String> = Vec::new();
    let mut backup_seen: HashSet<String> = HashSet::new();
    let mut phase = Phase::Main;

    for raw in content.lines() {
        let line = raw.trim_end_matches('\r').to_string();
        match phase {
            Phase::Main => {
                if is_mark(&line, MARK_START) {
                    phase = Phase::Block;
                } else if is_mark(&line, BACKUP_MARK_START) {
                    phase = Phase::Backup;
                } else if is_mark(&line, MARK_END) || is_mark(&line, BACKUP_MARK_END) {
                    // Stray end marker: do not copy it.
                } else if let Some(domains) = line_domains(&line) {
                    if domains.iter().any(|domain| managed.contains(domain)) {
                        push_unique(&mut backup_lines, &mut backup_seen, line);
                    } else {
                        main_lines.push(line);
                    }
                } else {
                    main_lines.push(line);
                }
            }
            Phase::Block => {
                if is_mark(&line, MARK_END) {
                    phase = Phase::Main;
                }
                // Everything inside our block is regenerated.
            }
            Phase::Backup => {
                if is_mark(&line, BACKUP_MARK_END) {
                    phase = Phase::Main;
                } else if let Some(domains) = line_domains(&line) {
                    if domains.iter().any(|domain| managed.contains(domain)) {
                        push_unique(&mut backup_lines, &mut backup_seen, line);
                    } else {
                        // No longer managed: restore the user's original entry.
                        main_lines.push(line);
                    }
                } else {
                    // Backup comments/blank structure are kept.
                    push_unique(&mut backup_lines, &mut backup_seen, line);
                }
            }
        }
    }

    while main_lines
        .last()
        .map(|line| line.trim().is_empty())
        .unwrap_or(false)
    {
        main_lines.pop();
    }
    let mut out = main_lines;
    if !out.is_empty() {
        out.push(String::new());
    }
    out.push(MARK_START.to_string());
    for (domain, ip) in entries {
        let domain = domain.trim();
        let ip = ip.trim();
        if !domain.is_empty() && !ip.is_empty() {
            out.push(format!("{ip} {domain}"));
        }
    }
    out.push(MARK_END.to_string());
    if !backup_lines.is_empty() {
        out.push(String::new());
        out.push(BACKUP_MARK_START.to_string());
        out.extend(backup_lines);
        out.push(BACKUP_MARK_END.to_string());
    }
    out.push(String::new());
    write_hosts_at(path, &join_hosts(&out))
}

/// Write a new hosts entry mapping (domain -> ip) inside our marker block.
pub fn update_hosts(entries: &[(String, String)]) -> Result<(), String> {
    update_hosts_at(&hosts_file_path(), entries)
}

fn remove_hosts_at(path: &Path) -> Result<(), String> {
    let content = read_hosts_at(path).unwrap_or_default();
    let mut main_lines: Vec<String> = Vec::new();
    let mut backup_lines: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    let mut phase = Phase::Main;
    for raw in content.lines() {
        let line = raw.trim_end_matches('\r').to_string();
        match phase {
            Phase::Main => {
                if is_mark(&line, MARK_START) {
                    phase = Phase::Block;
                } else if is_mark(&line, BACKUP_MARK_START) {
                    phase = Phase::Backup;
                } else if is_mark(&line, MARK_END) || is_mark(&line, BACKUP_MARK_END) {
                    // Stray end marker.
                } else {
                    main_lines.push(line);
                }
            }
            Phase::Block => {
                if is_mark(&line, MARK_END) {
                    phase = Phase::Main;
                }
            }
            Phase::Backup => {
                if is_mark(&line, BACKUP_MARK_END) {
                    phase = Phase::Main;
                } else {
                    push_unique(&mut backup_lines, &mut seen, line);
                }
            }
        }
    }
    while main_lines
        .last()
        .map(|line| line.trim().is_empty())
        .unwrap_or(false)
    {
        main_lines.pop();
    }
    if !backup_lines.is_empty() {
        if !main_lines.is_empty() {
            main_lines.push(String::new());
        }
        main_lines.extend(backup_lines);
    }
    write_hosts_at(path, &join_hosts(&main_lines))
}

/// Remove our marker block from the hosts file, restoring backed-up entries.
pub fn remove_by_tag() -> Result<(), String> {
    remove_hosts_at(&hosts_file_path())
}

/// The default hosts file content written by ResetFile (Windows sample).
const DEFAULT_HOSTS: &str = "\
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#\t127.0.0.1       localhost
#\t::1             localhost
";

/// Reset the hosts file to the Windows default sample (mirrors ResetFile).
pub fn reset_file() -> Result<(), String> {
    write_hosts_at(&hosts_file_path(), DEFAULT_HOSTS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_hosts() -> PathBuf {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let name = format!(
            "wtlite-hosts-test-{}-{}.txt",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(name);
        let _ = std::fs::remove_file(&path);
        path
    }

    #[test]
    fn the_hosts_path_is_the_system32_path_with_real_separators() {
        let text = hosts_file_path().to_string_lossy().to_lowercase();
        assert!(
            text.ends_with("drivers\\etc\\hosts") || text.ends_with("drivers/etc/hosts"),
            "unexpected hosts path: {text}"
        );
        assert!(!text.contains("windowssystem32"), "{text}");
    }

    #[test]
    fn conflicting_user_entries_are_backed_up_and_restored() {
        let path = temp_hosts();
        write_hosts_at(
            &path,
            "127.0.0.1 localhost\r\n1.2.3.4 example.com\r\n# keep me\r\n",
        )
        .unwrap();
        update_hosts_at(
            &path,
            &[
                ("example.com".to_string(), "127.0.0.1".to_string()),
                ("new.example".to_string(), "127.0.0.1".to_string()),
            ],
        )
        .unwrap();
        let updated = read_hosts_at(&path).unwrap();
        assert!(updated.contains(MARK_START), "{updated}");
        assert!(updated.contains("127.0.0.1 example.com"), "{updated}");
        assert!(updated.contains("127.0.0.1 new.example"), "{updated}");
        assert!(updated.contains(BACKUP_MARK_START), "{updated}");
        assert!(updated.contains("1.2.3.4 example.com"), "{updated}");
        assert!(updated.contains("127.0.0.1 localhost"), "{updated}");
        assert!(updated.contains("# keep me"), "{updated}");

        remove_hosts_at(&path).unwrap();
        let restored = read_hosts_at(&path).unwrap();
        assert!(!restored.contains(MARK_START), "{restored}");
        assert!(!restored.contains(BACKUP_MARK_START), "{restored}");
        assert!(restored.contains("1.2.3.4 example.com"), "{restored}");
        assert!(restored.contains("127.0.0.1 localhost"), "{restored}");
        assert!(restored.contains("# keep me"), "{restored}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn an_unmanaged_backup_entry_is_restored_on_the_next_update() {
        let path = temp_hosts();
        write_hosts_at(&path, "127.0.0.1 localhost\r\n1.2.3.4 old.example\r\n").unwrap();
        update_hosts_at(
            &path,
            &[("old.example".to_string(), "127.0.0.1".to_string())],
        )
        .unwrap();
        update_hosts_at(
            &path,
            &[("other.example".to_string(), "127.0.0.1".to_string())],
        )
        .unwrap();
        let updated = read_hosts_at(&path).unwrap();
        // old.example is no longer managed, so its original mapping returns to
        // the normal part of the file instead of staying hidden in the backup.
        assert!(
            updated.contains("1.2.3.4 old.example"),
            "restored line missing: {updated}"
        );
        assert!(updated.contains("127.0.0.1 other.example"), "{updated}");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_read_only_hosts_file_is_written_and_keeps_its_attribute() {
        let path = temp_hosts();
        std::fs::write(&path, "127.0.0.1 localhost\r\n").unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&path, permissions).unwrap();
        update_hosts_at(
            &path,
            &[("example.com".to_string(), "127.0.0.1".to_string())],
        )
        .unwrap();
        assert!(std::fs::metadata(&path).unwrap().permissions().readonly());
        assert!(read_hosts_at(&path)
            .unwrap()
            .contains("127.0.0.1 example.com"));
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(false);
        let _ = std::fs::set_permissions(&path, permissions);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn utf16_hosts_files_are_decoded() {
        let path = temp_hosts();
        let mut bytes = vec![0xFF, 0xFE];
        for unit in "127.0.0.1 localhost\r\n".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(&path, bytes).unwrap();
        update_hosts_at(
            &path,
            &[("example.com".to_string(), "127.0.0.1".to_string())],
        )
        .unwrap();
        let text = read_hosts_at(&path).unwrap();
        assert!(text.contains("127.0.0.1 localhost"), "{text}");
        assert!(text.contains("127.0.0.1 example.com"), "{text}");
        let _ = std::fs::remove_file(&path);
    }
}
