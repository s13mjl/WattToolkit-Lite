//! Pure UI logic: acceleration-tree toggling, log/traffic formatting and the
//! proxy-dialog <-> settings mapping. No Win32 here, so it is unit-testable.

use std::collections::{HashMap, VecDeque};

use wtlite_core::model::{AccelerateProject, AccelerateProjectGroup, ExternalProxyType, ProxyMode};
use wtlite_core::settings::ProxySettings;

/// Domains in a semicolon-separated manifest field.
pub fn count_domains(s: &str) -> usize {
    s.split(';')
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .count()
}

/// (enabled leaves, total leaves) under a project.
fn project_counts(p: &AccelerateProject) -> (usize, usize) {
    if p.items.is_empty() {
        (usize::from(p.three_state_enable == Some(true)), 1)
    } else {
        p.items.iter().fold((0, 0), |(on, total), c| {
            let (o, t) = project_counts(c);
            (on + o, total + t)
        })
    }
}

pub fn count_project_leaves(p: &AccelerateProject) -> usize {
    project_counts(p).1
}

pub fn count_group_leaves(g: &AccelerateProjectGroup) -> usize {
    g.items.iter().map(count_project_leaves).sum()
}

pub fn group_enabled(g: &AccelerateProjectGroup) -> bool {
    let (on, total) = g.items.iter().fold((0, 0), |(on, total), p| {
        let (o, t) = project_counts(p);
        (on + o, total + t)
    });
    total > 0 && on == total
}

/// All enabled leaf IDs (what the proxy actually receives).
pub fn enabled_ids(groups: &[AccelerateProjectGroup]) -> Vec<String> {
    groups
        .iter()
        .flat_map(|g| g.items.iter().flat_map(|p| p.enabled_ids()))
        .collect()
}

fn each_leaf_mut(p: &mut AccelerateProject, f: &mut impl FnMut(&mut AccelerateProject)) {
    if p.items.is_empty() {
        f(p);
    } else {
        for c in &mut p.items {
            each_leaf_mut(c, f);
        }
    }
}

fn set_leaf_in(p: &mut AccelerateProject, id: &str, on: bool) -> bool {
    if p.items.is_empty() {
        if p.id == id {
            p.three_state_enable = Some(on);
            return true;
        }
        return false;
    }
    for c in &mut p.items {
        if set_leaf_in(c, id, on) {
            return true;
        }
    }
    false
}

fn derive(p: &mut AccelerateProject) -> (usize, usize) {
    if p.items.is_empty() {
        return (usize::from(p.three_state_enable == Some(true)), 1);
    }
    let (on, total) = p.items.iter_mut().fold((0, 0), |(on, total), c| {
        let (o, t) = derive(c);
        (on + o, total + t)
    });
    p.three_state_enable = if on == 0 {
        Some(false)
    } else if on == total {
        Some(true)
    } else {
        None
    };
    (on, total)
}

/// Recompute container/group states from the leaves after any toggle.
pub fn recompute(groups: &mut [AccelerateProjectGroup]) {
    for g in groups.iter_mut() {
        let (on, total) = g.items.iter_mut().fold((0, 0), |(on, total), p| {
            let (o, t) = derive(p);
            (on + o, total + t)
        });
        g.three_state_enable = if total == 0 {
            Some(false)
        } else if on == total {
            Some(true)
        } else if on == 0 {
            Some(false)
        } else {
            None
        };
    }
}

pub fn leaf_states(groups: &[AccelerateProjectGroup]) -> HashMap<String, bool> {
    fn walk(p: &AccelerateProject, out: &mut HashMap<String, bool>) {
        if p.items.is_empty() {
            out.insert(p.id.clone(), p.three_state_enable == Some(true));
        } else {
            for c in &p.items {
                walk(c, out);
            }
        }
    }
    let mut out = HashMap::new();
    for g in groups {
        for p in &g.items {
            walk(p, &mut out);
        }
    }
    out
}

pub fn set_leaf(groups: &mut [AccelerateProjectGroup], id: &str, on: bool) -> bool {
    let mut found = false;
    for g in groups.iter_mut() {
        for p in &mut g.items {
            if set_leaf_in(p, id, on) {
                found = true;
                break;
            }
        }
        if found {
            break;
        }
    }
    if found {
        recompute(groups);
    }
    found
}

pub fn set_group(groups: &mut [AccelerateProjectGroup], name: &str, on: bool) -> bool {
    let Some(g) = groups.iter_mut().find(|g| g.name == name) else {
        return false;
    };
    for p in &mut g.items {
        each_leaf_mut(p, &mut |leaf| leaf.three_state_enable = Some(on));
    }
    recompute(groups);
    true
}

#[allow(dead_code)]
pub fn set_container(groups: &mut [AccelerateProjectGroup], container_id: &str, on: bool) -> bool {
    fn find_and_set(p: &mut AccelerateProject, id: &str, on: bool) -> bool {
        if p.id == id {
            for leaf in p.items.iter_mut() {
                each_leaf_mut(leaf, &mut |l| l.three_state_enable = Some(on));
            }
            return true;
        }
        for c in &mut p.items {
            if find_and_set(c, id, on) {
                return true;
            }
        }
        false
    }

    let mut found = false;
    for g in groups.iter_mut() {
        for p in &mut g.items {
            if find_and_set(p, container_id, on) {
                found = true;
                break;
            }
        }
        if found {
            break;
        }
    }
    if found {
        recompute(groups);
    }
    found
}

/// Newest-first log text (the same 500-line window the egui UI displayed).
pub fn logs_text(logs: &VecDeque<String>) -> String {
    if logs.is_empty() {
        return "(空)".to_string();
    }
    let mut out = String::with_capacity(logs.len().min(500) * 48);
    for line in logs.iter().rev().take(500) {
        out.push_str(line);
        out.push_str("\r\n");
    }
    out
}

/// Sorted traffic snapshot: total bytes plus (domain, bytes) descending.
pub fn traffic_snapshot(total: u64, by_domain: &HashMap<String, u64>) -> (u64, Vec<(String, u64)>) {
    let mut rows: Vec<(String, u64)> = by_domain.iter().map(|(k, v)| (k.clone(), *v)).collect();
    rows.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    (total, rows)
}

pub fn parse_port(text: &str, fallback: u16) -> u16 {
    text.trim().parse::<u16>().unwrap_or(fallback)
}

pub fn mode_index(mode: ProxyMode) -> i32 {
    ProxyMode::available()
        .iter()
        .position(|m| *m == mode)
        .unwrap_or(0) as i32
}

pub fn mode_from_index(index: i32) -> ProxyMode {
    let avail = ProxyMode::available();
    avail
        .get(index.max(0) as usize)
        .copied()
        .unwrap_or(avail[0])
}

/// Mutable copy of the proxy-settings dialog fields (mirrors the old egui one).
#[derive(Clone, Debug)]
pub struct ProxyDialogData {
    pub mode: ProxyMode,
    pub port: u16,
    pub dns: String,
    pub use_doh: bool,
    pub doh_address: String,
    pub enable_http_to_https: bool,
    pub enable_tls_decryption: bool,
    pub two_level_enable: bool,
    pub two_level_type: ExternalProxyType,
    pub two_level_ip: String,
    pub two_level_port: u16,
    pub two_level_user: String,
    pub two_level_password: String,
}

impl ProxyDialogData {
    pub fn from_settings(s: &ProxySettings) -> Self {
        Self {
            mode: s.proxy_mode,
            port: s.system_proxy_port,
            dns: s.proxy_master_dns.clone(),
            use_doh: s.use_doh,
            doh_address: s.custom_doh_address.clone(),
            enable_http_to_https: s.enable_http_proxy_to_https,
            enable_tls_decryption: s.enable_tls_decryption,
            two_level_enable: s.two_level_agent_enable,
            two_level_type: s.two_level_agent_type,
            two_level_ip: s.two_level_agent_ip.clone(),
            two_level_port: s.two_level_agent_port,
            two_level_user: s.two_level_agent_user.clone(),
            two_level_password: s.two_level_agent_password.clone(),
        }
    }

    pub fn apply_to(&self, s: &mut ProxySettings) {
        s.proxy_mode = self.mode;
        s.system_proxy_port = self.port;
        s.proxy_master_dns = self.dns.clone();
        s.use_doh = self.use_doh;
        s.custom_doh_address = self.doh_address.clone();
        s.enable_http_proxy_to_https = self.enable_http_to_https;
        s.enable_tls_decryption = self.enable_tls_decryption;
        s.two_level_agent_enable = self.two_level_enable;
        s.two_level_agent_type = self.two_level_type;
        s.two_level_agent_ip = self.two_level_ip.clone();
        s.two_level_agent_port = self.two_level_port;
        s.two_level_agent_user = self.two_level_user.clone();
        s.two_level_agent_password = self.two_level_password.clone();
    }
}

pub fn external_proxy_index(t: ExternalProxyType) -> i32 {
    match t {
        ExternalProxyType::Http => 0,
        ExternalProxyType::Socks4 => 1,
        ExternalProxyType::Socks5 => 2,
    }
}

pub fn external_proxy_from_index(index: i32) -> ExternalProxyType {
    match index {
        0 => ExternalProxyType::Http,
        1 => ExternalProxyType::Socks4,
        _ => ExternalProxyType::Socks5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(id: &str, on: Option<bool>) -> AccelerateProject {
        AccelerateProject {
            id: id.into(),
            name: id.into(),
            listen_domain_names: "a.com;b.com;".into(),
            three_state_enable: on,
            ..Default::default()
        }
    }

    fn groups() -> Vec<AccelerateProjectGroup> {
        vec![AccelerateProjectGroup {
            name: "G".into(),
            items: vec![
                AccelerateProject {
                    id: "p1".into(),
                    name: "P1".into(),
                    items: vec![leaf("a", Some(true)), leaf("b", Some(false))],
                    ..Default::default()
                },
                leaf("c", Some(false)),
            ],
            ..Default::default()
        }]
    }

    #[test]
    fn counts_and_group_state() {
        let g = &groups()[0];
        assert_eq!(count_domains("a.com; b.com;;"), 2);
        assert_eq!(count_group_leaves(g), 3);
        assert!(!group_enabled(g));
        let mut gs = groups();
        assert!(set_group(&mut gs, "G", true));
        assert!(group_enabled(&gs[0]));
        assert_eq!(enabled_ids(&gs), vec!["a", "b", "c"]);
        assert!(set_leaf(&mut gs, "b", false));
        assert!(!group_enabled(&gs[0]));
        assert_eq!(enabled_ids(&gs), vec!["a", "c"]);
        assert!(set_container(&mut gs, "p1", true));
        assert!(group_enabled(&gs[0]));
    }

    #[test]
    fn logs_are_newest_first_and_capped() {
        let mut logs = VecDeque::new();
        assert_eq!(logs_text(&logs), "(空)");
        for i in 0..700 {
            logs.push_back(format!("line {i}"));
        }
        while logs.len() > 1000 {
            logs.pop_front();
        }
        let text = logs_text(&logs);
        let first = text.lines().next().unwrap();
        assert_eq!(first, "line 699");
        assert_eq!(text.lines().count(), 500);
    }

    #[test]
    fn traffic_is_sorted_by_bytes_desc() {
        let map = HashMap::from([
            ("a".to_string(), 10u64),
            ("b".to_string(), 30u64),
            ("c".to_string(), 20u64),
        ]);
        let (total, rows) = traffic_snapshot(60, &map);
        assert_eq!(total, 60);
        assert_eq!(rows[0].0, "b");
        assert_eq!(rows[1].0, "c");
        assert_eq!(rows[2].0, "a");
    }

    #[test]
    fn ports_keep_the_previous_value_when_invalid() {
        assert_eq!(parse_port("26561", 1), 26561);
        assert_eq!(parse_port("", 1234), 1234);
        assert_eq!(parse_port("abc", 1234), 1234);
    }

    #[test]
    fn proxy_dialog_round_trips_every_field() {
        let mut s = ProxySettings::default();
        let mut d = ProxyDialogData::from_settings(&s);
        d.mode = ProxyMode::Pac;
        d.port = 12345;
        d.dns = "1.1.1.1".into();
        d.use_doh = false;
        d.doh_address = "https://example.test/resolve".into();
        d.enable_http_to_https = false;
        d.enable_tls_decryption = false;
        d.two_level_enable = true;
        d.two_level_type = ExternalProxyType::Http;
        d.two_level_ip = "10.0.0.2".into();
        d.two_level_port = 8080;
        d.two_level_user = "u".into();
        d.two_level_password = "p".into();
        d.apply_to(&mut s);
        let back = ProxyDialogData::from_settings(&s);
        assert_eq!(back.mode, d.mode);
        assert_eq!(back.port, d.port);
        assert_eq!(back.dns, d.dns);
        assert_eq!(back.use_doh, d.use_doh);
        assert_eq!(back.doh_address, d.doh_address);
        assert_eq!(back.enable_http_to_https, d.enable_http_to_https);
        assert_eq!(back.enable_tls_decryption, d.enable_tls_decryption);
        assert_eq!(back.two_level_enable, d.two_level_enable);
        assert_eq!(back.two_level_type, d.two_level_type);
        assert_eq!(back.two_level_ip, d.two_level_ip);
        assert_eq!(back.two_level_port, d.two_level_port);
        assert_eq!(back.two_level_user, d.two_level_user);
        assert_eq!(back.two_level_password, d.two_level_password);
    }
}
