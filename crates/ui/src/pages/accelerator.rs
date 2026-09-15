//! Acceleration page (mirrors AcceleratorPage2).

use crate::App;
use eframe::egui;
use std::collections::HashSet;
use wtlite_core::model::{AccelerateProject, AccelerateProjectGroup, ProxyMode};

/// Hosts file location (Windows).
const HOSTS_PATH: &str = r"C:\Windows\System32\drivers\etc\hosts";

/// Sub-tabs of the acceleration page.
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum AccTab {
    Platform,
    Services,
    Scripts,
    Logs,
    Traffic,
    NetTest,
}

/// Per-page state (sub-tab + network test results).
pub struct AccState {
    pub tab: AccTab,
    pub net_test_results: Vec<wtlite_core::nettest::TestResult>,
    pub testing: bool,
    /// Group names that are currently collapsed (empty = all expanded).
    pub collapsed: HashSet<String>,
}

impl Default for AccState {
    fn default() -> Self {
        Self {
            tab: AccTab::Platform,
            net_test_results: Vec::new(),
            testing: false,
            collapsed: HashSet::new(),
        }
    }
}

pub fn show(app: &mut App, ui: &mut egui::Ui) {
    let mut tab = crate::pages::GLOBAL_ACC.lock().unwrap().tab;

    egui::SidePanel::right("right_panel")
        .exact_width(280.0)
        .resizable(false)
        .show_inside(ui, |ui| {
            ui.add_space(8.0);
            right_panel(app, ui);
        });

    ui.add_space(8.0);
    crate::pages::hrow(ui, |ui| {
        if crate::pages::tab_btn(ui, tab == AccTab::Platform, "平台加速") {
            tab = AccTab::Platform;
        }
        if crate::pages::tab_btn(ui, tab == AccTab::Services, "服务") {
            tab = AccTab::Services;
        }
        if crate::pages::tab_btn(ui, tab == AccTab::Scripts, "加速脚本") {
            tab = AccTab::Scripts;
        }
        if crate::pages::tab_btn(ui, tab == AccTab::Logs, "代理日志") {
            tab = AccTab::Logs;
        }
        if crate::pages::tab_btn(ui, tab == AccTab::Traffic, "流量统计") {
            tab = AccTab::Traffic;
        }
        if crate::pages::tab_btn(ui, tab == AccTab::NetTest, "网络检测") {
            tab = AccTab::NetTest;
        }
    });
    {
        let mut st = crate::pages::GLOBAL_ACC.lock().unwrap();
        st.tab = tab;
    }

    ui.separator();
    ui.add_space(4.0);

    egui::ScrollArea::vertical().show(ui, |ui| match tab {
        AccTab::Platform => platform_tab(app, ui),
        AccTab::Services => services_tab(app, ui),
        AccTab::Scripts => scripts_tab(app, ui),
        AccTab::Logs => logs_tab(app, ui),
        AccTab::Traffic => traffic_tab(app, ui),
        AccTab::NetTest => net_test_tab(app, ui),
    });
}

fn right_panel(app: &mut App, ui: &mut egui::Ui) {
    ui.heading("加速控制");
    let running = app.proxy.is_running();
    let btn = if running {
        egui::Button::new(
            egui::RichText::new("停止加速").color(egui::Color32::from_rgb(255, 120, 120)),
        )
    } else {
        egui::Button::new(
            egui::RichText::new("启动加速").color(egui::Color32::from_rgb(120, 255, 120)),
        )
    };
    if ui.add_sized([240.0, 44.0], btn).clicked() {
        if running {
            app.proxy.stop();
            app.set_toast("加速已停止");
        } else {
            let groups = app.accel.groups();
            let ids: Vec<String> = groups
                .iter()
                .flat_map(|g| g.items.iter().flat_map(|p| p.enabled_ids()))
                .collect();
            app.settings.proxy.support_proxy_services_status = ids;
            let _ = app.settings.save();
            let mode = app.settings.proxy.proxy_mode;
            let settings = app.settings.proxy.clone();
            start_async(app, mode, settings, groups);
        }
    }
    ui.add_space(8.0);

    // 加速模式快速切换（原项目代理设置中的模式选择）。
    crate::pages::hrow(ui, |ui| {
        ui.label("加速模式:");
        let m = app.settings.proxy.proxy_mode;
        egui::ComboBox::from_id_salt("accel_mode")
            .selected_text(m.display_name())
            .width(140.0)
            .show_ui(ui, |ui| {
                for mode in wtlite_core::model::ProxyMode::available() {
                    let selected = *mode == app.settings.proxy.proxy_mode;
                    if ui.selectable_label(selected, mode.display_name()).clicked() {
                        app.switch_proxy_mode(*mode);
                    }
                }
            });
    });
    ui.add_space(4.0);
    ui.separator();
    ui.add_space(4.0);

    if ui.button("代理设置").clicked() {
        app.proxy_dialog = Some(crate::ProxySettingsDialog::from_settings(&app.settings.proxy));
    }
    ui.add_space(8.0);

    ui.heading("证书");
    crate::pages::hrow(ui, |ui| {
        if ui.button("安装证书").clicked() {
            let msg = app.proxy.cert.install().unwrap_or_else(|e| format!("失败: {e}"));
            app.set_toast(format!("证书: {msg}"));
        }
        if ui.button("删除证书").clicked() {
            let msg = app.proxy.cert.remove().unwrap_or_else(|e| format!("失败: {e}"));
            app.set_toast(format!("证书: {msg}"));
        }
        if ui.button("查看").clicked() {
            app.cert_dialog = Some(app.proxy.cert.info());
        }
        if ui.button("打开目录").clicked() {
            let _ = open::that(wtlite_core::paths::cert_dir().to_string_lossy().to_string());
        }
    });
    ui.add_space(8.0);

    ui.heading("Hosts");
    crate::pages::hrow(ui, |ui| {
        if ui.button("编辑").clicked() {
            let _ = open::that(HOSTS_PATH);
        }
        if ui.button("重置").clicked() {
            let r = wtlite_core::hosts::reset_file();
            app.set_toast(match r {
                Ok(()) => "Hosts 已重置".to_string(),
                Err(e) => format!("重置失败: {e}"),
            });
        }
        if ui.button("打开").clicked() {
            let _ = open::that(HOSTS_PATH);
        }
    });
    ui.add_space(8.0);

    if ui.button("打开日志目录").clicked() {
        let _ = open::that(wtlite_core::paths::log_dir().to_string_lossy().to_string());
    }
}

/// Last proxy start error, surfaced to the UI on the next frame.
pub static START_ERROR: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Start the proxy on a background thread.
///
/// The runtime is owned by `ProxyManager` (`start_blocking`), because the
/// listeners are spawned tasks: a runtime that dies with this thread would
/// cancel them, leaving the UI reporting "running" while nothing is bound.
pub(crate) fn start_async(
    app: &mut App,
    mode: ProxyMode,
    settings: wtlite_core::settings::ProxySettings,
    groups: Vec<AccelerateProjectGroup>,
) {
    let proxy = app.proxy.clone();
    std::thread::spawn(move || {
        match proxy.start_blocking(mode, &settings, &groups) {
            Ok(()) => log::info!("proxy started ({mode:?})"),
            Err(e) => {
                log::error!("proxy start failed: {e}");
                *START_ERROR.lock().unwrap() = Some(e);
            }
        }
    });
    app.set_toast(format!("正在启动加速…（{}）", mode.display_name()));
}

fn platform_tab(app: &mut App, ui: &mut egui::Ui) {
    let groups = app.accel.groups();
    if groups.is_empty() {
        ui.label("尚未加载加速项目。");
        return;
    }
    let mut toggled: Option<String> = None;
    {
        let st = crate::pages::GLOBAL_ACC.lock().unwrap();
        for grp in &groups {
            ui.add_space(4.0);
            let grp_name = grp.name.clone();
            let open = !st.collapsed.contains(&grp_name);
            // Group header row: [arrow] [checkbox] name (n 项)
            let mut on = group_enabled(grp);
            crate::pages::hrow(ui, |ui| {
                let arrow = if open { "▾" } else { "▸" };
                if ui.add(egui::Button::new(arrow).small()).clicked() {
                    toggled = Some(grp_name.clone());
                }
                if ui
                    .checkbox(&mut on, format!("{} ({} 项)", grp.name, count_group_items(grp)))
                    .changed()
                {
                    set_group_enable(app, &grp.name, on);
                }
            });
            if open {
                ui.indent(grp_name.as_str(), |ui| {
                    for proj in &grp.items {
                        project_tree(app, ui, proj);
                    }
                });
            }
        }
    }
    if let Some(name) = toggled {
        let mut st = crate::pages::GLOBAL_ACC.lock().unwrap();
        if st.collapsed.contains(&name) {
            st.collapsed.remove(&name);
        } else {
            st.collapsed.insert(name);
        }
    }
}

/// True when every leaf project in the group is enabled.
fn group_enabled(grp: &AccelerateProjectGroup) -> bool {
    let mut all = true;
    let mut any = false;
    for p in &grp.items {
        for leaf in p.all_leaves() {
            any = true;
            if leaf.three_state_enable != Some(true) {
                all = false;
            }
        }
    }
    all && any
}

/// Total leaf count in a group.
fn count_group_items(grp: &AccelerateProjectGroup) -> usize {
    grp.items.iter().map(|p| p.all_leaves().len()).sum()
}

/// Total leaf count under a project (including itself when it is a leaf).
fn count_group_leaves(proj: &AccelerateProject) -> usize {
    if proj.items.is_empty() {
        1
    } else {
        proj.items.iter().map(|c| count_group_leaves(c)).sum()
    }
}

fn project_tree(app: &mut App, ui: &mut egui::Ui, proj: &AccelerateProject) {
    if proj.items.is_empty() {
        let label = format!("{} ({} 个域名)", proj.name, count_domains(&proj.listen_domain_names));
        let mut on = proj.three_state_enable == Some(true);
        if ui.checkbox(&mut on, &label).changed() {
            set_project_enable(app, &proj.id, on);
        }
    } else {
        egui::CollapsingHeader::new(format!("{} ({} 项)", proj.name, count_group_leaves(proj)))
            .id_salt(proj.id.clone())
            .default_open(true)
            .show(ui, |ui| {
                ui.indent(proj.id.clone(), |ui| {
                    for child in &proj.items {
                        project_tree(app, ui, child);
                    }
                });
            });
    }
}

fn count_domains(s: &str) -> usize {
    s.split(';').map(|x| x.trim()).filter(|x| !x.is_empty()).count()
}

fn set_group_enable(app: &mut App, name: &str, on: bool) {
    let mut groups = app.accel.groups();
    if let Some(g) = groups.iter_mut().find(|g| &g.name == name) {
        g.three_state_enable = Some(on);
        for p in g.items.iter_mut() {
            let set: HashSet<String> = if on {
                p.all_leaves().iter().map(|l| l.id.clone()).collect()
            } else {
                HashSet::new()
            };
            p.restore_enable(&set);
        }
    }
    commit_groups(app, groups);
}

fn set_project_enable(app: &mut App, id: &str, on: bool) {
    let mut groups = app.accel.groups();
    let mut found = false;
    for g in groups.iter_mut() {
        if set_leaf(&mut g.items, id, on) {
            found = true;
        }
    }
    if found {
        commit_groups(app, groups);
    }
}

fn set_leaf(items: &mut [AccelerateProject], id: &str, on: bool) -> bool {
    for p in items.iter_mut() {
        if p.id == id {
            p.three_state_enable = Some(on);
            return true;
        }
        if set_leaf(&mut p.items, id, on) {
            return true;
        }
    }
    false
}

/// Commit checkbox changes back into the service (via enabled IDs).
fn commit_groups(app: &mut App, groups: Vec<AccelerateProjectGroup>) {
    let ids: Vec<String> = groups
        .iter()
        .flat_map(|g| g.items.iter().flat_map(|p| p.enabled_ids()))
        .collect();
    app.accel.apply_enabled(&ids);
}

fn services_tab(app: &mut App, ui: &mut egui::Ui) {
    let groups = app.accel.groups();
    for grp in &groups {
        ui.strong(&grp.name);
        for proj in &grp.items {
            for leaf in proj.all_leaves() {
                let mut on = leaf.three_state_enable == Some(true);
                if ui.checkbox(&mut on, &leaf.name).changed() {
                    set_project_enable(app, &leaf.id, on);
                }
            }
        }
    }
}

fn scripts_tab(app: &mut App, ui: &mut egui::Ui) {
    ui.heading("加速脚本");
    let mut on = app.settings.proxy.is_enable_script;
    if ui.checkbox(&mut on, "启用加速脚本").changed() {
        app.settings.proxy.is_enable_script = on;
        let _ = app.settings.save();
    }
    ui.label("加速脚本用于自定义域名匹配与转发规则。当前版本提供基础开关。");
}

fn logs_tab(app: &mut App, ui: &mut egui::Ui) {
    crate::pages::hrow(ui, |ui| {
        if ui.button("清空").clicked() {
            app.logs.clear();
        }
        ui.label("代理日志（最新 1000 条）");
    });
    egui::Frame::default()
        .fill(egui::Color32::from_rgb(20, 20, 20))
        .show(ui, |ui| {
            let mut text = String::new();
            for line in app.logs.iter().rev().take(500) {
                text.push_str(line);
                text.push('\n');
            }
            ui.monospace(if text.is_empty() { "(空)" } else { &text });
        });
}

fn traffic_tab(app: &mut App, ui: &mut egui::Ui) {
    let stats = app.proxy.stats();
    let s = stats.lock().unwrap();
    ui.label(format!("总流量: {} 字节", s.total_bytes));
    ui.add_space(6.0);
    for (d, b) in s.by_domain.iter() {
        crate::pages::hrow(ui, |ui| {
            ui.monospace(d);
            ui.label(format!("{} 字节", b));
        });
    }
}

fn net_test_tab(_app: &mut App, ui: &mut egui::Ui) {
    crate::pages::hrow(ui, |ui| {
        let testing = crate::pages::GLOBAL_ACC.lock().unwrap().testing;
        let label = if testing { "检测中…" } else { "开始检测" };
        if ui.add_enabled(!testing, egui::Button::new(label)).clicked() {
            {
                let mut st = crate::pages::GLOBAL_ACC.lock().unwrap();
                st.testing = true;
            }
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async move {
                    let mut results = Vec::new();
                    results.push(wtlite_core::nettest::check_nat().await);
                    results.push(wtlite_core::nettest::check_doh(
                        "Tencent DoH",
                        wtlite_core::dns::dns_const::DNS_ALI_DOH,
                    )
                    .await);
                    results.push(wtlite_core::nettest::check_doh(
                        "DNSPod DoH",
                        wtlite_core::dns::dns_const::DNSPOD_DOH,
                    )
                    .await);
                    results.push(wtlite_core::nettest::check_doh(
                        "Google DoH",
                        wtlite_core::dns::dns_const::GOOGLE_DOH,
                    )
                    .await);
                    results.push(wtlite_core::nettest::check_ipv6().await);
                    results.push(
                        wtlite_core::nettest::check_domain(
                            "域名连接",
                            wtlite_core::nettest::default_test_domain(),
                        )
                        .await,
                    );
                    let mut st = crate::pages::GLOBAL_ACC.lock().unwrap();
                    st.net_test_results = results;
                    st.testing = false;
                });
            });
        }
    });
    ui.add_space(6.0);
    let results = crate::pages::GLOBAL_ACC.lock().unwrap().net_test_results.clone();
    for r in &results {
        crate::pages::hrow(ui, |ui| {
            let color = match r.color {
                wtlite_core::nettest::TestColor::Green => egui::Color32::from_rgb(80, 200, 80),
                wtlite_core::nettest::TestColor::Orange => egui::Color32::from_rgb(255, 180, 60),
                wtlite_core::nettest::TestColor::Red => egui::Color32::from_rgb(255, 90, 90),
            };
            ui.colored_label(color, "●");
            ui.strong(&r.name);
            ui.label(&r.detail);
        });
    }
    if results.is_empty() {
        ui.label("点击“开始检测”运行网络诊断。");
    }
}
