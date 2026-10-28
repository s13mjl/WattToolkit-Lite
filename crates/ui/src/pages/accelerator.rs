//! Acceleration page: right control panel + six sub-tabs.

use std::collections::HashMap;

use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::Controls::{HTREEITEM, TVI_ROOT};
use windows_sys::Win32::UI::WindowsAndMessaging as wm;

use wtlite_core::model::{AccelerateProject, ProxyMode};

use crate::win32::{self, controls, Rect};
use crate::{ids, state, App};

#[derive(Clone, Debug)]
pub enum NodeRef {
    Group(String),
    Leaf(String),
}

pub unsafe fn build(app: &mut App) {
    let h = app.hwnd;
    let ui = app.fonts.ui;
    let bold = app.fonts.bold;

    app.ui.accel_heading = crate::pages::left_label(h, "加速控制", ids::ACCEL_HEADING, bold);
    app.ui.start = win32::create_control(
        h,
        windows_sys::Win32::UI::Controls::WC_BUTTONW,
        "启动加速",
        wm::BS_PUSHBUTTON as u32 | wm::WS_TABSTOP,
        0,
        ids::START,
        Rect::default(),
        app.fonts.button,
    );
    app.ui.mode_label = crate::pages::left_label(h, "加速模式:", ids::MODE_LABEL, ui);
    app.ui.mode_combo = crate::pages::combo(h, ids::MODE_COMBO, ui, false);
    let modes: Vec<&str> = ProxyMode::available().iter().map(|m| m.display_name()).collect();
    win32::combo_fill(app.ui.mode_combo, &modes);
    win32::set_combo_sel(app.ui.mode_combo, state::mode_index(app.settings.proxy.proxy_mode));
    app.ui.proxy_settings = crate::pages::button(h, "代理设置", ids::PROXY_SETTINGS, ui);

    app.ui.cert_heading = crate::pages::left_label(h, "证书", ids::CERT_HEADING, bold);
    app.ui.cert_install = crate::pages::button(h, "安装证书", ids::CERT_INSTALL, ui);
    app.ui.cert_remove = crate::pages::button(h, "删除证书", ids::CERT_REMOVE, ui);
    app.ui.cert_view = crate::pages::button(h, "查看", ids::CERT_VIEW, ui);
    app.ui.cert_open_dir = crate::pages::button(h, "打开目录", ids::CERT_OPEN_DIR, ui);

    app.ui.hosts_heading = crate::pages::left_label(h, "Hosts", ids::HOSTS_HEADING, bold);
    app.ui.hosts_edit = crate::pages::button(h, "编辑", ids::HOSTS_EDIT, ui);
    app.ui.hosts_reset = crate::pages::button(h, "重置", ids::HOSTS_RESET, ui);
    app.ui.hosts_open = crate::pages::button(h, "打开", ids::HOSTS_OPEN, ui);
    app.ui.open_log_dir = crate::pages::button(h, "打开日志目录", ids::OPEN_LOG_DIR, ui);

    app.ui.acc_tabs = controls::make_tabs(h, ids::ACC_TABS, Rect::default(), ui);
    controls::tabs_add(
        app.ui.acc_tabs,
        &["平台加速", "服务", "加速脚本", "代理日志", "流量统计", "网络检测"],
    );
    controls::tabs_set_sel(app.ui.acc_tabs, 0);

    app.ui.platform_tree = controls::make_tree(h, ids::PLATFORM_TREE, Rect::default(), ui, false);
    app.ui.services_tree = controls::make_tree(h, ids::SERVICES_TREE, Rect::default(), ui, true);

    app.ui.script_enable = crate::pages::checkbox(h, "启用加速脚本", ids::SCRIPT_ENABLE, ui);
    win32::set_check(app.ui.script_enable, app.settings.proxy.is_enable_script);
    app.ui.script_desc = crate::pages::wrap_label(
        h,
        "加速脚本用于自定义域名匹配与转发规则。当前版本提供基础开关。",
        ids::SCRIPT_DESC,
        ui,
    );

    app.ui.logs_clear = crate::pages::button(h, "清空", ids::LOGS_CLEAR, ui);
    app.ui.logs_label = crate::pages::left_label(h, "代理日志（最新 1000 条）", ids::LOGS_LABEL, ui);
    app.ui.logs_edit = win32::create_control(
        h,
        windows_sys::Win32::UI::Controls::WC_EDITW,
        "",
        wm::ES_MULTILINE as u32
            | wm::ES_READONLY as u32
            | wm::ES_AUTOVSCROLL as u32
            | wm::WS_VSCROLL
            | wm::WS_TABSTOP,
        0,
        ids::LOGS_EDIT,
        Rect::default(),
        app.fonts.log,
    );
    windows_sys::Win32::UI::Controls::SetWindowTheme(
        app.ui.logs_edit,
        windows_sys::core::w!("DarkMode_Explorer"),
        std::ptr::null(),
    );

    app.ui.traffic_total = crate::pages::left_label(h, "总流量: 0 字节", ids::TRAFFIC_TOTAL, ui);
    app.ui.traffic_list = controls::make_list(h, ids::TRAFFIC_LIST, Rect::default(), ui);
    controls::list_columns(app.ui.traffic_list, &[("域名", 300), ("字节", 100)]);

    app.ui.nettest_start = crate::pages::button(h, "开始检测", ids::NETTEST_START, ui);
    app.ui.nettest_hint = crate::pages::left_label(
        h,
        "点击“开始检测”运行网络诊断。",
        ids::NETTEST_HINT,
        ui,
    );
    app.ui.nettest_list = controls::make_list(h, ids::NETTEST_LIST, Rect::default(), ui);
    controls::list_columns(app.ui.nettest_list, &[("项目", 200), ("结果", 300)]);

    rebuild_platform(app);
    rebuild_services(app);
    sync_checks(app);
    refresh_nettest(app);
}

pub unsafe fn rebuild_platform(app: &mut App) {
    let tree = app.ui.platform_tree;
    if tree.is_null() {
        return;
    }
    controls::tree_clear(tree);
    app.platform_nodes.clear();
    app.platform_groups.clear();
    app.platform_leaves.clear();

    for g in &app.groups {
        let label = format!("{} ({} 项)", g.name, state::count_group_leaves(g));
        let group_item = controls::tree_insert(tree, TVI_ROOT, &label, Some(state::group_enabled(g)), false);
        if group_item == 0 {
            continue;
        }
        app.platform_nodes
            .insert(group_item, NodeRef::Group(g.name.clone()));
        app.platform_groups.insert(g.name.clone(), group_item);
        for p in &g.items {
            insert_project(tree, group_item, p, &mut app.platform_nodes, &mut app.platform_leaves);
        }
    }
}

unsafe fn insert_project(
    tree: HWND,
    parent: HTREEITEM,
    p: &AccelerateProject,
    nodes: &mut HashMap<isize, NodeRef>,
    leaves: &mut HashMap<String, HTREEITEM>,
) {
    if p.items.is_empty() {
        let label = format!("{} ({} 个域名)", p.name, state::count_domains(&p.listen_domain_names));
        let item = controls::tree_insert(
            tree,
            parent,
            &label,
            Some(p.three_state_enable == Some(true)),
            false,
        );
        if item != 0 {
            nodes.insert(item, NodeRef::Leaf(p.id.clone()));
            leaves.insert(p.id.clone(), item);
        }
    } else {
        let label = format!("{} ({} 项)", p.name, state::count_project_leaves(p));
        let item = controls::tree_insert(tree, parent, &label, None, true);
        for c in &p.items {
            insert_project(tree, item, c, nodes, leaves);
        }
    }
}

pub unsafe fn rebuild_services(app: &mut App) {
    let tree = app.ui.services_tree;
    if tree.is_null() {
        return;
    }
    controls::tree_clear(tree);
    app.services_leaves.clear();
    for g in &app.groups {
        let group_item = controls::tree_insert(tree, TVI_ROOT, &g.name, None, true);
        if group_item == 0 {
            continue;
        }
        for p in &g.items {
            insert_service_leaves(tree, group_item, p, &mut app.services_leaves);
        }
    }
}

unsafe fn insert_service_leaves(
    tree: HWND,
    parent: HTREEITEM,
    p: &AccelerateProject,
    leaves: &mut HashMap<String, HTREEITEM>,
) {
    if p.items.is_empty() {
        let item = controls::tree_insert(
            tree,
            parent,
            &p.name,
            Some(p.three_state_enable == Some(true)),
            false,
        );
        if item != 0 {
            leaves.insert(p.id.clone(), item);
        }
    } else {
        for c in &p.items {
            insert_service_leaves(tree, parent, c, leaves);
        }
    }
}

pub unsafe fn sync_checks(app: &mut App) {
    let states = state::leaf_states(&app.groups);
    for (id, item) in &app.platform_leaves {
        if let Some(on) = states.get(id) {
            controls::tree_set_check(app.ui.platform_tree, *item, *on);
        }
    }
    for g in &app.groups {
        if let Some(item) = app.platform_groups.get(&g.name) {
            controls::tree_set_check(app.ui.platform_tree, *item, state::group_enabled(g));
        }
    }
    for (id, item) in &app.services_leaves {
        if let Some(on) = states.get(id) {
            controls::tree_set_check(app.ui.services_tree, *item, *on);
        }
    }
}

pub unsafe fn on_platform_check(app: &mut App, item: HTREEITEM) {
    // Consume the click on the first notification for this tree (selection,
    // expansion or check) so a later programmatic notification cannot claim it.
    let clicked = crate::take_tree_click(app.ui.platform_tree);
    let Some(node) = app.platform_nodes.get(&item).cloned() else {
        return;
    };
    let Some(ctrl) = controls::tree_check(app.ui.platform_tree, item) else {
        return;
    };
    // Programmatic TVM_SETITEM notifications can arrive after the suppression
    // guard has been dropped. If the control already agrees with the model this
    // is not a user action, so it must not be applied again.
    match node {
        NodeRef::Group(name) => {
            let model = app
                .groups
                .iter()
                .find(|g| g.name == name)
                .map(state::group_enabled);
            if model == Some(ctrl) || !clicked {
                return;
            }
            if state::set_group(&mut app.groups, &name, ctrl) {
                commit(app);
            }
        }
        NodeRef::Leaf(id) => {
            let model = state::leaf_states(&app.groups).get(&id).copied();
            if model == Some(ctrl) || !clicked {
                return;
            }
            if state::set_leaf(&mut app.groups, &id, ctrl) {
                commit(app);
            }
        }
    }
}

pub unsafe fn on_service_check(app: &mut App, item: HTREEITEM) {
    let clicked = crate::take_tree_click(app.ui.services_tree);
    let Some(id) = app
        .services_leaves
        .iter()
        .find_map(|(id, h)| (*h == item).then(|| id.clone()))
    else {
        return;
    };
    let Some(ctrl) = controls::tree_check(app.ui.services_tree, item) else {
        return;
    };
    let model = state::leaf_states(&app.groups).get(&id).copied();
    if model == Some(ctrl) || !clicked {
        return;
    }
    if state::set_leaf(&mut app.groups, &id, ctrl) {
        commit(app);
    }
}

fn commit(app: &mut App) {
    let ids = state::enabled_ids(&app.groups);
    app.accel.apply_enabled(&ids);
    unsafe { sync_checks(app) };
}

pub unsafe fn refresh_logs(app: &mut App) {
    let text = state::logs_text(&app.logs);
    win32::set_text(app.ui.logs_edit, &text);
    app.logs_dirty = false;
}

pub unsafe fn refresh_traffic(app: &mut App) {
    let stats = app.proxy.stats();
    let (total, rows) = {
        let s = stats.lock().unwrap();
        state::traffic_snapshot(s.total_bytes, &s.by_domain)
    };
    if total == app.traffic_total && rows == app.traffic_rows {
        return;
    }
    app.traffic_total = total;
    app.traffic_rows = rows.clone();
    win32::set_text(app.ui.traffic_total, &format!("总流量: {total} 字节"));
    controls::list_clear(app.ui.traffic_list);
    for (domain, bytes) in rows {
        controls::list_add(app.ui.traffic_list, &[domain, bytes.to_string()], 0);
    }
}

pub unsafe fn refresh_nettest(app: &mut App) {
    controls::list_clear(app.ui.nettest_list);
    for r in &app.net_results {
        let color = match r.color {
            wtlite_core::nettest::TestColor::Green => 0,
            wtlite_core::nettest::TestColor::Orange => 1,
            wtlite_core::nettest::TestColor::Red => 2,
        };
        controls::list_add(
            app.ui.nettest_list,
            &[r.name.clone(), r.detail.clone()],
            color,
        );
    }
    let active = app.main_tab == crate::types::MainTab::Accelerator
        && app.acc_tab == crate::types::AccTab::NetTest;
    win32::set_visible(app.ui.nettest_hint, active && app.net_results.is_empty());
    refresh_nettest_button(app);
}

pub unsafe fn refresh_nettest_button(app: &mut App) {
    win32::set_text(
        app.ui.nettest_start,
        if app.testing { "检测中…" } else { "开始检测" },
    );
    win32::set_enabled(app.ui.nettest_start, !app.testing);
}

pub fn start_nettest(app: &mut App) {
    if app.testing {
        return;
    }
    app.testing = true;
    unsafe { refresh_nettest_button(app) };

    let (tx, rx) = std::sync::mpsc::channel();
    app.test_rx = Some(rx);
    std::thread::spawn(move || {
        use wtlite_core::nettest;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        let results = match rt {
            Ok(rt) => rt.block_on(async move {
                let mut results = Vec::new();
                results.push(nettest::check_nat().await);
                results.push(nettest::check_doh("Tencent DoH", wtlite_core::dns::dns_const::DNS_ALI_DOH).await);
                results.push(nettest::check_doh("DNSPod DoH", wtlite_core::dns::dns_const::DNSPOD_DOH).await);
                results.push(nettest::check_doh("Google DoH", wtlite_core::dns::dns_const::GOOGLE_DOH).await);
                results.push(nettest::check_ipv6().await);
                results.push(nettest::check_domain("域名连接", nettest::default_test_domain()).await);
                results
            }),
            Err(e) => vec![nettest::TestResult {
                name: "网络检测".to_string(),
                detail: format!("初始化失败: {e}"),
                color: nettest::TestColor::Red,
                latency_ms: None,
            }],
        };
        let _ = tx.send(results);
    });
}

pub unsafe fn update_mode_combo(app: &mut App) {
    let idx = state::mode_index(app.settings.proxy.proxy_mode);
    win32::set_combo_sel(app.ui.mode_combo, idx);
}

pub fn test_result_color(lparam: isize) -> u32 {
    match lparam {
        0 => win32::rgb(0, 140, 0),
        1 => win32::rgb(190, 110, 0),
        _ => win32::rgb(200, 50, 50),
    }
}
