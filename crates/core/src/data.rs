//! Built-in acceleration project data.
//!
//! The original project loads acceleration projects from the official
//! microservice API. Since this secondary development removes login and the
//! API contract is not publicly available, a built-in fallback list covering
//! common Steam domains is provided. When a local cache (LOCAL_ACCELERATE)
//! or a reachable API is available, it takes precedence.

use crate::model::{AccelerateProject, AccelerateProjectGroup, ProxyType};

fn p(id: &str, name: &str, order: i32, domains: &str) -> AccelerateProject {
    AccelerateProject {
        id: id.to_string(),
        name: name.to_string(),
        order,
        proxy_type: ProxyType::Normal,
        match_domain_names: domains.to_string(),
        forward_domain_names: None,
        ignore_ssl_cert_verification: false,
        fake_server_name: None,
        listen_domain_names: domains.to_string(),
        checked: false,
        three_state_enable: Some(true),
        items: Vec::new(),
    }
}

/// Built-in acceleration groups (offline fallback).
pub fn built_in_groups() -> Vec<AccelerateProjectGroup> {
    vec![
        AccelerateProjectGroup {
            name: "Steam 商店".to_string(),
            icon_url: None,
            order: 1,
            three_state_enable: Some(true),
            items: vec![
                p("steam-store", "商店页面", 1, "store.steampowered.com;www.steampowered.com"),
                p("steam-api", "Steam API", 2, "api.steampowered.com;api.data.amd.com;steambroadcast.steampowered.com"),
                p("steam-cdn", "Steam CDN", 3, "cdn.cloudflare.steamstatic.com;steamcdn-a.akamaihd.net;steamstore-a.akamaihd.net;steamcontent-a.akamaihd.net"),
            ],
        },
        AccelerateProjectGroup {
            name: "Steam 社区".to_string(),
            icon_url: None,
            order: 2,
            three_state_enable: Some(true),
            items: vec![
                p("steam-community", "社区主页", 1, "steamcommunity.com;www.steamcommunity.com"),
                p("steam-chat", "聊天/好友", 2, "community.steamapi.com;steammessages-a.akamaihd.net;steammessageslist-a.akamaihd.net"),
                p("steam-market", "市场", 3, "steamcommunity.com/market;steamhosting-a.akamaihd.net"),
            ],
        },
        AccelerateProjectGroup {
            name: "Steam 客户端".to_string(),
            icon_url: None,
            order: 3,
            three_state_enable: Some(true),
            items: vec![
                p("steam-client", "客户端连接", 1, "client.steamserver.net;cm.steampowered.com;relay.steampowered.com"),
                p("steam-dlc", "DLC/下载", 2, "steampipe.steamcontent.net;steambroadcast.steampowered.com"),
                p("steam-web", "内置浏览器", 3, "www.steamgames.com;help.steampowered.com;partner.steamgames.com"),
            ],
        },
        AccelerateProjectGroup {
            name: "Steam 创意工坊".to_string(),
            icon_url: None,
            order: 4,
            three_state_enable: Some(true),
            items: vec![
                p("steam-workshop", "创意工坊", 1, "steamcommunity.com/workshop;workshop.steamusercontent.com"),
            ],
        },
    ]
}
