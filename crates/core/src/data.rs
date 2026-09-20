//! Built-in acceleration project data.
//!
//! The original project loads acceleration projects from the official
//! microservice API and caches them in LOCAL_ACCELERATE.json. This secondary
//! development removes login and cannot rely on the live API, so a built-in
//! fallback list is provided here. The domain content below is copied from the
//! official client's acceleration list (Steam 服务 + Github). When a local cache
//! is present it takes precedence over this list (see AccelerateService::load).

use crate::model::{AccelerateProject, AccelerateProjectGroup, ProxyType};

/// Leaf project (no children).
fn leaf(id: &str, name: &str, order: i32, domains: &str) -> AccelerateProject {
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

/// Leaf project whose upstream is dialled through a substitute hostname.
///
/// Mirrors the original `ForwardDestination` + `TlsSni` data: when a domain is
/// blocked at the IP layer (steamcommunity.com resolves to a poisoned address
/// here), its CDN alias still resolves to a reachable edge. The request keeps
/// its original Host header; only the TCP/TLS target changes.
fn leaf_fwd(id: &str, name: &str, order: i32, domains: &str, forward: &str) -> AccelerateProject {
    let mut p = leaf(id, name, order, domains);
    p.forward_domain_names = Some(forward.to_string());
    p
}

/// Project with children.
fn p(id: &str, name: &str, order: i32, children: Vec<AccelerateProject>) -> AccelerateProject {
    AccelerateProject {
        id: id.to_string(),
        name: name.to_string(),
        order,
        proxy_type: ProxyType::Normal,
        match_domain_names: String::new(),
        forward_domain_names: None,
        ignore_ssl_cert_verification: false,
        fake_server_name: None,
        listen_domain_names: String::new(),
        checked: false,
        three_state_enable: Some(true),
        items: children,
    }
}

fn grp(name: &str, order: i32, items: Vec<AccelerateProject>) -> AccelerateProjectGroup {
    AccelerateProjectGroup {
        name: name.to_string(),
        icon_url: None,
        order,
        three_state_enable: Some(true),
        items,
    }
}

/// Built-in acceleration groups (offline fallback), copied from the official
/// client's default list: Steam 服务 and Github.
pub fn built_in_groups() -> Vec<AccelerateProjectGroup> {
    vec![
        grp(
            "Steam 服务",
            1,
            vec![
                // steamcommunity.com is DNS-poisoned here, so it is dialled
                // through its reachable CDN alias (Host header unchanged).
                leaf_fwd(
                    "steam-community",
                    "Steam 社区",
                    4,
                    "steamcommunity.com",
                    "steamcommunity-a.akamaihd.net",
                ),
                leaf("steam-image", "Steam 图片", 1, "steamcdn-a.akamaihd.net"),
                leaf("steam-static", "Steam 静态资源", 2, "community.steamstatic.com"),
                leaf("steam-update", "Steam 更新", 3, "media.steampowered.com"),
                leaf("steam-store", "Steam 商店", 5, "store.steampowered.com"),
                leaf(
                    "steam-community-video",
                    "Steam 社区视频封面加载 Beta",
                    6,
                    "img.youtube.com",
                ),
                leaf(
                    "steam-baiyun-cdn",
                    "Steam 白山云CDN 修复",
                    7,
                    "*.st.dl.eccdnx.com",
                ),
                // 官方该项不含域名（需配合下面的 IPv4 项使用），这里同样留空。
                leaf("steam-discussion", "Steam 讨论/留言 修复项 Beta", 8, ""),
                leaf(
                    "steam-discussion-ipv4",
                    "Steam 讨论/留言 (IPv4)",
                    9,
                    "*.steamcommunity.com",
                ),
            ],
        ),
        grp(
            "Github",
            2,
            vec![
                leaf("gh-huggingface", "huggingface.co Beta", 1, "huggingface.co"),
                leaf("gh-dev", "Github Dev", 2, "github.dev"),
                leaf("gh-api", "Github Api", 3, "api.github.com"),
                leaf("gh-assets", "Github Assets", 4, "github.githubassets.com"),
                leaf("gh-education", "Github Education", 5, "education.github.com"),
                leaf("gh-resources", "Github Resources", 6, "resources.github.com"),
                leaf("gh-uploads", "Github Uploads", 7, "uploads.github.com"),
                leaf(
                    "gh-archiveprogram",
                    "Github Archiveprogram",
                    8,
                    "archiveprogram.github.com",
                ),
                leaf("gh-usercontent", "Github UserContent", 9, "githubusercontent.com"),
                leaf("gh-website", "Github 网站 (Git Push)", 10, "github.com"),
                leaf("gh-app", "Github App", 11, "githubapp.com"),
                leaf("gh-docker", "Docker Hub", 12, "hub.docker.com"),
                leaf("gh-greasyfork", "greasyfork Beta", 13, "greasyfork.org"),
                leaf("gh-io", "Github.io", 14, "github.io"),
            ],
        ),
    ]
}
