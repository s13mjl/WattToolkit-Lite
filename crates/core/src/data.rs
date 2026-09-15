//! Built-in acceleration project data.
//!
//! The original project loads acceleration projects from the official
//! microservice API and caches them in LOCAL_ACCELERATE.json. This secondary
//! development removes login and cannot rely on the live API, so a built-in
//! fallback list is provided here. The platform/domain content mirrors the
//! data observed in the original WattToolkit local cache (LOCAL_ACCELERATE)
//! and well-known official service domains. When a local cache is present it
//! takes precedence over this list (see AccelerateService::load).

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
/// blocked at the IP layer, its CDN alias still resolves to a reachable edge.
/// The request keeps its original Host header; only the TCP/TLS target changes.
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

/// Built-in acceleration groups (offline fallback), mirroring the platform
/// set of the original WattToolkit local cache.
pub fn built_in_groups() -> Vec<AccelerateProjectGroup> {
    vec![
        grp(
            "Steam 服务",
            1,
            vec![
                leaf("steam-store", "商店", 1, "store.steampowered.com;www.steampowered.com;store.steamstatic.com"),
                // Verified: the bare domain is IP-blocked here, while its CDN
                // alias resolves to a reachable Akamai edge (Host header stays
                // steamcommunity.com).
                leaf_fwd(
                    "steam-community",
                    "社区",
                    2,
                    "steamcommunity.com;www.steamcommunity.com",
                    "steamcommunity-a.akamaihd.net",
                ),
                leaf("steam-community-cdn", "社区 CDN", 21, "community.steamstatic.com;shared.steamstatic.com"),
                leaf("steam-client", "客户端", 3, "client.steamserver.net;cm.steampowered.com;relay.steampowered.com;api.steampowered.com"),
                leaf("steam-download", "下载/CDN", 4, "cdn.cloudflare.steamstatic.com;steamcdn-a.akamaihd.net;steamstore-a.akamaihd.net;steamcontent-a.akamaihd.net;steampipe.steamcontent.net;steamusercontent-a.akamaihd.net"),
                leaf("steam-workshop", "创意工坊", 5, "steamcommunity.com/workshop;workshop.steamusercontent.com;steamcommunity-a.akamaihd.net"),
                leaf("steam-chat", "聊天/好友", 6, "steammessages-a.akamaihd.net;steammessageslist-a.akamaihd.net;community.steamapi.com"),
                leaf("steam-media", "图片/头像/视频", 7, "avatars.steamstatic.com;cdn.akamai.steamstatic.com;img.youtube.com;steamuserimages-a.akamaihd.net;avatars.cloudflare.steamstatic.com"),
                leaf("steam-api", "Steam API", 8, "api.steampowered.com;api.data.amd.com;help.steampowered.com;partner.steamgames.com;www.steamgames.com"),
                leaf("steam-unlock", "解锁访问限制", 9, "login.live.com;login.microsoftonline.com;www.microsoft.com;office.com;edge.microsoft.com;*.edgesuite.net"),
                leaf("steam-browser", "内置浏览器/商店修复", 10, "store.steampowered.com;checkout.steampowered.com;login.steampowered.com;g.app/*;www.google.com/generate_204"),
            ],
        ),
        grp(
            "Steam 头像 修复项",
            2,
            vec![
                leaf("steam-avatar-cdn", "头像 CDN", 1, "avatars.st.dl.eccdnx.com;akamai.steamstatic.com;steamavatars.akamaized.net;avatars.akamai.steamstatic.com"),
                leaf("steam-avatar-media", "头像媒体", 2, "media.steamstatic.com;cdn.queniuqe.com;steamcommunity-a.akamaihd.net"),
            ],
        ),
        grp(
            "Twitch 直播",
            3,
            vec![
                p("twitch-web", "网页加载", 1, vec![
                    leaf("twitch-web-main", "主站", 1, "twitch.tv;www.twitch.tv;app.twitch.tv;m.twitch.tv"),
                    leaf("twitch-web-static", "静态资源", 2, "static.twitchcdn.net;assets.twitchcdn.net;static-cdn.jtvnw.net;extension-files.twitch.tv"),
                    leaf("twitch-web-badges", "徽章/表情", 3, "badges.twitch.tv;log.tv;inspector.twitch.tv;storyboard.ingest.twitch.tv"),
                ]),
                p("twitch-chat", "聊天/直播", 2, vec![
                    leaf("twitch-chat-irc", "聊天 (IRC)", 1, "irc-ws.chat.twitch.tv;irc.chat.twitch.tv;chat.twitch.tv"),
                    leaf("twitch-chat-pubsub", "事件 (PubSub)", 2, "pubsub-edge.twitch.tv;pubsub.twitch.tv"),
                ]),
                leaf("twitch-live", "直播 CDN", 3, "*.pdx01.abs.hls.ttvnw.net;*.abs.hls.ttvnw.net;*.hls.ttvnw.net;video-edge-*.abs.hls.ttvnw.net;video-weaver.ice01.hls.ttvnw.net"),
                leaf("twitch-drops", "掉宝", 4, "gds-vhs-drops-campaign-*.abs.hls.ttvnw.net;science-edge-external-prod-73889260.us-west-2.elb.amazonaws.com"),
                leaf("twitch-clips", "剪片", 5, "clips-media-assets2.twitchcdn.net;d2xmjdvx03ij56.cloudfront.net;clips.twitch.tv"),
                leaf("twitch-api", "API", 6, "gql.twitch.tv;api.twitch.tv;passport.twitch.tv;auth.twitch.tv"),
            ],
        ),
        grp(
            "GitHub",
            4,
            vec![
                leaf("gh-main", "主站", 1, "github.com;www.github.com;gist.github.com"),
                leaf("gh-api", "API", 2, "api.github.com;github.githubassets.com"),
                leaf("gh-raw", "Raw/静态资源", 3, "raw.githubusercontent.com;githubusercontent.com;avatars.githubusercontent.com;avatars0.githubusercontent.com;avatars1.githubusercontent.com;avatars2.githubusercontent.com;avatars3.githubusercontent.com"),
                leaf("gh-download", "下载/发布", 4, "codeload.github.com;objects.githubusercontent.com;release-assets.githubusercontent.com;github-cloud.s3.amazonaws.com;github-com.s3.amazonaws.com;github-production-release-asset-2e65be.s3.amazonaws.com"),
            ],
        ),
        grp(
            "Discord",
            5,
            vec![
                leaf("dc-main", "主站/客户端", 1, "discord.com;www.discord.com;discordapp.com;ptb.discord.com;canary.discord.com;staging.discord.co"),
                leaf("dc-cdn", "媒体/附件 CDN", 2, "cdn.discordapp.com;media.discordapp.net;images-ext-*.discordapp.net;discord-attachments-*.discordapp.net;staticdelivery.net;streamkit.discord.com"),
                leaf("dc-api", "API/网关", 3, "discord.com/api;discordapp.com/api;gateway.discord.gg;status.discord.com"),
            ],
        ),
        grp(
            "Epic",
            6,
            vec![
                leaf("epic-store", "商店", 1, "store.epicgames.com;www.epicgames.com;epicgames.com"),
                leaf("epic-account", "账号/登录", 2, "accounts.epicgames.com;account.epicgames.com;www.epicgames.com/id"),
                leaf("epic-download", "下载/CDN", 3, "download.epicgames.com;launcher-public-service-prod06.ol.epicgames.com;epicgames-download1.akamaized.net;fastly.epicgames.com;cdn1.epicgames.com"),
            ],
        ),
        grp(
            "Ubisoft",
            7,
            vec![
                leaf("ubi-store", "商店/官网", 1, "store.ubisoft.com;www.ubisoft.com;ubisoft.com"),
                leaf("ubi-client", "客户端/API", 2, "uplay.ubi.com;public-ubiservices.ubi.com;connect.ubi.com;ubisoftconnect.com"),
                leaf("ubi-cdn", "CDN", 3, "ubistatic-a.akamaihd.net;ubistatic3-a.akamaihd.net;static-uplay.ubi.com"),
            ],
        ),
        grp(
            "Origin",
            8,
            vec![
                leaf("ea-store", "商店", 1, "origin.com;www.origin.com;store.origin.com;ea.com;www.ea.com"),
                leaf("ea-download", "下载/CDN", 2, "origin-a.akamaihd.net;ul-patch.origin.com;eaassets-a.akamaihd.net;origin-a.akamaihd.net"),
                leaf("ea-api", "API", 3, "api.origin.com;signin.ea.com;accounts.ea.com"),
            ],
        ),
        grp(
            "Spotify",
            9,
            vec![
                leaf("sp-web", "网页/客户端", 1, "open.spotify.com;www.spotify.com;accounts.spotify.com"),
                leaf("sp-api", "API", 2, "api.spotify.com;spclient.wg.spotify.com"),
                leaf("sp-media", "媒体 CDN", 3, "scdn.co;mosaic.scdn.co;i.scdn.co;p.scdn.co"),
            ],
        ),
        grp(
            "Microsoft",
            10,
            vec![
                leaf("ms-login", "登录", 1, "login.live.com;login.microsoftonline.com;account.microsoft.com;login.msa.akadns.net"),
                leaf("ms-office", "Office/办公", 2, "office.com;www.office.com;officecdn.microsoft.com;onedrive.live.com;sharepoint.com"),
                leaf("ms-store", "商店/系统", 3, "www.microsoft.com;store.microsoft.com;displaycatalog.mp.microsoft.com;www.microsoft.com/en-us/software-download"),
            ],
        ),
        grp(
            "Apple",
            11,
            vec![
                leaf("ap-main", "官网", 1, "apple.com;www.apple.com;support.apple.com;developer.apple.com"),
                leaf("ap-update", "更新/CDN", 2, "swcdn.apple.com;swdist.apple.com;swscan.apple.com;mesu.apple.com;gs.apple.com"),
                leaf("ap-icloud", "iCloud", 3, "icloud.com;www.icloud.com;gateway.icloud.com;setup.icloud.com"),
            ],
        ),
        grp(
            "AMD",
            12,
            vec![
                leaf("amd-main", "官网", 1, "amd.com;www.amd.com;community.amd.com"),
                leaf("amd-driver", "驱动/下载", 2, "drivers.amd.com;download.amd.com;drivers.trusted.platforms.amd.com;api.amd.com"),
            ],
        ),
        grp(
            "Riot Games",
            13,
            vec![
                leaf("riot-main", "主站", 1, "riotgames.com;www.riotgames.com;playvalorant.com;leagueoflegends.com"),
                leaf("riot-client", "客户端/认证", 2, "auth.riotgames.com;entitlements.auth.riotgames.com;riotclient.riotgames.com;valorant-api.riotgames.com"),
                leaf("riot-cdn", "CDN/下载", 3, "riotgamespatcher-a.akamaihd.net;lol.secure.dyn.riotcdn.net;valorant.secure.dyn.riotcdn.net;leagueoflegends.com/landing"),
            ],
        ),
        grp(
            "Google",
            14,
            vec![
                leaf("go-lib", "公共库/字体", 1, "fonts.googleapis.com;fonts.gstatic.com;ajax.googleapis.com;themes.googleusercontent.com;gstatic.com;*.gstatic.com"),
                leaf("go-translate", "翻译", 2, "translate.google.com;translate.googleapis.com;clients5.google.com"),
                leaf("go-generate204", "网络连通检测", 3, "www.google.com/generate_204;connectivitycheck.gstatic.com;www.gstatic.com/generate_204"),
            ],
        ),
    ]
}