//! Dialogs (mirrors ProxySettingsWindow and certificate info dialog).

use crate::App;
use eframe::egui;
use wtlite_core::dns;
use wtlite_core::model::ExternalProxyType;

/// Show the proxy settings dialog. The open flag is cleared when the user closes it.
pub fn show_proxy_settings(app: &mut App, ctx: &egui::Context, open: &mut bool) {
    if app.proxy_dialog.is_none() {
        *open = false;
        return;
    }
    let mut close_after = false;
    egui::Window::new("代理设置")
        .open(open)
        .resizable(false)
        .default_size([520.0, 480.0])
        .show(ctx, |ui| {
            let Some(dialog) = app.proxy_dialog.as_mut() else {
                return;
            };
            ui.heading("代理设置");
            ui.add_space(4.0);

            crate::pages::hrow(ui, |ui| {
                ui.label("加速模式:");
                let mode_label = dialog.mode.display_name().to_string();
                if ui.selectable_label(false, mode_label).clicked() {
                    let avail = wtlite_core::model::ProxyMode::available();
                    let idx = avail.iter().position(|m| *m == dialog.mode).unwrap_or(0);
                    dialog.mode = avail[(idx + 1) % avail.len()];
                }
                ui.label(format!("({})", dialog.mode.as_str()));
            });
            ui.label("提示: DNS 拦截模式需要 WinDivert 驱动，若驱动缺失将提示不可用。");

            ui.separator();
            crate::pages::hrow(ui, |ui| {
                ui.label("代理端口:");
                let mut port_s = dialog.port.to_string();
                if ui.add(egui::TextEdit::singleline(&mut port_s)).changed() {
                    if let Ok(p) = port_s.parse::<u16>() {
                        dialog.port = p;
                    }
                }
            });

            ui.separator();
            ui.heading("DNS");
            crate::pages::hrow(ui, |ui| {
                ui.label("DNS 服务器:");
                egui::ComboBox::from_label("选择 DNS")
                    .selected_text(&dialog.dns)
                    .show_ui(ui, |ui| {
                        for d in dns::dns_servers() {
                            if ui.selectable_label(dialog.dns == *d, d).clicked() {
                                dialog.dns = d.to_string();
                            }
                        }
                    });
            });
            crate::pages::hrow(ui, |ui| {
                ui.label("自定义 DNS:");
                let mut custom_dns = dialog.dns.clone();
                if ui.add(egui::TextEdit::singleline(&mut custom_dns)).changed() {
                    dialog.dns = custom_dns;
                }
            });
            ui.checkbox(&mut dialog.use_doh, "使用 DNS-over-HTTPS (DoH)");
            crate::pages::hrow(ui, |ui| {
                ui.label("DoH 地址:");
                egui::ComboBox::from_label("选择 DoH")
                    .selected_text(&dialog.doh_address)
                    .show_ui(ui, |ui| {
                        for d in dns::doh_addresses() {
                            if ui.selectable_label(dialog.doh_address == *d, d).clicked() {
                                dialog.doh_address = d.to_string();
                            }
                        }
                    });
            });

            ui.separator();
            ui.heading("转发");
            ui.checkbox(
                &mut dialog.enable_http_to_https,
                "允许 HTTP 请求转发为 HTTPS",
            );

            ui.separator();
            ui.heading("二级代理（外部代理）");
            ui.checkbox(&mut dialog.two_level_enable, "启用二级代理");
            if dialog.two_level_enable {
                let type_label = match dialog.two_level_type {
                    ExternalProxyType::Http => "HTTP",
                    ExternalProxyType::Socks4 => "SOCKS4",
                    ExternalProxyType::Socks5 => "SOCKS5",
                }
                .to_string();
                crate::pages::hrow(ui, |ui| {
                    ui.label("类型:");
                    if ui.selectable_label(false, type_label).clicked() {
                        dialog.two_level_type = match dialog.two_level_type {
                            ExternalProxyType::Http => ExternalProxyType::Socks4,
                            ExternalProxyType::Socks4 => ExternalProxyType::Socks5,
                            ExternalProxyType::Socks5 => ExternalProxyType::Http,
                        };
                    }
                });
                crate::pages::hrow(ui, |ui| {
                    ui.label("地址:");
                    ui.add(egui::TextEdit::singleline(&mut dialog.two_level_ip));
                    let mut port_s = dialog.two_level_port.to_string();
                    ui.add(egui::TextEdit::singleline(&mut port_s));
                    if let Ok(p) = port_s.parse::<u16>() {
                        dialog.two_level_port = p;
                    }
                });
                crate::pages::hrow(ui, |ui| {
                    ui.label("用户名:");
                    ui.add(egui::TextEdit::singleline(&mut dialog.two_level_user));
                    ui.label("密码:");
                    ui.add(egui::TextEdit::singleline(&mut dialog.two_level_password));
                });
            }

            ui.separator();
            crate::pages::hrow(ui, |ui| {
                if ui.button("取消").clicked() {
                    close_after = true;
                }
                if ui.button("确定").clicked() {
                    let d = app.proxy_dialog.take().unwrap();
                    app.settings.proxy.proxy_mode = d.mode;
                    app.settings.proxy.system_proxy_port = d.port;
                    app.settings.proxy.proxy_master_dns = d.dns;
                    app.settings.proxy.use_doh = d.use_doh;
                    app.settings.proxy.custom_doh_address = d.doh_address;
                    app.settings.proxy.enable_http_proxy_to_https = d.enable_http_to_https;
                    app.settings.proxy.two_level_agent_enable = d.two_level_enable;
                    app.settings.proxy.two_level_agent_type = d.two_level_type;
                    app.settings.proxy.two_level_agent_ip = d.two_level_ip;
                    app.settings.proxy.two_level_agent_port = d.two_level_port;
                    app.settings.proxy.two_level_agent_user = d.two_level_user;
                    app.settings.proxy.two_level_agent_password = d.two_level_password;
                    let _ = app.settings.save();
                    app.set_toast("代理设置已保存");
                    close_after = true;
                }
            });
        });
    if close_after {
        *open = false;
    }
}
