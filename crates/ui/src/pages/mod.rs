//! UI pages.

pub mod accelerator;
pub mod dialogs;
pub mod settings_page;

/// Global accelerator-page sub-tab state.
pub static GLOBAL_ACC: std::sync::LazyLock<std::sync::Mutex<accelerator::AccState>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(accelerator::AccState::default()));

/// Horizontal row of widgets (egui 0.29.x has no Ui::horizontal).
pub fn hrow(ui: &mut eframe::egui::Ui, add: impl FnOnce(&mut eframe::egui::Ui)) {
    ui.scope_builder(
        eframe::egui::UiBuilder::new().layout(eframe::egui::Layout::left_to_right(eframe::egui::Align::Center)),
        add,
    );
}

/// Right-aligned horizontal row.
pub fn hrow_right(ui: &mut eframe::egui::Ui, add: impl FnOnce(&mut eframe::egui::Ui)) {
    ui.scope_builder(
        eframe::egui::UiBuilder::new().layout(eframe::egui::Layout::right_to_left(eframe::egui::Align::Center)),
        add,
    );
}

/// Vertically centered block.
pub fn vcenter(ui: &mut eframe::egui::Ui, add: impl FnOnce(&mut eframe::egui::Ui)) {
    ui.scope_builder(
        eframe::egui::UiBuilder::new().layout(eframe::egui::Layout::top_down(eframe::egui::Align::Center)),
        add,
    );
}

/// Indented sub-block.
pub fn indent(ui: &mut eframe::egui::Ui, salt: impl std::hash::Hash, add: impl FnOnce(&mut eframe::egui::Ui)) {
    ui.scope_builder(eframe::egui::UiBuilder::new().id_salt(salt), |ui| {
        ui.add_space(18.0);
        add(ui);
    });
}

/// Tab-style selectable button; returns true when clicked.
pub fn tab_btn(ui: &mut eframe::egui::Ui, active: bool, label: &str) -> bool {
    ui.selectable_label(active, label).clicked()
}
