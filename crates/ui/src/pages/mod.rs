//! UI pages.

pub mod accelerator;
pub mod dialogs;
pub mod settings_page;

/// Global accelerator-page sub-tab state.
pub static GLOBAL_ACC: std::sync::LazyLock<std::sync::Mutex<accelerator::AccState>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(accelerator::AccState::default()));

/// Horizontal row of widgets.
pub fn hrow(ui: &mut eframe::egui::Ui, add: impl FnOnce(&mut eframe::egui::Ui)) {
    ui.horizontal(add);
}

/// Right-aligned horizontal row.
pub fn hrow_right(ui: &mut eframe::egui::Ui, add: impl FnOnce(&mut eframe::egui::Ui)) {
    ui.horizontal(|ui| {
        ui.with_layout(
            eframe::egui::Layout::right_to_left(eframe::egui::Align::Center),
            add,
        );
    });
}

/// Vertically centered block.
pub fn vcenter(ui: &mut eframe::egui::Ui, add: impl FnOnce(&mut eframe::egui::Ui)) {
    ui.vertical_centered(add);
}

/// Tab-style selectable button; returns true when clicked.
pub fn tab_btn(ui: &mut eframe::egui::Ui, active: bool, label: &str) -> bool {
    ui.selectable_label(active, label).clicked()
}
