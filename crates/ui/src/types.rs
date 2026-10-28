//! Page enums shared by the UI layers.

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MainTab {
    Accelerator,
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AccTab {
    Platform,
    Services,
    Scripts,
    Logs,
    Traffic,
    NetTest,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SettingsTab {
    General,
    Accelerate,
    About,
}

impl AccTab {
    pub fn from_index(i: i32) -> Self {
        match i {
            1 => AccTab::Services,
            2 => AccTab::Scripts,
            3 => AccTab::Logs,
            4 => AccTab::Traffic,
            5 => AccTab::NetTest,
            _ => AccTab::Platform,
        }
    }
}

impl SettingsTab {
    pub fn index(self) -> usize {
        match self {
            SettingsTab::General => 0,
            SettingsTab::Accelerate => 1,
            SettingsTab::About => 2,
        }
    }

    pub fn from_index(i: i32) -> Self {
        match i {
            1 => SettingsTab::Accelerate,
            2 => SettingsTab::About,
            _ => SettingsTab::General,
        }
    }
}
