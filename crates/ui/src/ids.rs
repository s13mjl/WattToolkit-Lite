//! Child-control IDs for the main window and dialogs.

// Header
pub const TITLE: i32 = 100;
pub const STATUS: i32 = 101;
pub const MAIN_TABS: i32 = 110;

// Accelerator right panel
pub const START: i32 = 120;
pub const MODE_LABEL: i32 = 121;
pub const MODE_COMBO: i32 = 122;
pub const PROXY_SETTINGS: i32 = 123;
pub const CERT_HEADING: i32 = 130;
pub const CERT_INSTALL: i32 = 131;
pub const CERT_REMOVE: i32 = 132;
pub const CERT_VIEW: i32 = 133;
pub const CERT_OPEN_DIR: i32 = 134;
pub const HOSTS_HEADING: i32 = 140;
pub const HOSTS_EDIT: i32 = 141;
pub const HOSTS_RESET: i32 = 142;
pub const HOSTS_OPEN: i32 = 143;
pub const OPEN_LOG_DIR: i32 = 150;
pub const ACCEL_HEADING: i32 = 151;

// Accelerator sub-tabs / pages
pub const ACC_TABS: i32 = 160;
pub const PLATFORM_TREE: i32 = 170;
pub const SERVICES_TREE: i32 = 180;
pub const SCRIPT_ENABLE: i32 = 190;
pub const SCRIPT_DESC: i32 = 191;
pub const LOGS_CLEAR: i32 = 200;
pub const LOGS_LABEL: i32 = 201;
pub const LOGS_EDIT: i32 = 202;
pub const TRAFFIC_TOTAL: i32 = 210;
pub const TRAFFIC_LIST: i32 = 211;
pub const NETTEST_START: i32 = 220;
pub const NETTEST_HINT: i32 = 221;
pub const NETTEST_LIST: i32 = 222;

// Settings
pub const SETTINGS_TABS: i32 = 230;
pub const GEN_AUTORUN: i32 = 240;
pub const GEN_MINIMIZE: i32 = 241;
pub const GEN_TRAY: i32 = 242;
pub const GEN_GPU: i32 = 243;
pub const GEN_SAVE: i32 = 244;
pub const ACCEL_MODE_LABEL: i32 = 250;
pub const ACCEL_MODE_COMBO: i32 = 251;
pub const ACCEL_STARTUP_RUN: i32 = 252;
pub const ACCEL_HTTP_HTTPS: i32 = 253;
pub const ACCEL_SCRIPT: i32 = 254;
pub const ACCEL_SAVE: i32 = 255;
pub const ABOUT_ICON: i32 = 260;
pub const ABOUT_NAME: i32 = 261;
pub const ABOUT_VERSION: i32 = 262;
pub const ABOUT_LICENSE_LABEL: i32 = 263;
pub const ABOUT_LICENSE: i32 = 264;
pub const ABOUT_UPSTREAM_LABEL: i32 = 265;
pub const ABOUT_UPSTREAM: i32 = 266;
pub const ABOUT_SECONDARY_LABEL: i32 = 267;
pub const ABOUT_SECONDARY: i32 = 268;
pub const ABOUT_DESC: i32 = 269;

// Tray menu
pub const TRAY_SHOW: usize = 9001;
pub const TRAY_EXIT: usize = 9002;

// Proxy settings dialog
pub mod proxy {
    pub const MODE_LABEL: i32 = 1000;
    pub const MODE: i32 = 1001;
    pub const HINT: i32 = 1002;
    pub const PORT_LABEL: i32 = 1003;
    pub const PORT: i32 = 1004;
    pub const DNS_LABEL: i32 = 1005;
    pub const DNS: i32 = 1006;
    pub const USE_DOH: i32 = 1007;
    pub const DOH_LABEL: i32 = 1008;
    pub const DOH: i32 = 1009;
    pub const HTTP_HTTPS: i32 = 1010;
    pub const TLS_DECRYPT: i32 = 1011;
    pub const TLS_HINT: i32 = 1012;
    pub const TWO_LEVEL: i32 = 1013;
    pub const TWO_TYPE_LABEL: i32 = 1014;
    pub const TWO_TYPE: i32 = 1015;
    pub const TWO_IP_LABEL: i32 = 1016;
    pub const TWO_IP: i32 = 1017;
    pub const TWO_PORT_LABEL: i32 = 1018;
    pub const TWO_PORT: i32 = 1019;
    pub const TWO_USER_LABEL: i32 = 1020;
    pub const TWO_USER: i32 = 1021;
    pub const TWO_PASS_LABEL: i32 = 1022;
    pub const TWO_PASS: i32 = 1023;
}

// Certificate info dialog
pub mod cert {
    pub const INFO: i32 = 1100;
}
