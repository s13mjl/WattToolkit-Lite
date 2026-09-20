//! WattToolkit-Lite entry point: sets up the egui window, system tray, and
//! runs the app. Windows-only.
//!
//! The binary is built as a GUI application (see `windows_subsystem` below) so
//! launching it never opens a console window. Diagnostics still go to
//! `%LOCALAPPDATA%\WattToolkit-Lite\logs\app.log` via env_logger.

// Hide the console window in release builds; debug builds keep it for output.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use image::{Rgba, RgbaImage};
use std::sync::{Arc, Mutex};
use tray_icon::menu::{Menu, MenuItem};
use tray_icon::{Icon, TrayIconBuilder};
use wtlite_ui::TrayState;

/// Original (blue) icon embedded at compile time (assets/accelerator.ico).
const ICON_SRC: &[u8] = include_bytes!("../../../assets/accelerator.ico");

/// Path of the recolor-generated icon used by window/tray/about
/// (stored in the app data dir, regenerated on first run).
fn icon_png_path() -> std::path::PathBuf {
    wtlite_core::paths::cache_dir().join("icon.png")
}

/// Hue-rotate bluish pixels toward green (mirrors the "更换色调" requirement).
fn recolor(img: &RgbaImage) -> RgbaImage {
    let mut out = RgbaImage::new(img.width(), img.height());
    for (x, y, px) in img.enumerate_pixels() {
        let (r, g, b, a) = (px[0] as f32 / 255.0, px[1] as f32 / 255.0, px[2] as f32 / 255.0, px[3]);
        let (hr, hg, hb) = rgb_to_hsv(r, g, b);
        // If the pixel is bluish (hue 0.5..0.78), rotate toward green (~0.36).
        let nh = if hr >= 0.5 && hr <= 0.78 && hb > 0.15 {
            0.36
        } else {
            hr
        };
        let (nr, ng, nb) = hsv_to_rgb(nh, hg, hb);
        out.put_pixel(x, y, Rgba([(nr * 255.0) as u8, (ng * 255.0) as u8, (nb * 255.0) as u8, a]));
    }
    out
}

fn rgb_to_hsv(r: f32, g: f32, b: f32) -> (f32, f32, f32) {
    let max = r.max(g).max(b);
    let min = r.min(g).min(b);
    let d = max - min;
    let l = (max + min) / 2.0;
    if d == 0.0 {
        return (0.0, 0.0, l);
    }
    let s = if l > 0.5 { d / (2.0 - max - min) } else { d / (max + min) };
    let h = if max == r {
        (((g - b) / d) % 6.0) / 6.0
    } else if max == g {
        ((b - r) / d + 2.0) / 6.0
    } else {
        ((r - g) / d + 4.0) / 6.0
    };
    let h = if h < 0.0 { h + 1.0 } else { h };
    (h, s, l)
}

fn hsv_to_rgb(h: f32, s: f32, l: f32) -> (f32, f32, f32) {
    if s == 0.0 {
        return (l, l, l);
    }
    let q = if l < 0.5 { l * (1.0 + s) } else { l + s - l * s };
    let p = 2.0 * l - q;
    let f = |t: f32| -> f32 {
        let t = if t < 0.0 { t + 1.0 } else if t > 1.0 { t - 1.0 } else { t };
        if t < 1.0 / 6.0 { p + (q - p) * 6.0 * t }
        else if t < 0.5 { q }
        else if t < 2.0 / 3.0 { p + (q - p) * (2.0 / 3.0 - t) * 6.0 }
        else { p }
    };
    (f(h + 1.0 / 3.0), f(h), f(h - 1.0 / 3.0))
}

/// Load (or generate+cache) the recolor icon RGBA.
fn load_icon() -> Option<RgbaImage> {
    let png_path = icon_png_path();
    // Try the generated PNG first.
    if png_path.exists() {
        if let Ok(img) = image::open(&png_path) {
            return Some(img.to_rgba8());
        }
    }
    // Generate from the embedded original ico.
    let img = image::load_from_memory(ICON_SRC).ok()?;
    let rgba = img.to_rgba8();
    let rec = recolor(&rgba);
    // Downscale to 256 for the about page / window icon.
    let rec = image::imageops::resize(&rec, 256, 256, image::imageops::FilterType::Lanczos3);
    let _ = image::DynamicImage::ImageRgba8(rec.clone()).save_with_format(&png_path, image::ImageFormat::Png);
    Some(rec)
}

/// Dispatch any pending Windows messages for the current thread (non-blocking).
#[cfg(windows)]
fn pump_messages() {
    use std::ffi::c_void;
    #[repr(C)]
    struct Msg {
        hwnd: *mut c_void,
        message: u32,
        w_param: usize,
        l_param: isize,
        time: u32,
        pt_x: i32,
        pt_y: i32,
    }
    #[link(name = "user32")]
    extern "system" {
        fn PeekMessageW(
            msg: *mut Msg,
            hwnd: *mut c_void,
            min: u32,
            max: u32,
            remove: u32,
        ) -> i32;
        fn TranslateMessage(msg: *const Msg) -> i32;
        fn DispatchMessageW(msg: *const Msg) -> isize;
    }
    const PM_REMOVE: u32 = 0x0001;
    unsafe {
        let mut msg: Msg = std::mem::zeroed();
        while PeekMessageW(&mut msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

#[cfg(not(windows))]
fn pump_messages() {}

/// Log to `%LOCALAPPDATA%\WattToolkit-Lite\logs\app.log`.
///
/// The app runs without a console (GUI subsystem), so a file is the only place
/// diagnostics can land; `RUST_LOG` still controls the level.
fn init_logging() {
    let dir = wtlite_core::paths::log_dir();
    let _ = std::fs::create_dir_all(&dir);
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("app.log"));
    let mut builder =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    // Keep a timestamp on every line (the default format prints one for the
    // default env filter, but be explicit here).
    builder.format_timestamp_millis();
    if let Ok(f) = file {
        builder.target(env_logger::Target::Pipe(Box::new(f)));
    }
    builder.init();
}

fn main() -> eframe::Result {
    init_logging();

    let icon = load_icon().expect("icon asset missing");
    let (w, h) = (icon.width(), icon.height());

    // Tray icon (events are polled by the UI via tray_icon::TrayIconEvent::receiver()).
    let tray_state: Arc<Mutex<TrayState>> = Arc::new(Mutex::new(TrayState {
        show_window: false,
        exit: false,
    }));
    let tray_icon = Icon::from_rgba(icon.as_raw().to_vec(), w, h).expect("tray icon");
    let show_item = MenuItem::with_id("show", "显示主窗口", true, None);
    let exit_item = MenuItem::with_id("exit", "退出", true, None);
    let menu = Menu::with_items(&[&show_item, &exit_item]).expect("menu");
    let _tray = TrayIconBuilder::new()
        .with_id("wtlite")
        .with_icon(tray_icon)
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_menu_on_right_click(true)
        .with_tooltip("WattToolkit-Lite")
        .build()
        .expect("tray");

    // The UI App must share the same tray state.
    wtlite_ui::set_tray_state(tray_state);

    // Tray events are handled on their own thread: once the window is hidden
    // (SW_HIDE) eframe stops calling App::update, so the UI loop can no longer
    // drain the tray channels - the window would never come back. This thread
    // keeps working while the window is hidden and drives Win32 directly.
    std::thread::spawn(move || {
        use tray_icon::menu::MenuEvent;
        use tray_icon::{MouseButton, TrayIconEvent};
        let mut ticks: u64 = 0;
        loop {
            // Pump the thread's message queue: tray-icon owns a hidden message
            // window on this thread and its callbacks (click / menu) only fire
            // while messages are dispatched. Without this the tray is silent.
            pump_messages();
            // Wait for the HWND to be captured by the first UI frame before we
            // can control the window (events before that are still queued).
            if !wtlite_ui::win32::has_handle() {
                std::thread::sleep(std::time::Duration::from_millis(100));
                // Keep the channels drained so a click made during startup is
                // acted on once the handle exists.
                while TrayIconEvent::receiver().try_recv().is_ok() {}
                while MenuEvent::receiver().try_recv().is_ok() {}
                continue;
            }
            let mut acted = false;
            while let Ok(ev) = TrayIconEvent::receiver().try_recv() {
                if let TrayIconEvent::Click { button, .. } | TrayIconEvent::DoubleClick { button, .. } = ev {
                    if button == MouseButton::Left {
                        let ok = wtlite_ui::win32::show();
                        log::info!("[tray] restore window -> visible={ok}");
                        acted = true;
                    }
                }
            }
            while let Ok(ev) = MenuEvent::receiver().try_recv() {
                match ev.id.as_ref() {
                    "show" => {
                        let ok = wtlite_ui::win32::show();
                        log::info!("[tray] menu 显示主窗口 -> visible={ok}");
                        acted = true;
                    }
                    "exit" => {
                        log::info!("[tray] menu 退出 -> stopping proxy and exiting");
                        wtlite_ui::shutdown();
                    }
                    _ => {}
                }
            }
            // The window focus/visibility changes we made must reach egui so the
            // UI recomputes its layout, but we must not busy-wait.
            std::thread::sleep(std::time::Duration::from_millis(if acted { 20 } else { 120 }));
            ticks += 1;
            if ticks % 400 == 0 {
                log::debug!("[tray] listener alive ({ticks} ticks, visible={})", wtlite_ui::win32::is_visible());
            }
        }
    });

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 680.0])
            .with_min_inner_size([528.0, 508.0])
            .with_icon(Arc::new(egui::IconData {
                rgba: icon.as_raw().to_vec(),
                width: w,
                height: h,
            })),
        ..Default::default()
    };

    eframe::run_native(
        "WattToolkit-Lite",
        options,
        Box::new(|_cc| Ok(Box::new(wtlite_ui::App::new(_cc)))),
    )
}
