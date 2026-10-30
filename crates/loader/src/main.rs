//! WattToolkit-Lite entry point.
//!
//! The binary is built as a GUI application (see `windows_subsystem` below) so
//! launching it never opens a console window. Diagnostics go to
//! `%LOCALAPPDATA%\WattToolkit-Lite\logs\app.log` via env_logger.
//!
//! The window/tray/UI live in `wtlite-ui` (native Win32/GDI); this binary only
//! prepares logging and the recoloured application icon.

// Hide the console window in release builds; debug builds keep it for output.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use image::{Rgba, RgbaImage};

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
        let (r, g, b, a) = (
            px[0] as f32 / 255.0,
            px[1] as f32 / 255.0,
            px[2] as f32 / 255.0,
            px[3],
        );
        let (hr, hg, hb) = rgb_to_hsv(r, g, b);
        // If the pixel is bluish (hue 0.5..0.78), rotate toward green (~0.36).
        let nh = if hr >= 0.5 && hr <= 0.78 && hb > 0.15 {
            0.36
        } else {
            hr
        };
        let (nr, ng, nb) = hsv_to_rgb(nh, hg, hb);
        out.put_pixel(
            x,
            y,
            Rgba([
                (nr * 255.0) as u8,
                (ng * 255.0) as u8,
                (nb * 255.0) as u8,
                a,
            ]),
        );
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
    let s = if l > 0.5 {
        d / (2.0 - max - min)
    } else {
        d / (max + min)
    };
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
    let q = if l < 0.5 {
        l * (1.0 + s)
    } else {
        l + s - l * s
    };
    let p = 2.0 * l - q;
    let f = |t: f32| -> f32 {
        let t = if t < 0.0 {
            t + 1.0
        } else if t > 1.0 {
            t - 1.0
        } else {
            t
        };
        if t < 1.0 / 6.0 {
            p + (q - p) * 6.0 * t
        } else if t < 0.5 {
            q
        } else if t < 2.0 / 3.0 {
            p + (q - p) * (2.0 / 3.0 - t) * 6.0
        } else {
            p
        }
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
    let _ = image::DynamicImage::ImageRgba8(rec.clone())
        .save_with_format(&png_path, image::ImageFormat::Png);
    Some(rec)
}

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
    builder.format_timestamp_millis();
    if let Ok(f) = file {
        builder.target(env_logger::Target::Pipe(Box::new(f)));
    }
    builder.init();
}

fn main() {
    init_logging();
    let Some(icon) = load_icon() else {
        log::error!("application icon could not be loaded");
        return;
    };
    let (width, height) = (icon.width(), icon.height());
    let data = wtlite_ui::IconData {
        rgba: icon.into_raw(),
        width,
        height,
    };
    if let Err(e) = wtlite_ui::run(data) {
        log::error!("UI exited with error: {e}");
    }
}
