//! Embeds the Windows icon (and version info) into the executable so Explorer
//! and the taskbar show the application icon. Uses `embed-resource`, which
//! locates a resource compiler itself (rc.exe from the Windows SDK, or its own
//! fallback) - no build-time dependency on the SDK being on PATH.

fn main() {
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=../../assets/wattoolkit-lite.ico");
        println!("cargo:rerun-if-changed=app.rc");
        let _ = embed_resource::compile("app.rc", embed_resource::NONE);
    }
}
