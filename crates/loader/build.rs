//! Embeds the Windows icon, application manifest and version info into the
//! executable. Uses `embed-resource`, which locates a resource compiler itself
//! (rc.exe from the Windows SDK, or its own fallback) - no build-time
//! dependency on the SDK being on PATH.

fn main() {
    #[cfg(windows)]
    {
        println!("cargo:rerun-if-changed=../../assets/wattoolkit-lite.ico");
        println!("cargo:rerun-if-changed=app.rc");
        println!("cargo:rerun-if-changed=app.manifest");
        let _ = embed_resource::compile("app.rc", embed_resource::NONE);
    }
}
