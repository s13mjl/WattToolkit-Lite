@echo off
set PATH=C:\Users\30816\.cargo\bin;%PATH%
set RUSTUP_TOOLCHAIN=1.98.0-x86_64-pc-windows-msvc
set CARGO_TARGET_DIR=%TEMP%\WattToolkit-Lite-target
cd /d D:\desktop\0824\Dev_Git\SteamTools\WattToolkit-Lite
cargo run --release -p wtlite-core --example rulecheck 2>&1
echo EXIT=%ERRORLEVEL%
