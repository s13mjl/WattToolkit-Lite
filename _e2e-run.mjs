
const chk2 = await tools.pwsh({ command: 'Write-Output ("e2e bat: " + (Test-Path "D:\\desktop\\0824\\Dev_Git\\SteamTools\\WattToolkit-Lite\\_e2e9.cmd"))' });
console.log(chk2.stdout.text);
if (chk2.stdout.text.includes("True")) {
  const p = await tools.pwsh({
    command: 'cmd /c "D:\\desktop\\0824\\Dev_Git\\SteamTools\\WattToolkit-Lite\\_e2e9.cmd" 2>&1 | Out-File -FilePath (Join-Path $env:TEMP "e2e-full.txt") -Encoding UTF8; Get-Content (Join-Path $env:TEMP "e2e-full.txt") | Select-Object -Last 45 | ForEach-Object { $_ }',
    description: "Run PAC e2e test",
    timeoutMs: 180000,
  });
  console.log(p.stdout.text.slice(0, 5000));
} else {
  const p = await tools.pwsh({
    command: '$env:PATH = "C:\\Users\\30816\\.cargo\\bin;" + $env:PATH; $env:RUSTUP_TOOLCHAIN = "1.98.0-x86_64-pc-windows-msvc"; $env:CARGO_TARGET_DIR = Join-Path $env:TEMP "WattToolkit-Lite-target"; cargo run --release -p wtlite-core --example pac_e2e 2>&1 | Out-File -FilePath (Join-Path $env:TEMP "e2e-full.txt") -Encoding UTF8; Get-Content (Join-Path $env:TEMP "e2e-full.txt") | Select-Object -Last 45 | ForEach-Object { $_ }',
    description: "Run e2e via cargo directly",
    workdir: proj,
    timeoutMs: 180000,
  });
  console.log(p.stdout.text.slice(0, 5000));
}
