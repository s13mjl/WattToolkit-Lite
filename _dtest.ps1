Write-Output '=== WinDivert driver status ==='
Get-Service -Name WinDivert* -ErrorAction SilentlyContinue | ForEach-Object { Write-Output ('  ' + $_.Name + '  ' + $_.Status) };
$wd = Get-Item (Join-Path $env:LOCALAPPDATA 'Steam++\native\win-x64\WinDivert64.sys') -ErrorAction SilentlyContinue
if ($wd) { Write-Output ('  driver file: ' + $wd.FullName + '  ' + $wd.Length + 'B') }
$wd2 = Get-ChildItem 'D:\desktop\0824\Dev_Git\SteamTools\WattToolkit-Lite' -Recurse -Filter 'WinDivert*' -ErrorAction SilentlyContinue | ForEach-Object { Write-Output ('  our dir: ' + $_.Name + '  ' + $_.Length) }

Write-Output '=== the dnstest example has a 120s window, let us test ==='
$out = Join-Path $env:TEMP 'dnstest-live.txt'
Remove-Item $out -ErrorAction SilentlyContinue
$env:PATH = 'C:\Users\30816\.cargo\bin;' + $env:PATH
$env:RUSTUP_TOOLCHAIN = '1.98.0-x86_64-pc-windows-msvc'
$env:CARGO_TARGET_DIR = Join-Path $env:TEMP 'WattToolkit-Lite-target'
Set-Location 'D:\desktop\0824\Dev_Git\SteamTools\WattToolkit-Lite'
cmd /c 'cargo build --release -p wtlite-core --example dnstest 2>&1' | Select-Object -Last 1
$proc = Start-Process -FilePath 'cmd' -ArgumentList '/c', 'cargo run --release -p wtlite-core --example dnstest' -PassThru -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError ($out+'.err')
Start-Sleep -Seconds 3
Write-Output '=== trigger DNS query for steamcommunity.com ==='
ipconfig /flushdns | Out-Null
try {
  $r = Resolve-DnsName steamcommunity.com -Type A -ErrorAction Stop -DnsOnly
  Write-Output ('  resolved: ' + (($r | ForEach-Object { $_.IPAddress }) -join ', '))
} catch { Write-Output ('  resolve ERR: ' + $_.Exception.Message) }
Start-Sleep -Seconds 2
Write-Output '=== DNS cache check ==='
ipconfig /displaydns 2>$null | Select-String 'steamcommunity' -Context 0,5 | Select-Object -First 8 | ForEach-Object { Write-Output $_.Line }
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
Write-Output '=== proxy log ==='
Get-Content $out -ErrorAction SilentlyContinue | Select-String 'LOG' | Select-Object -Last 12 | ForEach-Object { Write-Output ('  ' + $_.Line) }