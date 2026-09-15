$exe = Join-Path $env:TEMP 'WattToolkit-Lite-target\release\examples\probe9.exe'
$out = Join-Path $env:TEMP 'probe12.txt'
Remove-Item $out -ErrorAction SilentlyContinue
Get-Process probe9 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Set-Item env:RUST_LOG 'info'
$proc = Start-Process -FilePath $exe -PassThru -RedirectStandardOutput $out -RedirectStandardError ($out+'.err')
Start-Sleep -Seconds 4
Write-Output '=== REAL browser-engine test: schannel WITHOUT --ssl-no-revoke ==='
foreach ($u in 'https://steamcommunity.com','https://github.com','https://store.steampowered.com') {
  $r = & curl.exe -s -o NUL -w '%{http_code} t=%{time_total}s' --proxy http://127.0.0.1:26561 --connect-timeout 15 -m 40 $u 2>&1
  Write-Output ("   $u -> $r")
}
Start-Sleep -Seconds 2
Write-Output '=== proxy log ==='
Get-Content $out -ErrorAction SilentlyContinue | Select-String 'LOG' | Select-Object -Last 12 | ForEach-Object { Write-Output ('  ' + $_.Line) }
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue