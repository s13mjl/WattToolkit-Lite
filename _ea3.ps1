# stop BOTH official and any leftovers holding the port
Get-Process 'Steam++.Accelerator','Steam++','e2eA' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 3
$h = Get-NetTCPConnection -LocalPort 26561 -State Listen -ErrorAction SilentlyContinue
Write-Output ('port holders after kill: ' + (($h | ForEach-Object { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName }) -join ','))
$exe = Join-Path $env:TEMP 'WattToolkit-Lite-target\release\examples\e2eA.exe'
$out = Join-Path $env:TEMP 'ea3.txt'
Remove-Item $out -ErrorAction SilentlyContinue
$proc = Start-Process -FilePath $exe -PassThru -RedirectStandardOutput $out -RedirectStandardError ($out+'.err')
Start-Sleep -Seconds 4
$hh = Get-NetTCPConnection -LocalPort 26561 -State Listen -ErrorAction SilentlyContinue
Write-Output ('now holding: ' + (($hh | ForEach-Object { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName + '(' + $_.OwningProcess + ')' }) -join ','))
Write-Output '=== TLS via our proxy: steamcommunity.com ==='
$r = & curl.exe -s -o NUL -w '%{http_code} t=%{time_total}s size=%{size_download}' --proxy http://127.0.0.1:26561 --connect-timeout 15 -m 40 https://steamcommunity.com 2>&1
Write-Output ("  result: $r")
Write-Output '=== control: github.com via our proxy ==='
$r2 = & curl.exe -s -o NUL -w '%{http_code} t=%{time_total}s' --proxy http://127.0.0.1:26561 --connect-timeout 15 -m 30 https://github.com 2>&1
Write-Output ("  result: $r2")
Start-Sleep -Seconds 2
Write-Output '=== proxy log ==='
Get-Content $out -ErrorAction SilentlyContinue | Select-String 'LOG' | Select-Object -Last 15 | ForEach-Object { Write-Output ('  ' + $_.Line) }
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue