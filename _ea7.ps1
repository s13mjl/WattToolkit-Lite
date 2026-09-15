$exe = Join-Path $env:TEMP 'WattToolkit-Lite-target\release\examples\e2eA.exe'
$out = Join-Path $env:TEMP 'ea7.txt'
Remove-Item $out -ErrorAction SilentlyContinue
Get-Process e2eA -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$proc = Start-Process -FilePath $exe -PassThru -RedirectStandardOutput $out -RedirectStandardError ($out+'.err')
Start-Sleep -Seconds 4
Write-Output '=== steamcommunity.com through our MITM substitution proxy ==='
$r = & curl.exe -sk -o NUL -w '%{http_code} t=%{time_total}s size=%{size_download}' --proxy http://127.0.0.1:26577 --connect-timeout 15 -m 40 https://steamcommunity.com 2>&1
Write-Output ("  result: $r")
Write-Output '=== github.com (plain tunnel, control) ==='
$r2 = & curl.exe -s -o NUL -w '%{http_code} t=%{time_total}s' --proxy http://127.0.0.1:26577 --connect-timeout 15 -m 30 https://github.com 2>&1
Write-Output ("  result: $r2")
Start-Sleep -Seconds 2
Write-Output '=== proxy log ==='
Get-Content $out -ErrorAction SilentlyContinue | Select-String 'LOG' | Select-Object -Last 15 | ForEach-Object { Write-Output ('  ' + $_.Line) }
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue