$exe = Join-Path $env:TEMP 'WattToolkit-Lite-target\release\examples\e2eA.exe'
$out = Join-Path $env:TEMP 'ea6.txt'
Remove-Item $out -ErrorAction SilentlyContinue
Get-Process e2eA -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$proc = Start-Process -FilePath $exe -PassThru -RedirectStandardOutput $out -RedirectStandardError ($out+'.err')
Start-Sleep -Seconds 4
Write-Output '=== is our root CA in the trusted store? ==='
Get-ChildItem Cert:\LocalMachine\Root, Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -match 'WattToolkit-Lite' } | ForEach-Object { Write-Output ('  ' + $_.Subject + '  ' + $_.Thumbprint) }
Write-Output '=== curl with -k (ignore cert) to isolate server-side handshake ==='
$r = & curl.exe -s -o NUL -w '%{http_code} size=%{size_download}' -k --proxy http://127.0.0.1:26577 --connect-timeout 15 -m 40 https://steamcommunity.com 2>&1
Write-Output ("  result: $r")
Start-Sleep -Seconds 2
Write-Output '=== proxy log ==='
Get-Content $out -ErrorAction SilentlyContinue | Select-String 'LOG' | Select-Object -Last 12 | ForEach-Object { Write-Output ('  ' + $_.Line) }
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue