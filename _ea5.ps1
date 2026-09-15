$exe = Join-Path $env:TEMP 'WattToolkit-Lite-target\release\examples\e2eA.exe'
$out = Join-Path $env:TEMP 'ea5.txt'
Remove-Item $out -ErrorAction SilentlyContinue
Get-Process e2eA -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
$proc = Start-Process -FilePath $exe -PassThru -RedirectStandardOutput $out -RedirectStandardError ($out+'.err')
Start-Sleep -Seconds 4
Write-Output '=== curl verbose through our proxy (see TLS failure reason) ==='
& curl.exe -sv -o NUL --proxy http://127.0.0.1:26577 --connect-timeout 15 -m 30 https://steamcommunity.com 2>&1 | Select-String -Pattern 'CONNECT|schannel|certificate|SSL|TLS|error|subject|issuer|HTTP/' | Select-Object -First 20 | ForEach-Object { Write-Output ('  ' + $_.Line.Trim()) }
Start-Sleep -Seconds 1
Write-Output '=== log ==='
Get-Content $out -ErrorAction SilentlyContinue | Select-String 'LOG' | Select-Object -Last 10 | ForEach-Object { Write-Output ('  ' + $_.Line) }
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue