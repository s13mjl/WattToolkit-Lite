$exe = Join-Path $env:TEMP 'WattToolkit-Lite-target\release\examples\e2eA.exe'
$out = Join-Path $env:TEMP 'ea2.txt'; $err = $out + '.err'
Remove-Item $out,$err -ErrorAction SilentlyContinue
Get-Process e2eA -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Get-Process 'Steam++.Accelerator' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Write-Output ('port free: ' + ((Get-NetTCPConnection -LocalPort 26561 -State Listen -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0))
$proc = Start-Process -FilePath $exe -PassThru -RedirectStandardOutput $out -RedirectStandardError $err
Start-Sleep -Seconds 4
Write-Output ('alive: ' + (-not $proc.HasExited))
Write-Output '=== stdout ==='
Get-Content $out -ErrorAction SilentlyContinue | Select-Object -First 12 | ForEach-Object { Write-Output ('  ' + $_) }
Write-Output '=== stderr ==='
Get-Content $err -ErrorAction SilentlyContinue | Select-Object -First 20 | ForEach-Object { Write-Output ('  ' + $_) }
Write-Output ('=== port holder: ' + ((Get-NetTCPConnection -LocalPort 26561 -State Listen -ErrorAction SilentlyContinue | ForEach-Object { (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName + '(' + $_.OwningProcess + ')' }) -join ',') + ' ===')
Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue