$pid = 2812
function Snap {
  $set = @{}
  $lines = netstat -ano | Select-String ('\s' + $pid + '$')
  foreach ($l in $lines) {
    if ($l.Line -match '^\s*TCP\s+[\d.]+:(\d+)\s+([\d.]+):(\d+)\s+ESTABLISHED') { $set[$Matches[2] + ':' + $Matches[3]] = 1 }
  }
  return $set
}
Write-Output '=== snapshot BEFORE ==='
$before = Snap
Write-Output ('  established: ' + $before.Count)

# single request through official proxy
$job = Start-Job -ScriptBlock { & curl.exe -s -o NUL --ssl-no-revoke --proxy http://127.0.0.1:26561 --connect-timeout 20 -m 40 https://steamcommunity.com }
Start-Sleep -Milliseconds 400
$during = @{}
for ($i = 0; $i -lt 40; $i++) {
  $s = Snap
  foreach ($k in $s.Keys) { if (-not $before.ContainsKey($k)) { $during[$k] = 1 } }
  Start-Sleep -Milliseconds 120
}
Receive-Job $job -Wait -ErrorAction SilentlyContinue | Out-Null
Remove-Job $job -Force -ErrorAction SilentlyContinue
Write-Output '=== NEW connections attributable to MY request (diff) ==='
if ($during.Count -eq 0) { Write-Output '  (none captured - request may have completed too fast)' } else { $during.Keys | Sort-Object | ForEach-Object { Write-Output ('  ' + $_) } }