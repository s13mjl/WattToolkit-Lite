Write-Output '=== TEST 1: does 2.19.198.160 actually serve steamcommunity.com? ==='
foreach ($ip in @('2.19.198.160','2.19.198.144','2.19.198.168')) {
  $r = & curl.exe -s -o NUL -w '%{http_code} t=%{time_total}s' --resolve "steamcommunity.com:443:$ip" --ssl-no-revoke --noproxy '*' --connect-timeout 10 -m 25 https://steamcommunity.com 2>&1
  Write-Output ("  $ip -> $r")
}
Write-Output ''
Write-Output '=== TEST 2: repeat Ali DoH 12 times - do we ever get a non-poisoned IP? ==='
$seen = @{}
for ($i = 1; $i -le 12; $i++) {
  try {
    $r = Invoke-RestMethod -Uri 'https://223.5.5.5/resolve?name=steamcommunity.com&type=A' -TimeoutSec 8
    $ips = ($r.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { $_.data })
    foreach ($ip in $ips) { if (-not $seen.ContainsKey($ip)) { $seen[$ip] = 1; Write-Output ('  NEW: ' + $ip) } }
  } catch { Write-Output ('  attempt ' + $i + ' failed') }
}
Write-Output ('  distinct IPs over 12 queries: ' + $seen.Count)