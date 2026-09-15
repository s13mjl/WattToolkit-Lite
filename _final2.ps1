Write-Output '=== A. verbose: why does --resolve to Akamai fail? ==='
& curl.exe -sv -o NUL --resolve 'steamcommunity.com:443:2.19.198.130' --ssl-no-revoke --noproxy '*' --connect-timeout 8 -m 20 https://steamcommunity.com 2>&1 | Select-String -Pattern 'Connected|schannel|error|SSL|TLS|handshake|reset' | Select-Object -First 8 | ForEach-Object { Write-Output ('   ' + $_.Line.Trim()) }

Write-Output '=== B. plain HTTP to the Akamai IP with Host: steamcommunity.com (what MITM would do) ==='
foreach ($ip in @('2.19.198.130','2.19.198.168')) {
  $r = & curl.exe -s -o NUL -w '%{http_code} t=%{time_total}s' -H 'Host: steamcommunity.com' --noproxy '*' --connect-timeout 8 -m 20 "http://$ip/" 2>&1
  Write-Output ("   http://$ip/ (Host: steamcommunity.com) -> $r")
}

Write-Output '=== C. try https with SNI override ==='
foreach ($ip in @('2.19.198.130','2.19.198.168')) {
  $r = & curl.exe -s -o NUL -w '%{http_code}' --resolve "steamcommunity.com:443:$ip" --ssl-no-revoke --noproxy '*' --connect-timeout 8 -m 20 https://steamcommunity.com/ 2>&1
  Write-Output ("   https $ip -> $r")
  $r2 = & curl.exe -s -o NUL -w '%{http_code}' --resolve "www.steamcommunity.com:443:$ip" --ssl-no-revoke --noproxy '*' --connect-timeout 8 -m 20 https://www.steamcommunity.com/ 2>&1
  Write-Output ("   https www @ $ip -> $r2")
}