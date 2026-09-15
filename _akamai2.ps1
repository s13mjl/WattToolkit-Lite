Write-Output '=== VERIFY the mechanism: can we reach steamcommunity.com via the Akamai IP with correct SNI? ==='
# The Akamai edge needs SNI=steamcommunity.com but connect via a reachable IP; cert must cover the name
foreach ($ip in @('2.19.198.168','2.19.198.179','2.19.198.130')) {
  $r = & curl.exe -s -o NUL -w '%{http_code} t=%{time_total}s' --resolve "steamcommunity.com:443:$ip" --ssl-no-revoke --noproxy '*' --connect-timeout 8 -m 20 https://steamcommunity.com/ 2>&1
  Write-Output ("   --resolve steamcommunity.com -> $ip  = $r")
}
Write-Output ''
Write-Output '=== and with the akamai hostname itself (SNI=akamai) ==='
foreach ($h in @('steamcommunity-a.akamaihd.net','community.akamai.steamstatic.com')) {
  $r = & curl.exe -s -o NUL -w '%{http_code} t=%{time_total}s' --resolve "${h}:443:2.19.198.168" --ssl-no-revoke --noproxy '*' --connect-timeout 8 -m 20 "https://$h/" 2>&1
  Write-Output ("   $h @ 2.19.198.168 = $r")
}
Write-Output ''
Write-Output '=== Does Akamai edge serve steamcommunity content when SNI/Host = steamcommunity.com? ==='
$r = & curl.exe -s -o NUL -w '%{http_code}' --resolve 'steamcommunity.com:443:2.19.198.144' --ssl-no-revoke --noproxy '*' --connect-timeout 8 -m 20 https://steamcommunity.com/ 2>&1
Write-Output ("   2.19.198.144 = $r")