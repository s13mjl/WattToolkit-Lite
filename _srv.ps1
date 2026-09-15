Write-Output '=== confirm: which domains get the WattToolkit server vs plain direct? ==='
foreach ($u in 'https://steamcommunity.com','https://store.steampowered.com','https://github.com','https://www.baidu.com') {
  $h = & curl.exe -s -D - -o NUL --ssl-no-revoke --proxy http://127.0.0.1:26561 --connect-timeout 15 -m 35 $u 2>&1
  $wt = ($h | Select-String 'Server: WattToolkit' | Measure-Object).Count
  $status = ($h | Select-String '^HTTP/1.1' | Select-Object -Last 1)
  Write-Output ('  ' + $u.PadRight(36) + ' WattToolkit-server=' + $wt + '   ' + ($status -replace '\s+',' '))
}
Write-Output ''
Write-Output '=== the X-Watt headers the client sends (from source) are the token auth ==='
Write-Output '  X-Watt-Origin-Dest-Scheme / Host / PathAndQuery / Token'