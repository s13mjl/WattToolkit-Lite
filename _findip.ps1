Write-Output '=== 2.19.198.168 - who else resolves to it? (find the UNPOISONED domain) ==='
foreach ($h in @('steamcommunity.com','www.steamcommunity.com','steamcommunity-a.akamaihd.net','community.akamai.steamstatic.com','cdn.akamai.steamstatic.com','store.akamai.steamstatic.com','media.steampowered.com','avatars.akamai.steamstatic.com')) {
  # query Ali DoH AND system, show both
  $doh = '?'; $sys = '?'
  try { $r = Invoke-RestMethod -Uri ('https://223.5.5.5/resolve?name=' + $h + '&type=A') -TimeoutSec 6; $doh = (@($r.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { $_.data }) -join ',') ; if (-not $doh) { $doh = '(none)' } } catch { $doh = 'ERR' }
  try { $sys = ([System.Net.Dns]::GetHostAddresses($h) | ForEach-Object { $_.IPAddressToString }) -join ',' } catch { $sys = 'ERR' }
  $hasAkamai = if ($doh -match '2\.19\.198') { 'AKAMAI-OK' } else { '' }
  Write-Output ('  ' + $h.PadRight(36) + ' doh=' + $doh.PadRight(34) + ' sys=' + $sys + '  ' + $hasAkamai)
}