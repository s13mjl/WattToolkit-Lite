$ErrorActionPreference='Continue'
Write-Output '=== DoH JSON API (what my code uses) ==='
foreach ($u in 'https://223.5.5.5/resolve?name=steamcommunity.com&type=A','https://dns.alidns.com/resolve?name=steamcommunity.com&type=A','https://doh.pub/dns-query?name=steamcommunity.com&type=A') {
  try { $r = Invoke-RestMethod -Uri $u -TimeoutSec 10; $ips = ($r.Answer | Where-Object { $_.type -eq 1 } | ForEach-Object { $_.data }) -join ','; Write-Output ('  ' + $u.Split('?')[0].PadRight(38) + ' -> ' + $ips) } catch { Write-Output ('  ' + $u.Split('?')[0].PadRight(38) + ' -> FAIL ' + $_.Exception.Message.Substring(0,[Math]::Min(50,$_.Exception.Message.Length))) }
}
Write-Output ''
Write-Output '=== what does the system resolve (official may rely on this) ==='
try { $a = Resolve-DnsName steamcommunity.com -Type A -ErrorAction Stop; ($a | Where-Object {$_.IPAddress} | ForEach-Object { Write-Output ('  system DNS -> ' + $_.IPAddress) }) } catch { Write-Output '  system resolve failed' }
Write-Output ''
Write-Output '=== reachability of the Akamai IPs the official proxy uses ==='
foreach ($ip in '2.19.198.160','2.19.198.168') { $t = Test-NetConnection -ComputerName $ip -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue; Write-Output ('  ' + $ip + ':443 -> ' + $t) }