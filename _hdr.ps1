Write-Output '=== full response headers via official proxy ==='
$h = & curl.exe -s -D - -o NUL --ssl-no-revoke --proxy http://127.0.0.1:26561 --connect-timeout 20 -m 40 https://steamcommunity.com 2>&1
$h | Select-Object -First 30 | ForEach-Object { Write-Output ('  ' + $_) }
Write-Output ''
Write-Output '=== same request DIRECT (fails) vs via proxy - compare ==='
Write-Output '=== check TLS cert presented through official proxy (MITM evidence) ==='
$c = & curl.exe -sv -o NUL --ssl-no-revoke --proxy http://127.0.0.1:26561 --connect-timeout 20 -m 40 https://steamcommunity.com 2>&1
$c | Select-String -Pattern 'subject:|issuer:|start date|expire date|SSL connection|ALPN' | Select-Object -First 10 | ForEach-Object { Write-Output ('  ' + $_.Line.Trim()) }