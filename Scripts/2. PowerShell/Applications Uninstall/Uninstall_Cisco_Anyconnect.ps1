$product = gwmi win32_product -filter "Name LIKE '%Cisco Anyconnect%'"
Write-Output "$product"
msiexec /x {91213CC3-6174-4580-85D9-167470A24315} /q
exit $LASTEXITCODE

