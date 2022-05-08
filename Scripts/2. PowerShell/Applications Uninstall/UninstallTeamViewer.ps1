<# Computers and users
POBGC0245 - Rumen IT
POBGC0106 - Petko IT
POBGC0365 - Nenko IT
POBGC0362 - Grigor IT
POBGC0379 - Chavdar IT
POBGC0348 - TsvetkovB
POBGC0358 - SyarovN
POBGC0161 - IvanovO
POBGC0116 - AngelovY
POBGC0356 -KassabovK
#>


#File types and path to check
$fileToCheck = "${env:ProgramFiles(x86)}\TeamViewer\uninstall.exe"
$hosts = "POBGC0245", "POBGC0106", "POBGC0365", "POBGC0362", "POBGC0348", "POBGC0358", "POBGC0161", "POBGC0116", "POBGC0379", "POBGC0356"
$PC = $env:computername
<#Conditions #>
if ($hosts.Contains($pc))
{
write-output "Host is in the list" $pc
}
else
{
if (Test-Path $fileToCheck -PathType leaf)
{
#Process TeamViewer stop
stop-process -name "TeamViewer" -ErrorAction SilentlyContinue -Force

cd "${env:ProgramFiles(x86)}\TeamViewer\"
.\uninstall.exe /S
Write-Output "Success"
}
else
{
if (Test-Path "${env:ProgramFiles(x86)}\TeamViewer\Version9\" -PathType Leaf)
{
cd "${env:ProgramFiles(x86)}\TeamViewer\Version9\"
.\uninstall.exe /S
Write-Output "Success uninstall V9 Full"
}
else
{
Write-Output "PC isn't in the list and don't have TeamViewer Full version, Check it !"
}
}
}
