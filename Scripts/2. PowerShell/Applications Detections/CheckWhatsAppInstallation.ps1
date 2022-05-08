$usersfolders = get-childitem -Path c:\users -Name
$isWhatsAppInstalled = $false

foreach($userfolder in $usersfolders){
    $filepath = "c:\users\$userfolder\appdata\local\WhatsApp\WhatsApp.exe"
    # Write-Output $filepath
    $CheckInstallation = Test-path -Path $filepath -PathType Leaf
    if ($CheckInstallation -eq $true) {
        $isWhatsAppInstalled = $true
    }
}

Write-Output $isWhatsAppInstalled