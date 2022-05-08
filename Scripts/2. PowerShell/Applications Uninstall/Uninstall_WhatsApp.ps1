$usersfolders = get-childitem -Path c:\users -Name
$isWhatsAppInstalled = $false

foreach($userfolder in $usersfolders){
    $filepath = "c:\users\$userfolder\appdata\local\WhatsApp\Update.exe"
    # Write-Output $filepath
    $CheckInstallation = Test-path -Path $filepath -PathType Leaf
    if ($CheckInstallation -eq $true) {
        $isWhatsAppInstalled = $true
    }

    if ($isWhatsAppInstalled -eq $true) {
        try {
            Start-Process -Wait -FilePath "c:\users\$userfolder\appdata\local\WhatsApp\Update.exe" -ArgumentList ‘--uninstall -s’
            Write-Output "$userfolder OK"
        }
        catch {
            Write-Output "$userfolder error"
        }
        $isWhatsAppInstalled = $false
    }
}