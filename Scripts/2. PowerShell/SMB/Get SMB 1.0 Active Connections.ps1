Try{
    $smbstate = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol | Select-Object -Property State
} Catch{
    Write-Output "check skipped"
}

if($smbstate.State -eq "Enabled"){
    Get-SMBConnection | Where-Object {$_.Dialect -lt 2.0} | Select-Object -Property Dialect | foreach { $_.Dialect }
}else{
    Write-Output "Not Enabled"
}

