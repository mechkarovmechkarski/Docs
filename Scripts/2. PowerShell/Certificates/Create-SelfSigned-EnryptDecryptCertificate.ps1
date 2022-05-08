<# $SelfSignedCertParams = @{
KeyDescription = "PowerShell Script Encryption-Decryption Key"
Provider = "Microsoft Enhanced RSA and AES Cryptographic Provider"
KeyFriendlyName = "PSScriptEncryptDecryptKey"
FriendlyName = "$svcAccountName-PSScriptCipherCert"
Subject = "$svcAccountName-PSScriptCipherCert"
KeyUsage = "DataEncipherment"
Type = "DocumentEncryptionCert"
HashAlgorithm = "sha256"
CertStoreLocation = "Cert:\CurrentUser\My"
} #> 

$svcAccountName = Read-Host "Write what will be the service account using this certificate:"
$Months = Read-Host "Write how many months do you want the certificate to be valid (only numbers or script will fail):"

New-SelfSignedCertificate -KeyDescription "PowerShell Script Encryption-Decryption Key" `
-Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
-KeyFriendlyName "PSScriptEncryptDecryptKey" `
-FriendlyName "$svcAccountName-SelfSignedPSScriptCipherCert" `
-Subject "$svcAccountName-SelfSignedPSScriptCipherCert" `
-KeyUsage "DataEncipherment" `
-Type "DocumentEncryptionCert" `
-HashAlgorithm "sha256" `
-CertStoreLocation "Cert:\CurrentUser\My" `
-NotAfter (Get-Date).AddMonths($Months)
