$svcAccountName = Read-Host "Write what will be the service account using this certificate:"
$Months = Read-Host "Write how many months do you want the certificate to be valid (only numbers or script will fail):"

New-SelfSignedCertificate -CertStoreLocation cert:\currentuser\my `
-Subject "$svcAccountName-SelfSignedCodeSigning" `
-FriendlyName "$svcAccountName-SelfSignedCodeSigning" `
-KeyAlgorithm RSA `
-KeyLength 2048 `
-Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
-KeyExportPolicy Exportable `
-KeyUsage DigitalSignature `
-Type CodeSigningCert `
-NotAfter (Get-Date).AddMonths($Months)
# SIG # Begin signature block
# MIIFdgYJKoZIhvcNAQcCoIIFZzCCBWMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUg4Wd7UUiqXXv0OTcCYOJMzz1
# 6CugggMOMIIDCjCCAfKgAwIBAgIQEduA4TyHkbpNjS3q7jOyJzANBgkqhkiG9w0B
# AQUFADAdMRswGQYDVQQDDBJMb2NhbCBDb2RlIFNpZ25pbmcwHhcNMTkxMjA4MDgw
# NDU1WhcNMjAxMjA4MDgyNDU1WjAdMRswGQYDVQQDDBJMb2NhbCBDb2RlIFNpZ25p
# bmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDjcyZ7XWj943mMrUtH
# ZdXBIRMMBed+ueUPqCduUWgciF0puzP9ymqIruEstCQOJw1G/PBDwxYg4fFJvQ7U
# /5pZR/wUpmmuXwoaiDU3H1zxEfx1VeQoTl7rmUZVT7O8tszRIQUEH5q2Eql8W3MF
# ZHeinIBlGZJkWTAePoYUQJgaGRTrV0U6BWaCFMSUWoP2Wh8x1AQBBMTbdkM2elaM
# ghXPNHznSxuvZrj2LA3dZDDUg/JAenhmKlqllbOwP9pOCyWXyQDhhXpdZmHGgqwt
# mQ9V7Ppxl0yMLIVHZYGn7d4e7grX6ILDNe84npNhsdx7ifuugHeD75oPSnhYkRLh
# rzJtAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcD
# AzAdBgNVHQ4EFgQUYNXK9CJ/3VMst+RPMLg1rnOS4HIwDQYJKoZIhvcNAQEFBQAD
# ggEBAE6GTsJZSDQG0TYPYaXLm6KVz7+wGNGUR+yGvxdh5bhPtZWUa+URXpLZqU4D
# Jx3O0JCIrQbqCjfWApgIiuFVoFPTOz2ozZRqggpjrL6PLRFw0/NgZ0drDDe4OS7c
# 5K+72ztqheQa2PZYLBAb/YdlwCJK4Vl6EsT+lWbeKGvcwLOOpgZQzhZpa3oy/E4E
# GFjoUSNIOJJAjM5P8mqlBDQbS6vPNsgcVnBVOxYsg7oInsmqaNzm338a+ZWlbCug
# Zr9ORCslJxS9O2bcj9KESuO6Q1ukdL+mpsxUnSl4GOnfTvpBF7Rw9yV8yw3Er1p9
# Bb7HXq7yNalg0xHusxXjdoFJQSgxggHSMIIBzgIBATAxMB0xGzAZBgNVBAMMEkxv
# Y2FsIENvZGUgU2lnbmluZwIQEduA4TyHkbpNjS3q7jOyJzAJBgUrDgMCGgUAoHgw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQx
# FgQUNB6S8ejKcvZ9c4sLH4gCZyJ28eEwDQYJKoZIhvcNAQEBBQAEggEANioHvNCV
# oyvjf88l9I2W/ZNPH8GDpKSoiwIxAus2fGcfOPZI5POX+nCjpPcNBfomDi2LzT0E
# jzrdMyowN8Jq8wlQ+dLtyPdsuwmg0Eh1AobnbVYL9yvVHEe5Dwy0d+8DqTzOTmss
# omgSSXna16/mKRtap/0EuYLx445FsxYAd3sJ6zAZFRrgjCP38Nw2qbZjW+9G4Tqq
# r6I3K2t2psjedXquAhjXH0xDfIIc7Ouribpz1rQltYaI4FJ3/zvx7Yzj0wgC1Fbw
# FiC4wEFrWgbQz3dtbuma0eRTZJW2E5AvdOxAcM7IFcpy7qrNgpCVVNIM+VcVIWcb
# SzHM0FcxUOcrIQ==
# SIG # End signature block
