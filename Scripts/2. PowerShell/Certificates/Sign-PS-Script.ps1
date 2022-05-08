##################################################
########## For exporting certificate and signing one powershell script use this:
#$cert = @(Get-ChildItem cert:\CurrentUser\My -CodeSigning)[0]
#Set-AuthenticodeSignature .\your-script.ps1 $cert
#
#
##################################################


$PSscripts = Get-ChildItem -Path "C:\folder" -Filter "*.ps1" -Recurse | Select-Object FullName
$cert = (dir cert:\CurrentUser\My -CodeSigningCert)

foreach ($script in $PSscripts){
Set-AuthentiCodeSignature $script[0].FullName $cert
}
# SIG # Begin signature block
# MIIFdgYJKoZIhvcNAQcCoIIFZzCCBWMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUirLKgGgO/kvAfp8zCmv32xqo
# 5gGgggMOMIIDCjCCAfKgAwIBAgIQEduA4TyHkbpNjS3q7jOyJzANBgkqhkiG9w0B
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
# FgQUNBHfNnwSkTZf7Y69rlHld2KPGW4wDQYJKoZIhvcNAQEBBQAEggEAUIKKtr83
# VqzmRyQchGaSXnkNX21HZAK38lZlOvBetrX6iAk/ezgr4YrT/In4RF94Uby9cwKo
# N/+9PRHOgt4Syxx7iptAJolo/E5gLMqP+eY+xmw2FhRbHhRuBPJCyP28QFndHonV
# JfJOAu8W2RT2XR2FkwFMptkbliZ9a38qvR1F6mUcwpTzu6ycgizm7A7SCjL43g2+
# C+OeeYunZ0hY30jmQUDpwVhOyRe8tQRjEoryC299i3smjHzcBrBtBqIOQSYfdmPS
# GRS78MsNtwaO0pjEti2O+hYvJYkVfbC5s3RsOXi4jXJljDheTpNTi+gsxMgS08p3
# frOIddX1RN8CfQ==
# SIG # End signature block
