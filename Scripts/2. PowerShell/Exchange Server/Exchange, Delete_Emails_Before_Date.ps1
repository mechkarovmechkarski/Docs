param(
    # Get name used to get-mailbox
    [Parameter(Mandatory=$True,Position=0)]
    [ValidateNotNull()]
    [string]$name
)

Write-host "This script deletes only emails in the mailbox."
Write-host "Check the date in the script and change it manually!!!"
$confirmation = Read-Host "Do you want to continue? [y/n]"

while($confirmation -ne "y")
{
    if ($confirmation -eq 'n') {exit}
    $confirmation = Read-Host "Do you want to continue? [y/n]"
}

$mailbox_name = get-mailbox $name

Do {
    $result = Search-Mailbox -Identity $mailbox_name.Identity -SearchQuery ‘Received<=”01/01/2017” AND kind:email’ -DeleteContent -force -WarningAction Silentlycontinue
    
   write-host $result.resultitemscount -ForegroundColor Green
   Write-host $result.resultitemssize 
   
    } Until ($result.resultitemscount -eq 0)
# SIG # Begin signature block
# MIIFdgYJKoZIhvcNAQcCoIIFZzCCBWMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUkzmMboeND69/FmlS/ULAaSA
# w3OgggMOMIIDCjCCAfKgAwIBAgIQEduA4TyHkbpNjS3q7jOyJzANBgkqhkiG9w0B
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
# FgQU+7cSJNzKTF5czwpuUs79cYGeX5gwDQYJKoZIhvcNAQEBBQAEggEAIUXfDEBY
# FNKAOeofqkFYXhKl8fB48XVhzj/FALbXoCa471/2S9IptSIFQrkYn6HdZ7FdkmPb
# 27KTOXUX1sJDqMnGB/LJmO/Cqsx/R5W8s/RiEf06vvtiiv3L4fMkgRqKNPTzjtHO
# Y3BVkCeIYSESpA0hNrCNFkJ/2vvSdJRsSxyFbkA0KMRCRx5DOnwVxOSgAAgSDNHk
# O4lMuPbUWbxXUOfVcFwzjCIR4qG8SNDUv2PabCXOqVAMz9XZb2ixPdSfNRy5W8Cu
# Xtmdn6FhplwMoFz371nF72vg+I+iDGNIriMw/5WiDC13O5oVgBr2A+1WVGoWZTh+
# QeWAjCdVbWDtyA==
# SIG # End signature block
