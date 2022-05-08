#################################################################################
#
# The sample scripts are not supported under any Microsoft standard support 
# program or service. The sample scripts are provided AS IS without warranty 
# of any kind. Microsoft further disclaims all implied warranties including, without 
# limitation, any implied warranties of merchantability or of fitness for a particular 
# purpose. The entire risk arising out of the use or performance of the sample scripts 
# and documentation remains with you. In no event shall Microsoft, its authors, or 
# anyone else involved in the creation, production, or delivery of the scripts be liable 
# for any damages whatsoever (including, without limitation, damages for loss of business 
# profits, business interruption, loss of business information, or other pecuniary loss) 
# arising out of the use of or inability to use the sample scripts or documentation, 
# even if Microsoft has been advised of the possibility of such damages.
#
#################################################################################

# Version 21.03.11.0620

#################################################################################
#
# The sample scripts are not supported under any Microsoft standard support
# program or service. The sample scripts are provided AS IS without warranty
# of any kind. Microsoft further disclaims all implied warranties including, without
# limitation, any implied warranties of merchantability or of fitness for a particular
# purpose. The entire risk arising out of the use or performance of the sample scripts
# and documentation remains with you. In no event shall Microsoft, its authors, or
# anyone else involved in the creation, production, or delivery of the scripts be liable
# for any damages whatsoever (including, without limitation, damages for loss of business
# profits, business interruption, loss of business information, or other pecuniary loss)
# arising out of the use of or inability to use the sample scripts or documentation,
# even if Microsoft has been advised of the possibility of such damages.
#
#################################################################################
#

<#
.SYNOPSIS
    This script provides detection mechanism for exchange onprem security threats for E13, E16 and E19.
    For more information please go to https://aka.ms/exchangevulns

    .DESCRIPTION
    This script will:
        1. Examine the files in each exchange virtual directory in IIS and compares the file hashes against the baseline hashes from the exchange installation files.

    The result generated is stored in a file locally with the following format: <ExchangeVersion>_result.csv
    If there are errors during file comparision there is an error generated on the cmdline.

    How to read the output:
        Open the result csv file in excel or in powershell:
        $result = Import-Csv <Path to result file>

        If CompressSuspiciousAndMissingFilesToCSV is specified, you should find files marked as Suspicious and NoHashMatch zipped in current directory.

    Submitting files for analysis:
        Please submit the output file for analysis in the malware analysis portal
        in the link below. Please add the text "ExchangeMarchCVE" in
        "Additional Information" field on the portal submission form.
            https://www.microsoft.com/en-us/wdsi/filesubmission
        Instructions on how to use the portal can be found here:
            https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/submission-guide

    Disclaimer:
        The script currently only validates any compromised file in exchange vdirs, it does not check any files in the iis root.
        This script needs to be run as ADMINISTRATOR

    .EXAMPLE
    PS C:\> CompareExchangeHashes.ps1

    PS C:\> CompareExchangeHashes.ps1 -CompressSuspiciousAndMissingFilesToCSV $true
#>

[CmdletBinding(SupportsShouldProcess)]
param
(
    [Parameter(Mandatory = $false, HelpMessage = 'Compress files marked with NoHashFound and Suspicious to a zip file?')]
    [bool]$CompressSuspiciousAndMissingFilesToCSV = $false
)


$ErrorActionPreference = 'Stop';

$BuildVersion = "21.03.11.0620"

# use native powershell types
$KNOWN_BAD_HASH = @{ `
        'b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0' = $true; `
        '097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3e' = $true; `
        '2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1' = $true; `
        '65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5' = $true; `
        '511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1' = $true; `
        '4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea' = $true; `
        '811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d' = $true; `
        '1631a90eb5395c4e19c7dbcbf611bbe6444ff312eb7937e286e4637cb9e72944' = $true; `

}

$KNOWN_ROOT_FILES = @{ `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client"                                      = $true; `
        "$env:SystemDrive\inetpub\wwwroot\iisstart.htm"                                       = $true; `
        "$env:SystemDrive\inetpub\wwwroot\iisstart.png"                                       = $true; `
        "$env:SystemDrive\inetpub\wwwroot\web.config"                                         = $true; `
        "$env:SystemDrive\inetpub\wwwroot\web.config.bak"                                     = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs"                                              = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\newmantest.aspx"                      = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\newmantest2.aspx"                     = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\newmantest3.aspx"                     = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\poc.aspx"                             = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\system_web"                           = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\system_web\4_0_30319"                 = $true; `
        "$env:SystemDrive\inetpub\wwwroot\aspnet_client\system_web\poc.aspx"                  = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin"                                        = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification"                                = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\decommission"                                 = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\groupexpansion"                               = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing"                                    = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\AuditReportMgr.asmx"                    = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\ClusterInfoMgr.asmx"                    = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\EnterpriseMgr.asmx"                     = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\Global.asax"                            = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\RoleMgr.asmx"                           = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\TemplateMgr.asmx"                       = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\admin\web.config"                             = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\certification.asmx"             = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\global.asax"                    = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\MacCertification.asmx"          = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\MobileDeviceCertification.asmx" = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\Precertification.asmx"          = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\server.asmx"                    = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\ServerCertification.asmx"       = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\ServiceLocator.asmx"            = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\certification\web.config"                     = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\decommission\decommission.asmx"               = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\decommission\global.asax"                     = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\decommission\web.config"                      = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\groupexpansion\global.asax"                   = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\groupexpansion\GroupExpansion.asmx"           = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\groupexpansion\web.config"                    = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\editissuancelicense.asmx"           = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\global.asax"                        = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\license.asmx"                       = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\publish.asmx"                       = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\server.asmx"                        = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\ServiceLocator.asmx"                = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\TemplateDistribution.asmx"          = $true; `
        "$env:SystemDrive\inetpub\wwwroot\_wmcs\licensing\web.config"                         = $true;
}

$VALID_VERSIONS = @{ `
        # E19
        '15.2.858.5'   = $true; `
        '15.2.792.5'   = $true; `
        '15.2.792.3'   = $true; `
        '15.2.721.13'  = $true; `
        '15.2.792.10'  = $true; `
        '15.2.721.8'   = $true; `
        '15.2.721.6'   = $true; `
        '15.2.721.4'   = $true; `
        '15.2.721.3'   = $true; `
        '15.2.721.2'   = $true; `
        '15.2.659.11'  = $true; `
        '15.2.659.8'   = $true; `
        '15.2.659.7'   = $true; `
        '15.2.659.6'   = $true; `
        '15.2.659.4'   = $true; `
        '15.2.595.6'   = $true; `
        '15.2.595.3'   = $true; `
        '15.2.529.11'  = $true; `
        '15.2.529.8'   = $true; `
        '15.2.529.5'   = $true; `
        '15.2.464.5'   = $true; `
        '15.2.397.3'   = $true; `
        '15.2.330.5'   = $true; `
        '15.2.221.12'  = $true; `
        '15.2.196.0'   = $true; `

    #E16
    '15.1.2242.4'      = $true; `
        '15.1.2176.9'  = $true; `
        '15.1.2176.4'  = $true; `
        '15.1.2176.2'  = $true; `
        '15.1.2106.13' = $true; `
        '15.1.2106.8'  = $true; `
        '15.1.2106.6'  = $true; `
        '15.1.2106.4'  = $true; `
        '15.1.2106.3'  = $true; `
        '15.1.2106.2'  = $true; `
        '15.1.2044.12' = $true; `
        '15.1.2044.8'  = $true; `
        '15.1.2044.7'  = $true; `
        '15.1.2044.6'  = $true; `
        '15.1.2044.4'  = $true; `
        '15.1.1979.6'  = $true; `
        '15.1.1979.3'  = $true; `
        '15.1.1913.10' = $true; `
        '15.1.1913.7'  = $true; `
        '15.1.1913.5'  = $true; `
        '15.1.1847.10' = $true; `
        '15.1.1847.7'  = $true; `
        '15.1.1847.5'  = $true; `
        '15.1.1847.3'  = $true; `
        '15.1.1779.2'  = $true; `
        '15.1.1713.5'  = $true; `
        '15.1.1591.17' = $true; `
        '15.1.1591.16' = $true; `
        '15.1.1591.10' = $true; `
        '15.1.1591.8'  = $true; `
        '15.1.1531.10' = $true; `
        '15.1.1531.7'  = $true; `
        '15.1.1531.6'  = $true; `
        '15.1.1531.4'  = $true; `
        '15.1.1531.3'  = $true; `
        '15.1.1466.8'  = $true; `
        '15.1.1466.3'  = $true; `
        '15.1.1415.2'  = $true; `
        '15.1.1261.35' = $true; `
        '15.1.1034.33' = $true; `
        '15.1.1034.26' = $true; `
        '15.1.845.34'  = $true; `
        '15.1.669.32'  = $true; `
        '15.1.544.27'  = $true; `
        '15.1.466.34'  = $true; `
        '15.1.396.30'  = $true; `
        '15.1.225.42'  = $true; `
        '15.1.225.16'  = $true; `

    #E13
    '15.0.1497.12'     = $true; `
        '15.0.1497.10' = $true; `
        '15.0.1497.8'  = $true; `
        '15.0.1497.7'  = $true; `
        '15.0.1497.6'  = $true; `
        '15.0.1497.4'  = $true; `
        '15.0.1497.3'  = $true; `
        '15.0.1497.2'  = $true; `
        '15.0.1497.0'  = $true; `
        '15.0.1473.5'  = $true; `
        '15.0.1473.4'  = $true; `
        '15.0.1473.3'  = $true; `
        '15.0.1395.10' = $true; `
        '15.0.1395.8'  = $true; `
        '15.0.1395.7'  = $true; `
        '15.0.1395.6'  = $true; `
        '15.0.1395.4'  = $true; `
        '15.0.1367.9'  = $true; `
        '15.0.1367.6'  = $true; `
        '15.0.1367.3'  = $true; `
        '15.0.1365.7'  = $true; `
        '15.0.1365.1'  = $true; `
        '15.0.1347.5'  = $true; `
        '15.0.1347.4'  = $true; `
        '15.0.1347.3'  = $true; `
        '15.0.1347.2'  = $true; `
        '15.0.1347.0'  = $true; `
        '15.0.1320.4'  = $true; `
        '15.0.1293.2'  = $true; `
        '15.0.1263.5'  = $true; `
        '15.0.1236.6'  = $true; `
        '15.0.1236.3'  = $true; `
        '15.0.1210.3'  = $true; `
        '15.0.1178.4'  = $true; `
        '15.0.1156.6'  = $true; `
        '15.0.1130.10' = $true; `
        '15.0.1130.7'  = $true; `
        '15.0.1104.5'  = $true; `
        '15.0.1076.9'  = $true; `
        '15.0.1044.25' = $true; `
        '15.0.995.32'  = $true; `
        '15.0.995.29'  = $true; `
        '15.0.995.28'  = $true; `
        '15.0.913.22'  = $true; `
        '15.0.847.32'  = $true; `
        '15.0.775.38'  = $true; `
        '15.0.712.24'  = $true; `
        '15.0.712.23'  = $true; `
        '15.0.620.29'  = $true; `
        '15.0.516.32'  = $true; `
        '15.0.516.30'  = $true; `

    #E10
    '14.3.513.0'       = $true; `
        '14.3.509.0'   = $true; `
        '14.3.496.0'   = $true; `
        '14.3.468.0'   = $true; `
        '14.3.461.1'   = $true; `
        '14.3.452.0'   = $true; `
        '14.3.442.0'   = $true; `
        '14.3.435.0'   = $true; `
        '14.3.419.0'   = $true; `
        '14.3.417.1'   = $true; `
        '14.3.411.0'   = $true; `
        '14.3.399.2'   = $true; `
        '14.3.389.1'   = $true; `
        '14.3.382.0'   = $true; `
        '14.3.361.1'   = $true; `
        '14.3.352.0'   = $true; `
        '14.3.336.0'   = $true; `
        '14.3.319.2'   = $true; `
        '14.3.301.0'   = $true; `
        '14.3.294.0'   = $true; `
        '14.3.279.2'   = $true; `
        '14.3.266.2'   = $true; `
        '14.3.248.2'   = $true; `
        '14.3.235.1'   = $true; `
        '14.3.224.2'   = $true; `
        '14.3.224.1'   = $true; `
        '14.3.210.2'   = $true; `
        '14.3.195.1'   = $true; `
        '14.3.181.6'   = $true; `
        '14.3.174.1'   = $true; `
        '14.3.169.1'   = $true; `
        '14.3.158.1'   = $true; `
        '14.3.146.0'   = $true; `
        '14.3.123.4'   = $true; `

}

$MARK_AS_SUSPICIOUS_FROM = (Get-Date -Year "2020" -Month "12" -Day "01")

function PerformComparison {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseUsingScopeModifierInNewRunspaces', '', Justification = 'Incorrect rule result')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '', Justification = 'Incorrect rule result')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Incorrect rule result')]
    param (
        [Parameter()]
        $baselineData,

        [Parameter()]
        $pattern,

        [Parameter()]
        $baseExoVer
    )

    Write-Host "BaselineData - $($baselineData.Keys) $baseExoVer"
    $result = @{}
    $vdirBatches = GetVdirBatches
    $errFound = $false
    $vdirBatches.Keys | Sort-Object | ForEach-Object {
        $vdirs = $vdirBatches[$_]
        $jobs = @()
        Write-Host "Processing $($vdirs.Count) directories in parallel. Batch $($_ + 1) of $($vdirBatches.Count) batches."
        $vdirs | ForEach-Object {
            $j = Start-Job -ScriptBlock {
                param ($baselines, $pattern, $l, $known_bad, $KNOWN_ROOT_FILES, $mark_as_suspicious_from)
                $vdirErrors = @()
                $pdirErrors = @()
                $fErrors = @()
                $errHappend = $false

                $l -match $pattern | Out-Null;
                $vdir = $Matches[2];
                $pdir = $Matches[3]
                $pdir = $pdir -replace "%SystemDrive%", $env:SystemDrive
                $pdir = $pdir -replace "%windir%", $env:windir
                $sha256 = New-Object -TypeName System.Security.Cryptography.SHA256CryptoServiceProvider

                function GetFileHash([string] $filePath) {
                    $hash = ""
                    try {
                        $hash = [System.BitConverter]::ToString($sha256.ComputeHash([System.IO.File]::ReadAllBytes($filePath))).Replace('-', '')
                    } catch {
                        return ""
                    }

                    return $hash
                }

                $datetime_format = "MM/dd/yyyy HH:mm:ss"
                $isWWWRoot = $false

                if ($pdir.StartsWith("$env:SystemDrive\inetpub\wwwroot")) {
                    $isWWWRoot = $true
                    $inetpub_files = (Get-ChildItem -Recurse -Path $pdir -File -Exclude *aspx, *asmx, *asax, *js, *css, *htm, *html)
                    foreach ($f in $inetpub_files) {

                        $hash = GetFileHash $f.FullName
                        if ([string]::IsNullOrEmpty($hash)) {
                            $newError = New-Object PSObject -Property @{
                                VDir              = $vdir
                                PDir              = $pdir
                                FileName          = $f.Name
                                FilePath          = $f.FullName
                                FileHash          = ""
                                CreationTimeUtc   = $f.CreationTimeUtc
                                LastWriteTimeUtc  = $f.LastWriteTimeUtc
                                LastAccessTimeUtc = $f.LastAccessTimeUtc
                                Error             = "ReadError"
                            }
                            $fErrors += $newError;
                            $errHappend = $true
                        } else {
                            if ($mark_as_suspicious_from -le $f.LastWriteTimeUtc) {
                                $newError = New-Object PSObject -Property @{
                                    VDir              = $vdir
                                    PDir              = $pdir
                                    FileName          = $f.Name
                                    FilePath          = $f.FullName
                                    FileHash          = $hash
                                    CreationTimeUtc   = $f.CreationTimeUtc
                                    LastWriteTimeUtc  = $f.LastWriteTimeUtc
                                    LastAccessTimeUtc = $f.LastAccessTimeUtc
                                    Error             = "Suspicious"
                                }
                                $fErrors += $newError;
                                $errHappend = $true
                            }
                        }
                    }
                }

                foreach ($f in (Get-ChildItem -Recurse -Path $pdir -File -Include *aspx, *asmx, *asax, *js, *css, *htm, *html)) {
                    $hash = GetFileHash $f.FullName
                    if ([string]::IsNullOrEmpty($hash)) {
                        $newError = New-Object PSObject -Property @{
                            VDir              = $vdir
                            PDir              = $pdir
                            FileName          = $f.Name
                            FilePath          = $f.FullName
                            FileHash          = ""
                            CreationTimeUtc   = $f.CreationTimeUtc
                            LastWriteTimeUtc  = $f.LastWriteTimeUtc
                            LastAccessTimeUtc = $f.LastAccessTimeUtc
                            Error             = "ReadError"
                        }
                        $fErrors += $newError;
                        $errHappend = $true
                    }

                    if ($isWWWRoot -eq $true) {
                        if ($mark_as_suspicious_from -le $f.LastWriteTimeUtc) {
                            $newError = New-Object PSObject -Property @{
                                VDir              = $vdir
                                PDir              = $pdir
                                FileName          = $f.Name
                                FilePath          = $f.FullName
                                FileHash          = $hash
                                CreationTimeUtc   = $f.CreationTimeUtc
                                LastWriteTimeUtc  = $f.LastWriteTimeUtc
                                LastAccessTimeUtc = $f.LastAccessTimeUtc
                                Error             = "Suspicious"
                            }
                            $fErrors += $newError;
                            $errHappend = $true
                        } else {
                            if ($KNOWN_ROOT_FILES[$f.FullName]) {
                                continue;
                            }
                        }
                    }

                    if ($hash) {
                        if ($known_bad[$hash]) {
                            $newError = New-Object PSObject -Property @{
                                VDir              = $vdir
                                PDir              = $pdir
                                FileName          = $f.Name
                                FilePath          = $f.FullName
                                FileHash          = $hash
                                CreationTimeUtc   = $f.CreationTimeUtc
                                LastWriteTimeUtc  = $f.LastWriteTimeUtc
                                LastAccessTimeUtc = $f.LastAccessTimeUtc
                                Error             = "KnownBadHash"
                            }
                            $fErrors += $newError;
                            $errHappend = $true
                        }

                        $found = $false
                        foreach ($key in $baselines.Keys) {
                            if ([string]::IsNullOrEmpty($key)) {
                                continue;
                            }

                            if ($baselines[$key] -and [string]::IsNullOrEmpty($baselines[$key][$hash]) -ne $true) {
                                $found = $true
                                break;
                            }
                        }

                        if ($found -eq $false) {
                            if ($f.Name.EndsWith(".strings.localized.js") -eq $false) {
                                $newError = New-Object PSObject -Property @{
                                    VDir              = $vdir
                                    PDir              = $pdir
                                    FileName          = $f.Name
                                    FilePath          = $f.FullName
                                    FileHash          = $hash
                                    CreationTimeUtc   = $f.CreationTimeUtc
                                    LastWriteTimeUtc  = $f.LastWriteTimeUtc
                                    LastAccessTimeUtc = $f.LastAccessTimeUtc
                                    Error             = "NoHashMatch"
                                }
                                $fErrors += $newError;
                                $errHappend = $true
                            }
                        }
                    }
                }

                if ($errHappend -eq $false) {
                    return $null
                }

                return New-Object PSObject -Property @{
                    VDir       = $vdir
                    PDir       = $pdir
                    VDirErrors = $vdirErrors
                    PDirErrors = $pdirErrors
                    FileErrors = $fErrors
                }
            } -ArgumentList $baselineData, $pattern, $_, $KNOWN_BAD_HASH, $KNOWN_ROOT_FILES, $MARK_AS_SUSPICIOUS_FROM

            $jobs += $j
        }

        foreach ($job in $jobs) {
            $job | Wait-Job | Out-Null
            $res = Receive-Job $job.ID
            if ($res) {
                $errFound = $true
                $result[$res.VDir] = $res
            }
        }
    }

    return $result, $errFound
}

function Main() {
    [CmdletBinding()]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPositionalParameters', '', Justification = 'Just getting this working for now. Will revisit.')]
    param([bool]$CompressSuspiciousAndMissingFilesToCSV = $false)

    Write-Host "[$(Get-Date)] Started..." -ForegroundColor Green
    $exchVersion, $installedVers = FindInstalledVersions # Get-ExchangeVersion

    Write-Host "Found exchange version: $exchVersion" -ForegroundColor Green
    $pattern = New-Object System.Text.RegularExpressions.Regex -ArgumentList '(.+)\s+\"(.+)\"\s+\(physicalPath:(.+)\)'
    $baselineData = LoadBaseline $installedVers

    $result, $errFound = PerformComparison $baselineData $pattern $exchVersion
    Write-Host "Comparison complete. Writing results."
    WriteScriptResult $result $exchVersion $errFound $CompressSuspiciousAndMissingFilesToCSV
}

function LoadFromGitHub($url, $filename, $installed_versions) {
    Write-Host "Downloading baseline file from GitHub to $filename"

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        # this file is only used for network connectivity test
        Invoke-WebRequest -Uri "https://github.com/microsoft/CSS-Exchange/releases/latest/download/baseline_15.0.1044.25.checksum.txt" | Out-Null
    } catch {
        Write-Error "Cannot reach out to https://github.com/microsoft/CSS-Exchange/releases/latest, please download baseline files for $installed_versions from https://github.com/microsoft/CSS-Exchange/releases/latest manually to $(GetCurrDir), then rerun this script from $(GetCurrDir)."
    }

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $filename | Out-Null
    } catch {
        Write-Error "$filename not found... please open issue on https://github.com/microsoft/CSS-Exchange/issues, we will work on it"
    }
}

function PreProcessBaseline($baselines) {
    $data = @{}
    foreach ($baseline in $baselines) {
        # each baseline contains csv data corresponding the a version
        $baseline | ForEach-Object {
            $sp = $_.Split(',');

            if (-not $data[$sp[1]]) {
                $data[$sp[1]] = @{}
            }

            # only one hash should be found for the same file in a version.
            $data[$sp[1]][$sp[0]] = $sp[2]
        }
    }

    return $data
}

function FindInstalledVersions() {
    $VDIR_PATTERN = New-Object System.Text.RegularExpressions.Regex -ArgumentList  '(.+)\s+\"(.+)\"\s+\(physicalPath:(.+)\)'

    $versions = @{}

    Add-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.E2010" -ErrorAction SilentlyContinue
    $server = (Get-ExchangeServer) | Where-Object { $_.Identity.Name -eq (hostname) }
    if ($server.AdminDisplayVersion.Major -eq 14) {
        $exchange_version = (Get-Command ExSetup | ForEach-Object { $_.FileVersionInfo }).ProductVersion
    } else {
        $exchange_version = "$($server.AdminDisplayVersion.Major).$($server.AdminDisplayVersion.Minor).$($server.AdminDisplayVersion.Build).$($server.AdminDisplayVersion.Revision)"
    }

    Remove-PSSnapin -Name "Microsoft.Exchange.Management.PowerShell.E2010" -ErrorAction SilentlyContinue

    $versions[$exchange_version] = $true
    $vdir_paths = @()
    $logs = & (Join-Path $env:Windir "system32\inetsrv\appcmd.exe") LIST VDIRS | Sort-Object

    foreach ($log in $logs) {
        $log -match $VDIR_PATTERN | Out-Null;
        $vdir_physical_path = $Matches[3]
        $vdir_physical_path = $vdir_physical_path -replace "%SystemDrive%", $env:SystemDrive
        $vdir_physical_path = $vdir_physical_path -replace "%windir%", $env:windir

        # note: some vdirs share same physical paths
        $vdir_paths += $vdir_physical_path
    }

    $vdir_paths | Where-Object { Test-Path $_ } | ForEach-Object { Get-ChildItem -Directory -Path $_ -Recurse } | Where-Object { $VALID_VERSIONS[$_.Name] -eq $true } | ForEach-Object { $versions[$_.Name] = $true }

    return $exchange_version, $versions.Keys
}

function GetVdirBatches {
    $grps = @{}
    $i = 0
    $batchSize = 10
    $logs = & (Join-Path $env:Windir "system32\inetsrv\appcmd.exe") LIST VDIRS

    $logs | ForEach-Object {
        $bt = $i % $batchSize
        $grps[$bt] += @($_)
        $i++
    }

    return $grps
}

function LoadBaseline($installed_versions) {
    $data = @{}
    foreach ($version in $installed_versions) {
        $filename = "baseline_$version"
        $zip_file_name = "${filename}.zip"
        $filename = (Join-Path (GetCurrDir) $filename)
        $zip_file = "${filename}.zip"

        if (-not (Test-Path $zip_file)) {
            Write-Host "Can't find local baseline for $version"
            $zip_file_url = "https://github.com/microsoft/CSS-Exchange/releases/latest/download/$zip_file_name"
            LoadFromGitHub -url $zip_file_url -filename $zip_file -installed_versions $installed_versions
        }

        if (Get-Command Expand-Archive -EA SilentlyContinue) {
            Expand-Archive -Path $zip_file -DestinationPath $filename -Force | Out-Null
        } else {
            [Reflection.Assembly]::LoadWithPartialName( "System.IO.Compression.FileSystem" ) | Out-Null
            if (Test-Path  $filename) {
                Remove-Item $filename -Confirm:$false -Force -Recurse
            }

            [System.IO.Compression.ZipFile]::ExtractToDirectory($zip_file, $filename) | Out-Null
        }

        $csv_file = Get-ChildItem $filename | Select-Object -First 1 | Select-Object FullName
        $baselines = Get-Content $csv_file.FullName
        $processed_baselines = PreProcessBaseline $baselines

        foreach ($k in $processed_baselines.Keys) {
            Write-Host "Loaded baseline for $k, hashes number $($processed_baselines[$k].Count)"
            $data[$k] = $processed_baselines[$k]
        }
    }

    return $data
}

function RemoveExistingItem($filepath) {
    if (Test-Path  $filepath) {
        Remove-Item $filepath -Confirm:$false -Force -Recurse | Out-Null
    }
}


function WriteScriptResult ($result, $exchVersion, $errFound, $CompressSuspiciousAndMissingFilesToCSV) {
    $tmp_file = Join-Path (GetCurrDir) ($exchVersion + "_" + "result.csv")

    $idx_suspicious = 0
    $suspicious_dir = Join-Path (GetCurrDir) ($exchVersion + "_" + "suspicious")
    if ($CompressSuspiciousAndMissingFilesToCSV -eq $true) {
        RemoveExistingItem $suspicious_dir
        RemoveExistingItem ($suspicious_dir + ".zip")
        mkdir $suspicious_dir | Out-Null
    }

    $resData = @(
        $result.Keys | ForEach-Object {
            $currentResult = $result[$_]
            foreach ($fileError in $currentResult.FileErrors) {
                if ($CompressSuspiciousAndMissingFilesToCSV -eq $true -and (([string]$fileError.Error -eq "NoHashMatch") -or ([string]$fileError.Error -eq "Suspicious"))) {
                    $target_path = (Join-Path $suspicious_dir "${idx_suspicious}_$($fileError.FileName)")
                    Copy-Item $fileError.FilePath $target_path | Out-Null
                    $idx_suspicious += 1
                }

                New-Object PsObject -Property @{
                    'FileName'          = $fileError.FileName
                    'VDir'              = $fileError.VDir
                    'Error'             = [string]$fileError.Error
                    'FilePath'          = [string]$fileError.FilePath
                    'FileHash'          = [string]$fileError.FileHash
                    'CreationTimeUtc'   = [string]$fileError.CreationTimeUtc
                    'LastWriteTimeUtc'  = [string]$fileError.LastWriteTimeUtc
                    'LastAccessTimeUtc' = [string]$fileError.LastAccessTimeUtc
                    'PDir'              = [string]$fileError.PDir
                }
            }
        }
    )

    Write-Host "Exporting ${resData.Count} objects to results"
    $resData | Select-Object | Export-Csv -Path $tmp_file -NoTypeInformation;

    if ($CompressSuspiciousAndMissingFilesToCSV -eq $true) {
        Write-Host "Zipping NoHashMatch and Suspicious files into ${suspicious_dir}.zip"

        if ($tmp_file -gt 5mb) {
            [Reflection.Assembly]::LoadWithPartialName( "System.IO.Compression.FileSystem" ) | Out-Null
            [System.IO.Compression.ZipFile]::CreateFromDirectory($suspicious_dir, "${suspicious_dir}.zip") | Out-Null
        } else {
            Write-Warning "Diff size larger than 5MB, please submit script issue on https://github.com/microsoft/CSS-Exchange/issues"
        }

        Write-Host "Zipped ${suspicious_dir}.zip"
    }

    $fgCol = 'Green'
    $msg = "[$(Get-Date)] Done."
    if ($errFound -eq $true) {
        $fgCol = 'Red'
        $msg += ' One or more potentially malicious files found, please inspect the result file.'
        $msg += " ExchangeVersion: $exchVersion"
        $msg += " OSVersion: $([environment]::OSVersion.Version)"
        $msg += " ScriptVersion: $BuildVersion"
        $report_msg = @"
        Submitting files for analysis:
        Please submit the output file for analysis in the malware analysis portal
        in the link below. Please add the text 'ExchangeMarchCVE' in
        'Additional Information' field on the portal submission form.
        https://www.microsoft.com/en-us/wdsi/filesubmission
        Instructions on how to use the portal can be found here:
        https://docs.microsoft.com/en-us/windows/security/threat-protection/intelligence/submission-guide
"@

        Write-Host $report_msg
    }

    Write-Host "Exported results to $tmp_file"
    Write-Host $msg -ForegroundColor $fgCol
}

function GetCurrDir {
    if ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
        return $MyInvocation.MyCommand.Path
    }

    return Get-Location
}

Main $CompressSuspiciousAndMissingFilesToCSV

# SIG # Begin signature block
# MIIjtwYJKoZIhvcNAQcCoIIjqDCCI6QCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCBrsqFpvyiZ80Tc
# lLxikhevECrVbh0akvoUllu+fqKswKCCDYEwggX/MIID56ADAgECAhMzAAAB32vw
# LpKnSrTQAAAAAAHfMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMjAxMjE1MjEzMTQ1WhcNMjExMjAyMjEzMTQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQC2uxlZEACjqfHkuFyoCwfL25ofI9DZWKt4wEj3JBQ48GPt1UsDv834CcoUUPMn
# s/6CtPoaQ4Thy/kbOOg/zJAnrJeiMQqRe2Lsdb/NSI2gXXX9lad1/yPUDOXo4GNw
# PjXq1JZi+HZV91bUr6ZjzePj1g+bepsqd/HC1XScj0fT3aAxLRykJSzExEBmU9eS
# yuOwUuq+CriudQtWGMdJU650v/KmzfM46Y6lo/MCnnpvz3zEL7PMdUdwqj/nYhGG
# 3UVILxX7tAdMbz7LN+6WOIpT1A41rwaoOVnv+8Ua94HwhjZmu1S73yeV7RZZNxoh
# EegJi9YYssXa7UZUUkCCA+KnAgMBAAGjggF+MIIBejAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUOPbML8IdkNGtCfMmVPtvI6VZ8+Mw
# UAYDVR0RBEkwR6RFMEMxKTAnBgNVBAsTIE1pY3Jvc29mdCBPcGVyYXRpb25zIFB1
# ZXJ0byBSaWNvMRYwFAYDVQQFEw0yMzAwMTIrNDYzMDA5MB8GA1UdIwQYMBaAFEhu
# ZOVQBdOCqhc3NyK1bajKdQKVMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2lvcHMvY3JsL01pY0NvZFNpZ1BDQTIwMTFfMjAxMS0w
# Ny0wOC5jcmwwYQYIKwYBBQUHAQEEVTBTMFEGCCsGAQUFBzAChkVodHRwOi8vd3d3
# Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NlcnRzL01pY0NvZFNpZ1BDQTIwMTFfMjAx
# MS0wNy0wOC5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAgEAnnqH
# tDyYUFaVAkvAK0eqq6nhoL95SZQu3RnpZ7tdQ89QR3++7A+4hrr7V4xxmkB5BObS
# 0YK+MALE02atjwWgPdpYQ68WdLGroJZHkbZdgERG+7tETFl3aKF4KpoSaGOskZXp
# TPnCaMo2PXoAMVMGpsQEQswimZq3IQ3nRQfBlJ0PoMMcN/+Pks8ZTL1BoPYsJpok
# t6cql59q6CypZYIwgyJ892HpttybHKg1ZtQLUlSXccRMlugPgEcNZJagPEgPYni4
# b11snjRAgf0dyQ0zI9aLXqTxWUU5pCIFiPT0b2wsxzRqCtyGqpkGM8P9GazO8eao
# mVItCYBcJSByBx/pS0cSYwBBHAZxJODUqxSXoSGDvmTfqUJXntnWkL4okok1FiCD
# Z4jpyXOQunb6egIXvkgQ7jb2uO26Ow0m8RwleDvhOMrnHsupiOPbozKroSa6paFt
# VSh89abUSooR8QdZciemmoFhcWkEwFg4spzvYNP4nIs193261WyTaRMZoceGun7G
# CT2Rl653uUj+F+g94c63AhzSq4khdL4HlFIP2ePv29smfUnHtGq6yYFDLnT0q/Y+
# Di3jwloF8EWkkHRtSuXlFUbTmwr/lDDgbpZiKhLS7CBTDj32I0L5i532+uHczw82
# oZDmYmYmIUSMbZOgS65h797rj5JJ6OkeEUJoAVwwggd6MIIFYqADAgECAgphDpDS
# AAAAAAADMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0
# ZSBBdXRob3JpdHkgMjAxMTAeFw0xMTA3MDgyMDU5MDlaFw0yNjA3MDgyMTA5MDla
# MH4xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMT
# H01pY3Jvc29mdCBDb2RlIFNpZ25pbmcgUENBIDIwMTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQCr8PpyEBwurdhuqoIQTTS68rZYIZ9CGypr6VpQqrgG
# OBoESbp/wwwe3TdrxhLYC/A4wpkGsMg51QEUMULTiQ15ZId+lGAkbK+eSZzpaF7S
# 35tTsgosw6/ZqSuuegmv15ZZymAaBelmdugyUiYSL+erCFDPs0S3XdjELgN1q2jz
# y23zOlyhFvRGuuA4ZKxuZDV4pqBjDy3TQJP4494HDdVceaVJKecNvqATd76UPe/7
# 4ytaEB9NViiienLgEjq3SV7Y7e1DkYPZe7J7hhvZPrGMXeiJT4Qa8qEvWeSQOy2u
# M1jFtz7+MtOzAz2xsq+SOH7SnYAs9U5WkSE1JcM5bmR/U7qcD60ZI4TL9LoDho33
# X/DQUr+MlIe8wCF0JV8YKLbMJyg4JZg5SjbPfLGSrhwjp6lm7GEfauEoSZ1fiOIl
# XdMhSz5SxLVXPyQD8NF6Wy/VI+NwXQ9RRnez+ADhvKwCgl/bwBWzvRvUVUvnOaEP
# 6SNJvBi4RHxF5MHDcnrgcuck379GmcXvwhxX24ON7E1JMKerjt/sW5+v/N2wZuLB
# l4F77dbtS+dJKacTKKanfWeA5opieF+yL4TXV5xcv3coKPHtbcMojyyPQDdPweGF
# RInECUzF1KVDL3SV9274eCBYLBNdYJWaPk8zhNqwiBfenk70lrC8RqBsmNLg1oiM
# CwIDAQABo4IB7TCCAekwEAYJKwYBBAGCNxUBBAMCAQAwHQYDVR0OBBYEFEhuZOVQ
# BdOCqhc3NyK1bajKdQKVMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFHItOgIxkEO5FAVO
# 4eqnxzHRI4k0MFoGA1UdHwRTMFEwT6BNoEuGSWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcmwwXgYIKwYBBQUHAQEEUjBQME4GCCsGAQUFBzAChkJodHRwOi8vd3d3Lm1p
# Y3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dDIwMTFfMjAxMV8wM18y
# Mi5jcnQwgZ8GA1UdIASBlzCBlDCBkQYJKwYBBAGCNy4DMIGDMD8GCCsGAQUFBwIB
# FjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2RvY3MvcHJpbWFyeWNw
# cy5odG0wQAYIKwYBBQUHAgIwNB4yIB0ATABlAGcAYQBsAF8AcABvAGwAaQBjAHkA
# XwBzAHQAYQB0AGUAbQBlAG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAGfyhqWY
# 4FR5Gi7T2HRnIpsLlhHhY5KZQpZ90nkMkMFlXy4sPvjDctFtg/6+P+gKyju/R6mj
# 82nbY78iNaWXXWWEkH2LRlBV2AySfNIaSxzzPEKLUtCw/WvjPgcuKZvmPRul1LUd
# d5Q54ulkyUQ9eHoj8xN9ppB0g430yyYCRirCihC7pKkFDJvtaPpoLpWgKj8qa1hJ
# Yx8JaW5amJbkg/TAj/NGK978O9C9Ne9uJa7lryft0N3zDq+ZKJeYTQ49C/IIidYf
# wzIY4vDFLc5bnrRJOQrGCsLGra7lstnbFYhRRVg4MnEnGn+x9Cf43iw6IGmYslmJ
# aG5vp7d0w0AFBqYBKig+gj8TTWYLwLNN9eGPfxxvFX1Fp3blQCplo8NdUmKGwx1j
# NpeG39rz+PIWoZon4c2ll9DuXWNB41sHnIc+BncG0QaxdR8UvmFhtfDcxhsEvt9B
# xw4o7t5lL+yX9qFcltgA1qFGvVnzl6UJS0gQmYAf0AApxbGbpT9Fdx41xtKiop96
# eiL6SJUfq/tHI4D1nvi/a7dLl+LrdXga7Oo3mXkYS//WsyNodeav+vyL6wuA6mk7
# r/ww7QRMjt/fdW1jkT3RnVZOT7+AVyKheBEyIXrvQQqxP/uozKRdwaGIm1dxVk5I
# RcBCyZt2WwqASGv9eZ/BvW1taslScxMNelDNMYIVjDCCFYgCAQEwgZUwfjELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEoMCYGA1UEAxMfTWljcm9z
# b2Z0IENvZGUgU2lnbmluZyBQQ0EgMjAxMQITMwAAAd9r8C6Sp0q00AAAAAAB3zAN
# BglghkgBZQMEAgEFAKCBxjAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgb5jWxuJK
# CoVj3/ghX2V7nQbfQlu95XJ/lW5vcMOM8pEwWgYKKwYBBAGCNwIBDDFMMEqgGoAY
# AEMAUwBTACAARQB4AGMAaABhAG4AZwBloSyAKmh0dHBzOi8vZ2l0aHViLmNvbS9t
# aWNyb3NvZnQvQ1NTLUV4Y2hhbmdlIDANBgkqhkiG9w0BAQEFAASCAQBmO2HClftd
# ecxktVhhsdmjowgZjZ0Wus3BXImv2V2Bdt0dy4kSRssvCkxNLvGfcNjmljDnGO5t
# 6JNfm3ghzBV098nP3ruVlUsDSyE5nr06BrCzw3QuPQMzNaHqxWHM2ll8uJrkSVv2
# GvE0t77LI8Ju1T6to+Gq9oVIEhFDk8rKJqOp//iX07rhrkovWzGgyekwOdt8gm82
# JjB3fqxl9qs9+mtYnc1bekGGZchwYsbpGXWy5RiCZaOZDLMuZ2oaUi7PNiPyvlXl
# kjMI4mMQoyTxuyX1bkw0stbcepaJXbsyPuJkLVH82pB4ZGm5r2A4dGJOuOf/huAY
# KoEtfj/ACQxpoYIS/jCCEvoGCisGAQQBgjcDAwExghLqMIIS5gYJKoZIhvcNAQcC
# oIIS1zCCEtMCAQMxDzANBglghkgBZQMEAgEFADCCAVkGCyqGSIb3DQEJEAEEoIIB
# SASCAUQwggFAAgEBBgorBgEEAYRZCgMBMDEwDQYJYIZIAWUDBAIBBQAEIIatbSmt
# QmVHm0vQAKkPB5tWX0BRzNxTZuBpIiDaLRI0AgZgPTANLB4YEzIwMjEwMzExMDYz
# NTI5Ljc3M1owBIACAfSggdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RkM0MS00QkQ0LUQy
# MjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2Wggg5NMIIE
# +TCCA+GgAwIBAgITMwAAAUAjGdZe3pUkMQAAAAABQDANBgkqhkiG9w0BAQsFADB8
# MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVk
# bW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1N
# aWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDAeFw0yMDEwMTUxNzI4MjZaFw0y
# MjAxMTIxNzI4MjZaMIHSMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3Rv
# bjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0
# aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0
# ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkZDNDEtNEJENC1EMjIwMSUwIwYD
# VQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNlMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEArn1rM3Hq1S9N0z8R+YKqZu25ykk5OlT8TsuwtdBW
# yDCRFoASk9fB6siColFhXBhyej4c3yIwN0UyJWBOTAjHteOIYjfCpx539rbgBI5/
# BTHtC+qcBT7ftPknTtQn89lNOcpP70fuYVZLoQsDnLjGxxtW/eVewR5Q0I1mWQfJ
# y5xOfelk5OWjz3YV4HKtqyIRzJZd/RzcY8w6qmzoSNsYIdvliT2eeQZbyYTdJQsR
# ozIKTMLCJUBfVjow2fJMDtzDB9XEOdfhPWzvUOadYgqqh0lslAR7NV90FFmZgZWA
# RrG8j7ZnVnC5MOXOS/NI58S48ycsug0pN2NGLLk2YWjxCwIDAQABo4IBGzCCARcw
# HQYDVR0OBBYEFDVDHC4md0YgjozSqnVs+OeELQ5nMB8GA1UdIwQYMBaAFNVjOlyK
# MZDzQ3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWlj
# cm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3
# LTAxLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAtMDctMDEu
# Y3J0MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcN
# AQELBQADggEBAGMMUq2gQuCC9wr4YhISfPyobaNYV3Ov4YwWsSfIz/j1xaN9TvLA
# B2BxPi2CtRbgbBUf48n07yReZInwu2r8vwLoNG2TtYzey01DRyjjsNoiHF9UuRLF
# yKZChkKC3o9r0Oy2x0YYjUpDxVChZ5q5cAfw884wP0iUcYnKKGn8eJ0nwpr7zr/T
# lu+HOjXDT9C754aS4KUFNm8D7iwuvWWzSOVl7XMWdu82BnnTmB7s2Ocf3I4adGzd
# ixQ5Zxxa3zOAvKzrV+0HcVQIY3SQJ9PzjDRlzCviMThxA8FUIRL3FnYqvchWkEoZ
# 4w8S7FsGWNlXLWQ7fHMb3l4gjueHyO4p6tUwggZxMIIEWaADAgECAgphCYEqAAAA
# AAACMA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2Fz
# aGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENv
# cnBvcmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBB
# dXRob3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRt
# b25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1p
# Y3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/F
# w+Vhwna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC
# 3ZOs1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd
# 0WETbijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHR
# D5wGPmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9E
# uqf03GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIwEAYJKwYB
# BAGCNxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsG
# AQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTAD
# AQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0w
# S6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3Rz
# L01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYI
# KwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWlj
# Um9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsG
# AQQBgjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L1BLSS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUA
# ZwBhAGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkq
# hkiG9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpX
# bRkws8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2zEBAQZvc
# XBf/XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr
# 5MfO9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7Yl+a21dA
# 6fHOmWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt0uGc+R38
# ONiU9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2onGqBooP
# iRa6YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA3+cxB6ST
# OvdlR3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7G4kqVDmy
# W9rIDVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Kiyc8ZQU3g
# hvkqmqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9
# zOZN+w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P3nSISRKh
# ggLXMIICQAIBATCCAQChgdikgdUwgdIxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpX
# YXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQg
# Q29ycG9yYXRpb24xLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlv
# bnMgTGltaXRlZDEmMCQGA1UECxMdVGhhbGVzIFRTUyBFU046RkM0MS00QkQ0LUQy
# MjAxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1lLVN0YW1wIFNlcnZpY2WiIwoBATAH
# BgUrDgMCGgMVAEKl5h7yE6Y7MpfmMpEbQzkJclFToIGDMIGApH4wfDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0
# IFRpbWUtU3RhbXAgUENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDj9DRsMCIYDzIw
# MjEwMzExMTQxNzE2WhgPMjAyMTAzMTIxNDE3MTZaMHcwPQYKKwYBBAGEWQoEATEv
# MC0wCgIFAOP0NGwCAQAwCgIBAAICFNQCAf8wBwIBAAICE0IwCgIFAOP1hewCAQAw
# NgYKKwYBBAGEWQoEAjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgC
# AQACAwGGoDANBgkqhkiG9w0BAQUFAAOBgQAHCbOOlQZdrb4Ne0yHZD9HBVoibyDU
# Qt4K8G6vmMyq4w+rZ8c8AeHwPhyEMLR3PjVKVCUkSeWBOCOXkXobfx1WBGI7QX1X
# bzhJjmKp7cmzsf8bD7cCRKB1rd4OtvhWRTP8oOQqE1OLOfvYu7OMTzGTlw7nGxL3
# wdNNWuMWggLBMjGCAw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQI
# EwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3Nv
# ZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBD
# QSAyMDEwAhMzAAABQCMZ1l7elSQxAAAAAAFAMA0GCWCGSAFlAwQCAQUAoIIBSjAa
# BgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIITuEPti
# D+cINgm1WFqO4zya1crbXm3RFoCZ8UIe/wXxMIH6BgsqhkiG9w0BCRACLzGB6jCB
# 5zCB5DCBvQQgLzawterM0qRcJO/zcvJT7do/ycp8RZsRSTqqtgIIl4MwgZgwgYCk
# fjB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMH
# UmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQD
# Ex1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAAUAjGdZe3pUkMQAA
# AAABQDAiBCAM7cDmy/vbyJb5ouzdv+BUBwpQ5j67WEjrrpDJcTPANDANBgkqhkiG
# 9w0BAQsFAASCAQAtPSnEfy3el5e3E9+pcbZ56x4Z6XLbocf9asggGDKSxWv3ELe0
# WSoupPcj/bgflr0O/RiRS7P9F6yXwksjUbXY7nUVfuVesW2ZZI6vGSZHlfm9BwSl
# HEXcMAEWnGJpLrFxute2a9F3kR1viULK/6VqhKZgEPu8XjC6nKbllNsisVf/n3yY
# 5ZgHY81jQeKegWkaH+UfxNH10pHAJbNHoSYPAHOazcsAKhWdxV2dt3dA8456PqGu
# dtEdQ0AAiU6t2OnBjLls3wwKvx55+mPKe2iCU4x1hFBXptjBeqsn3VKpFHGiTTf5
# 3aT649aijPRo1he4bXIYIDuO9obzerhLQ0iy
# SIG # End signature block
