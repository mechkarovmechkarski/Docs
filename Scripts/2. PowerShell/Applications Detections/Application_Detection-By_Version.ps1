param
(
    [parameter(Mandatory=$true,HelpMessage="Write an application name to check in regex format.")]
    [ValidateNotNullOrEmpty()]
    [String]$chooseApplication,

    [parameter(Mandatory=$false,HelpMessage="Write an application Version to check in regex format.")]
    [String]$setVersion
)
#####Uses regex
#$chooseApplication = "Java 8"
#$setVersion = "^8[.]0[.]1"

$products = Get-CimInstance -Classname Win32_Product | where {($_.Name -Match $chooseApplication) -and ($_.Version -Match $setVersion)}

$ComputerName = hostname
if($products -eq $Null){
    Write-Host "Null"
    return
}

foreach($productname in $products){
    $AppName = $productname.Name
    $AppVersion = $productname.Version
    $productname
    Write-Host "$AppName - $AppVersion"
    }