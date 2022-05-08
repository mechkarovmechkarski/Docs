param
(
    [String]$setVersion
)
$chooseApplication = "Java 8"
#$setVersion = "^8[.]0[.]1"

$products = Get-CimInstance -Classname Win32_Product | where {($_.Name -Match $chooseApplication) -and ($_.Version -Match $setVersion)}

$ComputerName = hostname
if($products -eq $Null){
    Write-Host "Null"
    return
}

foreach($productname in $products){
    $AppName = $productname.Name
    Write-Host "$AppName"
    }
