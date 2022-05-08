$chooseApplication = "Java 8"
$setVersion = "^8[.]0[.]2"

$products = Get-CimInstance -Classname Win32_Product | where {($_.Name -Match $chooseApplication) -and ($_.Version -Match $setVersion)}

$ComputerName = hostname
if($products -eq $Null){
    Write-Host "Null"
    return
}

foreach($productname in $products){
    $AppName = $productname.Name
    Write-Host "Initiated uninst of $AppName"
    Start-Process -FilePath msiexec.exe -ArgumentList "/x",$productname.identifyingnumber,"/q","/norestart" -Wait
    }

$unsuccessfullUninstallations = Get-CimInstance -Classname Win32_Product | where {($_.Name -Match $chooseApplication) -and ($_.Version -Match $setVersion)}

foreach($productname in $unsuccessfullUninstallations){
    $AppName = $productname.Name
    $uninstallationAttempt = $false
    
    foreach($check in $products){
        $checkAppName = $check.Name
        if($AppName -eq $checkAppName){
                $uninstallationAttempt = $true
                break
        }
    }

    If($uninstallationAttempt){
        Write-Host "Success $AppName"
        }
    else{
        Write-Host "Unsuccess $AppName"
        }
    }