$ProgramFilesx86Folders = get-childitem -Path 'C:\Program Files (x86)\' -Name
$isJSignPDFInstalled = $false

foreach($folder in $ProgramFilesx86Folders){
    $JSignPDFFolder = 'JSignPdf'
    if ($folder -eq $JSignPDFFolder) {
        $isJSignPDFInstalled = $true
        break
    }
}

Write-Output $isJSignPDFInstalled