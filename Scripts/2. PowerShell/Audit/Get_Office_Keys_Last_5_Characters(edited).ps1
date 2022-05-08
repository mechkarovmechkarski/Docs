#version 2019.10.26
#
#
#Export last five characters from office key

#Get Paths for different office installations
$Office2013_32 = 'C:\Program Files (x86)\Microsoft Office\Office15\'
$Office2013_64 = 'C:\Program Files\Microsoft Office\Office15\'
$Office2016_64 = 'C:\Program Files\Microsoft Office\Office16\'
$Office2016_32 = 'C:\Program Files (x86)\Microsoft Office\Office16\'

#Computer name will be the name of the key file
New-PSDrive -Name P -PSProvider FileSystem -Root "\\SABEV-DC-03\office_keys" -Credential user.test
$KeysFileName = $env:computername + ".txt"

$exist = $false
$exist = Test-Path -Path $Office2013_32
If($exist)
{
#    $OSPPcommand = $Office2013_32 + "OSPP.VBS"
#    cmd /c @"
&    cscript 'C:\Program Files (x86)\Microsoft Office\Office15\OSPP.VBS' /dstatus | Out-File -FilePath P:\$KeysFileName
#"@ | Out-File -FilePath $KeysFilePath -Append
    Exit
}

$exist = Test-Path -Path $Office2013_64
If($exist)
{
#    $OSPPcommand = $Office2013_64 + "OSPP.VBS"
#    cmd /c @"
&    cscript 'C:\Program Files\Microsoft Office\Office15\OSPP.VBS' /dstatus | Out-File -FilePath P:\$KeysFileName
#"@ | Out-File -FilePath $KeysFilePath -Append
    Exit
}

$exist = Test-Path -Path $Office2016_64
If($exist)
{
#    $OSPPcommand = $Office2016_64 + "OSPP.VBS"
#    cmd /c @"
&    cscript 'C:\Program Files\Microsoft Office\Office16\OSPP.VBS' /dstatus | Out-File -FilePath P:\$KeysFileName
#"@ | Out-File -FilePath $KeysFilePath -Append
    Exit
}

$exist = Test-path -Path $Office2016_32
If($exist)
{
# cmd /c @"
& cscript "C:\Program Files (x86)\Microsoft Office\Office16\OSPP.VBS" /dstatus | Out-File -FilePath P:\$KeysFileName
#"@ | Out-File -FilePath $KeysFilePath -Append
    Exit
}