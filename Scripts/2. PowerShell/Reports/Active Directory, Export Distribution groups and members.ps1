function GetStringBetweenTwoStrings($firstString, $secondString, $sourcestring){
    #Regex pattern to compare two strings
    $pattern = "$firstString(.*?)$secondString"

    #Perform the opperation
    $result = [regex]::Match($sourcestring,$pattern).Groups[1].Value

    #Return result
    return $result
}

#Check if file already exist and delete it
$fileToCheck = "C:\Support\Scripts\Distribution groups and members.csv"
if (Test-Path $fileToCheck -PathType Leaf){
    Remove-Item $fileToCheck
}

#Get all groups
$groups = Get-ADGroup -Filter 'GroupCategory -eq "Distribution"' -SearchBase 'DC=domain,DC=local' -Properties members

#Get user membership for each group and write it to .csv file
foreach ($group in $groups) {
    $temp = $group.DistinguishedName
    $membergroup = GetStringBetweenTwoStrings -firstString "=" -secondString "," -sourcestring $temp

    $temp = $group.Members
    $firstString_1 = "CN="
    $secondString_1 = ","
    $pattern_1 = [Regex]::new("$firstString_1(.*?)$secondString_1")
    $matches = $pattern_1.Matches($temp)
    $memberusers = $matches.value.substring(3)
    
    foreach ($memberuser in $memberusers) {
        $memberuser = $memberuser.Substring(0,$memberuser.Length-1)
        $wrapper = New-Object PSObject -Property @{ Groups = $membergroup; Members = $memberuser}
        $wrapper | Select-Object Groups, Members | Export-Csv -Path "C:\Support\Scripts\Distribution groups and members.csv" -Append -NoTypeInformation
        #Export-Csv -InputObject $wrapper -Path "C:\temp\Distribution groups and members.csv" -Append -NoTypeInformation
    }
}