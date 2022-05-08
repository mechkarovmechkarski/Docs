#		Start of conifgurations
$csvPath = "C:\temp\usersExport.csv"
$OUtoExport = "DC=domain,DC=com"
#		End of configurations


<#
	EXECUTE on powershell
	#>
#		OPTION 1 : Export one user
Get-ADUser user.test -Properties * | Select-Object name | Export-Csv -Path $csvPath -NoTypeInformation
#		OPTION 2 : Export users from OU or All
Get-ADUser -Filter * -SearchBase $OUtoExport -Properties * | Select-Object name, mail, enabled | export-csv -path $csvPath -NoTypeInformation
#		OPTION 3 : Export users from AD Group
Get-ADGroupMember -Identity "trainers" | select name, mail, enabled | Export-Csv -Path $csvPath -NoTypeInformation
#       OPTION 4 : Export users with name and email from domain
Get-ADuser –filter 'enabled -eq $true' -property * | Select-object Name, mail, enabled | export-csv -path $csvPath -NoTypeInformation
