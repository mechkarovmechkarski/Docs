Get-ADGroup -filter * -SearchBase 'OU=Support,DC=domain,DC=local' -Properties * | Select-Object Name,GroupCategory,description | Export-Csv -Path C:\ADGroup_list.csv