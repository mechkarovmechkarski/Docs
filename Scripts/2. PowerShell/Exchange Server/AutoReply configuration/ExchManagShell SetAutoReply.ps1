#		Start of configurations
$csvPath = "C:\temp\usersInGroupsExport.csv"
$StartDate = "04/10/2021 08:00:00" #Date Format = mm/dd/yyyy HH:MM:SS
$EndDate = "04/10/2023 23:59:59" #Date Format = mm/dd/yyyy HH:MM:SS
$NewDomain = "domain.bg"
$AutoReplyTextTemplate = "Dear Sender, Please be informed my email ID has been changed to {0}@{1}"
#		End of configurations


<#EXECUTE on Exchange management shell#>
$users = Import-Csv $csvPath

#		Get current AutoReply configuration
foreach($user in $users){
    Get-MailboxAutoReplyConfiguration -Identity $user.Name | Select Identity, AutoReplyState, StartTime, EndTime, InternalMessage, ExternalMessage
    }

#		Set AutoReply configuration
foreach($user in $users){
    $AutoReplyText = $AutoReplyTextTemplate -f $user.Name.ToLower(), $NewDomain.ToLower()
    Set-MailboxAutoReplyConfiguration -Identity $user.Name -AutoReplyState Scheduled -StartTime $StartDate -EndTime $EndDate -InternalMessage $AutoReplyText -ExternalMessage $AutoReplyText
    }