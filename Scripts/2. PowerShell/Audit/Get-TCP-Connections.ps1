<#
.SYNOPSIS
Script that will log new TCP Connections, display to console & write to log file in csv or txt log file.
.DESCRIPTION
** Script that will log new incoming/outgoing TCP Connections between servers in specific duration or until the maximum log size is reached.
Example usage:																					  
.\Get-TcpLog.ps1 | ft
This will log the current & new incoming/outgoing TCP connections with the default duration of 10 minutes. The IncomingTCPConnection.log file
with timestamp will be written in the current directory. The output in table format will be output to console.
Author: phyoepaing3.142@gmail.com
Country: Myanmar(Burma)
Released: 08/27/2017
.EXAMPLE
.\Get-TcpLog.ps1 -hr 24 -LogSizeMB 100 | format-table
This will log  new incoming/outgoing TCP connections for 1 day or until the log file size reaches 100MB. The console output will be displayed in table format.
The TCPConnections.log file will be written under current directory.
.EXAMPLE
.\Get-TcpLog.ps1 -min 30 -CsvFile
This will log new incoming/outgoing TCP connections for next 30 minutes. The TCPConnections.csv file will be written current directory.
.PARAMETER hr
The number of hours to run the script.
.PARAMETER min
The number of minutes to run the script.
.PARAMETER sec
The number of seconds to run the script.
.PARAMETER LogSizeMB
Size of log file in MB allowed. When this size is reached, script is stopped.
.PARAMETER CsvFile
If defined, the logging output will be written as csv file.
.LINK
You can find this script and more at: https://www.sysadminplus.blogspot.com/
#>

param([switch]$CsvFile,[int]$hr=0,[int]$min=0,[int]$sec=0,[int]$LogSizeMB= 0 )

If ($hr -eq 0 -AND $min -eq 0 -AND $sec -eq 0) { $min = 10 }	## If the time is not specified,then run for 10 minutes
$LoopCount = ($hr * 3600 + $min * 60 + $sec) * 2	## Calculated based on 500ms per loop, change the number 2 to another value based on 1000ms/new-time-in-milliseconds formula

$ObjCollection = @(); 

### If the CsvFile Flag is not set and log file doesn't exist, create the file with headers ###
if (!(Test-path TCPConnections.log) -AND !($CsvFile))
	{
	Add-Content -Value " DateTime                LocalAddr           LPort       RemoteAddr        RPort      Process       File Path"  -Path  TCPConnections.log
	Add-Content  "-----------------       ------------      -----       ------------       ----       -------      -------------------------"   -Path TCPConnections.log
	}
$StartTime = Get-Date
Write-Host -fore yellow "TCP Logging started at $($StartTime.ToString())."

### The following line will loop the 'netstat' command, convert output into string type, covert into array, find the established connection, find process name/path and create object ###	
1..$($LoopCount) |   foreach { ((netstat -no | foreach { $_ }) -join "`n");   }   |   foreach {  
$_ -split "`n" | ? {  $_ -match "established" }  | foreach { 
 $SplitConn = $_.split('',[System.StringSplitOptions]::RemoveEmptyEntries); 
 $RemoteAddress = $SplitConn[2].Split(':'); 
 $LocalAddress= $SplitConn[1].Split(':') ; 
 $ProcID = $SplitConn[4]
 $Process = Get-Process -id $ProcID
 $ProcessName = $Process.Name
 $ProcessPath =  $Process.Path
 $obj = New-Object -TypeName PsObject -Property @{ DateTime="";Type= $SplitConn[0]; LocalAddr=$LocalAddress[0] ; RemoteAddr= $RemoteAddress[0]; LPort=$LocalAddress[1]; RPort =$RemoteAddress[1] ; Process = $ProcessName; FilePath = $ProcessPath } ; 
 $ObjCollection += $obj;	
 }   
 
$DuplicateFlag = 0;	## reset the duplicate flag

### Iterate the array of current connections  & Compare with the previous individual connections (stored in $LastObjCollection) ###
$ObjCollection | foreach { 
$CurConn = $_
$CurLocal = $_.LocalAddr
$CurRemote = $_.RemoteAddr
$CurLPort = $_.LPort
$CurRPort = $_.RPort

$LastObjCollection | foreach {
if ( $CurLocal -eq $_.LocalAddr -AND $CurRemote -eq $_.RemoteAddr -AND $CurLPort -eq $_.LPort -AND  $CurRPort -eq $_.RPort)
			{   $DuplicateFlag =1;		}	## set the Duplicate Flag to 1 when one duplicate is found. No need to compare current connection with other previous connections. Continue to next connection.
	}

If ($DuplicateFlag -eq 0)
	{
	$CurConn.DateTime = Get-date -Format ("MM/dd/yy HH:mm:ss")
	$CurConn  | select DateTime,LocalAddr,LPort,RemoteAddr,RPort,Process,FilePath 
	If ($CsvFile)
		{
			$CurConn  | select DateTime,LocalAddr,LPort,RemoteAddr,RPort,Process,FilePath | Export-CSV -NoType -Append  TCPConnections.csv
### If the log file size is larger than value defined in $LogSizeMB, then stop logging ###			
			If ($LogSizeMB -ne 0 -AND $i -eq 20) 
				{ 
					If ( (Gci TCPConnections.csv).Length / 1MB -gt $LogSizeMB)
					{  
					Write-Host -fore yellow "Maximun Log file size $LogSizeMB MB is reached. Logging is stopped."
					Exit;
					}
					$i =0;
				}
			$i++;
		}
	else 
		{
			Add-Content "$($CurConn.DateTime)       $($CurConn.LocalAddr)       $($CurConn.LPort)       $($CurConn.RemoteAddr)       $($CurConn.RPort)       $($CurConn.Process)       $($CurConn.FilePath)" -Path TCPConnections.log
### If the log file size is larger than value defined in $LogSizeMB, then stop logging ###
			If ($LogSizeMB -ne 0 -AND $i -eq 20) 
				{ 
					If ( (Gci TCPConnections.log).Length / 1MB -gt $LogSizeMB)
					{  
					Write-Host -fore yellow "Maximun Log file size $LogSizeMB MB is reached. Logging is stopped."
					Exit;
					}
					$i =0;
				}
			$i++;
		}	
	}
$DuplicateFlag = 0;	## After the current connection object is compared, then reset the Flag to 0.
}

$LastObjCollection = $ObjCollection;
$ObjCollection = @()

start-sleep -milliseconds 500;
}
$EndTime = Get-Date
Write-Host -fore yellow "TCP Logging finished at $($EndTime.ToString()). Time taken: $(($endtime - $starttime).ToString().split('.')[0])."
# SIG # Begin signature block
# MIIFdgYJKoZIhvcNAQcCoIIFZzCCBWMCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUE0VYYr9ic8U6fVjs1qdebJIO
# uJ6gggMOMIIDCjCCAfKgAwIBAgIQEduA4TyHkbpNjS3q7jOyJzANBgkqhkiG9w0B
# AQUFADAdMRswGQYDVQQDDBJMb2NhbCBDb2RlIFNpZ25pbmcwHhcNMTkxMjA4MDgw
# NDU1WhcNMjAxMjA4MDgyNDU1WjAdMRswGQYDVQQDDBJMb2NhbCBDb2RlIFNpZ25p
# bmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDjcyZ7XWj943mMrUtH
# ZdXBIRMMBed+ueUPqCduUWgciF0puzP9ymqIruEstCQOJw1G/PBDwxYg4fFJvQ7U
# /5pZR/wUpmmuXwoaiDU3H1zxEfx1VeQoTl7rmUZVT7O8tszRIQUEH5q2Eql8W3MF
# ZHeinIBlGZJkWTAePoYUQJgaGRTrV0U6BWaCFMSUWoP2Wh8x1AQBBMTbdkM2elaM
# ghXPNHznSxuvZrj2LA3dZDDUg/JAenhmKlqllbOwP9pOCyWXyQDhhXpdZmHGgqwt
# mQ9V7Ppxl0yMLIVHZYGn7d4e7grX6ILDNe84npNhsdx7ifuugHeD75oPSnhYkRLh
# rzJtAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcD
# AzAdBgNVHQ4EFgQUYNXK9CJ/3VMst+RPMLg1rnOS4HIwDQYJKoZIhvcNAQEFBQAD
# ggEBAE6GTsJZSDQG0TYPYaXLm6KVz7+wGNGUR+yGvxdh5bhPtZWUa+URXpLZqU4D
# Jx3O0JCIrQbqCjfWApgIiuFVoFPTOz2ozZRqggpjrL6PLRFw0/NgZ0drDDe4OS7c
# 5K+72ztqheQa2PZYLBAb/YdlwCJK4Vl6EsT+lWbeKGvcwLOOpgZQzhZpa3oy/E4E
# GFjoUSNIOJJAjM5P8mqlBDQbS6vPNsgcVnBVOxYsg7oInsmqaNzm338a+ZWlbCug
# Zr9ORCslJxS9O2bcj9KESuO6Q1ukdL+mpsxUnSl4GOnfTvpBF7Rw9yV8yw3Er1p9
# Bb7HXq7yNalg0xHusxXjdoFJQSgxggHSMIIBzgIBATAxMB0xGzAZBgNVBAMMEkxv
# Y2FsIENvZGUgU2lnbmluZwIQEduA4TyHkbpNjS3q7jOyJzAJBgUrDgMCGgUAoHgw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQx
# FgQUri9MBqS9QanhflKkDyr7LNiTPyQwDQYJKoZIhvcNAQEBBQAEggEARPD1tV7E
# MJ7IZFOKplsPxyvl6PDTIXlffUYUwXdqKtfLqlduthBnD9zFdwFzQ9StzcQ73+7j
# yWO39rGCUXixeedHKz6ZijBCwVwMqtTgC0sRkQk2Fw/7jBzlRNK9/CHPa9ECMYXD
# Qxm+cpTE/+0ZxewdJwf4pT8jPJZFqPJKnXljpqGb1xPXrBQGaPg4BRSB+9RM6iS3
# U7FpS4gn5KHQCu7hCo5i/3BsY+gL4+IGcpVbc9TJOM97V28Bp9NZmW/9wa2qiUJL
# 54r+/+0SOB2QNcrf835ZIhn4Vw4HX/mwhZA5mUaVt7SDYAQb8+HdNT8SSUpRijqo
# qGXeYCky+3HOcw==
# SIG # End signature block
