'################################################################################################
'# Title: AutomatedDiskCleanup.vbs																#
'# Rev: 1.01																					#
'# Author: Shaun Miller																			#
'# Company: University of Hull																	#
'# Created: 3/10/14																				#
'# Modified: 11/05/15																			#
'#       																						#
'# Description:																					#
'#		This script (installs if needed) and runs the disk cleanup wizard to free disk space	#
'#       																						#
'# Revisions:																					#
'#		NEW: 3/10/14	Shaun Miller	Created CCMCacheCleaner.vbs script.						#
'#		MOD: 22/10/14	Shaun Miller	Added logging and folder creation if missing.			#
'#		MOD: 11/05/15	Shaun Miller	Added FontCache cleanup for LocalService AppData.		#
'#       																						#
'################################################################################################
Option Explicit


'#############
'# Constants #
'#############

	Const CLEANMGR_EXE = "C:\Windows\System32\cleanmgr.exe"
	Const CLEANMGR_MUI = "C:\Windows\System32\en-us\cleanmgr.exe.mui"
	Const FONT_CACHE_PATH = "C:\Windows\ServiceProfiles\LocalService\AppData\Local"

	
'###############
'# Main Script #
'###############
	

	LogInfo "Starting new instance of Automated Disk Cleanup"
	LogInfo "Free space on 'C:' is " & GetFreeDiskSpace( "C:" ) & " GB"
	
	'Install Disk Cleanup Wizard if needed
	If Not FileExists( CLEANMGR_EXE ) Then InstallDiskCleanupWizard
	
	'Run disk cleanup wizard
	DiskCleanup()

	'Clean Font Cache for non-current users
	CleanFontCache()
	
	LogInfo "Free space on 'C:' is " & GetFreeDiskSpace( "C:" ) & " GB"
	LogInfo "Automated Disk Cleanup completed"


'######################
'# Subs and Functions #
'######################

	Public Sub CleanFontCache

		Dim sFilePath
		For Each sFilePath In Split( GetUserFontCacheFiles, "|" )
			
			Dim bDeleteFile
			bDeleteFile = True
			
			'Loop all user profiles SIDs
			Dim sUserProfileSID
			For Each sUserProfileSID In Split( GetUserProfileSIDs, "|" )
				
				'If the file name contains this sid then retain it
				If InStr( 1, sFilePath, sUserProfileSID, 1 ) > 0 Then
					bDeleteFile = False
				End If
				
			Next
			
			If bDeleteFile Then
				DeleteFile sFilePath
				WScript.Echo "Deleted " & sFilePath
			End If
			
			
			
		Next
	End Sub
	
	Public Function GetUserFontCacheFiles() 'As String

		Dim sRetVal : sRetVal = ""

		On Error Resume Next
		
		Dim oFSO	:	Set oFSO = CreateObject( "Scripting.FileSystemObject" )
		
		Dim oFolder	:	Set oFolder = oFSO.GetFolder( FONT_CACHE_PATH )
		
		Dim oFiles	:	Set oFiles = oFolder.Files
		
		Dim oFile
		For Each oFile in oFiles
			If Left( oFile.Name, 19 ) = "FontCache-S-1-5-21-" Or Left( oFile.Name, 20 ) = "~FontCache-S-1-5-21-" Then
				sRetVal = sRetVal & oFile.Path & "|"
			End If
		Next

		'Trim any trailing bar separators
		If Right( sRetVal, 1 ) = "|" Then
			sRetVal = Left( sRetVal, Len( sRetVal ) - 1 )
		End If
		
		On Error Goto 0
		
		GetUserFontCacheFiles = sRetVal

	End Function

	' Retrieves the sids of users with an existing user profile on
	' this device as a bar separated string
	Public Function GetUserProfileSIDs() 'As String


		Dim sRetVal : sRetVal = ""

		On Error Resume Next	
		
		Const HKU = &H80000003

		Dim oReg
		Set oReg = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")

		Dim aUserProfileSIDS
		oReg.EnumKey HKU, "", aUserProfileSIDS


		Dim sUserProfileSID
		For Each sUserProfileSID in aUserProfileSIDS
			If Left( sUserProfileSID, 9) = "S-1-5-21-" Then
				If Right( sUserProfileSID, 8 ) <> "_Classes" Then
					sRetVal = sRetVal & sUserProfileSID & "|"
				End If
			End If
		Next
		
		'Trim any trailing bar separators
		If Right( sRetVal, 1 ) = "|" Then
			sRetVal = Left( sRetVal, Len( sRetVal ) - 1 )
		End If

		On Error Goto 0
		
		GetUserProfileSIDs = sRetVal
		
	End Function

	Public Sub DeleteFile( sFilePath )

		'Error Checking Off
		On Error Resume Next
		
		'Delete the file
		Dim oFSO
		Set oFSO = CreateObject( "Scripting.FileSystemObject" )
		oFSO.DeleteFile sFilePath, True 'Force deletion 

		'Check if anything went wrong
		If Err.Number <> 0 Then
			LogError "An error deleting the file '" & sFilePath & "'"
		End If
		
		'Error Checking On
		On Error Goto 0

	End Sub
	
	Function GetFreeDiskSpace( driveLetter ) ' as Double
		Dim dRetVal : dRetVal = 0
		On Error Resume Next
		Dim oFSO : Set oFSO = CreateObject( "Scripting.FileSystemObject" )
		dRetVal = Round( oFSO.GetDrive( driveLetter ).FreeSpace / 1024 / 1024 / 1024, 2 )
		On Error Goto 0
		GetFreeDiskSpace = dRetVal
	End Function
	
	'Runs disk cleanup wizard
	Sub DiskCleanup
		
		LogInfo "Starting disk cleanup wizard"
		
		On Error Resume Next
		Dim oShell : Set oShell = CreateObject( "WScript.Shell" )
		
		'Write disk cleanup configuration keys
			oShell.RegWrite "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files\StateFlags9999", 2, "REG_DWORD"
			oShell.RegWrite "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files\StateFlags9999", 2, "REG_DWORD"
			oShell.RegWrite "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files\StateFlags9999", 2, "REG_DWORD"
			oShell.RegWrite "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations\StateFlags9999", 2, "REG_DWORD"
			oShell.RegWrite "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin\StateFlags9999", 2, "REG_DWORD"
			oShell.RegWrite "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Service Pack Cleanup\StateFlags9999", 2, "REG_DWORD"
			oShell.RegWrite "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files\StateFlags9999", 2, "REG_DWORD"
			oShell.RegWrite "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache\StateFlags9999", 2, "REG_DWORD"
			oShell.RegWrite "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup\StateFlags9999", 2, "REG_DWORD"
			oShell.RegWrite "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Upgrade Discarded Files\StateFlags9999", 2, "REG_DWORD"
			oShell.RegWrite "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files\StateFlags9999", 2, "REG_DWORD"
		
		'Run disk cleanup wizard configuration '9999'
			oShell.Run "CLEANMGR /sagerun:9999", 0, True

		'Delete disk cleanup configuration keys
			oShell.RegDelete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files\StateFlags9999"
			oShell.RegDelete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files\StateFlags9999"
			oShell.RegDelete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Offline Pages Files\StateFlags9999"
			oShell.RegDelete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations\StateFlags9999"
			oShell.RegDelete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin\StateFlags9999"
			oShell.RegDelete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Service Pack Cleanup\StateFlags9999"
			oShell.RegDelete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files\StateFlags9999"
			oShell.RegDelete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache\StateFlags9999"
			oShell.RegDelete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup\StateFlags9999"
			oShell.RegDelete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Upgrade Discarded Files\StateFlags9999"
			oShell.RegDelete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files\StateFlags9999"
		
		'Check if anything went wrong
		If Err.Number <> 0 Then
			LogError "An error occured running the disk cleanup wizard."
		End If
		
		On Error Goto 0
		
	End Sub
	
	'Installs Clean Manager executable and MUI
	Sub InstallDiskCleanupWizard()
		
		LogInfo "Disk cleanup wizard (cleanmgr.exe) is not installed. Attempting installation."
		
		'Check if server or client OS
		If OSProductType = "1" Then 'Client OS
		
			LogError "Disk Cleanup Wizard is installed by default on client Operating Systems. There may be a problem with your system. Try running 'SFC /scannow' as an administrator to repair windows.. Exiting."
			WScript.Quit(-1)

		Else 'Server OS (2=Domain Controller, 3=Member Server)
			
			'Check the OS Version
			LogInfo "Checking Operating System Version"
			Select Case OSVersion
				
				Case "6.0" 'Server 2008
				
					'Check if 32 or 64 bit
					If OSArchitecture = "32" Then
						
						LogInfo "Operating System is Windows Server 2008 (32-bit)"
						CopyFile "C:\Windows\winsxs\x86_microsoft-windows-cleanmgr_31bf3856ad364e35_6.0.6001.18000_none_6d4436615d8bd133\cleanmgr.exe", CLEANMGR_EXE
						CopyFile "C:\Windows\winsxs\x86_microsoft-windows-cleanmgr.resources_31bf3856ad364e35_6.0.6001.18000_en-us_5dd66fed98a6c5bc\cleanmgr.exe.mui", CLEANMGR_MUI
						
					Else '64
						
						LogInfo "Operating System is Windows Server 2008 (64-bit)"
						CopyFile "C:\Windows\winsxs\amd64_microsoft-windows-cleanmgr_31bf3856ad364e35_6.0.6001.18000_none_c962d1e515e94269\cleanmgr.exe", CLEANMGR_EXE
						CopyFile "C:\Windows\winsxs\amd64_microsoft-windows-cleanmgr.resources_31bf3856ad364e35_6.0.6001.18000_en-us_b9f50b71510436f2\cleanmgr.exe.mui", CLEANMGR_MUI

					End If
					
				Case "6.1" 'Server 2008 R2
				
					LogInfo "Operating System is Windows Server 2008 R2 (64-bit)"
					CopyFile "C:\Windows\winsxs\amd64_microsoft-windows-cleanmgr_31bf3856ad364e35_6.1.7600.16385_none_c9392808773cd7da\cleanmgr.exe", CLEANMGR_EXE
					CopyFile "C:\Windows\winsxs\amd64_microsoft-windows-cleanmgr.resources_31bf3856ad364e35_6.1.7600.16385_en-us_b9cb6194b257cc63\cleanmgr.exe.mui", CLEANMGR_MUI

				Case "6.2" 'Server 2012
				
					LogInfo "Operating System is Windows Server 2012 (64-bit)"
					CopyFile "C:\Windows\winsxs\amd64_microsoft-windows-cleanmgr_31bf3856ad364e35_6.2.9200.16384_none_c60dddc5e750072a\cleanmgr.exe", CLEANMGR_EXE
					CopyFile "C:\Windows\WinSxS\amd64_microsoft-windows-cleanmgr.resources_31bf3856ad364e35_6.2.9200.16384_en-us_b6a01752226afbb3\cleanmgr.exe.mui", CLEANMGR_MUI
				
				Case "6.3" 'Server 2012 R2
				
					LogInfo "Operating System is Windows Server 2012 R2 (64-bit)"
					'Check the script has access to the files it needs
					If FileExists( ScriptPath & "\2012R2\cleanmgr.exe" ) And FileExists( ScriptPath & "\2012R2\cleanmgr.exe.mui" ) Then
						CopyFile ScriptPath & "\2012R2\cleanmgr.exe", CLEANMGR_EXE
						CopyFile ScriptPath & "\2012R2\cleanmgr.exe.mui", CLEANMGR_MUI
					Else
						LogError "Disk cleanup wizard could not be installed. Please ensure that the files 'cleanmgr.exe' and 'cleanmgr.exe.mui' are present in the script location in a folder called '2012R2'. Exiting."
						WScript.Quit(-1)
					End If
				
				Case Else
				
					LogError "Operating System not recognised. Exiting."
					WScript.Quit(-1)
			
			End Select 'OSVersion
			
		End If 'OSProductType = "1"
		
		LogInfo "Install disk cleanup wizard"
		
	End Sub 'InstallDiskCleanupWizard()

	'Helper function to get operating system version
	Function OSVersion
		Dim sRetVal : sRetVal = ""
		On Error Resume Next
		
		Dim oWMIService
		Set oWMIService = GetObject("winmgmts:\\.\root\cimv2" )

		Dim oOperatingSystems
		Set oOperatingSystems = oWMIService.ExecQuery( "Select Version from Win32_OperatingSystem" )

		Dim oOperatingSystem
		For Each oOperatingSystem in oOperatingSystems
			
			sRetVal = oOperatingSystem.Version
			'Remove the last version component (e.g. 6.1.7600 becomes 6.1)
			sRetVal = Left( sRetVal, InStrRev( sRetVal, "." ) - 1 )

		Next 
		On Error Goto 0
		OSVersion = sRetVal
	End Function

	'Helper function to get operating system Architecture
	Function OSArchitecture
		Dim sRetVal : sRetVal = ""
		On Error Resume Next
		
		Dim oWMIService
		Set oWMIService = GetObject("winmgmts:\\.\root\cimv2" )

		Dim oOperatingSystems
		Set oOperatingSystems = oWMIService.ExecQuery( "Select OSArchitecture from Win32_OperatingSystem" )

		Dim oOperatingSystem
		For Each oOperatingSystem in oOperatingSystems
			
			sRetVal = Replace( oOperatingSystem.OSArchitecture, "-bit", "" )

		Next 
		On Error Goto 0
		OSArchitecture = sRetVal
	End Function
	
	'Helper function to get OS product type
	Function OSProductType
		Dim sRetVal : sRetVal = ""
		On Error Resume Next
		
		Dim oWMIService
		Set oWMIService = GetObject("winmgmts:\\.\root\cimv2" )

		Dim oOperatingSystems
		Set oOperatingSystems = oWMIService.ExecQuery( "Select ProductType from Win32_OperatingSystem" )

		Dim oOperatingSystem
		For Each oOperatingSystem in oOperatingSystems
			
			sRetVal = Replace( oOperatingSystem.ProductType, "-bit", "" )

		Next 
		On Error Goto 0
		OSProductType = sRetVal
	End Function
	
	'Helper function to get script path
	Function ScriptPath
		ScriptPath = Left( WScript.ScriptFullName, Len( WScript.ScriptFullName ) - Len( WScript.ScriptName ) - 1 )
	End Function
	
	'Helper Function to check file existance
	Function FileExists( filePath )
		Dim bRetVal : bRetVal = False
		On Error Resume Next
		Dim oFSO : Set oFSO = CreateObject( "Scripting.FileSystemObject" )
		bRetVal = oFSO.FileExists( filePath )
		On Error Goto 0
		FileExists = bRetVal
	End Function

	'Help function to copy files
	Sub CopyFile( source, destination )
		On Error Resume Next
		Dim oFSO : Set oFSO = CreateObject( "Scripting.FileSystemObject" )
		oFSO.CopyFile source, destination
		On Error Goto 0
	End Sub
	
	'Helper functions to write to log file
	Sub LogInfo( sEntry )
		WriteToLog sEntry, "info"
	End Sub 'LogInfo( sEntry )

	Sub LogWarning( sEntry )
		WriteToLog sEntry, "warning"
	End Sub 'LogWarning( sEntry )

	Sub LogError( sEntry )
		WriteToLog sEntry, "error"
	End Sub 'LogError( sEntry )

	Sub WriteToLog( sEntry, sType )
		
		'Set the error log type
		Dim iType
		Select Case lcase(sType)
			Case "error"
				iType = 3
			Case "warning"
				iType = 2
			Case Else 'E.g. "info"
				iType = 1
		End Select
		
		Const ForAppending = 8 
		
		'Set the log path
		Dim sLogPath
		sLogPath = "%windir%\temp\" & left( WScript.ScriptName, len( WScript.ScriptName ) - 4 ) & ".log"
		Dim oShell
		Set oShell = CreateObject( "WScript.Shell" )	
		sLogPath =  oShell.ExpandEnvironmentStrings( sLogPath )
		
		'Generate the time and date format strings
		Dim iMillisecs
		iMillisecs = Timer() - ((Hour(Now) * 3600) + (Minute(Now) * 60) + Second(Now))
		iMillisecs = Fix(iMillisecs * 1000)

		Dim sMonth
		sMonth = Month(Now)
		If Len(sMonth) < 2 Then
			sMonth = "0" & sMonth
		End If

		Dim sDay 
		sDay = Day(Now)
		If Len(sDay) < 2 Then
			sDay = "0" & sDay
		End If

		Dim sDate
		sDate = sMonth & "-" & sDay & "-" & (Year(Now))
		
		Dim sTime
		sTime = (Hour(Now)) & ":" & (Minute(Now)) & ":" & (Second(Now)) & "." & iMillisecs & "+00"
	  
		'Generate the expanded log file syntax
		Dim sExpandedEntry
		sExpandedEntry =	"<![LOG[" & sEntry & "]LOG]!>" & _
					"<time=" & chr(34) & sTime & chr(34) & _
					" date=" & chr(34) & sDate & chr(34) & _
					" component=" & chr(34) & left( WScript.ScriptName, len( WScript.ScriptName ) - 4 ) &  chr(34) & _
					" context=" & chr(34) & chr(34) & _
					" type=" & chr(34) & iType & chr(34) & _
					" thread=" & chr(34) & chr(34) & _
					" file=" & chr(34) & WScript.ScriptFullName & chr(34) & ">"
		
		'Create a filesystem object
		Dim oFS
		Set oFS = CreateObject( "Scripting.FileSystemObject" )
		
		'Open the log file for appending (the 'True' parameter means create the file if required)
		Dim oLogFile
		Set oLogFile = oFS.OpenTextFile( sLogPath, ForAppending, True) 

		'Write to the file
		oLogFile.WriteLine sExpandedEntry
		oLogFile.Close

		'Destroy objects
		Set oLogFile = Nothing
		Set oFS = Nothing
		
	End Sub 'WriteToLog( sEntry, sType )