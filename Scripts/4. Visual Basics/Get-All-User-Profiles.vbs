Option Explicit
On Error Resume Next

Dim strComputer
Dim objWMIService
Dim propValue
Dim objItem
Dim SWBemlocator
Dim UserName
Dim Password
Dim colItems
Dim strMessage
Dim deleteResponse

strComputer = ""
UserName = ""
Password = ""
strMessage = ""

strComputer = InputBox("Please enter the FQDN of a computer:")

If strComputer = "" Then
	strComputer = "localhost"
End If

If Not Ping (strComputer) Then
    MsgBox "The computer (" + strComputer + ") is not responding to ping - exiting"
    WScript.quit
End if

Set SWBemlocator = CreateObject("WbemScripting.SWbemLocator")
Set objWMIService = SWBemlocator.ConnectServer(strComputer,"root\CIMV2",UserName,Password)
Set colItems = objWMIService.ExecQuery("Select * from Win32_UserProfile",,48)
For Each objItem in colItems
	
    strMessage = ""
    If not objItem.LastDownloadTime = "" Then 
        strMessage = strMessage + "LastDownloadTime: " & left(objItem.LastDownloadTime,8) + Chr(10) + Chr(13)
    End If

    If Not objItem.LastUploadTime = "" Then
        strMessage = strMessage + "LastUploadTime: " & left(objItem.LastUploadTime,8) + Chr(10) + Chr(13)
    End if

    if not objItem.LastUseTime = "" then
        strMessage = strMessage + "LastUseTime: " & left(objItem.LastUseTime,8) + Chr(10) + Chr(13)
    End If

    If Not objItem.Loaded  = "" Then
        strMessage = strMessage + "Loaded: " & objItem.Loaded + Chr(10) + Chr(13)
    End If

    If not objItem.LocalPath = "" then
        strMessage = strMessage + "LocalPath: " & objItem.LocalPath + Chr(10) + Chr(13)
    End If

    if not objItem.RefCount = "" then
        strMessage = strMessage + "RefCount: " & objItem.RefCount + Chr(10) + Chr(13)
    End If

    if not objItem.RoamingConfigured = "" then
        strMessage = strMessage + "RoamingConfigured: " & objItem.RoamingConfigured + Chr(10) + Chr(13)
    End If

    if not objItem.RoamingPath = "" then
        strMessage = strMessage + "RoamingPath: " & objItem.RoamingPath + Chr(10) + Chr(13)
    End If

    if not objItem.RoamingPreference = "" then
        strMessage = strMessage + "RoamingPreference: " & objItem.RoamingPreference + Chr(10) + Chr(13)
    End If

    if not objItem.SID = "" then
        strMessage = strMessage + "SID: " & objItem.SID + Chr(10) + Chr(13)
    End If

    if not objItem.Special = "" then
        strMessage = strMessage + "Special: " & objItem.Special + Chr(10) + Chr(13)
    End If

    if not objItem.Status = "" then
        strMessage = strMessage + "Status: " & objItem.Status + Chr(10) + Chr(13)
    End If

	 WScript.Echo strMessage

Next

Function Ping(strHost)

    dim objPing, objRetStatus

    set objPing = GetObject("winmgmts:{impersonationLevel=impersonate}").ExecQuery _
      ("select * from Win32_PingStatus where address = '" & strHost & "'")

    for each objRetStatus in objPing
        if IsNull(objRetStatus.StatusCode) or objRetStatus.StatusCode<>0 then
                Ping = False
        else
            Ping = True
        end if
    Next
End Function