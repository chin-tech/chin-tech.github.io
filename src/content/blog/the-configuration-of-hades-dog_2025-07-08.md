---
heroImage: '../../assets/kerberos_banner.png'
layout: post
description: Discussing KRB5_CONFIG and fixing a small error in nmap's NSE
postType: OTHER
pubDate:  2025-07-08
title: "The Configuration of Hades Dog"
date: Tue Jul  8 07:02:49 -1000
---


## Overview

Now, I've done a few boxes so far in Hack The Box and I've occasionally had to use kerberos to get a ticket. And it was a realm (yeah, I did that) of complete fuzziness for me as to how to properly generate the correct configuration to actually get the ticket. I've watched a complete deep dive about how the authentication mechanism works in Keberos, the whole flow:
![mermaid_seq](../../assets/posts/configuring_hades_dog/mermaid.png)

and how small aspects of this process are exploitable in certain situations. However, the more practical use case within pentesting, which is dealing with the configuration to initialize it. Has left me fumbling along and it's finally bothered me enough to learn. So, I'm writing this down hopefully for anyone else to see, because you'll come across some situation where `nxc smb --generate-krb5-file` won't work because you need kerberos to authenticate, and then you cry because you have no idea what the domain realm is supposed to be or what comes after that.

## The File

They typically look like this:
```

[libdefaults]
    default_realm = MY.TLD
    dns_lookup_realm = true
    dns_lookup_kdc = true

[realms]
    MY.TLD = {
        kdc = DC.my.tld
        admin_server = DC.my.tld
        default_domain = DC.my.tld
    }

[domain_realm]
    my.tld = MY.TLD
    .my.tld = MY.TLD
```


## The Situation
Let's say you had a nice nmap scan with the typical scripts run and you get an output like this:

```

88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-07-09 07:34:53Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: voleur.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         syn-ack Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack Microsoft Windows RPC
62028/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
62029/tcp open  msrpc         syn-ack Microsoft Windows RPC
62041/tcp open  msrpc         syn-ack Microsoft Windows RPC
62046/tcp open  msrpc         syn-ack Microsoft Windows RPC
62060/tcp open  msrpc         syn-ack Microsoft Windows RPC

Host script results:
| smb2-time: 
|   date: 2025-07-09T07:35:47
|_  start_date: N/A
|_clock-skew: 7h59m55s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 48495/tcp): CLEAN (Timeout)
|   Check 2 (port 28595/tcp): CLEAN (Timeout)
|   Check 3 (port 60782/udp): CLEAN (Timeout)
|   Check 4 (port 34236/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul  8 13:36:34 2025 -- 1 IP address (1 host up) scanned in 233.16 seconds
```


The observant of you may notice this a HackTheBox box, don't worry there won't be any spoilers other than using the default credentials provided, but this was the impetus for me to learn, so I don't think there's a better example. 
As you can see, we have some common Microsoft AD services, and a domain being referenced: `voleur.htb0`
Let's clear up something, the 0 probably is irrelevant, it's not a [valid TLD](https://newgtlds.icann.org/sites/default/files/guidebook-full-04jun12-en.pdf).
```
1.2 The ASCII label must be a valid host name, as
specified in the technical standards DOD Internet
Host Table Specification (RFC 952), Requirements for
Internet Hosts — Application and Support (RFC
1123), and Application Techniques for Checking
and Transformation of Names (RFC 3696),
Internationalized Domain Names in Applications
(IDNA)(RFCs 5890-5894), and any updates thereto.
This includes the following:
    1.2.1 The ASCII label must consist entirely of letters
    (alphabetic characters a-z),
```


And we verify it with ldapsearch:
```bash
ldapsearch -x -H 'ldap://10.10.11.76' -b "" -s base namingcontexts
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectclass=*)
# requesting: namingcontexts
#
#
dn:
namingcontexts: DC=voleur,DC=htb
namingcontexts: CN=Configuration,DC=voleur,DC=htb
namingcontexts: CN=Schema,CN=Configuration,DC=voleur,DC=htb
namingcontexts: DC=DomainDnsZones,DC=voleur,DC=htb
namingcontexts: DC=ForestDnsZones,DC=voleur,DC=htb
# search result
search: 2
result: 0 Success
# numResponses: 2
# numEntries: 1
```

We see the DC=voleur, DC=htb so the actual domain is `voleur.htb`. So where's the 0 coming from?
nmap has a service probe that runs with the `-sV` option. The list of regexes actually are located typically: `/usr/share/nmap/nmap-service-probes`
You can open the file up and search for `Domain:` it should be around line 14745 and look a little something like this:
```
match ldap m|^0\x84\0\0..\x02\x01.*dsServiceName1\x84\0\0\0.\x04.CN=NTDS\x20Settings,CN=([^,]+),CN=Servers,CN=([^,]+),CN=Sites,CN=Configuration,DC=([^,]+),DC=([^,]+)0\x84\0|s p/Microsoft Windows Active Directory LDAP/ i/Domain: $3.$4, Site: $2/ o/Windows/ h/$1/ cpe:/o:microsoft:windows/a
```

So it's capturing the dsServiceName query and capturing someoutput and it seems it's precisely matching a zero at the end, but we're still capturing it? Perhaps it's in that query and the AD is just poorly configured?
```bash
ldapsearch -x -H 'ldap://10.10.11.76' -b "" -s base  dsServiceName
# extended LDIF
#
# LDAPv3
# base <> with scope baseObject
# filter: (objectclass=*)
# requesting: dsServiceName
#

#
dn:
dsServiceName: CN=NTDS Settings,CN=DC,CN=Servers,CN=Default-First-Site-Name,CN
 =Sites,CN=Configuration,DC=voleur,DC=htb

# search result
search: 2
result: 0 Success

```

Nope. 
So let's look at some packet captures.

```bash
tshark -i tun0 -f "port 389"
# <snip>
0050  7e 04 0d 64 73 53 65 72 76 69 63 65 4e 61 6d 65   ~..dsServiceName
0060  31 84 00 00 00 69 04 67 43 4e 3d 4e 54 44 53 20   1....i.gCN=NTDS
0070  53 65 74 74 69 6e 67 73 2c 43 4e 3d 44 43 2c 43   Settings,CN=DC,C
0080  4e 3d 53 65 72 76 65 72 73 2c 43 4e 3d 44 65 66   N=Servers,CN=Def
0090  61 75 6c 74 2d 46 69 72 73 74 2d 53 69 74 65 2d   ault-First-Site-
00a0  4e 61 6d 65 2c 43 4e 3d 53 69 74 65 73 2c 43 4e   Name,CN=Sites,CN
00b0  3d 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 2c 44   =Configuration,D
00c0  43 3d 76 6f 6c 65 75 72 2c 44 43 3d 68 74 62 30   C=voleur,DC=htb0
00d0  84 00 00 00 10 02 01 02 65 84 00 00 00 07 0a 01   ........e.......
00e0  00 04 00 04 00                                    .....
# </snip>
```
Clearly it ends in that same pattern: `0\x84\0`
So it seems the regex implementation is doing something interesting with the + and unecessarily capturing the trailing 0, even though we don't want it. I won't lie it's kind of confusing, because it is somehow 'capturing' the 0 but still using it as a delimiter. I'm unaware of how this behavior occurs, nmap apparently uses its own modified version of PCRE regex, which might hold the key to this behavior.

I do know that adding a simple ? to the end of the + allows for the correct domain parsing.
```
match ldap m|^0\x84\0\0..\x02\x01.*dsServiceName1\x84\0\0\0.\x04.CN=NTDS\x20Settings,CN=([^,]+),CN=Servers,CN=([^,]+),CN=Sites,CN=Configuration,DC=([^,]+),DC=([^,]+?)0\x84\0|s p/Microsoft Windows Active Directory LDAP/ i/Domain: $3.$4, Site: $2/ o/Windows/ h/$1/ cpe:/o:microsoft:windows/a
```
```bash
nmap -sV -p 389 10.10.11.76
```
```
 Starting Nmap 7.97 ( https://nmap.org ) at 2025-07-09 11:37 -1000
 Nmap scan report for voleur.htb (10.10.11.76)
 Host is up (0.19s latency).

PORT    STATE SERVICE VERSION
389/tcp open  ldap    Microsoft Windows Active Directory LDAP (Domain: voleur.htb, Site: Default-First-Site-Name)
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```


So I threw in a [pull request](https://github.com/nmap/nmap/pull/3149).  Hopefully it will get fixed.

So indeed, the 0 is a lie. Do not believe it.

What we were doing again? Oh right Kerberos Configuration.
So, we got this scan and verified the correct domain is `voleur.htb`
Let's try to use nxc to generate the kerberos config:
```bash
nxc smb 10.10.11.76 --generate-krb5 custom_krb.conf -u ryan.naylor -p HollowOct31Nyt --verbose
```
```
[13:07:12] INFO     Socket info: host=10.10.11.76, hostname=10.10.11.76, kerberos=False, ipv6=False, link-local ipv6=False                                                                                                    connection.py:165
           INFO     Creating SMBv3 connection to 10.10.11.76                                                                                                                                                                         smb.py:606
[13:07:13] INFO     Creating SMBv1 connection to 10.10.11.76                                                                                                                                                                         smb.py:575
           INFO     SMBv1 disabled on 10.10.11.76                                                                                                                                                                                    smb.py:598
[13:07:14] INFO     Resolved domain: 10.10.11.76 with dns, kdcHost: 10.10.11.76                                                                                                                                                      smb.py:321
SMB         10.10.11.76     445    10.10.11.76      [*]  x64 (name:10.10.11.76) (domain:10.10.11.76) (signing:True) (SMBv1:False) (NTLM:False)
           INFO     Creating SMBv3 connection to 10.10.11.76                                                                                                                                                                         smb.py:606
SMB         10.10.11.76     445    10.10.11.76      [-] 10.10.11.76\ryan.naylor:HollowOct31Nyt STATUS_NOT_SUPPORTED (The request is not supported.)

```

Oh no! It's not supported! Now we have to learn. (It does actually generate the configuration, but it just sticks the ip everywhere and is useless)

### [libdefaults]
#### default_realm
It specifies the default behaviors for the kerberos libraries, it, it's only for default behavior so it technically isn't required.
It makes usage quite easier eg.
If we don't specify a default_realm when we kinit, the default_realm will be used, otherwise  we have to do is `kinit user@MY.TLD`
- We still need to DEFINE our realm in the lower config!

#### dns_lookup_realm
Allows kerberos to use DNS to map domain names to kerberos realms eg. `voleur.htb` -> `VOLEUR.HTB`
- Only if the appropriate DNS txt records are set up and configured correctly on the target domain

#### dns_lookup_kdc
Allows keberos to use DNS SRV records to find Key Distribution Centers (KDC's), which will eliminate the need to specify the kdc field when we define our realms.
- This is only if those DNS SRV records exist, which may not always be the case. They would look like `_kerberos._tcp.voleur.htb`

### [realms]
This is where you define the realms which in kerberos' typical convention is the capitalized domain name, in our case it's `VOLEUR.HTB`
This was also a confusing thing for me, as why does capitalization matter? I always have had this association in my mind that kerberos tightly associated with windows, as that was the context I have almost always seen it. However the [origins](https://web.mit.edu/Saltzer/www/publications/Kerberosorigin.pdf) date back before windows even gained a foothold. And the reason they chose capitalization for realms is just convention. So we always assume the convention until we have conflicting information otherwise. Because we can even  have `VolEuR.HtB` if we wanted, but people don't configure things that way.
#### REALM.DOMAIN
the realm name corresponds to the target domain name eg. `voleur.htb`
##### kdc
Ideally stick the $ip:$kerb_port here to be explicit.
`kdc = 10.10.11.76:88`

##### default_domain
Maps the realm back to a domain_name, the oppost of what we do below.
`default_domain = voleur.htb`

### [domain-realm]
This is the explicit mapping of the domains to the kerberos realm
You typically do 2:
`voleur.htb = VOLEUR.HTB`
`.voleur.htb = VOLEUR.HTB`
The second one is for any extra domains, view it as *.voleur.htb

## Final Config

So if you have `10.10.11.76 voleur.htb` in your /etc/hosts file and the appropriate DNS records are supported by the box, this would be all you need.

```conf
[libdefaults]
    default_realm = VOLEUR.HTB

    dns_lookup_realm = true

    dns_lookup_kdc = true

[realms]

    VOLEUR.HTB = {}

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    voleur.htb = VOLEUR.HTB
```


Otherwise, you need some more explicit mapping, which you probably should for CTF's (you could set them the two false's to true, but it's better to be explicit for intended behavior)
```conf
[libdefaults]
    default_realm = VOLEUR.HTB

    dns_lookup_realm = false

    dns_lookup_kdc = false

[realms]
    VOLEUR.HTB = {
        kdc = 10.10.11.76:88
        default_domain = voleur.htb
         }

[domain_realm]
    .voleur.htb = VOLEUR.HTB
    voleur.htb = VOLEUR.HTB

```


You can add a few the admin_server as well in the realms section, but for basic auth that's not necessary and this should be enough to give you enough of an "Oh this is how this works", to delve deeper if you have to.

This mainly was caused by a lot of confusion I received from nmap, paired with only a extremely surface level look at the configuration file. It goes to show that understanding exactly what your tools are doing is a far more valuable skill than just reading the output of the tool and it's interesting how a tool's very mild innaccuracy can cause a host of confusion when your understanding isn't as confident as it should be.

I also made a script that [generates a krb5config](https://raw.githubusercontent.com/Phaze228/dotfiles/refs/heads/master/util_scripts/.local/bin/mkkrbconfig), that uses ldapsearch, so it should be useful for any other kerberos ventures.

