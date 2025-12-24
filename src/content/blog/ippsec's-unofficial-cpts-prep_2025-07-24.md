---
heroImage: '../../assets/posts/htb-cpts-prep-list/banner.png'
layout: post
description: Going through and summarizing my experience of the 22 boxes
postType: OTHER
pubDate:  2025-07-24
title: "Ippsec's Unofficial CPTS Prep"
date: Thu Jul 24 06:28:41 AM HST 2025
image:
    path: ../../assets/posts/htb-cpts-prep-list/banner.png
    alt: cpts_prep_banner
# List Format
table_of_contents:
    - Overview
    - Enumeration
    - Initial Foothold
    - Privilege Escalation
    - Remediation
initial_creds: ""
# List Format
ip_addresses: 
    - 10.10.11.68
---

I have recently gone through Ippsec's unofficial CPTS prep list in order to well-round myself before taking the exam.


My methodolgy for this was simple, attempt the box, if I get stuck for over an hour or two with no progress go over to guided for a nudge or listen to a portion of ippsec's introduction since it will usually highlight exactly what you're supposed to do, if not find the exact portion.

I learned a great deal from doing all of them but 11 out of the 22 gave me the most educational benefit: Forest, Soccer, Access, MetaTwo, Driver, Trick, Outdated, Agile, Pressed, Reddish, and Sekmet

They specifically challenged me in ways that made have to alter the typical way I was doing something or learn about syntax quirks or manage debug consoles, gpg keys and a really cool tactic of a forward shell. And the harder ones like Reddish and Sekhmet truly make sure you have a strjong fundamental of how things operate because if you can't question the right things or properly enumerate internal networks, you'd never progess and you can easily see how crucial that would be in an actual pentesting engagement.


I'd say it definitely was a necessary given as I was starting to feel like i was "getting good" at doing some boxes, but his playlist did hit me with a few boxes where I haven't been exposed to the particular possibility before.
So here's the prep-list in order and what I learned from them. All 22 boxes.

## Forest
Active directory box, which wasn't that hard once you get the user. (I definitely needed assistance here) Getting the user though was surprisingly tricky. You don't get any initial creds and anonymous logging in with SMB/RPC needs a specific syntax with updated tools. I wasn't really used to manually enumerating LDAP and I definitely was unaware that rpc can provide you with different information than ldap. Even if both allow for anonymous viewing. I also realized how absurdly powerful the Microsoft Exchange group can be. Allowing you to DCSync.
- RPC and LDAP can provide differing results based on access level even if both are anonymous!
- Windows Exchange Management is a little excessive in privileges.

## Union
This box was a great demonstration of how to do union injections. He specifically tailored this box to subvert certain aspects of sqlmap so you get forced to attempt it yourself. You're able to use union injection to determine the columns of output, you can group concat the output to merge it. You can enumerate tables and columns and you can even load files for viewing. It's a great box to give you a solid foundation of what is possible with union injections.
- Remember to test union injection with good data!

## Soccer
This box, I actually was able to do 95% of myself. It covered two different versions of a web application. The initial access had default credentials through TinyFileManager which you could upload a malicious php webshell and get a shell on the box. From there I uploaded a chisel binary to reverse port forward localhost:3000 which I saw was running. I realized a slightly better method would have been to just check the nginx configuration file, which would have showed it's accessible through a differnt vhost.

This new webpage is similar with more functionality. It lets you sign up and get a free ticket and we get to see what the port 9091 was actually used for now. A web socket client, that connects to a database. This is prone to a boolean injection, which thankfully we can automate with sqlmap. Once we were able to credentials to officially get on the box, I was actually a bit lost, because all typical avenues weren't present and I needed a nudge. It's not sudo that was used, it was doas. Which isn't very typical. This let you run a program called dstat as root, which you can maliciously load your own plugins which are basically python code.
- Keep an eye out for NGINX configurations
- Always be aware of optional and similar programs to sudo.

## Active
This box is another AD box that showcases the dangers of backwards compatibility and how terrible certain configurations used to be. We have anonymous read access to a group policy account. It's in a `Groups.xml` file and we get the username and the hashed password. We can crack it and from there we are a part of the windows pre-2k group which gives us read access over everything in the domain. It lets us do a bloodhound and we can see that the Administrator account has an SPN. This lets us kerberoast the administrator and crack his password and roots the box.
- Legacy misconfigurations

## Administrator
First box that we encounter that I actually finished prior to it being on the playlist. Although ippsec's box did teach me a way to quickly filter out groups that aren't default windows groups using jq, bloodhound, and their sids. Most default accounts hae sids ending below 1000, so filtering for above 1000 will retrieve the non-default ones. Which is pretty neat. 

## Delivery
This box utilizes a a cool technique that utilizes ticketing software. You can create a ticket and you get a @delivery.htb email you can email to send updates to the ticket. But that means we can send other things, like verification emails. Which we use to get into the mattermost server which gives us credentials on the box and the dialogue also gives some juicy information about the likely password the root user uses.
- Remember software may not always have coding vulnerabilties, but malformed configuration when paired with other applications

## Remote
This one shows an nfs service which has a backup of the webserver that's visible. It's an Umbraco service which it's config in the root folder of Web.Config and you can find the sql server connection in there which says it's in app_data called Umbraco.sdf. We can download that file, and just cat it. It looks a little rough, but we can see some usernames and hashes with the types. We can crack the admin hash, which let's us get onto the webserver and we can perform some RCE. The RCE let's us get a shell and after enabling our token privileges we can utilize RoguePotato to get the flags. 
- Enumerate windows versions

## Access
This one was surprisingly a challenge, not entirely because of the difficulty of escalation but because different filetypes you had to deal with and if you forget exactly how cmdkey works. I spent a little too long attempting to get certain things to work. Either way, you don't get a lot to go on, you have an http server, an FTP server and an open telnet. The FTP server gives access to a password-encrypted zip, and a backup mdb table.

The MDB table was one part of the trickiness for me. I was unaware of mdb-tools so I went online to find some converters that didn't work and after multiple did not work. I realized I may need to readdress how I downloaded the file. Make sure to download in binary mode with FTP..... lots of tables but within in auth_users we get the gold and find the password for engineer. Which is likely the password for the zip from the Engineer directory. Ippsec did a much more clever thing, which was just strings and make a wordlist to quickly find the password, so I will note that for future reference. Once we get in the zip, we get a .PST archive file which we can convert with readpst and get credentials for the security account.


This was my other pitfall, forgetting to do a simple cmdkey /list would have saved me a lot of time. I was thrown off by the telnet shell and the users directory had a lack of any AppData so I didn't even suspect it! So I was attempting alot of enumeration that ended in nowhere. I tried enabling an extra privilege, finding out that it didn't run, likely due to our powershell version. I then played the very start of the Ippsec video and he mentioned dpapi, so I checked `cmdkey /list` and I was rather annoyed. So I tried uploading mimikatz, but you can't upload it via wget, as the PS version is too old to alias it.

So upload it via certutil and then I find out GPO prevents its execution. But I did end up learning something new. If you have the saved cred, you can get the hash by simply setting up an impacket smbserver and using `net use \\$ip\share /user:ACCESS\ADMINISTRATOR` and it will authenticate it with that user to the share. Basically giving you a free lsass dump of the hash. I tried cracking it, but no avail, psexec didn't work because smb isn't up. So all the typical methods I'm used to weren't there. But then I remembered runas, so we can just upload a reverse shell and have it run it as an admin. I tried a reverse shell payload at first even base64'd, but it didn't work so I created an msfvenom payload which gave me the connection as Admin. Ipp's base64'd payload was different, and got it to work, so something else to note that I have to try.


- Binary mode in FTP
- Never forget checking cmdkey /list
- SMB Server connections can be a quick path to a hash rather than utilizing mimikatz if cmdkey works
- runas and double check your payloads!

## MetaTwo
Now this one didn't feel particular easy for me. It hilariously was, but due to some lack of experience enumerating wp sites proficiently how to properly handle the exploits, it took me alot. I was on the right track for all of it, but the execution was poor. I knew it had to do with the event creation, and likely a sql injection. I neglected to verify the version which would have confirmed it for me. I found the exact vulnerability, but I thought a little too hard about what to replace to make it work, when all I needed to change was the nonce.

Sqlmap also fails pretty hard at detecting it automatically, and I felt a bit better after it even took ippsec a little longer to navigate it then it should have taken. Once we dumped the database we get in the wordpress instance and can use an XXE vulnerability, which one POC failed me so I had to find another to see where it went wrong. This vulnerability is an arbirtrary file-read. We read the wp-config.php file and get the ftp login. the FTP login has a PHPMailer directory which has credentials jnelson and logging in reveals a password manager once you ls -la. It has a gpg private key with which is encrypts credentials and we can use gpg2john for the key and get the password and export the root password that is in there. This was far less complicated then I had imagined... and I think I hate wordpress a little bit


- Try agressive WP scans
- Remember to look at the page source, it takes like two seconds
- Pay attention to exactly why POC's works.
- Always do an ls -la

## Driver
A box covering printer driver exploits. I was a little burnt-out and tried a lot more than I should have more the entry point to this box. I was looking for malicious drivers right away, but it was far simpler than that...just make a SCF file that reaches back to your IP and you can steal an NTLM hash. Once there, I believe the inteded way to do this was to notice there's a powershell history file in which you can read that there was an Add-Printer command for ricoh. which has an exploit available. The only good POC for that is in the MSFramework, so I decided to just utilize PrintNightmare which also works just as well.
- Take note of *where* things are uploaded to and if it intends interaction.

## Trick
This box though 'Easy' because it provides an exceptional amount of ways to progress is actually an amazing learning opportunity. I think I'll be providing my own specific write-up on this box (I did, it's on the blog). Because conceptually it's very informative, to how you can progress by paying particular attention. However you only have 3 ports open, 25, 53, and 80. The DNS lets you grab the domain name and pull a zone transfer which exposes a pre-prod website that is vulnerable to SQLi with file-read privileges. So you can read the nginx config to find another preprod site. Which is vulnerable to another LFI which can help you figure out the user. Which is michael and you can read his ssh key, login and utilize his group privleges and sudo fail2ban privileges to on ban, give yourself root.
- Multiple attack methods
- php-filter-reads
- nginx configuration paths

## Shoppy
This box really is simple if you catch everything. I didn't. So this box really helped me recognize the NodeJS and MongoDB elements and hopefully I'll be signficantly quicker about making that leap to attempt a NoSQL injection. I had done all the enumeration and basically knew what I had to do, but couldn't figure it out until I saw how the nosql was performed. After that box really was simple. A bit more enumeration and after you're logged in and it's pretty straight forward from there.
- NoSQL / MongoDB and how `&& AND` operators have precedence over `|| OR` operators
- NodeJS and the `Cannot GET /` error with HTML

## Manager
This box is actually pretty cool, because it basically gives you nothing like a true pentest should. You ideally have to play around to find out the guest account is enabled which lets you brute force sids (or use lookupsids.py). The alternative method is to kerbrute, I failed with this because I didn't think of doing it with default account names, I was interested in other users. Then once you get the users you password spray and the best password spray to start with is the same username.

 This works for one of the accounts. Though my attempts at using kerbrute to password spray for some reason failed. I thought maybe due to clock skew, but even after adjusting it, it failed. It does give you a *sign* that it works, still saying the clock skew is wrong even though I adjusted it. We get an account which on the surface doesn't look promising until you notice the MSSQL port open. You can connect to that and utilize the `xp_dirtree` command. This lets us navigate the filesystem a bit and we can go toward the webroot which just had a static IIS page. And there is a backup folder, that contains creds. You can a shell with them, run some bloodhound and more importantly certipy find. This account has `Manage CA` permissions which basically allows you to request an administrator certificate and approve it. Which is ESC7.

- Notate the difference ways to brute: --rid-brute or lookupsids.py
- Remember MSSQL filesystem commands

## Outdated
This was a great box that once again humbled me stupidly. Perhaps it's a bit of burnout running through boxes as well. This box starts with needing some more smn enumeration as a null session, perplexing thing I learned here, which I had thought I learned in Forest was null sessions, but I had not. There's some subtle differences between a null session (which is basically non-existent in modern windows), guest accounts, and how smb "authorizes". You can give any username and it (in this case) falls back to guest access.

This will "authorize" even if you give a random password, but interestingly if you provide a password, you don't get access to the shares. It's almost as if you're in a weird fuzzy state of restricted guest access. But if you provide the default null password, you then can enumerate shares. Which paves the way for the first CVE which gets a shell on the box. The Follina exploit. This is one I *knew* existed but I had no idea what the name was or any technical aspects about it. We get an email to send to, and a list of CVE's that they're trying to patch. One of them is the folina. The interaction between this mail clicker and the exploit isn't the typical manner in which it's executed.

So you to modify the typical POC and just have a malicious link embdedded. From there you can get a shell, and you should ideally run bloodhound on this box to see what accesses you have over users. We can add a CredentialLink to another user, which we can just upload Whisker or if we paid attention to the user-agent from Powershell, this version is susceptible to SeriousSAM / HiveNightmare and the hives are readable by all users, and you can get a credential from there to run pywhisker. Once we add that, I used certipy to auth and get the hash for sflowers.

Sflowers is a member of the WSUS Admins. Which is the Windows Server Update Services. Which yes, that means we can administer updates and we can do that via SharpWSUS, by utilizing a windows signed binary (psexec) and run any arbitrary command we like. From there, I got a reverse shell from powershell. This may also be worth a write-up...
- SMB, Null passwords vs bad passwords
- Try and enumerate and determine how interactions are happening to proceed
- Pay attention to default groups and notate anything out of the ordinary (WSUS shares for instance)

## Agile
This box was also a bit crazy, reverse engineering a werkzeug debug pin from LFI  to getting rce. I found the LFI, and I honestly am sad I didn't ever notice flask had a debug console. Having coded a flask application and seeing that error screen, made me feel rather stupid for never paying attention to it. From there I was able to access mysql credentials and dumped a database and was honestly a little lost, because after getting two different users, only one had a sudo access for dev_admin and it was editing two files.

Once you realize there's a sudo vulnberability though, you realize you can edit any file owned or group-owned by dev_admin. Which for some reason, is cronjob'd by root to source the application's venv. Ippsec and 0xdf utilized the remote-debugger access in chromium which was rather cool, but for some reason I could just access view the config file and access the db. So I didn't need to do that. 

- Pay attention to debug consoles.
- If a user has sudo as any different user on a box, focus a bit more there.


## Pressed
This is actually weirdly easy yet hard box. As soon as you realize what you have to do, it's straight forward. The hard part is truly enumeration because that's what restricts you at every turn, as well as the red herrings. It's a word press site that has a backup we have access to. It gives us a password off by 1 which we can attempt to login to the wordpress site, but unfortunately, we can't, because MFA is on. But the xmlrpc is enabled, which is used for automation purposes and doesn't have the MFA restriction. So we have access to all the methods and we can create posts using an enabled plugin that allows for code execution.

That part alone is pretty tricky, but then when we try to spawn a reverse shell nothing will work, because the iptables only allow outbound connections from already established or related connections which the only allowed are into port 80 and also ICMP. There is the possibility of an ICMP reverse shell, but Ippsec used a forward shell, which is a clever mechanism that utilizes `tail -f | /bin/sh > fifo` to maintain a shell that we read and write to. At the time of the box, there was a popular exploit going on with pkexec and he threw that in for root, which if you don't have a stable shell is once again tricky to deal with, but the forward shell let's you execute it nicely.

- Enumerate quickly, then aggressively.
- If you're positive a shell _should_ work, something is blocking it.


## LogForge
This is blast from the past, utilizing log4j for most of the attack path. Although there's a crazy path traversal trick that I had never seen, where you can visit tomcat urls like `http://example.com/nonexistent/..;/manager/` and access unathorized urls. And some exposure to the jndi toolkit which is a nice reference in case any old outdated applications are still using unpatched log4j. It's definitely not anything I would think of currently, but I suppose it's worth a shot if you know you're in an older environment.
- Keep in mind legacy and unpatched things
- Just because something says it fails, don't assume it does! (The root flag was easily accessible)

## Hospital
This is also one I had done prior to realizing it was on the playlist. But it was over a year from me doing it so I decided to do it again. It's a windows box where I never bothered using bloodhound, so that's notable. You get a roundcube instance and a webserver running on a dockerized instance. 

You can get some rce from uploading a php file on the webserver and there you need utilize a kernel exploit to get root, to crack some passwords to get on the roundcube instance. Once there you can find you need to send an email to a doctor regarding needle designs in an EPS format, which you can maliciously hide a reverse shell. Then once you're on the box, you have a few ways to administrator. The intended VNC / Keylogger way which once I found out that was possible, is pretty epic and I have to be aware of it. The other which I did was a php web shell which happened to be running as system.
- Enumerate system versions, find a resource to make it easy
- qwinsta matters and migrating processes.
- Sometimes...webservers are ran as system

## Blackfield
This was my first windows hard box that I managed to in record time. I felt pretty good, but knowing this box is half a decade old, I have to be aware that the tooling available now is beyond exceptional for doing these kinds of thins. However, I'll say doing things like Forest and Outdated definitely made it easier. Guest access enabled, let's us brute force some rids to find a list of users to see if there are any asrep accounts.

From there, you can crack a hash on one of them, pivot to another which has access to a previous pentest apparently where they were found vulnerable and you can find a .zip that has some lsass goddness. They managed to clear up most of the problems, but the svc_backup accounts password was apparently still good as the ntlm hash worked. It being a backup account means you can backup the ntds and well..make them vulnerable again.
I don't really have any learnings from this one because it took me sub 2-hours. I felt pretty good with this box.

## Vintage
I have previously completed this one during the season. You're able to use the given credentials to map their AD environment. You do a little bit of digging and suspect a computer account might be the way through since it has ReadGMSAPassword so naturally how do you get in? Well, if it's a member of a pre-win2k you the default is for the password to be the name of the computer name but lowercase. So we utilize that, to carve our path into a ServiceManagers group which lets us enable a service account crack its hash via kerberoasting, password spray it, find the user and their dpapi credentials which happens to hold their admin password and from there we can do a delegation attack utilizing fs01 against the dc01 and dump all the good hashes.


## Reddish
This one was a bit crazy. It's fair because it is labeled as Insane. It's actually the one box that gave me a badge as well. The initial entry wasn't too crazy, it's the constant pivots on internal networks while trying to  maintain your sanity. You're left with bare shell essentially and enumerating in that manner, or maybe piping over a file from nc to run an automated script. It's worth a writeup on my own to properly consolidate my thoughts on it and how to approach boxes like this in the future.
- Stay organized
- Fundamentals are key
- Solidly understand port forwarding.


## Sekhmet
This was the -first- insane box I had attempted and watched the walkthrough with Ippsec, many months ago. I remember it being actually crazy because he had a 2 hour long video. I didn't remember any of it, so I tried to redo it. And I still actually got a little hung up unfortunately. I found the web vuln, but I got hung up on how to execute it. Escalating on the box, I forgot about being able to enumerate zip files to see what they're encrypted with, I had wasted a little bit of time with zip2john. Finding the form.ps1 was easy, but the 2-min timer in between trials made me once again go verify my payloads to see exactly why I was messing up after 3 missed attempts. Once I got to this point it was trivial to proceed how I would typically on a windows box. So I definitely improved, because I fully understand everything this time, and I feel like it stuck. But, I suppose I won't know until I try it again in like a year when I forget it again.
- Serialization!
- 7z can do a lot of nifty things!
- sss kerberos on linux, try to keep it in my mind.







