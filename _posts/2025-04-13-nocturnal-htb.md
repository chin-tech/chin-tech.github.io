---
layout: post
title: Nocturnal [HTB]
date: 2025-04-13 21:01 -1000
---


# Nocturnal #

Any and all IP's will be referenced as $IP


## Recon  ##

We'll begin with typical nmap scan
```bash
nmap -sCV -oA nmap/nocturnal -p- -vv $IP
```
Our results:
`
# Nmap 7.94SVN scan initiated Sat Apr 12 20:31:40 2025 as: nmap -sCV -oA nmap/nocturnal -vv -p- -T4 -Pn 10.10.11.64
Warning: 10.10.11.64 giving up on port because retransmission cap hit (6).
Nmap scan report for nocturnal.htb (10.10.11.64)
Host is up, received user-set (0.13s latency).
Scanned at 2025-04-12 20:31:40 HST for 794s
Not shown: 65512 closed tcp ports (conn-refused)
PORT      STATE    SERVICE      REASON      VERSION
22/tcp    open     ssh          syn-ack     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDpf3JJv7Vr55+A/O4p/l+TRCtst7lttqsZHEA42U5Edkqx/Kb8c+F0A4wMCVOMqwyR/PaMdmzAomYGvNYhi3NelwIEqdKKnL+5svrsStqb9XjyShPD9SQK5Su7xBt+/TfJyJFRcsl7ZJdfc6xnNHQITvwa6uZhLsicycj0yf1Mwdzy9hsc8KRY2fhzARBaPUFdG0xte2MkaGXCBuI0tMHsqJpkeZ46MQJbH5oh4zqg2J8KW+m1suAC5toA9kaLgRis8p/wSiLYtsfYyLkOt2U+E+FZs4i3vhVxb9Sjl9QuuhKaGKQN2aKc8ItrK8dxpUbXfHr1Y48HtUejBj+AleMrUMBXQtjzWheSe/dKeZyq8EuCAzeEKdKs4C7ZJITVxEe8toy7jRmBrsDe4oYcQU2J76cvNZomU9VlRv/lkxO6+158WtxqHGTzvaGIZXijIWj62ZrgTS6IpdjP3Yx7KX6bCxpZQ3+jyYN1IdppOzDYRGMjhq5ybD4eI437q6CSL20=
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLcnMmaOpYYv5IoOYfwkaYqI9hP6MhgXCT9Cld1XLFLBhT+9SsJEpV6Ecv+d3A1mEOoFL4sbJlvrt2v5VoHcf4M=
|   256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIASsDOOb+I4J4vIK5Kz0oHmXjwRJMHNJjXKXKsW0z/dy
80/tcp    open     http         syn-ack     nginx 1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Welcome to Nocturnal
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST
381/tcp   filtered hp-collector no-response
1292/tcp  filtered dsdn         no-response
9165/tcp  filtered unknown      no-response
16040/tcp filtered unknown      no-response
20610/tcp filtered unknown      no-response
21698/tcp filtered unknown      no-response
23306/tcp filtered unknown      no-response
24711/tcp filtered unknown      no-response
27976/tcp filtered unknown      no-response
37772/tcp filtered unknown      no-response
44487/tcp filtered unknown      no-response
46030/tcp filtered unknown      no-response
48289/tcp filtered unknown      no-response
49460/tcp filtered unknown      no-response
53254/tcp filtered unknown      no-response
54645/tcp filtered unknown      no-response
57155/tcp filtered unknown      no-response
57757/tcp filtered unknown      no-response
59150/tcp filtered unknown      no-response
60154/tcp filtered unknown      no-response
62008/tcp filtered unknown      no-response
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Apr 12 20:44:54 2025 -- 1 IP address (1 host up) scanned in 794.00 seconds

`




