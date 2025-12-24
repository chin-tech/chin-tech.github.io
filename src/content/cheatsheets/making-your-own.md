---
pubDate: 12-23-2025
description: How to use and extend tldr to make your own cheatsheets
heroImage: '../../assets/cheatsheets/tldr/banner.png'
title: tldr - Effective Reference Cheatsheets
---

## Overview
- [tealdeer-rs](https://github.com/tealdeer-rs/tealdeer) - fast tldr client
- [tldr](https://github.com/tldr-pages/tldr) - The tldr pages
> The tldr-pages project is a collection of community-maintained help pages for command-line tools, that aims to be a simpler, more approachable complement to traditional man pages.


It allows you to run a simple query with a command to give you references on how to use it, that alone is very useful. However with tealdeer-rs you can expand it for anything you'd like to reference.

Expand existing commands:

```bash
$ tldr sqlmap
  Detect and exploit SQL injection flaws.
  More information: <https://github.com/sqlmapproject/sqlmap/wiki/Usage>.

  Run sqlmap against a single target URL:

      python sqlmap.py [-u|--url] "http://www.example.com/vuln.php?id=1"

  Send data in a POST request (`--data` implies POST request):

      python sqlmap.py [-u|--url] "http://www.example.com/vuln.php" --data="id=1"

  Change the parameter delimiter (& is the default):

      python sqlmap.py [-u|--url] "http://www.example.com/vuln.php" --data="query=foobar;id=1" --param-del=";"

  Select a random `User-Agent` from `./txt/user-agents.txt` and use it:

      python sqlmap.py [-u|--url] "http://www.example.com/vuln.php" --random-agent

  Provide user credentials for HTTP protocol authentication:

      python sqlmap.py [-u|--url] "http://www.example.com/vuln.php" --auth-type Basic --auth-cred "testuser:testpass"

  Custom http-header injection, use the * :

      python sqlmap.py -u "http://www.target.com/vuln.php" -H="Cookie:id=1*"

  Options Breakdown

      --no-cast : disables casting/conversion of inferred data types
      --union-cols : specifies the amount of columns used for union queries
```

Or add entirely new ones, such as for mssql enumeration:

```bash
$ tldr mssql

  Schema Enumeration
      select * from INFORMATION_SCHEMA.SCHEMATA;

  Table Enumeration
      select TABLE_NAME from INFORMATION_SCHEMA.TABLES;

  Column Enumeration
      select * from INFORMATION_SCHEMA.COLUMNS;

  Role Enumeration
      select name FROM sys.database_principals WHERE type = 'R';

  Stored Procedure Enumeration
      select name FROM sys.procedures;

  Version
      select @@VERSION;

  Linked Servers
      select * FROM sys.servers;

  Sensitive Data
      select name FROM sys.tables WHERE name LIKE '%password%' OR name like '%secret%'
```


This, is extremely useful as a quick and dirt reference.

## Setup

Once you download the release;
```bash
$custom_note_path=$HOME/notes/tldr-notes/
tldr --seed-config && sed -i "/\[directories\]/acustom_pages_dir = \"$custom_note_path\"" ~/.config/tealdeer/config.toml
```

all NEW or REPLACEMENT pages are in the form of:

`<page_name>.page.md`

all pages that have ADDITIONAL content are in the form of:

`<page_name>.patch.md`

---
## Easy Aliases

To make this useful setup some aliases or functions (install fzf to make full use of them):

```bash
alias_file=~/.bashrc
cat << EOF >> $alias_file

function tldredit() {
   local note_path=~/notes/tldr-notes/
   local input_file=$(find "${note_path}" -maxdepth 1 -type f  | fzf --preview "bat --color=always {}")
   [[ -z $input_file ]] && return 1
   [[ -f $input_file ]] && ${EDITOR-vim} $input_file
}

function tldrnew() {
   local note_path=~/notes/tldr-notes/
   local note_name="${1}"
   local is_patch="${2}"
   local ext
   if [[ ! -z $is_patch ]]; then
      ext='patch.md'
   else
      ext='page.md'
   fi
   local new_file=${note_path}${note_name}.${ext}
   if [[ -e $new_file ]]; then
      echo "[[ Note: ${new_file} Exists! Try tldredit ]]"
      return 1
   fi
   ${EDITOR-vim} "${note_path}${note_name}.${ext}"
}
EOF
```







