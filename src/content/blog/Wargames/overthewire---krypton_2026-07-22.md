---
layout: post
pubDate: 2026-07-22
postType: Wargame
heroImage: ../../assets/posts/otw-krypton/banner.png
title: "OverTheWire - Krypton"
date: 2026-07-22
description: OverTheWire's Krypton Wargame
difficulty: Easy
scenario: 
tags: ['Write-Up']
---


## Overview

I haven't really messed with crypto stuff too much and Krypton feels like a nicer introductory to it. So here' sthis, which covers all levels of Krypton.

## Level 0
Presents a base64 encoded password, if you have `htmlq` you can easily grab it with one line.

```bash
curl -s https://overthewire.org/wargames/krypton/krypton0.html | htmlq -t code

## Output S1JZUFRPTklTR1JFQVQ=


curl -s https://overthewire.org/wargames/krypton/krypton0.html | htmlq -t code | base64 -d > krypton_passwords
```

From here out, we'll use sshpass and utilize our ssh_config to make things easy for us.

```bash
cat << EOF > ~/.ssh/config
Host krypton
    HostName %h.labs.overthewire.org
    port 2231
EOF
```

Now we can ssh easily.
```bash
lvl=0
(( lvl++ )); sshpass -p $(sed "${lvl}q;d" krypton_passwords) ssh krypton${lvl}@krypton

```
 The sed command prints the password at that line, so we can just incrememnt lvl and reuse the same command to ssh into our desired level :)



## Level 1  

This level presents a file that is ROT13'd


Two obvious ways present to me, you can use `tr` or more easily, `vim`

vim has a `g?` command which instantly ROT13's anything. We can load up vim or just run it non-interactively and be fancy.

```bash
vim -es -c 'normal ggVGg?' -c '%p' -c 'q!' krypton2

LEVEL TWO PASSWORD ROTTEN

```

Or the tr way:
```bash
tr 'A-Z' 'N-ZA-M' < krypton2
```


## Level 2

This one presents with another rotation cipher, but this time we're not given the key. We are given an binary that encrypts though, meaning we can obtain the key by just encrypting the alphabet.

It also gives us some setup instructions to make it work.

```
cd $(mktemp -d)
ln -s /krypton/krypton2/keyfile.dat
chmod 777 .
echo {a..z} > alphabet && /krypton/krypton2/encrypt ./alphabet
```

That results in some ciphertext being made in the directory.

`MNOPQRSTUVWXYZABCDEFGHIJKL`

This is easy enough. We can use `tr` again, as it gives out the layout to reverse it.

```bash
tr 'M-ZA-L' 'A-Z' < ciphertext

```
which reverses the cipher, now apply it to krypton3.


## Level 3

This time we don't know the cipher mechanism, but we do know it's english, so we can rely on frequency analysis.


The typical frequency I retrieved from this [page](https://universalium.en-academic.com/294558/Letter_frequency_distribution_for_a_sample_English_text):

Fancy bash lets us get them sorted.

```bash
curl https://universalium.en-academic.com/294558/Letter_frequency_distribution_for_a_sample_English_text -s | htmlq -t div | grep -P '^[A-Z]\s+.*[0-9]{3}' | sort -u | xargs -n 3 | sort -k3rn

```
```
E 8,915 .127 
T 6,828 .097 
I 5,260 .075 
A 5,161 .073 
O 4,814 .068 
N 4,774 .067 
S 4,700 .067 
R 4,517 .064 
H 3,452 .049 
C 3,188 .045 
L 2,810 .040 
D 2,161 .031 
P 2,082 .030 
Y 1,891 .027
M 1,675 .024
U 1,684 .024
F 1,488 .021
B 1,173 .017
G 1,113 .016
W 914 .013
K 548 .008
V 597 .008
X 330 .005
Q 132 .002
J 56 .001
Z 65 .001
```


```bash

python3 <<-EOF import string
frequency = {k:0 for k in string.ascii_uppercase}
filename = "/krypton/krypton3/found"
total = 0
for i in range(1,4):
    with open(filename+str(i), 'r') as f:
        content = f.read()
        for c in content:
            v = frequency.get(c)
            if v is not None:
                total += 1
                frequency[c] = v+1

print(f'Total Characters: {total}')
freqs = []
for k,v in frequency.items():
    freqs.append((k,v))
sorted_freq = sorted(freqs, key=lambda x: x[1], reverse=True)
print(sorted_freq)
for i in sorted_freq:
    print(f'{i[0]} {i[1]:03d} {i[1] / total:.3f}' )
EOF

python3 <<-EOF
import string
key = 0

with open("found3", 'r') as f:
    content = f.read()

while (key < 27):
    new_content = ""
    for i, v in enumerate(content):
        if v == ' ':
            new_content += " "
            continue
        new_i = (string.ascii_uppercase.find(v) + key) % 26
        new_content += string.ascii_uppercase[new_i]
    print(new_content)
    key += 1
EOF
            
            
            
    

```


We can put both results in files and paste them to see them close together.

```bash

krypton3@krypton:/tmp/tmp.o3XZDO5ceb$ paste eng freqs
E 8,915 .127 	S 398 0.130
T 6,828 .097 	Q 292 0.095
I 5,260 .075 	J 260 0.085
A 5,161 .073 	U 230 0.075
O 4,814 .068 	B 216 0.071
N 4,774 .067 	N 209 0.068
S 4,700 .067 	C 193 0.063
R 4,517 .064 	G 192 0.063
H 3,452 .049 	D 188 0.061
C 3,188 .045 	Z 116 0.038
L 2,810 .040 	W 113 0.037
D 2,161 .031 	V 109 0.036
P 2,082 .030 	Y 075 0.025
Y 1,891 .027	M 074 0.024
M 1,675 .024	T 069 0.023
U 1,684 .024	X 062 0.020
F 1,488 .021	K 055 0.018
B 1,173 .017	L 054 0.018
G 1,113 .016	E 051 0.017
W 914 .013	A 046 0.015
K 548 .008	F 023 0.008
V 597 .008	I 016 0.005
X 330 .005	O 010 0.003
Q 132 .002	H 004 0.001
J 56 .001	R 003 0.001
Z 65 .001	P 001 0.000
```

Then awk will help us see the direct translation:

```bash
krypton3@krypton:/tmp/tmp.o3XZDO5ceb$ awk '{print $1":"$4}' both
E:S
T:Q
I:J
A:U
O:B
N:N
S:C
R:G
H:D
C:Z
L:W
D:V
P:Y
Y:M
M:T
U:X
F:K
B:L
G:E
W:A
K:F
V:I
X:O
Q:H
J:R
Z:P


```

if you need the quotes for easy python fixing...
```
awk '{print "\""$4"\""":""\""$1"\""}' both
```

```bash

python3 <<-EOF
translation = {
"S":"E",
"Q":"T",
"J":"I",
"U":"A",
"B":"O",
"N":"N",
"C":"S",
"G":"R",
"D":"H",
"Z":"C",
"V":"L",
"W":"D",
"M":"P",
"Y":"Y",
"T":"M",
"X":"U",
"K":"F",
"E":"B",
"L":"G",
"A":"W",
"F":"K",
"I":"V",
"O":"X",
"H":"Q",
"R":"J",
"P":"Z",
}


file_name = '/krypton/krypton3/found'
for i in range(1,4):
    fname = file_name + str(i)
    with open(fname, 'r') as f:
        content = f.read()
    nc = ""
    for i in content:
        v = translation.get(i)
        if v is not None:
            nc += v
        else:
            nc += i
    print(nc)
EOF


```

If you look at that, it is...clearly incorrect. The only one that is likely to be 100% correct is S -> E.

How can we get the rest then?
The most reliable way is to move into bigrams, or add in a letter and see the relation betweem them.

[ Wikipedia ](https://en.wikipedia.org/wiki/Bigram) comes in handy

```bash
curl -s https://en.wikipedia.org/wiki/Bigram | htmlq -t pre | xargs -n 2 | sort -k 2nr

th 3.56%
he 3.07%
in 2.43%
er 2.05%
an 1.99%
re 1.85%
on 1.76%
at 1.49%
en 1.45%
nd 1.35%
es 1.34%
ti 1.34%
or 1.28%
te 1.20%
ed 1.17%
of 1.17%
is 1.13%
it 1.12%
al 1.09%
ar 1.07%
st 1.05%
to 1.05%
nt 1.04%
ng 0.95%
ha 0.93%
se 0.93%
as 0.87%
ou 0.87%
io 0.83%
le 0.83%
ve 0.83%
co 0.79%
me 0.79%
de 0.76%
hi 0.76%
ri 0.73%
ro 0.73%
ic 0.70%
ea 0.69%
ne 0.69%
ra 0.69%
ce 0.65%
```


So now we need the ratios of our example text.


```bash

python3 <<-EOF
from collections import defaultdict

bigrams = defaultdict(int) 
file_name = '/krypton/krypton3/found'
total_bigrams = 0
for i in range(1,4):
    fname = file_name + str(i)
    with open(fname, 'r') as f:
        content = f.read()
        content = content.replace(' ', '')
    for n in range(0,len(content), 2):
        bigram = content[n:n+2]
        total_bigrams += 1
        bigrams[bigram] += 1
print(f'Total Bigram Count: {total_bigrams}')
unsorted = []

for k,v in bigrams.items():
    unsorted.append((k,v))
s = sorted(unsorted, key=lambda x: x[1], reverse=True)
for k,v in s:
    print(f"{k} {v:02d} {v/total_bigrams:.03f}")
EOF

```


Running that gives us this snippet:
```

Total Bigram Count: 1764
DS 47 0.027
JD 42 0.024
SN 35 0.020
QN 31 0.018
SU 30 0.017
DQ 28 0.016
QJ 26 0.015
NS 26 0.015
BG 25 0.014
CG 24 0.014
UJ 23 0.013
SQ 23 0.013
SW 23 0.013
JS 22 0.012
GW 20 0.011
NQ 19 0.011
DC 19 0.011
CU 19 0.011
JC 19 0.011
QG 18 0.010
GJ 18 0.010
```


We're confident that S -> E; so we can garner that `HE` is the digram we're looking at the top.So D -> H.
Which should mean that:

S -> E

D -> H

J -> T

N -> R

Q ->  A (since EO basically never happens)

U -> N or S


Orginal Mapping:

```

SQJUBNCGDZWVYMTXKLEAFIOHRP
ETIAONSRHCLDPYMUFBGWKVXQJZ
```

New Mapping solely based on bigrams:
```

SQJUBNCGDZWVYMTXKLEAFIOHRP
EATSOR..HCLDPYMUFBGWKVXQJZ
EATNOR..HCLDPYMUFBGWKVXQJZ
```

Tring both variants we see the first where U = S works a lot better.
We can see words like "SHAKESPEARE" in the text.

Particularly:

`LDEGE .LTHA TSHAK ESPEA REUDE LTHET OF.UO RDO.L O.TOE SCAPE PROSE CYT.O .UORL EE`

The ending portion seems like it wants to say "To Escape Prosecution"
So to adjust our mapping for that...

We'll do some indexing to make sure we're looking at the right stuff.

```bash
cat /krypton/krypton3/found2 | tr 'SQJUBNCGDZWVYMTXKLEAFIOHRP' 'EATSOR..HCLDPYMUFBGWKVXQJZ' | grep 'LDEGE .LTHA TSHAK ESPEA REUDE LTHET OF.UO RDO.L O.TOE SCAPE PROSE CYT.O .UORL EE' -bao
1530:LDEGE .LTHA TSHAK ESPEA REUDE LTHET OF.UO RDO.L O.TOE SCAPE PROSE CYT.O .UORL EE

## Now we index that
dd if=/krypton/krypton3/found2 bs=1 skip=1530 count=80 status=none
WVSES GWJDQ JUDQF SUYSQ NSXVS WJDSJ BKGXB NVBGW BGJBS UZQYS YNBUS ZMJCB GXBNW SS
```



```

WVSES GWJDQ JUDQF SUYSQ NSXVS WJDSJ BKGXB NVBGW BGJBS UZQYS YNBUS ZMJCB GXBNW SS
LDEGE .LTHA TSHAK ESPEA REUDE LTHET OF.UO RDO.L O.TOE SCAPE PROSE CYT.O .UORL EE
                                                  TOE SCAPE PROSE CUTIO N
SQJUBNCGDZWVYMTXKLEAFIOHRP
EATSORINHCDPUM.FBGWKVXQJZ

```

Doing this same pattern for some other files, helps move the mapping, suggesting my W->L mapping is actually W->D
So I just switchd them.

And you can tr for this now, as it's easier.


```

SQJUBNCGDZWVYMTXKLEAFIOHRP
EATSORINHCDLPUM.FBGWKVXQJZ

```

This shows that  L -> Y:

```
SQJUBNCGDZWVYMTXKLEAFIOHRP
EATSORINHCDLPUM.FYGWKVXQJZ

```

X -> F:

```
SQJUBNCGDZWVYMTXKLEAFIOHRP
EATSORINHCDLPUMF.YGWKVXQJZ


```

A -> B:

```
SQJUBNCGDZWVYMTXKLEAFIOHRP
EATSORINHCDLPUMF.YGBKVXQJZ
```

K -> W:

```
SQJUBNCGDZWVYMTXKLEAFIOHRP
EATSORINHCDLPUMFWYGBKVXQJZ

```

And that, looks like it works perfectly well for all our solutions.



## Level 4


This is vignere cipher, and we have two again. The hint says we should do some frequency analysis but as a "slice" of the key length.

So if we split every 6 characters and take the columns 1-6 we should be able to get a reliable statistic.

```bash
cd (mktemp -d)
fold -w 6 <(tr -d ' ' < /krypton/krypton4/found1 ) | head -n -1  > letters

cat << EOF > joiner.py
import sys
lines = [line.rstrip("\n") for line in sys.stdin if line.rstrip("\n")]
for col in zip(*lines):
    print("".join(col))
EOF

python3 joiner.py < letters

```

This outputs:
```

YIYWNQRLYTRHYDJTWZSLNNHTMJJYFNYIJJSLWNMFXBBKXIMJTBMIYJJNTYBWKWWLFGWISJSZYSYPJNFJQFWTYWKJJMMNSYWKYSAYMTSQZJRFDMKXFJJPKFSTTTJMBMJDSQIJPFJTSJWJPJIKXISJFFYXMQMYIMZYFSJWJNTWGJYGZTMTYSFFJTWJQBSFSJSJIJJNKWSXZYZKXMSSIFTXSSKTJTYWMYKLTISNJFITWIXNBSJHJ
YZYVJVKYIWVZZIUFVRFRMJVTVTJKTJSKGCVRFVZUKZZKKUPZRVVZYJVJXNKVZZVZKVVKWEFRYKYZNEEPYMYKYVFRJVRWKYUKVVVIVIRCXNRMFVKKBWZVZEFNUPVVYVKFFKYPVEYUUUUJZIJKUYUNZEVUPNVPIVKYTFIZWKCXLNYFEJRCJTEJRKVVURCIUPTXSIICFVFEJYEKKVUKZWFLVKRINKFKRYFYKKUFKEFERWCKFRJIG
IIXIOHLXIXVXPIXQXVJXISVOMXXLOKSLSCHXYRGPSGXLESXWHVKEIRZLSELARRHVAITLSWAVIVIIMHHSIIEWIGVRXVXJWIMLWLVSVIXCLSOIYLLFISWHIHXCILTAIWWYXSIXHHMFXXXXRJSKSIXMWHVSWSTWILSIIAWWSASVXLIRHRHSKSHAWLWQGWIFEEIVISEPVAJSIMXLEKAMRXRRLLGXIVSLHEVXLSXRMHAXWIILSRGSM
CBRXODBRORKIDKRGRNDONPEOBKYOSBHOVYDOBNRODUMOCBRXKOEXQYOODIOONADVSKVOBRCOMIGCVIWEBCZKCBGDBYSOKQKOXKNILCEDDEOCKKOEMBGKBWKYCODOBEKMPPBRRLWIEYRGQSPBDBRDSLMBDBBSCKXZLDEOEKXOZSBKDOKCBVGRNICOSCPOCNNYMEXSDOKBCCBOXBKVDODCYOORBOPOODONIDRGBVXRCVODNNKGX
SAIAVLSIXIPYLGILIMLWXJRHWGTQRIERMTLJJWVELILAOSISRHESESVWLLRXLYLXPWMQAICMSSMWPSEEWTWMGSISSLWVMYRKSWIIISVLWPWSWWVXEWMRGEPYXVSWIRREEMXEMEKIVAIESIWEXIILIYYSMIIPWHMEYSVWRWKIYXMVSGPXISEMSWXVXSXLXZXYEKHILVVLMGCAHSWPLVLLXMWIIIJQWFRSESIIIEYIEPTLQXVOK
JGEFQCSQQCBLCFPCEYCJFGJRNJSZFYLFRCCMPUMBCBMCCRPPQRPDRLURYMYMCGCFJWCYFIMLSDLFDSIJJCLBYUKBWRBCBYMYMCQBDGYMFBJDQMCRPFABCWJRPIRRRQBLGLFLKBMYLYUJTJMQCYPBQRNRJRRIQNLJRFNFBLCLPCZMRIQGCPQRPBFYWMDGFYFLKFFPCCKMLMMCRSSCCLCMGPDPLQCQMCGPLYJPBWNELYUCYFCCU
```


Which we can run a frequency analysis 

```

python3 <<-EOF
from collections import defaultdict
f1,f2,f3,f4,f5,f6 = defaultdict(int),defaultdict(int),defaultdict(int),defaultdict(int),defaultdict(int),defaultdict(int),
diks = [f1,f2,f3,f4,f5,f6]
filename = "cols_split"
with open(filename, 'r') as f:
    for i, lines in enumerate(f, start=0):
        diks[i]['total'] = len(lines)
        for l in lines:
            diks[i][l] += 1

freqs = []
for i,d in enumerate(diks):
    print(f'==== Column {i} ===')
    with open(f'col{i}.txt', 'w') as f:
        for k,v in d.items():
            f.write(f'{k} {v:03d} {v/d['total']:.03f}\n')            
            print(f'{k} {v:03d} {v/d['total']:.03f}')

EOF
for k,v in frequency.items():
    freqs.append((k,v))
sorted_freq = sorted(freqs, key=lambda x: x[1], reverse=True)
print(sorted_freq)
for i in sorted_freq:
    print(f'{i[0]} {i[1]:03d} {i[1] / total:.3f}' )
EOF


```


We assume most top letters are E.

```bash

for f in col{0..5}; do cat $f.txt  | tail -n +2 | head -n -2 | sort -k 2nr| head -4 ;printf "\n"; done
J 037 0.153
S 024 0.099
Y 022 0.091
T 020 0.083

V 035 0.145
K 031 0.128
F 019 0.079
Y 019 0.079

I 034 0.140
X 030 0.124
S 027 0.112
L 022 0.091

O 037 0.153
B 026 0.107
D 022 0.091
K 021 0.087

I 032 0.132
S 026 0.107
W 024 0.099
L 021 0.087

C 033 0.136
R 020 0.083
F 019 0.079
L 019 0.079
```


"Reference:
"
E 8,915 .127 	S 398 0.130
T 6,828 .097 	Q 292 0.095
I 5,260 .075 	J 260 0.085
A 5,161 .073 	U 230 0.075
O 4,814 .068 	B 216 0.071
N 4,774 .067 	N 209 0.068

```bash
python3 <<-EOF

import string
upper = string.ascii_uppercase
top_letters = ['J', 'V', 'I', 'O' ,'I', 'C']
def printletters(n, *args):
    text = ""
    for i in args:
        text += f'{upper[(n-i) % 26]} | '
    print(text)

for c in top_letters:
    n = upper.find(c)
    e = upper.find('E')
    t = upper.find('T')
    a = upper.find('A')
    i = upper.find('I')
    o = upper.find('O')
    printletters(n,e,t,a,i,o)

EOF

```

Gives us :
```

F | Q | J | B | V |
R | B | U | M | G |
E | P | I | A | U |
K | V | O | G | A |
E | P | I | A | U |
Y | J | C | U | O |
```

Then we'll see how these look...

```bash
python3 <<-EOF
import string
u = string.ascii_uppercase

KEYS = ['FREKEY', 'QBPVPJ', 'JUIOIC', 'BMAGAU', 'VGUAUO' ]
with open('/krypton/krypton4/found1','r') as f:
    cipher = f.read().replace(' ', '').strip()

def decipher(key, cipher):
    ptext = ""
    for i,c in enumerate(cipher):
        if c in u:
            c_idx = u.find(c)
            k_idx = u.find(k[ i % len(k)])
            p_idx = (c_idx - k_idx) % 26
            ptext += u[p_idx]
        else:
            ptext += c
    print(f'KEY: {k}')
    print(ptext)
    print()
        

for k in KEYS:
    decipher(k,cipher)

EOF

```

Looking at that output, it looks like 'FREKEY' is the correct version.  Nice!

Now just use the above, and get the pass.

```bash

python3 <<-EOF
import string
u = string.ascii_uppercase

with open('/krypton/krypton4/krypton5','r') as f:
    cipher = f.read().replace(' ', '').strip()

def decipher(key, cipher):
    ptext = ""
    for i,c in enumerate(cipher):
        if c in u:
            c_idx = u.find(c)
            k_idx = u.find(k[ i % len(k)])
            p_idx = (c_idx - k_idx) % 26
            ptext += u[p_idx]
        else:
            ptext += c
    print(f'KEY: {k}')
    print(ptext)
    print()
        

decipher('FREKEY',cipher)

EOF

```



## Level 5

This is another one, however we don't know the key length!
So we kind of have to combine a little of everything before...so instead of rewriting a whole bunch of inline python, let's make a script. It'll implement kasisiki examniation and index of coincidence. Together they'll be able to give us the likely key length and from there we can try again to determine the key from the frequencies.

The script I made is [here](https://codeberg.org/chin-tech/krypton-vignere.git)

However the relevant bits are the IoC and Kasiski examniation.

This is the index of coincidence.

```python
def calculate_ioc(text: str) -> float:
    N = len(text)
    if N <= 1:
        return 0.0
    counts = defaultdict(int)
    for c in text:
        if c.isalpha():
            counts[c.upper()] += 1 
    numerator = sum(f * (f - 1) for f in counts.values())
    denominator = N * (N-1)
    return numerator / denominator

def analyze_ioc(text: str, max_len: int = 15):
    scores = list()
    print(f"{'-'*5} Index Of Coincidence {'-'*5}")
    for klen in range(1, max_len + 1):
        cols = columnize(text,klen)
        avg_ioc = sum(calculate_ioc(s) for s in cols) / klen
        scores.append((klen, avg_ioc))

        bar = "#" * int(avg_ioc * 500)
        marker = " <-- [Likely Key Length]" if avg_ioc > 0.060 else ""
        print(f"{klen:<12} | {avg_ioc:<12.4f} | {bar}{marker}")
    print()
```

It basically samples the text to find the probability that two random letters are the same. Which for english is about 0.067. So anything close to that would be a likely candidate.

So we take "guesses" of the key length, split by columns and calculate the average IoC for each column for each key length.  Nice idea yeah?

Kasiski Examination is another method, which looks for repeating sequences, then measures the distance between them and gets the factor. The idea is that the key is going to repeat, so the factor should show.

```python
def kasiski_examiniation(text: str, seq_len: int=3) -> list[tuple[int,int]]:
    sequences = defaultdict(list)
    for i in range(len(text) - seq_len + 1):
        seq = text[i:i + seq_len]
        sequences[seq].append(i)
    distances = list()
    for seq,idx in sequences.items():
        if len(idx) > 1:
            for i in range(len(idx) - 1 ):
                distances.append(idx[i+1] - idx[i])
    factor_counts = Counter()
    for d in distances:
        for f in range(2,21):
            if d % f == 0:
                factor_counts[f] += 1

    print(f"{'-'*5} Kasiski Examniation {'-'*5}")
    print(f"{'Candidate Key Length':<22} | {'Factor Hits'}")
    print("-" * 35)
    for factor, count in factor_counts.most_common(8):
        print(f"{factor:<22} | {count}")
    print()

    return factor_counts.most_common(10)
```

and running the script gives us this for all candiates:

```
./vig.py -f /krypton/krypton5/found3 -a
----- Kasiski Examniation -----
Candidate Key Length   | Factor Hits
-----------------------------------
3                      | 165
9                      | 142
2                      | 98
6                      | 83
18                     | 79
4                      | 43
5                      | 41
7                      | 37

----- Index Of Coincidence -----
1            | 0.0408       | ####################
2            | 0.0409       | ####################
3            | 0.0488       | ########################
4            | 0.0406       | ####################
5            | 0.0407       | ####################
6            | 0.0492       | ########################
7            | 0.0402       | ####################
8            | 0.0406       | ####################
9            | 0.0625       | ############################### <-- [Likely Key Length]
10           | 0.0409       | ####################
11           | 0.0408       | ####################
12           | 0.0495       | ########################
13           | 0.0404       | ####################
14           | 0.0402       | ####################
15           | 0.0486       | ########################
```

Which points to a key length of 9.

Running the script, it will automatically try lengths of 9 and we get a close first hit:

```bash

./vig.py -f /krypton/krypton5/found1 -g -c 9
Column 0: B: 20, O: 17, C: 17
Column 1: I: 26, S: 18, X: 17
Column 2: C: 28, R: 16, M: 16
Column 3: P: 23, E: 17, L: 12
Column 4: I: 27, X: 15, M: 14
Column 5: R: 20, G: 18, N: 17
Column 6: G: 19, Z: 17, K: 14
Column 7: X: 26, T: 18, K: 16
Column 8: L: 27, V: 25, A: 16
KEY: XEYLENCTH
DECODED:
VTWASTLEBRSTOFTMMEFITWASXHEJORSTOJTIZESITWESTUEAGEOJWIFDOMITAASGHEAGESFFBOLISHRESFITWASXHERPOCHOJBEYIEFITAASGHEEPOGHOSINCREHULVTYITWESTUESEASSNOSLIGHTMTWNSTHESIASBNOFDAVKNRSSITWESTUESPRIRGOSHOPEIXWAFTHEWIRTEEOFDESTAIEWEHADIVEEYTHINKBESOREUSAEHNDNOTHMNGOEFOREYSWRWEREAPLGBINGDIVECGTOHEAZENJEWEREELLTOINGDMREPTTHEOXHEEWAYINWHOETTHEPIRIBDWASSSFAELIKETLEPEESENTTERVODTHAXSOZEOFITWNOVSIESTEUTUORITIISIASISTEHONVTSBEIRGRRCEIVEHFOEGOODOVFOEEVILIRTHRSUPERPATVVEDEGVEEBFCOMPERIFONONLCTHRREWERIAKVNGWITLALNRGEJAAANQAQUEERWIGHAPLAMNFNCEONTLETURONEOJENTLANDTLERRWEREAOINTWITHAPARTEJAWARDADUEENWMTHNFAIRFECEBNTHETLROAEOFFRENCRINBOTLCOHNTRIEWITJASCLEEREETHANCVYSGALTOTLELBRDSOFXHEFTATEPVESRRVESOJLONVESANHFIFHESTHETTUINGSIRGEAERALWIREFETTLEHFOEEVERIXWAFTHEYEEROSOURLOVDOAETHOUWANQSEVENLUNQREDANHSEIENTYFMVEFPIRITYALEEVELAXIOASWEREGONPEDEDTSENTLANDAXTHNTFAVOYREQPERIOHASNTTHISQRSFOUTHCSTTUADRECINTYYATTAMNEQHERFIZEAADTWENXIEGHBLESWEDOIRTHDEYOSWHOMATROCHETICTRIIATEINXHEYIFEGUERDFHADHEVALQEDTHEWUBYIMEAPTEAEANCEBCANAOUNCIRGTUATARRENGRMENTSAERRMADEFSRTUESWALPOWVNGUPOJLOADONANHWEFTMINSXERRVENTHICOPKLANEKHOFTHADBIENYAIDONPYAEOUNDDSZEAOFYEAVSASTERRATPIAGOUTIXSMRSSAGEWASGHESPIVITFOFTHIWVEEYYEARPASGPASTSYPEENATURELLLDEFICMENGINORIKINNLITYREPPRDOUTTLEIESMEREQESFAGESIRTHREARTHPYOEDEROFIVEATSHADPATRLYCOMITOGHEENGPISUCROWNENDCEOPLEJROZACONGVESFOFBRIXISUSUBJEGTSVNAMERMCAJHICHSXRAAGETORILAGEHAVETROIEDMORIIMCORTANXTOGHEHUMENRNCETHARANLCOMMURICNTIONSCETEECEIVIDTUROUGHENYBFTHECLICXENSOFXHEPOCKLAREBEOOD

KEY: KONATCVPR
DECODED:
IJHLDESIREIEZQETQUSYEHLDELUWECDEZQXYMUDTEHLWJHULRPZQAYSTZXTEHEITXPLRPZJVOEWTDSYIISYEHLDELUEFZNSZQFULYPQTEHEITXPPAZNLEFYYNCPOYBIJJTEHLWJHUDPLDZREFBTRSETXMAIESPDPEIODZQOLCODEIDTEHLWJHUDACTYKEFXZAPTEAQSJSPHTYXUREQOPDAEYRMPSLOPZUROESTYRFUFECPFDHIXATYZESTRWBUQZCPFWMEMPCPLWPWOYYROTCISTJZSPLGIDWUHPCPLPBGETYROTVUCJESPZELURMLJTYDLERJESPAPVYOTHLDDZJQRBTVPESIFRUDPYEAIHIEOESLEWEMUZQTEDREIITPDELYJHECTETPWYNITDEPOSDIJDMPTYKHESPTGPOJERWZZOZCJERUGTWTYXXEIFAPCWEJILPOPRCIUOVNZXALVYSEYZYWJXXEHPHPCPEAIDRHTESEBAHRPULHEDDQBFPPYAYTXLAWLTRVASPZYESIJHHZYPZQIDGBLYOESIHEMPCPLVMDGMTESLWEHGUULHLYHQQKPPYHTXXAVLTCQLGUODESPESVENUZQQCLRSEYYMZESGEUDECTPDMJWQDNWPLVURJSLYNCCITQWEZESIBOHODZQELUSJLEPACIIEHGPDZQPEALPDLYOJYSXPDESLXJHYYRDTYKUNUCLWHPVUSUEEWPOJERUGPCTEAQSJSPJPLVEFEFCWZCHENUESZFDEDDIPGPYSYDDHPOLYOWUVUYEJQTZUSFTCTEFEBRUGPWLEMENIHPCPNSDCUOPOEZIDGBLYOLEXXAJQLGZFVUDFPCTZOEIAJESTDXVISEFESNZXJHQOCPNPRJLOLEELTRUDXPCQTGIQNTEHPYEMUTXMWPDDITBYCESOLCEFMSZXLAVEPXPETNAVYVQEPTYELULYQPRFLVTSXLOSPCEBDUOESPDYRLYXPLAAIQRQYNPMJEDNEFYNTYKJHQELCCLRWECPYEDHIHECLOPQZVJHUDHLWWSMIDRFAZQPENTZYLYOAUSJXTYDEIHELPYESPGECAWLYPRLESJSLOMPIDLQTOZYWCQREFYOOZDUNEQJPLCWQFJPCCLATYNWZFETEWCEIDLRPDEITXPDATCMJSEQESTDZUROJPLCWEITFLDEDFTURDLEFCLPBYTPQTNTIDTYYZCTRMDABTEJCLTFETZFEESIYRIXPCPXIISQRPDTYXXEULCESWCERTPCZQPZUNJDSLOWEJEBJNZXPXETXPPYRWMIHSCZHYLRTPUZAWPQVEMQNZYRCIISEQMCTEMIHIFMUPNXIIDLXPCTGQWXTNSDEVQNWPEZCPPQTUSLGPAVEVUOXZCPMCPECELYEXETXPSFXLRHASPESLYEDYSZXXFYMSAJTZYDJIJRUNPTGPHJHHZFRSLROOVESPNSMSKUYDZQELUCENVWLYIRREZO

KEY: YTIHIJGGW
DECODED:
UEMEOXHRMQDJSBXIZPETJAWWTUPIZHWPSFGTYPIMPAAFETPQKASFJTEOEQEXWNDFSUECIOSQAZBMOLNRDETJAWWTUPQAEGDSFOPXTUJEXWNDFSUILSCUZRTDGNIDHWUEOMPAAFETPIIWWOAZRWYKDXIGHMDJLAWENDAYEJZERXYQDIMPAAFETPITNMNTZRSETAMTJLEEXISMNGPDZVHAWPNTDHULWHEIPDJJLERGOPRZHIQWWRSMODSPLIARNPVSNIUFHQHUVAELYRATDKZMRRNFEELAEVRYIPMINIAYWSZYRCHIEPOEJLASTUPDHQCERSUZDEJLATEETAOMEOWOSLDWYOAXHRADPIIJXPRCUZTXDETFZYPEJEXSAZUDYIOXAHETZHMPMEFTZDYWPIDBYUEIFAMNTCQNUMRIDSZDRESZSRSZDPLMHMNGSQDKTAVLNEUGUHAKRRPAQSSITAETEZDSJPYGSQCUAAVENVUYWAEXHNWMCWIFEWNYPLGYAINJTFSQTHEIAQMNUSJXHRETCERASFRYSWQRZXHRCQHUVAEKVYSHYXDELNCSPZESENQLCFUIJAIGSMQQMNJAPPAYJLAXHEZZPEJBVAANQTDFKXHPZGYJVEISVEILIGHIAEPDEXEJGRLDFLBXKXHRWACTWKJTUPEEQXATRRDQCLIOSFYZMGUWWRDSTESUWPLAGETTDKOMNTPZPHEHAEEPEPJXHIDSZDPLINMTJLEEXIUIAEZRZKVHSRQZZPJLKYSNYPDUZARHHYPCUHWRDFPHPDXUJIIPEAYVEXUNWDPLIHETVZZDMINICBYOPTIZXORYSWQRZETGSMEVERSUEPPAUVESDNDMEJLEWMEDEZKXDGOGETLTVAGEAEXJQXPEIAPPSUVBMVRLZOJAARTVPFSRPAWSRONTHXDHALZRHXSIEPEZBSUXEGPETHLJIERTUPXTVICYAEOESQHDIRNWPPTXDISHMXTCIWTPRLDLDGAFYNYZZKRYMNTETLJENVAARQXURPWWRCQXQHAJOEETPIAWPLBHUYWYLSFYZZOERWRDJPEECMJWTRCQGURPLEPZOVBEJIGUZEEXEZFERYXLYHKRLLLDZKRZHOMPZZVCAERFLREUVNEPCTZREYPMTFXQDIECISNDFSUWLMRVEEZVXDMSIPDJOIWVLNDFAQWPWUCPDYQXQVAYWKOUJEGIRYFTDSNMGVYMWYXUVACAQOEYPXHRTDDCINIMRDELWIOMNGSQPQVPLLLZDOUVKJEIPZEILWHLNEQWOGKQEGZFSUIJKLVDTNHSSRAAOBPETHIFEZYLSSJKRRDEZVFNMTVDTDKFFICGDUYQQAVIPLISYGDWTELZRUXKVEYLFPXERIPEZHPTQKVEVXBZHXWRTGZFSULQQAACMNUXDENNYKNEQIYNVNMEYSJWYREDPSIEZEQETCEYCLAAJAQJLAGHVNWPDWKJTUPOZSOHENRMDZEH
```

Classic "IT WAS THE BEST OF TIMES IT WAS THE WORST OF TIMES"

So the first key is the closest, we just need a few changes to make it perfect. My first suspicion is KEYLENGTH since, that's the closest actual word to it...

```bash

./vig.py -f /krypton/krypton5/found1 -d KEYLENGTH
KEY: KEYLENGTH
DECODED:
ITWASTHEBESTOFTIMESITWASTHEWORSTOFTIMESITWASTHEAGEOFWISDOMITWASTHEAGEOFFOOLISHNESSITWASTHEEPOCHOFBELIEFITWASTHEEPOCHOFINCREDULITYITWASTHESEASONOFLIGHTITWASTHESEASONOFDARKNESSITWASTHESPRINGOFHOPEITWASTHEWINTEROFDESPAIRWEHADEVERYTHINGBEFOREUSWEHADNOTHINGBEFOREUSWEWEREALLGOINGDIRECTTOHEAVENWEWEREALLGOINGDIRECTTHEOTHERWAYINSHORTTHEPERIODWASSOFARLIKETHEPRESENTPERIODTHATSOMEOFITSNOISIESTAUTHORITIESINSISTEDONITSBEINGRECEIVEDFORGOODORFOREVILINTHESUPERLATIVEDEGREEOFCOMPARISONONLYTHEREWEREAKINGWITHALARGEJAWANDAQUEENWITHAPLAINFACEONTHETHRONEOFENGLANDTHEREWEREAKINGWITHALARGEJAWANDAQUEENWITHAFAIRFACEONTHETHRONEOFFRANCEINBOTHCOUNTRIESITWASCLEARERTHANCRYSTALTOTHELORDSOFTHESTATEPRESERVESOFLOAVESANDFISHESTHATTHINGSINGENERALWERESETTLEDFOREVERITWASTHEYEAROFOURLORDONETHOUSANDSEVENHUNDREDANDSEVENTYFIVESPIRITUALREVELATIONSWERECONCEDEDTOENGLANDATTHATFAVOUREDPERIODASATTHISMRSSOUTHCOTTHADRECENTLYATTAINEDHERFIVEANDTWENTIETHBLESSEDBIRTHDAYOFWHOMAPROPHETICPRIVATEINTHELIFEGUARDSHADHERALDEDTHESUBLIMEAPPEARANCEBYANNOUNCINGTHATARRANGEMENTSWEREMADEFORTHESWALLOWINGUPOFLONDONANDWESTMINSTEREVENTHECOCKLANEGHOSTHADBEENLAIDONLYAROUNDDOZENOFYEARSAFTERRAPPINGOUTITSMESSAGESASTHESPIRITSOFTHISVERYYEARLASTPASTSUPERNATURALLYDEFICIENTINORIGINALITYRAPPEDOUTTHEIRSMEREMESSAGESINTHEEARTHLYORDEROFEVENTSHADLATELYCOMETOTHEENGLISHCROWNANDPEOPLEFROMACONGRESSOFBRITISHSUBJECTSINAMERICAWHICHSTRANGETORELATEHAVEPROVEDMOREIMPORTANTTOTHEHUMANRACETHANANYCOMMUNICATIONSYETRECEIVEDTHROUGHANYOFTHECHICKENSOFTHECOCKLANEBROOD
```


## Level 6


Level 6 brings in stream ciphers. We get an encryptor to arbitratily encrypt things which is great.

Environment setup:

```bash

k=/krypton/krypton6
cd $(mktemp -d) && ln -sf $k/keyfile.dat && chmod 777 .
```

Now the easiest thing to do with things like this is to see if the same message gets encrypted the same, and then have the same message repeated to see if the encryption repeats at all.

```bash
echo 'meow' > t1
$k/encrypt6 t1 tc1
$k/encrypt6 t1 tc2

paste tc{1,2}
QMQP	QMQP
```

So that's a good first sign, there's no "randomness" that is consistently padding it.

Now for a long string:
```bash
python3 -c 'print("a"*512)' > p1
$k/encrypt6 p1 c1
cat c1


EICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEI
```


And you can glance and see that this seems to be repeating...by how much? I don't like counting.

```bash
grep -bao 'EICTDGY' c1
0:EICTDGY
30:EICTDGY
60:EICTDGY
90:EICTDGY
120:EICTDGY
150:EICTDGY
180:EICTDGY
210:EICTDGY
240:EICTDGY
270:EICTDGY
300:EICTDGY
330:EICTDGY
360:EICTDGY
390:EICTDGY
420:EICTDGY
450:EICTDGY
480:EICTDGY

fold -w 30 c1

EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
```


So it seems to repeat every 30 characters. This lets us do a nifty trick actually.

Because it's 30 characters and we know that 'A' the only character, the offset is based on index (even though it's technically calculated) so we can use this our advantage.

```bash
python3 <<-EOF
import string
known_cipher = 'EICTDGYIYZKTHNSIRFXYCPFUEOCKRN'
u = string.ascii_uppercase
def get_content(in_file):
    with open(in_file, 'r') as f:
        return f.read().replace(' ', '').strip()
encrypted = get_content('./c1')

plain = ""
for i,c in enumerate(encrypted):
    shift = (u.find(known_cipher[i % 30]) - u.find('A')) %26
    original = (u.find(c) - shift) % 26
    plain += u[original]
print(plain)
EOF

```

Which gives us our 'A's back, and we can then read the password with the same technique.

Which lets us to the next level.

## Level 7

```bash
sshpass -p "$(sed "${lvl}q;d" krypton_passwords)" ssh krypton${lvl}@krypton -q "cat /krypton/krypton7/README"
Congratulations on beating Krypton!
```


That's all folks!

