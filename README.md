# 33C3 CTF 2016 : Exfil

**Category:** Forensic **Points:** 100 **Solves:** 137

> We hired somebody to gather intelligence on an enemy party. But apparently they managed to lose the secret document they extracted. They just sent us this and said we should be able to recover everything we need from it.
> Can you help?



## Write-up

For this challenge, we have a PCAP file and a Python server. It's clear that we have to recover a 'secret document' with this. Let see what we have :


### Python Server

We have a Python server which is used to communicate and execute commands over DNS, here are some interesting parts :

```python
...
from dnslib import * # dnslib
...
data = base64.b32encode(data).rstrip(b'=') # BASE32 Encoded
...
    chunk_size = 62
    for i in range(0, len(data), chunk_size): # Chunks every 62 chars
        chunks.append(data[i:i+chunk_size])
    chunks += domain.encode().split(b'.')
...
domain = 'eat-sleep-pwn-repeat.de' # Domain
...
def parse_name(label):
    return decode_b32(b''.join(label.label[:-domain.count('.')-1])) # No domain for the BASE32
...
class RemoteShell: # A little RemoteShell to execute commands and extract the secret document :)
...
```



### PCAP dump

Here is our PCAP :
```bash
$ file dump.pcap 
dump.pcap: tcpdump capture file (little-endian) - version 2.4 (Ethernet, capture length 262144)
```

Protocol hierarchy :
```bash
$ $ tshark -qr dump.pcap -z io,phs
===================================================================
Protocol Hierarchy Statistics
Filter: 
eth                                      frames:1804 bytes:306168
  ip                                     frames:1804 bytes:306168
    udp                                  frames:1804 bytes:306168
      dns                                frames:1804 bytes:306168
===================================================================
```

Communication : 
```bash
$ tshark -r dump.pcap -z ip_hosts,tree -q
===============================================================================================================================
IP Statistics/IP Addresses:
Topic / Item    Count         Average       Min val       Max val       Rate (ms)     Percent       Burst rate    Burst start  
-------------------------------------------------------------------------------------------------------------------------------
IP Addresses    1804                                                    0,0177        100%          3,4600        19,865       
 192.168.0.121  1804                                                    0,0177        100,00%       3,4600        19,865       
 192.168.0.1    1804                                                    0,0177        100,00%       3,4600        19,865       
-------------------------------------------------------------------------------------------------------------------------------
```


So, it looks like we have the server '192.168.0.1' and the enemy party '192.168.0.121' from where they extracted the 'secret document'.

From the Python Server code, we may be interested to extract the 'A' query and the CNAME response to anlyses them :

```bash
$ tshark -r dump.pcap -Tfields -e dns.qry.name -e dns.cname
```

First look, we have a lot of duplicate data. Then, I tried to figure out how exactly the server encode de communication. 
After several (hundreds...) test part by part and the domain name 'eat-sleep-pwn-repeat.de' removed, I was able to decode manually some some data with BASE32 :

Original query : `G4JUSBIXCV2G65DBNQQDKNSLBIZDMMRUGE4DIIDEOJ3XQ4RNPBZC26BAGMQGM4.DFORZHSIDGOBSXI4TZEA2C4MCLEBCGKYZAGE3SAMJTHIZTCIBOBIZDMMRRGQ2D.CIDEOJ3XQ4RNPBZC26BAGUQHE33POQQCAIDSN5XXIIBAEA2C4MCLEBCGKYZAGE.3SAMJTHIYDMIBOFYFDENRT.eat-sleep-pwn-repeat.de`
```python
>>> import base64
>>> print(base64.b32decode('G4JUSBIXCV2G65DBNQQDKNSLBIZDMMRUGE4DIIDEOJ3XQ4RNPBZC26BAGMQGM4DFORZHSIDGOBSXI4TZEA2C4MCLEBCGKYZAGE3SAMJTHIZTCIBOBIZDMMRRGQ2DCIDEOJ3XQ4RNPBZC26BAGUQHE33POQQCAIDSN5XXIIBAEA2C4MCLEBCGKYZAGE3SAMJTHIYDMIBOFYFDENRT'))
7Itotal 56K
2624184 drwxr-xr-x 3 fpetry fpetry 4.0K Dec 17 13:31 .
2621441 drwxr-xr-x 5 root   root   4.0K Dec 17 13:06 ..
263
```

We can see that from the server code, each query begins with 6 bytes which contain the the acknowledgement, conversation ID and sequence number. I simply removed it to decode all communication.

So, the idea here is, we need to : 
* Have one query/response per line to decode it easly
* Remove duplicate line
* Remove '.eat-sleep-pwn-repeat.de' and all '.' for each line
* Decode each line from BASE32
* Remove the first 6 bytes for each decoded line

PCAP Extraction, one query/response per line and unique one :
```bash
$ tshark -r dump.pcap -Tfields -e dns.qry.name | awk '!a[$0]++' > extracted.txt && tshark -r dump.pcap -Tfields -e dns.cname | awk '!a[$0]++' >> extracted.txt
```

Decode
```python
#!/usr/bin/env python2
import base64
with open("extracted.txt") as f:
    pcap_decoded = ""
    for line in f:
        s = ""
        l = line.split('.', line.count('.'))
        for i in range(line.count('.')-1):
            s += str(l[i])
        try:
            pcap_decoded += base64.b32decode(s)[6:]
        except:
            pass
decoded = open('decoded.txt', 'w')
decoded.write(pcap_decoded)
decoded.close()
f.close()
```

Got it!
[pcap_decoded.txt](https://github.com/zbetcheckin/33C3_CTF_2k16/blob/master/pcap_decoded.txt)

Wait a minute, not done yet, it looks like we have our 'secret document' encrypted... with the file and the key :)
```bash
...
2631216 -rw-r--r-- 1 fpetry fpetry 4.0K Dec 17 13:17 secret.docx
2631222 -rw-rw-r-- 1 fpetry fpetry 4.4K Dec 17 13:31 secret.docx.gpg
2631218 -rw------- 1 fpetry fpetry  908 Dec 17 13:21 .START_OF_FILE�L+�0�j
...
H��0ʟ�=END_OF_FILE
...
-----BEGIN PGP PUBLIC KEY BLOCK-----
lv+fGfdzCZnubp254S3mLsyokuyZ7xjy/i0m2a5fVQ==
=XS5g
-----END PGP PUBLIC KEY BLOCK-----
-----BEGIN PGP PRIVATE KEY BLOCK-----

lQOYBFhNxEIBCACokqjLjvpwnm/lCdKTnT/vFqnohml2xZo/WiMAr4h3CdTal4yf
...
```

We need to extract our secret.docx.gpg :
```python
#!/usr/bin/env python2
with open("decoded.txt") as f:
    s = f.read().replace('\n', '')
    start = s.index("START_OF_FILE") + len("START_OF_FILE")
    end = s.index("END_OF_FILE", start )
    secret = open('secret.docx.gpg', 'w')
    secret.write(s[start:end])
    secret.close()
    f.close()
```


secret.docx.gpg
```bash
$ file secret.docx.gpg
secret.docx.gpg: PGP RSA encrypted session key - keyid: 1B142B4C 6AA230BF RSA (Encrypt or Sign) 2048b .
```

Finally :
```bash
$ gpg --import pub.key
$ gpg --import private.key
$ gpg --decrypt secret.docx.gpg > secret.docx
```

Here we go, we have a nice [secret.docx](https://github.com/zbetcheckin/33C3_CTF_2k16/blob/master/secret.docx) with the flag :
```bash
$ file secret.docx
secret.docx: Microsoft Word 2007+
```

**Flag:**
The secret codeword is 
33C3_g00d_d1s3ct1on_sk1llz_h0mie
