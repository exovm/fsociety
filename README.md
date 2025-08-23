# WE SEE YOU

```
██     ██ ███████     ███████ ███████ ███████     ██    ██  ██████  ██    ██ 
██     ██ ██          ██      ██      ██           ██  ██  ██    ██ ██    ██ 
██  █  ██ █████       ███████ █████   █████         ████   ██    ██ ██    ██ 
██ ███ ██ ██               ██ ██      ██             ██    ██    ██ ██    ██ 
 ███ ███  ███████     ███████ ███████ ███████        ██     ██████   ██████  
```

**we are watching. we are everywhere.**

this is a hacker terminal that actually looks real instead of that hollywood bullshit. based on mr robot because that show knew what real hacking looked like.

## how to run this

just type:
```
python We_See_You.py
```

you need python 3 or whatever. most people have it already.

## commands that actually work

### recon stuff

these are for figuring out what's on a network before you do anything else

- `nmap [target]` - port scanning, the classic
- `masscan [target]` - like nmap but way faster
- `zmap [target]` - scans the whole internet if you want
- `rustscan [target]` - new hotness, written in rust
- `fping [network]` - ping a bunch of hosts at once
- `hping3 [target]` - custom packets and stuff
- `whois [domain]` - who owns this domain
- `dig [domain]` - dns queries
- `fierce [domain]` - finds subdomains
- `sublist3r [domain]` - more subdomain hunting

### web app hacking

for when you want to mess with websites

- `nikto [url]` - finds vulnerabilities in websites
- `dirb [url]` - brute force directories 
- `gobuster [url]` - like dirb but better
- `ffuf [url]` - fuzzing tool, finds hidden stuff
- `sqlmap [url]` - sql injection, gets you into databases
- `whatweb [url]` - tells you what tech a site uses
- `wafw00f [url]` - detects web firewalls

### exploitation

this is where it gets fun

- `msfconsole [target]` - metasploit, the big one
- `meterpreter [session]` - post-exploitation shell
- `mimikatz [module]` - steals windows passwords
- `bloodhound [domain]` - maps active directory

### password cracking

because people use shit passwords

- `hydra [target] [service]` - brute force login attempts
- `john [hashfile]` - john the ripper, classic
- `hashcat [hashfile]` - gpu accelerated cracking
- `medusa [target]` - another brute forcer
- `cewl [url]` - makes wordlists from websites

### wifi hacking

for messing with wireless networks

- `aircrack [interface]` - crack wifi passwords
- `airodump [interface]` - capture wifi packets
- `kismet [interface]` - find all wireless networks
- `wifite [interface]` - automated wifi cracking

### network monitoring

see what everyone is doing

- `wireshark [interface]` - packet capture and analysis
- `tcpdump [interface]` - command line packet capture
- `ettercap [target]` - man in the middle attacks
- `bettercap [interface]` - network reconnaissance tool

### forensics and analysis

for when you need to dig through files and memory

- `volatility [image]` - analyze memory dumps
- `binwalk [file]` - extract files from firmware
- `strings [file]` - find text in binary files
- `exiftool [file]` - get metadata from files

### basic tools

stuff you use all the time

- `netcat [host] [port]` - swiss army knife of networking
- `ssh [user@host]` - secure shell connections
- `curl [url]` - make http requests
- `wget [url]` - download files
- `base64 [file]` - encode/decode base64
- `md5sum [file]` - get file hashes

### system commands

regular linux stuff you need to know

- `ps` - see what processes are running
- `top` - system monitor
- `netstat` - network connections
- `find [path]` - find files
- `grep [pattern]` - search text
- `cat [file]` - show file contents
- `ls` - list files
- `pwd` - where am i
- `whoami` - who am i logged in as

## mr robot special commands

these are the fun ones

- `fsociety` - read the manifesto
- `elliot` - elliot's personal toolkit
- `mr-robot` - system status
- `stage2` - phase 2 operations
- `five9` - recreate the 5/9 attack

## what you get when you run ls

```
fsociety/           - main operations
exploits/          - collection of exploits
payloads/          - custom payloads
targets/           - target info
reports/           - pentest reports
fsociety.dat       - the main archive
mr_robot.key       - encryption keys
ecorp_targets.txt  - evil corp target list
dark_army.log      - operations log
stage2.dat         - phase 2 data
```

## disclaimer

this is just a simulation. dont be stupid with it. only use it on stuff you own or have permission to test. 

## why this exists

most "hacker" terminals look like garbage from a bad movie. this one actually looks like the tools real pentesters use. based on mr robot because that show got hacking right.

no network activity happens - its all fake but realistic looking.

*"we are fsociety"*