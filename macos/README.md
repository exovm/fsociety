# fsociety terminal - macOS

basically a mr robot inspired hacker terminal that actually looks legit instead of that hollywood garbage. built this because i got tired of seeing "hacking" scenes that look nothing like real pentesting.

## what it does

simulates real cybersecurity tools in a terminal that looks like something elliot would actually use. no fake matrix code or green text on black - just authentic looking penetration testing tools.

got 100+ commands that simulate everything from nmap to metasploit. perfect for learning what these tools do without actually running them against real targets.

## macos setup

### option 1: easy way (recommended)
```
chmod +x *.sh
./install_macos.sh
./run_macos.sh
```

### option 2: manual way
```
pip3 install opencv-python numpy
python3 We_See_You.py
```

### option 3: build executable
```
./build_macos.sh
```

## new advanced features in v5.0+
- neural-scanner - AI-powered vulnerability detection
- quantum-decrypt - quantum computing decryption simulator
- zero-day - advanced 0-day exploit framework
- blockchain-penetrator - DeFi protocol vulnerability scanner
- deepfake - deepfake video/audio generation studio
- satellite-hijack - satellite communication interception
- biometric-spoof - fingerprint/facial recognition bypass
- cyber-warfare - nation-state attack simulation suite
- 5g-exploit - 5G network infrastructure attacks
- ai-phishing - AI-generated phishing campaigns
- supply-chain - software supply chain attacks
- firmware-rootkit - hardware-level persistence
- deepweb-crawler - dark web intelligence gathering
- neural-net - neural network vulnerability scanner
- quantum-hack - quantum hacking suite

## commands

### network stuff
- `nmap [target]` - port scanning
- `masscan [target]` - faster port scanning  
- `dig [domain]` - dns lookups
- `whois [domain]` - domain info
- `sublist3r [domain]` - subdomain enumeration

### web hacking
- `sqlmap [url]` - sql injection testing
- `nikto [url]` - web vulnerability scanner
- `dirb [url]` - directory bruteforcing
- `gobuster [url]` - better directory bruteforcing

### wifi
- `aircrack-ng` - crack wifi passwords
- `airodump-ng` - capture wifi packets
- `wash` - scan for wps

### password attacks  
- `john [hashfile]` - crack password hashes
- `hashcat [hashfile]` - gpu password cracking
- `hydra [target]` - bruteforce logins

### exploitation
- `msfconsole` - metasploit framework
- `meterpreter` - post exploitation shell
- `mimikatz` - windows credential extraction

### forensics
- `volatility [image]` - memory analysis
- `binwalk [file]` - firmware analysis  
- `strings [file]` - extract text from binaries

### mr robot specials
- `fsociety` - the manifesto
- `elliot` - elliot's toolkit
- `stage2` - phase 2 operations

## customization

everything is configurable through text files:

- run `python3 text_editor.py` to customize messages and banners
- edit `text_config.json` directly if you want
- change loading messages, banners, command responses, whatever

## compatibility mode

if the visual effects mess up your terminal:
```
./run_macos.sh --safe
```

## requirements

- macos 10.14+
- python 3.7+ (installs automatically with install_macos.sh)

## troubleshooting

**Q: "permission denied" when running shell scripts**  
A: the scripts aren't executable. run `chmod +x *.sh` to fix permissions.

**Q: "command not found: python3"**  
A: install python3 from python.org or use homebrew: `brew install python3`

**Q: pip3 install fails**  
A: try `pip3 install --user opencv-python numpy` or use `python3 -m pip install opencv-python numpy`

**Q: terminal effects don't work**  
A: some mac terminals don't support all effects. use `./run_macos.sh --safe` for compatibility mode.

**Q: "cannot execute binary file"**  
A: you might be on an M1 mac trying to run an intel build. compile from source with `./build_macos.sh`

**Q: commands are slow/laggy**  
A: that's intentional to simulate real tool processing time. if it's too slow, you can modify the delays in the code.

**Q: can i add my own commands?**  
A: yeah, check out the contributing guide. it's pretty straightforward to add new command simulations.

**Q: is this actually hacking?**  
A: no, it's all simulation. no real network traffic or actual penetration testing happens. it's for learning what these tools look like.

## disclaimer

this is for education only. don't be stupid with it. only use on systems you own or have permission to test. not my fault if you get in trouble.

## contributing

found a bug? want to add a command? cool, submit a pr. 

just keep it realistic - no hollywood hacking bullshit. if you're adding a tool simulation, make it look like the real thing.

## why this exists

watched too many movies/shows with terrible "hacking" scenes. mr robot got it right - real hackers use terminals and command line tools, not flashy guis with spinning 3d models.

built this to help people learn what real penetration testing looks like without having to set up vulnerable labs or risk breaking things.

---

*"we are fsociety"*

**created by exovm**

not affiliated with the show obviously, just inspired by it