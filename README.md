# fsociety terminal

basically a mr robot inspired hacker terminal that actually looks legit instead of that hollywood garbage. built this because i got tired of seeing "hacking" scenes that look nothing like real pentesting.

## what it does

simulates real cybersecurity tools in a terminal that looks like something elliot would actually use. no fake matrix code or green text on black - just authentic looking penetration testing tools.

got 80+ commands that simulate everything from nmap to metasploit. perfect for learning what these tools do without actually running them against real targets.

## platforms

**windows** - works on 10 and 11, needs python 3.7+  
**macos** - tested on 10.14+, also needs python 3.7+

## install & run

### windows
```
git clone https://github.com/exovm/fsociety.git
cd fsociety
install_windows.bat
RUN_ME.bat
```

### mac
```
git clone https://github.com/exovm/fsociety.git
cd fsociety
chmod +x install_macos.sh
./install_macos.sh
./run_macos.sh
```

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

- run `edit_text.bat` on windows or `python3 text_editor.py` on mac
- edit `text_config.json` directly if you want
- change loading messages, banners, command responses, whatever

## building executables

**windows**: run `build_exe.bat`  
**mac**: run `./build_macos.sh`

creates standalone executables so you don't need python installed.

## compatibility mode

if the visual effects mess up your terminal:
```
RUN_ME.bat --safe        # windows
./run_macos.sh --safe    # mac
```

## project structure

```
fsociety/
├── We_See_You.py           # main terminal
├── extended_commands.py    # extra command implementations  
├── text_config.json        # customizable text
├── text_editor.py          # config editor
├── install_windows.bat     # windows setup
├── install_macos.sh        # mac setup  
├── RUN_ME.bat             # windows launcher
└── run_macos.sh           # mac launcher
```

## troubleshooting

### windows problems

**Q: "python is not recognized as an internal or external command"**  
A: you don't have python installed or it's not in your PATH. download python from python.org and make sure to check "Add Python to PATH" during installation.

**Q: pip install fails with permission errors**  
A: run command prompt as administrator or use `pip install --user opencv-python numpy`

**Q: the terminal looks weird/corrupted**  
A: your terminal doesn't support the visual effects. run with `RUN_ME.bat --safe` instead.

**Q: "cv2 module not found"**  
A: opencv didn't install properly. try `pip uninstall opencv-python` then `pip install opencv-python`

**Q: executable won't run/windows defender blocks it**  
A: windows defender sometimes flags pyinstaller executables as suspicious. add an exception or run the python script directly.

### mac problems

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

### both platforms

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

not affiliated with the show obviously, just inspired by it.