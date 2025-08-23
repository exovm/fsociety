# contributing

want to help make this better? cool. here's how to do it without breaking things.

## setup

1. **fork the repo**
   ```bash
   git clone https://github.com/yourusername/fsociety.git
   cd fsociety
   ```

2. **get it running**
   
   windows: run `install_windows.bat`  
   mac: run `./install_macos.sh`

3. **test it works**
   ```bash
   python We_See_You.py --safe
   ```

## adding new commands

### implementation
- add your command function to `We_See_You.py` or `extended_commands.py`
- make the output look realistic - check what the real tool actually outputs
- add some random delays to simulate processing time

### register it
```python
self.tools = {
    'your_new_command': self.your_new_function,
    # ... other commands
}
```

### update help
- add it to the help system in `display_help()`
- put it in the right category
- keep descriptions short and to the point

## style guidelines

- don't overthink it, just make it work
- use normal python conventions
- comment confusing parts
- test on python 3.7+ if possible

## what makes a good command

1. **realistic output** - looks like the actual tool
2. **proper error handling** - doesn't crash on bad input  
3. **respects safe mode** - no fancy effects if `--safe` is used
4. **cleans up after itself** - doesn't leave terminal in weird state

## testing

before submitting:
- [ ] command runs without errors
- [ ] output looks realistic
- [ ] works in safe mode
- [ ] doesn't break other commands
- [ ] help text is updated

## submitting changes

1. **make a branch**
   ```bash
   git checkout -b add-your-command
   ```

2. **do your thing**
   - implement the feature
   - test it works
   - update docs if needed

3. **commit**
   ```bash
   git commit -m "add command: your-tool-name"
   ```

4. **submit pr**
   - clear title describing what you did
   - mention if you tested it
   - screenshots if it changes the ui

## commit messages

keep them simple:
- "add nessus command"
- "fix bug in network scanner"  
- "update mac installer"

## command categories

put new commands in the right section:
- **network stuff**: nmap, dig, whois, etc
- **web hacking**: nikto, sqlmap, dirb, etc
- **wifi**: aircrack, airodump, etc
- **password attacks**: john, hashcat, hydra, etc
- **exploitation**: metasploit, meterpreter, etc
- **forensics**: volatility, strings, etc

## text customization

all user-facing text should use the config system:
```python
msg = self.text_config.get('category', 'key', 'fallback')
```

## cross-platform stuff

- test on both windows and mac if you can
- use `os.name` for platform-specific code
- make sure shell scripts are executable (`chmod +x`)

## visual effects

- respect the `safe_mode` setting
- wrap effects in try/except blocks
- provide fallbacks for unsupported terminals

## documentation

### for new commands
```python
def new_command(self, target=None):
    """Simulate tool-name - what it does"""
    # code here
```

### updating readme
- keep install instructions current
- add new commands to command list
- don't make it too formal

## questions?

- open an issue for bugs
- check existing issues first
- include system info for bug reports

## don't do this

- overly complex code
- hollywood-style fake output
- breaking existing functionality
- making it look less authentic

## do this

- make output look like real tools
- keep the mr robot vibe
- help people learn actual cybersecurity
- test your changes

thanks for contributing. let's make this the most realistic hacker terminal simulator out there.