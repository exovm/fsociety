# fsociety Terminal

A cybersecurity education terminal inspired by the Mr. Robot TV series. This project provides an immersive penetration testing simulation environment for learning cybersecurity concepts and tools.

## 🖥️ Platform Support

### Windows
- **Requirements**: Windows 10/11, Python 3.7+
- **Installation**: Run `install_windows.bat`
- **Quick Start**: Use `RUN_ME.bat`

### macOS
- **Requirements**: macOS 10.14+, Python 3.7+
- **Installation**: Run `./install_macos.sh`
- **Quick Start**: Use `./run_macos.sh`

## 🚀 Quick Start

### Windows Users
```batch
# Clone and install
git clone https://github.com/yourusername/fsociety-terminal.git
cd fsociety-terminal
install_windows.bat

# Launch terminal
RUN_ME.bat
```

### macOS Users  
```bash
# Clone and install
git clone https://github.com/yourusername/fsociety-terminal.git
cd fsociety-terminal
chmod +x install_macos.sh
./install_macos.sh

# Launch terminal
./run_macos.sh
```

## 🛠️ Features

### Core Functionality
- **80+ Simulated Security Tools** - Realistic penetration testing commands
- **Network Reconnaissance** - Port scanning, DNS enumeration, subdomain discovery
- **Web Application Testing** - SQL injection testing, directory bruteforcing
- **Wireless Security** - WiFi scanning and security assessment
- **Social Engineering** - OSINT tools and phishing simulation
- **Forensics & Steganography** - File analysis and hidden data extraction

### User Experience
- **Authentic Terminal Interface** - Mr. Robot inspired design
- **Matrix-Style Visual Effects** - Glitch animations and hacker aesthetics  
- **Session Logging** - Track commands and maintain session history
- **Fullscreen Mode** - Immersive terminal experience
- **Safe Mode** - Compatibility option for older terminals

### Customization
- **Text Configuration System** - Customize all messages and responses
- **Interactive Text Editor** - Easy-to-use configuration interface
- **Profile Management** - Save and load different terminal personalities

## 📋 Command Categories

<details>
<summary><strong>Network Reconnaissance</strong></summary>

- `nmap`, `masscan`, `zmap`, `rustscan` - Port and network scanning
- `hping3`, `traceroute`, `fping` - Network probing and routing  
- `dig`, `whois`, `fierce`, `dnsrecon` - DNS enumeration
- `sublist3r`, `amass` - Subdomain discovery
</details>

<details>
<summary><strong>Web Application Testing</strong></summary>

- `sqlmap`, `nikto`, `dirb`, `gobuster` - Web vulnerability scanning
- `ffuf`, `wfuzz`, `whatweb`, `wafw00f` - Web fuzzing and fingerprinting
- `burpsuite`, `owasp-zap` - Web application security testing
</details>

<details>
<summary><strong>Wireless Security</strong></summary>

- `airodump-ng`, `aircrack-ng` - WiFi scanning and analysis
- `aireplay-ng`, `wash` - WiFi attacks and WPS scanning
- `reaver`, `bully` - WPS PIN attacks
</details>

<details>
<summary><strong>Password Attacks</strong></summary>

- `john`, `hashcat` - Password cracking tools
- `hydra`, `medusa` - Network login brute-forcers
- `crunch`, `cewl`, `cupp` - Wordlist generators
</details>

<details>
<summary><strong>Forensics & Analysis</strong></summary>

- `volatility`, `autopsy` - Memory and disk forensics
- `binwalk`, `steghide` - Firmware and steganography analysis
- `exiftool`, `strings`, `hexdump` - File analysis and metadata
</details>

## 🔧 Building Executables

### Windows Executable
```batch
build_exe.bat
# Creates: dist/We_See_You.exe
```

### macOS Executable  
```bash
./build_macos.sh
# Creates: dist/fsociety-terminal
```

## ⚙️ Configuration

### Text Customization
- **Windows**: Run `edit_text.bat` 
- **macOS**: Run `python3 text_editor.py`
- **Manual**: Edit `text_config.json` directly

### Safe Mode
For compatibility with older terminals:
```bash
# Windows
RUN_ME.bat --safe

# macOS  
./run_macos.sh --safe
```

## 📁 Project Structure

```
fsociety-terminal/
├── We_See_You.py           # Main terminal application
├── extended_commands.py    # Additional command implementations
├── text_config.json        # Customizable text configuration
├── text_editor.py          # Interactive text configuration editor
├── install_windows.bat     # Windows installer
├── build_exe.bat          # Windows executable builder
├── RUN_ME.bat             # Windows launcher
├── edit_text.bat          # Windows text editor launcher
├── install_macos.sh       # macOS installer  
├── build_macos.sh         # macOS executable builder
├── run_macos.sh           # macOS launcher
└── README.md              # This file
```

## 🎓 Educational Purpose

This tool is designed for:
- **Cybersecurity Education** - Learn penetration testing concepts
- **Training Environments** - Practice security assessment techniques
- **Capture The Flag (CTF)** - Familiarize with common security tools
- **Security Awareness** - Understand attack methodologies

## ⚠️ Legal Disclaimer

This software is intended for **educational purposes only**. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for any misuse of this software.

Only use this tool on:
- Systems you own
- Systems you have explicit permission to test
- Authorized training environments

## 🤝 Contributing

We welcome contributions! Please feel free to submit pull requests or open issues for:
- Bug fixes
- New command implementations  
- Platform compatibility improvements
- Documentation updates

## 📊 System Requirements

### Minimum Requirements
- **Python**: 3.7 or higher
- **Memory**: 512 MB RAM
- **Storage**: 100 MB available space
- **Display**: Terminal with color support

### Recommended Requirements
- **Python**: 3.9 or higher
- **Memory**: 1 GB RAM  
- **Storage**: 500 MB available space
- **Display**: Full-screen terminal capability

## 🔄 Version History

- **v3.0** - Cross-platform support, text customization system
- **v2.1** - Enhanced visual effects, session logging
- **v2.0** - Major UI overhaul, 80+ commands  
- **v1.5** - Stability improvements, profile system
- **v1.0** - Initial release

---

**"We are fsociety. We are legion. We do not forgive. We do not forget."**

*This project is not affiliated with the Mr. Robot TV series or USA Network.*