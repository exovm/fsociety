# Contributing to fsociety Terminal

Thank you for your interest in contributing to fsociety Terminal! This document provides guidelines and information for contributors.

## Getting Started

1. **Fork the Repository**
   ```bash
   git clone https://github.com/yourusername/fsociety-terminal.git
   cd fsociety-terminal
   ```

2. **Set Up Development Environment**
   
   **Windows:**
   ```batch
   install_windows.bat
   ```
   
   **macOS:**
   ```bash
   ./install_macos.sh
   ```

3. **Test Your Setup**
   ```bash
   python We_See_You.py --safe
   ```

## Development Guidelines

### Code Style
- Follow PEP 8 Python style guidelines
- Use meaningful variable and function names
- Add comments for complex logic
- Maintain compatibility with Python 3.7+

### Adding New Commands

1. **Command Implementation**
   - Add new command functions to `We_See_You.py` or `extended_commands.py`
   - Follow the existing pattern for realistic output simulation
   - Include appropriate delays and formatting

2. **Command Registration**
   ```python
   self.tools = {
       'newcommand': self.new_command_function,
       # ... existing commands
   }
   ```

3. **Help Documentation**
   - Update the help system in `display_help()` method
   - Add command to appropriate category
   - Include brief description of functionality

### Text Customization

- All user-facing text should use the `text_config.json` system
- Use the `self.text_config.get()` method for retrieving text
- Provide fallback defaults for all text lookups

### Cross-Platform Compatibility

- Test on both Windows and macOS when possible
- Use `os.name` checks for platform-specific code
- Ensure shell scripts have proper permissions (`chmod +x`)

### Visual Effects

- All effects should respect the `safe_mode` setting
- Provide graceful fallbacks for unsupported terminals
- Use try/except blocks around effect code

## Testing

### Manual Testing Checklist

- [ ] Terminal starts without errors
- [ ] All major commands execute successfully
- [ ] Visual effects work (or fall back gracefully)
- [ ] Text customization system functions
- [ ] Safe mode disables effects properly
- [ ] Cross-platform scripts execute correctly

### Testing New Commands

1. Verify realistic output formatting
2. Check error handling for invalid inputs
3. Ensure proper terminal cleanup after execution
4. Test with various argument combinations

## Submitting Changes

### Pull Request Process

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/new-command
   ```

2. **Make Your Changes**
   - Implement your feature or fix
   - Test thoroughly on your platform
   - Update documentation if needed

3. **Commit Changes**
   ```bash
   git commit -m "Add new command: example-tool"
   ```

4. **Push and Create PR**
   ```bash
   git push origin feature/new-command
   ```

### PR Guidelines

- **Clear Title**: Describe what your PR does
- **Detailed Description**: Explain the changes and why they're needed
- **Testing Notes**: Include how you tested the changes
- **Screenshots**: If UI changes, include before/after screenshots

### Commit Messages

Use clear, descriptive commit messages:
- `Add new command: nessus vulnerability scanner`
- `Fix text rendering bug in matrix effect`
- `Update macOS installer for M1 compatibility`
- `Improve error handling in network commands`

## Command Categories

When adding new commands, place them in the appropriate category:

- **Network Reconnaissance**: `nmap`, `masscan`, `dig`, etc.
- **Web Application Testing**: `nikto`, `sqlmap`, `dirb`, etc.
- **Wireless Security**: `aircrack-ng`, `airodump-ng`, etc.
- **Password Attacks**: `john`, `hashcat`, `hydra`, etc.
- **Exploitation**: `metasploit`, `msfvenom`, etc.
- **Forensics**: `volatility`, `binwalk`, `strings`, etc.
- **Social Engineering**: `setoolkit`, `gophish`, etc.
- **Crypto/Utilities**: `openssl`, `base64`, `md5sum`, etc.

## Documentation

### README Updates
- Keep installation instructions current
- Update command lists when adding new tools
- Maintain version history section

### Code Comments
```python
def new_command(self, target=None):
    """
    Simulate [tool name] - brief description
    
    Args:
        target (str): Target IP, domain, or file
        
    Simulates realistic output from the actual tool
    """
    # Implementation here
```

## Community

- Be respectful and constructive in discussions
- Help other contributors when possible
- Follow the project's educational mission
- Maintain the Mr. Robot aesthetic and theme

## Questions?

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- Include relevant system information in bug reports

Thank you for contributing to fsociety Terminal! Together we're building an authentic cybersecurity education tool.