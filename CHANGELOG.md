# Changelog

All notable changes to the fsociety Terminal project will be documented in this file.

## [3.0.0] - 2024-12-20

### Added
- **Cross-Platform Support**: Full macOS compatibility with native shell scripts
- **Text Configuration System**: Comprehensive customization of all terminal text
- **Interactive Text Editor**: Easy-to-use configuration interface (`text_editor.py`)
- **Platform-Specific Installers**: Automated setup for Windows and macOS
- **Enhanced Documentation**: Professional README with detailed usage instructions
- **Safe Mode**: Compatibility option for older terminals (`--safe` flag)

### New Files
- `install_windows.bat` - Automated Windows installer
- `install_macos.sh` - Automated macOS installer  
- `build_macos.sh` - macOS executable builder
- `run_macos.sh` - macOS launcher script
- `text_config.json` - Customizable text configuration
- `text_editor.py` - Interactive configuration editor
- `edit_text.bat` - Windows text editor launcher

### Improved
- **Terminal Stability**: Better cleanup and error handling
- **Visual Effects**: Enhanced matrix and glitch effects with fallbacks
- **User Experience**: More authentic Mr. Robot theming
- **Code Organization**: Modular text loading system
- **Documentation**: Human-written, professional documentation

### Fixed
- Text rendering bugs during loading sequence
- Terminal state corruption after certain commands
- Cross-platform compatibility issues
- Unicode character display problems

## [2.1.0] - 2024-11-15

### Added
- Enhanced visual effects with matrix animations
- Session logging and command history
- Profile management system
- Fullscreen terminal mode
- IP address tracing like Mr. Robot show

### Improved
- Command response authenticity
- Terminal startup sequence
- Error handling and recovery

## [2.0.0] - 2024-10-01

### Added
- Major UI overhaul with Mr. Robot theming
- 80+ simulated cybersecurity commands
- Realistic command output simulation
- Advanced terminal effects and animations

### Changed
- Complete redesign of terminal interface
- Improved command categorization
- Enhanced hacker aesthetics

## [1.5.0] - 2024-08-15

### Added
- Profile and session management
- Command history tracking
- Improved stability and error handling

### Fixed
- Various bugs and stability issues
- Memory leaks in visual effects

## [1.0.0] - 2024-06-01

### Added
- Initial release of fsociety Terminal
- Basic command simulation
- Mr. Robot inspired interface
- Core penetration testing tool simulation