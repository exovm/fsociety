# changelog

what's new in each version

## [3.0.0] - 2024-12-20

### new stuff
- **mac support** - finally works on macos with proper shell scripts
- **text customization** - change all the messages to whatever you want
- **text editor** - interactive tool to edit configuration without messing with json
- **better installers** - automated setup scripts for windows and mac
- **safe mode** - compatibility mode for terminals that don't like fancy effects

### new files
- `install_windows.bat` - sets up everything on windows
- `install_macos.sh` - sets up everything on mac
- `build_macos.sh` - creates mac executable
- `run_macos.sh` - launches on mac
- `text_config.json` - all the customizable text
- `text_editor.py` - edit configuration interactively
- `edit_text.bat` - windows shortcut for text editor

### fixes
- text rendering bugs during startup
- terminal getting messed up after commands
- unicode character issues
- better error handling overall

### improved
- more authentic mr robot feel
- better visual effects with fallbacks
- cleaner code organization
- way better documentation

## [2.1.0] - 2024-11-15

### new stuff
- matrix-style animations during startup
- session logging so you can see what you did
- profile system for saving different setups
- fullscreen mode for better immersion
- ip tracing like in the show

### improvements
- commands look more realistic
- better startup sequence
- doesn't crash as much

## [2.0.0] - 2024-10-01

### big changes
- completely redesigned interface
- 80+ simulated cybersecurity commands
- realistic output that actually looks like real tools
- way better terminal effects

this was basically a complete rewrite to make it look authentic instead of like a movie prop.

## [1.5.0] - 2024-08-15

### new stuff
- profile and session management
- command history tracking
- more stable, crashes less

### bug fixes
- fixed memory leaks in visual effects
- various stability improvements

## [1.0.0] - 2024-06-01

### initial release
- basic fsociety terminal
- mr robot inspired interface
- simulation of common penetration testing tools

this was the first version that actually worked. pretty basic but it was a start.