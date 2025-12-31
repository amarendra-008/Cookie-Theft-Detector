# Cookie Theft Detector

A real-time security monitoring tool that detects browser cookie theft attempts on macOS. Built to demonstrate understanding of browser security, system monitoring, and defensive security techniques.

## Project Overview

Modern browsers store authentication cookies in encrypted SQLite databases. Malware known as "infostealers" target these cookies to hijack user sessions. This tool implements detection mechanisms for each stage of a cookie theft attack:

1. **Cookie Database Access** - Monitors browser cookie files for unauthorized reads
2. **Encryption Key Extraction** - Detects attempts to extract decryption keys from macOS Keychain
3. **Data Exfiltration** - Identifies suspicious outbound network connections

## Technical Implementation

### Architecture

```
cookie_theft_detector/
├── monitor.py              # Central orchestrator using Observer pattern
├── alerts.py               # Alert management with severity classification
├── cli.py                  # Command-line interface with argparse
└── detectors/
    ├── cookie_access.py    # File system monitoring (stat, hashing)
    ├── keychain_monitor.py # Keychain API monitoring
    └── network_monitor.py  # Network connection analysis
```

### Key Technical Concepts Demonstrated

- **File Integrity Monitoring**: SHA-256 hashing and metadata tracking
- **Process Monitoring**: Using `lsof` and `ps` for process analysis
- **SQLite Database Handling**: Reading browser cookie databases
- **Network Analysis**: Connection tracking and domain classification
- **Multi-threading**: Background monitoring with daemon threads
- **Event-Driven Architecture**: Callback-based alert system
- **CLI Development**: Professional command-line interface with argparse

### Detection Methods

| Attack Vector | Detection Technique | Implementation |
|--------------|---------------------|----------------|
| Cookie file read | File access time monitoring | `os.stat()` atime comparison |
| Database query | SQLite WAL file detection | Check for `-wal` journal files |
| Key extraction | Keychain command monitoring | Process list scanning |
| Data upload | Connection analysis | `lsof -i` parsing |

## Installation

```bash
git clone https://github.com/amarendra-008/Cookie-Theft-Detector.git
cd Cookie-Theft-Detector
python3 -m venv venv
source venv/bin/activate
```

**No external dependencies** - Built entirely with Python standard library.

## Usage

```bash
# Quick security scan
python main.py scan

# Real-time monitoring
python main.py monitor

# Demonstration mode (simulates attack detection)
python main.py demo

# Generate security report
python main.py report --json
```

## Sample Output

```
==================================================
  Security Scan
==================================================

[*] Initializing detectors...
[+] Cookie detector ready - monitoring 3 browser(s)
    -> chrome
    -> brave
    -> edge
[+] Keychain monitor ready
[+] Network monitor ready - 47 active connections

[*] Running security checks...

==================================================
  Scan Results
==================================================

[+] No threats detected!

Your browser cookies appear to be secure.
```

## Supported Platforms

- **OS**: macOS 10.15 (Catalina) and later
- **Python**: 3.9+
- **Browsers**: Chrome, Brave, Edge, Firefox, Safari

## Skills Demonstrated

- Python development with type hints and dataclasses
- System programming and OS-level monitoring
- Security concepts: threat detection, defense-in-depth
- Software architecture: modular design, separation of concerns
- CLI development with user-friendly output

## Future Improvements

- [ ] Windows and Linux support
- [ ] Machine learning-based anomaly detection
- [ ] Integration with SIEM systems
- [ ] Memory forensics for in-flight data detection

## License

MIT License

## Author

**Amarendra Mishra**
Security Enthusiast | Software Developer
