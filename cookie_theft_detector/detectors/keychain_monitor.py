"""
Keychain Access Monitor

Monitors for suspicious attempts to access browser encryption keys
stored in the macOS Keychain. Cookie stealers typically need to
extract these keys to decrypt cookie values.
"""

import subprocess
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Callable
from pathlib import Path


@dataclass
class KeychainAccessEvent:
    """Represents a detected keychain access event."""
    timestamp: datetime
    keychain_item: str
    accessing_process: str
    event_type: str
    details: str
    severity: str


class KeychainMonitor:
    """
    Monitors macOS Keychain for suspicious access to browser encryption keys.

    Detection methods:
    1. Parse system log for security framework access
    2. Monitor for 'security' command usage
    3. Detect unauthorized access to Chrome Safe Storage
    """

    # Keychain items that cookie stealers typically target
    SENSITIVE_KEYCHAIN_ITEMS = [
        "Chrome Safe Storage",
        "Chromium Safe Storage",
        "Brave Safe Storage",
        "Microsoft Edge Safe Storage",
        "Opera Safe Storage",
        "Vivaldi Safe Storage",
    ]

    # Known malicious patterns in process names
    SUSPICIOUS_PROCESS_PATTERNS = [
        r"python[23]?",
        r"osascript",
        r"Terminal",
        r"iTerm",
        r"sh$",
        r"bash$",
        r"zsh$",
    ]

    def __init__(self, callback: Optional[Callable[[KeychainAccessEvent], None]] = None):
        self.callback = callback
        self.events: list[KeychainAccessEvent] = []
        self._running = False
        self._last_check_time = None

    def _parse_security_log(self, since_seconds: int = 60) -> list[dict]:
        """Parse system log for security framework access events."""
        events = []

        try:
            # Query unified logging system for security events
            cmd = [
                "log", "show",
                "--predicate", 'subsystem == "com.apple.securityd"',
                "--last", f"{since_seconds}s",
                "--style", "json"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0 and result.stdout.strip():
                # Parse log entries for keychain access
                for line in result.stdout.split('\n'):
                    if any(item in line for item in self.SENSITIVE_KEYCHAIN_ITEMS):
                        events.append({
                            "raw": line,
                            "type": "keychain_access"
                        })

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass

        return events

    def _check_security_command_usage(self) -> list[dict]:
        """Check for recent usage of the 'security' command."""
        events = []

        try:
            # Check running processes for security command
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if 'security' in line and 'find-generic-password' in line:
                        # Extract the keychain item being accessed
                        match = re.search(r'-s\s+"?([^"]+)"?', line)
                        item = match.group(1) if match else "unknown"

                        if any(sensitive in item for sensitive in self.SENSITIVE_KEYCHAIN_ITEMS):
                            events.append({
                                "process_line": line,
                                "keychain_item": item,
                                "type": "security_command"
                            })

        except Exception:
            pass

        return events

    def _check_process_keychain_access(self) -> list[KeychainAccessEvent]:
        """Monitor for processes accessing keychain items."""
        detected = []

        try:
            # Use lsof to check what processes have keychain files open
            keychain_paths = [
                Path.home() / "Library/Keychains/login.keychain-db",
                Path("/Library/Keychains/System.keychain"),
            ]

            for keychain_path in keychain_paths:
                if not keychain_path.exists():
                    continue

                result = subprocess.run(
                    ["lsof", str(keychain_path)],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                if result.returncode == 0:
                    for line in result.stdout.split('\n')[1:]:  # Skip header
                        if not line.strip():
                            continue

                        parts = line.split()
                        if len(parts) >= 1:
                            process_name = parts[0]

                            # Check if this is a suspicious process
                            is_suspicious = any(
                                re.search(pattern, process_name)
                                for pattern in self.SUSPICIOUS_PROCESS_PATTERNS
                            )

                            if is_suspicious:
                                event = KeychainAccessEvent(
                                    timestamp=datetime.now(),
                                    keychain_item=str(keychain_path),
                                    accessing_process=process_name,
                                    event_type="suspicious_access",
                                    details=f"Suspicious process '{process_name}' accessing keychain",
                                    severity="high"
                                )
                                detected.append(event)

        except Exception:
            pass

        return detected

    def _emit_event(self, event: KeychainAccessEvent):
        """Emit a detected event."""
        self.events.append(event)
        if self.callback:
            self.callback(event)

    def check_for_threats(self) -> list[KeychainAccessEvent]:
        """Run all detection checks and return findings."""
        detected = []

        # Check 1: Security command usage
        security_events = self._check_security_command_usage()
        for evt in security_events:
            event = KeychainAccessEvent(
                timestamp=datetime.now(),
                keychain_item=evt.get("keychain_item", "unknown"),
                accessing_process="security",
                event_type="key_extraction",
                details="Detected attempt to extract browser encryption key via 'security' command",
                severity="critical"
            )
            detected.append(event)
            self._emit_event(event)

        # Check 2: Process keychain access
        process_events = self._check_process_keychain_access()
        for event in process_events:
            detected.append(event)
            self._emit_event(event)

        # Check 3: System log analysis
        log_events = self._parse_security_log()
        for evt in log_events:
            event = KeychainAccessEvent(
                timestamp=datetime.now(),
                keychain_item="browser_key",
                accessing_process="unknown",
                event_type="log_detection",
                details=f"Security log indicates keychain access: {evt.get('raw', '')[:100]}",
                severity="medium"
            )
            detected.append(event)
            self._emit_event(event)

        return detected

    def simulate_attack_detection(self) -> KeychainAccessEvent:
        """
        Simulate what detection would look like during an actual attack.
        Useful for testing and demonstration purposes.
        """
        return KeychainAccessEvent(
            timestamp=datetime.now(),
            keychain_item="Chrome Safe Storage",
            accessing_process="python3",
            event_type="key_extraction",
            details="[SIMULATED] Detected unauthorized extraction of Chrome encryption key",
            severity="critical"
        )

    def start_monitoring(self, interval: float = 5.0):
        """Start continuous monitoring loop."""
        self._running = True

        while self._running:
            self.check_for_threats()
            time.sleep(interval)

    def stop_monitoring(self):
        """Stop the monitoring loop."""
        self._running = False

    def get_protection_status(self) -> dict:
        """Get current protection status."""
        protected_items = []
        for item in self.SENSITIVE_KEYCHAIN_ITEMS:
            try:
                result = subprocess.run(
                    ["security", "find-generic-password", "-s", item, "-w"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    protected_items.append(item)
            except Exception:
                pass

        return {
            "monitored_items": self.SENSITIVE_KEYCHAIN_ITEMS,
            "detected_items": protected_items,
            "events_detected": len(self.events)
        }
