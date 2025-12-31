"""
Cookie Access Detector

Monitors browser cookie database files for unauthorized access attempts.
Detects when non-browser processes attempt to read cookie stores.
"""

import os
import time
import hashlib
import sqlite3
import tempfile
import shutil
from pathlib import Path
from dataclasses import dataclass
from typing import Optional, Callable
from datetime import datetime


@dataclass
class CookieAccessEvent:
    """Represents a detected cookie access event."""
    timestamp: datetime
    browser: str
    cookie_path: Path
    event_type: str  # 'modified', 'accessed', 'copied'
    details: str
    severity: str  # 'low', 'medium', 'high', 'critical'


class CookieAccessDetector:
    """
    Monitors browser cookie databases for unauthorized access.

    Detection methods:
    1. File modification time monitoring
    2. File hash change detection
    3. SQLite WAL file monitoring (indicates active access)
    4. Cookie count anomaly detection
    """

    BROWSER_COOKIE_PATHS = {
        "chrome": Path.home() / "Library/Application Support/Google/Chrome/Default/Cookies",
        "chrome_beta": Path.home() / "Library/Application Support/Google/Chrome Beta/Default/Cookies",
        "brave": Path.home() / "Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies",
        "edge": Path.home() / "Library/Application Support/Microsoft Edge/Default/Cookies",
        "firefox": Path.home() / "Library/Application Support/Firefox/Profiles",
        "safari": Path.home() / "Library/Cookies/Cookies.binarycookies",
    }

    # Known legitimate processes that access cookies
    TRUSTED_PROCESSES = {
        "Google Chrome", "Chrome", "Brave Browser", "Microsoft Edge",
        "Firefox", "Safari", "Google Chrome Helper", "Chromium"
    }

    def __init__(self, callback: Optional[Callable[[CookieAccessEvent], None]] = None):
        self.callback = callback
        self.baseline: dict[str, dict] = {}
        self.events: list[CookieAccessEvent] = []
        self._running = False

    def _get_file_metadata(self, path: Path) -> Optional[dict]:
        """Get file metadata for comparison."""
        if not path.exists():
            return None

        stat = path.stat()
        try:
            with open(path, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
        except (PermissionError, IOError):
            file_hash = None

        return {
            "mtime": stat.st_mtime,
            "atime": stat.st_atime,
            "size": stat.st_size,
            "hash": file_hash,
        }

    def _get_cookie_count(self, path: Path) -> Optional[int]:
        """Get cookie count from SQLite database."""
        if not path.exists() or path.suffix == '.binarycookies':
            return None

        temp_path = None
        try:
            # Copy to temp to avoid locking issues
            temp_fd, temp_path = tempfile.mkstemp()
            os.close(temp_fd)
            shutil.copy2(path, temp_path)

            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM cookies")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception:
            return None
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)

    def _check_wal_file(self, path: Path) -> bool:
        """Check if WAL file exists (indicates active database access)."""
        # SQLite WAL files are named like "Cookies-wal", not "Cookies.wal"
        wal_path = path.parent / (path.name + "-wal")
        return wal_path.exists()

    def establish_baseline(self) -> dict[str, dict]:
        """Establish baseline state of all cookie files."""
        self.baseline = {}

        for browser, path in self.BROWSER_COOKIE_PATHS.items():
            if browser == "firefox":
                # Firefox uses profile directories
                firefox_cookies = list(path.glob("*/cookies.sqlite"))
                for cookie_file in firefox_cookies:
                    key = f"firefox_{cookie_file.parent.name}"
                    metadata = self._get_file_metadata(cookie_file)
                    if metadata:
                        metadata["cookie_count"] = self._get_cookie_count(cookie_file)
                        metadata["path"] = cookie_file
                        self.baseline[key] = metadata
            else:
                metadata = self._get_file_metadata(path)
                if metadata:
                    metadata["cookie_count"] = self._get_cookie_count(path)
                    metadata["path"] = path
                    self.baseline[browser] = metadata

        return self.baseline

    def _emit_event(self, event: CookieAccessEvent):
        """Emit a detected event."""
        self.events.append(event)
        if self.callback:
            self.callback(event)

    def check_for_anomalies(self) -> list[CookieAccessEvent]:
        """Check for anomalies compared to baseline."""
        detected = []

        for browser, baseline in self.baseline.items():
            path = baseline["path"]
            current = self._get_file_metadata(path)

            if not current:
                continue

            # Check 1: Hash changed (file was modified)
            if current["hash"] and baseline["hash"]:
                if current["hash"] != baseline["hash"]:
                    # Check if browser is running
                    browser_running = self._is_browser_running(browser)

                    if not browser_running:
                        event = CookieAccessEvent(
                            timestamp=datetime.now(),
                            browser=browser,
                            cookie_path=path,
                            event_type="modified",
                            details="Cookie database modified while browser is closed",
                            severity="critical"
                        )
                        detected.append(event)
                        self._emit_event(event)

            # Check 2: Access time changed significantly
            if current["atime"] - baseline["atime"] > 1:
                browser_running = self._is_browser_running(browser)
                if not browser_running:
                    event = CookieAccessEvent(
                        timestamp=datetime.now(),
                        browser=browser,
                        cookie_path=path,
                        event_type="accessed",
                        details="Cookie database accessed while browser is closed",
                        severity="high"
                    )
                    detected.append(event)
                    self._emit_event(event)

            # Check 3: WAL file appeared (active access)
            if self._check_wal_file(path):
                browser_running = self._is_browser_running(browser)
                if not browser_running:
                    event = CookieAccessEvent(
                        timestamp=datetime.now(),
                        browser=browser,
                        cookie_path=path,
                        event_type="active_access",
                        details="SQLite WAL file detected - database being actively queried",
                        severity="critical"
                    )
                    detected.append(event)
                    self._emit_event(event)

            # Check 4: Cookie count anomaly
            current_count = self._get_cookie_count(path)
            if current_count and baseline.get("cookie_count"):
                diff = abs(current_count - baseline["cookie_count"])
                if diff > 100:  # Significant change threshold
                    event = CookieAccessEvent(
                        timestamp=datetime.now(),
                        browser=browser,
                        cookie_path=path,
                        event_type="count_anomaly",
                        details=f"Cookie count changed significantly: {baseline['cookie_count']} -> {current_count}",
                        severity="medium"
                    )
                    detected.append(event)
                    self._emit_event(event)

        return detected

    def _is_browser_running(self, browser: str) -> bool:
        """Check if the browser process is currently running."""
        import subprocess

        browser_process_names = {
            "chrome": "Google Chrome",
            "chrome_beta": "Google Chrome Beta",
            "brave": "Brave Browser",
            "edge": "Microsoft Edge",
            "safari": "Safari",
        }

        process_name = browser_process_names.get(browser, browser)

        try:
            result = subprocess.run(
                ["pgrep", "-x", process_name],
                capture_output=True,
                text=True
            )
            return result.returncode == 0
        except Exception:
            return True  # Assume running if we can't check

    def get_detected_browsers(self) -> list[str]:
        """Get list of browsers with detected cookie stores."""
        return list(self.baseline.keys())

    def start_monitoring(self, interval: float = 5.0):
        """Start continuous monitoring loop."""
        self._running = True
        self.establish_baseline()

        while self._running:
            self.check_for_anomalies()
            # Update baseline for next iteration
            self.establish_baseline()
            time.sleep(interval)

    def stop_monitoring(self):
        """Stop the monitoring loop."""
        self._running = False
