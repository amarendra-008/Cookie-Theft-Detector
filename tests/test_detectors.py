"""
Tests for the detection modules.
"""

import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock

from cookie_theft_detector.detectors.cookie_access import (
    CookieAccessDetector,
    CookieAccessEvent
)
from cookie_theft_detector.detectors.keychain_monitor import (
    KeychainMonitor,
    KeychainAccessEvent
)
from cookie_theft_detector.detectors.network_monitor import (
    NetworkMonitor,
    NetworkEvent
)


class TestCookieAccessEvent:
    """Tests for CookieAccessEvent dataclass."""

    def test_event_creation(self):
        """Test creating a cookie access event."""
        event = CookieAccessEvent(
            timestamp=datetime.now(),
            browser="chrome",
            cookie_path=Path("/test/path"),
            event_type="modified",
            details="Test details",
            severity="high"
        )

        assert event.browser == "chrome"
        assert event.event_type == "modified"
        assert event.severity == "high"


class TestCookieAccessDetector:
    """Tests for CookieAccessDetector class."""

    def test_detector_creation(self):
        """Test creating a detector instance."""
        detector = CookieAccessDetector()

        assert detector.baseline == {}
        assert detector.events == []

    def test_browser_paths_defined(self):
        """Test that browser cookie paths are defined."""
        assert "chrome" in CookieAccessDetector.BROWSER_COOKIE_PATHS
        assert "brave" in CookieAccessDetector.BROWSER_COOKIE_PATHS
        assert "firefox" in CookieAccessDetector.BROWSER_COOKIE_PATHS
        assert "safari" in CookieAccessDetector.BROWSER_COOKIE_PATHS

    def test_trusted_processes_defined(self):
        """Test that trusted processes are defined."""
        assert "Google Chrome" in CookieAccessDetector.TRUSTED_PROCESSES
        assert "Safari" in CookieAccessDetector.TRUSTED_PROCESSES

    def test_callback_is_called(self):
        """Test that callback is called when event is emitted."""
        callback = MagicMock()
        detector = CookieAccessDetector(callback=callback)

        event = CookieAccessEvent(
            timestamp=datetime.now(),
            browser="chrome",
            cookie_path=Path("/test"),
            event_type="test",
            details="test",
            severity="low"
        )

        detector._emit_event(event)

        callback.assert_called_once_with(event)
        assert len(detector.events) == 1

    def test_get_detected_browsers(self):
        """Test getting list of detected browsers."""
        detector = CookieAccessDetector()
        detector.baseline = {"chrome": {}, "brave": {}}

        browsers = detector.get_detected_browsers()

        assert "chrome" in browsers
        assert "brave" in browsers
        assert len(browsers) == 2


class TestKeychainAccessEvent:
    """Tests for KeychainAccessEvent dataclass."""

    def test_event_creation(self):
        """Test creating a keychain access event."""
        event = KeychainAccessEvent(
            timestamp=datetime.now(),
            keychain_item="Chrome Safe Storage",
            accessing_process="python3",
            event_type="key_extraction",
            details="Test details",
            severity="critical"
        )

        assert event.keychain_item == "Chrome Safe Storage"
        assert event.accessing_process == "python3"
        assert event.severity == "critical"


class TestKeychainMonitor:
    """Tests for KeychainMonitor class."""

    def test_monitor_creation(self):
        """Test creating a monitor instance."""
        monitor = KeychainMonitor()

        assert monitor.events == []

    def test_sensitive_items_defined(self):
        """Test that sensitive keychain items are defined."""
        items = KeychainMonitor.SENSITIVE_KEYCHAIN_ITEMS

        assert "Chrome Safe Storage" in items
        assert "Brave Safe Storage" in items

    def test_suspicious_patterns_defined(self):
        """Test that suspicious process patterns are defined."""
        patterns = KeychainMonitor.SUSPICIOUS_PROCESS_PATTERNS

        assert any("python" in p for p in patterns)

    def test_simulate_attack_detection(self):
        """Test the attack simulation feature."""
        monitor = KeychainMonitor()

        event = monitor.simulate_attack_detection()

        assert event.keychain_item == "Chrome Safe Storage"
        assert event.accessing_process == "python3"
        assert event.severity == "critical"
        assert "[SIMULATED]" in event.details


class TestNetworkEvent:
    """Tests for NetworkEvent dataclass."""

    def test_event_creation(self):
        """Test creating a network event."""
        event = NetworkEvent(
            timestamp=datetime.now(),
            destination="files.catbox.moe",
            process="python3",
            event_type="suspicious_connection",
            details="Connection detected",
            severity="critical"
        )

        assert event.destination == "files.catbox.moe"
        assert event.process == "python3"
        assert event.severity == "critical"


class TestNetworkMonitor:
    """Tests for NetworkMonitor class."""

    def test_monitor_creation(self):
        """Test creating a monitor instance."""
        monitor = NetworkMonitor()

        assert monitor.events == []
        assert monitor.blocked_connections == []

    def test_suspicious_domains_defined(self):
        """Test that suspicious domains are defined."""
        domains = NetworkMonitor.SUSPICIOUS_DOMAINS

        assert "catbox.moe" in domains
        assert "pastebin.com" in domains
        assert "api.telegram.org" in domains

    def test_suspicious_processes_defined(self):
        """Test that suspicious processes are defined."""
        processes = NetworkMonitor.SUSPICIOUS_PROCESSES

        assert "python" in processes
        assert "python3" in processes

    def test_add_suspicious_domain(self):
        """Test adding a new suspicious domain."""
        monitor = NetworkMonitor()
        initial_count = len(monitor.SUSPICIOUS_DOMAINS)

        monitor.add_suspicious_domain("evil.example.com")

        assert "evil.example.com" in monitor.SUSPICIOUS_DOMAINS
        assert len(monitor.SUSPICIOUS_DOMAINS) == initial_count + 1

    def test_get_monitored_domains(self):
        """Test getting list of monitored domains."""
        monitor = NetworkMonitor()

        domains = monitor.get_monitored_domains()

        assert isinstance(domains, list)
        assert len(domains) > 0

    def test_simulate_exfiltration_detection(self):
        """Test the exfiltration simulation feature."""
        monitor = NetworkMonitor()

        event = monitor.simulate_exfiltration_detection()

        assert event.destination == "files.catbox.moe"
        assert event.process == "python3"
        assert event.severity == "critical"
        assert "[SIMULATED]" in event.details

    def test_get_network_summary(self):
        """Test getting network summary."""
        monitor = NetworkMonitor()

        summary = monitor.get_network_summary()

        assert "total_connections" in summary
        assert "suspicious_connections" in summary
        assert "events_detected" in summary