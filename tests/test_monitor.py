"""
Tests for the main monitor orchestration module.
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch

from cookie_theft_detector.monitor import CookieTheftMonitor, MonitorStatus


class TestMonitorStatus:
    """Tests for MonitorStatus dataclass."""

    def test_status_creation(self):
        """Test creating a monitor status."""
        status = MonitorStatus(
            is_running=True,
            start_time=datetime.now(),
            browsers_monitored=["chrome", "brave"],
            total_checks=10,
            threats_detected=2
        )

        assert status.is_running == True
        assert len(status.browsers_monitored) == 2
        assert status.total_checks == 10
        assert status.threats_detected == 2


class TestCookieTheftMonitor:
    """Tests for CookieTheftMonitor class."""

    def test_monitor_creation(self):
        """Test creating a monitor instance."""
        monitor = CookieTheftMonitor()

        assert monitor.alert_manager is not None
        assert monitor.cookie_detector is not None
        assert monitor.keychain_monitor is not None
        assert monitor.network_monitor is not None

    def test_monitor_with_callback(self):
        """Test creating a monitor with alert callback."""
        callback = MagicMock()
        monitor = CookieTheftMonitor(alert_callback=callback)

        assert monitor.alert_callback == callback

    def test_initialize(self):
        """Test monitor initialization."""
        monitor = CookieTheftMonitor()

        result = monitor.initialize()

        assert "cookie_detector" in result
        assert "keychain_monitor" in result
        assert "network_monitor" in result
        assert "browsers_found" in result

    def test_get_status_before_start(self):
        """Test getting status before monitoring starts."""
        monitor = CookieTheftMonitor()

        status = monitor.get_status()

        assert status.is_running == False
        assert status.start_time is None
        assert status.total_checks == 0
        assert status.threats_detected == 0

    def test_run_single_check(self):
        """Test running a single security check."""
        monitor = CookieTheftMonitor()
        monitor.initialize()

        findings = monitor.run_single_check()

        assert "timestamp" in findings
        assert "cookie_events" in findings
        assert "keychain_events" in findings
        assert "network_events" in findings
        assert "total_threats" in findings

    def test_get_full_report(self):
        """Test generating a full security report."""
        monitor = CookieTheftMonitor()
        monitor.initialize()

        report = monitor.get_full_report()

        assert "report_time" in report
        assert "monitor_status" in report
        assert "browsers_monitored" in report
        assert "threat_summary" in report
        assert "network_status" in report
        assert "recent_alerts" in report

    def test_run_demo(self):
        """Test running demo mode."""
        monitor = CookieTheftMonitor()
        monitor.alert_manager.enable_notifications = False
        monitor.initialize()

        report = monitor.run_demo()

        assert report["threat_summary"]["total_threats_detected"] >= 2

    def test_stop_monitoring(self):
        """Test stopping the monitor."""
        monitor = CookieTheftMonitor()

        # Should not raise even if not started
        monitor.stop_monitoring()

        status = monitor.get_status()
        assert status.is_running == False

    def test_handle_cookie_event(self):
        """Test handling a cookie access event."""
        callback = MagicMock()
        monitor = CookieTheftMonitor(alert_callback=callback)
        monitor.alert_manager.enable_notifications = False

        # Create a mock event
        from cookie_theft_detector.detectors.cookie_access import CookieAccessEvent
        from pathlib import Path

        event = CookieAccessEvent(
            timestamp=datetime.now(),
            browser="chrome",
            cookie_path=Path("/test"),
            event_type="modified",
            details="Test event",
            severity="high"
        )

        monitor._handle_cookie_event(event)

        assert monitor._threat_count == 1
        callback.assert_called_once()

    def test_handle_keychain_event(self):
        """Test handling a keychain access event."""
        callback = MagicMock()
        monitor = CookieTheftMonitor(alert_callback=callback)
        monitor.alert_manager.enable_notifications = False

        from cookie_theft_detector.detectors.keychain_monitor import KeychainAccessEvent

        event = KeychainAccessEvent(
            timestamp=datetime.now(),
            keychain_item="Chrome Safe Storage",
            accessing_process="python3",
            event_type="key_extraction",
            details="Test event",
            severity="critical"
        )

        monitor._handle_keychain_event(event)

        assert monitor._threat_count == 1
        callback.assert_called_once()

    def test_handle_network_event(self):
        """Test handling a network event."""
        callback = MagicMock()
        monitor = CookieTheftMonitor(alert_callback=callback)
        monitor.alert_manager.enable_notifications = False

        from cookie_theft_detector.detectors.network_monitor import NetworkEvent

        event = NetworkEvent(
            timestamp=datetime.now(),
            destination="catbox.moe",
            process="python3",
            event_type="suspicious_connection",
            details="Test event",
            severity="critical"
        )

        monitor._handle_network_event(event)

        assert monitor._threat_count == 1
        callback.assert_called_once()