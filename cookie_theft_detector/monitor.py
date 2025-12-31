"""
Cookie Theft Detector - Monitor

Main orchestration module that coordinates all detection components
and provides a unified monitoring interface.
"""

import time
import threading
from datetime import datetime
from typing import Optional, Callable
from dataclasses import dataclass

from .detectors import CookieAccessDetector, KeychainMonitor, NetworkMonitor
from .alerts import AlertManager, Alert


@dataclass
class MonitorStatus:
    """Current status of the monitor."""
    is_running: bool
    start_time: Optional[datetime]
    browsers_monitored: list[str]
    total_checks: int
    threats_detected: int


class CookieTheftMonitor:
    """
    Main monitoring orchestrator for Cookie Theft Detector.

    Coordinates all detection components:
    - Cookie file access monitoring
    - Keychain access detection
    - Network exfiltration detection

    Provides unified alerting and reporting.
    """

    def __init__(self, alert_callback: Optional[Callable[[Alert], None]] = None):
        self.alert_manager = AlertManager()
        self.alert_callback = alert_callback

        # Initialize detectors with callbacks
        self.cookie_detector = CookieAccessDetector(
            callback=self._handle_cookie_event
        )
        self.keychain_monitor = KeychainMonitor(
            callback=self._handle_keychain_event
        )
        self.network_monitor = NetworkMonitor(
            callback=self._handle_network_event
        )

        # State
        self._running = False
        self._start_time: Optional[datetime] = None
        self._check_count = 0
        self._threat_count = 0
        self._monitor_thread: Optional[threading.Thread] = None

    def _handle_cookie_event(self, event):
        """Handle events from cookie access detector."""
        alert = self.alert_manager.create_alert(
            severity=event.severity,
            category="cookie_access",
            title=f"Cookie Database Access Detected - {event.browser}",
            description=event.details,
            raw_event={"browser": event.browser, "path": str(event.cookie_path)}
        )
        self._threat_count += 1
        if self.alert_callback:
            self.alert_callback(alert)

    def _handle_keychain_event(self, event):
        """Handle events from keychain monitor."""
        alert = self.alert_manager.create_alert(
            severity=event.severity,
            category="keychain",
            title=f"Keychain Access Detected - {event.keychain_item}",
            description=event.details,
            raw_event={"item": event.keychain_item, "process": event.accessing_process}
        )
        self._threat_count += 1
        if self.alert_callback:
            self.alert_callback(alert)

    def _handle_network_event(self, event):
        """Handle events from network monitor."""
        alert = self.alert_manager.create_alert(
            severity=event.severity,
            category="network",
            title=f"Suspicious Network Activity - {event.process}",
            description=event.details,
            raw_event={"destination": event.destination, "process": event.process}
        )
        self._threat_count += 1
        if self.alert_callback:
            self.alert_callback(alert)

    def initialize(self) -> dict:
        """
        Initialize the monitor and establish baselines.
        Returns initialization status.
        """
        results = {
            "cookie_detector": False,
            "keychain_monitor": False,
            "network_monitor": False,
            "browsers_found": [],
        }

        # Initialize cookie detector
        try:
            baseline = self.cookie_detector.establish_baseline()
            results["cookie_detector"] = True
            results["browsers_found"] = list(baseline.keys())
        except Exception as e:
            results["cookie_detector_error"] = str(e)

        # Initialize keychain monitor
        try:
            status = self.keychain_monitor.get_protection_status()
            results["keychain_monitor"] = True
            results["keychain_items"] = status.get("detected_items", [])
        except Exception as e:
            results["keychain_monitor_error"] = str(e)

        # Initialize network monitor
        try:
            summary = self.network_monitor.get_network_summary()
            results["network_monitor"] = True
            results["active_connections"] = summary.get("total_connections", 0)
        except Exception as e:
            results["network_monitor_error"] = str(e)

        return results

    def run_single_check(self) -> dict:
        """
        Run a single check across all detectors.
        Returns summary of findings.
        """
        self._check_count += 1
        findings = {
            "timestamp": datetime.now().isoformat(),
            "cookie_events": [],
            "keychain_events": [],
            "network_events": [],
        }

        # Run cookie check
        cookie_events = self.cookie_detector.check_for_anomalies()
        findings["cookie_events"] = [
            {"browser": e.browser, "type": e.event_type, "severity": e.severity}
            for e in cookie_events
        ]

        # Run keychain check
        keychain_events = self.keychain_monitor.check_for_threats()
        findings["keychain_events"] = [
            {"item": e.keychain_item, "process": e.accessing_process, "severity": e.severity}
            for e in keychain_events
        ]

        # Run network check
        network_events = self.network_monitor.check_for_exfiltration()
        findings["network_events"] = [
            {"destination": e.destination, "process": e.process, "severity": e.severity}
            for e in network_events
        ]

        findings["total_threats"] = (
            len(cookie_events) + len(keychain_events) + len(network_events)
        )

        return findings

    def _monitoring_loop(self, interval: float):
        """Main monitoring loop."""
        while self._running:
            self.run_single_check()
            time.sleep(interval)

    def start_monitoring(self, interval: float = 5.0, background: bool = True):
        """
        Start continuous monitoring.

        Args:
            interval: Seconds between checks
            background: Run in background thread if True
        """
        self._running = True
        self._start_time = datetime.now()

        # Establish initial baselines
        self.initialize()

        if background:
            self._monitor_thread = threading.Thread(
                target=self._monitoring_loop,
                args=(interval,),
                daemon=True
            )
            self._monitor_thread.start()
        else:
            self._monitoring_loop(interval)

    def stop_monitoring(self):
        """Stop all monitoring."""
        self._running = False
        self.cookie_detector.stop_monitoring()
        self.keychain_monitor.stop_monitoring()
        self.network_monitor.stop_monitoring()

        if self._monitor_thread:
            self._monitor_thread.join(timeout=5)

    def get_status(self) -> MonitorStatus:
        """Get current monitor status."""
        return MonitorStatus(
            is_running=self._running,
            start_time=self._start_time,
            browsers_monitored=self.cookie_detector.get_detected_browsers(),
            total_checks=self._check_count,
            threats_detected=self._threat_count
        )

    def get_full_report(self) -> dict:
        """Generate comprehensive security report."""
        status = self.get_status()
        alert_summary = self.alert_manager.get_alert_summary()
        network_summary = self.network_monitor.get_network_summary()

        return {
            "report_time": datetime.now().isoformat(),
            "monitor_status": {
                "running": status.is_running,
                "start_time": status.start_time.isoformat() if status.start_time else None,
                "uptime_seconds": (datetime.now() - status.start_time).total_seconds() if status.start_time else 0,
                "total_checks": status.total_checks,
            },
            "browsers_monitored": status.browsers_monitored,
            "threat_summary": {
                "total_threats_detected": status.threats_detected,
                "alerts": alert_summary,
            },
            "network_status": network_summary,
            "recent_alerts": [
                a.to_dict() for a in self.alert_manager.get_recent_alerts(5)
            ]
        }

    def run_demo(self):
        """
        Run a demonstration of the detection capabilities.
        Simulates attack detection without actual threats.
        """
        print("\n[DEMO MODE] Simulating cookie theft detection...\n")

        # Simulate cookie access detection
        cookie_event = self.cookie_detector.check_for_anomalies()

        # Simulate keychain detection
        keychain_sim = self.keychain_monitor.simulate_attack_detection()
        self._handle_keychain_event(keychain_sim)

        # Simulate network detection
        network_sim = self.network_monitor.simulate_exfiltration_detection()
        self._handle_network_event(network_sim)

        return self.get_full_report()
