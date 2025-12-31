"""
Alert System

Handles alert generation, formatting, and notification delivery
for detected security events.
"""

import json
import subprocess
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import Optional
from enum import Enum


class AlertSeverity(Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    """Represents a security alert."""
    id: str
    timestamp: datetime
    severity: AlertSeverity
    category: str  # 'cookie_access', 'keychain', 'network'
    title: str
    description: str
    recommendation: str
    raw_event: Optional[dict] = None

    def to_dict(self) -> dict:
        """Convert alert to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "recommendation": self.recommendation,
        }

    def to_json(self) -> str:
        """Convert alert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class AlertManager:
    """
    Manages security alerts and notifications.
    """

    SEVERITY_COLORS = {
        AlertSeverity.LOW: "\033[94m",      # Blue
        AlertSeverity.MEDIUM: "\033[93m",   # Yellow
        AlertSeverity.HIGH: "\033[91m",     # Red
        AlertSeverity.CRITICAL: "\033[95m", # Magenta
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"

    def __init__(self):
        self.alerts: list[Alert] = []
        self._alert_counter = 0
        self.enable_notifications = True
        self.enable_sound = True

    def _generate_id(self) -> str:
        """Generate unique alert ID."""
        self._alert_counter += 1
        return f"CTD-{datetime.now().strftime('%Y%m%d')}-{self._alert_counter:04d}"

    def create_alert(
        self,
        severity: str,
        category: str,
        title: str,
        description: str,
        recommendation: str = "",
        raw_event: Optional[dict] = None
    ) -> Alert:
        """Create and store a new alert."""

        # Convert string severity to enum
        sev = AlertSeverity(severity.lower())

        alert = Alert(
            id=self._generate_id(),
            timestamp=datetime.now(),
            severity=sev,
            category=category,
            title=title,
            description=description,
            recommendation=recommendation or self._get_default_recommendation(category),
            raw_event=raw_event
        )

        self.alerts.append(alert)

        # Send notifications
        if self.enable_notifications:
            self._send_notification(alert)

        if self.enable_sound and sev in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
            self._play_alert_sound()

        return alert

    def _get_default_recommendation(self, category: str) -> str:
        """Get default recommendation based on alert category."""
        recommendations = {
            "cookie_access": "Review recently installed applications and running processes. Consider rotating browser sessions.",
            "keychain": "Check for unauthorized applications with keychain access in System Preferences > Security & Privacy.",
            "network": "Monitor outbound network traffic and consider blocking suspicious connections with a firewall.",
        }
        return recommendations.get(category, "Investigate the alert and take appropriate action.")

    def _send_notification(self, alert: Alert):
        """Send macOS notification for alert."""
        try:
            severity_emoji = {
                AlertSeverity.LOW: "info",
                AlertSeverity.MEDIUM: "caution",
                AlertSeverity.HIGH: "stop",
                AlertSeverity.CRITICAL: "stop",
            }

            script = f'''
            display notification "{alert.description}" with title "CookieGuard Alert" subtitle "{alert.title}" sound name "Basso"
            '''

            subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                timeout=5
            )
        except Exception:
            pass

    def _play_alert_sound(self):
        """Play alert sound for critical alerts."""
        try:
            subprocess.run(
                ["afplay", "/System/Library/Sounds/Sosumi.aiff"],
                capture_output=True,
                timeout=5
            )
        except Exception:
            pass

    def format_alert(self, alert: Alert, use_color: bool = True) -> str:
        """Format alert for terminal display."""
        if use_color:
            color = self.SEVERITY_COLORS[alert.severity]
            return f"""
{self.BOLD}{color}[{alert.severity.value.upper()}]{self.RESET} {alert.title}
{color}ID:{self.RESET} {alert.id}
{color}Time:{self.RESET} {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
{color}Category:{self.RESET} {alert.category}
{color}Description:{self.RESET} {alert.description}
{color}Recommendation:{self.RESET} {alert.recommendation}
"""
        else:
            return f"""
[{alert.severity.value.upper()}] {alert.title}
ID: {alert.id}
Time: {alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Category: {alert.category}
Description: {alert.description}
Recommendation: {alert.recommendation}
"""

    def get_alerts_by_severity(self, severity: AlertSeverity) -> list[Alert]:
        """Get all alerts of a specific severity."""
        return [a for a in self.alerts if a.severity == severity]

    def get_recent_alerts(self, count: int = 10) -> list[Alert]:
        """Get most recent alerts."""
        return sorted(self.alerts, key=lambda a: a.timestamp, reverse=True)[:count]

    def get_alert_summary(self) -> dict:
        """Get summary of all alerts."""
        return {
            "total": len(self.alerts),
            "by_severity": {
                "low": len(self.get_alerts_by_severity(AlertSeverity.LOW)),
                "medium": len(self.get_alerts_by_severity(AlertSeverity.MEDIUM)),
                "high": len(self.get_alerts_by_severity(AlertSeverity.HIGH)),
                "critical": len(self.get_alerts_by_severity(AlertSeverity.CRITICAL)),
            },
            "by_category": self._count_by_category(),
        }

    def _count_by_category(self) -> dict:
        """Count alerts by category."""
        counts = {}
        for alert in self.alerts:
            counts[alert.category] = counts.get(alert.category, 0) + 1
        return counts

    def export_alerts(self, filepath: str):
        """Export all alerts to JSON file."""
        with open(filepath, 'w') as f:
            json.dump([a.to_dict() for a in self.alerts], f, indent=2)

    def clear_alerts(self):
        """Clear all stored alerts."""
        self.alerts = []
