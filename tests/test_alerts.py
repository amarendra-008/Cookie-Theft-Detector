"""
Tests for the alert management system.
"""

import pytest
from datetime import datetime

from cookie_theft_detector.alerts import Alert, AlertManager, AlertSeverity


class TestAlertSeverity:
    """Tests for AlertSeverity enum."""

    def test_severity_values(self):
        """Verify all severity levels exist."""
        assert AlertSeverity.LOW.value == "low"
        assert AlertSeverity.MEDIUM.value == "medium"
        assert AlertSeverity.HIGH.value == "high"
        assert AlertSeverity.CRITICAL.value == "critical"


class TestAlert:
    """Tests for Alert dataclass."""

    def test_alert_creation(self):
        """Test creating an alert with required fields."""
        alert = Alert(
            id="CTD-20251231-0001",
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            category="cookie_access",
            title="Test Alert",
            description="This is a test alert",
            recommendation="Take action"
        )

        assert alert.id == "CTD-20251231-0001"
        assert alert.severity == AlertSeverity.HIGH
        assert alert.category == "cookie_access"
        assert alert.title == "Test Alert"

    def test_alert_to_dict(self):
        """Test converting alert to dictionary."""
        alert = Alert(
            id="CTD-20251231-0001",
            timestamp=datetime(2025, 12, 31, 12, 0, 0),
            severity=AlertSeverity.CRITICAL,
            category="keychain",
            title="Keychain Access",
            description="Detected keychain access",
            recommendation="Check processes"
        )

        result = alert.to_dict()

        assert result["id"] == "CTD-20251231-0001"
        assert result["severity"] == "critical"
        assert result["category"] == "keychain"
        assert "timestamp" in result

    def test_alert_to_json(self):
        """Test converting alert to JSON string."""
        alert = Alert(
            id="CTD-20251231-0001",
            timestamp=datetime(2025, 12, 31, 12, 0, 0),
            severity=AlertSeverity.MEDIUM,
            category="network",
            title="Network Alert",
            description="Suspicious connection",
            recommendation="Block connection"
        )

        json_str = alert.to_json()

        assert "CTD-20251231-0001" in json_str
        assert "medium" in json_str
        assert "network" in json_str


class TestAlertManager:
    """Tests for AlertManager class."""

    def test_create_alert_manager(self):
        """Test creating an AlertManager instance."""
        manager = AlertManager()

        assert manager.alerts == []
        assert manager.enable_notifications == True

    def test_create_alert(self):
        """Test creating an alert through the manager."""
        manager = AlertManager()
        manager.enable_notifications = False  # Disable for testing

        alert = manager.create_alert(
            severity="high",
            category="cookie_access",
            title="Test Alert",
            description="Test description"
        )

        assert alert.severity == AlertSeverity.HIGH
        assert alert.category == "cookie_access"
        assert len(manager.alerts) == 1

    def test_alert_id_generation(self):
        """Test that alert IDs are unique and incremental."""
        manager = AlertManager()
        manager.enable_notifications = False

        alert1 = manager.create_alert(
            severity="low",
            category="test",
            title="Alert 1",
            description="First alert"
        )

        alert2 = manager.create_alert(
            severity="low",
            category="test",
            title="Alert 2",
            description="Second alert"
        )

        assert alert1.id != alert2.id
        assert "CTD-" in alert1.id
        assert "CTD-" in alert2.id

    def test_get_alerts_by_severity(self):
        """Test filtering alerts by severity."""
        manager = AlertManager()
        manager.enable_notifications = False

        manager.create_alert(severity="low", category="test", title="Low", description="")
        manager.create_alert(severity="high", category="test", title="High", description="")
        manager.create_alert(severity="low", category="test", title="Low 2", description="")

        low_alerts = manager.get_alerts_by_severity(AlertSeverity.LOW)
        high_alerts = manager.get_alerts_by_severity(AlertSeverity.HIGH)

        assert len(low_alerts) == 2
        assert len(high_alerts) == 1

    def test_get_recent_alerts(self):
        """Test getting recent alerts."""
        manager = AlertManager()
        manager.enable_notifications = False

        for i in range(15):
            manager.create_alert(
                severity="low",
                category="test",
                title=f"Alert {i}",
                description=""
            )

        recent = manager.get_recent_alerts(count=5)

        assert len(recent) == 5

    def test_get_alert_summary(self):
        """Test generating alert summary."""
        manager = AlertManager()
        manager.enable_notifications = False

        manager.create_alert(severity="low", category="cookie_access", title="", description="")
        manager.create_alert(severity="high", category="cookie_access", title="", description="")
        manager.create_alert(severity="critical", category="network", title="", description="")

        summary = manager.get_alert_summary()

        assert summary["total"] == 3
        assert summary["by_severity"]["low"] == 1
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_category"]["cookie_access"] == 2
        assert summary["by_category"]["network"] == 1

    def test_clear_alerts(self):
        """Test clearing all alerts."""
        manager = AlertManager()
        manager.enable_notifications = False

        manager.create_alert(severity="low", category="test", title="", description="")
        manager.create_alert(severity="high", category="test", title="", description="")

        assert len(manager.alerts) == 2

        manager.clear_alerts()

        assert len(manager.alerts) == 0
