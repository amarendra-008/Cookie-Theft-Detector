"""
Network Exfiltration Monitor

Detects suspicious network activity that may indicate cookie data
being exfiltrated to external servers. Monitors for connections to
known malicious endpoints and unusual data transfer patterns.
"""

import subprocess
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Callable


@dataclass
class NetworkEvent:
    """Represents a detected network exfiltration event."""
    timestamp: datetime
    destination: str
    process: str
    event_type: str
    details: str
    severity: str


class NetworkMonitor:
    """
    Monitors network activity for signs of cookie exfiltration.

    Detection methods:
    1. Monitor connections to known file hosting/paste sites
    2. Detect unusual outbound data patterns from scripting processes
    3. DNS query analysis for suspicious domains
    """

    # Known exfiltration endpoints used by cookie stealers
    SUSPICIOUS_DOMAINS = [
        # File hosting often used for exfiltration
        "catbox.moe",
        "files.catbox.moe",
        "transfer.sh",
        "file.io",
        "0x0.st",
        "uguu.se",
        "temp.sh",
        "tmpfiles.org",

        # Paste sites
        "pastebin.com",
        "paste.ee",
        "hastebin.com",
        "rentry.co",
        "ghostbin.com",

        # Discord webhooks (common exfil method)
        "discord.com/api/webhooks",
        "discordapp.com/api/webhooks",

        # Telegram bots
        "api.telegram.org",

        # Other suspicious
        "ngrok.io",
        "serveo.net",
        "localhost.run",
    ]

    # Processes that typically don't need outbound connections
    SUSPICIOUS_PROCESSES = [
        "python", "python3", "python2",
        "ruby", "perl", "node",
        "osascript", "bash", "sh", "zsh",
    ]

    def __init__(self, callback: Optional[Callable[[NetworkEvent], None]] = None):
        self.callback = callback
        self.events: list[NetworkEvent] = []
        self._running = False
        self.blocked_connections: list[dict] = []

    def _get_active_connections(self) -> list[dict]:
        """Get list of active network connections."""
        connections = []

        try:
            # Use lsof to get network connections
            result = subprocess.run(
                ["lsof", "-i", "-n", "-P"],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if not line.strip():
                        continue

                    parts = line.split()
                    if len(parts) >= 9:
                        connections.append({
                            "process": parts[0],
                            "pid": parts[1],
                            "user": parts[2],
                            "type": parts[4],
                            "node": parts[7] if len(parts) > 7 else "",
                            "name": parts[8] if len(parts) > 8 else "",
                        })

        except Exception:
            pass

        return connections

    def _check_dns_queries(self) -> list[str]:
        """Check recent DNS queries for suspicious domains."""
        suspicious_queries = []

        try:
            # Query DNS cache (requires admin on some systems)
            result = subprocess.run(
                ["dscacheutil", "-cachedump", "-entries"],
                capture_output=True,
                text=True,
                timeout=10
            )

            output = result.stdout.lower()
            for domain in self.SUSPICIOUS_DOMAINS:
                if domain.lower() in output:
                    suspicious_queries.append(domain)

        except Exception:
            pass

        return suspicious_queries

    def _analyze_connection(self, conn: dict) -> Optional[NetworkEvent]:
        """Analyze a single connection for suspicious activity."""

        process = conn.get("process", "").lower()
        name = conn.get("name", "")

        # Check if connection is from a suspicious process
        is_suspicious_process = any(
            proc in process for proc in self.SUSPICIOUS_PROCESSES
        )

        # Check if connecting to suspicious domain
        is_suspicious_domain = any(
            domain in name.lower() for domain in self.SUSPICIOUS_DOMAINS
        )

        # Determine severity based on combination
        if is_suspicious_domain:
            severity = "critical" if is_suspicious_process else "high"
            return NetworkEvent(
                timestamp=datetime.now(),
                destination=name,
                process=conn.get("process", "unknown"),
                event_type="suspicious_connection",
                details=f"Connection to known exfiltration endpoint: {name}",
                severity=severity
            )

        # Check for suspicious process making any external connection
        if is_suspicious_process and "->" in name:
            # Extract destination
            dest = name.split("->")[-1] if "->" in name else name

            # Skip localhost connections
            if "localhost" in dest or "127.0.0.1" in dest:
                return None

            return NetworkEvent(
                timestamp=datetime.now(),
                destination=dest,
                process=conn.get("process", "unknown"),
                event_type="scripting_outbound",
                details=f"Scripting process '{process}' making outbound connection",
                severity="medium"
            )

        return None

    def _emit_event(self, event: NetworkEvent):
        """Emit a detected event."""
        self.events.append(event)
        if self.callback:
            self.callback(event)

    def check_for_exfiltration(self) -> list[NetworkEvent]:
        """Run all network detection checks."""
        detected = []

        # Check active connections
        connections = self._get_active_connections()
        for conn in connections:
            event = self._analyze_connection(conn)
            if event:
                detected.append(event)
                self._emit_event(event)

        # Check DNS queries
        suspicious_dns = self._check_dns_queries()
        for domain in suspicious_dns:
            event = NetworkEvent(
                timestamp=datetime.now(),
                destination=domain,
                process="dns",
                event_type="suspicious_dns",
                details=f"DNS query to suspicious domain: {domain}",
                severity="high"
            )
            detected.append(event)
            self._emit_event(event)

        return detected

    def get_network_summary(self) -> dict:
        """Get summary of current network state."""
        connections = self._get_active_connections()

        # Categorize connections
        by_process = {}
        for conn in connections:
            proc = conn.get("process", "unknown")
            if proc not in by_process:
                by_process[proc] = []
            by_process[proc].append(conn)

        # Count suspicious
        suspicious_count = sum(
            1 for conn in connections
            if self._analyze_connection(conn) is not None
        )

        return {
            "total_connections": len(connections),
            "suspicious_connections": suspicious_count,
            "connections_by_process": {k: len(v) for k, v in by_process.items()},
            "events_detected": len(self.events)
        }

    def simulate_exfiltration_detection(self) -> NetworkEvent:
        """
        Simulate what detection would look like during an exfiltration attempt.
        Useful for testing and demonstration purposes.
        """
        return NetworkEvent(
            timestamp=datetime.now(),
            destination="files.catbox.moe",
            process="python3",
            event_type="suspicious_connection",
            details="[SIMULATED] Python process uploading data to file hosting service",
            severity="critical"
        )

    def start_monitoring(self, interval: float = 5.0):
        """Start continuous monitoring loop."""
        self._running = True

        while self._running:
            self.check_for_exfiltration()
            time.sleep(interval)

    def stop_monitoring(self):
        """Stop the monitoring loop."""
        self._running = False

    def add_suspicious_domain(self, domain: str):
        """Add a domain to the suspicious list."""
        if domain not in self.SUSPICIOUS_DOMAINS:
            self.SUSPICIOUS_DOMAINS.append(domain)

    def get_monitored_domains(self) -> list[str]:
        """Get list of monitored suspicious domains."""
        return self.SUSPICIOUS_DOMAINS.copy()
