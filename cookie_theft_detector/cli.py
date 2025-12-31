"""
Cookie Theft Detector CLI

Command-line interface for the Cookie Theft Detector.
Provides real-time monitoring, scanning, and reporting capabilities.
"""

import argparse
import sys
import time
import json
import signal
from datetime import datetime

from .monitor import CookieTheftMonitor
from .alerts import Alert


# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


BANNER = f"""{Colors.CYAN}{Colors.BOLD}
   ___           _   _        _____ _          __ _
  / __|___  ___ | |_(_)___   |_   _| |_  ___ / _| |_
 | (__/ _ \\/ _ \\| / / / -_)    | | | ' \\/ -_)  _|  _|
  \\___\\___/\\___/|_\\_\\_\\___|    |_| |_||_\\___|_|  \\__|
  ___      _          _
 |   \\ ___| |_ ___ __| |_ ___ _ _
 | |) / -_)  _/ -_) _|  _/ _ \\ '_|
 |___/\\___|\\__\\___\\__|\\__\\___/_|
{Colors.RESET}
{Colors.DIM}v1.0.0 - Defensive Security Tool for macOS{Colors.RESET}
"""


def print_status(message: str, status: str = "info"):
    """Print a status message with appropriate formatting."""
    icons = {
        "info": f"{Colors.BLUE}[*]{Colors.RESET}",
        "success": f"{Colors.GREEN}[+]{Colors.RESET}",
        "warning": f"{Colors.YELLOW}[!]{Colors.RESET}",
        "error": f"{Colors.RED}[-]{Colors.RESET}",
        "critical": f"{Colors.RED}{Colors.BOLD}[!!!]{Colors.RESET}",
    }
    icon = icons.get(status, icons["info"])
    print(f"{icon} {message}")


def print_section(title: str):
    """Print a section header."""
    print(f"\n{Colors.BOLD}{Colors.CYAN}{'=' * 50}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {title}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 50}{Colors.RESET}\n")


def format_alert(alert: Alert) -> str:
    """Format an alert for display."""
    severity_colors = {
        "low": Colors.BLUE,
        "medium": Colors.YELLOW,
        "high": Colors.RED,
        "critical": Colors.RED + Colors.BOLD,
    }
    color = severity_colors.get(alert.severity.value, Colors.RESET)

    return f"""
{color}[{alert.severity.value.upper()}]{Colors.RESET} {Colors.BOLD}{alert.title}{Colors.RESET}
  {Colors.DIM}ID:{Colors.RESET} {alert.id}
  {Colors.DIM}Time:{Colors.RESET} {alert.timestamp.strftime('%H:%M:%S')}
  {Colors.DIM}Details:{Colors.RESET} {alert.description}
  {Colors.DIM}Action:{Colors.RESET} {alert.recommendation}
"""


def handle_alert(alert: Alert):
    """Handle incoming alerts during monitoring."""
    print(format_alert(alert))


def cmd_scan(args):
    """Run a single security scan."""
    print(BANNER)
    print_section("Security Scan")

    monitor = CookieTheftMonitor(alert_callback=handle_alert)

    print_status("Initializing detectors...")
    init_result = monitor.initialize()

    # Display initialization results
    if init_result.get("cookie_detector"):
        browsers = init_result.get("browsers_found", [])
        print_status(f"Cookie detector ready - monitoring {len(browsers)} browser(s)", "success")
        for browser in browsers:
            print(f"    {Colors.DIM}-> {browser}{Colors.RESET}")
    else:
        print_status("Cookie detector failed to initialize", "error")

    if init_result.get("keychain_monitor"):
        print_status("Keychain monitor ready", "success")
    else:
        print_status("Keychain monitor failed to initialize", "error")

    if init_result.get("network_monitor"):
        conns = init_result.get("active_connections", 0)
        print_status(f"Network monitor ready - {conns} active connections", "success")
    else:
        print_status("Network monitor failed to initialize", "error")

    print_status("\nRunning security checks...")

    # Run the scan
    findings = monitor.run_single_check()

    # Display results
    print_section("Scan Results")

    total_threats = findings.get("total_threats", 0)

    if total_threats == 0:
        print_status("No threats detected!", "success")
        print(f"\n{Colors.GREEN}Your browser cookies appear to be secure.{Colors.RESET}\n")
    else:
        print_status(f"Detected {total_threats} potential threat(s)!", "critical")

        for alert in monitor.alert_manager.get_recent_alerts():
            print(format_alert(alert))

    # Show summary
    print_section("Summary")
    print(f"  Browsers scanned: {len(init_result.get('browsers_found', []))}")
    print(f"  Threats detected: {total_threats}")
    print(f"  Scan time: {findings.get('timestamp', 'N/A')}")


def cmd_monitor(args):
    """Start continuous monitoring."""
    print(BANNER)
    print_section("Real-Time Monitoring")

    monitor = CookieTheftMonitor(alert_callback=handle_alert)

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print_status("\nStopping monitor...", "warning")
        monitor.stop_monitoring()
        report = monitor.get_full_report()
        print_section("Session Summary")
        print(f"  Duration: {report['monitor_status']['uptime_seconds']:.1f} seconds")
        print(f"  Checks performed: {report['monitor_status']['total_checks']}")
        print(f"  Threats detected: {report['threat_summary']['total_threats_detected']}")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    print_status("Initializing detectors...")
    init_result = monitor.initialize()

    browsers = init_result.get("browsers_found", [])
    print_status(f"Monitoring {len(browsers)} browser(s)", "success")

    print_status(f"Starting monitoring (interval: {args.interval}s)...", "info")
    print_status("Press Ctrl+C to stop\n", "info")

    print(f"{Colors.DIM}Watching for:{Colors.RESET}")
    print(f"  {Colors.DIM}-> Unauthorized cookie database access{Colors.RESET}")
    print(f"  {Colors.DIM}-> Keychain encryption key extraction{Colors.RESET}")
    print(f"  {Colors.DIM}-> Suspicious network exfiltration{Colors.RESET}")
    print()

    # Start monitoring
    monitor.start_monitoring(interval=args.interval, background=True)

    # Keep main thread alive and show heartbeat
    check_count = 0
    while True:
        time.sleep(args.interval)
        check_count += 1
        status = monitor.get_status()
        if check_count % 12 == 0:  # Every minute at 5s intervals
            print_status(
                f"Heartbeat: {status.total_checks} checks, "
                f"{status.threats_detected} threats",
                "info"
            )


def cmd_demo(args):
    """Run demonstration mode."""
    print(BANNER)
    print_section("Demonstration Mode")

    print_status("This demo simulates attack detection without actual threats.\n", "info")

    monitor = CookieTheftMonitor(alert_callback=handle_alert)
    monitor.initialize()

    print_status("Simulating cookie theft attack...\n", "warning")
    time.sleep(1)

    report = monitor.run_demo()

    print_section("Detection Summary")
    print(f"  Alerts generated: {report['threat_summary']['alerts']['total']}")
    print(f"  Critical: {report['threat_summary']['alerts']['by_severity']['critical']}")
    print(f"  High: {report['threat_summary']['alerts']['by_severity']['high']}")

    print(f"\n{Colors.GREEN}Demo complete! Successfully detected the simulated attack.{Colors.RESET}\n")


def cmd_report(args):
    """Generate a security report."""
    print(BANNER)
    print_section("Security Report")

    monitor = CookieTheftMonitor()
    init_result = monitor.initialize()
    findings = monitor.run_single_check()
    report = monitor.get_full_report()

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"{Colors.BOLD}Report Generated:{Colors.RESET} {report['report_time']}")
        print(f"\n{Colors.BOLD}Browsers Monitored:{Colors.RESET}")
        for browser in report['browsers_monitored']:
            print(f"  - {browser}")

        print(f"\n{Colors.BOLD}Network Status:{Colors.RESET}")
        net = report['network_status']
        print(f"  Active connections: {net['total_connections']}")
        print(f"  Suspicious connections: {net['suspicious_connections']}")

        print(f"\n{Colors.BOLD}Threat Summary:{Colors.RESET}")
        threats = report['threat_summary']
        print(f"  Total detected: {threats['total_threats_detected']}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print_status(f"Report saved to {args.output}", "success")


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description="Cookie Theft Detector - Defensive Security Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py scan              Run a quick security scan
  python main.py monitor           Start real-time monitoring
  python main.py monitor -i 10     Monitor with 10-second intervals
  python main.py demo              Run a demonstration
  python main.py report --json     Generate JSON report
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Run a quick security scan")
    scan_parser.set_defaults(func=cmd_scan)

    # Monitor command
    monitor_parser = subparsers.add_parser("monitor", help="Start real-time monitoring")
    monitor_parser.add_argument(
        "-i", "--interval",
        type=float,
        default=5.0,
        help="Check interval in seconds (default: 5)"
    )
    monitor_parser.set_defaults(func=cmd_monitor)

    # Demo command
    demo_parser = subparsers.add_parser("demo", help="Run demonstration mode")
    demo_parser.set_defaults(func=cmd_demo)

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate security report")
    report_parser.add_argument(
        "--json",
        action="store_true",
        help="Output report as JSON"
    )
    report_parser.add_argument(
        "-o", "--output",
        type=str,
        help="Save report to file"
    )
    report_parser.set_defaults(func=cmd_report)

    args = parser.parse_args()

    if args.command is None:
        # Default to scan if no command provided
        args.func = cmd_scan
        args.func(args)
    else:
        args.func(args)


if __name__ == "__main__":
    main()
