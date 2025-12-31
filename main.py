#!/usr/bin/env python3
"""
Cookie Theft Detector

A defensive security tool that monitors for and detects attempts
to steal browser cookies on macOS systems.

Usage:
    python main.py scan      # Run a quick scan
    python main.py monitor   # Start real-time monitoring
    python main.py demo      # Run demonstration mode
    python main.py report    # Generate security report
"""

from cookie_theft_detector.cli import main

if __name__ == "__main__":
    main()
