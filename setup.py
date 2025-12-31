#!/usr/bin/env python3
"""
Setup script for Cookie Theft Detector.

This file enables the package to be installed via pip and
provides metadata for package distribution.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

setup(
    name="cookie-theft-detector",
    version="1.0.0",
    author="Amarendra Mishra",
    description="A security tool that detects browser cookie theft attempts on macOS",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/amarendra-008/Cookie-Theft-Detector",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS :: MacOS X",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    ],
    python_requires=">=3.9",
    entry_points={
        "console_scripts": [
            "cookie-theft-detector=cookie_theft_detector.cli:main",
        ],
    },
    keywords=[
        "security",
        "cookies",
        "browser",
        "detection",
        "monitoring",
        "macos",
    ],
)
