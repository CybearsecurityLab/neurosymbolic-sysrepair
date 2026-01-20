"""
phase1/common/logger.py

Simple logging utility for Phase 1.
"""

import sys
from datetime import datetime
from typing import TextIO


def log(message: str, level: str = "INFO"):
    """
    Simple logging function that prints to stdout.
    
    Args:
        message: The message to log
        level: Log level (INFO, WARNING, ERROR, DEBUG)
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}", file=sys.stderr if level == "ERROR" else sys.stdout)

def set_log_stream(stream: TextIO):
    """
    Set the output stream for log messages.

    Args:
        stream: A file-like object (e.g., sys.stderr, open('log.txt', 'w'))
    """
    global _log_stream
    _log_stream = stream