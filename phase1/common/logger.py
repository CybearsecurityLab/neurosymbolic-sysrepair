"""
phase1/common/logger.py

Centralized logging utility for the Phase 1 pipeline.
Allows redirecting progress output to stderr or devnull.
"""

import sys
from typing import TextIO, Any

# Default to stdout
_log_stream: Any = sys.stdout


def log(msg: str):
    """
    Print a message to the configured log stream.

    Args:
        msg: The message string to print.
    """
    try:
        print(msg, file=_log_stream)
        # Flush to ensure immediate output for long-running processes
        if hasattr(_log_stream, "flush"):
            _log_stream.flush()
    except (IOError, BrokenPipeError):
        # Handle cases where the pipe is closed (e.g. | head)
        # Reopen stdout to /dev/null to suppress further errors
        import os

        sys.stdout = open(os.devnull, "w")


def set_log_stream(stream: TextIO):
    """
    Set the output stream for log messages.

    Args:
        stream: A file-like object (e.g., sys.stderr, open('log.txt', 'w'))
    """
    global _log_stream
    _log_stream = stream
