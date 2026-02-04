"""
phase1/common/logger.py

Logging utility for Phase 1 with dual output (console + file).
"""

import sys
import os
from datetime import datetime
from typing import TextIO, Optional, List


# Global state for logging
_console_stream: TextIO = sys.stdout
_file_stream: Optional[TextIO] = None
_log_file_path: Optional[str] = None
_suppress_console: bool = False


def setup_logging(output_dir: str, log_filename: str = "phase1.log") -> str:
    """
    Set up logging to both console and file.

    Args:
        output_dir: Directory where log file will be created
        log_filename: Name of the log file

    Returns:
        Path to the log file
    """
    global _file_stream, _log_file_path

    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)

    # Close existing file stream if any
    if _file_stream is not None:
        try:
            _file_stream.close()
        except:
            pass

    # Open new log file
    _log_file_path = os.path.join(output_dir, log_filename)
    _file_stream = open(_log_file_path, "w", buffering=1)  # Line buffered

    # Write header
    _file_stream.write(f"{'=' * 70}\n")
    _file_stream.write(f"Phase 1: System Introspection Log\n")
    _file_stream.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    _file_stream.write(f"{'=' * 70}\n\n")
    _file_stream.flush()

    return _log_file_path


def log(message: str, level: str = "INFO"):
    """
    Log a message to both console and file.

    Args:
        message: The message to log
        level: Log level (INFO, WARNING, ERROR, DEBUG)
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    formatted = f"[{timestamp}] [{level}] {message}"

    # Write to console (unless suppressed)
    if not _suppress_console:
        stream = sys.stderr if level == "ERROR" else _console_stream
        print(formatted, file=stream)
        stream.flush()

    # Write to file (if configured)
    if _file_stream is not None:
        try:
            _file_stream.write(formatted + "\n")
            _file_stream.flush()
        except:
            pass  # Don't crash if file write fails


def set_log_stream(stream: TextIO):
    """
    Set the output stream for console log messages.

    Args:
        stream: A file-like object (e.g., sys.stderr, open('log.txt', 'w'))
    """
    global _console_stream
    _console_stream = stream


def suppress_console(suppress: bool = True):
    """
    Suppress console output (file logging continues).

    Args:
        suppress: Whether to suppress console output
    """
    global _suppress_console
    _suppress_console = suppress


def get_log_file_path() -> Optional[str]:
    """Get the current log file path."""
    return _log_file_path


def close_logging():
    """Close the log file (call at end of execution)."""
    global _file_stream, _log_file_path

    if _file_stream is not None:
        try:
            _file_stream.write(f"\n{'=' * 70}\n")
            _file_stream.write(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            _file_stream.write(f"{'=' * 70}\n")
            _file_stream.close()
        except:
            pass
        _file_stream = None