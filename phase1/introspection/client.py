"""
phase1/introspection/client.py

Interfaces for communicating with osquery (Thrift API and Shell fallback).
"""

import json
import subprocess
from abc import ABC, abstractmethod
from typing import Optional, Iterator, List
from phase1.common.logger import log


# =============================================================================
# Abstract Interface
# =============================================================================

class OSQueryInterface(ABC):
    """Abstract interface for osquery operations."""

    @abstractmethod
    def execute_query(self, sql: str) -> List[dict]:
        """Execute an SQL query and return results."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if osquery is available on the system."""
        pass

    def close(self):
        """Clean up resources (optional hook)."""
        pass


# =============================================================================
# Shell Interface (Fallback)
# =============================================================================

class OSQueryShellInterface(OSQueryInterface):
    """
    Interface using osqueryi shell via subprocess.
    Used as a fallback when the python-osquery Thrift library is not available.
    """

    def __init__(self, osqueryi_path: str = "osqueryi"):
        self.osqueryi_path = osqueryi_path
        self._available = False
        self.version = None
        self._check_availability()

    def _check_availability(self):
        """Verify osqueryi is installed and accessible."""
        try:
            result = subprocess.run(
                [self.osqueryi_path, "--version"],
                capture_output=True, text=True, timeout=10
            )
            self._available = result.returncode == 0
            if self._available:
                self.version = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._available = False
            self.version = None

    def is_available(self) -> bool:
        return self._available

    def execute_query(self, sql: str) -> List[dict]:
        """Execute query via osqueryi with JSON output."""
        if not self._available:
            raise RuntimeError("osqueryi is not available")

        try:
            result = subprocess.run(
                [self.osqueryi_path, "--json", sql],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                raise RuntimeError(f"Query failed: {result.stderr}")

            return json.loads(result.stdout) if result.stdout.strip() else []
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse osquery JSON output: {e}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Query timed out")


# =============================================================================
# Thrift Interface (Primary)
# =============================================================================

class OSQueryThriftInterface(OSQueryInterface):
    """
    Interface using osquery Thrift API.
    Requires: pip install osquery==3.1.1

    The osquery library spawns an extension manager instance that communicates
    via Thrift, providing efficient query execution for multiple queries.
    """

    def __init__(self, socket_path: Optional[str] = None):
        """
        Initialize osquery Thrift interface.

        Args:
            socket_path: Optional path to osquery socket. If None, spawns
                        a new instance. Use for connecting to osqueryd.
        """
        self.instance = None
        self.client = None
        self._available = False
        self._version = "unknown"
        self._socket_path = socket_path
        self._initialize()

    def _initialize(self):
        """Initialize osquery extension manager via Thrift API."""
        try:
            import osquery

            if self._socket_path:
                # Connect to existing osqueryd instance
                self.instance = osquery.ExtensionClient(self._socket_path)
                self.instance.open()
                self.client = self.instance.extension_client()
            else:
                # Spawn standalone instance (recommended for Phase 1 introspection)
                self.instance = osquery.SpawnInstance()
                self.instance.open()
                self.client = self.instance.client

            # Verify connection with the test query
            test_result = self.client.query("SELECT version() as v")
            if test_result.status.code == 0:
                self._available = True
                if test_result.response:
                    self._version = test_result.response[0].get("v", "unknown")
            else:
                raise RuntimeError(f"Connection test failed: {test_result.status.message}")

        except ImportError:
            raise RuntimeError(
                "osquery library not installed. Install with: pip install osquery==3.1.1"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to initialize osquery Thrift API: {e}")

    @property
    def version(self) -> str:
        return self._version

    def is_available(self) -> bool:
        return self._available

    def execute_query(self, sql: str) -> List[dict]:
        """
        Execute SQL query via Thrift API.
        Returns list of dicts, each dict representing a row.
        """
        if not self._available or not self.client:
            raise RuntimeError("osquery Thrift API not available")

        result = self.client.query(sql)

        if result.status.code != 0:
            raise RuntimeError(
                f"Query failed (code {result.status.code}): {result.status.message}"
            )

        # Convert ExtensionResponse to list of dicts
        return [dict(row) for row in result.response]

    def get_table_schema(self, table_name: str) -> List[dict]:
        """Get schema information for a table (useful for validation)."""
        return self.execute_query(f"PRAGMA table_info({table_name})")

    def batch_query(self, queries: List[str]) -> Iterator[tuple[str, List[dict]]]:
        """
        Execute multiple queries efficiently over single Thrift connection.
        Yields (query, results) tuples.
        """
        for sql in queries:
            try:
                yield sql, self.execute_query(sql)
            except RuntimeError as e:
                yield sql, []  # Return empty on error, log warning
                log(f"Warning: Query failed: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Clean up osquery instance."""
        if self.instance:
            try:
                self.instance.close()
            except Exception:
                pass
            self.instance = None
            self.client = None

    def __del__(self):
        self.close()


# =============================================================================
# Factory
# =============================================================================

def get_osquery_interface(prefer_thrift: bool = True,
                          socket_path: Optional[str] = None) -> OSQueryInterface:
    """
    Factory function to get osquery interface.

    Args:
        prefer_thrift: If True, prefer Thrift API (osquery library 3.1.1).
                      Falls back to shell only if library unavailable.
        socket_path: Optional socket path for connecting to osqueryd.

    Returns:
        OSQueryInterface implementation

    Raises:
        RuntimeError if no interface is available
    """
    errors = []

    if prefer_thrift:
        try:
            thrift = OSQueryThriftInterface(socket_path=socket_path)
            if thrift.is_available():
                log(f"  Using osquery Thrift API v{thrift.version}")
                return thrift
        except RuntimeError as e:
            errors.append(f"Thrift API: {e}")

    # Fall back to shell interface
    try:
        shell = OSQueryShellInterface()
        if shell.is_available():
            log(f"  Using osqueryi shell (fallback): {shell.version}")
            return shell
    except Exception as e:
        errors.append(f"Shell interface: {e}")

    raise RuntimeError(
        "No osquery interface available.\n"
        f"Errors: {'; '.join(errors)}\n\n"
        "To install osquery library: pip install osquery==3.1.1\n"
        "To install osqueryi: https://osquery.io/downloads/"
    )