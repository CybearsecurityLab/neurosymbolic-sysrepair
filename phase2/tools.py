"""
phase2/tools.py

Tools for documentation extraction and system introspection.
Provides man page parsing and help output fetching.
"""

import logging
import subprocess
import re
from functools import lru_cache
from typing import Optional

logger = logging.getLogger("Phase2.Tools")


class DocumentationExtractor:
    """
    Extracts documentation from system utilities.
    Fetches man pages and --help output.
    """

    # Cache size for man pages
    CACHE_SIZE = 100

    def __init__(self):
        self._man_cache: dict[str, str] = {}
        self._help_cache: dict[str, str] = {}

    @lru_cache(maxsize=CACHE_SIZE)
    def fetch_man_page(self, utility: str, section: int = 1) -> str:
        """
        Fetch and parse a man page for a utility.

        Args:
            utility: Name of the utility (e.g., 'apt', 'systemctl')
            section: Man page section (default: 1 for user commands)

        Returns:
            Man page content as text, or empty string if not found
        """
        try:
            # Use man with -P cat to avoid pager
            result = subprocess.run(
                ["man", "-P", "cat", str(section), utility],
                capture_output=True,
                text=True,
                timeout=10,
                env={"MANWIDTH": "120", "LANG": "C"},
            )

            if result.returncode == 0:
                content = result.stdout
                # Clean up formatting
                content = self._clean_man_output(content)
                logger.debug(f"Fetched man page for {utility} ({len(content)} chars)")
                return content
            else:
                logger.debug(f"Man page not found for {utility}")
                return ""

        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout fetching man page for {utility}")
            return ""
        except Exception as e:
            logger.warning(f"Error fetching man page for {utility}: {e}")
            return ""

    @lru_cache(maxsize=CACHE_SIZE)
    def fetch_help_output(self, utility: str) -> str:
        """
        Fetch --help output for a utility.

        Args:
            utility: Name of the utility

        Returns:
            Help output as text, or empty string if not available
        """
        try:
            # Try --help first
            result = subprocess.run(
                [utility, "--help"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0 and result.stdout:
                logger.debug(f"Fetched --help for {utility}")
                return result.stdout
            elif result.stderr:
                # Some utilities output help to stderr
                return result.stderr

            # Try -h as fallback
            result = subprocess.run(
                [utility, "-h"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0 and result.stdout:
                return result.stdout
            elif result.stderr:
                return result.stderr

            return ""

        except FileNotFoundError:
            logger.debug(f"Utility {utility} not found")
            return ""
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout fetching help for {utility}")
            return ""
        except Exception as e:
            logger.warning(f"Error fetching help for {utility}: {e}")
            return ""

    def _clean_man_output(self, text: str) -> str:
        """Clean up man page output by removing control characters."""
        # Remove backspace sequences (bold/underline formatting)
        text = re.sub(r".\x08", "", text)
        # Remove other control characters
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
        # Normalize whitespace
        text = re.sub(r" +", " ", text)
        return text.strip()

    def get_utility_docs(self, utilities: list[str]) -> dict[str, str]:
        """
        Get documentation for multiple utilities.

        Args:
            utilities: List of utility names

        Returns:
            Dict mapping utility name to combined documentation
        """
        docs = {}

        for utility in utilities:
            man_content = self.fetch_man_page(utility)
            help_content = self.fetch_help_output(utility)

            combined = ""
            if man_content:
                combined += f"=== MAN PAGE ===\n{man_content}\n\n"
            if help_content:
                combined += f"=== HELP OUTPUT ===\n{help_content}\n"

            if combined:
                docs[utility] = combined
            else:
                logger.warning(f"No documentation found for {utility}")
                docs[utility] = f"# {utility}\nNo documentation available."

        return docs

    def extract_subcommands(self, utility: str) -> list[str]:
        """
        Extract subcommands from a utility's documentation.

        Args:
            utility: Name of the utility

        Returns:
            List of subcommand names
        """
        subcommands = []

        help_text = self.fetch_help_output(utility)
        if not help_text:
            return subcommands

        # Common patterns for subcommand listings
        patterns = [
            r"^\s*(\w+)\s+[-–]\s+",  # "subcommand - description"
            r"^\s{2,4}(\w+)\s{2,}",  # "  subcommand  description"
            r"^Commands:\s*\n((?:\s+\w+.*\n)+)",  # Commands: section
        ]

        for pattern in patterns[:2]:
            matches = re.findall(pattern, help_text, re.MULTILINE)
            for match in matches:
                if match and match not in ["the", "a", "an", "or", "and"]:
                    subcommands.append(match)

        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for cmd in subcommands:
            if cmd not in seen:
                seen.add(cmd)
                unique.append(cmd)

        return unique

    def extract_options(self, utility: str) -> list[dict]:
        """
        Extract command-line options from documentation.

        Args:
            utility: Name of the utility

        Returns:
            List of option dicts with 'short', 'long', 'description'
        """
        options = []

        help_text = self.fetch_help_output(utility)
        man_text = self.fetch_man_page(utility)

        combined = f"{help_text}\n{man_text}"

        # Pattern for options like "-v, --verbose    Description"
        pattern = r"^\s*(-\w)?(?:,\s*)?(--[\w-]+)?\s+(.+)$"

        for match in re.finditer(pattern, combined, re.MULTILINE):
            short_opt = match.group(1)
            long_opt = match.group(2)
            description = match.group(3).strip()

            if short_opt or long_opt:
                options.append(
                    {
                        "short": short_opt,
                        "long": long_opt,
                        "description": description[:100],  # Truncate
                    }
                )

        return options


class SystemIntrospector:
    """
    Introspects the local system for package and service information.
    Complements osquery data when available.
    """

    @staticmethod
    def get_installed_packages() -> list[str]:
        """Get list of installed package names."""
        try:
            result = subprocess.run(
                ["dpkg-query", "-f", "${Package}\n", "-W"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                return result.stdout.strip().split("\n")
        except Exception as e:
            logger.warning(f"Failed to get installed packages: {e}")
        return []

    @staticmethod
    def get_running_services() -> list[str]:
        """Get list of running service names."""
        try:
            result = subprocess.run(
                [
                    "systemctl",
                    "list-units",
                    "--type=service",
                    "--state=running",
                    "--no-legend",
                    "--plain",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                services = []
                for line in result.stdout.strip().split("\n"):
                    if line:
                        parts = line.split()
                        if parts:
                            services.append(parts[0])
                return services
        except Exception as e:
            logger.warning(f"Failed to get running services: {e}")
        return []

    @staticmethod
    def get_system_users() -> list[str]:
        """Get list of system user names."""
        try:
            with open("/etc/passwd", "r") as f:
                users = []
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 1:
                        users.append(parts[0])
                return users
        except Exception as e:
            logger.warning(f"Failed to get system users: {e}")
        return []

    @staticmethod
    def check_ubuntu_version() -> tuple[str, str]:
        """
        Check Ubuntu version and detect sudo-rs/uutils.

        Returns:
            Tuple of (version_id, variant_info)
        """
        version_id = ""
        variant_info = ""

        try:
            with open("/etc/os-release", "r") as f:
                for line in f:
                    if line.startswith("VERSION_ID="):
                        version_id = line.split("=")[1].strip().strip('"')
                        break
        except Exception:
            pass

        # Check for sudo-rs (Ubuntu 25.10+)
        try:
            result = subprocess.run(
                ["sudo", "--version"], capture_output=True, text=True, timeout=5
            )
            if "sudo-rs" in result.stdout.lower():
                variant_info = "sudo-rs"
            else:
                variant_info = "sudo"
        except Exception:
            pass

        # Check for uutils coreutils
        try:
            result = subprocess.run(
                ["ls", "--version"], capture_output=True, text=True, timeout=5
            )
            if "uutils" in result.stdout.lower():
                variant_info += "+uutils" if variant_info else "uutils"
        except Exception:
            pass

        return version_id, variant_info

    @staticmethod
    def get_os_capabilities() -> dict:
        """
        Returns a capability dict for prompt injection.
        Detects if strict Rust variants are active.
        """
        version_id, variant_info = SystemIntrospector.check_ubuntu_version()

        return {
            "is_sudo_rs": "sudo-rs" in variant_info,
            "is_uutils": "uutils" in variant_info,
            "os_version": version_id,
            "raw_variant": variant_info
        }
