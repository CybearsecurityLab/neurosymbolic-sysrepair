"""
phase2/tools.py

Tools for documentation extraction and system introspection.
Provides man page parsing, help output fetching, and smart chunking.
"""

import logging
import subprocess
import re
from functools import lru_cache
from typing import Optional, Iterator

logger = logging.getLogger("Phase2.Tools")


class DocumentationExtractor:
    """
    Extracts documentation from system utilities.
    Fetches man pages and --help output.
    """

    # Cache size for man pages
    CACHE_SIZE = 100

    def __init__(self, shell=None):
        self._man_cache: dict[str, str] = {}
        self._help_cache: dict[str, str] = {}
        if shell is None:
            from common.shell import HostShellRunner
            shell = HostShellRunner()
        self.shell = shell

    def _fetch_man_section(self, utility: str, section: int) -> str:
        """
        Fetch a specific man page section via the configured shell runner.
        """
        # MANWIDTH/LANG are exported inline so they apply equally to host shell and docker exec.
        cmd = f"MANWIDTH=120 LANG=C man -P cat {section} {utility}"
        res = self.shell.run(cmd, timeout=10)
        if res.ok and res.stdout:
            content = self._clean_man_output(res.stdout)
            logger.debug(
                f"Fetched man page for {utility} section {section} ({len(content)} chars)"
            )
            return content
        return ""

    def fetch_man_page(self, utility: str, sections: Optional[list[int]] = None) -> str:
        """
        Fetch and parse a man page for a utility.
        Tries multiple sections if specific one not found.
        """
        if sections is None:
            sections = [1, 8, 5]

        for section in sections:
            content = self._fetch_man_section(utility, section)
            if content:
                return content

        logger.debug(f"Man page not found for {utility} in sections {sections}")
        return ""

    def fetch_help_output(self, utility: str) -> str:
        """
        Fetch --help output for a utility (via configured shell runner).
        """
        if utility in self._help_cache:
            return self._help_cache[utility]

        for flag in ("--help", "-h"):
            res = self.shell.run(f"{utility} {flag}", timeout=5)
            if res.ok and res.stdout:
                self._help_cache[utility] = res.stdout
                return res.stdout
            if res.stderr and not res.ok:
                # Many utilities print usage on stderr with nonzero exit
                self._help_cache[utility] = res.stderr
                return res.stderr

        self._help_cache[utility] = ""
        return ""

    def _clean_man_output(self, text: str) -> str:
        """Clean up man page output by removing control characters."""
        text = re.sub(r".\x08", "", text)
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
        text = re.sub(r" +", " ", text)
        return text.strip()

    def get_utility_docs(self, utilities: list[str]) -> dict[str, str]:
        """Get combined documentation for multiple utilities (Legacy/Simple)."""
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
                docs[utility] = f"# {utility}\nNo documentation available."

        return docs

    def get_chunked_docs(
        self, utility: str, max_chunk_size: int = 8000
    ) -> Iterator[str]:
        """
        Get documentation split into chunks, preserving the header (NAME/SYNOPSIS)
        in EVERY chunk so the LLM maintains context.

        Args:
            utility: The command name
            max_chunk_size: Approximate characters per chunk

        Yields:
            Strings containing [Persistent Header] + [Unique Body Chunk]
        """
        full_text = self.fetch_man_page(utility)
        if not full_text:
            # Fallback to help if no man page
            full_text = self.fetch_help_output(utility)

        if not full_text:
            yield f"# {utility}\nNo documentation available."
            return

        lines = full_text.splitlines()

        # 1. Extract Persistent Header (NAME and SYNOPSIS)
        # We look for the start of "DESCRIPTION" or "OPTIONS" to end the header
        header_lines = []
        body_start_index = 0

        # Simple heuristic: Take first 20 lines OR up to DESCRIPTION
        for i, line in enumerate(lines):
            header_lines.append(line)
            # Stop if we hit Description or if header gets too long (safety valve)
            if (
                re.match(r"^\s*(DESCRIPTION|OPTIONS|OVERVIEW)", line, re.IGNORECASE)
                or i > 50
            ):
                body_start_index = i
                break

        header_text = "\n".join(header_lines) + "\n\n... [Header Preserved] ...\n\n"
        header_len = len(header_text)

        # 2. Chunk the rest
        current_chunk = []
        current_len = 0
        effective_limit = max_chunk_size - header_len

        for line in lines[body_start_index:]:
            line_len = len(line) + 1  # +1 for newline

            if current_len + line_len > effective_limit:
                # Yield current chunk with header
                yield header_text + "\n".join(current_chunk)
                current_chunk = []
                current_len = 0

            current_chunk.append(line)
            current_len += line_len

        # Yield final chunk
        if current_chunk:
            yield header_text + "\n".join(current_chunk)

    # ... (Keep extract_subcommands and extract_options as they were) ...
    def extract_subcommands(self, utility: str) -> list[str]:
        """Extract subcommands from a utility's documentation."""
        subcommands = []
        help_text = self.fetch_help_output(utility)
        if not help_text:
            return subcommands

        patterns = [
            r"^\s*(\w+)\s+[-–]\s+",
            r"^\s{2,4}(\w+)\s{2,}",
            r"^Commands:\s*\n((?:\s+\w+.*\n)+)",
        ]

        for pattern in patterns[:2]:
            matches = re.findall(pattern, help_text, re.MULTILINE)
            for match in matches:
                if match and match not in ["the", "a", "an", "or", "and"]:
                    subcommands.append(match)

        seen = set()
        unique = []
        for cmd in subcommands:
            if cmd not in seen:
                seen.add(cmd)
                unique.append(cmd)

        return unique

    def extract_options(self, utility: str) -> list[dict]:
        """Extract command-line options from documentation."""
        options = []
        help_text = self.fetch_help_output(utility)
        man_text = self.fetch_man_page(utility)
        combined = f"{help_text}\n{man_text}"

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
                        "description": description[:300],
                    }
                )

        return options


class SystemIntrospector:
    # ... (Keep SystemIntrospector exactly as it was in your uploaded file) ...
    @staticmethod
    def get_installed_packages() -> list[str]:
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
        version_id, variant_info = SystemIntrospector.check_ubuntu_version()
        return {
            "is_sudo_rs": "sudo-rs" in variant_info,
            "is_uutils": "uutils" in variant_info,
            "os_version": version_id,
            "raw_variant": variant_info,
        }
