import hashlib
import subprocess
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

logger = logging.getLogger("Phase2.Tools")

class DocumentationExtractor:
    """Extracts and caches system documentation for LLM processing."""

    def __init__(self, cache_dir: str = "/tmp/pddl_doc_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache: dict[str, str] = {}

    def _cache_key(self, utility: str) -> str:
        return hashlib.md5(utility.encode()).hexdigest()

    def fetch_man_page(self, utility: str) -> Optional[str]:
        """Fetch cleaned man page content."""
        cache_key = self._cache_key(f"man_{utility}")

        if cache_key in self._cache:
            return self._cache[cache_key]

        cache_file = self.cache_dir / f"{cache_key}.txt"
        if cache_file.exists():
            content = cache_file.read_text()
            self._cache[cache_key] = content
            return content

        try:
            # FIX: Added text=True (returns str) and stdin=DEVNULL (fixes Bad File Descriptor)
            proc = subprocess.Popen(
                f"man {utility} 2>/dev/null | col -b",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.DEVNULL,  # <--- CRITICAL FIX
                text=True                  # <--- Returns str, no decode needed
            )
            stdout, _ = proc.communicate(timeout=30)

            if proc.returncode == 0 and stdout:
                # FIX: Removed .decode() because text=True handles it
                content = self._clean_man_page(stdout)
                self._cache[cache_key] = content
                cache_file.write_text(content)
                return content
        except Exception as e:
            logger.warning(f"Failed to fetch man page for {utility}: {e}")

        return None

    def fetch_help_output(self, utility: str) -> Optional[str]:
        """Fetch --help output."""
        cache_key = self._cache_key(f"help_{utility}")

        if cache_key in self._cache:
            return self._cache[cache_key]

        try:
            # FIX: Added stdin=DEVNULL
            result = subprocess.run(
                [utility, "--help"],
                capture_output=True,
                text=True,
                timeout=10,
                stdin=subprocess.DEVNULL # <--- CRITICAL FIX
            )
            content = result.stdout or result.stderr
            if content:
                self._cache[cache_key] = content
                return content
        except Exception:
            pass

        return None

    def _clean_man_page(self, content: str) -> str:
        """Clean and truncate man page for LLM context."""
        lines = content.split("\n")
        cleaned = []
        prev_empty = False
        for line in lines:
            line = line.rstrip()
            is_empty = not line.strip()
            if is_empty and prev_empty:
                continue
            cleaned.append(line)
            prev_empty = is_empty

        if len(cleaned) > 500:
            cleaned = cleaned[:500] + ["... [truncated]"]

        return "\n".join(cleaned)

    def get_utility_docs(self, utilities: list[str]) -> dict[str, str]:
        results = {}
        with ThreadPoolExecutor(max_workers=min(len(utilities), 20)) as executor:
            future_to_util = {
                executor.submit(self._get_single_doc, u): u for u in utilities
            }
            for future in as_completed(future_to_util):
                utility = future_to_util[future]
                try:
                    results[utility] = future.result()
                except Exception as e:
                    logger.warning(f"Doc extraction failed for {utility}: {e}")
                    results[utility] = ""
        return results

    def _get_single_doc(self, utility: str) -> str:
        man_page = self.fetch_man_page(utility) or ""
        help_text = self.fetch_help_output(utility) or ""
        return f"=== MAN PAGE: {utility} ===\n{man_page}\n\n=== HELP OUTPUT: {utility} ===\n{help_text}\n"