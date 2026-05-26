"""
Scenario discovery for the sysrepair benchmark.

Re-exports the existing scenario loader so phase1/phase2/phase3 and
the main pipeline don't have to depend on the `eval` package.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from eval.scenario_loader import (
    Scenario,
    load_scenario,
    load_all_scenarios as _load_nested,
    load_scenarios as _load_nested_filtered,
)


def _has_flat_layout(bench: Path) -> bool:
    """True if scenarios live directly under bench (no ccdc/meta2 wrapper)."""
    return any(p.is_dir() and p.name.startswith("scenario-") for p in bench.iterdir())


def _parse_from_directive(dockerfile: Path) -> str | None:
    """Return the FROM image of a Dockerfile, ignoring multi-stage aliases."""
    try:
        for raw in dockerfile.read_text().splitlines():
            line = raw.strip()
            if line.lower().startswith("from "):
                parts = line.split()
                if len(parts) >= 2:
                    return parts[1]
    except OSError:
        return None
    return None


def _fix_base_image(scenario: Scenario) -> Scenario:
    """Replace the loader's collection-based guess with the Dockerfile's real FROM."""
    real = _parse_from_directive(scenario.dockerfile_path)
    if real and real != scenario.base_image:
        scenario.base_image = real
    return scenario


def load_all_scenarios(bench_root: Path | str) -> list[Scenario]:
    """Load scenarios from a flat (scenario-*/) or nested (<collection>/scenario-*/) layout.

    Collection names are case-insensitively matched against the directory name
    (so ``CCDC/`` is normalized to ``ccdc``), and any sub-directory containing
    ``scenario-*`` entries counts as a collection — not just ``ccdc``/``meta2``.
    """
    bench = Path(bench_root)
    if not bench.exists():
        return []

    out: list[Scenario] = []

    if _has_flat_layout(bench):
        collection = (bench.name or "scenario").lower()
        for d in sorted(bench.iterdir()):
            if d.is_dir() and d.name.startswith("scenario-"):
                s = load_scenario(d, collection)
                if s:
                    out.append(_fix_base_image(s))
        return out

    for coll_dir in sorted(bench.iterdir()):
        if not coll_dir.is_dir():
            continue
        scenario_dirs = [d for d in coll_dir.iterdir() if d.is_dir() and d.name.startswith("scenario-")]
        if not scenario_dirs:
            continue
        collection = coll_dir.name.lower()
        for d in sorted(scenario_dirs):
            s = load_scenario(d, collection)
            if s:
                out.append(_fix_base_image(s))
    return out


def load_scenarios(
    bench_root: Path | str,
    collection: str | None = None,
    ids: Iterable[str] | None = None,
    categories: Iterable[str] | None = None,
) -> list[Scenario]:
    """Filter the scenarios under ``bench_root`` (handles both layouts)."""
    scenarios = load_all_scenarios(bench_root)
    if collection:
        scenarios = [s for s in scenarios if s.collection == collection]
    if ids:
        id_set = set(ids)
        # Be lenient about a couple of common id forms: the layout-derived id
        # (e.g. ``benchmark-01``) and a bare directory-style id (``scenario-01``).
        scenarios = [
            s for s in scenarios
            if s.id in id_set
            or s.dockerfile_path.parent.name in id_set
            or s.id.rsplit("-", 1)[-1] in {i.rsplit("-", 1)[-1] for i in id_set}
        ]
    if categories:
        cats = set(categories)
        scenarios = [s for s in scenarios if s.category in cats]
    return scenarios


def select_scenarios(
    bench_path: Path | str,
    collection: str | None = None,
    ids: Iterable[str] | None = None,
    scenarios_file: Path | str | None = None,
) -> list[Scenario]:
    """Select scenarios by collection / explicit IDs / file. Handles flat + nested layouts."""
    bench = Path(bench_path)
    file_ids: list[str] = []
    if scenarios_file:
        for line in Path(scenarios_file).read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                file_ids.append(line)

    id_list = list(ids) if ids else []
    id_list.extend(file_ids)
    id_list = id_list or None

    return load_scenarios(bench, collection=collection, ids=id_list)


__all__ = [
    "Scenario",
    "load_scenario",
    "load_all_scenarios",
    "load_scenarios",
    "select_scenarios",
]
