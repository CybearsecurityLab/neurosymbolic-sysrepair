"""Shared PDDL validation via the ``pddl`` library.

Every PDDL artifact produced by the pipeline (Phase 2's domain, Phase 3's
refined domain, the LLM-generated per-scenario problem) is run through this
parser so structural defects surface at the point they were created instead
of as cryptic "planner failed" symptoms downstream.

This is the canonical PDDL engineering practice: parse and validate before
handing to a planner. Defensible for ACSAC.
"""

from __future__ import annotations

import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger("PDDLValidation")


@dataclass
class PDDLValidationResult:
    """Outcome of a parse attempt."""

    ok: bool
    error: Optional[str] = None
    detail: Optional[str] = None
    # When ok=True we expose what we learned about the artifact so callers
    # can decide policy (e.g. don't ship an empty domain).
    name: Optional[str] = None
    types: tuple[str, ...] = ()
    predicates: tuple[str, ...] = ()
    actions: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.ok


def _safe_import_pddl():
    """Lazy + tolerant import so callers don't crash if the library is gone."""
    try:
        from pddl import parse_domain, parse_problem  # type: ignore
        return parse_domain, parse_problem
    except Exception as e:  # pragma: no cover - import-time best effort
        logger.warning(f"pddl library import failed: {e}")
        return None, None


def _text_or_path(arg: str | Path) -> tuple[Path, bool]:
    """Return (path, is_tempfile). If arg is already a path on disk we use it
    directly; otherwise we materialise it as a tempfile so the pddl library
    can read it (its parse_domain/problem APIs both take a file path)."""
    p = Path(arg) if isinstance(arg, (str, Path)) and not isinstance(arg, str) else None
    if isinstance(arg, Path) and arg.exists():
        return arg, False
    if isinstance(arg, str) and Path(arg).exists():
        return Path(arg), False
    # Treat arg as raw PDDL text
    text = arg.read_text() if isinstance(arg, Path) else str(arg)
    tmp = Path(tempfile.NamedTemporaryFile(
        prefix="pddl-validate-", suffix=".pddl", delete=False
    ).name)
    tmp.write_text(text)
    return tmp, True


def validate_domain(arg: str | Path) -> PDDLValidationResult:
    """Parse a PDDL domain (text or path). Reports detected types,
    predicates, and action names on success.
    """
    parse_domain, _ = _safe_import_pddl()
    if parse_domain is None:
        return PDDLValidationResult(
            ok=False,
            error="pddl library not installed",
            detail="pip/uv add pddl>=0.3.1",
        )

    path, tmp = _text_or_path(arg)
    try:
        d = parse_domain(str(path))
        types = tuple(sorted(str(t) for t in getattr(d, "types", []) or ()))
        preds = tuple(sorted(str(p.name) for p in getattr(d, "predicates", []) or ()))
        actions = tuple(sorted(str(a.name) for a in getattr(d, "actions", []) or ()))
        return PDDLValidationResult(
            ok=True,
            name=str(getattr(d, "name", "")),
            types=types,
            predicates=preds,
            actions=actions,
        )
    except Exception as e:
        msg = str(e)
        return PDDLValidationResult(
            ok=False,
            error="domain parse error",
            detail=msg[:600],
        )
    finally:
        if tmp:
            try: path.unlink()
            except OSError: pass


def validate_problem(
    domain: str | Path,
    problem: str | Path,
) -> PDDLValidationResult:
    """Parse a PDDL problem against a domain. Catches both pure-syntax
    errors and type/predicate signatures that don't match the domain.
    """
    parse_domain, parse_problem = _safe_import_pddl()
    if parse_problem is None:
        return PDDLValidationResult(
            ok=False,
            error="pddl library not installed",
            detail="pip/uv add pddl>=0.3.1",
        )

    dpath, dtmp = _text_or_path(domain)
    ppath, ptmp = _text_or_path(problem)
    try:
        # parse_domain first so we get a sharp error if the *domain* itself
        # is the broken party (very common during refinement).
        parse_domain(str(dpath))
        prob = parse_problem(str(ppath))
        return PDDLValidationResult(
            ok=True,
            name=str(getattr(prob, "name", "")),
        )
    except Exception as e:
        msg = str(e)
        return PDDLValidationResult(
            ok=False,
            error="problem parse error",
            detail=msg[:600],
        )
    finally:
        if dtmp:
            try: dpath.unlink()
            except OSError: pass
        if ptmp:
            try: ppath.unlink()
            except OSError: pass


def assert_valid_domain(arg: str | Path, *, source: str = "") -> PDDLValidationResult:
    """Validate-and-log helper. Returns the result; logs warning on failure."""
    res = validate_domain(arg)
    tag = f" [{source}]" if source else ""
    if res.ok:
        logger.info(
            f"pddl-validate{tag} domain={res.name!r} types={len(res.types)} "
            f"preds={len(res.predicates)} actions={len(res.actions)}"
        )
    else:
        logger.warning(f"pddl-validate{tag} INVALID: {res.error}: {res.detail}")
    return res


def assert_valid_problem(
    domain: str | Path,
    problem: str | Path,
    *,
    source: str = "",
) -> PDDLValidationResult:
    """Validate-and-log a (domain, problem) pair."""
    res = validate_problem(domain, problem)
    tag = f" [{source}]" if source else ""
    if res.ok:
        logger.info(f"pddl-validate{tag} problem={res.name!r}")
    else:
        logger.warning(f"pddl-validate{tag} INVALID: {res.error}: {res.detail}")
    return res
