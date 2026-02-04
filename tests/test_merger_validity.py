import pytest
import re
import sys
import os

# Ensure the parent directory is in the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from phase2.merger import MergerAgent
from phase2.models import PartialPDDLDomain, PDDLAction, PDDLPredicate, PDDLType
from phase2.repair import PDDLValidator


@pytest.fixture
def merger():
    """Returns a MergerAgent instance without an LLM."""
    return MergerAgent(llm=None)


@pytest.fixture
def sample_partial_domains():
    """Creates two partial domains with safe, valid PDDL names."""

    # Domain 1: File management
    d1 = PartialPDDLDomain(
        worker_name="file_worker",
        group_name="file_management",
        types=[PDDLType("file", "object"), PDDLType("directory", "object")],
        predicates=[
            # Changed 'file_present' to 'file_secure' to avoid canonicalization to 'exists'
            PDDLPredicate("file_secure", [("f", "file")]),
            PDDLPredicate("is_writable", [("f", "file")]),
        ],
        actions=[
            PDDLAction(
                name="touch_file",
                parameters=[("f", "file")],
                preconditions=["(not (file_secure ?f))"],
                effects=["(file_secure ?f)"],
                command_template="touch {f}",
            )
        ],
    )

    # Domain 2: User management
    d2 = PartialPDDLDomain(
        worker_name="user_worker",
        group_name="user_management",
        types=[
            PDDLType("user", "object"),
            PDDLType("file", "object"),
        ],
        predicates=[
            PDDLPredicate("owns", [("u", "user"), ("f", "file")]),
            # Duplicate predicate name
            PDDLPredicate("file_secure", [("f", "file")]),
        ],
        actions=[
            PDDLAction(
                name="chown_file",
                parameters=[("u", "user"), ("f", "file")],
                # Using 'user_active' to avoid 'exists' keyword issues
                preconditions=["(file_secure ?f)", "(user_active ?u)"],
                effects=["(owns ?u ?f)"],
                command_template="chown {u} {f}",
            ),
            # Duplicate action
            PDDLAction(
                name="touch_file",
                parameters=[("f", "file")],
                preconditions=[],
                effects=["(file_secure ?f)"],
                command_template="touch {f}",
            ),
        ],
    )

    return [d1, d2]


# =============================================================================
# Tests
# =============================================================================


def test_basic_structure(merger, sample_partial_domains):
    """Validate that the output has the correct PDDL skeleton and actions."""
    pddl_output = merger.merge(sample_partial_domains)

    assert "(define (domain sysadmin)" in pddl_output
    assert "(:requirements :strips :typing :negative-preconditions)" in pddl_output
    assert "(:types" in pddl_output
    assert "(:predicates" in pddl_output
    assert "(:action" in pddl_output


def test_type_unification(merger, sample_partial_domains):
    """Ensure hierarchy is respected (including Core Hierarchy overrides)."""
    pddl_output = merger.merge(sample_partial_domains)
    # Normalize whitespace to single spaces
    clean_pddl = re.sub(r"\s+", " ", pddl_output)

    assert (
        "file - filesystem_object" in clean_pddl
        or "file directory - filesystem_object" in clean_pddl
    )
    assert "filesystem_object - object" in clean_pddl


def test_predicate_unification(merger, sample_partial_domains):
    """Ensure duplicate predicates are merged."""
    pddl_output = merger.merge(sample_partial_domains)

    # Extract everything from (:predicates DOWN TO (:action
    # This avoids the "stop at first closing paren" bug
    match = re.search(r"\(:predicates(.*?)(?=\(:action)", pddl_output, re.DOTALL)
    assert match, "Could not find predicate section (or action section missing)"

    predicate_section = match.group(1)
    normalized_section = re.sub(r"\s+", " ", predicate_section).strip()

    # Check for our safe predicate 'file_secure'
    # It should appear exactly once as "(file_secure ?f - file)"
    count = normalized_section.count("(file_secure ?f - file)")

    assert count == 1, (
        f"Expected 1 occurrence of '(file_secure ?f - file)', found {count}.\n"
        f"Normalized Section: {normalized_section}"
    )

    # Check 'owns' exists
    assert "(owns ?u - user ?f - file)" in normalized_section


def test_action_consolidation(merger, sample_partial_domains):
    """Test that actions with the same name are merged."""
    pddl_output = merger.merge(sample_partial_domains)

    matches = re.findall(r"\(:action touch_file", pddl_output)
    assert len(matches) == 1, "Action 'touch_file' was not consolidated"


def test_action_validity(merger, sample_partial_domains):
    """Check action parameter formatting."""
    pddl_output = merger.merge(sample_partial_domains)

    # Check Header
    assert ":parameters (?u - user ?f - file)" in pddl_output

    # Extract the full action block correctly
    # We look for '(:action chown_file' and capture until the next '(:action' or end of file
    chown_match = re.search(
        r"\(:action chown_file(.*?)(?=\(:action|\)\s*$)", pddl_output, re.DOTALL
    )

    assert chown_match, "Could not find chown_file action block"
    chown_block = chown_match.group(1)

    # Check for the predicates in the body
    assert "(owns ?u ?f)" in chown_block
    assert "(file_secure ?f)" in chown_block


def test_internal_validation(merger, sample_partial_domains):
    """Use the project's own validator on the output."""
    pddl_output = merger.merge(sample_partial_domains)
    validator = PDDLValidator()
    is_valid, errors = validator.validate_domain(pddl_output)
    assert is_valid, f"Generated PDDL failed internal validation: {errors}"


def test_implicit_predicate_extraction(merger):
    """Test that predicates used in actions but not declared are auto-generated."""
    domain = PartialPDDLDomain(
        worker_name="lazy_worker",
        group_name="test",
        types=[PDDLType("file", "object")],
        predicates=[],
        actions=[
            PDDLAction(
                name="check_file",
                parameters=[("f", "file")],
                preconditions=["(is_safe ?f)"],
                effects=["(checked ?f)"],
            )
        ],
    )

    pddl_output = merger.merge([domain])

    # Check for implicit predicates
    assert (
        "(is_safe ?f - file)" in pddl_output
        or "(is_safe ?f - object)" in pddl_output
        or "(is_safe ?var0 - object)" in pddl_output
    )
