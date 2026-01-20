"""
common/predicates.py

Canonical predicate definitions shared between Phase 1 and Phase 2.
Based on Section 3.2 of the research document: Predicates as State Abstractions.

This module provides:
- Base predicate definitions (static and dynamic)
- Predicate generation from osquery mappings
- Predicate vocabulary for LLM prompting
"""

from typing import Optional
from dataclasses import dataclass


@dataclass
class PredicateDefinition:
    """Definition of a PDDL predicate."""
    name: str
    parameters: list[tuple[str, str]]  # [(var_name, type_name), ...]
    description: str = ""
    is_static: bool = False  # True if this predicate doesn't change during planning
    category: str = "general"


# =============================================================================
# Static Predicates (invariant properties)
# =============================================================================

STATIC_PREDICATES: list[PredicateDefinition] = [
    # Dependencies
    PredicateDefinition(
        name="depends_on",
        parameters=[("s", "service"), ("p", "package")],
        description="Service s depends on package p",
        is_static=True,
        category="relationship"
    ),
    PredicateDefinition(
        name="configures",
        parameters=[("f", "configuration_file"), ("s", "service")],
        description="Configuration file f configures service s",
        is_static=True,
        category="relationship"
    ),
    PredicateDefinition(
        name="file_owned_by",
        parameters=[("f", "filesystem_object"), ("u", "user")],
        description="File f is owned by user u",
        is_static=True,
        category="relationship"
    ),
    PredicateDefinition(
        name="member_of",
        parameters=[("u", "user"), ("g", "group")],
        description="User u is a member of group g",
        is_static=True,
        category="relationship"
    ),
]


# =============================================================================
# Dynamic Predicates (mutable state)
# =============================================================================

DYNAMIC_PREDICATES: list[PredicateDefinition] = [
    # Package predicates
    PredicateDefinition(
        name="package_installed",
        parameters=[("p", "package")],
        description="Package p is installed on the system",
        category="package"
    ),
    PredicateDefinition(
        name="package_outdated",
        parameters=[("p", "package")],
        description="Package p has an available update",
        category="package"
    ),
    PredicateDefinition(
        name="package_configured",
        parameters=[("p", "package")],
        description="Package p is properly configured",
        category="package"
    ),
    PredicateDefinition(
        name="vulnerable",
        parameters=[("p", "package")],
        description="Package p has known vulnerabilities",
        category="package"
    ),
    PredicateDefinition(
        name="package_enabled",
        parameters=[("p", "package")],
        description="Package p (snap) is enabled",
        category="package"
    ),
    PredicateDefinition(
        name="package_reverted",
        parameters=[("p", "package")],
        description="Package p (snap) has been reverted",
        category="package"
    ),
    
    # Service predicates
    PredicateDefinition(
        name="service_exists",
        parameters=[("s", "service")],
        description="Service s is registered in systemd",
        category="service"
    ),
    PredicateDefinition(
        name="service_running",
        parameters=[("s", "service")],
        description="Service s is currently active/running",
        category="service"
    ),
    PredicateDefinition(
        name="service_enabled",
        parameters=[("s", "service")],
        description="Service s is enabled to start at boot",
        category="service"
    ),
    PredicateDefinition(
        name="service_failed",
        parameters=[("s", "service")],
        description="Service s is in failed state",
        category="service"
    ),
    PredicateDefinition(
        name="config_applied",
        parameters=[("s", "service")],
        description="Service s has had its configuration applied (via restart/reload)",
        category="service"
    ),
    
    # Filesystem predicates
    PredicateDefinition(
        name="file_exists",
        parameters=[("f", "filesystem_object")],
        description="File or directory f exists on the filesystem",
        category="filesystem"
    ),
    PredicateDefinition(
        name="file_readable",
        parameters=[("f", "filesystem_object")],
        description="File f is readable",
        category="filesystem"
    ),
    PredicateDefinition(
        name="file_writable",
        parameters=[("f", "filesystem_object")],
        description="File f is writable",
        category="filesystem"
    ),
    PredicateDefinition(
        name="file_executable",
        parameters=[("f", "filesystem_object")],
        description="File f is executable",
        category="filesystem"
    ),
    PredicateDefinition(
        name="file_critical",
        parameters=[("f", "filesystem_object")],
        description="File f is a critical system file (should not be deleted)",
        category="filesystem"
    ),
    
    # User predicates
    PredicateDefinition(
        name="user_exists",
        parameters=[("u", "user")],
        description="User u exists on the system",
        category="user"
    ),
    PredicateDefinition(
        name="user_critical",
        parameters=[("u", "user")],
        description="User u is a system-critical user",
        category="user"
    ),
    PredicateDefinition(
        name="user_locked",
        parameters=[("u", "user")],
        description="User u account is locked",
        category="user"
    ),
    PredicateDefinition(
        name="can_escalate",
        parameters=[("u", "user")],
        description="User u can escalate privileges (sudo)",
        category="user"
    ),
    
    # Group predicates
    PredicateDefinition(
        name="group_exists",
        parameters=[("g", "group")],
        description="Group g exists on the system",
        category="group"
    ),
    
    # Network predicates
    PredicateDefinition(
        name="port_open",
        parameters=[("p", "port")],
        description="Port p is open and listening",
        category="network"
    ),
    PredicateDefinition(
        name="port_allowed",
        parameters=[("p", "port")],
        description="Port p is allowed through firewall",
        category="network"
    ),
    PredicateDefinition(
        name="interface_exists",
        parameters=[("i", "interface")],
        description="Network interface i exists",
        category="network"
    ),
    PredicateDefinition(
        name="interface_up",
        parameters=[("i", "interface")],
        description="Network interface i is up",
        category="network"
    ),
    
    # Firewall predicates
    PredicateDefinition(
        name="firewall_rule_exists",
        parameters=[("r", "firewall_rule")],
        description="Firewall rule r exists",
        category="firewall"
    ),
    PredicateDefinition(
        name="traffic_blocked",
        parameters=[("r", "firewall_rule")],
        description="Traffic matching rule r is blocked",
        category="firewall"
    ),
    
    # Process predicates
    PredicateDefinition(
        name="process_running",
        parameters=[("pr", "process")],
        description="Process pr is currently running",
        category="process"
    ),
    PredicateDefinition(
        name="executed_as_root",
        parameters=[("pr", "process")],
        description="Process pr was executed with root privileges",
        category="process"
    ),
    
    # Environment predicates
    PredicateDefinition(
        name="network_available",
        parameters=[],
        description="Network connectivity is available",
        category="environment"
    ),
    PredicateDefinition(
        name="requires_env_preservation",
        parameters=[("pr", "process")],
        description="Process pr requires environment variable preservation (sudo-rs constraint)",
        category="environment"
    ),
]


# =============================================================================
# Utility Functions
# =============================================================================

def get_all_predicates() -> list[PredicateDefinition]:
    """Get all predicate definitions (static + dynamic)."""
    return STATIC_PREDICATES + DYNAMIC_PREDICATES


def get_predicates_by_category(category: str) -> list[PredicateDefinition]:
    """Get predicates filtered by category."""
    return [p for p in get_all_predicates() if p.category == category]


def get_base_predicates() -> list[str]:
    """
    Get list of base predicates in PDDL format for LLM prompting.
    Used to seed the LLM context so it prefers existing vocabulary.
    
    Returns:
        List of predicate strings like "(package_installed ?p - package)"
    """
    predicates = []
    
    for pred in get_all_predicates():
        if pred.parameters:
            params = " ".join(f"?{p[0]} - {p[1]}" for p in pred.parameters)
            predicates.append(f"({pred.name} {params})")
        else:
            predicates.append(f"({pred.name})")
    
    return sorted(predicates)


def get_predicate_names() -> set[str]:
    """Get set of all known predicate names."""
    return {p.name for p in get_all_predicates()}


def format_predicates_for_prompt() -> str:
    """
    Format predicates for inclusion in LLM prompts.
    Groups by category for readability.
    """
    lines = []
    
    categories = sorted(set(p.category for p in get_all_predicates()))
    
    for category in categories:
        preds = get_predicates_by_category(category)
        if preds:
            lines.append(f"\n{category.upper()} PREDICATES:")
            for pred in preds:
                if pred.parameters:
                    params = " ".join(f"?{p[0]} - {p[1]}" for p in pred.parameters)
                    lines.append(f"  ({pred.name} {params})")
                else:
                    lines.append(f"  ({pred.name})")
                if pred.description:
                    lines.append(f"    ; {pred.description}")
    
    return "\n".join(lines)


def generate_predicates_pddl() -> str:
    """
    Generate the (:predicates ...) section for PDDL domain.
    
    Returns:
        PDDL predicates declaration string
    """
    lines = ["  (:predicates"]
    
    # Group by category
    categories = ["package", "service", "filesystem", "user", "group", 
                  "network", "firewall", "process", "environment", "relationship"]
    
    for category in categories:
        preds = get_predicates_by_category(category)
        if preds:
            lines.append(f"    ; {category.title()} predicates")
            for pred in preds:
                if pred.parameters:
                    params = " ".join(f"?{p[0]} - {p[1]}" for p in pred.parameters)
                    lines.append(f"    ({pred.name} {params})")
                else:
                    lines.append(f"    ({pred.name})")
            lines.append("")
    
    lines.append("  )")
    return "\n".join(lines)


def is_known_predicate(name: str) -> bool:
    """Check if a predicate name is in the known vocabulary."""
    return name in get_predicate_names()


def get_predicate_arity(name: str) -> Optional[int]:
    """Get the expected arity (number of parameters) for a predicate."""
    for pred in get_all_predicates():
        if pred.name == name:
            return len(pred.parameters)
    return None


# =============================================================================
# Predicate Aliases (for unification during merge)
# =============================================================================

PREDICATE_ALIASES: dict[str, list[str]] = {
    "file_exists": ["file_present", "has_file", "exists"],
    "service_running": ["service_active", "svc_running", "is_running"],
    "package_installed": ["pkg_installed", "has_package", "installed"],
    "user_exists": ["user_present", "has_user"],
    "group_exists": ["group_present", "has_group"],
    "port_open": ["port_listening", "is_open"],
    "interface_up": ["interface_active", "is_up"],
}


def get_canonical_predicate_name(name: str) -> str:
    """
    Get the canonical predicate name, resolving aliases.
    
    Args:
        name: A predicate name (possibly an alias)
        
    Returns:
        The canonical predicate name
    """
    # Build reverse mapping
    for canonical, aliases in PREDICATE_ALIASES.items():
        if name in aliases:
            return canonical
    return name
