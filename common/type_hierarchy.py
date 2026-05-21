"""
common/type_hierarchy.py

Canonical PDDL type hierarchy shared between Phase 1 and Phase 2.
This is the single source of truth for type definitions.

Based on Section 3.1 of the research document: Hierarchical Type System
"""

from typing import Optional

# =============================================================================
# Core Type Hierarchy (Section 3.1)
# =============================================================================

# Maps type_name -> parent_type (None for root types)
CORE_TYPE_HIERARCHY: dict[str, Optional[str]] = {
    # Base type
    "object": None,
    
    # Filesystem types
    "filesystem_object": "object",
    "file": "filesystem_object",
    "directory": "filesystem_object",
    "configuration_file": "file",
    
    # Execution types
    "service": "object",
    "process": "object",
    
    # Package management types
    "package": "object",
    "repository": "object",
    
    # Access control types
    "user": "object",
    "group": "object",
    "system_user": "user",
    "human_user": "user",
    
    # Network types
    "port": "object",
    "interface": "object",
    "firewall_rule": "object",
}

# Set of all valid types for validation
VALID_TYPES: frozenset[str] = frozenset(CORE_TYPE_HIERARCHY.keys())

# Map hallucinated/invalid types to valid ones
TYPE_MAPPINGS: dict[str, str] = {
    # CamelCase variants
    "FirewallRule": "firewall_rule",
    "Interface": "interface",
    "Port": "port",
    "Repository": "repository",
    "Package": "package",
    "Service": "service",
    "User": "user",
    "Group": "group",
    "File": "file",
    "Directory": "directory",
    "ConfigurationFile": "configuration_file",
    "FilesystemObject": "filesystem_object",
    
    # Common LLM hallucinations
    "Timestamp": "object",
    "Permission": "object",
    "Owner": "user",
    "ACL": "object",
    "boolean": "object",
    "string": "object",
    "integer": "object",
    "list": "object",
    "command": "process",
    "cmd": "process",
    
    # Typos and variations
    "_user": "user",
    "_group": "group",
    "_file": "file",
    "config": "configuration_file",
    "config_file": "configuration_file",
    "conf_file": "configuration_file",
    "svc": "service",
    "pkg": "package",
    "proc": "process",
    "iface": "interface",
    "fw_rule": "firewall_rule",
}


def normalize_type(type_name: str) -> str:
    """
    Normalize a type name to a valid PDDL type.
    
    Args:
        type_name: The type name to normalize
        
    Returns:
        A valid type name from VALID_TYPES, defaults to 'object'
    """
    if not type_name:
        return "object"

    # Reused Phase 1 action parameters carry PDDLType enums (or other
    # non-str objects) rather than plain strings. Coerce to the string
    # form before any string operations.
    if not isinstance(type_name, str):
        type_name = getattr(type_name, "value", None) or str(type_name)

    # Check if already valid
    if type_name in VALID_TYPES:
        return type_name
    
    # Check mappings
    if type_name in TYPE_MAPPINGS:
        return TYPE_MAPPINGS[type_name]
    
    # Try lowercase
    lower = type_name.lower()
    if lower in VALID_TYPES:
        return lower
    
    if lower in TYPE_MAPPINGS:
        return TYPE_MAPPINGS[lower]
    
    # Default to object
    return "object"


def get_type_parent(type_name: str) -> Optional[str]:
    """Get the parent type of a given type."""
    normalized = normalize_type(type_name)
    return CORE_TYPE_HIERARCHY.get(normalized)


def is_subtype_of(child: str, parent: str) -> bool:
    """
    Check if child is a subtype of parent in the hierarchy.
    
    Args:
        child: The potential child type
        parent: The potential parent type
        
    Returns:
        True if child is a subtype of parent (or equal)
    """
    child = normalize_type(child)
    parent = normalize_type(parent)
    
    if child == parent:
        return True
    
    current = child
    while current is not None:
        current = CORE_TYPE_HIERARCHY.get(current)
        if current == parent:
            return True
    
    return False


def generate_types_pddl() -> str:
    """
    Generate the (:types ...) section for PDDL domain.
    
    Returns:
        PDDL types declaration string
    """
    lines = ["  (:types"]
    
    # Group types by parent
    parent_groups: dict[str, list[str]] = {}
    for type_name, parent in CORE_TYPE_HIERARCHY.items():
        if parent is None:
            continue  # Skip root 'object'
        if parent not in parent_groups:
            parent_groups[parent] = []
        parent_groups[parent].append(type_name)
    
    # Output in hierarchy order for readability
    hierarchy_order = ["object", "filesystem_object", "file", "user"]
    
    # Add comments and type declarations
    lines.append("    ; Base types")
    lines.append("    ")
    
    lines.append("    ; Filesystem types")
    if "object" in parent_groups:
        fs_types = [t for t in parent_groups["object"] if t in ["filesystem_object"]]
        if fs_types:
            lines.append(f"    {' '.join(fs_types)} - object")
    if "filesystem_object" in parent_groups:
        lines.append(f"    {' '.join(sorted(parent_groups['filesystem_object']))} - filesystem_object")
    if "file" in parent_groups:
        lines.append(f"    {' '.join(sorted(parent_groups['file']))} - file")
    lines.append("    ")
    
    lines.append("    ; Execution types")
    exec_types = [t for t in parent_groups.get("object", []) if t in ["service", "process"]]
    if exec_types:
        lines.append(f"    {' '.join(sorted(exec_types))} - object")
    lines.append("    ")
    
    lines.append("    ; Package management types")
    pkg_types = [t for t in parent_groups.get("object", []) if t in ["package", "repository"]]
    if pkg_types:
        lines.append(f"    {' '.join(sorted(pkg_types))} - object")
    lines.append("    ")
    
    lines.append("    ; Access control types")
    access_types = [t for t in parent_groups.get("object", []) if t in ["user", "group"]]
    if access_types:
        lines.append(f"    {' '.join(sorted(access_types))} - object")
    if "user" in parent_groups:
        lines.append(f"    {' '.join(sorted(parent_groups['user']))} - user")
    lines.append("    ")
    
    lines.append("    ; Network types")
    net_types = [t for t in parent_groups.get("object", []) if t in ["port", "interface", "firewall_rule"]]
    if net_types:
        lines.append(f"    {' '.join(sorted(net_types))} - object")
    
    lines.append("  )")
    
    return "\n".join(lines)
