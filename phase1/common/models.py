"""
phase1/common/models.py

Core data models, Enums, and Data Classes used throughout the system.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, List


# =============================================================================
# Enums
# =============================================================================

class PDDLType(Enum):
    """Base PDDL types mapped from OS concepts."""
    PACKAGE = "package"
    SERVICE = "service"
    USER = "user"
    GROUP = "group"
    FILE = "file"
    DIRECTORY = "directory"
    CONFIG_FILE = "configuration_file"
    PORT = "port"
    INTERFACE = "interface"
    FIREWALL_RULE = "firewall_rule"
    PROCESS = "process"


class EntityType(Enum):
    """Types of entities in the system dependency graph (Scoping)."""
    PORT = "port"
    PROCESS = "process"
    SERVICE = "service"
    PACKAGE = "package"
    USER = "user"
    GROUP = "group"
    CONFIG_FILE = "configuration_file"
    FILE = "file"
    FIREWALL_RULE = "firewall_rule"
    INTERFACE = "interface"

# =============================================================================
# Configuration Data Classes
# =============================================================================

@dataclass
class OSQueryMapping:
    """Configuration for mapping osquery tables to PDDL constructs."""
    table: str
    query: str
    pddl_type: PDDLType
    predicate_name: str
    predicate_condition: Optional[str] = None  # SQL condition for predicate truth
    name_column: str = "name"
    additional_columns: List[str] = field(default_factory=list)


@dataclass
class LLMExtractionConfig:
    """Configuration for LLM-based action extraction."""
    model_id: str
    model_url: str = "http://localhost:11434"
    enabled: bool = True
    timeout: int = 600
    max_retries: int = 2
    temperature: float = 0.0

# =============================================================================
# Extraction Data Classes
# =============================================================================

@dataclass
class ExtractedObject:
    """Represents an extracted system object."""
    pddl_type: PDDLType
    name: str
    properties: dict = field(default_factory=dict)


@dataclass
class ExtractedPredicate:
    """Represents a grounded predicate from the system state."""
    name: str
    arguments: list
    value: bool = True


@dataclass
class GraphEntity:
    """A node in the dependency graph (used in Scoping)."""
    id: str
    entity_type: EntityType
    name: str
    original_data: dict = field(default_factory=dict)
    is_anchor: bool = False
    anchor_reason: str = ""
    reachable: bool = False
    depth: int = -1

# =============================================================================
# Action Mining Data Classes
# =============================================================================

@dataclass
class ActionParameter:
    """Parameter for a PDDL action."""
    name: str
    pddl_type: PDDLType


@dataclass
class ActionSchema:
    """Extracted action schema from man pages."""
    name: str
    parameters: List[ActionParameter]
    preconditions: List[str]
    effects: List[str]
    command_template: str
    requires_root: bool = False
    source_utility: str = ""
    extraction_method: str = "regex"