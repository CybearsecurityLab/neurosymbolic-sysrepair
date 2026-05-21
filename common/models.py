"""
common/models.py

Shared data models for Phase 1 and Phase 2.
Provides serialization/deserialization for passing data between phases.
"""

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


# =============================================================================
# Enums (shared between phases)
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
    REPOSITORY = "repository"
    OBJECT = "object"


class EntityType(Enum):
    """Types of entities in the system dependency graph."""
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
# Action Schema (shared between phases)
# =============================================================================

@dataclass
class ActionParameter:
    """Parameter for a PDDL action."""
    name: str
    pddl_type: str  # String type name for easy serialization
    
    def to_dict(self) -> dict:
        return {"name": self.name, "type": self.pddl_type}
    
    @classmethod
    def from_dict(cls, data: dict) -> "ActionParameter":
        return cls(
            name=data["name"],
            pddl_type=data.get("type", data.get("pddl_type", "object"))
        )


@dataclass
class ActionSchema:
    """
    Extracted action schema - the core unit of PDDL action definition.
    Used by both Phase 1 (extraction) and Phase 2 (synthesis).
    """
    name: str
    parameters: list[ActionParameter]
    preconditions: list[str]
    effects: list[str]
    command_template: str = ""
    requires_root: bool = False
    source_utility: str = ""
    extraction_method: str = "unknown"  # "regex", "llm", "merged"
    
    def to_dict(self) -> dict:
        """Serialize to dictionary for JSON storage."""
        return {
            "name": self.name,
            "parameters": [p.to_dict() for p in self.parameters],
            "preconditions": self.preconditions,
            "effects": self.effects,
            "command_template": self.command_template,
            "requires_root": self.requires_root,
            "source_utility": self.source_utility,
            "extraction_method": self.extraction_method,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ActionSchema":
        """Deserialize from dictionary."""
        params = [ActionParameter.from_dict(p) for p in data.get("parameters", [])]
        return cls(
            name=data["name"],
            parameters=params,
            preconditions=data.get("preconditions", []),
            effects=data.get("effects", []),
            command_template=data.get("command_template", ""),
            requires_root=data.get("requires_root", False),
            source_utility=data.get("source_utility", ""),
            extraction_method=data.get("extraction_method", "unknown"),
        )
    
    def to_pddl(self, include_root_param: bool = True) -> str:
        """
        Generate PDDL action string.
        
        Args:
            include_root_param: If True and requires_root, add ?actor parameter
            
        Returns:
            PDDL action definition string
        """
        lines = [f"  (:action {self.name}"]
        
        # Build parameters
        params_list = [f"?{p.name} - {p.pddl_type}" for p in self.parameters]
        if include_root_param and self.requires_root:
            params_list.insert(0, "?actor - user")
        
        params = " ".join(params_list)
        lines.append(f"    :parameters ({params})")
        
        # Preconditions
        lines.append("    :precondition (and")
        for pre in self.preconditions:
            lines.append(f"      {pre}")
        if self.requires_root:
            lines.append("      (can_escalate ?actor)")
        lines.append("    )")
        
        # Effects
        lines.append("    :effect (and")
        if self.effects:
            for eff in self.effects:
                lines.append(f"      {eff}")
        else:
            lines.append(f"      (action_completed_{self.name})")
        lines.append("    )")
        
        lines.append("  )")
        return "\n".join(lines)

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
# Extracted Object (from osquery)
# =============================================================================

@dataclass
class ExtractedObject:
    """Represents an extracted system object."""
    name: str
    original_name: str
    pddl_type: str
    properties: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "original_name": self.original_name,
            "type": self.pddl_type,
            "properties": self.properties,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ExtractedObject":
        return cls(
            name=data["name"],
            original_name=data.get("original_name", data["name"]),
            pddl_type=data.get("type", data.get("pddl_type", "object")),
            properties=data.get("properties", {}),
        )


# =============================================================================
# Extracted Predicate
# =============================================================================

@dataclass
class ExtractedPredicate:
    """Represents a grounded predicate from the system state."""
    name: str
    arguments: list[str]
    value: bool = True
    
    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "arguments": self.arguments,
            "value": self.value,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "ExtractedPredicate":
        return cls(
            name=data["name"],
            arguments=data.get("arguments", []),
            value=data.get("value", True),
        )


# =============================================================================
# Relationship
# =============================================================================

@dataclass
class Relationship:
    """Represents a relationship between objects."""
    relation_type: str  # "depends_on", "configures", "member_of", etc.
    source: str
    target: str
    properties: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "type": self.relation_type,
            "source": self.source,
            "target": self.target,
            "properties": self.properties,
        }


# =============================================================================
# Phase 1 Output State (for Phase 2 consumption)
# =============================================================================

@dataclass
class Phase1State:
    """
    Complete Phase 1 output state for consumption by Phase 2.
    Provides full context including objects, predicates, actions, and relationships.
    """
    objects: dict[str, list[dict]] = field(default_factory=dict)
    predicates: list[dict] = field(default_factory=list)
    relationships: dict[str, list[dict]] = field(default_factory=dict)
    actions: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return {
            "objects": self.objects,
            "predicates": self.predicates,
            "relationships": self.relationships,
            "actions": self.actions,
            "metadata": self.metadata,
        }
    
    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
    
    @classmethod
    def from_dict(cls, data: dict) -> "Phase1State":
        return cls(
            objects=data.get("objects", {}),
            predicates=data.get("predicates", []),
            relationships=data.get("relationships", {}),
            actions=data.get("actions", []),
            metadata=data.get("metadata", {}),
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> "Phase1State":
        return cls.from_dict(json.loads(json_str))
    
    @classmethod
    def from_file(cls, filepath: str) -> "Phase1State":
        with open(filepath, "r") as f:
            return cls.from_dict(json.load(f))
    
    def get_actions(self) -> list[ActionSchema]:
        """Deserialize actions to ActionSchema objects."""
        return [ActionSchema.from_dict(a) for a in self.actions]
    
    def get_actions_by_utility(self, utility: str) -> list[ActionSchema]:
        """Get actions filtered by source utility."""
        return [
            ActionSchema.from_dict(a) 
            for a in self.actions 
            if a.get("source_utility", "") == utility
        ]
    
    def get_actions_for_utilities(self, utilities: list[str]) -> list[ActionSchema]:
        """Get actions for multiple utilities."""
        utility_set = set(utilities)
        return [
            ActionSchema.from_dict(a) 
            for a in self.actions 
            if a.get("source_utility", "") in utility_set
        ]
    
    def get_predicate_names(self) -> set[str]:
        """Get set of all predicate names from extracted predicates."""
        return {p["name"] for p in self.predicates}
    
    def get_object_names(self, pddl_type: Optional[str] = None) -> set[str]:
        """Get set of object names, optionally filtered by type."""
        names = set()
        for type_name, objs in self.objects.items():
            if pddl_type is None or type_name == pddl_type:
                for obj in objs:
                    names.add(obj.get("name", ""))
        return names


# =============================================================================
# OSQuery Mapping Configuration
# =============================================================================

@dataclass
class OSQueryMapping:
    """Configuration for mapping osquery tables to PDDL constructs."""
    table: str
    query: str
    pddl_type: str
    predicate_name: str
    predicate_condition: Optional[str] = None
    name_column: str = "name"
    additional_columns: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)


# =============================================================================
# LLM Extraction Configuration
# =============================================================================

@dataclass
class LLMExtractionConfig:
    """Configuration for LLM-based action extraction."""
    model_id: str = "gemma-4-31b"
    model_url: str = "http://localhost:8001/v1"
    api_key: str = "vllm"
    enabled: bool = True
    timeout: int = 600
    max_retries: int = 2
    temperature: float = 0.0
    max_workers: int = 1  # Number of parallel LLM extraction workers
    # Output cap per call. 0 means "no cap" (let reasoning models run).
    max_tokens: int = 0
