"""
common/__init__.py

Shared modules for PDDL domain generation pipeline.
Provides unified type hierarchy, predicates, sanitization, and models.
"""

from common.type_hierarchy import (
    CORE_TYPE_HIERARCHY,
    VALID_TYPES,
    TYPE_MAPPINGS,
    normalize_type,
    get_type_parent,
    is_subtype_of,
    generate_types_pddl,
)

from common.predicates import (
    STATIC_PREDICATES,
    DYNAMIC_PREDICATES,
    PredicateDefinition,
    get_all_predicates,
    get_predicates_by_category,
    get_base_predicates,
    get_predicate_names,
    format_predicates_for_prompt,
    generate_predicates_pddl,
    is_known_predicate,
    get_predicate_arity,
    PREDICATE_ALIASES,
    get_canonical_predicate_name,
)

from common.pddl_sanitizer import (
    PDDL_RESERVED_KEYWORDS,
    KEYWORD_TO_PREDICATE,
    sanitize_pddl_identifier,
    sanitize_pddl_name,
    sanitize_predicate,
    sanitize_effect,
    PDDLSanitizer,
    repair_pddl,
)

from common.models import (
    PDDLType,
    EntityType,
    ActionParameter,
    ActionSchema,
    ExtractedObject,
    ExtractedPredicate,
    Relationship,
    Phase1State,
    OSQueryMapping,
    LLMExtractionConfig,
)

__all__ = [
    # Type hierarchy
    "CORE_TYPE_HIERARCHY",
    "VALID_TYPES",
    "TYPE_MAPPINGS",
    "normalize_type",
    "get_type_parent",
    "is_subtype_of",
    "generate_types_pddl",
    
    # Predicates
    "STATIC_PREDICATES",
    "DYNAMIC_PREDICATES",
    "PredicateDefinition",
    "get_all_predicates",
    "get_predicates_by_category",
    "get_base_predicates",
    "get_predicate_names",
    "format_predicates_for_prompt",
    "generate_predicates_pddl",
    "is_known_predicate",
    "get_predicate_arity",
    "PREDICATE_ALIASES",
    "get_canonical_predicate_name",
    
    # Sanitization
    "PDDL_RESERVED_KEYWORDS",
    "KEYWORD_TO_PREDICATE",
    "sanitize_pddl_identifier",
    "sanitize_pddl_name",
    "sanitize_predicate",
    "sanitize_effect",
    "PDDLSanitizer",
    "repair_pddl",
    
    # Models
    "PDDLType",
    "EntityType",
    "ActionParameter",
    "ActionSchema",
    "ExtractedObject",
    "ExtractedPredicate",
    "Relationship",
    "Phase1State",
    "OSQueryMapping",
    "LLMExtractionConfig",
]
