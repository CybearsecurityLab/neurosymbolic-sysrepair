"""
phase1/common/pddl_rules.py

Distilled PDDL 3.1 rules derived from the official BNF.
Used to instruct the LLM on valid syntax generation.
"""

# Derived from BNF Section 1.1 (Domain) and 1.2 (Problem)
PDDL_SYNTAX_GUIDE = """
STRICT PDDL 3.1 SYNTAX RULES:

1. NAMING CONVENTIONS:
   - Predicates and variables must use alphanumeric characters, hyphens (-), and underscores (_).
   - Variables must always start with '?' (e.g., ?pkg, ?file).
   - Do NOT use paths (e.g., /etc/passwd) as identifiers; use abstract names (e.g., file_etc_passwd).

2. PREDICATES:
   - Format: (predicate_name ?arg1 ?arg2)
   - Example: (package_installed ?p)
   - Do NOT nest predicates inside logical operators within a single string.
     BAD: "(not (package_installed ?p))" (as a predicate name)
     GOOD: "not" is an effect/condition wrapper, not part of the name.

3. CONDITIONS & EFFECTS:
   - Preconditions: Use (and ...), (not ...), (or ...), (forall ...), (exists ...).
   - Effects: Use (and ...), (not ...), (when ...), (forall ...).
   - Negation: To delete a fact, use (not (predicate ?x)).

4. TYPES:
   - All parameters must be typed.
   - Hierarchy: object -> filesystem_object -> file -> configuration_file.
"""
