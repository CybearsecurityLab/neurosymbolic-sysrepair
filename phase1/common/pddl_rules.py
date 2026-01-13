"""
phase1/common/pddl_rules.py

Distilled PDDL 3.1 rules derived from the official BNF.
Used to instruct the LLM on valid syntax generation.
"""

# Derived from BNF Section 1.1 (Domain) and 1.2 (Problem)
# Reference: "Complete BNF description of PDDL 3.1" by Daniel L. Kovacs
PDDL_SYNTAX_GUIDE = """
STRICT PDDL 3.1 SYNTAX RULES:

1. NAMING CONVENTIONS:
   - Predicates and variables must use alphanumeric characters, hyphens (-), and underscores (_).
   - Variables must always start with '?' (e.g., ?pkg, ?file).
   - Names must start with a letter: <name> ::= <letter> <any char>*
   - Do NOT use paths (e.g., /etc/passwd) as identifiers; use abstract names (e.g., file_etc_passwd).

2. RESERVED KEYWORDS - NEVER use these as predicate names:
   - Logical operators: and, or, not, imply
   - Quantifiers: exists, forall  <- NEVER USE, not even as quantifiers (we use STRIPS)
   - Conditionals: when
   - Structure: define, domain, problem, action, parameters, precondition, effect
   - Types: either, object, number
   - Operators: assign, increase, decrease, scale-up, scale-down
   - Temporal: at, over, start, end, always, sometime, within
   - Other: preference, minimize, maximize, total-cost, total-time
   
   CRITICAL - "exists" errors:
   WRONG: (exists ?f)                        <- "exists" is reserved, malformed
   WRONG: (exists (?f - file) (pred ?f))     <- Don't use quantifiers at all
   RIGHT: (file_exists ?f)                   <- Use descriptive predicate name

3. PREFIX NOTATION ONLY - PDDL uses Lisp-style prefix notation:
   WRONG: (file_exists ?f) or (directory_exists ?f)    <- Infix "or" is INVALID
   WRONG: (pred1 ?x) and (pred2 ?x)                    <- Infix "and" is INVALID
   RIGHT: (or (file_exists ?f) (directory_exists ?f))  <- Prefix notation
   RIGHT: (and (pred1 ?x) (pred2 ?x))                  <- Prefix notation

4. PREDICATES:
   - Format: (predicate_name ?arg1 ?arg2)
   - Example: (package_installed ?p)
   - Predicate names must NOT be reserved keywords
   - Each predicate is a single S-expression, not multiple joined by operators

5. PRECONDITIONS - Valid forms (STRIPS level, no quantifiers):
   - Atomic: (predicate ?args)
   - Negation: (not (predicate ?args))
   - Conjunction: (and (pred1 ?x) (pred2 ?y) ...)
   
   DO NOT USE quantifiers (exists, forall) - we target STRIPS without :existential-preconditions
   WRONG: (exists (?f - file) (file_exists ?f))   <- Don't use exists
   WRONG: (forall (?p - package) (installed ?p))  <- Don't use forall
   RIGHT: (file_exists ?f)                         <- Simple predicate

6. EFFECTS - Valid forms per BNF <effect> and <c-effect>:
   - Add fact: (predicate ?args)
   - Delete fact: (not (predicate ?args))
   - Conjunction: (and (effect1) (effect2) ...)
   - Conditional: (when (condition) (effect))         [requires :conditional-effects]
   - NO disjunction (or) in effects - this is INVALID in PDDL

7. DO NOT USE QUANTIFIERS:
   We generate STRIPS-level PDDL. Do NOT use exists or forall.
   WRONG: (exists (?x - file) (pred ?x))     <- No quantifiers
   WRONG: (exists ?x)                        <- Definitely wrong  
   WRONG: (forall (?p - pkg) (installed ?p)) <- No quantifiers
   RIGHT: (file_exists ?f)                   <- Simple predicate with action parameter

8. TYPES:
   - All parameters must be typed: ?var - type
   - Hierarchy: object -> filesystem_object -> file -> configuration_file
   - Use specific types: package, service, user, group, file, port, process

9. OUTPUT FORMAT FOR EXTRACTED ACTIONS:
   - preconditions: List of INDIVIDUAL predicates, NOT joined with "or"/"and"
     WRONG: ["(file_exists ?f) or (directory_exists ?f)"]
     RIGHT: ["(file_exists ?f)", "(directory_exists ?f)"]  <- Separate list items
   - effects: List of INDIVIDUAL predicates
     WRONG: ["(not (file_exists ?f)) and (not (directory_exists ?f))"]  
     RIGHT: ["(not (file_exists ?f))", "(not (directory_exists ?f))"]
"""