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
   - Quantifiers: exists, forall
   - Conditionals: when
   - Structure: define, domain, problem, action, parameters, precondition, effect
   - Types: either, object, number
   - Operators: assign, increase, decrease, scale-up, scale-down
   - Temporal: at, over, start, end, always, sometime, within
   - Other: preference, minimize, maximize, total-cost, total-time
   
   WRONG: (exists ?f)           <- "exists" is a reserved quantifier keyword
   RIGHT: (file_exists ?f)      <- Use descriptive predicate name

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

5. PRECONDITIONS - Valid forms per BNF <GD> and <pre-GD>:
   - Atomic: (predicate ?args)
   - Negation: (not (predicate ?args))
   - Conjunction: (and (pred1 ?x) (pred2 ?y) ...)
   - Disjunction: (or (pred1 ?x) (pred2 ?y) ...)      [requires :disjunctive-preconditions]
   - Existential: (exists (?var - type) (predicate ?var))  [requires :existential-preconditions]
   - Universal: (forall (?var - type) (predicate ?var))    [requires :universal-preconditions]

6. EFFECTS - Valid forms per BNF <effect> and <c-effect>:
   - Add fact: (predicate ?args)
   - Delete fact: (not (predicate ?args))
   - Conjunction: (and (effect1) (effect2) ...)
   - Conditional: (when (condition) (effect))         [requires :conditional-effects]
   - NO disjunction (or) in effects - this is INVALID in PDDL

7. QUANTIFIER SYNTAX - exists/forall require typed variable list:
   WRONG: (exists ?x (pred ?x))              <- Missing type declaration
   WRONG: (exists ?x)                        <- Incomplete, missing body
   RIGHT: (exists (?x - file) (pred ?x))     <- Correct: typed var + body

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