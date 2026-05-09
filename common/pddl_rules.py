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
   - ALL arguments in action preconditions/effects MUST be variables with ? prefix
     WRONG: (cmd_executed_by_group command ?group)  <- "command" needs ?
     WRONG: (configures dir ?usr)                   <- "dir" needs ?
     RIGHT: (cmd_executed_by_group ?command ?group) <- Both are variables
     RIGHT: (configures ?dir ?usr)                  <- Both are variables

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

10. BNF GRAMMAR FOR ACTION BLOCKS (must follow EXACTLY):

   <action-def> ::=
       (:action <name>
           :parameters (<typed-list-variable>)
           [:precondition <pre-GD>]
           [:effect <effect>]
       )

   <typed-list-variable> ::=
       <variable> - <type>
       | <variable> <variable> ... - <type>
       | (empty)

   <variable> ::= ?<name>

   <pre-GD> ::=
       ()                                        ;; empty precondition (always true)
       | <atomic-formula>                         ;; single predicate
       | (and <pre-GD>*)                          ;; conjunction
       | (not <atomic-formula>)                   ;; negation (STRIPS)

   <effect> ::=
       ()                                        ;; no effect (rare but valid)
       | <atomic-formula>                         ;; add a fact
       | (not <atomic-formula>)                   ;; delete a fact
       | (and <c-effect>*)                        ;; conjunction of effects
       | (when <pre-GD> <c-effect>)               ;; conditional effect

   <atomic-formula> ::= (<predicate-name> <variable>+)

   KEY RULES from BNF:
   - :parameters MUST be followed by ( ... ) even if empty: :parameters ()
   - :precondition MUST be followed by ( ... ) -- NEVER :precondition :effect
   - :effect MUST be followed by ( ... ) -- NEVER :effect )
   - Every ( must have a matching )
   - Action body keywords appear in fixed order: :parameters, :precondition, :effect

11. COMMON MISTAKES TO AVOID (frequently made by LLMs):

   a) Variables in effects/preconditions NOT declared in :parameters:
      WRONG:
        (:action install_pkg
          :parameters (?pkg - package)
          :precondition (repo_available ?repo)     ;; ?repo not in :parameters!
          :effect (package_installed ?pkg))
      RIGHT:
        (:action install_pkg
          :parameters (?pkg - package ?repo - repository)
          :precondition (repo_available ?repo)
          :effect (package_installed ?pkg))

   b) Empty or missing precondition body (causes parse errors):
      WRONG: :precondition :effect (something ?x)  ;; missing precondition body!
      WRONG: :precondition                          ;; dangling keyword
      RIGHT: :precondition () :effect (something ?x)
      RIGHT: :precondition (and) :effect (something ?x)

   c) Using reserved words as predicate names:
      WRONG: (exists ?f)         ;; "exists" is a reserved quantifier
      WRONG: (not ?service)      ;; "not" is a logical operator, not a predicate
      WRONG: (and ?x ?y)         ;; "and" is a logical operator
      RIGHT: (file_exists ?f)
      RIGHT: (service_stopped ?service)
      RIGHT: (items_linked ?x ?y)

   d) Predicate arity mismatch (using different arg counts than declared):
      If declared: (:predicates (file_owned_by ?f - file ?u - user))
      WRONG: (file_owned_by ?f)           ;; only 1 arg, declared with 2
      WRONG: (file_owned_by ?f ?u ?g)     ;; 3 args, declared with 2
      RIGHT: (file_owned_by ?f ?u)        ;; matches declaration

   e) Disjunction (or) in effects -- INVALID in PDDL:
      WRONG: :effect (or (state_a ?x) (state_b ?x))
      RIGHT: :effect (state_a ?x)    ;; pick the intended effect

   f) Bare predicates without wrapping conjunction:
      WRONG: :precondition (pred1 ?x) (pred2 ?y)   ;; two unwrapped predicates
      RIGHT: :precondition (and (pred1 ?x) (pred2 ?y))

   g) Non-variable arguments in predicates:
      WRONG: (service_running sshd)           ;; "sshd" is a constant, not ?var
      WRONG: (file_has_mode ?f 0644)          ;; "0644" is not a variable
      RIGHT: (service_running ?svc)
      RIGHT: (file_has_mode ?f ?mode)

   h) Nested actions or duplicate keywords:
      WRONG: (:action foo :parameters () :precondition () :precondition () :effect ())
      WRONG: (:action foo :parameters () :effect () (:action bar ...))
      RIGHT: One :parameters, one :precondition, one :effect per action

12. CORRECT vs INCORRECT FULL ACTION EXAMPLES:

   CORRECT example:
     (:action restart_service
       :parameters (?svc - service)
       :precondition (and
         (service_installed ?svc)
         (not (service_running ?svc)))
       :effect (and
         (service_running ?svc)
         (service_healthy ?svc)))

   INCORRECT example 1 -- missing :precondition body:
     (:action restart_service
       :parameters (?svc - service)
       :precondition                        ;; ERROR: no body after :precondition
       :effect (service_running ?svc))

   INCORRECT example 2 -- undeclared variable and infix operator:
     (:action change_owner
       :parameters (?f - file)
       :precondition (file_exists ?f)
       :effect (file_owned_by ?f ?u))       ;; ERROR: ?u not in :parameters

   INCORRECT example 3 -- reserved word as predicate, bare constants:
     (:action delete_user
       :parameters (?u - user)
       :precondition (exists ?u)            ;; ERROR: "exists" is reserved
       :effect (not (exists ?u)))           ;; ERROR: same problem

   CORRECTED version of example 3:
     (:action delete_user
       :parameters (?u - user)
       :precondition (user_exists ?u)
       :effect (not (user_exists ?u)))

   INCORRECT example 4 -- multiple bare predicates, no conjunction:
     (:action secure_file
       :parameters (?f - file ?u - user)
       :precondition (file_exists ?f) (user_exists ?u)    ;; ERROR: not wrapped in (and ...)
       :effect (not (file_world_readable ?f)) (file_owned_by ?f ?u))  ;; ERROR: same

   CORRECTED version of example 4:
     (:action secure_file
       :parameters (?f - file ?u - user)
       :precondition (and (file_exists ?f) (user_exists ?u))
       :effect (and (not (file_world_readable ?f)) (file_owned_by ?f ?u)))
"""