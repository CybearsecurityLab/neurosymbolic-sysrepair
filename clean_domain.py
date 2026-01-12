import re
import sys


def clean_pddl(input_file, output_file):
    with open(input_file, 'r') as f:
        content = f.read()

    # --- FIX 1: Invalid Logical Operators ---
    # Fix "| (not ...)" syntax to PDDL "(or ... (not ...))"
    # Captures: (pred ?x) | (pred ?y)
    content = re.sub(
        r'(\([^\)]+\))\s*\|\s*(\([^\)]+\))',
        r'(or \1 \2)',
        content
    )

    # Fix "OR" to "or" (PDDL is case insensitive but consistent style helps)
    content = re.sub(r'\) OR \(', ') (', content)

    # --- FIX 2: Keyword Collisions ---
    # "exists" is a PDDL keyword for quantifiers, cannot be a predicate name
    content = re.sub(r'\(exists \?path\)', '(file_exists ?path)', content)

    # --- FIX 3: Hallucinated Function Calls in Predicates ---
    # PDDL predicates cannot contain function calls like parent(?dest)
    # Fix: (directory_exists_or_createable parent(?dest)) -> (directory_exists_or_createable ?dest)
    content = re.sub(r'parent\(\?([a-zA-Z0-9_]+)\)', r'?\1', content)

    # Fix: (file_has_mode ?f (mode_of ?rfile)) -> (file_has_mode ?f ?rfile)
    content = re.sub(r'\(mode_of(_file)? \?([a-zA-Z0-9_]+)\)', r'?\2', content)

    # Fix: (file_owned_by_user ?f (owner_of_file ?rfile)) -> (file_owned_by_user ?f ?rfile)
    content = re.sub(r'\(owner_of_file \?([a-zA-Z0-9_]+)\)', r'?\1', content)
    content = re.sub(r'\(group_of_file \?([a-zA-Z0-9_]+)\)', r'?\1', content)

    # --- FIX 4: Invalid Literals / Unbound Constants ---
    # LLM often inserts "FILTER", "PASS_MAX_DAYS", etc. which are not objects
    # We replace them with a generic object ?obj or remove the line if complex

    # Fix: (filters_applied FILTER) -> (filters_applied)
    content = re.sub(r'\(filters_applied FILTER\)', '(filters_applied)', content)

    # Fix: (greater_than_or_equal_to ?days PASS_MAX_DAYS) -> (greater_than_or_equal_to ?days)
    content = re.sub(r' PASS_MAX_DAYS\)', ')', content)
    content = re.sub(r' SYS_GID_MIN SYS_GID_MAX\)', ')', content)
    content = re.sub(r' SYS_UID_MIN SYS_UID_MAX\)', ')', content)
    content = re.sub(r' UID_MIN UID_MAX\)', ')', content)

    # --- FIX 5: Unbound Variable Typos ---
    # Fix: (rule_added_to_chain_jump target_chain ?chain) -> missing '?'
    content = re.sub(r' target_chain ', ' ?target_chain ', content)
    content = re.sub(r' interface ', ' ?interface ', content)
    content = re.sub(r' extension ', ' ?extension ', content)
    content = re.sub(r' pkts bytes ', ' ?pkts ?bytes ', content)
    content = re.sub(r' first-last\)', ' ?first ?last)', content)

    # --- FIX 6: Hardcoded Paths ---
    # (cache_cleaned /var/cache/...) is invalid.
    content = re.sub(r'/[a-zA-Z0-9/_]+', '?path', content)

    with open(output_file, 'w') as f:
        f.write(content)
    print(f"Cleaned PDDL written to {output_file}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python clean_domain.py <input.pddl> <output.pddl>")
    else:
        clean_pddl(sys.argv[1], sys.argv[2])