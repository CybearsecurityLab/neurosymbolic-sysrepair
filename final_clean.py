import re
import sys

def repair_pddl(input_file, output_file):
    with open(input_file, 'r') as f:
        content = f.read()

    # FIX 1: The "|" operator is invalid in standard PDDL.
    # The clean script might have missed cases with newlines.
    # Pattern: (pred) | (pred) -> (or (pred) (pred))
    # We replace " |" with nothing, then wrap the preceding/following clauses in (or ...) if needed,
    # but a safer quick fix for "A | B" is often just "A" (simplification) or "or A B".
    # Given the context in line 800+ of your file:
    # (file_exists ?f) | (not (file_exists ?f))
    # This is a tautology (always true). We can just remove the second part or wrap in OR.
    content = re.sub(r'\|\s*\n\s*\(not \(file_exists \?f\)\)', '', content)

    # FIX 2: "parent(?dest)" is not valid PDDL.
    # Logic: (directory_exists_or_createable parent(?dest))
    # Fix: (directory_exists_or_createable ?dest)
    content = re.sub(r'parent\(\?([a-zA-Z0-9_]+)\)', r'?\1', content)

    # FIX 3: "mode_of ?reference_file" function calls inside predicates
    # Logic: (file_has_mode ?target_file (mode_of ?reference_file))
    # Fix: (file_has_mode ?target_file ?reference_file)
    content = re.sub(r'\(mode_of \?([a-zA-Z0-9_]+)\)', r'?\1', content)
    content = re.sub(r'\(mode_of_file \?([a-zA-Z0-9_]+)\)', r'?\1', content)

    # FIX 4: "owner_of_file" and "group_of_file"
    content = re.sub(r'\(owner_of_file \?([a-zA-Z0-9_]+)\)', r'?\1', content)
    content = re.sub(r'\(group_of_file \?([a-zA-Z0-9_]+)\)', r'?\1', content)

    # FIX 5: Missing '?' prefix on variables in "add_subordinate_uids"
    # Logic: (subuid_range_added ?user first-last)
    # Fix: (subuid_range_added ?user ?first ?last)
    content = content.replace(' first-last)', ' ?first ?last)')

    # FIX 6: Missing '?' prefix on "add_firewall_rule_match_extension"
    # Logic: ... extension ?chain)
    # Fix: ... ?extension ?chain)
    content = content.replace(' extension ?chain)', ' ?extension ?chain)')

    # FIX 7: Missing '?' prefix on "add_firewall_rule_out_interface"
    # Logic: ... interface ?chain)
    # Fix: ... ?interface ?chain)
    content = content.replace(' interface ?chain)', ' ?interface ?chain)')

    # FIX 8: Missing '?' prefix on "add_firewall_rule_set_counters"
    # Logic: ... pkts bytes ?chain)
    # Fix: ... ?pkts ?bytes ?chain)
    content = content.replace(' pkts bytes ?chain)', ' ?pkts ?bytes ?chain)')

    # FIX 9: Missing '?' prefix on "add_firewall_rule_goto_chain"
    # Logic: ... target_chain ?chain)
    # Fix: ... ?target_chain ?chain)
    content = content.replace(' target_chain ?chain)', ' ?target_chain ?chain)')

    # FIX 10: Remove hardcoded paths in predicates (e.g., /home/user)
    # Pattern: (directory_exists /home/user)
    # We replace any word starting with / that isn't inside quotes (simplified)
    # A safer bet is replacing specific known bad paths from the file
    bad_paths = ['/home/user', 'mail_spool', '/var/cache/apt/archives', '/var/lib/apt/lists', '/etc/subuid', '/etc/subgid']
    for path in bad_paths:
        content = content.replace(f' {path})', ' ?path)')

    # FIX 11: Fix "FILTER" literal in apply_filters_from_file
    content = content.replace(' FILTER)', ' ?filter_file)')

    # FIX 12: Ensure requirements include :adl for advanced logic if used
    if '(:requirements' in content:
        if ':adl' not in content:
            content = content.replace('(:requirements', '(:requirements :adl')

    with open(output_file, 'w') as f:
        f.write(content)
    print(f"Repaired PDDL written to {output_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python final_clean.py <input.pddl> <output.pddl>")
    else:
        repair_pddl(sys.argv[1], sys.argv[2])