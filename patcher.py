#!/usr/bin/env python3
"""
Quick patch script to fix common PDDL validation errors in generated domain files.
Usage: python fix_pddl.py pddl_output/sysadmin.pddl
"""

import re
import sys
from pathlib import Path


def fix_pddl_domain(content: str) -> str:
    """Apply fixes to PDDL domain content."""

    # FIX 1: Replace invalid OR syntax with valid PDDL
    # Pattern: (pred1) OR (pred2) -> just use pred1 (simplification)
    content = re.sub(
        r'\([^)]+\)\s+OR\s+\([^)]+\)',
        lambda m: m.group(0).split(' OR ')[0],
        content,
        flags=re.IGNORECASE
    )

    # FIX 2: Replace invalid | syntax
    content = re.sub(
        r'\([^)]+\)\s*\|\s*\([^)]+\)',
        lambda m: m.group(0).split('|')[0].strip(),
        content
    )

    # FIX 3: Remove actions with (exists ?path) - PDDL keyword conflict
    # Find and comment out these actions
    content = re.sub(
        r'(\(:action remove_file_or_directory.*?^\s*\))',
        r'; REMOVED - uses PDDL keyword "exists" as predicate\n; \1',
        content,
        flags=re.MULTILINE | re.DOTALL
    )

    # FIX 4: Remove actions with nested function calls in effects
    # Pattern: (pred (func ?x))
    problematic_patterns = [
        r'\(file_has_mode \?[a-z_]+ \(mode_of[^\)]+\)\)',
        r'\(file_owned_by_user \?[a-z_]+ \(owner_of_file[^\)]+\)\)',
        r'\(file_grouped_to_group \?[a-z_]+ \(group_of_file[^\)]+\)\)',
    ]

    for pattern in problematic_patterns:
        # Replace with a simpler valid effect
        content = re.sub(
            pattern,
            lambda m: f"(permissions_copied {' '.join(re.findall(r'\\?[a-z_]+', m.group(0))[:2])})",
            content
        )

    # FIX 5: Remove hardcoded paths like /var/cache/apt/archives
    content = re.sub(
        r'\((?:directory_exists|cache_cleaned|lists_cleaned)\s+/[^\)]+\)',
        '; REMOVED - hardcoded path not valid PDDL object',
        content
    )

    # FIX 6: Fix preconditions with hardcoded paths in clean_cache action
    # Replace the whole action with a corrected version
    clean_cache_fix = '''  (:action clean_cache
    :parameters (?actor - user ?cache_dir - directory)
    :precondition (and
      (directory_exists ?cache_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (cache_cleaned ?cache_dir)
    )
  )'''

    content = re.sub(
        r'\(:action clean_cache.*?^\s*\)\s*(?=\(:action|\)$)',
        clean_cache_fix + '\n\n',
        content,
        flags=re.MULTILINE | re.DOTALL
    )

    # FIX 7: Add missing predicates to predicates section
    missing_predicates = [
        "(permissions_copied ?f1 - file ?f2 - file)",
        "(cache_cleaned ?d - directory)",
    ]

    # Find predicates section and add missing ones
    pred_section_end = content.find("; Dynamically Discovered Predicates")
    if pred_section_end > 0:
        insert_text = "\n    ; Patched predicates\n"
        for pred in missing_predicates:
            if pred.split()[0][1:] not in content:  # Check if not already defined
                insert_text += f"    {pred}\n"
        content = content[:pred_section_end] + insert_text + content[pred_section_end:]

    # FIX 8: Remove undefined action_completed_* effects and replace
    # Find all action_completed_X that aren't defined
    undefined_completions = re.findall(
        r'\(action_completed_([a-z_]+)\)',
        content
    )

    # These need predicates defined - add them
    for action_name in set(undefined_completions):
        pred_def = f"(action_completed_{action_name})"
        if pred_def not in content[:content.find("(:action")]:
            # Add to predicates section
            insert_point = content.find("; Dynamically Discovered Predicates")
            if insert_point > 0:
                content = (
                        content[:insert_point] +
                        f"    (action_completed_{action_name})\n" +
                        content[insert_point:]
                )

    return content


def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_pddl.py <domain.pddl> [output.pddl]")
        sys.exit(1)

    input_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2]) if len(sys.argv) > 2 else input_file.with_suffix('.fixed.pddl')

    print(f"Reading: {input_file}")
    content = input_file.read_text()

    print("Applying fixes...")
    fixed_content = fix_pddl_domain(content)

    print(f"Writing: {output_file}")
    output_file.write_text(fixed_content)

    print("Done! Try validating with:")
    print(f"  Validate {output_file} pddl_output/problem.pddl")


if __name__ == "__main__":
    main()