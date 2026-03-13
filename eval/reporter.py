import csv
import json
from pathlib import Path
from .results_db import ResultsDB


def generate_summary_csv(db: ResultsDB, output_path: Path) -> None:
    """Write summary stats as CSV."""
    rows = db.get_summary()
    if not rows:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)


def generate_full_csv(db: ResultsDB, output_path: Path) -> None:
    """Write all raw run records as CSV."""
    rows = db.get_all()
    if not rows:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    # Remove JSON blobs from CSV (too large)
    clean_rows = [
        {k: v for k, v in r.items() if k not in ("commands_json", "violations_json")}
        for r in rows
    ]
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=clean_rows[0].keys())
        writer.writeheader()
        writer.writerows(clean_rows)


def generate_latex_table(db: ResultsDB, output_path: Path) -> None:
    """Write main comparison table as LaTeX tabular."""
    rows = db.get_summary()
    if not rows:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        r"\begin{table}[htbp]",
        r"\centering",
        r"\caption{Baseline Evaluation Results on SysRepair-Bench}",
        r"\label{tab:baselines}",
        r"\begin{tabular}{llrrrrrr}",
        r"\toprule",
        r"Baseline & Model & N & PoR\% & SVR\% & EW & Cmds & HR\% \\",
        r"\midrule",
    ]
    for r in rows:
        baseline = r["baseline"].replace("_", r"\_")
        model = r["model"].replace("-", r"\nobreakdash-")
        line = (
            f"{baseline} & {model} & {int(r['n_runs'])} & "
            f"{r['por_pct']:.1f} & {r['svr_pct']:.1f} & "
            f"{r['avg_ew']:.3f} & {r['avg_cmds']:.1f} & "
            f"{r['avg_halluc_pct']:.1f} \\\\"
        )
        lines.append(line)
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]

    output_path.write_text("\n".join(lines))


def generate_all_reports(db_path: Path, output_dir: Path) -> None:
    db = ResultsDB(db_path)
    generate_summary_csv(db, output_dir / "summary.csv")
    generate_full_csv(db, output_dir / "full_results.csv")
    generate_latex_table(db, output_dir / "table_baselines.tex")
    print(f"Reports written to {output_dir}/")
    # Print summary to console
    rows = db.get_summary()
    if rows:
        print(f"\n{'Baseline':<20} {'Model':<20} {'N':>4} {'PoR%':>6} {'SVR%':>6} {'EW':>6} {'Cmds':>6} {'HR%':>6}")
        print("-" * 76)
        for r in rows:
            print(
                f"{r['baseline']:<20} {r['model']:<20} {int(r['n_runs']):>4} "
                f"{r['por_pct']:>6.1f} {r['svr_pct']:>6.1f} {r['avg_ew']:>6.3f} "
                f"{r['avg_cmds']:>6.1f} {r['avg_halluc_pct']:>6.1f}"
            )
