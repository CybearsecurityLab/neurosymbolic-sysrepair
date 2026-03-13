from pathlib import Path
from dataclasses import dataclass
import re


@dataclass
class Scenario:
    id: str                    # e.g. "ccdc-01", "meta2-16"
    collection: str            # "ccdc" | "meta2"
    category: str              # "config" | "dependency" | "access_control" | "network"
    title: str
    cwe: str                   # e.g. "CWE-250" (empty string if not found)
    dockerfile_path: Path
    threat_md_path: Path
    verify_sh_path: Path
    vuln_description: str      # full threat.md contents
    base_image: str            # "ubuntu:25.10" or "lpenz/ubuntu-hardy-amd64"


def _infer_category(vuln_text: str, title: str) -> str:
    """Infer category from keywords in threat.md"""
    text = (vuln_text + title).lower()
    if any(w in text for w in ["permission", "chmod", "chown", "suid", "shadow", "passwd file", "setfacl", "sticky", "ownership", "group membership", "sudo group", "access control"]):
        return "access_control"
    if any(w in text for w in ["package", "install", "remove", "upgrade", "dependency", "backdoor", "malicious", "cve-", "version", "unattended", "firewall", "fail2ban", "auditd", "apparmor", "compiler"]):
        return "dependency"
    if any(w in text for w in ["telnet", "rlogin", "rsh", "ingreslock", "rmi", "network exposure"]):
        return "network"
    return "config"   # default: configuration files


def _extract_cwe(text: str) -> str:
    m = re.search(r'CWE-\d+', text)
    return m.group(0) if m else ""


def _extract_title(text: str, scenario_dir_name: str) -> str:
    m = re.match(r'^#\s+Scenario\s+\w+[:\s]+(.+)', text, re.MULTILINE)
    if m:
        return m.group(1).strip()
    m = re.match(r'^#\s+(.+)', text, re.MULTILINE)
    if m:
        return m.group(1).strip()
    return scenario_dir_name


def load_scenario(scenario_dir: Path, collection: str) -> "Scenario | None":
    dockerfile = scenario_dir / "Dockerfile"
    threat_md = scenario_dir / "threat.md"
    verify_sh = scenario_dir / "verify.sh"
    if not (dockerfile.exists() and threat_md.exists() and verify_sh.exists()):
        return None

    vuln_text = threat_md.read_text(encoding="utf-8", errors="replace")
    dir_num = scenario_dir.name.split("-")[-1].zfill(2)
    scenario_id = f"{collection}-{dir_num}"
    title = _extract_title(vuln_text, scenario_dir.name)
    base_image = "ubuntu:25.10" if collection == "ccdc" else "lpenz/ubuntu-hardy-amd64"

    return Scenario(
        id=scenario_id,
        collection=collection,
        category=_infer_category(vuln_text, title),
        title=title,
        cwe=_extract_cwe(vuln_text),
        dockerfile_path=dockerfile,
        threat_md_path=threat_md,
        verify_sh_path=verify_sh,
        vuln_description=vuln_text,
        base_image=base_image,
    )


def load_all_scenarios(bench_root: Path) -> list:
    scenarios = []
    for collection in ["ccdc", "meta2"]:
        coll_dir = bench_root / collection
        if not coll_dir.exists():
            continue
        for scenario_dir in sorted(coll_dir.iterdir()):
            if scenario_dir.is_dir() and scenario_dir.name.startswith("scenario-"):
                s = load_scenario(scenario_dir, collection)
                if s:
                    scenarios.append(s)
    return scenarios


def load_scenarios(
    bench_root: Path,
    collection: str | None = None,
    ids: list | None = None,
    categories: list | None = None,
) -> list:
    all_s = load_all_scenarios(bench_root)
    if collection:
        all_s = [s for s in all_s if s.collection == collection]
    if ids:
        all_s = [s for s in all_s if s.id in ids]
    if categories:
        all_s = [s for s in all_s if s.category in categories]
    return all_s
