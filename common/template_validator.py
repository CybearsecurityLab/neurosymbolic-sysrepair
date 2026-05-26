"""Static quality gate for Phase-2 emitted action schemas.

Phase 2 merges Phase 1's mined operators with the LLM-synthesised
operators. Across ~1000 actions, the LLM-synthesised half has three
recurring defect classes that show up dominantly in the EW
discrepancy log:

1. **Empty command_template** — the LLM produced a (:action ...) block
   but no bash mapping. Phase 3 concretizes such an action at EW time
   via a *different* LLM call, which routinely invents wrong primary
   commands (``output_format``, ``delay_interval``).

2. **Hallucinated primary command** — template's first token is not a
   real Linux binary (`output_format file.txt`, `delay_interval 30`).
   This usually means the LLM treated a PDDL parameter name as if it
   were a bash command.

3. **Invalid flag combinations for a real binary** — `useradd -F`
   (no -F flag), `useradd -U -g` (contradictory), `apt-get install
   --depends` (no such option). The binary exists; the command just
   can't run.

Each of these makes the action infeasible to evaluate — EW will sample
it, the bash will exit nonzero, and a discrepancy will be logged.
Worse, the refiner can't fix them within its per-iter LLM budget
because there are hundreds and each requires bespoke template surgery.

The defensible PDDL response is to **drop the schema at the Phase 2 /
Phase 3 boundary**, with a logged justification. This is not pruning
for a benchmark; it's enforcing a well-formedness contract on the
auto-emitted domain — analogous to type checking before runtime.

The validator runs *after* canonical-action injection, capability
enrichment, and precondition synthesis, so the canonical operators
the rest of the pipeline relies on are never affected.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

logger = logging.getLogger("TemplateValidator")


# ---------------------------------------------------------------------------
# Known-binary allowlist.
#
# A "real" Linux binary that one would reasonably find on a sysadmin
# system. The list is intentionally broad — we want to reject only the
# obvious hallucinations (PDDL parameter names treated as commands),
# not legitimate utilities we happen to omit. Sourced from coreutils,
# util-linux, common sysadmin packages, and the capability table.
# ---------------------------------------------------------------------------

KNOWN_BINARIES: frozenset[str] = frozenset({
    # coreutils
    "true", "false", "echo", "printf", "cat", "tac", "head", "tail",
    "ls", "stat", "wc", "cut", "paste", "sort", "uniq", "tee", "split",
    "tr", "rev", "fmt", "fold", "pr", "csplit", "expand", "unexpand",
    "od", "base64", "base32", "basename", "dirname", "realpath",
    "readlink", "touch", "cp", "mv", "rm", "rmdir", "mkdir", "mkfifo",
    "mknod", "link", "ln", "unlink", "chmod", "chown", "chgrp",
    "chcon", "id", "groups", "whoami", "logname", "users", "who",
    "tty", "uname", "hostname", "hostid", "uptime", "date", "df",
    "du", "sync", "shred", "truncate", "test", "expr", "factor",
    "seq", "yes", "nohup", "timeout", "nice", "env", "kill", "sleep",
    "pwd", "pushd", "popd", "dirs", "type", "command", "which", "find",
    "xargs", "grep", "egrep", "fgrep", "sed", "awk", "perl", "python3",
    "diff", "patch", "cmp", "comm", "join", "tr", "less", "more",
    "vi", "nano", "tar", "gzip", "gunzip", "bzip2", "bunzip2", "xz",
    "unxz", "zip", "unzip",

    # util-linux
    "blkid", "lsblk", "findmnt", "mount", "umount", "mountpoint",
    "swapon", "swapoff", "fsck", "fdisk", "sfdisk", "partprobe",
    "wipefs", "fallocate", "fstrim", "setterm", "stty", "clear",
    "reset", "agetty", "login", "lscpu", "lsmem", "lsipc", "lsns",
    "lsof", "lsusb", "lspci", "lshw", "dmidecode", "ipcs", "ipcrm",
    "renice", "ionice", "taskset", "chrt", "uuidgen", "rev", "col",
    "colrm", "column", "look", "rename", "rename.ul", "script",
    "scriptreplay", "flock", "logger", "su", "newgrp", "chsh", "chfn",
    "passwd", "gpasswd", "useradd", "userdel", "usermod", "groupadd",
    "groupdel", "groupmod", "newusers", "chpasswd", "vipw", "vigr",
    "pwconv", "pwunconv", "grpconv", "grpunconv", "pwck", "grpck",
    "chage", "lastlog", "faillog", "last", "lastb",

    # process / signals
    "ps", "top", "htop", "pgrep", "pkill", "pidof", "killall", "jobs",
    "fg", "bg", "wait", "trap", "exec", "set", "unset",

    # net
    "ip", "ifconfig", "iwconfig", "iwlist", "iw", "route", "arp",
    "netstat", "ss", "tcpdump", "ngrep", "nmap", "ping", "ping6",
    "traceroute", "traceroute6", "mtr", "dig", "nslookup", "host",
    "getent", "resolvectl", "resolvconf", "ethtool", "mii-tool",
    "iptables", "ip6tables", "iptables-save", "iptables-restore",
    "ip6tables-save", "ip6tables-restore", "nft", "ufw", "firewall-cmd",
    "fwupd", "nmcli", "nmtui", "networkctl", "wg", "wg-quick",
    "wpa_cli", "wpa_supplicant", "openvpn", "ssh", "scp", "sftp",
    "rsync", "curl", "wget", "ftp",

    # auth / sec
    "sudo", "su", "doas", "auditctl", "auditd", "ausearch", "aureport",
    "setfacl", "getfacl", "setfattr", "getfattr", "lsattr", "chattr",
    "selinuxenabled", "setenforce", "getenforce", "sestatus", "semanage",
    "restorecon", "chcon", "audit2allow", "audit2why", "sealert",
    "aa-status", "aa-enforce", "aa-complain", "aa-disable", "apparmor_parser",
    "fail2ban-client", "fail2ban-server",

    # systemd
    "systemctl", "journalctl", "loginctl", "machinectl", "hostnamectl",
    "timedatectl", "localectl", "busctl", "systemd-analyze", "systemd-cat",
    "systemd-detect-virt", "systemd-resolve", "systemd-run", "systemd-tmpfiles",
    "service", "update-rc.d", "chkconfig",

    # pkg
    "apt", "apt-get", "apt-cache", "apt-mark", "apt-key", "aptitude",
    "dpkg", "dpkg-query", "dpkg-deb", "dpkg-reconfigure", "dpkg-divert",
    "dpkg-trigger", "snap", "yum", "dnf", "rpm", "zypper", "pacman",

    # misc admin
    "crontab", "atd", "at", "atq", "atrm", "batch", "anacron",
    "tzselect", "tzdata", "dpkg-reconfigure", "update-alternatives",
    "ldconfig", "ldd", "strace", "ltrace", "lsmod", "modprobe",
    "modinfo", "rmmod", "insmod", "depmod", "lsblk", "fdisk", "parted",
    "mkfs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs", "mkfs.vfat",
    "mkswap", "tune2fs", "e2fsck", "resize2fs", "xfs_growfs",
    "dd", "shred", "smartctl", "hdparm", "blockdev",
    "loadkeys", "kbd_mode", "consolechars", "setfont",
    "openssl", "gpg", "gpg2", "gpgv", "ssh-keygen", "ssh-keyscan",
    "ssh-add", "ssh-agent", "sshd",
    "sysctl", "loadavg", "iostat", "vmstat", "mpstat", "free",
    "iotop", "atop",
    "logrotate", "rsyslogd", "syslog-ng",
    "reboot", "shutdown", "halt", "poweroff", "init", "telinit",
    "mesg", "wall", "write", "talk", "lpr", "lprm", "lpq", "lpstat",
    "lpadmin", "cupsenable", "cupsdisable", "accept", "reject",
    "netplan", "cloud-init",

    # docker / k8s / containers
    "docker", "podman", "ctr", "runc", "containerd", "buildah", "skopeo",
    "kubectl", "helm", "kubeadm", "minikube",

    # shells
    "bash", "sh", "dash", "zsh", "ksh", "csh", "tcsh", "fish",
})

# Aliases / paths to normalise primary-command lookups.
_BIN_ALIASES = {
    "/bin/true": "true",
    "/usr/bin/true": "true",
    "/bin/false": "false",
    "/usr/bin/false": "false",
}

# ---------------------------------------------------------------------------
# Per-binary invalid-flag patterns. Conservative — only known
# hallucinations seen in the EW discrepancy log.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FlagRule:
    """If `template` matches `pattern`, reject."""
    binary: str
    pattern: re.Pattern
    reason: str


_FLAG_RULES: tuple[FlagRule, ...] = (
    # useradd -F is not a flag (-F doesn't exist on shadow useradd)
    FlagRule(
        binary="useradd",
        pattern=re.compile(r"\buseradd\b[^|;&]*\s-F\b"),
        reason="useradd has no -F flag",
    ),
    # useradd -U creates a group with the user's name; combined with
    # -g (specify group) it's contradictory and shadow rejects.
    FlagRule(
        binary="useradd",
        pattern=re.compile(r"\buseradd\b[^|;&]*\s-U\b[^|;&]*\s-g\b"),
        reason="useradd -U and -g are mutually exclusive",
    ),
    FlagRule(
        binary="useradd",
        pattern=re.compile(r"\buseradd\b[^|;&]*\s-g\b[^|;&]*\s-U\b"),
        reason="useradd -U and -g are mutually exclusive",
    ),
    # useradd -D (defaults mode) takes no LOGIN; if the template also
    # has a parameter placeholder it will fail with "Usage: useradd...".
    # Order-independent: -D and the placeholder may appear on either side.
    FlagRule(
        binary="useradd",
        pattern=re.compile(r"\buseradd\b(?:[^|;&]*\s-D\b[^|;&]*\{[A-Za-z_]\w*\}|[^|;&]*\{[A-Za-z_]\w*\}[^|;&]*\s-D\b)"),
        reason="useradd -D forbids any LOGIN/argument",
    ),
    # apt-get install --depends is not a flag
    FlagRule(
        binary="apt-get",
        pattern=re.compile(r"\bapt-get\b[^|;&]*\binstall\b[^|;&]*--depends\b"),
        reason="apt-get install has no --depends flag",
    ),
    # apt-get satisfy "" — empty dependency expression
    FlagRule(
        binary="apt-get",
        pattern=re.compile(r'\bapt-get\b[^|;&]*\bsatisfy\b\s*""'),
        reason='apt-get satisfy with empty argument',
    ),
    # dpkg -i with no argument (deb path) — would always error
    FlagRule(
        binary="dpkg",
        pattern=re.compile(r"\bdpkg\b\s+-i\s*$"),
        reason="dpkg -i requires a .deb path argument",
    ),
    # apt-get install --conflicts / --breaks / --recommends as if they
    # were package selectors. These are unknown to apt-get and exit 100.
    FlagRule(
        binary="apt-get",
        pattern=re.compile(r"\bapt-get\b[^|;&]*\binstall\b[^|;&]*--(?:conflicts|breaks|recommends-only|enhances|suggests|provides|replaces|pre-depends|conflicts-only)\b"),
        reason="apt-get install does not accept that dependency-class flag",
    ),
    # apt-get source / fetch (network IO) — accept syntactically but
    # mark — no syntactic rule here.
    # passwd -d / passwd -l / passwd -u on a critical account — these
    # are gated by precondition_synthesis (`not user_critical`); no
    # template-level pattern here.
)


# ---------------------------------------------------------------------------
# Template inspection
# ---------------------------------------------------------------------------

_PREFIX_TOKENS = {"sudo", "env", "timeout", "nohup", "exec", "bash", "/bin/bash"}


def _primary_command(template: str) -> str | None:
    """Return the lowercase first non-prefix token of a bash template."""
    if not template:
        return None
    tokens = template.strip().split()
    i = 0
    while i < len(tokens) and "=" in tokens[i] and not tokens[i].startswith("/"):
        i += 1
    while i < len(tokens) and tokens[i].lower() in _PREFIX_TOKENS:
        i += 1
    if i >= len(tokens):
        return None
    cmd = tokens[i]
    cmd = _BIN_ALIASES.get(cmd, cmd).lower()
    return cmd.rsplit("/", 1)[-1] if "/" in cmd else cmd


# ---------------------------------------------------------------------------
# Domain rewrite
# ---------------------------------------------------------------------------

_ACTION_HEAD = re.compile(r"\(:action\s+([A-Za-z_][\w-]*)\b")


def _balanced_block(text: str, start: int) -> tuple[int, int] | None:
    if text[start] != "(":
        return None
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return (start, i)
    return None


@dataclass
class ValidationReport:
    actions_total: int = 0
    actions_kept: int = 0
    actions_dropped: int = 0
    drops_by_reason: dict[str, int] = field(default_factory=dict)
    dropped_names: list[tuple[str, str]] = field(default_factory=list)  # (name, reason)


_VAR_RE = re.compile(r"\?[A-Za-z_][\w-]*")
_PARAMS_RE = re.compile(r":parameters\s*\(([^)]*)\)", re.DOTALL)
_PRECOND_RE = re.compile(r":precondition\b", re.MULTILINE)
_EFFECT_RE = re.compile(r":effect\b", re.MULTILINE)
_PREDICATES_BLOCK_RE = re.compile(
    r"\(:predicates\b([\s\S]*?)\)\s*(?=\(:functions|\(:constants|\(:action|\)\s*\Z)"
)


def _predicate_arities(domain_text: str) -> dict[str, int]:
    """Extract {predicate_name: declared_arity} from (:predicates ...)."""
    m = _PREDICATES_BLOCK_RE.search(domain_text)
    if not m:
        return {}
    body = m.group(1)
    # Each predicate is `(name ?p1 - t1 ?p2 - t2 ...)`.
    out: dict[str, int] = {}
    depth = 0
    start = -1
    for i, ch in enumerate(body):
        if ch == "(":
            if depth == 0:
                start = i
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0 and start >= 0:
                inner = body[start + 1:i]
                tokens = inner.split()
                if tokens:
                    name = tokens[0]
                    # Count '?vars' as the arity.
                    arity = sum(1 for t in tokens if t.startswith("?"))
                    out[name] = arity
                start = -1
    return out


_ATOM_RE = re.compile(r"\(([A-Za-z_][\w-]*)((?:\s+[^()\s]+)*)\s*\)")


def _arity_mismatches(action_block: str, arities: dict[str, int]) -> list[str]:
    """Return list of `predicate_name(used_arity/declared_arity)` strings
    for every predicate occurrence in :precondition or :effect that does
    not match its declared arity. PDDL keywords (and, or, not, …) are
    skipped.

    Fast Downward's translator rejects domains where a predicate is
    used with a different arity than declared. We catch this at the
    Phase 2 boundary so the planner never sees it.
    """
    pddl_keywords = {"and", "or", "not", "when", "forall", "exists",
                     "imply", "increase", "decrease", "assign", "=", "+", "-"}
    mismatches: list[str] = []
    for head_re in (_PRECOND_RE, _EFFECT_RE):
        m = head_re.search(action_block)
        if not m:
            continue
        idx = m.end()
        while idx < len(action_block) and action_block[idx].isspace():
            idx += 1
        if idx >= len(action_block) or action_block[idx] != "(":
            continue
        depth = 0
        start = idx
        section_end = len(action_block)
        for j in range(idx, len(action_block)):
            ch = action_block[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    section_end = j + 1
                    break
        section = action_block[start:section_end]
        for atom in _ATOM_RE.finditer(section):
            pred = atom.group(1)
            if pred in pddl_keywords:
                continue
            if pred not in arities:
                continue  # not declared; covered by other checks (unknown predicate)
            # Count args = whitespace-separated non-empty tokens after the name.
            args_str = atom.group(2).strip()
            used_arity = len(args_str.split()) if args_str else 0
            if used_arity != arities[pred]:
                mismatches.append(f"{pred}({used_arity}/{arities[pred]})")
    return mismatches


def _undeclared_variables(action_block: str) -> set[str]:
    """Return the set of ``?vars`` referenced in :precondition or :effect
    that are NOT declared in :parameters.

    Fast Downward's strict PDDL translator rejects any action with an
    undeclared variable; the pddl-library loader does *not*, so a domain
    can pass the Phase 2 / Phase 3 validation gate and then crash the
    planner at runtime. We add this check at the Phase 2 boundary so
    Phase 3 EW and the neurosymbolic planner downstream get a clean
    domain.
    """
    pm = _PARAMS_RE.search(action_block)
    declared = set(_VAR_RE.findall(pm.group(1))) if pm else set()
    # Find :precondition / :effect segments by walking balanced parens.
    used: set[str] = set()
    for head_re in (_PRECOND_RE, _EFFECT_RE):
        m = head_re.search(action_block)
        if not m:
            continue
        # Skip whitespace to the opening paren after the keyword.
        idx = m.end()
        while idx < len(action_block) and action_block[idx].isspace():
            idx += 1
        if idx >= len(action_block) or action_block[idx] != "(":
            continue
        depth = 0
        start = idx
        for j in range(idx, len(action_block)):
            ch = action_block[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    used.update(_VAR_RE.findall(action_block[start:j + 1]))
                    break
    return used - declared


def _classify(
    action_name: str,
    template: str,
    action_block: str | None,
    canonical_names: frozenset[str],
    arities: dict[str, int] | None = None,
) -> str | None:
    """Return a drop-reason string if the action fails the gate, else None."""
    if action_name in canonical_names:
        return None  # never drop canonical operators

    # 1) Structural: undeclared variables in precondition/effect — these
    # crash Fast Downward's strict translator (the pddl-library loader
    # is permissive about this). Catch them here.
    if action_block:
        undecl = _undeclared_variables(action_block)
        if undecl:
            return f"undeclared_variable:{','.join(sorted(undecl))}"
        # 2) Structural: predicate arity mismatch.
        if arities:
            mm = _arity_mismatches(action_block, arities)
            if mm:
                return f"arity_mismatch:{','.join(sorted(set(mm)))}"

    primary = _primary_command(template)

    if not template or not primary:
        return "empty_template"

    if primary not in KNOWN_BINARIES:
        return f"unknown_primary_command:{primary}"

    for rule in _FLAG_RULES:
        if rule.binary == primary and rule.pattern.search(template):
            return f"invalid_flag_combo:{rule.reason}"

    return None


def validate_and_filter_domain(
    domain_path: Path | str,
    action_templates: dict[str, str],
    canonical_names: Iterable[str] | None = None,
    backup_suffix: str = ".pre-validation.pddl",
) -> ValidationReport:
    """Drop actions whose bash template fails the well-formedness gate.

    ``action_templates`` is the union of every template we can find for
    each action (Phase 1 mined, Phase 2 partial domains, concretizer
    cache). ``canonical_names`` is the set of action names injected by
    `common.canonical_actions` — those are *never* dropped, even if we
    can't find a template for them, because they're guaranteed correct
    by construction.
    """
    domain_path = Path(domain_path)
    if not domain_path.exists():
        raise FileNotFoundError(f"domain not found: {domain_path}")

    domain_path.with_suffix(backup_suffix).write_text(domain_path.read_text())
    text = domain_path.read_text()

    canonical = frozenset(canonical_names or ())
    arities = _predicate_arities(text)

    report = ValidationReport()

    out_parts: list[str] = []
    pos = 0
    for m in _ACTION_HEAD.finditer(text):
        report.actions_total += 1
        name = m.group(1)
        blk = _balanced_block(text, m.start())
        if not blk:
            continue
        start, end = blk

        out_parts.append(text[pos:start])

        template = action_templates.get(name, "")
        block_text = text[start:end + 1]
        reason = _classify(name, template, block_text, canonical, arities)

        if reason is None:
            out_parts.append(text[start:end + 1])
            report.actions_kept += 1
        else:
            report.actions_dropped += 1
            short_reason = reason.split(":", 1)[0]
            report.drops_by_reason[short_reason] = (
                report.drops_by_reason.get(short_reason, 0) + 1
            )
            report.dropped_names.append((name, reason))
            # Replace the dropped action with a brief inline comment so the
            # surrounding whitespace stays correct and the audit log is
            # discoverable on inspection.
            out_parts.append(f";; DROPPED action {name}: {reason}\n  ")

        pos = end + 1

    out_parts.append(text[pos:])
    new_text = "".join(out_parts)
    domain_path.write_text(new_text)

    logger.info(
        f"template validator: kept={report.actions_kept}, "
        f"dropped={report.actions_dropped}, drops_by_reason={report.drops_by_reason}"
    )
    return report


def collect_templates_for_validation(
    phase1_metadata: Path | str | None = None,
    partial_domains: Path | str | None = None,
    concretizer_cache: Path | str | None = None,
) -> dict[str, str]:
    """Union of action -> template from every DESIGN-TIME source.

    The concretizer cache is deliberately *not* consulted by the
    validator: cache entries are LLM-filled at EW runtime and have
    routinely contained pollution like ``usermod -c "format" user``
    (literal "user" instead of a placeholder) — pollution that we
    don't want to whitelist a hallucinated action through. Validation
    must reflect the design-time semantics of the schema; runtime
    auto-fills are not authoritative. The cache is still useful for
    enrichment / precondition synthesis (where we just want a hint
    of the primary command), and is consumed there.
    """
    out: dict[str, str] = {}

    def _set(name: str, template: str) -> None:
        if not name:
            return
        if name in out and out[name]:
            return  # keep first non-empty
        out[name] = template or out.get(name, "")

    if phase1_metadata:
        p = Path(phase1_metadata)
        if p.exists():
            try:
                for a in json.loads(p.read_text()).get("actions", []):
                    _set(a.get("name", ""),
                         a.get("command_template", "") or "")
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"could not read {p}: {e}")

    if partial_domains:
        p = Path(partial_domains)
        if p.exists():
            try:
                workers = json.loads(p.read_text())
                if isinstance(workers, list):
                    for w in workers:
                        for a in w.get("actions", []) or []:
                            _set(a.get("name", ""),
                                 a.get("command_template", "") or "")
            except (OSError, json.JSONDecodeError) as e:
                logger.warning(f"could not read {p}: {e}")

    # Intentionally ignore concretizer_cache for validation purposes
    # (see docstring). Accept the unused kwarg to keep the signature
    # stable for callers that pass it explicitly.
    _ = concretizer_cache
    return out
