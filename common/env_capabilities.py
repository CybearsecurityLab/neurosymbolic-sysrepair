"""Per-scenario environment-capability probing + PDDL fact emission.

This module is the defensible-PDDL answer to "actions in the domain reference
tools that aren't present in this scenario's container". Instead of pruning
the domain (which throws away potentially-useful knowledge), we:

  1. **Probe** the scenario container for a fixed set of capabilities.
  2. Emit each as a 0-arity PDDL predicate (e.g. ``(systemd_init_present)``).
  3. **Enrich** every action whose bash template needs a given tool with a
     matching ``(<tool>_available)`` precondition.
  4. Set those predicates in the problem :init based on what was probed.

The planner then naturally skips actions whose preconditions are unmet — no
discrepancies are logged for infeasible actions during Phase 3 walks, EW
rises. No pruning, no special-cased blacklists.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Callable

logger = logging.getLogger("EnvCapabilities")


# ---------------------------------------------------------------------------
# Capability schema.
#
# Each entry:
#   key               unique identifier
#   predicate         PDDL predicate name to emit (0-arity)
#   commands          list of bash commands whose presence -> this capability
#   probe             bash one-liner that exits 0 iff capability is present
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Capability:
    key: str
    predicate: str
    probe: str
    # bash commands considered to "require" this capability when present as
    # the primary command of an action's command_template.
    commands: tuple[str, ...]


# All probes are read-only, fast, and exit 0/1 (never write state).
CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        key="systemd_init",
        predicate="systemd_init_present",
        probe="test \"$(readlink /proc/1/exe 2>/dev/null)\" = /usr/lib/systemd/systemd "
              "|| test \"$(readlink /proc/1/exe 2>/dev/null)\" = /lib/systemd/systemd",
        commands=("systemctl", "journalctl", "loginctl", "machinectl",
                  "hostnamectl", "timedatectl", "localectl", "busctl"),
    ),
    Capability(
        key="iptables", predicate="iptables_available",
        probe="command -v iptables >/dev/null 2>&1",
        commands=("iptables", "ip6tables"),
    ),
    Capability(
        key="nftables", predicate="nftables_available",
        probe="command -v nft >/dev/null 2>&1",
        commands=("nft",),
    ),
    Capability(
        key="ufw", predicate="ufw_available",
        probe="command -v ufw >/dev/null 2>&1",
        commands=("ufw",),
    ),
    Capability(
        key="firewalld", predicate="firewalld_available",
        probe="command -v firewall-cmd >/dev/null 2>&1",
        commands=("firewall-cmd",),
    ),
    Capability(
        key="netplan", predicate="netplan_available",
        probe="command -v netplan >/dev/null 2>&1",
        commands=("netplan",),
    ),
    Capability(
        key="sudo", predicate="sudo_available",
        probe="command -v sudo >/dev/null 2>&1",
        commands=("sudo",),
    ),
    Capability(
        key="apt", predicate="apt_available",
        probe="command -v apt-get >/dev/null 2>&1",
        commands=("apt", "apt-get", "apt-cache", "apt-mark", "apt-key"),
    ),
    Capability(
        key="dpkg", predicate="dpkg_available",
        probe="command -v dpkg >/dev/null 2>&1",
        commands=("dpkg", "dpkg-query", "dpkg-deb", "dpkg-reconfigure"),
    ),
    Capability(
        key="snap", predicate="snap_available",
        probe="command -v snap >/dev/null 2>&1",
        commands=("snap",),
    ),
    Capability(
        key="auditd", predicate="auditd_available",
        probe="command -v auditctl >/dev/null 2>&1",
        commands=("auditctl", "auditd", "auditspd-plugin"),
    ),
    Capability(
        key="fail2ban", predicate="fail2ban_available",
        probe="command -v fail2ban-client >/dev/null 2>&1",
        commands=("fail2ban-client", "fail2ban-server"),
    ),
    Capability(
        key="apparmor", predicate="apparmor_available",
        probe="command -v aa-status >/dev/null 2>&1",
        commands=("aa-status", "aa-enforce", "aa-complain", "aa-disable", "apparmor_parser"),
    ),
    Capability(
        key="selinux", predicate="selinux_available",
        probe="command -v setenforce >/dev/null 2>&1 && command -v getenforce >/dev/null 2>&1",
        commands=("setenforce", "getenforce", "semanage", "restorecon", "chcon"),
    ),
    Capability(
        key="docker", predicate="docker_available",
        probe="command -v docker >/dev/null 2>&1",
        commands=("docker",),
    ),
    Capability(
        key="container_safe_reboot",
        predicate="reboot_allowed",
        # We never want to actually let an action try to reboot the
        # container — refusal is intentional and the predicate stays false.
        probe="false",
        commands=("reboot", "shutdown", "halt", "poweroff", "init", "telinit"),
    ),
    Capability(
        # NetworkManager / D-Bus — `nmcli` exits with "Could not create
        # NMClient" in stripped containers. Common EW discrepancy class.
        key="network_manager", predicate="nm_available",
        probe="nmcli general status >/dev/null 2>&1",
        commands=("nmcli",),
    ),
    Capability(
        # Kernel-module manipulation needs /lib/modules + write access;
        # absent in most scenario containers.
        key="kernel_modules", predicate="kmod_available",
        probe="test -d /lib/modules/\"$(uname -r)\" && command -v modprobe >/dev/null 2>&1",
        commands=("modprobe", "insmod", "rmmod", "depmod"),
    ),
    Capability(
        # systemd-resolved / systemd-networkd helpers — depend on the
        # respective daemons being live, which is rare in test containers.
        key="systemd_resolved", predicate="resolved_available",
        probe="resolvectl status >/dev/null 2>&1",
        commands=("resolvectl",),
    ),
    Capability(
        key="systemd_networkd", predicate="networkd_available",
        probe="networkctl status >/dev/null 2>&1",
        commands=("networkctl",),
    ),
    Capability(
        # WireGuard userspace
        key="wireguard", predicate="wg_available",
        probe="command -v wg >/dev/null 2>&1",
        commands=("wg", "wg-quick"),
    ),
    Capability(
        # tc / traffic control needs CAP_NET_ADMIN + qdiscs; not on by
        # default in scenario containers.
        key="traffic_control", predicate="tc_available",
        probe="command -v tc >/dev/null 2>&1 && tc qdisc show >/dev/null 2>&1",
        commands=("tc",),
    ),
)


def command_to_capability() -> dict[str, str]:
    """Reverse index: primary bash command -> capability key."""
    idx: dict[str, str] = {}
    for cap in CAPABILITIES:
        for cmd in cap.commands:
            idx[cmd.lower()] = cap.key
    return idx


def capability_to_predicate() -> dict[str, str]:
    return {cap.key: cap.predicate for cap in CAPABILITIES}


# ---------------------------------------------------------------------------
# Probe + emit
# ---------------------------------------------------------------------------

def probe_capabilities(shell_run: Callable[[str], int]) -> dict[str, bool]:
    """Run every probe via ``shell_run(bash_cmd) -> exit_code`` and return
    ``{capability_key: bool}``.

    ``shell_run`` is a function the caller supplies that executes a bash
    one-liner in the scenario container and returns its exit code.
    """
    out: dict[str, bool] = {}
    for cap in CAPABILITIES:
        try:
            code = shell_run(cap.probe)
        except Exception as e:
            logger.warning(f"probe failed for {cap.key}: {e}")
            code = 1
        out[cap.key] = (code == 0)
    return out


def init_facts(capabilities: dict[str, bool]) -> list[str]:
    """Format the probe results as PDDL (:init ...) facts.

    Only emits the positive facts (PDDL closed-world assumption: anything
    not in :init is false).
    """
    facts: list[str] = []
    for cap in CAPABILITIES:
        if capabilities.get(cap.key):
            facts.append(f"({cap.predicate})")
    return facts
