"""
phase1/common/config.py

Configuration constants, schema mappings, and scoping criteria.
Updated to use shared common modules.
"""

import os
import sys

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from common.models import OSQueryMapping
from common.predicates import get_base_predicates as _get_base_predicates


# =============================================================================
# Global Configuration
# =============================================================================

LLM_MAX_CONTEXT_CHARS = 30000

# Critical paths to scan for file system objects
CRITICAL_FILE_PATHS = [
    "/etc",
    "/var/log",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
]


# =============================================================================
# OSQuery Schema Mappings
# =============================================================================

OSQUERY_MAPPINGS = [
    OSQueryMapping(
        table="deb_packages",
        query="SELECT name, version, arch, status FROM deb_packages",
        pddl_type="package",
        predicate_name="package_installed",
        name_column="name",
        additional_columns=["version", "arch"],
    ),
    OSQueryMapping(
        table="systemd_units",
        query="""SELECT id,
                        active_state,
                        sub_state,
                        load_state,
                        fragment_path
                 FROM systemd_units
                 WHERE id LIKE '%.service'""",
        pddl_type="service",
        predicate_name="service_running",
        predicate_condition="active_state='active'",
        name_column="id",
        additional_columns=["active_state", "sub_state", "load_state", "fragment_path"],
    ),
    OSQueryMapping(
        table="users",
        query="SELECT username, uid, gid, directory, shell FROM users",
        pddl_type="user",
        predicate_name="user_exists",
        name_column="username",
        additional_columns=["uid", "gid", "directory"],
    ),
    OSQueryMapping(
        table="groups",
        query="SELECT groupname, gid FROM groups",
        pddl_type="group",
        predicate_name="group_exists",
        name_column="groupname",
        additional_columns=["gid"],
    ),
    OSQueryMapping(
        table="listening_ports",
        query="""SELECT port, protocol, address, pid, family
                 FROM listening_ports""",
        pddl_type="port",
        predicate_name="port_open",
        name_column="port",
        additional_columns=["protocol", "address", "pid"],
    ),
    OSQueryMapping(
        table="iptables",
        query="""SELECT filter_name,
                        chain,
                        policy,
                        target,
                        protocol,
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port
                 FROM iptables""",
        pddl_type="firewall_rule",
        predicate_name="firewall_rule_exists",
        name_column="chain",
        additional_columns=["policy", "target", "src_ip", "dst_ip"],
    ),
    OSQueryMapping(
        table="processes",
        query="SELECT pid, name, state, uid, cmdline FROM processes",
        pddl_type="process",
        predicate_name="process_running",
        predicate_condition="state='R' OR state='S'",
        name_column="name",
        additional_columns=["pid", "state", "uid"],
    ),
    OSQueryMapping(
        table="interface_addresses",
        query="""SELECT interface, address, type, mask
                 FROM interface_addresses
                 WHERE interface NOT LIKE 'lo%'""",
        pddl_type="interface",
        predicate_name="interface_exists",
        name_column="interface",
        additional_columns=["address", "type"],
    ),
]


# =============================================================================
# Scoping Heuristics
# =============================================================================


class AnchorCriteria:
    """
    Criteria for identifying anchor entities in the dependency graph.
    These are the 'roots' from which we trace dependencies to scope the PDDL domain.
    """

    SYSTEM_PORT_MAX = 1024
    EPHEMERAL_PORT_MIN = 32768
    SYSTEM_UID_MAX = 999
    HUMAN_UID_MIN = 1000
    ROOT_UID = 0
    ACTIVE_STATES = {"active", "activating", "reloading"}

    KERNEL_THREAD_PATTERNS = [
        "[",
        "kworker",
        "ksoftirqd",
        "migration",
        "rcu_",
        "watchdog",
        "cpuhp",
        "idle_inject",
    ]

    @classmethod
    def is_anchor_port(cls, port_data: dict) -> tuple[bool, str]:
        """Identify if a port is significant."""
        port_num = int(port_data.get("port", 0))
        protocol = port_data.get("protocol", "tcp")

        if port_num <= cls.SYSTEM_PORT_MAX:
            return True, f"system_port_{protocol}_{port_num}"
        if port_num < cls.EPHEMERAL_PORT_MIN:
            return True, f"listening_port_{protocol}_{port_num}"
        return False, ""

    @classmethod
    def is_anchor_user(cls, user_data: dict) -> tuple[bool, str]:
        """Identify if a user is significant."""
        uid = int(user_data.get("uid", -1))
        username = user_data.get("username", "")

        if uid == cls.ROOT_UID:
            return True, "root_user"
        if uid >= cls.HUMAN_UID_MIN:
            return True, f"human_user_{username}"
        return False, ""

    @classmethod
    def is_anchor_service(cls, service_data: dict) -> tuple[bool, str]:
        """Identify if a service is significant."""
        active_state = service_data.get("active_state", "")

        if active_state in cls.ACTIVE_STATES:
            return True, "active_service"
        return False, ""

    @classmethod
    def is_kernel_thread(cls, process_data: dict) -> bool:
        """Check if a process is a kernel thread."""
        name = process_data.get("name", "")
        if name.startswith("[") and name.endswith("]"):
            return True
        return any(name.startswith(p) for p in cls.KERNEL_THREAD_PATTERNS)


def get_base_predicates() -> list[str]:
    """
    Get list of base predicates from the shared common module.
    This is the canonical source for predicate vocabulary.
    """
    return _get_base_predicates()
