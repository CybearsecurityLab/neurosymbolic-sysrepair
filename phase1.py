"""
Phase 1: System Introspection Module (The "Map" Phase)
Automated Neurosymbolic Domain Formalization for Ubuntu 25.10

This module extracts system state via osquery and mines actions from man pages
to generate a grounded PDDL domain.
"""

import json
import re
import subprocess
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Iterator, TextIO, Any

_log_stream: Any = sys.stdout

def log(msg: str):
    """Print to log stream (stdout or stderr depending on output mode)."""
    print(msg, file=_log_stream)


def set_log_stream(stream: TextIO):
    """Set the output stream for progress messages."""
    global _log_stream
    _log_stream = stream


# =============================================================================
# SECTION 1: Data Models & Configuration
# =============================================================================
class PDDLType(Enum):
    """Base PDDL types mapped from OS concepts."""
    PACKAGE = "package"
    SERVICE = "service"
    USER = "user"
    GROUP = "group"
    FILE = "file"
    DIRECTORY = "directory"
    CONFIG_FILE = "configuration_file"
    PORT = "port"
    INTERFACE = "interface"
    FIREWALL_RULE = "firewall_rule"
    PROCESS = "process"


class PDDLValidator:
    """
    Validates generated PDDL using VAL (PDDL validator).
    https://github.com/KCL-Planning/VAL
    """

    def __init__(self, val_path: str = "Validate"):
        self.val_path = val_path
        self._available = self._check_available()

    def _check_available(self) -> bool:
        """Check if VAL validator is installed."""
        try:
            result = subprocess.run(
                [self.val_path, "-h"],
                capture_output=True, timeout=5
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def is_available(self) -> bool:
        return self._available

    def validate_domain(self, domain_pddl: str) -> tuple[bool, str]:
        """Validate domain syntax."""
        if not self._available:
            return True, "Validator not available - skipping"

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pddl', delete=False) as f:
            f.write(domain_pddl)
            domain_file = f.name

        try:
            result = subprocess.run(
                [self.val_path, "-v", domain_file],
                capture_output=True, text=True, timeout=30
            )
            success = result.returncode == 0
            return success, result.stdout + result.stderr
        finally:
            import os
            os.unlink(domain_file)

    def validate_problem(self, domain_pddl: str, problem_pddl: str) -> tuple[bool, str]:
        """Validate problem against domain."""
        if not self._available:
            return True, "Validator not available - skipping"

        import tempfile
        import os

        with tempfile.NamedTemporaryFile(mode='w', suffix='.pddl', delete=False) as f:
            f.write(domain_pddl)
            domain_file = f.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.pddl', delete=False) as f:
            f.write(problem_pddl)
            problem_file = f.name

        try:
            result = subprocess.run(
                [self.val_path, domain_file, problem_file],
                capture_output=True, text=True, timeout=30
            )
            success = result.returncode == 0
            return success, result.stdout + result.stderr
        finally:
            os.unlink(domain_file)
            os.unlink(problem_file)


@dataclass
class OSQueryMapping:
    """Configuration for mapping osquery tables to PDDL constructs."""
    table: str
    query: str
    pddl_type: PDDLType
    predicate_name: str
    predicate_condition: Optional[str] = None  # Column condition for predicate truth
    name_column: str = "name"
    additional_columns: list = field(default_factory=list)


@dataclass
class ExtractedObject:
    """Represents an extracted system object."""
    pddl_type: PDDLType
    name: str
    properties: dict = field(default_factory=dict)


@dataclass
class ExtractedPredicate:
    """Represents a grounded predicate from the system state."""
    name: str
    arguments: list
    value: bool = True


@dataclass
class ActionParameter:
    """Parameter for a PDDL action."""
    name: str
    pddl_type: PDDLType


@dataclass
class ActionSchema:
    """Extracted action schema from man pages."""
    name: str
    parameters: list
    preconditions: list
    effects: list
    command_template: str
    requires_root: bool = False
    source_utility: str = ""


# Schema mapping configuration (Section 4.1.1)
OSQUERY_MAPPINGS = [
    OSQueryMapping(
        table="deb_packages",
        query="SELECT name, version, arch, status FROM deb_packages",
        pddl_type=PDDLType.PACKAGE,
        predicate_name="package_installed",
        name_column="name",
        additional_columns=["version", "arch"]
    ),
    OSQueryMapping(
        table="systemd_units",
        query="""SELECT id, active_state, sub_state, load_state, 
                 fragment_path FROM systemd_units WHERE id LIKE '%.service'""",
        pddl_type=PDDLType.SERVICE,
        predicate_name="service_running",
        predicate_condition="active_state='active'",
        name_column="id",
        additional_columns=["active_state", "sub_state", "load_state", "fragment_path"]
    ),
    OSQueryMapping(
        table="users",
        query="SELECT username, uid, gid, directory, shell FROM users",
        pddl_type=PDDLType.USER,
        predicate_name="user_exists",
        name_column="username",
        additional_columns=["uid", "gid", "directory"]
    ),
    OSQueryMapping(
        table="groups",
        query="SELECT groupname, gid FROM groups",
        pddl_type=PDDLType.GROUP,
        predicate_name="group_exists",
        name_column="groupname",
        additional_columns=["gid"]
    ),
    OSQueryMapping(
        table="listening_ports",
        query="""SELECT port, protocol, address, pid, family 
                 FROM listening_ports""",
        pddl_type=PDDLType.PORT,
        predicate_name="port_open",
        name_column="port",
        additional_columns=["protocol", "address", "pid"]
    ),
    OSQueryMapping(
        table="iptables",
        query="""SELECT filter_name, chain, policy, target, protocol, 
                 src_ip, dst_ip, src_port, dst_port FROM iptables""",
        pddl_type=PDDLType.FIREWALL_RULE,
        predicate_name="firewall_rule_exists",
        name_column="chain",
        additional_columns=["policy", "target", "src_ip", "dst_ip"]
    ),
    OSQueryMapping(
        table="processes",
        query="SELECT pid, name, state, uid, cmdline FROM processes",
        pddl_type=PDDLType.PROCESS,
        predicate_name="process_running",
        predicate_condition="state='R' OR state='S'",
        name_column="name",
        additional_columns=["pid", "state", "uid"]
    ),
]

# Critical paths for file extraction
CRITICAL_FILE_PATHS = [
    "/etc",
    "/var/log",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
]


# =============================================================================
# SECTION 2: OSQuery Interface
# =============================================================================

class OSQueryInterface(ABC):
    """Abstract interface for osquery operations."""

    @abstractmethod
    def execute_query(self, sql: str) -> list[dict]:
        """Execute an SQL query and return results."""
        pass

    @abstractmethod
    def is_available(self) -> bool:
        """Check if osquery is available on the system."""
        pass


class OSQueryShellInterface(OSQueryInterface):
    """Interface using osqueryi shell (Section 4.1.2)."""

    def __init__(self, osqueryi_path: str = "osqueryi"):
        self.osqueryi_path = osqueryi_path
        self._check_availability()

    def _check_availability(self):
        """Verify osqueryi is installed and accessible."""
        try:
            result = subprocess.run(
                [self.osqueryi_path, "--version"],
                capture_output=True, text=True, timeout=10
            )
            self._available = result.returncode == 0
            if self._available:
                self.version = result.stdout.strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._available = False
            self.version = None

    def is_available(self) -> bool:
        return self._available

    def execute_query(self, sql: str) -> list[dict]:
        """Execute query via osqueryi with JSON output."""
        if not self._available:
            raise RuntimeError("osqueryi is not available")

        try:
            result = subprocess.run(
                [self.osqueryi_path, "--json", sql],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode != 0:
                raise RuntimeError(f"Query failed: {result.stderr}")

            return json.loads(result.stdout) if result.stdout.strip() else []
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse osquery JSON output: {e}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("Query timed out")


class OSQueryThriftInterface(OSQueryInterface):
    """
    Interface using osquery Thrift API (Section 4.1.2).
    Requires: pip install osquery==3.1.1

    The osquery library spawns an extension manager instance that communicates
    via Thrift, providing efficient query execution for multiple queries.
    """

    def __init__(self, socket_path: Optional[str] = None):
        """
        Initialize osquery Thrift interface.

        Args:
            socket_path: Optional path to osquery socket. If None, spawns
                        a new instance. Use for connecting to osqueryd.
        """
        self.instance = None
        self.client = None
        self._available = False
        self._socket_path = socket_path
        self._initialize()

    def _initialize(self):
        """Initialize osquery extension manager via Thrift API."""
        try:
            import osquery

            if self._socket_path:
                # Connect to existing osqueryd instance
                self.instance = osquery.ExtensionClient(self._socket_path)
                self.instance.open()
                self.client = self.instance.extension_client()
            else:
                # Spawn standalone instance (recommended for Phase 1)
                self.instance = osquery.SpawnInstance()
                self.instance.open()
                self.client = self.instance.client

            # Verify connection with the test query
            test_result = self.client.query("SELECT version() as v")
            if test_result.status.code == 0:
                self._available = True
                self._version = test_result.response[0].get("v", "unknown")
            else:
                raise RuntimeError(f"Connection test failed: {test_result.status.message}")

        except ImportError:
            raise RuntimeError(
                "osquery library not installed. Install with: pip install osquery==3.1.1"
            )
        except Exception as e:
            raise RuntimeError(f"Failed to initialize osquery Thrift API: {e}")

    @property
    def version(self) -> str:
        return getattr(self, '_version', 'unknown')

    def is_available(self) -> bool:
        return self._available

    def execute_query(self, sql: str) -> list[dict]:
        """
        Execute SQL query via Thrift API.

        Returns list of dicts, each dict representing a row.
        """
        if not self._available or not self.client:
            raise RuntimeError("osquery Thrift API not available")

        result = self.client.query(sql)

        if result.status.code != 0:
            raise RuntimeError(
                f"Query failed (code {result.status.code}): {result.status.message}"
            )

        # Convert ExtensionResponse to list of dicts
        return [dict(row) for row in result.response]

    def get_table_schema(self, table_name: str) -> list[dict]:
        """Get schema information for a table (useful for validation)."""
        return self.execute_query(f"PRAGMA table_info({table_name})")

    def batch_query(self, queries: list[str]) -> Iterator[tuple[str, list[dict]]]:
        """
        Execute multiple queries efficiently over single Thrift connection.

        Yields (query, results) tuples. More efficient than individual calls
        as it reuses the connection.
        """
        for sql in queries:
            try:
                yield sql, self.execute_query(sql)
            except RuntimeError as e:
                yield sql, []  # Return empty on error, log warning
                log(f"Warning: Query failed: {e}")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Clean up osquery instance."""
        if self.instance:
            try:
                self.instance.close()
            except Exception:
                pass
            self.instance = None
            self.client = None

    def __del__(self):
        self.close()


def get_osquery_interface(prefer_thrift: bool = True,
                          socket_path: Optional[str] = None) -> OSQueryInterface:
    """
    Factory function to get osquery interface.

    Args:
        prefer_thrift: If True, prefer Thrift API (osquery library 3.1.1).
                      Falls back to shell only if library unavailable.
        socket_path: Optional socket path for connecting to osqueryd.

    Returns:
        OSQueryInterface implementation

    Raises:
        RuntimeError if no interface is available
    """
    errors = []

    if prefer_thrift:
        try:
            thrift = OSQueryThriftInterface(socket_path=socket_path)
            if thrift.is_available():
                log(f"  Using osquery Thrift API v{thrift.version}")
                return thrift
        except RuntimeError as e:
            errors.append(f"Thrift API: {e}")

    # Fall back to shell interface
    try:
        shell = OSQueryShellInterface()
        if shell.is_available():
            log(f"  Using osqueryi shell (fallback): {shell.version}")
            return shell
    except Exception as e:
        errors.append(f"Shell interface: {e}")

    raise RuntimeError(
        "No osquery interface available.\n"
        f"Errors: {'; '.join(errors)}\n\n"
        "To install osquery library: pip install osquery==3.1.1\n"
        "To install osqueryi: https://osquery.io/downloads/"
    )


# =============================================================================
# SECTION 3: Dynamic Scope Analyzer (Graph-Based Reachability)
# =============================================================================
class EntityType(Enum):
    """Types of entities in the system dependency graph."""
    PORT = "port"
    PROCESS = "process"
    SERVICE = "service"
    PACKAGE = "package"
    USER = "user"
    GROUP = "group"
    CONFIG_FILE = "configuration_file"
    FILE = "file"
    FIREWALL_RULE = "firewall_rule"
    INTERFACE = "interface"


@dataclass
class GraphEntity:
    """A node in the dependency graph."""
    id: str
    entity_type: EntityType
    name: str
    original_data: dict = field(default_factory=dict)
    is_anchor: bool = False
    anchor_reason: str = ""
    reachable: bool = False
    depth: int = -1


class AnchorCriteria:
    """Criteria for identifying anchor entities."""

    SYSTEM_PORT_MAX = 1024
    EPHEMERAL_PORT_MIN = 32768
    SYSTEM_UID_MAX = 999
    HUMAN_UID_MIN = 1000
    ROOT_UID = 0
    ACTIVE_STATES = {"active", "activating", "reloading"}
    KERNEL_THREAD_PATTERNS = [
        "[", "kworker", "ksoftirqd", "migration", "rcu_",
        "watchdog", "cpuhp", "idle_inject"
    ]

    @classmethod
    def is_anchor_port(cls, port_data: dict) -> tuple[bool, str]:
        port_num = int(port_data.get("port", 0))
        protocol = port_data.get("protocol", "tcp")

        if port_num <= cls.SYSTEM_PORT_MAX:
            return True, f"system_port_{protocol}_{port_num}"
        if port_num < cls.EPHEMERAL_PORT_MIN:
            return True, f"listening_port_{protocol}_{port_num}"
        return False, ""

    @classmethod
    def is_anchor_user(cls, user_data: dict) -> tuple[bool, str]:
        uid = int(user_data.get("uid", -1))
        username = user_data.get("username", "")

        if uid == cls.ROOT_UID:
            return True, "root_user"
        if uid >= cls.HUMAN_UID_MIN:
            return True, f"human_user_{username}"
        return False, ""

    @classmethod
    def is_anchor_service(cls, service_data: dict) -> tuple[bool, str]:
        active_state = service_data.get("active_state", "")
        service_id = service_data.get("id", "")

        if active_state in cls.ACTIVE_STATES:
            return True, f"active_service"
        return False, ""

    @classmethod
    def is_kernel_thread(cls, process_data: dict) -> bool:
        name = process_data.get("name", "")
        if name.startswith("[") and name.endswith("]"):
            return True
        return any(name.startswith(p) for p in cls.KERNEL_THREAD_PATTERNS)


class DependencyGraph:
    """Graph structure for system entity dependencies."""

    def __init__(self):
        self.entities: dict[str, GraphEntity] = {}
        self.edges: list[tuple[str, str, str]] = []  # (source, target, type)
        self.outgoing: dict[str, list[str]] = defaultdict(list)
        self.incoming: dict[str, list[str]] = defaultdict(list)

    def add_entity(self, entity: GraphEntity):
        self.entities[entity.id] = entity

    def add_edge(self, source_id: str, target_id: str, edge_type: str):
        self.edges.append((source_id, target_id, edge_type))
        self.outgoing[source_id].append(target_id)
        self.incoming[target_id].append(source_id)

    def get_neighbors(self, entity_id: str) -> set[str]:
        return set(self.outgoing.get(entity_id, [])) | set(self.incoming.get(entity_id, []))

    def get_anchors(self) -> list[GraphEntity]:
        return [e for e in self.entities.values() if e.is_anchor]

    def get_reachable(self) -> list[GraphEntity]:
        return [e for e in self.entities.values() if e.reachable]

    def get_by_type(self, entity_type: EntityType) -> list[GraphEntity]:
        return [e for e in self.entities.values() if e.entity_type == entity_type]


class ScopeAnalyzer:
    """
    Implements "Anchor & Propagate" algorithm for context-aware PDDL scoping.

    Instead of arbitrary static caps, identifies anchor entities and propagates
    reachability through the dependency graph.
    """

    def __init__(self, osquery_interface):
        self.osquery = osquery_interface
        self.graph = DependencyGraph()
        self.pid_to_entity: dict[str, str] = {}
        self.uid_to_entity: dict[str, str] = {}

    def analyze(self) -> dict:
        """Execute Anchor & Propagate algorithm."""
        self._build_graph()
        self._identify_anchors()
        self._propagate_reachability()
        return self._extract_scoped_state()

    def _build_graph(self):
        """Build dependency graph from osquery data."""
        self._extract_users()
        self._extract_groups()
        self._extract_processes()
        self._extract_ports()
        self._extract_services()
        self._extract_packages()
        self._extract_config_files()
        self._build_edges()

    def _extract_users(self):
        results = self.osquery.execute_query(
            "SELECT username, uid, gid, directory, shell FROM users"
        )
        for row in results:
            uid = str(row.get("uid", ""))
            entity = GraphEntity(
                id=f"user:{uid}",
                entity_type=EntityType.USER,
                name=row.get("username", ""),
                original_data=row
            )
            self.graph.add_entity(entity)
            self.uid_to_entity[uid] = entity.id

    def _extract_groups(self):
        results = self.osquery.execute_query("SELECT groupname, gid FROM groups")
        for row in results:
            entity = GraphEntity(
                id=f"group:{row.get('gid', '')}",
                entity_type=EntityType.GROUP,
                name=row.get("groupname", ""),
                original_data=row
            )
            self.graph.add_entity(entity)

    def _extract_processes(self):
        results = self.osquery.execute_query(
            "SELECT pid, name, uid, gid, state, cmdline FROM processes"
        )
        for row in results:
            if AnchorCriteria.is_kernel_thread(row):
                continue
            pid = str(row.get("pid", ""))
            entity = GraphEntity(
                id=f"process:{pid}",
                entity_type=EntityType.PROCESS,
                name=row.get("name", ""),
                original_data=row
            )
            self.graph.add_entity(entity)
            self.pid_to_entity[pid] = entity.id

    def _extract_ports(self):
        results = self.osquery.execute_query(
            "SELECT port, protocol, address, pid FROM listening_ports"
        )
        for row in results:
            port_num = row.get("port", "")
            protocol = row.get("protocol", "tcp")
            entity = GraphEntity(
                id=f"port:{protocol}:{port_num}",
                entity_type=EntityType.PORT,
                name=f"{protocol}_{port_num}",
                original_data=row
            )
            self.graph.add_entity(entity)

    def _extract_services(self):
        results = self.osquery.execute_query(
            """SELECT id, active_state, sub_state, load_state, fragment_path 
               FROM systemd_units WHERE id LIKE '%.service'"""
        )
        for row in results:
            service_id = row.get("id", "")
            entity = GraphEntity(
                id=f"service:{service_id}",
                entity_type=EntityType.SERVICE,
                name=service_id,
                original_data=row
            )
            self.graph.add_entity(entity)

    def _extract_packages(self):
        results = self.osquery.execute_query(
            "SELECT name, version FROM deb_packages"
        )
        for row in results:
            pkg_name = row.get("name", "")
            entity = GraphEntity(
                id=f"package:{pkg_name}",
                entity_type=EntityType.PACKAGE,
                name=pkg_name,
                original_data=row
            )
            self.graph.add_entity(entity)

    def _extract_config_files(self):
        try:
            results = self.osquery.execute_query(
                """SELECT path, filename, uid, gid FROM file 
                   WHERE path LIKE '/etc/%' AND type = 'regular'
                   AND (path LIKE '%.conf' OR path LIKE '%.cfg')"""
            )
            for row in results:
                path = row.get("path", "")
                entity = GraphEntity(
                    id=f"config:{path}",
                    entity_type=EntityType.CONFIG_FILE,
                    name=path,
                    original_data=row
                )
                self.graph.add_entity(entity)
        except Exception:
            pass

    def _build_edges(self):
        """Build dependency edges between entities."""
        # Port -> Process (binding)
        for entity in self.graph.get_by_type(EntityType.PORT):
            pid = str(entity.original_data.get("pid", ""))
            if pid in self.pid_to_entity:
                self.graph.add_edge(entity.id, self.pid_to_entity[pid], "binds")

        # Process -> User (ownership)
        for entity in self.graph.get_by_type(EntityType.PROCESS):
            uid = str(entity.original_data.get("uid", ""))
            if uid in self.uid_to_entity:
                self.graph.add_edge(entity.id, self.uid_to_entity[uid], "owned_by")

        # Service -> Package (provides)
        packages = {e.name: e.id for e in self.graph.get_by_type(EntityType.PACKAGE)}
        for service in self.graph.get_by_type(EntityType.SERVICE):
            svc_name = service.name.replace(".service", "")
            if svc_name in packages:
                self.graph.add_edge(service.id, packages[svc_name], "uses")
            else:
                for pkg_name, pkg_id in packages.items():
                    if svc_name.startswith(pkg_name) or pkg_name.startswith(svc_name):
                        self.graph.add_edge(service.id, pkg_id, "uses")
                        break

        # Service -> Config (configured_by)
        for service in self.graph.get_by_type(EntityType.SERVICE):
            svc_name = service.name.replace(".service", "").lower()
            for config in self.graph.get_by_type(EntityType.CONFIG_FILE):
                if svc_name in config.name.lower():
                    self.graph.add_edge(service.id, config.id, "configured_by")

        # User group membership and sudo
        try:
            results = self.osquery.execute_query("SELECT uid, gid FROM user_groups")
            for row in results:
                uid, gid = str(row.get("uid", "")), str(row.get("gid", ""))
                user_id = f"user:{uid}"
                group_id = f"group:{gid}"
                if user_id in self.graph.entities and group_id in self.graph.entities:
                    self.graph.add_edge(user_id, group_id, "member_of")

            # Mark sudo users
            sudo_result = self.osquery.execute_query(
                "SELECT gid FROM groups WHERE groupname = 'sudo'"
            )
            if sudo_result:
                sudo_gid = str(sudo_result[0].get("gid", ""))
                members = self.osquery.execute_query(
                    f"SELECT uid FROM user_groups WHERE gid = {sudo_gid}"
                )
                for m in members:
                    uid = str(m.get("uid", ""))
                    user_id = f"user:{uid}"
                    if user_id in self.graph.entities:
                        self.graph.entities[user_id].original_data["can_sudo"] = True
        except Exception:
            pass

    def _identify_anchors(self):
        """Mark anchor entities based on criteria."""
        for entity in self.graph.get_by_type(EntityType.PORT):
            is_anchor, reason = AnchorCriteria.is_anchor_port(entity.original_data)
            if is_anchor:
                entity.is_anchor = True
                entity.anchor_reason = reason

        for entity in self.graph.get_by_type(EntityType.USER):
            is_anchor, reason = AnchorCriteria.is_anchor_user(entity.original_data)
            if is_anchor:
                entity.is_anchor = True
                entity.anchor_reason = reason

        for entity in self.graph.get_by_type(EntityType.SERVICE):
            is_anchor, reason = AnchorCriteria.is_anchor_service(entity.original_data)
            if is_anchor:
                entity.is_anchor = True
                entity.anchor_reason = reason

    def _propagate_reachability(self):
        """BFS from anchors to mark reachable entities."""
        from collections import deque

        queue = deque()
        for entity in self.graph.get_anchors():
            entity.reachable = True
            entity.depth = 0
            queue.append(entity.id)

        while queue:
            current_id = queue.popleft()
            current = self.graph.entities[current_id]

            for neighbor_id in self.graph.get_neighbors(current_id):
                if neighbor_id not in self.graph.entities:
                    continue
                neighbor = self.graph.entities[neighbor_id]
                if not neighbor.reachable:
                    neighbor.reachable = True
                    neighbor.depth = current.depth + 1
                    queue.append(neighbor_id)

    def _extract_scoped_state(self) -> dict:
        """Extract scoped state from reachable entities."""
        state = {
            "objects": defaultdict(list),
            "predicates": [],
            "relationships": defaultdict(list),
            "metadata": {
                "total_entities": len(self.graph.entities),
                "anchor_count": len(self.graph.get_anchors()),
                "reachable_count": len(self.graph.get_reachable()),
                "pruned_count": len(self.graph.entities) - len(self.graph.get_reachable()),
                "scoping_method": "anchor_propagate"
            }
        }

        type_map = {
            EntityType.PORT: "port",
            EntityType.PROCESS: "process",
            EntityType.SERVICE: "service",
            EntityType.PACKAGE: "package",
            EntityType.USER: "user",
            EntityType.GROUP: "group",
            EntityType.CONFIG_FILE: "configuration_file",
        }

        # 1. Update the loop that creates OBJECTS
        for entity in self.graph.get_reachable():
            pddl_type = type_map.get(entity.entity_type, "object")

            # CHANGE: Add prefix to ensure uniqueness (e.g. user_root, group_root)
            clean_name = self._sanitize_name(f"{pddl_type}_{entity.name}")

            obj = {
                "name": clean_name,
                "original_name": entity.name,
                "type": pddl_type,
                "properties": entity.original_data
            }

            state["objects"][pddl_type].append(obj)

            # Generate predicates (Pass the NEW name)
            self._add_predicates(entity, state["predicates"], clean_name)

        # 2. Update the loop that creates RELATIONSHIPS
        reachable_ids = {e.id for e in self.graph.get_reachable()}
        for src_id, tgt_id, edge_type in self.graph.edges:
            if src_id in reachable_ids and tgt_id in reachable_ids:
                src = self.graph.entities[src_id]
                tgt = self.graph.entities[tgt_id]

                # CHANGE: Apply same prefix logic here
                src_type = type_map.get(src.entity_type, "object")
                tgt_type = type_map.get(tgt.entity_type, "object")
                src_name = self._sanitize_name(f"{src_type}_{src.name}")
                tgt_name = self._sanitize_name(f"{tgt_type}_{tgt.name}")

                if edge_type == "uses":
                    state["relationships"]["depends_on"].append({
                        "service": src_name, "package": tgt_name
                    })
                elif edge_type == "configured_by":
                    state["relationships"]["configures"].append({
                        "config": tgt_name, "service": src_name
                    })
                elif edge_type == "member_of":
                    state["relationships"]["member_of"].append({
                        "user": src_name, "group": tgt_name
                    })

        # Add can_escalate relationships
        for entity in self.graph.get_reachable():
            if entity.entity_type == EntityType.USER:
                if entity.original_data.get("can_sudo"):
                    state["relationships"]["can_escalate"].append({
                        "user": self._sanitize_name(entity.name)
                    })

        return dict(state)

    def _add_predicates(self, entity: GraphEntity, predicates: list, name: str):
        """Generate predicates for an entity."""
        name = self._sanitize_name(entity.name)
        data = entity.original_data

        if entity.entity_type == EntityType.SERVICE:
            predicates.append({"name": "service_exists", "arguments": [name], "value": True})
            active = data.get("active_state") in AnchorCriteria.ACTIVE_STATES
            predicates.append({"name": "service_running", "arguments": [name], "value": active})
            predicates.append({"name": "service_failed", "arguments": [name],
                             "value": data.get("active_state") == "failed"})
            enabled = data.get("load_state") == "loaded" and data.get("fragment_path")
            predicates.append({"name": "service_enabled", "arguments": [name], "value": enabled})

        elif entity.entity_type == EntityType.USER:
            predicates.append({"name": "user_exists", "arguments": [name], "value": True})
            uid = int(data.get("uid", 0))
            predicates.append({"name": "user_critical", "arguments": [name],
                             "value": uid < AnchorCriteria.HUMAN_UID_MIN})
            predicates.append({"name": "can_escalate", "arguments": [name],
                             "value": data.get("can_sudo", False)})

        elif entity.entity_type == EntityType.PACKAGE:
            predicates.append({"name": "package_installed", "arguments": [name], "value": True})

        elif entity.entity_type == EntityType.PORT:
            predicates.append({"name": "port_open", "arguments": [name], "value": True})

        elif entity.entity_type == EntityType.CONFIG_FILE:
            predicates.append({"name": "file_exists", "arguments": [name], "value": True})

        elif entity.entity_type == EntityType.PROCESS:
            predicates.append({"name": "process_running", "arguments": [name], "value": True})

        elif entity.entity_type == EntityType.GROUP:
            predicates.append({"name": "group_exists", "arguments": [name], "value": True})

    def _sanitize_name(self, name: str) -> str:
            if not name:
                return ""
            # Replace non-alphanumeric chars with underscores
            sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', str(name))

            # Ensure it starts with a letter (if starts with _ or digit, prepend 'obj_')
            if sanitized and not sanitized[0].isalpha():
                sanitized = "obj_" + sanitized.lstrip('_')

            return sanitized.lower()

    def get_statistics(self) -> dict:
        """Return scoping statistics."""
        stats = {"total": {}, "anchors": {}, "reachable": {}, "pruned": {}}

        for etype in EntityType:
            entities = self.graph.get_by_type(etype)
            anchors = [e for e in entities if e.is_anchor]
            reachable = [e for e in entities if e.reachable]

            stats["total"][etype.value] = len(entities)
            stats["anchors"][etype.value] = len(anchors)
            stats["reachable"][etype.value] = len(reachable)
            stats["pruned"][etype.value] = len(entities) - len(reachable)

        return stats


# =============================================================================
# SECTION 4: System State Extractor
# =============================================================================

class SystemStateExtractor:
    """
    Extracts system state using osquery (Section 4.1).
    Provides the "Ground Truth" for PDDL generation.

    Uses osquery 3.1.1 Thrift API as primary interface for efficient
    multi-query execution against the OS state database.

    Supports two scoping modes:
    - "dynamic" (default): Graph-based Anchor & Propagate algorithm
    - "static": Legacy static caps (deprecated)
    """

    def __init__(self, osquery_interface: Optional[OSQueryInterface] = None,
                 socket_path: Optional[str] = None,
                 scoping_mode: str = "dynamic"):
        """
        Initialize extractor with osquery interface.

        Args:
            osquery_interface: Pre-configured interface (for testing)
            socket_path: Socket path for osqueryd connection
            scoping_mode: "dynamic" for graph-based, "static" for legacy caps
        """
        self.osquery = osquery_interface or get_osquery_interface(
            prefer_thrift=True,
            socket_path=socket_path
        )
        self.scoping_mode = scoping_mode
        self.scope_analyzer = None
        self.extracted_objects: list[ExtractedObject] = []
        self.extracted_predicates: list[ExtractedPredicate] = []
        self.relationships: dict[str, list] = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self.osquery, 'close'):
            self.osquery.close()

    def extract_all(self) -> dict:
        """
        Execute all extraction queries and return unified state.

        Uses dynamic scoping (Anchor & Propagate) by default.
        """
        if self.scoping_mode == "dynamic":
            return self._extract_with_dynamic_scoping()
        else:
            return self._extract_with_static_caps()

    def _extract_with_dynamic_scoping(self) -> dict:
        """
        Extract using graph-based Anchor & Propagate algorithm.

        This is the scientifically defensible approach that:
        1. Identifies anchor entities (listening ports, active services, humans)
        2. Propagates through dependency graph
        3. Prunes unreachable entities
        """
        self.scope_analyzer = ScopeAnalyzer(self.osquery)
        state = self.scope_analyzer.analyze()

        # Add statistics to metadata
        stats = self.scope_analyzer.get_statistics()
        state["metadata"]["scoping_statistics"] = stats

        return state

    def _extract_with_static_caps(self) -> dict:
        """
        Legacy extraction with static caps (deprecated).
        Use dynamic scoping for production.
        """
        log("  ⚠ Using legacy static caps (consider --scoping=dynamic)")
        """
        Execute all extraction queries and return unified state.
        This is the main entry point for Phase 1 static extraction.
        """
        state = {
            "objects": {},
            "predicates": [],
            "relationships": {},
            "metadata": {
                "osquery_version": getattr(self.osquery, 'version', 'unknown'),
                "extraction_complete": False
            }
        }

        # Extract objects and predicates for each mapping
        for mapping in OSQUERY_MAPPINGS:
            try:
                objects, predicates = self._extract_from_mapping(mapping)

                type_name = mapping.pddl_type.value
                if type_name not in state["objects"]:
                    state["objects"][type_name] = []
                state["objects"][type_name].extend(objects)
                state["predicates"].extend(predicates)

            except Exception as e:
                log(f"Warning: Failed to extract {mapping.table}: {e}")

        # Extract file system objects
        try:
            file_objects, file_predicates = self._extract_files()
            state["objects"]["file"] = file_objects
            state["predicates"].extend(file_predicates)
        except Exception as e:
            log(f"Warning: Failed to extract files: {e}")

        # Extract relationships (dependencies, ownership, etc.)
        try:
            state["relationships"] = self._extract_relationships(state["objects"])
        except Exception as e:
            log(f"Warning: Failed to extract relationships: {e}")

        state["metadata"]["extraction_complete"] = True
        return state

    def _extract_from_mapping(self, mapping: OSQueryMapping) -> tuple[list, list]:
        """Extract objects and predicates from a single mapping."""
        results = self.osquery.execute_query(mapping.query)

        objects = []
        predicates = []

        for row in results:
            # Create object
            name = self._sanitize_pddl_name(row.get(mapping.name_column, ""))
            if not name:
                continue

            properties = {col: row.get(col) for col in mapping.additional_columns}
            obj = {
                "name": name,
                "original_name": row.get(mapping.name_column),
                "type": mapping.pddl_type.value,
                "properties": properties
            }
            objects.append(obj)

            # Create predicate based on condition
            predicate_value = True
            if mapping.predicate_condition:
                predicate_value = self._evaluate_condition(
                    row, mapping.predicate_condition
                )

            pred = {
                "name": mapping.predicate_name,
                "arguments": [name],
                "value": predicate_value
            }
            predicates.append(pred)

            # Additional predicates for services
            if mapping.pddl_type == PDDLType.SERVICE:
                # service_exists is always true if we found it
                predicates.append({
                    "name": "service_exists",
                    "arguments": [name],
                    "value": True
                })

                # service_enabled: check if load_state is 'loaded' and has fragment_path
                # In systemd, enabled services have UnitFileState='enabled'
                load_state = row.get("load_state", "")
                fragment_path = row.get("fragment_path", "")
                is_enabled = load_state == "loaded" and fragment_path
                predicates.append({
                    "name": "service_enabled",
                    "arguments": [name],
                    "value": is_enabled
                })

                # service_failed
                active_state = row.get("active_state", "")
                predicates.append({
                    "name": "service_failed",
                    "arguments": [name],
                    "value": active_state == "failed"
                })

            # Additional predicates for users
            elif mapping.pddl_type == PDDLType.USER:
                uid = row.get("uid")
                # System users have UID < 1000
                is_system = uid is not None and int(uid) < 1000
                predicates.append({
                    "name": "user_critical",
                    "arguments": [name],
                    "value": is_system
                })

        return objects, predicates

    def _extract_files(self) -> tuple[list, list]:
        """Extract file system objects from critical paths."""
        objects = []
        predicates = []

        for base_path in CRITICAL_FILE_PATHS:
            query = f"""
                SELECT path, filename, type, uid, gid, mode, size 
                FROM file 
                WHERE path LIKE '{base_path}%' 
                AND type IN ('regular', 'directory')
            """
            try:
                results = self.osquery.execute_query(query)

                for row in results:
                    path = row.get("path", "")
                    name = self._sanitize_pddl_name(path)
                    file_type = row.get("type", "regular")

                    pddl_type = (PDDLType.DIRECTORY.value
                                if file_type == "directory"
                                else PDDLType.FILE.value)

                    # Detect configuration files
                    if (file_type == "regular" and
                        (path.startswith("/etc/") or path.endswith(".conf"))):
                        pddl_type = PDDLType.CONFIG_FILE.value

                    obj = {
                        "name": name,
                        "original_path": path,
                        "type": pddl_type,
                        "properties": {
                            "uid": row.get("uid"),
                            "gid": row.get("gid"),
                            "mode": row.get("mode"),
                            "size": row.get("size")
                        }
                    }
                    objects.append(obj)

                    predicates.append({
                        "name": "file_exists",
                        "arguments": [name],
                        "value": True
                    })

            except Exception as e:
                log(f"Warning: Failed to query path {base_path}: {e}")

        return objects, predicates

    def _extract_relationships(self, objects: dict) -> dict:
        """Extract relationships between objects (dependencies, ownership)."""
        relationships = {
            "depends_on": [],      # service -> package
            "configures": [],      # config_file -> service
            "owned_by": [],        # file -> user
            "member_of": [],       # user -> group
            "can_escalate": [],    # users who can sudo
        }

        # Extract service -> package dependencies via systemd
        if "service" in objects:
            for svc in objects["service"]:
                svc_name = svc.get("original_name", "").replace(".service", "")
                # Check if a package with similar name exists
                if "package" in objects:
                    for pkg in objects["package"]:
                        if pkg["name"] == svc_name or svc_name.startswith(pkg["name"]):
                            relationships["depends_on"].append({
                                "service": svc["name"],
                                "package": pkg["name"]
                            })

        # Extract config file -> service relationships
        if "configuration_file" in objects and "service" in objects:
            for cfg in objects.get("configuration_file", []):
                cfg_path = cfg.get("original_path", "")
                for svc in objects["service"]:
                    svc_name = svc.get("original_name", "").replace(".service", "")
                    if svc_name in cfg_path:
                        relationships["configures"].append({
                            "config": cfg["name"],
                            "service": svc["name"]
                        })

        # Extract user group memberships and sudo capability
        try:
            query = "SELECT uid, gid FROM user_groups"
            results = self.osquery.execute_query(query)
            for row in results:
                relationships["member_of"].append({
                    "user_uid": row.get("uid"),
                    "group_gid": row.get("gid")
                })
        except Exception:
            pass

        # Check for sudo group membership (GID 27 on Debian/Ubuntu)
        try:
            # Get sudo group GID
            sudo_query = "SELECT gid FROM groups WHERE groupname = 'sudo'"
            sudo_results = self.osquery.execute_query(sudo_query)
            if sudo_results:
                sudo_gid = sudo_results[0].get("gid")

                # Find users in sudo group
                members_query = f"SELECT uid FROM user_groups WHERE gid = {sudo_gid}"
                member_results = self.osquery.execute_query(members_query)

                # Map UIDs to usernames
                if "user" in objects:
                    sudo_uids = {r.get("uid") for r in member_results}
                    for user in objects["user"]:
                        uid = user.get("properties", {}).get("uid")
                        if uid in sudo_uids:
                            relationships["can_escalate"].append({
                                "user": user["name"]
                            })
        except Exception:
            pass

        return relationships

    def _sanitize_pddl_name(self, name: str) -> str:
        """Convert system names to valid PDDL identifiers."""
        if not name:
            return ""
        # Replace invalid characters with underscores
        sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
        # Ensure doesn't start with number
        if sanitized and sanitized[0].isdigit():
            sanitized = "obj_" + sanitized
        # Truncate if too long
        return sanitized.lower()

    def _evaluate_condition(self, row: dict, condition: str) -> bool:
        """Evaluate a simple condition string against a row."""
        # Handle OR conditions
        if " OR " in condition:
            parts = condition.split(" OR ")
            return any(self._evaluate_condition(row, p.strip()) for p in parts)

        # Handle AND conditions
        if " AND " in condition:
            parts = condition.split(" AND ")
            return all(self._evaluate_condition(row, p.strip()) for p in parts)

        # Parse simple equality: column='value'
        match = re.match(r"(\w+)\s*=\s*'([^']*)'", condition)
        if match:
            col, val = match.groups()
            return row.get(col) == val

        return True


# =============================================================================
# SECTION 4: Man Page Parser for Action Mining (Section 4.2)
# =============================================================================

class ManPageParser:
    """
    Extracts action schemas from man pages (Section 4.2).
    Handles sudo-rs and uutils specifics for Ubuntu 25.10.
    """

    # Utilities to extract actions from
    TARGET_UTILITIES = {
        "package_management": ["apt-get", "apt", "dpkg", "snap"],
        "service_management": ["systemctl", "journalctl"],
        "file_operations": ["cp", "mv", "rm", "chmod", "chown", "mkdir", "touch"],
        "network": ["iptables", "ip", "ss", "netstat"],
        "privilege": ["sudo", "su"],
        "user_management": ["useradd", "usermod", "userdel", "groupadd"],
    }

    # Patterns for extracting action information
    PATTERNS = {
        "requires_root": [
            r"must be root",
            r"requires? (?:root|superuser)",
            r"only (?:root|superuser)",
            r"permission denied",
            r"EACCES",
        ],
        "precondition_indicators": [
            r"requires?\s+(.+?)(?:\.|,|$)",
            r"must (?:be|have|exist)\s+(.+?)(?:\.|,|$)",
            r"depends? on\s+(.+?)(?:\.|,|$)",
        ],
        "effect_indicators": [
            r"creates?\s+(.+?)(?:\.|,|$)",
            r"removes?\s+(.+?)(?:\.|,|$)",
            r"modif(?:y|ies)\s+(.+?)(?:\.|,|$)",
            r"starts?\s+(.+?)(?:\.|,|$)",
            r"stops?\s+(.+?)(?:\.|,|$)",
        ],
    }

    def __init__(self):
        self.cached_manpages: dict[str, str] = {}
        self.detected_variants: dict[str, str] = {}  # e.g., {"sudo": "sudo-rs"}

    def fetch_manpage(self, utility: str) -> Optional[str]:
        """
        Fetch and clean man page content (Section 4.2.1).
        Uses: man [utility] | col -b
        """
        if utility in self.cached_manpages:
            return self.cached_manpages[utility]

        try:
            # Use col -b to strip backspaces and formatting
            process = subprocess.Popen(
                f"man {utility} 2>/dev/null | col -b",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, _ = process.communicate(timeout=30)

            if process.returncode == 0 and stdout:
                content = stdout.decode('utf-8', errors='replace')
                self.cached_manpages[utility] = content

                # Detect sudo-rs (Section 4.2.2)
                # Look for specific sudo-rs identifiers, not just "rust"
                if utility == "sudo":
                    sudo_rs_indicators = [
                        "sudo-rs",
                        "memorysafe",
                        "trifecta tech",
                        "prossimo"
                    ]
                    if any(ind in content.lower() for ind in sudo_rs_indicators):
                        self.detected_variants["sudo"] = "sudo-rs"

                # Detect uutils - only for coreutils commands
                # uutils replaces: cp, mv, rm, ls, chmod, chown, mkdir, touch, etc.
                UUTILS_COMMANDS = {
                    "cp", "mv", "rm", "ls", "chmod", "chown", "mkdir", "touch",
                    "cat", "head", "tail", "wc", "sort", "uniq", "cut", "paste",
                    "basename", "dirname", "realpath", "pwd", "whoami", "id",
                    "date", "echo", "printf", "true", "false", "yes", "seq"
                }
                if utility in UUTILS_COMMANDS:
                    uutils_indicators = [
                        "uutils",
                        "coreutils-rust",
                        "rust implementation of coreutils"
                    ]
                    if any(ind in content.lower() for ind in uutils_indicators):
                        self.detected_variants[utility] = "uutils"

                return content
        except (subprocess.TimeoutExpired, Exception) as e:
            log(f"Warning: Failed to fetch man page for {utility}: {e}")

        return None

    def fetch_help_output(self, utility: str) -> Optional[str]:
        """Fetch --help output as fallback for action mining."""
        try:
            result = subprocess.run(
                [utility, "--help"],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout or result.stderr
        except Exception:
            return None

    def extract_actions_from_utility(self, utility: str) -> list[ActionSchema]:
        """Extract action schemas from a single utility."""
        actions = []

        manpage = self.fetch_manpage(utility)
        help_text = self.fetch_help_output(utility)

        combined_text = ""
        if manpage:
            combined_text += manpage
        if help_text:
            combined_text += "\n" + help_text

        if not combined_text:
            return actions

        # Determine if requires root
        requires_root = any(
            re.search(pattern, combined_text, re.IGNORECASE)
            for pattern in self.PATTERNS["requires_root"]
        )

        # Extract based on utility category
        if utility in ["apt-get", "apt"]:
            actions.extend(self._extract_apt_actions(combined_text, requires_root))
        elif utility == "dpkg":
            actions.extend(self._extract_dpkg_actions(combined_text, requires_root))
        elif utility == "snap":
            actions.extend(self._extract_snap_actions(combined_text, requires_root))
        elif utility == "systemctl":
            actions.extend(self._extract_systemctl_actions(combined_text, requires_root))
        elif utility in ["cp", "mv", "rm", "chmod", "chown"]:
            actions.extend(self._extract_file_actions(utility, combined_text, requires_root))
        elif utility in ["mkdir", "touch"]:
            actions.extend(self._extract_create_actions(utility, combined_text, requires_root))
        elif utility == "iptables":
            actions.extend(self._extract_iptables_actions(combined_text, requires_root))
        elif utility == "ip":
            actions.extend(self._extract_ip_actions(combined_text, requires_root))
        elif utility == "sudo":
            actions.extend(self._extract_sudo_actions(combined_text))
        elif utility in ["useradd", "usermod", "userdel"]:
            actions.extend(self._extract_user_actions(utility, combined_text, requires_root))
        elif utility == "groupadd":
            actions.extend(self._extract_group_actions(combined_text, requires_root))

        return actions

    def _extract_dpkg_actions(self, text: str, requires_root: bool) -> list[ActionSchema]:
        """Extract dpkg package management actions."""
        actions = []

        # dpkg install local package
        actions.append(ActionSchema(
            name="install_local_package",
            parameters=[
                ActionParameter("pkg", PDDLType.PACKAGE),
                ActionParameter("deb_file", PDDLType.FILE)
            ],
            preconditions=[
                "(not (package_installed ?pkg))",
                "(file_exists ?deb_file)"
            ],
            effects=[
                "(package_installed ?pkg)"
            ],
            command_template="dpkg -i {deb_file}",
            requires_root=True,
            source_utility="dpkg"
        ))

        # dpkg configure (fix broken packages)
        actions.append(ActionSchema(
            name="configure_package",
            parameters=[
                ActionParameter("pkg", PDDLType.PACKAGE)
            ],
            preconditions=[
                "(package_installed ?pkg)"
            ],
            effects=[
                "(package_configured ?pkg)"
            ],
            command_template="dpkg --configure {pkg}",
            requires_root=True,
            source_utility="dpkg"
        ))

        return actions

    def _extract_snap_actions(self, text: str, requires_root: bool) -> list[ActionSchema]:
        """Extract snap package management actions."""
        actions = []

        # snap install
        actions.append(ActionSchema(
            name="install_snap",
            parameters=[
                ActionParameter("pkg", PDDLType.PACKAGE)
            ],
            preconditions=[
                "(not (package_installed ?pkg))",
                "(network_available)"
            ],
            effects=[
                "(package_installed ?pkg)"
            ],
            command_template="snap install {pkg}",
            requires_root=True,
            source_utility="snap"
        ))

        # snap remove
        actions.append(ActionSchema(
            name="remove_snap",
            parameters=[
                ActionParameter("pkg", PDDLType.PACKAGE)
            ],
            preconditions=[
                "(package_installed ?pkg)"
            ],
            effects=[
                "(not (package_installed ?pkg))"
            ],
            command_template="snap remove {pkg}",
            requires_root=True,
            source_utility="snap"
        ))

        # snap refresh (update)
        actions.append(ActionSchema(
            name="refresh_snap",
            parameters=[
                ActionParameter("pkg", PDDLType.PACKAGE)
            ],
            preconditions=[
                "(package_installed ?pkg)",
                "(network_available)"
            ],
            effects=[
                "(not (package_outdated ?pkg))"
            ],
            command_template="snap refresh {pkg}",
            requires_root=True,
            source_utility="snap"
        ))

        return actions

    def _extract_create_actions(self, utility: str, text: str,
                                requires_root: bool) -> list[ActionSchema]:
        """Extract file/directory creation actions."""
        actions = []
        is_uutils = self.detected_variants.get(utility) == "uutils"

        if utility == "mkdir":
            actions.append(ActionSchema(
                name="create_directory",
                parameters=[
                    ActionParameter("d", PDDLType.DIRECTORY)
                ],
                preconditions=[
                    "(not (file_exists ?d))"
                ],
                effects=[
                    "(file_exists ?d)"
                ],
                command_template="mkdir -p {d}",
                requires_root=False,
                source_utility=f"mkdir ({'uutils' if is_uutils else 'coreutils'})"
            ))

        elif utility == "touch":
            actions.append(ActionSchema(
                name="create_file",
                parameters=[
                    ActionParameter("f", PDDLType.FILE)
                ],
                preconditions=[
                    "(not (file_exists ?f))"
                ],
                effects=[
                    "(file_exists ?f)"
                ],
                command_template="touch {f}",
                requires_root=False,
                source_utility=f"touch ({'uutils' if is_uutils else 'coreutils'})"
            ))

        return actions

    def _extract_ip_actions(self, text: str, requires_root: bool) -> list[ActionSchema]:
        """Extract network interface management actions."""
        actions = []

        # ip link set up
        actions.append(ActionSchema(
            name="enable_interface",
            parameters=[
                ActionParameter("iface", PDDLType.INTERFACE)
            ],
            preconditions=[
                "(interface_exists ?iface)",
                "(not (interface_up ?iface))"
            ],
            effects=[
                "(interface_up ?iface)"
            ],
            command_template="ip link set {iface} up",
            requires_root=True,
            source_utility="ip"
        ))

        # ip link set down
        actions.append(ActionSchema(
            name="disable_interface",
            parameters=[
                ActionParameter("iface", PDDLType.INTERFACE)
            ],
            preconditions=[
                "(interface_up ?iface)"
            ],
            effects=[
                "(not (interface_up ?iface))"
            ],
            command_template="ip link set {iface} down",
            requires_root=True,
            source_utility="ip"
        ))

        return actions

    def _extract_group_actions(self, text: str, requires_root: bool) -> list[ActionSchema]:
        """Extract group management actions."""
        actions = []

        # groupadd
        actions.append(ActionSchema(
            name="create_group",
            parameters=[
                ActionParameter("g", PDDLType.GROUP)
            ],
            preconditions=[
                "(not (group_exists ?g))"
            ],
            effects=[
                "(group_exists ?g)"
            ],
            command_template="groupadd {g}",
            requires_root=True,
            source_utility="groupadd"
        ))

        return actions

    def _extract_apt_actions(self, text: str, requires_root: bool) -> list[ActionSchema]:
        """Extract package management actions."""
        actions = []

        # install_package
        actions.append(ActionSchema(
            name="install_package",
            parameters=[
                ActionParameter("pkg", PDDLType.PACKAGE)
            ],
            preconditions=[
                "(not (package_installed ?pkg))",
                "(network_available)"
            ],
            effects=[
                "(package_installed ?pkg)"
            ],
            command_template="apt-get install -y {pkg}",
            requires_root=True,
            source_utility="apt-get"
        ))

        # remove_package
        actions.append(ActionSchema(
            name="remove_package",
            parameters=[
                ActionParameter("pkg", PDDLType.PACKAGE)
            ],
            preconditions=[
                "(package_installed ?pkg)"
            ],
            effects=[
                "(not (package_installed ?pkg))"
            ],
            command_template="apt-get remove -y {pkg}",
            requires_root=True,
            source_utility="apt-get"
        ))

        # update_package
        actions.append(ActionSchema(
            name="update_package",
            parameters=[
                ActionParameter("pkg", PDDLType.PACKAGE)
            ],
            preconditions=[
                "(package_installed ?pkg)",
                "(network_available)"
            ],
            effects=[
                "(not (package_outdated ?pkg))",
                "(not (vulnerable ?pkg))"
            ],
            command_template="apt-get install --only-upgrade -y {pkg}",
            requires_root=True,
            source_utility="apt-get"
        ))

        return actions

    def _extract_systemctl_actions(self, text: str, requires_root: bool) -> list[ActionSchema]:
        """Extract service management actions."""
        actions = []

        # start_service
        actions.append(ActionSchema(
            name="start_service",
            parameters=[
                ActionParameter("svc", PDDLType.SERVICE)
            ],
            preconditions=[
                "(service_exists ?svc)",
                "(not (service_running ?svc))"
            ],
            effects=[
                "(service_running ?svc)"
            ],
            command_template="systemctl start {svc}",
            requires_root=True,
            source_utility="systemctl"
        ))

        # stop_service
        actions.append(ActionSchema(
            name="stop_service",
            parameters=[
                ActionParameter("svc", PDDLType.SERVICE)
            ],
            preconditions=[
                "(service_running ?svc)"
            ],
            effects=[
                "(not (service_running ?svc))"
            ],
            command_template="systemctl stop {svc}",
            requires_root=True,
            source_utility="systemctl"
        ))

        # restart_service
        actions.append(ActionSchema(
            name="restart_service",
            parameters=[
                ActionParameter("svc", PDDLType.SERVICE),
                ActionParameter("cfg", PDDLType.CONFIG_FILE)
            ],
            preconditions=[
                "(service_exists ?svc)",
                "(configures ?cfg ?svc)",
                "(file_exists ?cfg)"
            ],
            effects=[
                "(service_running ?svc)",
                "(config_applied ?svc)"
            ],
            command_template="systemctl restart {svc}",
            requires_root=True,
            source_utility="systemctl"
        ))

        # enable_service
        actions.append(ActionSchema(
            name="enable_service",
            parameters=[
                ActionParameter("svc", PDDLType.SERVICE)
            ],
            preconditions=[
                "(service_exists ?svc)"
            ],
            effects=[
                "(service_enabled ?svc)"
            ],
            command_template="systemctl enable {svc}",
            requires_root=True,
            source_utility="systemctl"
        ))

        # disable_service
        actions.append(ActionSchema(
            name="disable_service",
            parameters=[
                ActionParameter("svc", PDDLType.SERVICE)
            ],
            preconditions=[
                "(service_enabled ?svc)"
            ],
            effects=[
                "(not (service_enabled ?svc))"
            ],
            command_template="systemctl disable {svc}",
            requires_root=True,
            source_utility="systemctl"
        ))

        return actions

    def _extract_file_actions(self, utility: str, text: str,
                              requires_root: bool) -> list[ActionSchema]:
        """Extract file operation actions, handling uutils variants."""
        actions = []
        is_uutils = self.detected_variants.get(utility) == "uutils"

        if utility == "cp":
            actions.append(ActionSchema(
                name="copy_file",
                parameters=[
                    ActionParameter("src", PDDLType.FILE),
                    ActionParameter("dst", PDDLType.FILE)
                ],
                preconditions=[
                    "(file_exists ?src)",
                    "(not (file_exists ?dst))"
                ],
                effects=[
                    "(file_exists ?dst)"
                ],
                command_template="cp {src} {dst}",
                requires_root=False,
                source_utility=f"cp ({'uutils' if is_uutils else 'coreutils'})"
            ))

        elif utility == "mv":
            actions.append(ActionSchema(
                name="move_file",
                parameters=[
                    ActionParameter("src", PDDLType.FILE),
                    ActionParameter("dst", PDDLType.FILE)
                ],
                preconditions=[
                    "(file_exists ?src)"
                ],
                effects=[
                    "(not (file_exists ?src))",
                    "(file_exists ?dst)"
                ],
                command_template="mv {src} {dst}",
                requires_root=False,
                source_utility=f"mv ({'uutils' if is_uutils else 'coreutils'})"
            ))

        elif utility == "rm":
            actions.append(ActionSchema(
                name="delete_file",
                parameters=[
                    ActionParameter("f", PDDLType.FILE)
                ],
                preconditions=[
                    "(file_exists ?f)",
                    "(not (file_critical ?f))"
                ],
                effects=[
                    "(not (file_exists ?f))"
                ],
                command_template="rm {f}",
                requires_root=False,
                source_utility=f"rm ({'uutils' if is_uutils else 'coreutils'})"
            ))

        elif utility == "chmod":
            actions.append(ActionSchema(
                name="change_permissions",
                parameters=[
                    ActionParameter("f", PDDLType.FILE)
                ],
                preconditions=[
                    "(file_exists ?f)"
                ],
                effects=[
                    "(file_writable ?f)"  # Simplified effect
                ],
                command_template="chmod {mode} {f}",
                requires_root=False,
                source_utility=f"chmod ({'uutils' if is_uutils else 'coreutils'})"
            ))

        elif utility == "chown":
            actions.append(ActionSchema(
                name="change_owner",
                parameters=[
                    ActionParameter("f", PDDLType.FILE),
                    ActionParameter("u", PDDLType.USER)
                ],
                preconditions=[
                    "(file_exists ?f)",
                    "(user_exists ?u)"
                ],
                effects=[
                    "(file_owned_by ?f ?u)"
                ],
                command_template="chown {u} {f}",
                requires_root=True,
                source_utility=f"chown ({'uutils' if is_uutils else 'coreutils'})"
            ))

        return actions

    def _extract_iptables_actions(self, text: str,
                                  requires_root: bool) -> list[ActionSchema]:
        """Extract firewall management actions."""
        actions = []

        # block_traffic
        actions.append(ActionSchema(
            name="block_traffic",
            parameters=[
                ActionParameter("rule", PDDLType.FIREWALL_RULE)
            ],
            preconditions=[
                "(not (firewall_rule_exists ?rule))"
            ],
            effects=[
                "(firewall_rule_exists ?rule)",
                "(traffic_blocked ?rule)"
            ],
            command_template="iptables -A INPUT -s {src} -j DROP",
            requires_root=True,
            source_utility="iptables"
        ))

        # allow_traffic
        actions.append(ActionSchema(
            name="allow_traffic",
            parameters=[
                ActionParameter("rule", PDDLType.FIREWALL_RULE)
            ],
            preconditions=[
                "(traffic_blocked ?rule)"
            ],
            effects=[
                "(not (traffic_blocked ?rule))"
            ],
            command_template="iptables -D INPUT -s {src} -j DROP",
            requires_root=True,
            source_utility="iptables"
        ))

        # open_port
        actions.append(ActionSchema(
            name="open_port",
            parameters=[
                ActionParameter("p", PDDLType.PORT)
            ],
            preconditions=[
                "(not (port_allowed ?p))"
            ],
            effects=[
                "(port_allowed ?p)"
            ],
            command_template="iptables -A INPUT -p tcp --dport {p} -j ACCEPT",
            requires_root=True,
            source_utility="iptables"
        ))

        return actions

    def _extract_sudo_actions(self, text: str) -> list[ActionSchema]:
        """
        Extract privilege escalation actions.
        Handles sudo-rs specifics (Section 4.2.2).
        """
        actions = []
        is_sudo_rs = self.detected_variants.get("sudo") == "sudo-rs"

        # Base execute_privileged action
        preconditions = [
            "(user_exists ?u)",
            "(can_escalate ?u)"
        ]

        # sudo-rs specific: -E flag is restricted
        # Environment variables must be passed explicitly
        if is_sudo_rs:
            preconditions.append("(not (requires_env_preservation ?cmd))")

        actions.append(ActionSchema(
            name="execute_privileged",
            parameters=[
                ActionParameter("u", PDDLType.USER),
                ActionParameter("cmd", PDDLType.PROCESS)
            ],
            preconditions=preconditions,
            effects=[
                "(executed_as_root ?cmd)"
            ],
            command_template="sudo {cmd}" if not is_sudo_rs else "sudo --reset-timestamp {cmd}",
            requires_root=False,
            source_utility="sudo-rs" if is_sudo_rs else "sudo"
        ))

        return actions

    def _extract_user_actions(self, utility: str, text: str,
                              requires_root: bool) -> list[ActionSchema]:
        """Extract user management actions."""
        actions = []

        if utility == "useradd":
            actions.append(ActionSchema(
                name="create_user",
                parameters=[
                    ActionParameter("u", PDDLType.USER)
                ],
                preconditions=[
                    "(not (user_exists ?u))"
                ],
                effects=[
                    "(user_exists ?u)"
                ],
                command_template="useradd {u}",
                requires_root=True,
                source_utility="useradd"
            ))

        elif utility == "usermod":
            # Add user to group
            actions.append(ActionSchema(
                name="add_user_to_group",
                parameters=[
                    ActionParameter("u", PDDLType.USER),
                    ActionParameter("g", PDDLType.GROUP)
                ],
                preconditions=[
                    "(user_exists ?u)",
                    "(group_exists ?g)",
                    "(not (member_of ?u ?g))"
                ],
                effects=[
                    "(member_of ?u ?g)"
                ],
                command_template="usermod -aG {g} {u}",
                requires_root=True,
                source_utility="usermod"
            ))

            # Lock user account
            actions.append(ActionSchema(
                name="lock_user",
                parameters=[
                    ActionParameter("u", PDDLType.USER)
                ],
                preconditions=[
                    "(user_exists ?u)",
                    "(not (user_locked ?u))"
                ],
                effects=[
                    "(user_locked ?u)"
                ],
                command_template="usermod -L {u}",
                requires_root=True,
                source_utility="usermod"
            ))

            # Unlock user account
            actions.append(ActionSchema(
                name="unlock_user",
                parameters=[
                    ActionParameter("u", PDDLType.USER)
                ],
                preconditions=[
                    "(user_exists ?u)",
                    "(user_locked ?u)"
                ],
                effects=[
                    "(not (user_locked ?u))"
                ],
                command_template="usermod -U {u}",
                requires_root=True,
                source_utility="usermod"
            ))

        elif utility == "userdel":
            actions.append(ActionSchema(
                name="delete_user",
                parameters=[
                    ActionParameter("u", PDDLType.USER)
                ],
                preconditions=[
                    "(user_exists ?u)",
                    "(not (user_critical ?u))"
                ],
                effects=[
                    "(not (user_exists ?u))"
                ],
                command_template="userdel {u}",
                requires_root=True,
                source_utility="userdel"
            ))

        return actions

    def extract_all_actions(self) -> list[ActionSchema]:
        """Extract actions from all target utilities."""
        all_actions = []

        for category, utilities in self.TARGET_UTILITIES.items():
            for utility in utilities:
                try:
                    actions = self.extract_actions_from_utility(utility)
                    all_actions.extend(actions)
                    log(f"  Extracted {len(actions)} actions from {utility}")
                except Exception as e:
                    log(f"  Warning: Failed to extract from {utility}: {e}")

        return all_actions


# =============================================================================
# SECTION 5: PDDL Generator
# =============================================================================

class PDDLGenerator:
    """
    Generates PDDL domain from extracted system state and actions.

    When using dynamic scoping (Anchor & Propagate), the state is already
    optimally filtered. When using static scoping, legacy limits apply.
    """

    # Legacy limits for static scoping mode only
    STATIC_OBJECT_LIMITS = {
        "package": 100,
        "service": 50,
        "user": 50,
        "group": 50,
        "port": 20,
        "firewall_rule": 20,
        "process": 30,
        "file": 50,
        "configuration_file": 50,
        "directory": 20,
    }

    def __init__(self, domain_name: str = "sysadmin"):
        self.domain_name = domain_name

    def generate_domain(self, state: dict, actions: list[ActionSchema]) -> str:
        """Generate complete PDDL domain file."""
        lines = []

        # Header
        lines.append(f"(define (domain {self.domain_name})")
        lines.append("")

        # Requirements
        lines.append("  (:requirements :strips :typing :negative-preconditions)")
        lines.append("")

        # Types
        lines.append(self._generate_types(state))
        lines.append("")

        # Predicates
        lines.append(self._generate_predicates(state))
        lines.append("")

        # Deduplicate actions by name (keep first occurrence)
        seen_actions = set()
        unique_actions = []
        for action in actions:
            if action.name not in seen_actions:
                seen_actions.add(action.name)
                unique_actions.append(action)

        # Actions
        for action in unique_actions:
            lines.append(self._generate_action(action))
            lines.append("")

        lines.append(")")

        return "\n".join(lines)

    def generate_problem(self, state: dict, goal_predicates: list[str],
                        problem_name: str = "sysadmin-problem") -> str:
        """Generate PDDL problem file from current state."""
        lines = []

        # Header
        lines.append(f"(define (problem {problem_name})")
        lines.append(f"  (:domain {self.domain_name})")
        lines.append("")

        # Objects
        lines.append(self._generate_objects(state))
        lines.append("")

        # Initial state
        lines.append(self._generate_init(state))
        lines.append("")

        # Goal
        lines.append("  (:goal")
        lines.append("    (and")
        for pred in goal_predicates:
            lines.append(f"      {pred}")
        lines.append("    )")
        lines.append("  )")

        lines.append(")")

        return "\n".join(lines)

    def _generate_types(self, state: dict) -> str:
        """Generate PDDL type hierarchy."""
        lines = ["  (:types"]

        # Base types
        lines.append("    ; Base types")
        #lines.append("    object")
        lines.append("    ")

        # Filesystem hierarchy
        lines.append("    ; Filesystem types")
        lines.append("    filesystem_object - object")
        lines.append("    file directory - filesystem_object")
        lines.append("    configuration_file - file")
        lines.append("    ")

        # Execution types
        lines.append("    ; Execution types")
        lines.append("    service process - object")
        lines.append("    ")

        # Package types
        lines.append("    ; Package management types")
        lines.append("    package repository - object")
        lines.append("    ")

        # Access control types
        lines.append("    ; Access control types")
        lines.append("    user group - object")
        lines.append("    system_user human_user - user")
        lines.append("    ")

        # Network types
        lines.append("    ; Network types")
        lines.append("    port interface firewall_rule - object")

        lines.append("  )")

        return "\n".join(lines)

    def _generate_predicates(self, state: dict) -> str:
        """Generate PDDL predicates."""
        lines = ["  (:predicates"]

        # Dynamic predicates (from state)
        lines.append("    ; Dynamic state predicates - Packages")
        lines.append("    (package_installed ?p - package)")
        lines.append("    (package_outdated ?p - package)")
        lines.append("    (package_configured ?p - package)")
        lines.append("    (vulnerable ?p - package)")
        lines.append("    ")
        lines.append("    ; Dynamic state predicates - Services")
        lines.append("    (service_exists ?s - service)")
        lines.append("    (service_running ?s - service)")
        lines.append("    (service_enabled ?s - service)")
        lines.append("    (service_failed ?s - service)")
        lines.append("    (config_applied ?s - service)")
        lines.append("    ")
        lines.append("    ; Dynamic state predicates - Filesystem")
        lines.append("    (file_exists ?f - filesystem_object)")
        lines.append("    (file_readable ?f - filesystem_object)")
        lines.append("    (file_writable ?f - filesystem_object)")
        lines.append("    (file_critical ?f - filesystem_object)")
        lines.append("    ")
        lines.append("    ; Dynamic state predicates - Users")
        lines.append("    (user_exists ?u - user)")
        lines.append("    (user_critical ?u - user)")
        lines.append("    (user_locked ?u - user)")
        lines.append("    (can_escalate ?u - user)")
        lines.append("    ")
        lines.append("    ; Dynamic state predicates - Groups")
        lines.append("    (group_exists ?g - group)")
        lines.append("    ")
        lines.append("    ; Dynamic state predicates - Network")
        lines.append("    (port_open ?p - port)")
        lines.append("    (port_allowed ?p - port)")
        lines.append("    (interface_exists ?i - interface)")
        lines.append("    (interface_up ?i - interface)")
        lines.append("    ")
        lines.append("    ; Dynamic state predicates - Firewall")
        lines.append("    (firewall_rule_exists ?r - firewall_rule)")
        lines.append("    (traffic_blocked ?r - firewall_rule)")
        lines.append("    ")
        lines.append("    ; Dynamic state predicates - Processes")
        lines.append("    (process_running ?pr - process)")
        lines.append("    (executed_as_root ?pr - process)")
        lines.append("    ")

        # Static relationship predicates
        lines.append("    ; Static relationship predicates")
        lines.append("    (depends_on ?s - service ?p - package)")
        lines.append("    (configures ?f - configuration_file ?s - service)")
        lines.append("    (file_owned_by ?f - filesystem_object ?u - user)")
        lines.append("    (member_of ?u - user ?g - group)")
        lines.append("    ")

        # Environment predicates
        lines.append("    ; Environment predicates")
        lines.append("    (network_available)")
        lines.append("    (requires_env_preservation ?pr - process)")

        lines.append("  )")

        return "\n".join(lines)

    def _generate_action(self, action: ActionSchema) -> str:
        """Generate PDDL action from schema."""
        lines = [f"  (:action {action.name}"]

        # Build parameters list
        params_list = [
            f"?{p.name} - {p.pddl_type.value}"
            for p in action.parameters
        ]

        # Add ?actor parameter for actions requiring privilege
        if action.requires_root:
            params_list.insert(0, "?actor - user")

        params = " ".join(params_list)
        lines.append(f"    :parameters ({params})")

        # Preconditions
        lines.append("    :precondition (and")
        for pre in action.preconditions:
            lines.append(f"      {pre}")

        # Add root requirement if needed (now using ?actor which is declared)
        if action.requires_root:
            lines.append("      (can_escalate ?actor)")

        lines.append("    )")

        # Effects
        lines.append("    :effect (and")
        for eff in action.effects:
            lines.append(f"      {eff}")
        lines.append("    )")

        lines.append("  )")

        return "\n".join(lines)

    def _generate_objects(self, state: dict) -> str:
        """Generate PDDL objects from extracted state."""
        lines = ["  (:objects"]

        # Check if using dynamic scoping (no limits needed)
        is_dynamic = state.get("metadata", {}).get("scoping_method") == "anchor_propagate"

        for pddl_type, objects in state.get("objects", {}).items():
            if objects:
                if is_dynamic:
                    # Dynamic scoping: already optimally filtered
                    selected_objects = objects
                else:
                    # Static scoping: apply legacy limits
                    limit = self.STATIC_OBJECT_LIMITS.get(pddl_type, 50)
                    selected_objects = objects[:limit]
                    if len(objects) > limit:
                        lines.append(f"    ; ... truncated {len(objects) - limit} more {pddl_type}s")

                obj_names = " ".join(obj["name"] for obj in selected_objects)
                lines.append(f"    {obj_names} - {pddl_type}")

        lines.append("  )")

        return "\n".join(lines)

    def _generate_init(self, state: dict) -> str:
        """Generate initial state from extracted predicates."""
        lines = ["  (:init"]

        # Check scoping method
        is_dynamic = state.get("metadata", {}).get("scoping_method") == "anchor_propagate"

        # Build set of included object names
        included_objects = set()
        for pddl_type, objects in state.get("objects", {}).items():
            if is_dynamic:
                selected = objects
            else:
                limit = self.STATIC_OBJECT_LIMITS.get(pddl_type, 50)
                selected = objects[:limit]
            for obj in selected:
                included_objects.add(obj["name"])

        # Add predicates only for included objects
        for pred in state.get("predicates", []):
            if pred.get("value", True):
                args = pred.get("arguments", [])
                if all(arg in included_objects for arg in args):
                    args_str = " ".join(args)
                    lines.append(f"    ({pred['name']} {args_str})")

        # Add relationships (also filtered)
        for rel_type, relations in state.get("relationships", {}).items():
            for rel in relations:  # Reasonable limit for relationships
                if rel_type == "depends_on":
                    svc, pkg = rel.get('service'), rel.get('package')
                    if svc in included_objects and pkg in included_objects:
                        lines.append(f"    (depends_on {svc} {pkg})")
                elif rel_type == "configures":
                    cfg, svc = rel.get('config'), rel.get('service')
                    if cfg in included_objects and svc in included_objects:
                        lines.append(f"    (configures {cfg} {svc})")
                elif rel_type == "can_escalate":
                    user = rel.get('user')
                    if user in included_objects:
                        lines.append(f"    (can_escalate {user})")
                elif rel_type == "member_of":
                    user, group = rel.get('user'), rel.get('group')
                    if user in included_objects and group in included_objects:
                        lines.append(f"    (member_of {user} {group})")

        # Assume network available by default
        lines.append("    (network_available)")

        lines.append("  )")

        return "\n".join(lines)


# =============================================================================
# SECTION 6: Main Orchestrator
# =============================================================================

class Phase1Orchestrator:
    """
    Main orchestrator for Phase 1: System Introspection.
    Coordinates extraction, action mining, and PDDL generation.

    Uses osquery 3.1.1 Thrift API for system state extraction.
    """

    def __init__(self, output_dir: str = "./pddl_output",
                 osquery_socket: Optional[str] = None,
                 validate: bool = False,
                 scoping_mode: str = "dynamic"):
        """
        Initialize orchestrator.

        Args:
            output_dir: Directory for PDDL output files
            osquery_socket: Optional socket path for osqueryd connection.
                           If None, spawns standalone instance.
            validate: If True, validate generated PDDL with VAL
            scoping_mode: "dynamic" for graph-based Anchor & Propagate,
                         "static" for legacy arbitrary caps
        """
        self.output_dir = output_dir
        self.osquery_socket = osquery_socket
        self.validate = validate
        self.scoping_mode = scoping_mode
        self.extractor = None
        self.parser = None
        self.generator = PDDLGenerator()
        self.validator = PDDLValidator() if validate else None
        self.state = {}
        self.actions = []

    def run(self) -> dict:
        """Execute the complete Phase 1 pipeline."""
        results = {
            "success": False,
            "state_extracted": False,
            "actions_mined": False,
            "pddl_generated": False,
            "errors": [],
            "warnings": [],
            "statistics": {}
        }

        # Step 1: Initialize osquery interface
        log("=" * 60)
        log("Phase 1: System Introspection")
        log("=" * 60)
        log("\n[1/4] Initializing osquery Thrift API (osquery==3.1.1)...")

        try:
            self.extractor = SystemStateExtractor(
                socket_path=self.osquery_socket,
                scoping_mode=self.scoping_mode
            )
            log(f"  ✓ Connected to osquery")
        except Exception as e:
            results["errors"].append(f"Failed to initialize osquery: {e}")
            log(f"  ✗ Failed: {e}")
            log("  Hint: pip install osquery==3.1.1")
            # Continue without osquery (will generate skeleton domain)

        # Step 2: Extract system state
        log(f"\n[2/4] Extracting system state (scoping: {self.scoping_mode})...")

        if self.extractor:
            try:
                self.state = self.extractor.extract_all()
                results["state_extracted"] = True

                # Statistics
                for obj_type, objs in self.state.get("objects", {}).items():
                    results["statistics"][f"{obj_type}_count"] = len(objs)
                results["statistics"]["predicate_count"] = len(
                    self.state.get("predicates", [])
                )

                # Show scoping results if using dynamic mode
                metadata = self.state.get("metadata", {})
                if metadata.get("scoping_method") == "anchor_propagate":
                    log(f"  ✓ Scoping: {metadata.get('anchor_count', 0)} anchors → "
                        f"{metadata.get('reachable_count', 0)} reachable "
                        f"(pruned {metadata.get('pruned_count', 0)})")

                log(f"  ✓ Extracted objects: {results['statistics']}")
            except Exception as e:
                results["errors"].append(f"State extraction failed: {e}")
                log(f"  ✗ Failed: {e}")
                self.state = {"objects": {}, "predicates": [], "relationships": {}}
        else:
            log("  ⚠ Skipping (osquery not available)")
            self.state = {"objects": {}, "predicates": [], "relationships": {}}

        # Step 3: Mine actions from man pages
        log("\n[3/4] Mining actions from system documentation...")

        try:
            self.parser = ManPageParser()
            self.actions = self.parser.extract_all_actions()
            results["actions_mined"] = True
            results["statistics"]["action_count"] = len(self.actions)

            # Report detected variants
            if self.parser.detected_variants:
                log(f"  ✓ Detected variants: {self.parser.detected_variants}")
            log(f"  ✓ Extracted {len(self.actions)} action schemas")

        except Exception as e:
            results["errors"].append(f"Action mining failed: {e}")
            log(f"  ✗ Failed: {e}")
            self.actions = []

        # Step 4: Generate PDDL
        log("\n[4/4] Generating PDDL domain...")

        try:
            domain_pddl = self.generator.generate_domain(self.state, self.actions)
            problem_pddl = self.generator.generate_problem(
                self.state,
                ["(network_available)"],  # Trivial goal for validation
                "sysadmin-initial"
            )

            results["pddl_generated"] = True
            results["domain_pddl"] = domain_pddl
            results["problem_pddl"] = problem_pddl

            log(f"  ✓ Generated domain ({len(domain_pddl)} chars)")
            log(f"  ✓ Generated problem ({len(problem_pddl)} chars)")

        except Exception as e:
            results["errors"].append(f"PDDL generation failed: {e}")
            log(f"  ✗ Failed: {e}")

        # Step 5: Validate PDDL (optional)
        if self.validate and results.get("pddl_generated"):
            log("\n[5/5] Validating PDDL...")

            if self.validator and self.validator.is_available():
                # Validate domain
                domain_valid, domain_msg = self.validator.validate_domain(
                    results.get("domain_pddl", "")
                )
                results["domain_valid"] = domain_valid
                if domain_valid:
                    log("  ✓ Domain syntax valid")
                else:
                    log(f"  ✗ Domain invalid: {domain_msg[:200]}")
                    results["warnings"].append(f"Domain validation: {domain_msg[:500]}")

                # Validate problem
                problem_valid, problem_msg = self.validator.validate_problem(
                    results.get("domain_pddl", ""),
                    results.get("problem_pddl", "")
                )
                results["problem_valid"] = problem_valid
                if problem_valid:
                    log("  ✓ Problem syntax valid")
                else:
                    log(f"  ✗ Problem invalid: {problem_msg[:200]}")
                    results["warnings"].append(f"Problem validation: {problem_msg[:500]}")
            else:
                log("  ⚠ VAL validator not installed (skipping)")
                log("    Install from: https://github.com/KCL-Planning/VAL")

        # Final status
        results["success"] = (
            results["pddl_generated"] and
            len(results["errors"]) == 0
        )

        # Cleanup osquery connection
        if self.extractor and hasattr(self.extractor.osquery, 'close'):
            self.extractor.osquery.close()
            log("\n  ✓ Closed osquery connection")

        log("\n" + "=" * 60)
        log(f"Phase 1 Complete: {'SUCCESS' if results['success'] else 'PARTIAL'}")
        log("=" * 60)

        return results


# =============================================================================
# SECTION 7: Entry Point
# =============================================================================

def main():
    """Main entry point for Phase 1 execution."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Phase 1: System Introspection for PDDL Domain Generation"
    )
    parser.add_argument(
        "--output-dir", "-o",
        default="./pddl_output",
        help="Output directory for PDDL files"
    )
    parser.add_argument(
        "--json-output", "-j",
        action="store_true",
        help="Output results as JSON to stdout (progress goes to stderr)"
    )
    parser.add_argument(
        "--include-pddl",
        action="store_true",
        help="Include PDDL content in JSON output (use with -j)"
    )
    parser.add_argument(
        "--osquery-socket", "-s",
        default=None,
        help="Path to osqueryd socket (e.g., /var/osquery/osquery.em). "
             "If not specified, spawns standalone instance."
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output"
    )
    parser.add_argument(
        "--validate", "-v",
        action="store_true",
        help="Validate generated PDDL with VAL validator"
    )
    parser.add_argument(
        "--write-files", "-w",
        action="store_true",
        help="Write PDDL files to output directory"
    )
    parser.add_argument(
        "--scoping",
        choices=["dynamic", "static"],
        default="dynamic",
        help="Scoping method: 'dynamic' (graph-based Anchor & Propagate) or "
             "'static' (legacy arbitrary caps). Default: dynamic"
    )

    args = parser.parse_args()

    # Configure logging output
    if args.json_output:
        # Send progress to stderr so stdout is clean JSON
        set_log_stream(sys.stderr)

    if args.quiet:
        # Suppress all progress output (cross-platform null device)
        import os
        set_log_stream(open(os.devnull, 'w'))

    # Run orchestrator
    orchestrator = Phase1Orchestrator(
        output_dir=args.output_dir,
        osquery_socket=args.osquery_socket,
        validate=args.validate,
        scoping_mode=args.scoping
    )
    results = orchestrator.run()

    # Write files if requested
    if args.write_files and results.get("pddl_generated"):
        import os
        os.makedirs(args.output_dir, exist_ok=True)

        domain_path = os.path.join(args.output_dir, "sysadmin.pddl")
        problem_path = os.path.join(args.output_dir, "problem.pddl")

        with open(domain_path, 'w') as f:
            f.write(results.get("domain_pddl", ""))
        with open(problem_path, 'w') as f:
            f.write(results.get("problem_pddl", ""))

        log(f"\nFiles written to {args.output_dir}/")
        log(f"  - sysadmin.pddl ({len(results.get('domain_pddl', ''))} bytes)")
        log(f"  - problem.pddl ({len(results.get('problem_pddl', ''))} bytes)")

    if args.json_output:
        # Build JSON output
        output = {
            "success": results.get("success", False),
            "state_extracted": results.get("state_extracted", False),
            "actions_mined": results.get("actions_mined", False),
            "pddl_generated": results.get("pddl_generated", False),
            "statistics": results.get("statistics", {}),
            "errors": results.get("errors", []),
            "warnings": results.get("warnings", []),
        }

        if args.include_pddl:
            output["domain_pddl"] = results.get("domain_pddl", "")
            output["problem_pddl"] = results.get("problem_pddl", "")

        # Output clean JSON to stdout
        print(json.dumps(output, indent=2))
    else:
        # Print PDDL to stdout
        if results.get("domain_pddl"):
            print("\n" + "=" * 60)
            print("GENERATED DOMAIN (sysadmin.pddl)")
            print("=" * 60)
            print(results["domain_pddl"])

    return 0 if results["success"] else 1


if __name__ == "__main__":
    exit(main())