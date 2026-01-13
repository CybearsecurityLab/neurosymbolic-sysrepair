import re
from collections import defaultdict

from phase1.common.config import AnchorCriteria
from phase1.common.models import GraphEntity, EntityType


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
        self._extract_interfaces()
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

    def _extract_interfaces(self):
        """Extract network interfaces."""
        try:
            results = self.osquery.execute_query(
                "SELECT interface, address, type FROM interface_addresses WHERE interface NOT LIKE 'lo%'"
            )
            for row in results:
                iface = row.get("interface", "")
                entity = GraphEntity(
                    id=f"interface:{iface}",
                    entity_type=EntityType.INTERFACE,
                    name=iface,
                    original_data=row
                )
                self.graph.add_entity(entity)
        except Exception:
            pass

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
        """Extract scoped state from reachable entities with guaranteed uniqueness."""
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

        # --- PASS 1: Generate Unique Names & Cache Them ---
        # We map entity_id -> unique_pddl_name to ensure consistency between objects and relationships
        entity_id_to_pddl_name = {}
        used_names = set()

        for entity in self.graph.get_reachable():
            pddl_type = type_map.get(entity.entity_type, "object")

            # 1. Base sanitization (e.g. "user:root" -> "user_root")
            raw_name = f"{pddl_type}_{entity.name}"
            sanitized = re.sub(r'[^a-zA-Z0-9_-]', '_', str(raw_name)).lower()

            # Ensure valid PDDL start char
            if not sanitized or not sanitized[0].isalpha():
                sanitized = "obj_" + sanitized.lstrip('_')

            # 2. Collision Resolution (e.g. "user_root" -> "user_root_1")
            final_name = sanitized
            counter = 1
            while final_name in used_names:
                final_name = f"{sanitized}_{counter}"
                counter += 1

            used_names.add(final_name)
            entity_id_to_pddl_name[entity.id] = final_name

        # --- PASS 2: Build Objects ---
        for entity in self.graph.get_reachable():
            pddl_type = type_map.get(entity.entity_type, "object")
            clean_name = entity_id_to_pddl_name[entity.id]

            obj = {
                "name": clean_name,
                "original_name": entity.name,
                "type": pddl_type,
                "properties": entity.original_data
            }

            state["objects"][pddl_type].append(obj)
            self._add_predicates(entity, state["predicates"], clean_name)

        # --- PASS 3: Build Relationships ---
        # Now we use the cached names so relationships point to the correct objects
        reachable_ids = set(entity_id_to_pddl_name.keys())

        for src_id, tgt_id, edge_type in self.graph.edges:
            if src_id in reachable_ids and tgt_id in reachable_ids:
                src_name = entity_id_to_pddl_name[src_id]
                tgt_name = entity_id_to_pddl_name[tgt_id]

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
            if entity.entity_type == EntityType.USER and entity.original_data.get("can_sudo"):
                clean_name = entity_id_to_pddl_name[entity.id]
                state["relationships"]["can_escalate"].append({
                    "user": clean_name
                })

        return dict(state)

    def _add_predicates(self, entity: GraphEntity, predicates: list, name: str):
        """Generates PDDL state predicates for the problem file."""
        data = entity.original_data

        if entity.entity_type == EntityType.SERVICE:
            # 1. Existence
            predicates.append({"name": "service_exists", "arguments": [name], "value": True})

            # 2. State (Running)
            is_active = data.get("active_state") in AnchorCriteria.ACTIVE_STATES
            predicates.append({"name": "service_running", "arguments": [name], "value": is_active})

            # 3. State (Failed) - FIX for missing predicate
            is_failed = data.get("active_state") == "failed"
            predicates.append({"name": "service_failed", "arguments": [name], "value": is_failed})

            # 4. State (Enabled) - FIX for missing predicate
            # Note: osquery 'load_state' is usually 'loaded', 'masked', or 'not-found'
            # We treat 'loaded' + presence of fragment path as a proxy for enabled/manageable
            is_loaded = data.get("load_state") == "loaded" and bool(data.get("fragment_path"))
            predicates.append({"name": "service_enabled", "arguments": [name], "value": is_loaded})

        elif entity.entity_type == EntityType.PACKAGE:
            predicates.append({"name": "package_installed", "arguments": [name], "value": True})
            # Note: 'vulnerable' predicate requires external CVE data not available in standard osquery tables

        elif entity.entity_type == EntityType.USER:
            predicates.append({"name": "user_exists", "arguments": [name], "value": True})

            # 1. Privileges
            is_root = str(data.get("uid")) == "0"
            if is_root or data.get("can_sudo"):
                predicates.append({"name": "can_escalate", "arguments": [name], "value": True})

            # 2. Criticality - FIX for missing predicate
            # System users (uid < 1000) are generally critical
            uid = int(data.get("uid", 9999))
            is_critical = uid < 1000 or is_root
            predicates.append({"name": "user_critical", "arguments": [name], "value": is_critical})

        elif entity.entity_type in [EntityType.CONFIG_FILE, EntityType.FILE]:
            predicates.append({"name": "file_exists", "arguments": [name], "value": True})

            # 1. Criticality - FIX for missing predicate
            # Check if path is in critical system directories
            path = data.get("path") or data.get("filename") or ""
            critical_prefixes = ["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/boot", "/usr/bin"]
            is_critical = any(path.startswith(p) for p in critical_prefixes)
            predicates.append({"name": "file_critical", "arguments": [name], "value": is_critical})

        elif entity.entity_type == EntityType.PORT:
            predicates.append({"name": "port_open", "arguments": [name], "value": True})

        elif entity.entity_type == EntityType.PROCESS:
            # Process state: R=running, S=sleeping, D=disk sleep, Z=zombie, T=stopped
            state = data.get("state", "")
            is_running = state in ["R", "S", "D"]  # Consider sleeping processes as "running"
            predicates.append({"name": "process_running", "arguments": [name], "value": is_running})

        elif entity.entity_type == EntityType.INTERFACE:
            predicates.append({"name": "interface_exists", "arguments": [name], "value": True})
            # Assume interfaces with addresses are "up"
            has_address = bool(data.get("address"))
            predicates.append({"name": "interface_up", "arguments": [name], "value": has_address})

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