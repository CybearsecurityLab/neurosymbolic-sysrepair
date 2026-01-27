import re
from typing import Optional

from phase1.common.config import OSQUERY_MAPPINGS, CRITICAL_FILE_PATHS
from common.models import (
    ExtractedObject,
    ExtractedPredicate,
    OSQueryMapping,
    PDDLType,
)
from phase1.common.logger import log
from phase1.introspection.client import OSQueryInterface, get_osquery_interface
from phase1.introspection.scoping import ScopeAnalyzer


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

    def __init__(
        self,
        osquery_interface: Optional[OSQueryInterface] = None,
        socket_path: Optional[str] = None,
        scoping_mode: str = "dynamic",
    ):
        """
        Initialize extractor with osquery interface.

        Args:
            osquery_interface: Pre-configured interface (for testing)
            socket_path: Socket path for osqueryd connection
            scoping_mode: "dynamic" for graph-based, "static" for legacy caps
        """
        self.osquery = osquery_interface or get_osquery_interface(
            prefer_thrift=True, socket_path=socket_path
        )
        self.scoping_mode = scoping_mode
        self.scope_analyzer = None
        self.extracted_objects: list[ExtractedObject] = []
        self.extracted_predicates: list[ExtractedPredicate] = []
        self.relationships: dict[str, list] = {}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if hasattr(self.osquery, "close"):
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
                "osquery_version": getattr(self.osquery, "version", "unknown"),
                "extraction_complete": False,
            },
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
                "type": mapping.pddl_type,
                "properties": properties,
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
                "value": predicate_value,
            }
            predicates.append(pred)

            # Additional predicates for services
            if mapping.pddl_type == PDDLType.SERVICE:
                # service_exists is always true if we found it
                predicates.append(
                    {"name": "service_exists", "arguments": [name], "value": True}
                )

                # service_enabled: check if load_state is 'loaded' and has fragment_path
                # In systemd, enabled services have UnitFileState='enabled'
                load_state = row.get("load_state", "")
                fragment_path = row.get("fragment_path", "")
                is_enabled = load_state == "loaded" and fragment_path
                predicates.append(
                    {
                        "name": "service_enabled",
                        "arguments": [name],
                        "value": is_enabled,
                    }
                )

                # service_failed
                active_state = row.get("active_state", "")
                predicates.append(
                    {
                        "name": "service_failed",
                        "arguments": [name],
                        "value": active_state == "failed",
                    }
                )

            # Additional predicates for users
            elif mapping.pddl_type == PDDLType.USER:
                uid = row.get("uid")
                # System users have UID < 1000
                is_system = uid is not None and int(uid) < 1000
                predicates.append(
                    {"name": "user_critical", "arguments": [name], "value": is_system}
                )

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

                    pddl_type = (
                        PDDLType.DIRECTORY.value
                        if file_type == "directory"
                        else PDDLType.FILE.value
                    )

                    # Detect configuration files
                    if file_type == "regular" and (
                        path.startswith("/etc/") or path.endswith(".conf")
                    ):
                        pddl_type = PDDLType.CONFIG_FILE.value

                    obj = {
                        "name": name,
                        "original_path": path,
                        "type": pddl_type,
                        "properties": {
                            "uid": row.get("uid"),
                            "gid": row.get("gid"),
                            "mode": row.get("mode"),
                            "size": row.get("size"),
                        },
                    }
                    objects.append(obj)

                    predicates.append(
                        {"name": "file_exists", "arguments": [name], "value": True}
                    )

            except Exception as e:
                log(f"Warning: Failed to query path {base_path}: {e}")

        return objects, predicates

    def _extract_relationships(self, objects: dict) -> dict:
        """Extract relationships between objects (dependencies, ownership)."""
        relationships = {
            "depends_on": [],  # service -> package
            "configures": [],  # config_file -> service
            "file_owned_by": [],  # file -> user
            "file_owned_by_group": [],  # file -> group
            "member_of": [],  # user -> group
            "can_escalate": [],  # users who can sudo
        }

        # Build lookup maps for users and groups by UID/GID
        uid_to_user = {}
        gid_to_group = {}

        if "user" in objects:
            for user in objects["user"]:
                uid = user.get("properties", {}).get("uid")
                if uid:
                    uid_to_user[str(uid)] = user["name"]

        if "group" in objects:
            for group in objects["group"]:
                gid = group.get("properties", {}).get("gid")
                if gid:
                    gid_to_group[str(gid)] = group["name"]

        # Extract service -> package dependencies via systemd
        if "service" in objects:
            for svc in objects["service"]:
                svc_name = svc.get("original_name", "").replace(".service", "")
                # Check if a package with similar name exists
                if "package" in objects:
                    for pkg in objects["package"]:
                        if pkg["name"] == svc_name or svc_name.startswith(pkg["name"]):
                            relationships["depends_on"].append(
                                {"service": svc["name"], "package": pkg["name"]}
                            )

        # Extract config file -> service relationships
        if "configuration_file" in objects and "service" in objects:
            for cfg in objects.get("configuration_file", []):
                cfg_path = cfg.get("original_path", "")
                for svc in objects["service"]:
                    svc_name = svc.get("original_name", "").replace(".service", "")
                    if svc_name in cfg_path:
                        relationships["configures"].append(
                            {"config": cfg["name"], "service": svc["name"]}
                        )

        # Extract file ownership relationships
        for file_type in ["file", "configuration_file"]:
            if file_type in objects:
                for f in objects[file_type]:
                    props = f.get("properties", {})
                    uid = str(props.get("uid", ""))
                    gid = str(props.get("gid", ""))

                    if uid in uid_to_user:
                        relationships["file_owned_by"].append(
                            {"file": f["name"], "user": uid_to_user[uid]}
                        )
                    if gid in gid_to_group:
                        relationships["file_owned_by_group"].append(
                            {"file": f["name"], "group": gid_to_group[gid]}
                        )

        # Extract user group memberships
        try:
            query = "SELECT uid, gid FROM user_groups"
            results = self.osquery.execute_query(query)
            for row in results:
                uid = str(row.get("uid", ""))
                gid = str(row.get("gid", ""))
                if uid in uid_to_user and gid in gid_to_group:
                    relationships["member_of"].append(
                        {"user": uid_to_user[uid], "group": gid_to_group[gid]}
                    )
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
                    sudo_uids = {str(r.get("uid")) for r in member_results}
                    for user in objects["user"]:
                        uid = str(user.get("properties", {}).get("uid", ""))
                        if uid in sudo_uids:
                            relationships["can_escalate"].append({"user": user["name"]})
        except Exception:
            pass

        return relationships

    def _sanitize_pddl_name(self, name: str) -> str:
        """Convert system names to valid PDDL identifiers."""
        if not name:
            return ""
        # Replace invalid characters with underscores
        sanitized = re.sub(r"[^a-zA-Z0-9_-]", "_", name)
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