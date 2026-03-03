"""
Configuration for Phase 3: Iterative Refinement via Exploration Walks
"""

import os
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("Phase3.Config")


@dataclass
class DockerConfig:
    """Docker container configuration for sandboxed execution."""

    image: str = "ubuntu:25.10"
    container_name: str = "pddl-sandbox"

    # Resource limits
    mem_limit: str = "4g"
    cpu_count: int = 2

    # Timeouts
    exec_timeout: int = 30  # seconds per command
    startup_timeout: int = 60  # seconds to wait for container

    # Networking
    network_mode: str = "none"  # Isolated by default

    # Volumes (read-only mounts if needed)
    volumes: dict = field(default_factory=dict)

    # Container lifecycle
    auto_remove: bool = False  # Keep for debugging
    detach: bool = True
    tty: bool = True

    def to_docker_kwargs(self) -> dict:
        """Convert to docker.containers.run() kwargs."""
        return {
            "image": self.image,
            "name": self.container_name,
            "mem_limit": self.mem_limit,
            "cpu_count": self.cpu_count,
            "network_mode": self.network_mode,
            "volumes": self.volumes,
            "auto_remove": self.auto_remove,
            "detach": self.detach,
            "tty": self.tty,
        }


@dataclass
class PlannerConfig:
    """Fast Downward planner configuration."""

    # Path to Fast Downward
    fast_downward_path: str = "/home/resbears/fast_downward/fast-downward.py"

    # Search configuration for random walks
    search_config: str = "eager_greedy([ff()])"

    # Random walk parameters
    default_walk_depth: int = 5  # Max actions per walk
    default_num_walks: int = 10  # Number of exploration walks

    # Timeout for planning
    plan_timeout: int = 300  # seconds (large domains need more time)

    # Temporary directory for PDDL files
    temp_dir: str = "/tmp/pddl_planning"


@dataclass
class LLMRefinementConfig:
    """LLM configuration for domain refinement."""

    model_name: str = "mistralai/Mistral-7B-Instruct-v0.3"
    base_url: str = "http://localhost:8000/v1"
    max_tokens: int = 4096
    temperature: float = 0.2  # Slightly higher for creative fixes

    # Prompting
    max_feedback_items: int = 10  # Max discrepancies to include in prompt
    max_retries: int = 3  # Retries per refinement attempt


@dataclass
class Phase3Config:
    """Main configuration for Phase 3."""

    # Sub-configurations
    docker: DockerConfig = field(default_factory=DockerConfig)
    planner: PlannerConfig = field(default_factory=PlannerConfig)
    llm: LLMRefinementConfig = field(default_factory=LLMRefinementConfig)

    # Exploration Walk parameters
    ew_target_score: float = 0.9  # Target EW score to achieve
    max_refinement_iterations: int = 10  # Max iterations before giving up
    walks_per_iteration: int = 10  # N in EW formula (default; overridden by auto-scale)
    walk_depth: int = 5  # T_max in EW formula (default; overridden by auto-scale)
    ew_params_explicitly_set: bool = False  # True if user provided --walks/--depth

    # I/O
    input_domain_path: str = "./pddl_output/sysadmin.pddl"
    input_problem_path: str = "./pddl_output/problem.pddl"
    output_dir: str = "./pddl_output/phase3"

    # Logging
    log_level: str = "INFO"
    save_intermediate_domains: bool = True

    # Mock mode for testing
    use_mock_docker: bool = False
    use_mock_planner: bool = False
    use_mock_llm: bool = False

    def auto_scale_ew_params(self, num_actions: int) -> None:
        """
        Auto-scale EW parameters based on domain size, ONLY if the user
        did not explicitly set them via CLI args.

        Formulas:
        - walks_per_iteration = clamp(num_actions // 10, 30, 100)
        - walk_depth = clamp(num_actions // 100, 8, 20)

        For 1,132 actions: walks=100, depth=11 -> 1,100 total steps
        For 50 actions: walks=30, depth=8 -> 240 total steps
        For 500 actions: walks=50, depth=8 -> 400 total steps
        """
        if self.ew_params_explicitly_set:
            logger.info(
                f"EW params explicitly set by user: "
                f"walks={self.walks_per_iteration}, depth={self.walk_depth}"
            )
            return

        self.walks_per_iteration = max(30, min(100, num_actions // 10))
        self.walk_depth = max(8, min(20, num_actions // 100))

        logger.info(
            f"Auto-scaled EW params for {num_actions} actions: "
            f"walks={self.walks_per_iteration}, depth={self.walk_depth} "
            f"(~{self.walks_per_iteration * self.walk_depth} total steps/iteration)"
        )

    @classmethod
    def from_env(cls) -> "Phase3Config":
        """Create config from environment variables."""
        config = cls()

        # Override from environment
        if os.environ.get("PDDL_DOMAIN_PATH"):
            config.input_domain_path = os.environ["PDDL_DOMAIN_PATH"]
        if os.environ.get("PDDL_PROBLEM_PATH"):
            config.input_problem_path = os.environ["PDDL_PROBLEM_PATH"]
        if os.environ.get("PHASE3_OUTPUT_DIR"):
            config.output_dir = os.environ["PHASE3_OUTPUT_DIR"]
        if os.environ.get("EW_TARGET_SCORE"):
            config.ew_target_score = float(os.environ["EW_TARGET_SCORE"])
        if os.environ.get("LLM_BASE_URL"):
            config.llm.base_url = os.environ["LLM_BASE_URL"]
        if os.environ.get("LLM_MODEL"):
            config.llm.model_name = os.environ["LLM_MODEL"]
        if os.environ.get("DOCKER_IMAGE"):
            config.docker.image = os.environ["DOCKER_IMAGE"]

        return config


# Action concretization mapping: PDDL action patterns -> bash templates
ACTION_TEMPLATES = {
    # Package management
    "install_package": "apt-get install -y {package}",
    "remove_package": "apt-get remove -y {package}",
    "purge_package": "apt-get purge -y {package}",
    "update_package_list": "apt-get update",
    "upgrade_packages": "apt-get upgrade -y",
    "upgrade_package": "apt-get install --only-upgrade -y {package}",
    "downgrade_package": "apt-get install -y --allow-downgrades {package}",
    "hold_package": "apt-mark hold {package}",
    "unhold_package": "apt-mark unhold {package}",
    "autoremove_packages": "apt-get autoremove -y",
    "clean_package_cache": "apt-get clean",
    "autoclean_package_cache": "apt-get autoclean",
    "simulate_apt_action": "apt-get -s install {package}",
    "mark_auto": "apt-mark auto {package}",
    "mark_manual": "apt-mark manual {package}",
    "download_package": "apt-get download {package}",
    "download_dsc_only": "apt-get source --download-only {package}",
    "download_diff_only": "apt-get source --diff-only {package}",
    "download_tar_only": "apt-get source --tar-only {package}",
    "host_architecture": "dpkg --print-architecture",
    "prefer_alias": "true",
    "autoremove": "apt-get autoremove -y",
    "audit_package": "apt-cache policy {package}",
    "process_arch_only": "apt-get source --compile {package}",
    "download_source": "apt-get source {source}",
    "why_not_package": "apt-cache policy {package}",
    "only_upgrade": "apt-get install --only-upgrade -y {package}",
    "check_package": "dpkg -s {package}",
    "process_indep_only": "apt-get source --compile {package}",
    "build_dependencies": "apt-get build-dep -y {source}",
    "dpkg_remove": "dpkg --remove {package}",

    # Snap package management
    "snap_install": "snap install {package}",
    "snap_remove": "snap remove {package}",
    "snap_refresh": "snap refresh {package}",
    "refresh_snap": "snap refresh {package}",
    "snap_revert": "snap revert {package}",
    "revert_snap": "snap revert {package}",
    "snap_enable": "snap enable {package}",
    "snap_disable": "snap disable {package}",
    "snap_alias": "snap alias {package} {alias}",
    "snap_unalias": "snap unalias {alias}",
    "snap_connect": "snap connect {plug} {slot}",
    "snap_ack": "snap ack {file}",
    "snap_changes": "snap changes",
    "snapshot": "snap save {package}",

    # Service management
    "start_service": "systemctl start {service}",
    "stop_service": "systemctl stop {service}",
    "restart_service": "systemctl restart {service}",
    "enable_service": "systemctl enable {service}",
    "disable_service": "systemctl disable {service}",
    "reload_service": "systemctl reload {service}",
    "mask_service": "systemctl mask {service}",
    "unmask_service": "systemctl unmask {service}",

    # User management
    "create_user": "useradd {user}",
    "delete_user": "userdel {user}",
    "lock_user": "usermod -L {user}",
    "unlock_user": "usermod -U {user}",
    "add_user_to_group": "usermod -aG {group} {user}",
    "add_user_to_existing_group": "usermod -aG {group} {user}",
    "add_users_to_group": "usermod -aG {group} {user}",
    "change_user_shell": "chsh -s {shell} {user}",
    "change_user_password": "echo '{user}:{password}' | chpasswd",
    "change_home_directory": "usermod -d /home/{user} {user}",
    "change_login_name": "usermod -l {new_name} {user}",
    "change_user_uid": "usermod -u {uid} {user}",
    "change_user_id_non_unique": "usermod -o {user}",
    "change_primary_group": "usermod -g {group} {user}",
    "change_supplementary_groups": "usermod -G {groups} {user}",
    "append_supplementary_group": "usermod -aG {group} {user}",
    "append_user_to_groups": "usermod -aG {groups} {user}",
    "change_user": "su - {user}",
    "run_as_user": "su - {user}",
    "userdel_selinux": "userdel {user}",
    "userdel_force": "userdel --force {user}",
    "execute_whoami": "whoami",
    "passwd_unlock_password": "passwd -u {user}",
    "passwd_delete_password": "passwd -d {user}",
    "passwd_help": "passwd --help",
    "initialize_environment": "su - {user} -c true",
    "add_subids_for_system": "usermod --add-subuids 100000-165535 --add-subgids 100000-165535 {user}",
    "preserve_environment": "true",
    "change_user_login": "usermod -l {new_login} {user}",
    "change_username": "usermod -l {new_login} {old_login}",
    "reset_session_timestamp": "true",
    "manage_mail_spool": "true",

    # Group management
    "create_group": "groupadd {group}",
    "delete_group": "groupdel {group}",
    "change_group": "chgrp {group} {file}",
    "groupmod_append_members": "usermod -aG {group} {user}",
    "groupmod_rename": "groupmod -n {group} {group}",

    # File operations
    "create_file": "touch {file}",
    "delete_file": "rm -f {file}",
    "create_directory": "mkdir -p {directory}",
    "delete_directory": "rm -rf {directory}",
    "set_file_permissions": "chmod {mode} {file}",
    "set_file_owner": "chown {user}:{group} {file}",
    "copy_file": "cp {source} {destination}",
    "move_file": "mv {source} {destination}",
    "change_file_mode": "chmod {mode} {file}",
    "change_owner": "chown {user} {file}",
    "change_owner_and_group": "chown {user}:{group} {file}",
    "change_owner_recursive": "chown -R {user}:{group} {file}",
    "change_ownership": "chown {user}:{group} {file}",
    "change_permissions_symlink": "chmod -h {mode} {file}",
    "adapt_file_ownership": "chown {user} /home/{user}",

    # Hostname/system configuration
    "hostnamectl_hostname": "hostnamectl set-hostname {hostname}",
    "hostnamectl_static": "hostnamectl set-hostname --static {hostname}",
    "hostnamectl_pretty": "hostnamectl set-hostname --pretty {hostname}",
    "hostnamectl_transient": "hostnamectl set-hostname --transient {hostname}",
    "hostnamectl_chassis": "hostnamectl set-chassis {chassis}",
    "hostnamectl_deployment": "hostnamectl set-deployment {deployment}",
    "hostnamectl_location": "hostnamectl set-location {location}",
    "hostnamectl_icon_name": "hostnamectl set-icon-name {icon}",
    "hostnamectl_status": "hostnamectl status",

    # Time/date configuration
    "timedatectl_set_time": "timedatectl set-time {time}",
    "timedatectl_set_timezone": "timedatectl set-timezone {timezone}",
    "timedatectl_set_ntp": "timedatectl set-ntp {enabled}",
    "timedatectl_set_local_rtc": "timedatectl set-local-rtc {enabled}",
    "timedatectl_list_timezones": "timedatectl list-timezones",
    "timedatectl_show": "timedatectl show",

    # Journal/log management
    "journalctl": "journalctl --no-pager -n 50",
    "journal_rotate": "journalctl --rotate",
    "journal_vacuum_time": "journalctl --vacuum-time={time}",
    "journal_vacuum_size": "journalctl --vacuum-size={size}",
    "journal_vacuum_files": "journalctl --vacuum-files={count}",
    "journal_flush": "journalctl --flush",
    "journal_sync": "journalctl --sync",
    "journal_verify": "journalctl --verify",
    "journal_disk_usage": "journalctl --disk-usage",
    "journal_list_catalog": "journalctl --list-catalog",
    "journal_update_catalog": "journalctl --update-catalog",
    "journal_dump_catalog": "journalctl --dump-catalog",

    # Process management
    "ps_list_processes": "ps aux",
    "ps_list_threads": "ps -eLf",
    "ps_list_format_specifiers": "ps L",

    # Network/firewall
    "allow_port": "ufw allow {port}",
    "deny_port": "ufw deny {port}",
    "enable_firewall": "ufw --force enable",
    "disable_firewall": "ufw disable",
    "firewall_disable": "ufw disable",
    "ufw_disable": "ufw disable",
    "ufw_status_numbered": "ufw status numbered",
    "allow_traffic": "ufw allow {rule}",
    "add_firewall_rule": "iptables -A {chain} {rule}",
    "append_iptables_rule": "iptables -A {chain} {rule}",
    "append_rule": "iptables -A {chain} {rule}",
    "delete_rule": "iptables -D {chain} {rule}",
    "add_rule": "iptables -A {chain} {rule}",

    # Radio/wireless (rfkill)
    "radio_all_off": "rfkill block all",
    "radio_all_on": "rfkill unblock all",
    "radio_wwan_off": "rfkill block wwan",
    "radio_wwan_on": "rfkill unblock wwan",

    # Nohup
    "print_nohup_help": "nohup --help",
    "print_nohup_version": "nohup --version",

    # Top/terminal (interactive commands - safe no-ops)
    "top_show_user": "top -b -n 1 -u {user}",
    "top_toggle_window": "true",
    "top_toggle_window_name": "true",
    "top_toggle_forest_view": "true",
    "toggle_command_column_visibility": "true",
    "toggle_command_column_justification": "true",
    "make_command_column_last": "true",
    "resize_xterm": "true",

    # System status
    "status": "systemctl status --no-pager",

    # --- ADDITIONAL PACKAGE MANAGEMENT ---
    "apt": "apt list --installed",
    "apt_list": "apt list --installed",
    "apt_satisfy": "apt-get satisfy -y {package}",
    "apt_show": "apt-cache show {package}",
    "apt_why": "apt rdepends {package}",
    "apt_why_not": "apt-cache policy {package}",
    "autoclean_cache": "apt-get autoclean",
    "build_package": "dpkg-buildpackage -us -uc",
    "cache_apt_archives": "true",
    "cache_apt_archives_partial": "true",
    "cache_apt_lists": "true",
    "check_package": "dpkg -s {package}",
    "clean_cache": "apt-get clean",
    "cleanup_apt_lists": "rm -rf /var/lib/apt/lists/*",
    "compare_versions": "dpkg --compare-versions {version} gt {version}",
    "compile_source": "dpkg-buildpackage -us -uc",
    "dist_upgrade": "apt-get dist-upgrade -y",
    "download_only": "apt-get install -y --download-only {package}",
    "extract_package": "dpkg -x {package} {directory}",
    "extract_package_control": "dpkg -e {package} {directory}",
    "fetch_source_package": "apt-get source {package}",
    "hold_back_package": "apt-mark hold {package}",
    "install_dependencies": "apt-get install -y -f",
    "install_local_package": "dpkg -i {package}",
    "install_package_before_upgrade": "apt-get install -y {package}",
    "install_package_distribution": "apt-get install -y -t {release} {package}",
    "install_package_version": "apt-get install -y {package}={version}",
    "install_snap": "snap install {package}",
    "manage_package": "dpkg -s {package}",
    "merge_available": "dpkg --merge-avail {file}",
    "no_upgrade": "apt-get install -y --no-upgrade {package}",
    "output_package_ctrl_tarfile": "dpkg-deb --ctrl-tarfile {package}",
    "output_package_fsys_tarfile": "dpkg-deb --fsys-tarfile {package}",
    "print_package_avail": "dpkg --print-avail {package}",
    "reinstall_package": "apt-get install -y --reinstall {package}",
    "report_package_status": "dpkg -s {package}",
    "satisfy_dependencies": "apt-get install -y -f",
    "satisfy_dependency": "apt-get install -y -f",
    "search_package": "apt-cache search {package}",
    "set_selections": "dpkg --set-selections",
    "validate_version": "dpkg --compare-versions {version} gt 0",
    "vextract_package": "dpkg -X {package} {directory}",
    "display_package_field": "dpkg -s {package}",
    "list_package_contents": "dpkg -L {package}",
    "list_package_files": "dpkg -L {package}",
    "list_packages": "dpkg -l",

    # --- ADDITIONAL SNAP ---
    "snap_aliases": "snap aliases",
    "snap_components": "snap info {package}",
    "disable_snap": "snap disable {package}",
    "enable_snap": "snap enable {package}",
    "remove_snap": "snap remove {package}",
    "select_snapshot": "snap saved",

    # --- ADDITIONAL SERVICE MANAGEMENT ---
    "service_start": "systemctl start {service}",
    "service_stop": "systemctl stop {service}",
    "service_status": "systemctl status {service} --no-pager",
    "service_full_restart": "systemctl restart {service}",
    "service_full_restart_2": "systemctl restart {service}",

    # --- ADDITIONAL USER MANAGEMENT ---
    "create_home_dir": "mkhomedir_helper {user}",
    "create_home_directory": "mkdir -p /home/{user} && chown {user}:{user} /home/{user}",
    "create_mail_spool": "touch /var/mail/{user}",
    "create_non_unique_user": "useradd -o {user}",
    "create_system_account": "useradd -r {user}",
    "create_system_user": "useradd -r -s /usr/sbin/nologin {user}",
    "create_user_default_home": "useradd -m {user}",
    "create_user_group": "groupadd {user}",
    "create_user_with_default_group": "useradd -N {user}",
    "create_user_with_group": "useradd -U {user}",
    "create_user_with_home": "useradd -m {user}",
    "create_user_with_shell": "useradd -s {shell} {user}",
    "create_user_with_subgid": "useradd {user}",
    "create_user_with_subuid": "useradd {user}",
    "delete_mail_spool": "rm -f /var/mail/{user}",
    "execute_as_user": "su - {user} -c {command}",
    "force_delete_user": "userdel --force {user}",
    "force_remove_user": "userdel --force {user}",
    "lock_account": "usermod -L {user}",
    "lock_user_account": "usermod -L {user}",
    "lock_user_password": "passwd -l {user}",
    "modify_user_account": "usermod {user}",
    "move_home_directory": "usermod -d {home} -m {user}",
    "move_mail_spool": "true",
    "non_unique_user": "useradd -o {user}",
    "remove_at_jobs": "true",
    "remove_session_cache": "true",
    "remove_user_from_group": "gpasswd -d {user} {group}",
    "remove_user_home": "rm -rf /home/{user}",
    "run_login_shell": "su - {user}",
    "run_useradd_hook": "true",
    "run_userdel_cmd": "true",
    "start_login_shell": "su - {user}",
    "unlock_account": "usermod -U {user}",
    "update_default_user_info": "true",
    "update_lastlog": "true",
    "update_user_comment": "usermod -c {comment} {user}",
    "user_lock": "usermod -L {user}",
    "user_unlock": "usermod -U {user}",
    "userdel": "userdel {user}",
    "userdel_prefix": "userdel --prefix {prefix} {user}",
    "userdel_root": "userdel --root {root} {user}",
    "userdel_selinux_user": "userdel -Z {user}",
    "userdel_remove": "userdel -r {user}",
    "add_user_to_supplementary_groups": "usermod -aG {group} {user}",

    # --- PASSWD VARIANTS ---
    "passwd_delete": "passwd -d {user}",
    "passwd_display_status": "passwd -S {user}",
    "passwd_expire": "passwd -e {user}",
    "passwd_keep_tokens": "passwd -k {user}",
    "passwd_lock": "passwd -l {user}",
    "passwd_set_repository": "true",
    "passwd_stdin": "true",
    "passwd_unlock": "passwd -u {user}",
    "disable_password_aging": "chage -M -1 {user}",
    "list_account_aging": "chage -l {user}",
    "set_password": "true",
    "set_password_expiry": "chage -M {days} {user}",
    "set_password_grace_period": "chage -W {days} {user}",
    "set_password_inactive": "chage -I {days} {user}",
    "set_password_warning_age": "chage -W {file} root",
    "set_max_password_age": "chage -M {file} root",
    "set_min_password_age": "chage -m {file} root",
    "set_account_expiration": "chage -E {date} {user}",
    "set_user_expiration": "usermod -e {date} {user}",

    # --- GROUP MANAGEMENT ---
    "groupadd": "groupadd {group}",
    "groupadd_system": "groupadd -r {group}",
    "groupadd_with_gid": "groupadd -g {gid} {group}",
    "groupadd_with_password": "groupadd -p {password} {group}",
    "groupadd_with_users": "groupadd {group}",
    "groupmod_add_members": "gpasswd -a {user} {group}",
    "groupmod_set_chroot": "groupmod -R {root} {group}",
    "groupmod_set_gid": "groupmod -g {gid} {group}",
    "groupmod_set_name": "groupmod -n {name} {group}",
    "groupmod_set_prefix": "groupmod -P {prefix} {group}",
    "create_group_entry": "groupadd {group}",
    "create_group_with_gid": "groupadd -g {gid} {group}",
    "create_group_with_non_unique_gid": "groupadd -o -g {gid} {group}",
    "create_system_group": "groupadd -r {group}",
    "force_remove_group": "groupdel -f {group}",
    "remove_group": "groupdel {group}",
    "remove_group_in_chroot": "groupdel -R {root} {group}",
    "remove_group_in_prefix": "groupdel -P {prefix} {group}",
    "secure_group_account": "gpasswd -r {group}",
    "split_group": "true",
    "update_group_file": "grpconv",
    "chroot_group_operation": "true",
    "no_user_group": "true",

    # --- SUBORDINATE ID MANAGEMENT ---
    "add_sub_gids": "usermod --add-subgids {range} {user}",
    "add_sub_uids": "usermod --add-subuids {range} {user}",
    "add_subordinate_gids": "usermod --add-subgids {range} {user}",
    "add_subordinate_uids": "usermod --add-subuids {range} {user}",
    "allocate_subordinate_gids": "usermod --add-subgids 100000-165535 {user}",
    "allocate_subordinate_group_ids": "usermod --add-subgids 100000-165535 {user}",
    "allocate_subordinate_uids": "usermod --add-subuids 100000-165535 {user}",
    "remove_sub_gids": "usermod --del-subgids {range} {user}",
    "remove_sub_uids": "usermod --del-subuids {range} {user}",
    "remove_subordinate_gids": "usermod --del-subgids {range} {user}",
    "remove_subordinate_uids": "usermod --del-subuids {range} {user}",
    "update_subids": "true",
    "set_gid_range": "true",
    "set_uid_range": "true",

    # --- CHMOD VARIANTS ---
    "chmod": "chmod {mode} {file}",
    "chmod_dereference": "chmod {mode} {file}",
    "chmod_no_dereference": "chmod -h {mode} {file}",
    "chmod_no_preserve_root": "chmod --no-preserve-root {mode} {file}",
    "chmod_preserve_root": "chmod --preserve-root {mode} {file}",
    "chmod_recursive": "chmod -R {mode} {file}",
    "chmod_reference": "chmod --reference={reference} {file}",
    "chmod_silent": "chmod -f {mode} {file}",
    "chmod_verbose": "chmod -v {mode} {file}",
    "clear_setgid_bit": "chmod g-s {file}",
    "clear_suid_sgid_bits_numeric": "chmod 0{mode} {file}",
    "preserve_suid_sgid_bits": "true",
    "recursive_permission_change": "chmod -R {mode} {file}",
    "reference_file_mode": "chmod --reference={reference} {reference}",
    "set_file_mode": "chmod {mode} {file}",

    # --- CHOWN VARIANTS ---
    "chown_changes": "chown -c {user}:{group} {file}",
    "chown_dereference": "chown {user}:{group} {file}",
    "chown_no_dereference": "chown -h {user}:{group} {file}",
    "chown_owner": "chown {user} {file}",
    "chown_owner_group": "chown {user}:{group} {file}",
    "chown_preserve_root": "chown --preserve-root {user}:{group} {file}",
    "chown_recursive": "chown -R {user}:{group} {file}",
    "chown_silent": "chown -f {user}:{group} {file}",
    "chown_verbose": "chown -v {user}:{group} {file}",
    "change_group_only": "chgrp {group} {file}",
    "change_owner_group": "chown {user}:{group} {file}",
    "change_ownership_if_match": "chown --from={user} {user}:{group} {file}",
    "recursive_ownership_change": "chown -R root:root {file}",
    "reference_ownership": "chown --reference={reference} {file}",
    "use_reference_ownership": "chown --reference={reference} {file}",

    # --- TOUCH/TIMESTAMP VARIANTS ---
    "touch_file": "touch {file}",
    "touch_file_no_create": "touch -c {file}",
    "touch_file_no_dereference": "touch -h {file}",
    "touch_file_with_reference": "touch --reference={reference} {file}",
    "touch_file_with_time": "touch -t {time} {file}",
    "change_specific_timestamp": "touch -t {time} {file}",
    "change_symlink_timestamp": "touch -h {file}",
    "reference_file_times": "touch --reference={reference} {file}",
    "update_access_time": "touch -a {file}",
    "update_file_times": "touch {file}",
    "update_file_times_no_create": "touch -c {file}",
    "update_file_times_with_date": "touch -d {date} {file}",
    "update_file_times_with_stamp": "touch -t {time} {file}",
    "update_file_timestamp": "touch {file}",
    "update_modification_time": "touch -m {file}",

    # --- COPY VARIANTS ---
    "copy_all_files": "cp -a {source} {destination}",
    "copy_directory_recursively": "cp -r {source} {destination}",
    "copy_fail": "true",
    "copy_file_attributes_only": "cp --attributes-only {source} {destination}",
    "copy_file_backup": "cp --backup {source} {destination}",
    "copy_file_backup_existing": "cp --backup=existing {source} {destination}",
    "copy_file_backup_none": "cp --backup=none {source} {destination}",
    "copy_file_backup_numbered": "cp --backup=numbered {source} {destination}",
    "copy_file_backup_simple": "cp --backup=simple {source} {destination}",
    "copy_file_context_set_custom": "cp --context {source} {destination}",
    "copy_file_context_set_default": "cp -Z {source} {destination}",
    "copy_file_copy_contents": "cp --copy-contents {source} {destination}",
    "copy_file_debug": "cp --debug {source} {destination}",
    "copy_file_dereference": "cp -L {source} {destination}",
    "copy_file_force": "cp -f {source} {destination}",
    "copy_file_hard_link": "cp -l {source} {destination}",
    "copy_file_interactive": "cp -i {source} {destination}",
    "copy_file_keep_directory_symlink": "cp --keep-directory-symlink {source} {destination}",
    "copy_file_no_clobber": "cp -n {source} {destination}",
    "copy_file_no_dereference": "cp -P {source} {destination}",
    "copy_file_no_target_directory": "cp -T {source} {destination}",
    "copy_file_one_file_system": "cp -x {source} {destination}",
    "copy_file_parents": "cp --parents {source} {destination}",
    "copy_file_recursive": "cp -r {source} {destination}",
    "copy_file_reflink": "cp --reflink=auto {source} {destination}",
    "copy_file_remove_destination": "cp --remove-destination {source} {destination}",
    "copy_file_sparse_always": "cp --sparse=always {source} {destination}",
    "copy_file_sparse_never": "cp --sparse=never {source} {destination}",
    "copy_file_strip_trailing_slashes": "cp --strip-trailing-slashes {source} {destination}",
    "copy_file_suffix_set": "cp -S {suffix} {source} {destination}",
    "copy_file_symbolic_link": "cp -s {source} {destination}",
    "copy_file_target_directory": "cp -t {directory} {source}",
    "copy_file_to_directory": "cp {source} {directory}",
    "copy_file_update_all": "cp --update=all {source} {destination}",
    "copy_file_update_none": "cp --update=none {source} {destination}",
    "copy_file_update_none_fail": "cp --update=none-fail {source} {destination}",
    "copy_file_update_older": "cp -u {source} {destination}",
    "copy_files_to_directory": "cp {source} {directory}",
    "copy_no_clobber": "cp -n {source} {destination}",
    "copy_no_clobber_fail": "cp -n {source} {destination}",
    "copy_reflink": "cp --reflink=auto {source} {destination}",
    "copy_special_file_contents": "cp --copy-contents {source} {destination}",
    "copy_standard": "cp {source} {destination}",
    "copy_to_directory": "cp {source} {directory}",
    "copy_update_older": "cp -u {source} {destination}",
    "dereference_copy": "cp -L {source} {destination}",
    "fallback_copy": "cp {source} {destination}",
    "follow_symlink_copy": "cp -L {source} {destination}",
    "force_copy": "cp -f {source} {destination}",
    "hard_link_copy": "cp -l {source} {destination}",
    "hard_link_files": "ln {source} {destination}",
    "interactive_copy": "cp -i {source} {destination}",
    "lightweight_copy": "cp --reflink=auto {source} {destination}",
    "no_clobber_copy": "cp -n {source} {destination}",
    "no_dereference_copy": "cp -P {source} {destination}",
    "no_preserve_copy": "cp --no-preserve=all {source} {destination}",
    "preserve_attributes_copy": "cp -p {source} {destination}",
    "preserve_copy": "cp -p {source} {destination}",
    "recursive_copy": "cp -r {source} {destination}",
    "remove_destination_before_copy": "cp --remove-destination {source} {destination}",

    # --- MOVE VARIANTS ---
    "move_file_to_directory": "mv {source} {directory}",
    "move_to_directory": "mv {source} {directory}",
    "rename_file": "mv {source} {destination}",
    "replace_all_files": "mv -f {source} {destination}",
    "replace_older_files": "mv -u {source} {destination}",
    "enable_mv_backup": "true",
    "enable_mv_context": "true",
    "enable_mv_exchange": "true",
    "enable_mv_force": "true",
    "enable_mv_interactive": "true",
    "enable_mv_no_clobber": "true",
    "enable_mv_no_copy": "true",
    "enable_mv_no_target_directory": "true",
    "enable_mv_strip_trailing_slashes": "true",
    "enable_mv_update_all": "true",
    "enable_mv_update_none": "true",
    "enable_mv_update_older": "true",
    "enable_mv_verbose": "true",

    # --- SYMBOLIC LINK VARIANTS ---
    "create_symbolic_link": "ln -s {source} {destination}",
    "create_hard_link": "ln {source} {destination}",
    "create_relative_link": "ln -sr {source} {destination}",
    "create_force_link": "ln -sf {source} {destination}",
    "create_interactive_link": "ln -i {source} {destination}",
    "create_logical_link": "ln -L {source} {destination}",
    "create_physical_link": "ln -P {source} {destination}",
    "create_no_dereference_link": "ln -n {source} {destination}",
    "create_no_target_directory_link": "ln -T {source} {destination}",
    "create_target_directory_link": "ln -t {directory} {source}",
    "create_verbose_link": "ln -sv {source} {destination}",
    "create_backup_link": "ln --backup {source} {destination}",
    "modify_symbolic_link": "ln -sf {file} {file}",
    "dereference_symbolic_link": "readlink -f {file}",
    "dereference_symlinks": "readlink -f {file}",

    # --- DIRECTORY OPERATIONS ---
    "create_directory_verbose": "mkdir -pv {directory}",
    "create_directory_with_mode": "mkdir -m {mode} {directory}",
    "create_directory_with_parents": "mkdir -p {directory}",
    "remove_directory": "rm -rf {directory}",
    "remove_directory_force": "rm -rf {directory}",
    "remove_directory_interactive": "rm -ri {directory}",
    "remove_directory_recursively": "rm -rf {directory}",
    "remove_directory_verbose": "rm -rfv {directory}",
    "remove_empty_directories": "rmdir {directory}",
    "remove_empty_directory": "rmdir {directory}",
    "remove_file": "rm -f {file}",
    "remove_file_force": "rm -f {file}",
    "remove_file_interactive": "rm -i {file}",
    "remove_file_with_dash_prefix": "rm -- {file}",
    "remove_recursively": "rm -rf {file}",
    "remove_verbose": "rm -v {file}",
    "remove_with_preserve_root": "rm --preserve-root -rf {file}",
    "remove_one_file_system": "rm --one-file-system -rf {file}",
    "delete_files_manually": "rm -f {file}",

    # --- RM BEHAVIOR FLAGS (no-ops as they modify rm behavior) ---
    "no_preserve_root": "true",
    "preserve_root": "true",
    "prompt_according_to_when": "true",
    "prompt_always": "true",
    "prompt_before_removal": "true",
    "prompt_interactive": "true",
    "prompt_once": "true",

    # --- BACKUP VARIANTS (cp/mv backup modes) ---
    "backup_destination_file": "true",
    "backup_existing": "true",
    "backup_file": "cp --backup {source} {destination}",
    "backup_none": "true",
    "backup_numbered": "true",
    "backup_simple": "true",
    "backup_with_suffix": "true",
    "make_backup": "cp --backup {source} {destination}",
    "make_backup_force": "cp -f --backup {source} {destination}",
    "make_numbered_backup": "cp --backup=numbered {source} {destination}",
    "make_simple_backup": "cp --backup=simple {source} {destination}",
    "enable_existing_backups": "true",
    "enable_numbered_backups": "true",
    "enable_simple_backups": "true",
    "disable_backups": "true",
    "override_backup_suffix": "true",
    "set_version_control": "true",

    # --- FILE ATTRIBUTE/PRESERVE FLAGS ---
    "preserve_attributes": "true",
    "no_preserve_attributes": "true",
    "no_clobber": "true",
    "no_dereference": "true",
    "no_target_directory": "true",
    "strip_trailing_slashes": "true",
    "treat_dest_as_normal_file": "true",
    "control_file_update": "true",
    "control_file_updates": "true",
    "control_sparse_file_creation": "true",
    "create_sparse_file": "true",
    "create_temp_file_copies": "true",
    "inhibit_sparse_file": "true",
    "reject_separate_device": "true",
    "stay_on_filesystem": "true",
    "skip_different_filesystem": "true",
    "skip_files": "true",

    # --- SYMLINK TRAVERSAL FLAGS ---
    "do_not_traverse_symbolic_links": "true",
    "do_not_treat_root_special": "true",
    "follow_command_line_symlinks": "true",
    "follow_directory_symlinks": "true",
    "no_traverse_symlinks": "true",
    "skip_symbolic_links": "true",
    "traverse_all_symbolic_links": "true",
    "traverse_all_symlinks": "true",
    "traverse_symbolic_link_hierarchy": "true",
    "traverse_symbolic_links": "true",

    # --- GETFACL VARIANTS ---
    "getfacl_absolute_names": "getfacl --absolute-names {file}",
    "getfacl_access": "getfacl --access {file}",
    "getfacl_all_effective": "getfacl --all-effective {file}",
    "getfacl_default": "getfacl --default {file}",
    "getfacl_logical": "getfacl -L {file}",
    "getfacl_no_effective": "getfacl --no-effective {file}",
    "getfacl_numeric": "getfacl --numeric {file}",
    "getfacl_omit_header": "getfacl --omit-header {file}",
    "getfacl_physical": "getfacl -P {file}",
    "getfacl_recursive": "getfacl -R {file}",
    "getfacl_skip_base": "getfacl --skip-base {file}",
    "getfacl_tabular": "getfacl --tabular {file}",

    # --- SETFACL VARIANTS ---
    "set_acl_default_copy": "setfacl -d -m {acl} {file}",
    "set_acl_mask_adjust": "setfacl --mask {file}",
    "set_acl_modify": "setfacl -m {acl} {file}",
    "set_acl_remove": "setfacl -x {acl} {file}",

    # --- IPTABLES/FIREWALL ---
    "accept_packet": "iptables -A INPUT -j ACCEPT",
    "drop_packet": "iptables -A INPUT -j DROP",
    "block_traffic": "ufw deny {port}",
    "create_chain": "iptables -N {chain}",
    "create_firewall_chain": "nft add chain {table} {chain}",
    "define_firewall_table": "nft add table {table}",
    "delete_chain": "iptables -X {chain}",
    "delete_empty_chains": "iptables -X",
    "delete_firewall_chain": "nft delete chain {table} {chain}",
    "delete_firewall_rule": "nft delete rule {table} {chain} handle {handle}",
    "delete_iptables_rule": "iptables -D {chain} {rule}",
    "delete_iptables_rule_by_num": "iptables -D {chain} {number}",
    "delete_referring_rules": "iptables -X {chain}",
    "flush_chain": "iptables -F {chain}",
    "flush_firewall_rules": "nft flush ruleset",
    "flush_rules": "iptables -F",
    "goto_chain": "true",
    "insert_firewall_rule": "iptables -I {chain} {rule}",
    "insert_iptables_rule": "iptables -I {chain} {rule}",
    "insert_rule_with_ipv4_option": "iptables -4 -I INPUT {rule}",
    "insert_rule_with_ipv6_option": "ip6tables -I INPUT {rule}",
    "jump_target": "true",
    "jump_to_chain": "true",
    "jump_to_target": "true",
    "rename_chain": "iptables -E {chain} {new_chain}",
    "rename_firewall_chain": "nft rename chain {table} {chain} {new_chain}",
    "replace_firewall_rule": "iptables -R {chain} {number} {rule}",
    "replace_iptables_rule": "iptables -R INPUT 1 -j ACCEPT",
    "return_from_chain": "true",
    "set_chain_policy": "iptables -P {chain} {policy}",
    "zero_counters": "iptables -Z",
    "set_counters": "iptables -c {packets} {bytes}",
    "load_iptables_modules": "true",
    "iptables_setuid_error": "true",
    "set_table": "true",

    # --- IPTABLES MATCH/PROTOCOL FLAGS ---
    "change_policy": "iptables -P {chain} {policy}",
    "extended_match": "true",
    "invert_address_sense": "true",
    "invert_protocol_test": "true",
    "match_fragmented_packets": "true",
    "match_fragments": "true",
    "match_head_fragments": "true",
    "specify_match_extension": "true",
    "set_in_interface": "true",
    "set_out_interface": "true",
    "set_output_interface": "true",
    "set_protocol": "true",
    "set_protocol_family": "true",
    "set_rule_protocol": "true",
    "set_network_mask": "true",
    "numeric_output": "true",
    "register_netfilter_hook": "true",

    # --- FIREWALL RULE ACTIONS (nft actions) ---
    "firewall_rule_accept": "true",
    "firewall_rule_conntrack": "true",
    "firewall_rule_continue": "true",
    "firewall_rule_counter": "true",
    "firewall_rule_drop": "true",
    "firewall_rule_extension_set": "true",
    "firewall_rule_goto": "true",
    "firewall_rule_jump": "true",
    "firewall_rule_log": "true",
    "firewall_rule_payload_set": "true",
    "firewall_rule_queue": "true",
    "firewall_rule_reject": "true",
    "firewall_rule_return": "true",

    # --- ADD FIREWALL RULE VARIANTS ---
    "add_firewall_rule_dscp": "iptables -A INPUT -m dscp --dscp {value}",
    "add_firewall_rule_ecn": "iptables -A INPUT -m ecn --ecn-tcp-cwr",
    "add_firewall_rule_icmp_checksum": "iptables -A INPUT -p icmp -j ACCEPT",
    "add_firewall_rule_icmp_code": "iptables -A INPUT -p icmp --icmp-type {value}",
    "add_firewall_rule_icmp_gateway": "iptables -A INPUT -p icmp -j ACCEPT",
    "add_firewall_rule_icmp_id": "iptables -A INPUT -p icmp -j ACCEPT",
    "add_firewall_rule_icmp_mtu": "iptables -A INPUT -p icmp -j ACCEPT",
    "add_firewall_rule_icmp_sequence": "iptables -A INPUT -p icmp -j ACCEPT",
    "add_firewall_rule_icmp_type": "iptables -A INPUT -p icmp --icmp-type {value}",
    "add_firewall_rule_icmpv6_checksum": "ip6tables -A INPUT -p icmpv6 -j ACCEPT",
    "add_firewall_rule_icmpv6_code": "ip6tables -A INPUT -p icmpv6 -j ACCEPT",
    "add_firewall_rule_icmpv6_daddr": "ip6tables -A INPUT -p icmpv6 -j ACCEPT",
    "add_firewall_rule_icmpv6_id": "ip6tables -A INPUT -p icmpv6 -j ACCEPT",
    "add_firewall_rule_icmpv6_max_delay": "ip6tables -A INPUT -p icmpv6 -j ACCEPT",
    "add_firewall_rule_icmpv6_packet_too_big": "ip6tables -A INPUT -p icmpv6 --icmpv6-type packet-too-big -j ACCEPT",
    "add_firewall_rule_icmpv6_parameter_problem": "ip6tables -A INPUT -p icmpv6 --icmpv6-type parameter-problem -j ACCEPT",
    "add_firewall_rule_icmpv6_sequence": "ip6tables -A INPUT -p icmpv6 -j ACCEPT",
    "add_firewall_rule_icmpv6_taddr": "ip6tables -A INPUT -p icmpv6 -j ACCEPT",
    "add_firewall_rule_icmpv6_type": "ip6tables -A INPUT -p icmpv6 -j ACCEPT",
    "add_firewall_rule_igmp_checksum": "iptables -A INPUT -p igmp -j ACCEPT",
    "add_firewall_rule_igmp_group": "iptables -A INPUT -p igmp -j ACCEPT",
    "add_firewall_rule_igmp_mrt": "iptables -A INPUT -p igmp -j ACCEPT",
    "add_firewall_rule_igmp_type": "iptables -A INPUT -p igmp -j ACCEPT",
    "add_firewall_rule_ip": "iptables -A INPUT -j ACCEPT",
    "add_firewall_rule_ip6": "ip6tables -A INPUT -j ACCEPT",
    "add_firewall_rule_ip6_dscp": "ip6tables -A INPUT -m dscp --dscp {value}",
    "add_firewall_rule_ip6_ecn": "ip6tables -A INPUT -m ecn --ecn-tcp-cwr",
    "add_firewall_rule_ip6_flowlabel": "ip6tables -A INPUT -j ACCEPT",
    "add_firewall_rule_ip6_hoplimit": "ip6tables -A INPUT -m hl --hl-eq {value}",
    "add_firewall_rule_ip6_length": "ip6tables -A INPUT -m length --length {value}",
    "add_firewall_rule_ip6_nexthdr": "ip6tables -A INPUT -j ACCEPT",
    "add_firewall_rule_ip6_version": "ip6tables -A INPUT -j ACCEPT",
    "add_firewall_rule_port": "iptables -A INPUT -p tcp --dport {port}",
    "add_firewall_rule_proto": "iptables -A INPUT -p {protocol}",
    "add_inspect_entry": "true",
    "add_rule_nat_prerouting_dnat_to_jhash_ip_saddr_mod_2_map": "true",
    "add_rule_nat_prerouting_dnat_to_symhash_mod_2_map": "true",
    "create_filter": "iptables -N FILTER",

    # --- NFT VARIANTS ---
    "nft_add_counter": "nft add counter {rule}",
    "nft_add_ct_expectation": "nft add ct expectation {rule}",
    "nft_add_ct_timeout": "nft add ct timeout {rule}",
    "nft_add_quota": "nft add quota {rule}",
    "nft_add_rule": "nft add rule {rule}",
    "nft_delete_rule": "nft delete rule {rule}",
    "remove_filter": "nft delete table {table}",

    # --- UFW VARIANTS ---
    "ufw_allow": "ufw allow {port}",
    "ufw_allow_ah": "ufw allow proto ah from {source}",
    "ufw_allow_esp": "ufw allow proto esp from {source}",
    "ufw_allow_from": "ufw allow from {source}",
    "ufw_allow_ipv6": "ufw allow {port}",
    "ufw_allow_to": "ufw allow to {destination}",
    "ufw_allow_vrrp": "ufw allow proto 112 from {source}",
    "ufw_deny": "ufw deny {port}",
    "ufw_drop": "ufw deny {port}",
    "ufw_reject": "ufw reject {port}",
    "open_port": "ufw allow {port}",

    # --- TCP/UDP/SCTP FLAG CHECKS ---
    "tcp_flag_exists": "true",
    "udp_flag_exists": "true",
    "sctp_chunk_exists": "true",
    "sctp_field_exists": "true",

    # --- SOCKET (SS) OPERATIONS ---
    "socket_bpf_info": "ss --bpf",
    "socket_cgroup_info": "ss --cgroup",
    "socket_close": "ss -K",
    "socket_context": "ss -Z",
    "socket_contexts": "ss -Z",
    "socket_dccp": "ss --dccp",
    "socket_events": "ss -E",
    "socket_exists": "ss -tuln",
    "socket_extended_info": "ss -e",
    "socket_internal_info": "ss -i",
    "socket_ipv4": "ss -4",
    "socket_ipv6": "ss -6",
    "socket_memory_usage": "ss -m",
    "socket_mptcp": "ss --mptcp",
    "socket_namespace": "ss -N {namespace}",
    "socket_packet": "ss -0",
    "socket_process_info": "ss -p",
    "socket_raw": "ss -w",
    "socket_sctp": "ss --sctp",
    "socket_summary": "ss -s",
    "socket_tcp": "ss -t",
    "socket_thread_info": "ss --threads",
    "socket_timer_info": "ss -o",
    "socket_tipc": "ss --tipc",
    "socket_tipcinfo": "ss --tipc -i",
    "socket_tos_info": "ss --tos",
    "socket_udp": "ss -u",
    "socket_unix": "ss -x",
    "socket_vsock": "ss --vsock",
    "socket_xdp": "ss --xdp",

    # --- LOCALECTL VARIANTS ---
    "localectl_disable_pager": "localectl --no-pager status",
    "localectl_enable_colors": "true",
    "localectl_enable_secure_pager": "true",
    "localectl_enable_urlify": "true",
    "localectl_set_keyboard_layout": "localectl set-keymap {layout}",
    "localectl_set_locale": "localectl set-locale {locale}",

    # --- TIMEDATECTL ADDITIONAL ---
    "timedatectl_ntp_servers": "timedatectl ntp-servers {interface} {server}",
    "timedatectl_revert": "timedatectl revert",
    "timedatectl_show_status": "timedatectl status",
    "timedatectl_show_timesync": "timedatectl timesync-status",
    "timedatectl_status": "timedatectl status",
    "timedatectl_timesync_status": "timedatectl timesync-status",
    "disable_ntp": "timedatectl set-ntp false",
    "enable_ntp": "timedatectl set-ntp true",

    # --- HOSTNAMECTL ADDITIONAL ---
    "hostnamectl_help": "hostnamectl --help",
    "hostnamectl_host": "hostnamectl set-hostname {hostname}",
    "hostnamectl_json": "hostnamectl status --json=short",
    "hostnamectl_json_off": "hostnamectl status",
    "hostnamectl_json_pretty": "hostnamectl status --json=pretty",
    "hostnamectl_json_short": "hostnamectl status --json=short",
    "hostnamectl_machine": "hostnamectl -M {machine} status",
    "hostnamectl_no_ask_password": "hostnamectl --no-ask-password status",
    "hostnamectl_version": "hostnamectl --version",

    # --- JOURNALCTL ADDITIONAL ---
    "journalctl_with_field": "journalctl --no-pager -n 50 {field}={value}",
    "journalctl_with_two_fields": "journalctl --no-pager -n 50 {field}={value}",
    "journal_entry_filter_by_after_cursor": "journalctl --after-cursor={cursor} --no-pager -n 50",
    "journal_entry_filter_by_boot": "journalctl -b --no-pager -n 50",
    "journal_entry_filter_by_case_sensitive": "journalctl --case-sensitive --no-pager -n 50",
    "journal_entry_filter_by_cursor": "journalctl --cursor={cursor} --no-pager -n 50",
    "journal_entry_filter_by_cursor_file": "journalctl --cursor-file={file} --no-pager -n 50",
    "journal_entry_filter_by_exclude_identifier": "journalctl --no-pager -n 50",
    "journal_entry_filter_by_facility": "journalctl --facility={facility} --no-pager -n 50",
    "journal_entry_filter_by_grep": "journalctl -g {pattern} --no-pager -n 50",
    "journal_entry_filter_by_identifier": "journalctl -t {identifier} --no-pager -n 50",
    "journal_entry_filter_by_invoc": "journalctl --no-pager -n 50",
    "journal_entry_filter_by_kernel": "journalctl -k --no-pager -n 50",
    "journal_entry_filter_by_output": "journalctl -o {format} --no-pager -n 50",
    "journal_entry_filter_by_priority": "journalctl -p {priority} --no-pager -n 50",
    "journal_entry_filter_by_unit": "journalctl -u {unit} --no-pager -n 50",
    "journal_entry_filter_by_user_unit": "journalctl --user-unit={unit} --no-pager -n 50",
    "show_kernel_logs": "journalctl -k --no-pager -n 50",
    "show_live_logs": "journalctl -f --no-pager -n 50",
    "show_logs": "journalctl --no-pager -n 50",
    "show_active_filters": "journalctl --no-pager -n 50",
    "output_oneline": "journalctl -o short --no-pager -n 50",

    # --- NETPLAN ---
    "netplan_apply": "netplan apply",
    "netplan_generate": "netplan generate",
    "netplan_get": "netplan get",
    "netplan_set": "netplan set {setting}",
    "netplan_status": "netplan status",
    "netplan_try": "netplan try",

    # --- SYSCTL ---
    "sysctl_force_write": "sysctl -w {key}={value}",
    "sysctl_load_config": "sysctl -p",
    "sysctl_write": "sysctl -w {key}={value}",

    # --- MODPROBE ---
    "modprobe_command": "modprobe {module}",
    "set_modprobe_command": "true",

    # --- IP / NETWORK MANAGEMENT ---
    "bring_down_interface": "ip link set {interface} down",
    "bring_up_interface": "ip link set {interface} up",
    "disable_interface": "ip link set {interface} down",
    "enable_interface": "ip link set {interface} up",
    "switch_network_namespace": "ip netns exec {namespace} true",
    "tunnel_over_ip": "ip tunnel show",
    "manage_ipsec_policies": "ip xfrm policy show",
    "manage_ipv6_segment_routing": "ip sr show",
    "manage_tcp_metrics": "ip tcp_metrics show",
    "manage_tokenized_interface_identifiers": "true",
    "manage_tun_tap_devices": "ip tuntap show",
    "manage_vrf_devices": "ip vrf show",
    "configure_addrlabel": "ip addrlabel list",
    "configure_fou": "ip fou show",
    "configure_ila": "ip ila list",
    "configure_ioam": "true",
    "configure_l2tp": "ip l2tp show session",
    "configure_link": "ip link show",
    "configure_macsec": "ip macsec show",
    "configure_maddress": "ip maddress show",
    "configure_monitor": "true",
    "configure_mptcp": "ip mptcp endpoint show",
    "configure_mroute": "ip mroute show",
    "configure_mrule": "ip mrule show",
    "configure_neigh": "ip neigh show",
    "configure_netns": "ip netns list",
    "configure_route": "ip route show",
    "configure_rule": "ip rule show",
    "configure_tunnel": "ip tunnel show",
    "configure_xfrm": "ip xfrm state list",

    # --- PROCESS MANAGEMENT ADDITIONAL ---
    "ps_print_debug_info": "ps --info",
    "ps_print_version": "ps --version",
    "ps_set_wide_output": "ps auxww",
    "send_signal": "kill {signal} {process}",
    "send_signal_to_group": "kill -{signal} -{group}",
    "terminate_child": "kill {process}",
    "list_signals": "kill -l",
    "list_signals_table": "kill -L",
    "pgrep_help": "pgrep --help",
    "pgrep_ignore_ancestors": "pgrep --ignore-ancestors",
    "pgrep_version": "pgrep --version",
    "run_nice_command": "nice -n {priority} {command}",
    "display_nice_help": "nice --help",
    "display_nice_version": "nice --version",
    "sleep": "sleep 1",
    "start_top": "top -b -n 1",

    # --- DISPLAY/STAT ---
    "display_stat": "stat {file}",
    "display_stat_filesystem": "stat -f {file}",
    "display_stat_format": "stat -c {format} {file}",
    "display_stat_terse": "stat -t {file}",
    "display_whoami_help": "whoami --help",
    "display_whoami_version": "whoami --version",

    # --- SYSTEMCTL/LIST VARIANTS ---
    "list": "systemctl list-units --no-pager",
    "list_automounts": "systemctl list-units --type=automount --no-pager",
    "list_paths": "systemctl list-units --type=path --no-pager",
    "list_sockets": "systemctl list-units --type=socket --no-pager",
    "list_timers": "systemctl list-units --type=timer --no-pager",
    "list_units": "systemctl list-units --no-pager",

    # --- SELINUX ---
    "set_security_context": "true",
    "set_selinux_context": "true",
    "set_selinux_context_custom": "true",
    "set_selinux_range": "true",
    "set_selinux_user": "true",
    "remove_selinux_user": "true",
    "remove_selinux_user_mapping": "true",
    "update_selinux_user_mapping": "true",
    "configure_mandatory_access_control": "true",

    # --- MISC CONFIG/SET FLAGS ---
    "activate_build_profiles": "true",
    "add_line_numbers": "true",
    "add_source_file": "true",
    "allow_bad_names": "true",
    "allow_downgrades": "true",
    "allow_insecure_repositories": "true",
    "allow_new_packages": "true",
    "allow_releaseinfo_change": "true",
    "allow_unauthenticated": "true",
    "apply_changes_chroot": "true",
    "apply_changes_prefix": "true",
    "apply_chroot_changes": "true",
    "apply_config_changes": "true",
    "apply_temp_file_changes": "true",
    "assert_feature": "true",
    "change_default_options": "true",
    "check_sudoers_file": "visudo -c",
    "chroot_directory": "chroot {directory}",
    "configure_apt": "apt-get update",
    "configure_apt_fragments": "true",
    "configure_apt_partial_state_directory": "true",
    "configure_apt_preferences": "true",
    "configure_apt_preferences_fragments": "true",
    "configure_apt_state_directory": "true",
    "configure_package": "dpkg --configure -a",
    "configure_top": "true",
    "allocate_pty": "su - {user}",
    "create_pty": "true",
    "exact_output": "true",
    "disable_download": "true",
    "disable_root_preservation": "true",
    "edit_file": "true",
    "edit_file_as_user": "true",
    "edit_files": "true",
    "edit_sources": "true",
    "edit_sudoers_file": "visudo",
    "edit_temp_files": "true",
    "enable_root_preservation": "true",
    "error_on_any": "true",
    "execute_command_on_all_objects": "true",
    "exit": "true",
    "expand_numbers": "true",
    "force_overwrite": "true",
    "ignore_holds": "true",
    "ignore_missing": "true",
    "interactive_overwrite": "true",
    "no_upgrade": "apt-get install -y --no-upgrade {package}",
    "obtain_lock": "true",
    "perform_switcheroo": "true",
    "quiet_mode": "true",
    "read_default_config": "true",
    "refresh_sudo_timestamp": "true",
    "remove_print_jobs": "true",
    "reset_environment": "true",
    "reset_resource_limits": "true",
    "run_additional_command": "true",
    "set_apt_config": "true",
    "set_color_output": "true",
    "set_config_option": "true",
    "set_default_group": "true",
    "set_default_release": "apt-get -t {release} update",
    "set_default_shell": "usermod -s {file} root",
    "set_firewall_policy": "iptables -P {chain} {policy}",
    "set_gecos_field": "usermod -c {comment} {user}",
    "set_group_password": "gpasswd {group}",
    "set_home_directory": "usermod -d {home} {user}",
    "set_host_architecture": "dpkg --add-architecture {architecture}",
    "set_log_color": "true",
    "set_log_location": "true",
    "set_log_ratelimit": "true",
    "set_log_target": "true",
    "set_log_tid": "true",
    "set_log_time": "true",
    "set_login_shell": "usermod -s /bin/bash {user}",
    "set_pager": "true",
    "set_pager_secure": "true",
    "set_prefix": "true",
    "set_primary_group": "usermod -g {group} {user}",
    "set_supplementary_groups": "usermod -G {groups} {user}",
    "set_trivial_only": "true",
    "set_umask": "umask {mode}",
    "set_update_mode": "true",
    "set_urlify": "true",
    "set_user_comment": "usermod -c {comment} {user}",
    "set_user_groups": "usermod -G {groups} {user}",
    "set_user_shell": "usermod -s {shell} {user}",
    "set_user_uid": "usermod -u 1000 {user}",
    "set_usergroups_ena": "true",
    "set_wait_time": "true",
    "skip_log_init": "true",
    "skip_user_group_creation": "true",
    "soft": "true",
    "switch": "true",
    "use_config_file": "true",
    "use_extra_users": "true",
    "wait_for_lock": "true",
    "update_available": "dpkg --update-avail",
    "update_before_command": "apt-get update",
    "update_package": "apt-get install --only-upgrade -y {package}",
    "update_package_index": "apt-get update",
    "update_package_lists": "apt-get update",

    # --- MOVE COLUMN / TOGGLE (interactive no-ops) ---
    "move_right_in_command_column": "true",
    "toggle_color": "true",
    "toggle_forest_view": "true",
    "toggle_top_windows": "true",
    "configure_color_output": "true",

    # --- ARCHIVE/SOURCE ---
    "apt_edit_sources": "true",
    "apt_full_upgrade": "apt-get full-upgrade -y",
    "apt_autoremove": "apt-get autoremove -y",
    "apt_install": "apt-get install -y {package}",
    "apt_purge": "apt-get purge -y {package}",
    "apt_remove": "apt-get remove -y {package}",
    "apt_search": "apt-cache search {package}",
    "apt_update": "apt-get update",
    "apt_upgrade": "apt-get upgrade -y",

    # --- SHOW VARIANTS ---
    "show_package_info": "dpkg -s {package}",

    # --- CHAGE (password aging) ---
    "chage_list_info": "chage -l {user}",
    "chage_set_expiredate": "chage -E {value} {user}",
    "chage_set_inactive": "chage -I {value} {user}",
    "chage_set_lastday": "chage -d {value} {user}",
    "chage_set_maxdays": "chage -M {value} {user}",
    "chage_set_mindays": "chage -m {value} {user}",
    "chage_set_prefix": "true",
    "chage_set_root": "true",
    "chage_set_warndays": "chage -W {value} {user}",

    # --- FIREWALL RULE VARIANTS (deny/reject/limit/prepend/insert/check) ---
    "deny_firewall_rule": "iptables -A {chain} -i {interface} -p tcp --dport {port} -j DROP",
    "reject_firewall_rule": "iptables -A {chain} -i {interface} -p tcp --dport {port} -j REJECT",
    "limit_firewall_rule": "iptables -A {chain} -i {interface} -p tcp --dport {port} -m limit --limit 25/minute -j ACCEPT",
    "prepend_firewall_rule": "iptables -I INPUT 1 -j ACCEPT",
    "insert_rule": "iptables -I {chain} {rule}",
    "check_rule": "iptables -C {chain} -j ACCEPT",
    "rename_firewall_chain": "iptables -E {chain} {new_chain}",
    "match_all_protocols": "true",

    # --- SERVICE MANAGEMENT (clean/kill/status) ---
    "clean_service": "systemctl reset-failed {service}",
    "kill_service": "systemctl kill {service}",

    # --- SU / USER SWITCHING ---
    "switch_user": "su - {user}",
    "execute_command_as_user": "su - {user} -c {command}",

    # --- SOCKET / BPF QUERIES ---
    "dump_socket_data": "ss -a",
    "query_bpf_map_data": "ss --bpf",
    "query_socket_by_device": "ss -i",
    "query_socket_by_family": "ss -f {family}",
    "query_socket_by_port": "ss -tuln sport = :{port}",
    "query_socket_by_state": "ss state {state}",
    "query_socket_by_table": "ss -a",

    # --- PS LIST VARIANTS ---
    "ps_list_by_command": "ps aux",
    "ps_list_by_group": "ps -G {group}",
    "ps_list_by_parent": "ps --ppid {process}",
    "ps_list_by_pid": "ps -p {process}",
    "ps_list_by_session": "ps -s {session}",
    "ps_list_by_terminal": "ps -t {interface}",
    "ps_list_by_user": "ps -u {user}",
    "ps_list_running": "ps aux",

    # --- ACL OPERATIONS ---
    "test_acl": "getfacl {file}",
    "restore_acl": "setfacl --restore={file}",

    # --- FILE / CONFIG READS ---
    "read_filter_from_file": "cat {file}",
    "read_su_config": "cat {file}",
    "check": "true",
}

# Predicate state checks: how to verify PDDL predicates in the real environment
PREDICATE_CHECKS = {
    # Package predicates
    "package_installed": "dpkg -s {package} 2>/dev/null | grep -q 'Status: install ok installed'",
    "package_outdated": "apt list --upgradable 2>/dev/null | grep -q '^{package}/'",
    "package": "dpkg -s {package} 2>/dev/null | grep -q 'Status: install ok installed'",

    # Service predicates
    "service_running": "systemctl is-active --quiet {service}",
    "service_enabled": "systemctl is-enabled --quiet {service}",
    "service_failed": "systemctl is-failed --quiet {service}",
    "service": "systemctl is-active --quiet {service} 2>/dev/null || systemctl list-unit-files {service}.service --no-pager -q | grep -q .",

    # User predicates
    "user_exists": "id {user} >/dev/null 2>&1",
    "user_locked": "passwd -S {user} 2>/dev/null | grep -q ' L '",
    "user": "id {user} >/dev/null 2>&1",

    # Group predicates
    "group_exists": "getent group {group} >/dev/null 2>&1",
    "member_of": "id -nG {user} 2>/dev/null | grep -qw {group}",
    "group": "getent group {group} >/dev/null 2>&1",

    # File predicates
    "file_exists": "test -e {file}",
    "file_readable": "test -r {file}",
    "file_writable": "test -w {file}",
    "file_executable": "test -x {file}",
    "directory_exists": "test -d {directory}",

    # Network predicates
    "port_open": "ss -tuln | grep -q ':{port} '",
    "interface_up": "ip link show {interface} | grep -q 'state UP'",
}
