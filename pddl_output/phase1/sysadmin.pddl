(define (domain sysadmin)

  (:requirements :strips :typing :negative-preconditions)

  (:types
    ; Base types
    
    ; Filesystem types
    filesystem_object - object
    file directory - filesystem_object
    configuration_file - file
    
    ; Execution types
    service process - object
    
    ; Package management types
    package repository - object
    
    ; Access control types
    user group - object
    system_user human_user - user
    
    ; Network types
    port interface firewall_rule - object
  )

  (:predicates
    ; Dynamic state predicates - Packages
    (package_installed ?p - package)
    (package_outdated ?p - package)
    (package_configured ?p - package)
    (vulnerable ?p - package)
    ; Dynamic state predicates - Services
    (service_exists ?s - service)
    (service_running ?s - service)
    (service_enabled ?s - service)
    (service_failed ?s - service)
    (config_applied ?s - service)
    ; Dynamic state predicates - Filesystem
    (file_exists ?f - filesystem_object)
    (file_readable ?f - filesystem_object)
    (file_writable ?f - filesystem_object)
    (file_critical ?f - filesystem_object)
    ; Dynamic state predicates - Users
    (user_exists ?u - user)
    (user_critical ?u - user)
    (user_locked ?u - user)
    (can_escalate ?u - user)
    ; Dynamic state predicates - Groups
    (group_exists ?g - group)
    ; Dynamic state predicates - Network
    (port_open ?p - port)
    (port_allowed ?p - port)
    (interface_exists ?i - interface)
    (interface_up ?i - interface)
    ; Dynamic state predicates - Firewall
    (firewall_rule_exists ?r - firewall_rule)
    (traffic_blocked ?r - firewall_rule)
    ; Dynamic state predicates - Processes
    (process_running ?pr - process)
    (executed_as_root ?pr - process)
    ; Static relationship predicates
    (depends_on ?s - service ?p - package)
    (configures ?f - configuration_file ?s - service)
    (file_owned_by ?f - filesystem_object ?u - user)
    (member_of ?u - user ?g - group)
    ; Environment predicates
    (network_available)
    (requires_env_preservation ?pr - process)
    ; Dynamically Discovered Predicates
    (package_list_updated)
    (package_index_updated)
    (package_exists ?x0 - object)
    (package_reverted ?x0 - object)
    (file_modified ?x0 - object)
    (apt_option_changed ?x0 - object)
    (packages_upgraded)
    (system_upgraded)
    (unnecessary_packages_installed)
    (unnecessary_packages_removed)
    (cache_exists)
    (cache_cleared)
    (old_cache_exists)
    (old_cache_removed)
    (build_deps_installed ?x0 - object)
    (apt_install_recommends_disabled)
    (apt_install_suggests_enabled)
    (packages_downloaded)
    (broken_dependencies_exist)
    (broken_dependencies_fixed)
    (download_disabled)
    (quiet_mode_set ?x0 - object)
    (simulation_performed)
    (requires_root)
    (apt_lists_cleaned)
    (snapshot_enabled)
    (snapshot_selected ?x0 - object)
    (package_pinned ?x0 - object)
    (trivial_operations_only)
    (package_automatically_installed ?x0 - object)
    (aborted ?x0 - object)
    (package_required ?x0 - object)
    (package_removed ?x0 - object)
    (apt_config_set ?x0 - object ?x1 - object)
    (apt_diff_downloaded ?x0 - object)
    (apt_dsc_downloaded ?x0 - object)
    (apt_tar_downloaded ?x0 - object)
    (apt_arch_deps_processed ?x0 - object)
    (apt_indep_deps_processed ?x0 - object)
    (apt_unauthenticated_allowed ?x0 - object)
    (allow_insecure_repositories)
    (allow_releaseinfo_change)
    (source_file_added ?x0 - object)
    (error_on_any_enabled)
    (update_run_before_command)
    (apt_config_option_set ?x0 - object)
    (apt_color_setting ?x0 - object)
    (file_executable ?x0 - object)
    (directory_exists ?x0 - object)
    (state_storage_set ?x0 - object)
    (package_lists_updated)
    (package_enabled ?x0 - object)
    (pending_change_exists ?x0 - object)
    (change_aborted ?x0 - object)
    (assertion_valid ?x0 - object)
    (signature_verified ?x0 - object)
    (assertion_consistent ?x0 - object)
    (assertion_added ?x0 - object)
    (alias_exists ?x0 - object ?x1 - object)
    (snap_plug_connected ?x0 - object ?x1 - object ?x2 - object ?x3 - object)
    (cohort_keys_created ?x0 - object)
    (snap_installed)
    (seeding_details_obtained ?x0 - object)
    (stacktraces_obtained)
    (snapd_state_inspected ?x0 - object)
    (snapd_state_inspected_bypass ?x0 - object)
    (task_exists ?x0 - object)
    (task_inspected ?x0 - object)
    (change_exists ?x0 - object)
    (change_inspected ?x0 - object)
    (seeding_status_output)
    (dot_output_generated)
    (hold_tasks_omitted)
    (connection_forgotten ?x0 - object)
    (snapshot_exported ?x0 - object)
    (quota_group_exists ?x0 - object)
    (memory_limit_increased ?x0 - object)
    (memory_limit_decreased ?x0 - object)
    (cpu_limit_increased ?x0 - object)
    (cpu_limit_decreased ?x0 - object)
    (cpu_set_modified ?x0 - object)
    (threads_limit_increased ?x0 - object)
    (quota_threads_decreased ?x0 - object)
    (journal_limits_increased ?x0 - object)
    (journal_limits_set ?x0 - object)
    (journal_limits_decreased ?x0 - object)
    (quotas_set ?x0 - object)
    (quota_group_removed ?x0 - object)
    (quota_group_recreated ?x0 - object)
    (snap_exists ?x0 - object)
    (snaps_added ?x0 - object)
    (services_restarted ?x0 - object)
    (cpu_quota_set ?x0 - object ?x1 - object ?x2 - object ?x3 - object)
    (key_exists ?x0 - object)
    (assertion_signed ?x0 - object)
    (snap_alias_exists ?x0 - object)
    (snap_alias_removed ?x0 - object)
    (config_removed ?x0 - object ?x1 - object)
    (validation_enforced ?x0 - object)
    (validation_forgotten ?x0 - object)
    (validation_refreshed ?x0 - object)
    (configuration_waited ?x0 - object)
    (warning_exists ?x0 - object)
    (warning_silenced ?x0 - object)
    (alias_preferred ?x0 - object)
    (authenticated)
    (snapshot_exists ?x0 - object)
    (snapshot_restored ?x0 - object)
    (device_exists ?x0 - object)
    (device_remodeled ?x0 - object)
    (device_rebooted ?x0 - object)
    (warnings_listed ?x0 - object)
    (warnings_acknowledged ?x0 - object)
    (debug_command_run ?x0 - object ?x1 - object)
    (snap_packed ?x0 - object)
    (snap_command_executed ?x0 - object ?x1 - object)
    (device_image_prepared ?x0 - object)
    (public_key_exported ?x0 - object)
    (quota_group_updated ?x0 - object)
    (service_in_maintenance ?x0 - object)
    (service_reloading ?x0 - object)
    (service_refreshing ?x0 - object)
    (output_displayed ?x0 - object)
    (output_ellipsized ?x0 - object)
    (unit_loaded ?x0 - object)
    (unit_load_error ?x0 - object)
    (unit_not_found ?x0 - object)
    (unit_bad_setting ?x0 - object)
    (unit_masked ?x0 - object)
    (pager_secure_disabled ?x0 - object)
    (colors_enabled ?x0 - object)
    (color_mode_restricted ?x0 - object)
    (term_decision_overridden ?x0 - object)
    (systemd_decision_overridden ?x0 - object)
    (path_bound ?x0 - object ?x1 - object)
    (image_mounted ?x0 - object ?x1 - object ?x2 - object ?x3 - object)
    (log_level_set ?x0 - object ?x1 - object)
    (log_target_set ?x0 - object ?x1 - object)
    (failed_state_reset ?x0 - object)
    (process_exists ?x0 - object)
    (unit_caller_identified ?x0 - object)
    (unit_enabled ?x0 - object)
    (unit_disabled ?x0 - object)
    (unit_reenabled ?x0 - object)
    (unit_linked ?x0 - object)
    (service_wants ?x0 - object ?x1 - object)
    (service_requires ?x0 - object ?x1 - object)
    (daemon_reloaded)
    (daemon_reexecuted)
    (service_watchdogs_enabled ?x0 - object)
    (system_mode_default)
    (system_mode_rescue)
    (system_mode_emergency)
    (system_halted)
    (system_powered_off)
    (system_rebooted)
    (system_kexec_rebooted)
    (userspace_rebooted)
    (instance_exited)
    (root_changed ?x0 - object)
    (system_sleeping)
    (system_suspended)
    (system_hibernated)
    (system_hybrid_sleep)
    (system_suspended_then_hibernated)
    (wall_message_disabled)
    (shutdown_message_set ?x0 - object)
    (service_disabled ?x0 - object)
    (daemon_not_reloaded)
    (user_unit_globally_edited ?x0 - object)
    (unit_temporarily_edited ?x0 - object)
    (symlinks_overridden)
    (shutdown_executed_immediately)
    (preset_mode_applied ?x0 - object)
    (unit_edited_in_root ?x0 - object ?x1 - object)
    (image_policy_set ?x0 - object)
    (journal_lines_set ?x0 - object)
    (journal_output_mode_set ?x0 - object)
    (boot_loader_menu_enabled ?x0 - object)
    (boot_loader_entry_set ?x0 - object)
    (reboot_argument_set ?x0 - object)
    (symbolic_link_exists ?x0 - object)
    (file_symlinked ?x0 - object ?x1 - object)
    (filesystem_boundary_respected ?x0 - object ?x1 - object)
    (selinux_context_set ?x0 - object)
    (security_context_set ?x0 - object ?x1 - object)
    (file_sparse ?x0 - object)
    (files_replaced ?x0 - object)
    (files_not_replaced ?x0 - object)
    (older_files_replaced ?x0 - object)
    (lightweight_copy ?x0 - object)
    (copy_possible ?x0 - object ?x1 - object)
    (backup_option_set)
    (backup_exists ?x0 - object)
    (backup_option_set_to_numbered)
    (numbered_backup_exists ?x0 - object)
    (backup_option_set_to_simple)
    (simple_backup_exists ?x0 - object)
    (backup_option_set_to_existing)
    (src ?x0 - object)
    (force_option_set)
    (files_copied ?x0 - object ?x1 - object)
    (file_backed_up ?x0 - object)
    (file_contents_copied ?x0 - object ?x1 - object)
    (symlink_followed ?x0 - object ?x1 - object)
    (hard_link_created ?x0 - object ?x1 - object)
    (symlink_dereferenced ?x0 - object ?x1 - object)
    (backup_suffix_set ?x0 - object)
    (file_copied_to_directory ?x0 - object ?x1 - object)
    (file_update_controlled ?x0 - object)
    (selinux_context_set_custom ?x0 - object ?x1 - object)
    (skipped_files_fail ?x0 - object ?x1 - object)
    (files_replaced_if_older ?x0 - object ?x1 - object)
    (reflink_supported)
    (files_reflinked ?x0 - object ?x1 - object)
    (files_copied_standard ?x0 - object ?x1 - object)
    (version_control_set ?x0 - object)
    (file_in_directory ?x0 - object ?x1 - object)
    (backup_disabled ?x0 - object)
    (backup_numbered ?x0 - object)
    (backup_existing ?x0 - object)
    (backup_simple ?x0 - object)
    (update_mode_set ?x0 - object)
    (interactive_prompted ?x0 - object)
    (count_files ?x0 - object ?x1 - object)
    (interactive_prompted_once ?x0 - object)
    (directory_removed ?x0 - object)
    (directory_empty ?x0 - object)
    (filesystem_different ?x0 - object)
    (root_not_special ?x0 - object)
    (dir_equals_root ?x0 - object)
    (separate_device ?x0 - object)
    (when_in_never_once_always ?x0 - object)
    (prompted_interactive ?x0 - object)
    (prompted_always ?x0 - object)
    (prompted_once ?x0 - object)
    (preserved_special_bits ?x0 - object)
    (modified_special_bits ?x0 - object)
    (cleared_special_bits ?x0 - object)
    (restricted_deletion_flag_set ?x0 - object)
    (file_mode_changed ?x0 - object)
    (errors_suppressed ?x0 - object)
    (symbolic_link ?x0 - object)
    (referent_affected ?x0 - object)
    (symbolic_link_affected ?x0 - object)
    (recursive_change_applied ?x0 - object)
    (file_mode_copied ?x0 - object ?x1 - object)
    (file_mode_referenced ?x0 - object ?x1 - object)
    (file_permissions_recursive ?x0 - object)
    (file_is_symbolic_link ?x0 - object)
    (symbolic_link_traversed ?x0 - object)
    (no_symbolic_links_traversed ?x0 - object)
    (file_owner ?x0 - object ?x1 - object)
    (file_group ?x0 - object ?x1 - object)
    (root_not_preserved ?x0 - object)
    (file_ownership_referenced ?x0 - object ?x1 - object)
    (ownership_changed_recursively ?x0 - object)
    (symlinks_traversed ?x0 - object)
    (symlinks_not_traversed ?x0 - object)
    (file_access_time_updated ?x0 - object)
    (file_modification_time_updated ?x0 - object)
    (file_timestamp_changed ?x0 - object)
    (time_type_valid ?x0 - object)
    (human_readable_output_enabled)
    (batch_execution_completed)
    (non_zero_return_code)
    (detailed_output_enabled)
    (very_detailed_output_enabled)
    (max_loops_set ?x0 - object)
    (protocol_family_set ?x0 - object)
    (output_format_oneline)
    (network_namespace_active ?x0 - object)
    (command_executed_all_objects)
    (color_output_configured ?x0 - object)
    (addrlabel_configured ?x0 - object)
    (fou_configured ?x0 - object)
    (ila_configured ?x0 - object)
    (ioam_configured ?x0 - object)
    (l2tp_configured ?x0 - object)
    (link_configured ?x0 - object)
    (macsec_configured ?x0 - object)
    (maddress_configured ?x0 - object)
    (monitor_configured ?x0 - object)
    (mptcp_configured ?x0 - object)
    (mroute_configured ?x0 - object)
    (mrule_configured ?x0 - object)
    (neigh_configured ?x0 - object)
    (netns_configured ?x0 - object)
    (route_configured ?x0 - object)
    (rule_configured ?x0 - object)
    (tunnel_configured ?x0 - object)
    (xfrm_configured ?x0 - object)
    (segment_routing_configured ?x0 - object)
    (tcp_metrics_configured ?x0 - object)
    (tokenized_interface_configured ?x0 - object)
    (tuntap_device_configured ?x0 - object)
    (vrf_device_configured ?x0 - object)
    (ipsec_policy_configured ?x0 - object)
    (command_exists ?x0 - object)
    (firewall_rule_modified ?x0 - object ?x1 - object ?x2 - object)
    (firewall_rule_inserted ?x0 - object ?x1 - object ?x2 - object ?x3 - object)
    (firewall_rule_replaced ?x0 - object ?x1 - object ?x2 - object ?x3 - object)
    (firewall_rule_deleted ?x0 - object ?x1 - object ?x2 - object)
    (firewall_rules_flushed ?x0 - object ?x1 - object ?x2 - object)
    (firewall_chain_created ?x0 - object ?x1 - object)
    (firewall_chain_deleted ?x0 - object ?x1 - object)
    (firewall_policy_set ?x0 - object ?x1 - object ?x2 - object)
    (firewall_chain_renamed ?x0 - object ?x1 - object ?x2 - object)
    (firewall_rule_configured ?x0 - object)
    (firewall_table_defined ?x0 - object)
    (firewall_chain_added ?x0 - object)
    (firewall_rule_added ?x0 - object)
    (packet_acceptance_set ?x0 - object)
    (packet_drop_set ?x0 - object)
    (packet_return_set ?x0 - object)
    (table_exists ?x0 - object)
    (packet_table_set ?x0 - object)
    (iptables_rule_appended ?x0 - object ?x1 - object)
    (rule_exists ?x0 - object ?x1 - object)
    (firewall_rule_flushed ?x0 - object)
    (firewall_rule_counters_zeroed ?x0 - object)
    (firewall_rule_referenced ?x0 - object)
    (firewall_rule_policy_set ?x0 - object ?x1 - object)
    (firewall_rule_renamed ?x0 - object ?x1 - object)
    (ipv4_ipv6_rules_allowed ?x0 - object)
    (protocol_set ?x0 - object)
    (packet_matched_interface ?x0 - object)
    (out_interface_set ?x0 - object)
    (out_interface_wildcard_set ?x0 - object)
    (fragmented_packets_matched)
    (head_fragments_matched)
    (counters_initialized ?x0 - object)
    (modprobe_command_set ?x0 - object)
    (exit_code ?x0 - object)
    (setuid_to_root)
    (command_executed ?x0 - object)
    (session_record_exists)
    (timestamp_removed ?x0 - object)
    (timestamp_reset ?x0 - object)
    (session_preserved ?x0 - object)
    (file_edited ?x0 - object)
    (file_updated ?x0 - object)
    (timestamp_invalidated ?x0 - object)
    (environment_modified_by_pam ?x0 - object)
    (resource_limits_reset ?x0 - object)
    (command_executed_as_user ?x0 - object ?x1 - object)
    (shell_login ?x0 - object)
    (home_directory_changed ?x0 - object)
    (login_shell_set ?x0 - object)
    (environment_preserved ?x0 - object)
    (pty_created ?x0 - object)
    (path_set_for_root ?x0 - object ?x1 - object)
    (always_set_path ?x0 - object)
    (path_initialized ?x0 - object)
    (pam_configured ?x0 - object)
    (user_primary_group ?x0 - object ?x1 - object)
    (user_supplementary_groups ?x0 - object ?x1 - object)
    (user_in_group ?x0 - object ?x1 - object)
    (user_home_directory ?x0 - object ?x1 - object)
    (file_ownership_adapted ?x0 - object)
    (user_id_non_unique ?x0 - object)
    (user_password_changed ?x0 - object)
    (changes_applied_in_chroot ?x0 - object)
    (changes_applied_in_prefix ?x0 - object)
    (user_shell_changed ?x0 - object ?x1 - object)
    (user_uid_changed ?x0 - object ?x1 - object)
    (subordinate_uids_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_uids_removed ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gids_added ?x0 - object ?x1 - object ?x2 - object)
    (user_has_subordinate_gids ?x0 - object ?x1 - object ?x2 - object)
    (user_has_selinux_user ?x0 - object ?x1 - object)
    (selinux_user_set ?x0 - object)
    (selinux_range_set ?x0 - object ?x1 - object)
    (create_mail_spool)
    (mail_spool_exists ?x0 - object)
    (mail_spool_moved ?x0 - object ?x1 - object)
    (subordinate_uids_allocated ?x0 - object)
    (subordinate_gids_allocated ?x0 - object)
    (user_has_bad_name ?x0 - object)
    (user_gecos ?x0 - object ?x1 - object)
    (user_password_inactive ?x0 - object ?x1 - object)
    (user_groups_set ?x0 - object ?x1 - object)
    (user_login_changed ?x0 - object ?x1 - object)
    (user_shell_set ?x0 - object ?x1 - object)
    (user_comment_set ?x0 - object ?x1 - object)
    (password_inactive_days_set ?x0 - object ?x1 - object)
    (subids_updated ?x0 - object)
    (user_in_lastlog ?x0 - object)
    (user_in_faillog ?x0 - object)
    (home_directory_exists ?x0 - object)
    (subuid_updated ?x0 - object)
    (subgid_updated ?x0 - object)
    (home_base_dir_set ?x0 - object)
    (default_group_set ?x0 - object)
    (default_shell_set ?x0 - object)
    (min ?x0 - object)
    (max ?x0 - object)
    (group_id_range_set ?x0 - object ?x1 - object)
    (mode ?x0 - object)
    (home_directory_mode_set ?x0 - object)
    (lastlog_uid_max_set ?x0 - object)
    (mail_dir_set ?x0 - object)
    (mail_file_set ?x0 - object)
    (max_members_per_group_set ?x0 - object)
    (group_member_limit_set ?x0 - object ?x1 - object)
    (password_max_days_set ?x0 - object ?x1 - object)
    (password_min_days_set ?x0 - object ?x1 - object)
    (sub_gid_allocated ?x0 - object)
    (sub_uid_allocated ?x0 - object)
    (umask_set ?x0 - object)
    (group_empty ?x0 - object)
    (chrooted ?x0 - object)
    (prefix_set ?x0 - object)
    (extra_users_enabled)
    (gid_used ?x0 - object)
    (group_password_set ?x0 - object)
    (group_is_system ?x0 - object)
    (group_operation_in_chroot ?x0 - object ?x1 - object)
    (group_split ?x0 - object)
    (selinux_user_mapping_removed ?x0 - object)
    (cron_job_exists ?x0 - object)
    (at_job_exists ?x0 - object)
    (print_job_exists ?x0 - object)
    (print_job_removed ?x0 - object)
    (user_removed ?x0 - object)
    (home_directory_removed ?x0 - object)
    (mail_spool_removed ?x0 - object)
    (extra_users_database_enabled)
  )

  (:action install_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action remove_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action update_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?pkg))
      (not (vulnerable ?pkg))
    )
  )

  (:action update_package_list
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_list_updated)
    )
  )

  (:action update_package_index
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_index_updated)
    )
  )

  (:action manage_package
    :parameters (?actor - user ?pkg - package ?action - file)
    :precondition (and
      (package_exists ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action purge_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?pkg)
    )
  )

  (:action satisfy_dependencies
    :parameters (?actor - user ?dep - package)
    :precondition (and
      (package_installed ?dep)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?dep)
    )
  )

  (:action determine_why_not_installable
    :parameters (?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
    )
    :effect (and
      (package_reverted ?pkg)
    )
  )

  (:action edit_sources
    :parameters (?actor - user ?file - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (file_modified ?file)
    )
  )

  (:action change_apt_options
    :parameters (?option - file)
    :precondition (and
      (file_exists ?option)
    )
    :effect (and
      (apt_option_changed ?option)
    )
  )

  (:action reinstall_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action upgrade_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_list_updated)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_upgraded)
    )
  )

  (:action dist_upgrade
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_list_updated)
      (can_escalate ?actor)
    )
    :effect (and
      (system_upgraded)
    )
  )

  (:action autoremove_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (unnecessary_packages_installed)
      (can_escalate ?actor)
    )
    :effect (and
      (unnecessary_packages_removed)
    )
  )

  (:action clean_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (cache_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (cache_cleared)
    )
  )

  (:action autoclean_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (old_cache_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (old_cache_removed)
    )
  )

  (:action install_package_before_upgrade
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action upgrade_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_outdated ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_configured ?pkg)
    )
  )

  (:action install_package_version
    :parameters (?actor - user ?pkg - package ?version - file)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action install_package_distribution
    :parameters (?actor - user ?pkg - package ?dist - file)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action fetch_source
    :parameters (?pkg - package)
    :precondition (and
      (package_installed ?pkg)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action examine_packages
    :parameters (?pkg - package)
    :precondition (and
      (package_installed ?pkg)
    )
    :effect (and
      (package_outdated ?pkg)
    )
  )

  (:action download_source_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (not (package_installed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action compile_source_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action install_build_deps
    :parameters (?actor - user ?src - package)
    :precondition (and
      (network_available)
      (not (build_deps_installed ?src))
      (can_escalate ?actor)
    )
    :effect (and
      (build_deps_installed ?src)
    )
  )

  (:action download_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?pkg)
    )
  )

  (:action disable_install_recommends
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (apt_install_recommends_disabled)
    )
  )

  (:action enable_install_suggests
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (apt_install_suggests_enabled)
    )
  )

  (:action download_only
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_downloaded)
    )
  )

  (:action fix_broken
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (broken_dependencies_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (broken_dependencies_fixed)
    )
  )

  (:action disable_package_download
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (download_disabled)
    )
  )

  (:action set_quiet_mode
    :parameters (?actor - user ?level - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (quiet_mode_set ?level)
    )
  )

  (:action simulate_events
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (simulation_performed)
    )
  )

  (:action simulate_apt_operations
    :parameters (?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (requires_root))
    )
    :effect (and
      (package_configured ?pkg)
      (package_reverted ?pkg)
      (package_installed ?pkg)
    )
  )

  (:action activate_build_profiles
    :parameters (?actor - user ?profiles - directory)
    :precondition (and
      (package_installed ?profiles)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?profiles)
    )
  )

  (:action compile_source
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action ignore_hold
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action upgrade_with_new_pkgs
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action upgrade_package_with_new_deps
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_configured ?pkg)
    )
  )

  (:action prevent_package_upgrade
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?pkg))
    )
  )

  (:action upgrade_only_installed
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_configured ?pkg)
    )
  )

  (:action allow_package_downgrades
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_reverted ?pkg)
    )
  )

  (:action clean_apt_lists
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (apt_lists_cleaned)
    )
  )

  (:action select_snapshot
    :parameters (?actor - user ?snapshot - file)
    :precondition (and
      (snapshot_enabled)
      (can_escalate ?actor)
    )
    :effect (and
      (snapshot_selected ?snapshot)
    )
  )

  (:action set_default_release
    :parameters (?actor - user ?release - directory)
    :precondition (and
      (file_exists ?release)
      (can_escalate ?actor)
    )
    :effect (and
      (package_pinned ?release)
    )
  )

  (:action trivial_only
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (trivial_operations_only)
    )
  )

  (:action mark_auto
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_automatically_installed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_automatically_installed ?pkg)
    )
  )

  (:action abort_on_remove
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (aborted ?pkg)
    )
  )

  (:action autoremove
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_required ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_removed ?pkg)
    )
  )

  (:action set_only_source
    :parameters (?actor - user ?config - file)
    :precondition (and
      (file_exists ?config)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_config_set ?config ?apt_get_only-source)
    )
  )

  (:action download_diff_only
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_diff_downloaded ?pkg)
    )
  )

  (:action download_dsc_only
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_dsc_downloaded ?pkg)
    )
  )

  (:action download_tar_only
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_tar_downloaded ?pkg)
    )
  )

  (:action process_arch_only
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_arch_deps_processed ?pkg)
    )
  )

  (:action process_indep_only
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_indep_deps_processed ?pkg)
    )
  )

  (:action allow_unauthenticated
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_unauthenticated_allowed ?pkg)
    )
  )

  (:action allow_insecure_repositories
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (allow_insecure_repositories)
    )
  )

  (:action allow_releaseinfo_change
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (allow_releaseinfo_change)
    )
  )

  (:action add_source_file
    :parameters (?actor - user ?filename - file)
    :precondition (and
      (file_exists ?filename)
      (can_escalate ?actor)
    )
    :effect (and
      (source_file_added ?filename)
    )
  )

  (:action error_on_any
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (error_on_any_enabled)
    )
  )

  (:action update_before_command
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (update_run_before_command)
    )
  )

  (:action set_apt_config_option
    :parameters (?option - file)
    :precondition (and
      (file_exists ?option)
    )
    :effect (and
      (apt_config_option_set ?option)
    )
  )

  (:action toggle_apt_color
    :parameters (?color - file)
    :precondition (and
    )
    :effect (and
      (apt_color_setting ?color)
    )
  )

  (:action configure_apt
    :parameters (?actor - user ?config - file)
    :precondition (and
      (file_exists ?config)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?config)
    )
  )

  (:action configure_apt_fragments
    :parameters (?actor - user ?config - file)
    :precondition (and
      (file_exists ?config)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?config)
    )
  )

  (:action configure_apt_preferences
    :parameters (?actor - user ?config - file)
    :precondition (and
      (file_exists ?config)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?config)
    )
  )

  (:action configure_apt_preferences_fragments
    :parameters (?actor - user ?config - file)
    :precondition (and
      (file_exists ?config)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?config)
    )
  )

  (:action configure_apt_cache
    :parameters (?actor - user ?config - file)
    :precondition (and
      (file_exists ?config)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?config)
    )
  )

  (:action configure_apt_cache_partial
    :parameters (?actor - user ?config - file)
    :precondition (and
      (file_exists ?config)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?config)
    )
  )

  (:action configure_apt_state
    :parameters (?actor - user ?config - file)
    :precondition (and
      (file_exists ?config)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?config)
    )
  )

  (:action set_state_storage
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (state_storage_set ?dir)
    )
  )

  (:action update_package_lists
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_lists_updated)
    )
  )

  (:action install_local_package
    :parameters (?actor - user ?pkg - package ?deb_file - file)
    :precondition (and
      (not (package_installed ?pkg))
      (file_exists ?deb_file)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action configure_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action install_snap
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action remove_snap
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action refresh_snap
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?pkg))
    )
  )

  (:action revert_snap
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?pkg)
    )
  )

  (:action enable_snap
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_enabled ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_enabled ?pkg)
    )
  )

  (:action disable_snap
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_enabled ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_enabled ?pkg))
    )
  )

  (:action abort_pending_change
    :parameters (?actor - user ?change_type - file)
    :precondition (and
      (pending_change_exists ?change_type)
      (can_escalate ?actor)
    )
    :effect (and
      (change_aborted ?change_type)
    )
  )

  (:action add_assertion
    :parameters (?actor - user ?assertion - file)
    :precondition (and
      (file_exists ?assertion)
      (assertion_valid ?assertion)
      (signature_verified ?assertion)
      (assertion_consistent ?assertion)
      (can_escalate ?actor)
    )
    :effect (and
      (assertion_added ?assertion)
    )
  )

  (:action set_alias
    :parameters (?app - service ?alias - service)
    :precondition (and
      (service_exists ?app)
    )
    :effect (and
      (alias_exists ?app ?alias)
    )
  )

  (:action connect_snap_plug
    :parameters (?actor - user ?snap1 - file ?plug - file ?snap2 - file ?slot - file)
    :precondition (and
      (package_installed ?snap1)
      (package_installed ?snap2)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_plug_connected ?snap1 ?plug ?snap2 ?slot)
    )
  )

  (:action create_cohort_keys
    :parameters (?actor - user ?snaps - package)
    :precondition (and
      (package_installed ?snaps)
      (can_escalate ?actor)
    )
    :effect (and
      (cohort_keys_created ?snaps)
    )
  )

  (:action obtain_seeding_details
    :parameters (?unicode - file)
    :precondition (and
      (snap_installed)
    )
    :effect (and
      (seeding_details_obtained ?unicode)
    )
  )

  (:action obtain_stacktraces
    :parameters (?obj - file)
    :precondition (and
      (snap_installed)
    )
    :effect (and
      (stacktraces_obtained)
    )
  )

  (:action inspect_snapd_state
    :parameters (?state_file - file)
    :precondition (and
      (file_exists ?state_file)
    )
    :effect (and
      (snapd_state_inspected ?state_file)
    )
  )

  (:action inspect_snapd_state_bypass
    :parameters (?state_file - file)
    :precondition (and
      (file_exists ?state_file)
    )
    :effect (and
      (snapd_state_inspected_bypass ?state_file)
    )
  )

  (:action inspect_task
    :parameters (?task_id - file)
    :precondition (and
      (task_exists ?task_id)
    )
    :effect (and
      (task_inspected ?task_id)
    )
  )

  (:action inspect_change
    :parameters (?change_id - file)
    :precondition (and
      (change_exists ?change_id)
    )
    :effect (and
      (change_inspected ?change_id)
    )
  )

  (:action output_seeding_status
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (seeding_status_output)
    )
  )

  (:action dot_output
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (dot_output_generated)
    )
  )

  (:action omit_hold_tasks
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (hold_tasks_omitted)
    )
  )

  (:action disconnect_plug
    :parameters (?actor - user ?snap_name - package ?plug_name - package ?slot_name - package)
    :precondition (and
      (package_installed ?snap_name)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?snap_name)
    )
  )

  (:action disconnect_forget
    :parameters (?connection - file)
    :precondition (and
      (file_exists ?connection)
    )
    :effect (and
      (connection_forgotten ?connection)
    )
  )

  (:action download_snap
    :parameters (?snap - package ?revision - directory ?basename - directory ?target_directory - directory ?components - file ?cohort - directory)
    :precondition (and
      (package_installed ?snap)
      (network_available)
    )
    :effect (and
      (package_installed ?snap)
    )
  )

  (:action export_key
    :parameters (?account - user)
    :precondition (and
      (user_exists ?account)
    )
    :effect (and
      (package_configured ?account)
    )
  )

  (:action export_snapshot
    :parameters (?filename - file)
    :precondition (and
    )
    :effect (and
      (snapshot_exported ?filename)
    )
  )

  (:action increase_memory_limit
    :parameters (?actor - user ?group - group)
    :precondition (and
      (quota_group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (memory_limit_increased ?group)
    )
  )

  (:action decrease_memory_limit
    :parameters (?actor - user ?quota_group - group)
    :precondition (and
      (quota_group_exists ?quota_group)
      (can_escalate ?actor)
    )
    :effect (and
      (memory_limit_decreased ?quota_group)
    )
  )

  (:action increase_cpu_limit
    :parameters (?actor - user ?quota_group - group)
    :precondition (and
      (quota_group_exists ?quota_group)
      (can_escalate ?actor)
    )
    :effect (and
      (cpu_limit_increased ?quota_group)
    )
  )

  (:action decrease_cpu_limit
    :parameters (?actor - user ?quota_group - group)
    :precondition (and
      (quota_group_exists ?quota_group)
      (can_escalate ?actor)
    )
    :effect (and
      (cpu_limit_decreased ?quota_group)
    )
  )

  (:action modify_cpu_set_limit
    :parameters (?actor - user ?quota_group - group)
    :precondition (and
      (quota_group_exists ?quota_group)
      (can_escalate ?actor)
    )
    :effect (and
      (cpu_set_modified ?quota_group)
    )
  )

  (:action increase_threads_limit
    :parameters (?actor - user ?quota_group - group)
    :precondition (and
      (quota_group_exists ?quota_group)
      (can_escalate ?actor)
    )
    :effect (and
      (threads_limit_increased ?quota_group)
    )
  )

  (:action decrease_quota_threads
    :parameters (?actor - user ?group - group)
    :precondition (and
      (quota_group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (quota_threads_decreased ?group)
    )
  )

  (:action increase_journal_limits
    :parameters (?actor - user ?group - group)
    :precondition (and
      (quota_group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_limits_increased ?group)
    )
  )

  (:action decrease_journal_limits
    :parameters (?actor - user ?group - group)
    :precondition (and
      (quota_group_exists ?group)
      (journal_limits_set ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_limits_decreased ?group)
    )
  )

  (:action set_new_quotas
    :parameters (?actor - user ?group - group)
    :precondition (and
      (quota_group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (quotas_set ?group)
    )
  )

  (:action remove_and_recreate_group
    :parameters (?actor - user ?group - group)
    :precondition (and
      (quota_group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (quota_group_removed ?group)
      (quota_group_recreated ?group)
    )
  )

  (:action add_snaps_to_group
    :parameters (?actor - user ?group - group ?snap - file)
    :precondition (and
      (quota_group_exists ?group)
      (snap_exists ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snaps_added ?group)
      (services_restarted ?group)
    )
  )

  (:action set_cpu_quota
    :parameters (?actor - user ?threads - file ?journal_size - file ?journal_rate_limit - file ?parent - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (cpu_quota_set ?threads ?journal_size ?journal_rate_limit ?parent)
    )
  )

  (:action sign_assertion
    :parameters (?key - file ?body - file)
    :precondition (and
      (key_exists ?key)
    )
    :effect (and
      (assertion_signed ?body)
    )
  )

  (:action start_services
    :parameters (?actor - user ?services - service)
    :precondition (and
      (service_exists ?services)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?services)
    )
  )

  (:action start_snap_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (not (service_running ?svc))
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
    )
  )

  (:action stop_snap_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?svc))
    )
  )

  (:action disable_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_enabled ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_enabled ?svc))
    )
  )

  (:action switch_snap_channel
    :parameters (?snap - package ?channel - file)
    :precondition (and
      (package_installed ?snap)
    )
    :effect (and
      (package_configured ?snap)
    )
  )

  (:action switch_snap_cohort
    :parameters (?snap - package ?cohort - file)
    :precondition (and
      (package_installed ?snap)
    )
    :effect (and
      (package_configured ?snap)
    )
  )

  (:action leave_snap_cohort
    :parameters (?snap - package)
    :precondition (and
      (package_installed ?snap)
    )
    :effect (and
      (package_configured ?snap)
    )
  )

  (:action try_snap
    :parameters (?actor - user ?snap - package)
    :precondition (and
      (package_installed ?snap)
      (not (service_running ?snap))
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?snap)
    )
  )

  (:action snap_try
    :parameters (?snap_dir - directory)
    :precondition (and
      (file_exists ?snap_dir)
      (directory_exists ?snap_dir)
    )
    :effect (and
      (snap_installed ?snap_dir)
    )
  )

  (:action snap_unalias
    :parameters (?alias_name - file)
    :precondition (and
      (snap_alias_exists ?alias_name)
    )
    :effect (and
      (snap_alias_removed ?alias_name)
    )
  )

  (:action remove_config_options
    :parameters (?actor - user ?snap_name - service ?config_path - file)
    :precondition (and
      (service_exists ?snap_name)
      (can_escalate ?actor)
    )
    :effect (and
      (config_removed ?snap_name ?config_path)
    )
  )

  (:action enforce_validation
    :parameters (?validation_set - file)
    :precondition (and
      (file_exists ?validation_set)
    )
    :effect (and
      (validation_enforced ?validation_set)
    )
  )

  (:action forget_validation
    :parameters (?validation_set - file)
    :precondition (and
      (validation_enforced ?validation_set)
    )
    :effect (and
      (validation_forgotten ?validation_set)
    )
  )

  (:action refresh_validation
    :parameters (?validation_set - file)
    :precondition (and
      (validation_enforced ?validation_set)
    )
    :effect (and
      (validation_refreshed ?validation_set)
    )
  )

  (:action wait_configuration
    :parameters (?config - file)
    :precondition (and
      (file_exists ?config)
    )
    :effect (and
      (configuration_waited ?config)
    )
  )

  (:action silence_snap_warnings
    :parameters (?warning_id - firewall_rule)
    :precondition (and
      (warning_exists ?warning_id)
    )
    :effect (and
      (warning_silenced ?warning_id)
    )
  )

  (:action manage_snap
    :parameters (?actor - user ?snap - package)
    :precondition (and
      (not (package_installed ?snap))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?snap)
    )
  )

  (:action switch_snap
    :parameters (?actor - user ?pkg - package ?channel - file)
    :precondition (and
      (package_installed ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action start_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (not (service_running ?svc))
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
    )
  )

  (:action stop_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?svc))
    )
  )

  (:action restart_service
    :parameters (?actor - user ?svc - service ?cfg - configuration_file)
    :precondition (and
      (service_exists ?svc)
      (configures ?cfg ?svc)
      (file_exists ?cfg)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
      (config_applied ?svc)
    )
  )

  (:action connect_plug
    :parameters (?actor - user ?plug - interface ?slot - interface)
    :precondition (and
      (interface_exists ?plug)
      (interface_exists ?slot)
      (can_escalate ?actor)
    )
    :effect (and
      (interface_up ?plug)
      (interface_up ?slot)
    )
  )

  (:action change_config_options
    :parameters (?actor - user ?key - file ?value - file)
    :precondition (and
      (file_exists ?key)
      (file_exists ?value)
      (can_escalate ?actor)
    )
    :effect (and
      (file_writable ?key)
      (file_writable ?value)
    )
  )

  (:action remove_alias
    :parameters (?alias_name - file)
    :precondition (and
      (alias_exists ?alias_name)
    )
    :effect (and
      (not (alias_exists ?alias_name))
    )
  )

  (:action prefer_alias
    :parameters (?snap_name - package)
    :precondition (and
      (package_installed ?snap_name)
    )
    :effect (and
      (alias_preferred ?snap_name)
    )
  )

  (:action login
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (authenticated)
    )
  )

  (:action logout
    :parameters (?obj - file)
    :precondition (and
      (authenticated)
    )
    :effect (and
      (not (authenticated))
    )
  )

  (:action save_snapshot
    :parameters (?snapshot_name - file)
    :precondition (and
    )
    :effect (and
      (snapshot_exists ?snapshot_name)
    )
  )

  (:action restore_snapshot
    :parameters (?snapshot_name - file)
    :precondition (and
      (snapshot_exists ?snapshot_name)
    )
    :effect (and
      (snapshot_restored ?snapshot_name)
    )
  )

  (:action delete_snapshot
    :parameters (?snapshot_name - file)
    :precondition (and
      (snapshot_exists ?snapshot_name)
    )
    :effect (and
      (not (snapshot_exists ?snapshot_name))
    )
  )

  (:action remodel_device
    :parameters (?actor - user ?device - file)
    :precondition (and
      (device_exists ?device)
      (can_escalate ?actor)
    )
    :effect (and
      (device_remodeled ?device)
    )
  )

  (:action reboot_device
    :parameters (?actor - user ?device - file)
    :precondition (and
      (device_exists ?device)
      (can_escalate ?actor)
    )
    :effect (and
      (device_rebooted ?device)
    )
  )

  (:action acknowledge_warnings
    :parameters (?actor - user ?device - file)
    :precondition (and
      (device_exists ?device)
      (warnings_listed ?device)
      (can_escalate ?actor)
    )
    :effect (and
      (warnings_acknowledged ?device)
    )
  )

  (:action run_debug
    :parameters (?actor - user ?device - file ?command - file)
    :precondition (and
      (device_exists ?device)
      (can_escalate ?actor)
    )
    :effect (and
      (debug_command_run ?device ?command)
    )
  )

  (:action pack_directory
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (snap_packed ?dir)
    )
  )

  (:action run_snap_command
    :parameters (?snap_name - file ?command - file)
    :precondition (and
      (snap_installed ?snap_name)
    )
    :effect (and
      (snap_command_executed ?snap_name ?command)
    )
  )

  (:action prepare_device_image
    :parameters (?actor - user ?image_file - file)
    :precondition (and
      (file_exists ?image_file)
      (can_escalate ?actor)
    )
    :effect (and
      (device_image_prepared ?image_file)
    )
  )

  (:action export_public_key
    :parameters (?key_file - file)
    :precondition (and
      (key_exists)
    )
    :effect (and
      (public_key_exported ?key_file)
    )
  )

  (:action set_quota
    :parameters (?actor - user ?quota_group - file)
    :precondition (and
      (quota_group_exists ?quota_group)
      (can_escalate ?actor)
    )
    :effect (and
      (quota_group_updated ?quota_group)
    )
  )

  (:action remove_quota
    :parameters (?actor - user ?quota_group - file)
    :precondition (and
      (quota_group_exists ?quota_group)
      (can_escalate ?actor)
    )
    :effect (and
      (quota_group_removed ?quota_group)
    )
  )

  (:action enable_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_enabled ?svc)
    )
  )

  (:action set_unit_state
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?unit)
    )
  )

  (:action fail_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_failed ?svc)
    )
  )

  (:action activate_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (not (service_running ?svc))
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
    )
  )

  (:action deactivate_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?svc))
    )
  )

  (:action maintain_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (not (service_running ?svc))
      (can_escalate ?actor)
    )
    :effect (and
      (service_in_maintenance ?svc)
    )
  )

  (:action reload_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_running ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_reloading ?unit)
    )
  )

  (:action refresh_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_running ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_refreshing ?unit)
    )
  )

  (:action ellipsize_output
    :parameters (?lines - file)
    :precondition (and
      (output_displayed ?lines)
    )
    :effect (and
      (output_ellipsized ?lines)
    )
  )

  (:action load_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_loaded ?unit)
    )
  )

  (:action unload_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (service_running ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?unit))
    )
  )

  (:action load_unit_error
    :parameters (?svc - service)
    :precondition (and
      (service_exists ?svc)
      (not (unit_loaded ?svc))
    )
    :effect (and
      (unit_load_error ?svc)
    )
  )

  (:action unit_not_found
    :parameters (?svc - service)
    :precondition (and
      (not (service_exists ?svc))
    )
    :effect (and
      (unit_not_found ?svc)
    )
  )

  (:action unit_bad_setting
    :parameters (?svc - service)
    :precondition (and
      (service_exists ?svc)
      (not (unit_loaded ?svc))
    )
    :effect (and
      (unit_bad_setting ?svc)
    )
  )

  (:action mask_unit
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (not (unit_masked ?svc))
      (can_escalate ?actor)
    )
    :effect (and
      (unit_masked ?svc)
    )
  )

  (:action set_pager_secure
    :parameters (?value - file)
    :precondition (and
      (file_exists ?value)
    )
    :effect (and
      (pager_secure_disabled ?value)
    )
  )

  (:action set_colors
    :parameters (?colors - file)
    :precondition (and
    )
    :effect (and
      (colors_enabled ?colors)
    )
  )

  (:action restrict_color_usage
    :parameters (?color_mode - file)
    :precondition (and
      (file_exists ?color_mode)
    )
    :effect (and
      (color_mode_restricted ?color_mode)
    )
  )

  (:action override_term_decision
    :parameters (?term_value - file)
    :precondition (and
      (file_exists ?term_value)
    )
    :effect (and
      (term_decision_overridden ?term_value)
    )
  )

  (:action override_systemd_decision
    :parameters (?urlify_value - file)
    :precondition (and
      (file_exists ?urlify_value)
    )
    :effect (and
      (systemd_decision_overridden ?urlify_value)
    )
  )

  (:action start_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (not (service_running ?unit))
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?unit)
    )
  )

  (:action stop_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (service_running ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?unit))
    )
  )

  (:action restart_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?unit)
    )
  )

  (:action try_restart_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (service_running ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?unit)
    )
  )

  (:action reload_or_restart_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?unit)
    )
  )

  (:action try_reload_or_restart_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (service_running ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?unit)
    )
  )

  (:action isolate_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?unit)
    )
  )

  (:action kill_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (service_running ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?unit))
    )
  )

  (:action clean_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?unit)
    )
  )

  (:action freeze_unit
    :parameters (?actor - user ?pattern - service)
    :precondition (and
      (service_exists ?pattern)
      (service_running ?pattern)
      (can_escalate ?actor)
    )
    :effect (and
      (requires_env_preservation ?pattern)
    )
  )

  (:action thaw_unit
    :parameters (?actor - user ?pattern - service)
    :precondition (and
      (service_exists ?pattern)
      (requires_env_preservation ?pattern)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?pattern)
    )
  )

  (:action set_property
    :parameters (?actor - user ?unit - service ?property - file ?value - file)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?unit)
    )
  )

  (:action bind_mount_path
    :parameters (?actor - user ?unit - service ?path - directory)
    :precondition (and
      (service_exists ?unit)
      (directory_exists ?path)
      (can_escalate ?actor)
    )
    :effect (and
      (path_bound ?unit ?path)
    )
  )

  (:action mount_image
    :parameters (?actor - user ?unit - service ?image - file ?path - directory ?opts - directory)
    :precondition (and
      (service_exists ?unit)
      (file_exists ?image)
      (directory_exists ?path)
      (can_escalate ?actor)
    )
    :effect (and
      (image_mounted ?unit ?image ?path ?opts)
    )
  )

  (:action set_log_level
    :parameters (?actor - user ?svc - service ?level - directory)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (log_level_set ?svc ?level)
    )
  )

  (:action set_log_target
    :parameters (?actor - user ?svc - service ?target - directory)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (log_target_set ?svc ?target)
    )
  )

  (:action reset_failed
    :parameters (?actor - user ?pattern - directory)
    :precondition (and
      (service_exists ?pattern)
      (can_escalate ?actor)
    )
    :effect (and
      (failed_state_reset ?pattern)
    )
  )

  (:action whoami
    :parameters (?pid - directory)
    :precondition (and
      (process_exists ?pid)
    )
    :effect (and
      (unit_caller_identified ?pid)
    )
  )

  (:action enable_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_enabled ?unit)
    )
  )

  (:action disable_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_disabled ?unit)
    )
  )

  (:action reenable_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_reenabled ?unit)
    )
  )

  (:action preset_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_enabled ?unit)
    )
  )

  (:action unmask_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (unit_masked ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (not (unit_masked ?unit))
    )
  )

  (:action link_unit
    :parameters (?actor - user ?path - file)
    :precondition (and
      (file_exists ?path)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_linked ?path)
    )
  )

  (:action revert_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?unit)
    )
  )

  (:action add_wants
    :parameters (?actor - user ?target - service ?unit - service)
    :precondition (and
      (service_exists ?target)
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_wants ?target ?unit)
    )
  )

  (:action add_requires
    :parameters (?actor - user ?target - service ?unit - service)
    :precondition (and
      (service_exists ?target)
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_requires ?target ?unit)
    )
  )

  (:action edit_unit_file
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?unit)
    )
  )

  (:action cancel_jobs
    :parameters (?actor - user ?job - process)
    :precondition (and
      (process_running ?job)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?job))
    )
  )

  (:action reload_daemon
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (daemon_reloaded)
    )
  )

  (:action reexec_daemon
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (daemon_reexecuted)
    )
  )

  (:action set_service_watchdogs
    :parameters (?actor - user ?bool - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (service_watchdogs_enabled ?bool)
    )
  )

  (:action enter_default_mode
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_mode_default)
    )
  )

  (:action enter_rescue_mode
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_mode_rescue)
    )
  )

  (:action enter_emergency_mode
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_mode_emergency)
    )
  )

  (:action halt_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_halted)
    )
  )

  (:action poweroff_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_powered_off)
    )
  )

  (:action reboot_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_rebooted)
    )
  )

  (:action kexec_reboot
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_kexec_rebooted)
    )
  )

  (:action soft_reboot
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (userspace_rebooted)
    )
  )

  (:action exit_instance
    :parameters (?exit_code - file)
    :precondition (and
    )
    :effect (and
      (instance_exited)
    )
  )

  (:action switch_root
    :parameters (?actor - user ?root - directory ?init - service)
    :precondition (and
      (directory_exists ?root)
      (can_escalate ?actor)
    )
    :effect (and
      (root_changed ?root)
    )
  )

  (:action sleep_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_sleeping)
    )
  )

  (:action suspend_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_suspended)
    )
  )

  (:action hibernate_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (system_hibernated)
    )
  )

  (:action hybrid_sleep_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (system_hybrid_sleep)
    )
  )

  (:action suspend_then_hibernate_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (system_suspended_then_hibernated)
    )
  )

  (:action send_signal
    :parameters (?actor - user ?unit - service ?signal - file)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_failed ?unit)
    )
  )

  (:action remove_resources
    :parameters (?actor - user ?unit - service ?resources - file)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_failed ?unit)
    )
  )

  (:action wait_for_stop
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_running ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?unit))
    )
  )

  (:action apply_unit_change
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?unit)
    )
  )

  (:action halt_without_wall_message
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (wall_message_disabled)
    )
  )

  (:action shutdown_with_message
    :parameters (?actor - user ?message - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (shutdown_message_set ?message)
    )
  )

  (:action disable_unit_without_reload
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_disabled ?unit)
      (daemon_not_reloaded)
    )
  )

  (:action edit_user_unit_globally
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (user_unit_globally_edited ?unit)
    )
  )

  (:action edit_unit_temporarily
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_temporarily_edited ?unit)
    )
  )

  (:action enable_unit_force
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_enabled ?unit)
      (symlinks_overridden)
    )
  )

  (:action shutdown_immediately
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (shutdown_executed_immediately)
    )
  )

  (:action apply_preset_mode
    :parameters (?actor - user ?mode - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (preset_mode_applied ?mode)
    )
  )

  (:action edit_unit_in_root
    :parameters (?actor - user ?unit - service ?root - directory)
    :precondition (and
      (service_exists ?unit)
      (directory_exists ?root)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_edited_in_root ?unit ?root)
    )
  )

  (:action set_image_policy
    :parameters (?actor - user ?image - file ?policy - directory)
    :precondition (and
      (file_exists ?image)
      (can_escalate ?actor)
    )
    :effect (and
      (image_policy_set ?image)
    )
  )

  (:action set_journal_lines
    :parameters (?lines - file)
    :precondition (and
    )
    :effect (and
      (journal_lines_set ?lines)
    )
  )

  (:action set_journal_output
    :parameters (?mode - file)
    :precondition (and
    )
    :effect (and
      (journal_output_mode_set ?mode)
    )
  )

  (:action boot_into_loader_menu
    :parameters (?actor - user ?time - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (boot_loader_menu_enabled ?time)
    )
  )

  (:action boot_into_loader_entry
    :parameters (?actor - user ?name - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (boot_loader_entry_set ?name)
    )
  )

  (:action set_reboot_argument
    :parameters (?actor - user ?arg - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (reboot_argument_set ?arg)
    )
  )

  (:action copy_file
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (not (file_exists ?dst))
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action force_copy
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?dest)
    )
    :effect (and
      (not (file_exists ?dest))
    )
  )

  (:action interactive_copy
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?dest)
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action follow_symlink_copy
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action hard_link_copy
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action dereference_copy
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action no_clobber_copy
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?dest)
    )
    :effect (and
      (not (file_exists ?dest))
    )
  )

  (:action no_dereference_copy
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action preserve_copy
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action preserve_attributes_copy
    :parameters (?src - file ?dest - file ?attrs - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action no_preserve_copy
    :parameters (?src - file ?dest - file ?attrs - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action copy_directory_recursively
    :parameters (?src - directory ?dst - directory)
    :precondition (and
      (directory_exists ?src)
    )
    :effect (and
      (directory_exists ?dst)
    )
  )

  (:action create_symbolic_link
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (symbolic_link_exists ?dst)
    )
  )

  (:action remove_destination_before_copy
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action control_sparse_file_creation
    :parameters (?src - file ?dst - file ?when - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action strip_trailing_slashes
    :parameters (?src - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?src)
    )
  )

  (:action treat_dest_as_normal_file
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action control_file_update
    :parameters (?src - file ?dst - file ?update - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action follow_directory_symlinks
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (file_symlinked ?src ?dst)
    )
  )

  (:action stay_on_filesystem
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (filesystem_boundary_respected ?src ?dst)
    )
  )

  (:action set_selinux_context
    :parameters (?actor - user ?dst - file)
    :precondition (and
      (file_exists ?dst)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_context_set ?dst)
    )
  )

  (:action set_security_context
    :parameters (?actor - user ?dst - file ?ctx - file)
    :precondition (and
      (file_exists ?dst)
      (can_escalate ?actor)
    )
    :effect (and
      (security_context_set ?dst ?ctx)
    )
  )

  (:action create_sparse_file
    :parameters (?dest - file ?source - file)
    :precondition (and
      (file_exists ?source)
    )
    :effect (and
      (file_sparse ?dest)
    )
  )

  (:action inhibit_sparse_files
    :parameters (?dest - file ?source - file)
    :precondition (and
      (file_exists ?source)
    )
    :effect (and
      (not (file_sparse ?dest))
    )
  )

  (:action replace_all_files
    :parameters (?dest - directory ?source - directory)
    :precondition (and
      (directory_exists ?dest)
      (directory_exists ?source)
    )
    :effect (and
      (files_replaced ?dest)
    )
  )

  (:action skip_replacing_files
    :parameters (?dest - directory ?source - directory)
    :precondition (and
      (directory_exists ?dest)
      (directory_exists ?source)
    )
    :effect (and
      (files_not_replaced ?dest)
    )
  )

  (:action replace_older_files
    :parameters (?dest - directory ?source - directory)
    :precondition (and
      (directory_exists ?dest)
      (directory_exists ?source)
    )
    :effect (and
      (older_files_replaced ?dest)
    )
  )

  (:action perform_lightweight_copy
    :parameters (?dest - file ?source - file)
    :precondition (and
      (file_exists ?source)
    )
    :effect (and
      (lightweight_copy ?dest)
    )
  )

  (:action copy_fail
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (not (file_exists ?dst))
    )
  )

  (:action fallback_copy
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (not (copy_possible ?src ?dst))
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action make_backup
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (backup_option_set)
    )
    :effect (and
      (backup_exists ?src)
    )
  )

  (:action make_numbered_backup
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (backup_option_set_to_numbered)
    )
    :effect (and
      (numbered_backup_exists ?src)
    )
  )

  (:action make_simple_backup
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (backup_option_set_to_simple)
    )
    :effect (and
      (simple_backup_exists ?src)
    )
  )

  (:action make_existing_backup
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (backup_option_set_to_existing)
      (numbered_backup_exists ?src)
    )
    :effect (and
      (numbered_backup_exists ?src)
    )
  )

  (:action make_simple_backup_if_no_numbered
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (backup_option_set_to_existing)
      (not (numbered_backup_exists ?src))
    )
    :effect (and
      (simple_backup_exists ?src)
    )
  )

  (:action make_backup_when_force_and_backup
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
      (src ?dst)
      (force_option_set)
      (backup_option_set)
    )
    :effect (and
      (backup_exists ?src)
    )
  )

  (:action copy_files_to_directory
    :parameters (?sources - file ?directory - directory)
    :precondition (and
      (directory_exists ?directory)
    )
    :effect (and
      (files_copied ?sources ?directory)
    )
  )

  (:action backup_destination_file
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?dest)
    )
    :effect (and
      (file_backed_up ?dest)
    )
  )

  (:action copy_special_file_contents
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_contents_copied ?src ?dest)
    )
  )

  (:action follow_command_line_symlinks
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (symlink_followed ?src ?dest)
    )
  )

  (:action hard_link_files
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (hard_link_created ?src ?dest)
    )
  )

  (:action dereference_symlinks
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (symlink_dereferenced ?src ?dest)
    )
  )

  (:action no_clobber
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?dst)
    )
    :effect (and
      (not (file_exists ?dst))
    )
  )

  (:action no_dereference
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action preserve_attributes
    :parameters (?src - file ?dst - file ?attrs - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action no_preserve_attributes
    :parameters (?src - file ?dst - file ?attrs - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action recursive_copy
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action override_backup_suffix
    :parameters (?suffix - file)
    :precondition (and
    )
    :effect (and
      (backup_suffix_set ?suffix)
    )
  )

  (:action copy_to_directory
    :parameters (?src - file ?dir - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dir)
    )
    :effect (and
      (file_copied_to_directory ?src ?dir)
    )
  )

  (:action control_file_updates
    :parameters (?update - file)
    :precondition (and
      (file_exists ?update)
    )
    :effect (and
      (file_update_controlled ?update)
    )
  )

  (:action set_selinux_context_custom
    :parameters (?dest - file ?ctx - file)
    :precondition (and
      (file_exists ?dest)
      (file_exists ?ctx)
    )
    :effect (and
      (selinux_context_set_custom ?dest ?ctx)
    )
  )

  (:action copy_all_files
    :parameters (?src - directory ?dst - directory)
    :precondition (and
      (directory_exists ?src)
      (directory_exists ?dst)
    )
    :effect (and
      (files_replaced ?src ?dst)
    )
  )

  (:action copy_no_clobber
    :parameters (?src - directory ?dst - directory)
    :precondition (and
      (directory_exists ?src)
      (directory_exists ?dst)
    )
    :effect (and
      (files_not_replaced ?src ?dst)
    )
  )

  (:action copy_no_clobber_fail
    :parameters (?src - directory ?dst - directory)
    :precondition (and
      (directory_exists ?src)
      (directory_exists ?dst)
    )
    :effect (and
      (files_not_replaced ?src ?dst)
      (skipped_files_fail ?src ?dst)
    )
  )

  (:action copy_update_older
    :parameters (?src - directory ?dst - directory)
    :precondition (and
      (directory_exists ?src)
      (directory_exists ?dst)
    )
    :effect (and
      (files_replaced_if_older ?src ?dst)
    )
  )

  (:action copy_reflink
    :parameters (?src - directory ?dst - directory)
    :precondition (and
      (directory_exists ?src)
      (directory_exists ?dst)
      (reflink_supported)
    )
    :effect (and
      (files_reflinked ?src ?dst)
    )
  )

  (:action copy_standard
    :parameters (?src - directory ?dst - directory)
    :precondition (and
      (directory_exists ?src)
      (directory_exists ?dst)
    )
    :effect (and
      (files_copied_standard ?src ?dst)
    )
  )

  (:action set_version_control
    :parameters (?method - file)
    :precondition (and
      (file_exists ?method)
    )
    :effect (and
      (version_control_set ?method)
    )
  )

  (:action move_file
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (not (file_exists ?src))
      (file_exists ?dst)
    )
  )

  (:action move_files_to_directory
    :parameters (?source - file ?directory - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?directory)
    )
    :effect (and
      (file_in_directory ?source ?directory)
    )
  )

  (:action move_to_directory
    :parameters (?src - file ?dir - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dir)
    )
    :effect (and
      (file_in_directory ?src ?dir)
    )
  )

  (:action disable_backup
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (backup_disabled ?file)
    )
  )

  (:action enable_numbered_backup
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (backup_numbered ?file)
    )
  )

  (:action enable_existing_backup
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (backup_existing ?file)
    )
  )

  (:action enable_simple_backup
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (backup_simple ?file)
    )
  )

  (:action rename_file
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
    )
    :effect (and
      (file_exists ?dest)
      (not (file_exists ?source))
    )
  )

  (:action backup_file
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?dst)
    )
    :effect (and
      (file_exists ?dst)
      (file_backed_up ?dst)
    )
  )

  (:action force_overwrite
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?dst)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action interactive_overwrite
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?dst)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action no_target_directory
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?dst)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action set_update_mode
    :parameters (?mode - file)
    :precondition (and
      (file_exists ?mode)
    )
    :effect (and
      (update_mode_set ?mode)
    )
  )

  (:action backup_with_suffix
    :parameters (?src - file ?dst - file ?suffix - directory)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action backup_numbered
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action backup_simple
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action backup_existing
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action backup_none
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action delete_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (not (file_critical ?f))
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action remove_file
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (not (file_exists ?file))
    )
  )

  (:action prompt_before_removal
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (interactive_prompted ?file)
    )
  )

  (:action prompt_once_before_removal
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
      (count_files ?file ?obj_3)
    )
    :effect (and
      (interactive_prompted_once ?file)
    )
  )

  (:action remove_directory_recursively
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_removed ?dir)
    )
  )

  (:action remove_empty_directory
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (directory_empty ?dir)
    )
    :effect (and
      (directory_removed ?dir)
    )
  )

  (:action remove_directory
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (not (directory_exists ?dir))
    )
  )

  (:action skip_different_filesystem
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (filesystem_different ?dir)
    )
    :effect (and
      (not (directory_removed ?dir))
    )
  )

  (:action do_not_treat_root_special
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (root_not_special ?dir)
    )
  )

  (:action preserve_root
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (dir_equals_root ?dir)
    )
    :effect (and
      (not (directory_removed ?dir))
    )
  )

  (:action reject_separate_device
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (separate_device ?dir)
    )
    :effect (and
      (not (directory_removed ?dir))
    )
  )

  (:action prompt_interactive
    :parameters (?when - file)
    :precondition (and
      (when_in_never_once_always ?when)
    )
    :effect (and
      (prompted_interactive ?when)
    )
  )

  (:action prompt_always
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (prompted_always ?dir)
    )
  )

  (:action prompt_once
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (prompted_once ?dir)
    )
  )

  (:action remove_file_with_dash_prefix
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (not (file_exists ?file))
    )
  )

  (:action change_permissions
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_writable ?f)
    )
  )

  (:action change_file_mode
    :parameters (?f - file ?mode - directory)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action set_permissions
    :parameters (?f - file ?mode - directory)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action change_symlink_target_permissions
    :parameters (?link - file)
    :precondition (and
      (file_exists ?link)
    )
    :effect (and
      (file_executable ?link)
    )
  )

  (:action preserve_special_bits
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (preserved_special_bits ?f)
    )
  )

  (:action modify_special_bits
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (modified_special_bits ?f)
    )
  )

  (:action clear_special_bits_numeric
    :parameters (?d - directory)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (cleared_special_bits ?d)
    )
  )

  (:action set_restricted_deletion_flag
    :parameters (?actor - user ?d - directory)
    :precondition (and
      (directory_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (restricted_deletion_flag_set ?d)
    )
  )

  (:action change_mode_reference
    :parameters (?file - file ?rfile - file)
    :precondition (and
      (file_exists ?file)
      (file_exists ?rfile)
    )
    :effect (and
      (file_mode_changed ?file)
    )
  )

  (:action suppress_errors
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (errors_suppressed ?file)
    )
  )

  (:action dereference_symbolic_link
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
      (symbolic_link ?file)
    )
    :effect (and
      (referent_affected ?file)
    )
  )

  (:action no_dereference_symbolic_link
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
      (symbolic_link ?file)
    )
    :effect (and
      (symbolic_link_affected ?file)
    )
  )

  (:action recursive_change
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (recursive_change_applied ?file)
    )
  )

  (:action traverse_symbolic_links
    :parameters (?path - directory)
    :precondition (and
      (file_exists ?path)
      (not (file_executable ?path))
    )
    :effect (and
      (file_executable ?path)
    )
  )

  (:action traverse_all_symbolic_links
    :parameters (?path - directory)
    :precondition (and
      (file_exists ?path)
      (not (file_executable ?path))
    )
    :effect (and
      (file_executable ?path)
    )
  )

  (:action do_not_traverse_symbolic_links
    :parameters (?path - directory)
    :precondition (and
      (file_exists ?path)
      (not (file_executable ?path))
    )
    :effect (and
      (file_executable ?path)
    )
  )

  (:action copy_file_mode
    :parameters (?f - file ?r - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?r)
    )
    :effect (and
      (file_mode_copied ?f ?r)
    )
  )

  (:action reference_file_mode
    :parameters (?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
    )
    :effect (and
      (file_mode_referenced ?f ?rfile)
    )
  )

  (:action recursive_permissions
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_permissions_recursive ?f)
    )
  )

  (:action traverse_symbolic_link
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (file_is_symbolic_link ?f)
    )
    :effect (and
      (symbolic_link_traversed ?f)
    )
  )

  (:action no_symbolic_link_traversal
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (no_symbolic_links_traversed ?f)
    )
  )

  (:action make_file_executable
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action change_owner
    :parameters (?actor - user ?f - file ?u - user)
    :precondition (and
      (file_exists ?f)
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?f ?u)
    )
  )

  (:action change_ownership
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?f ?owner ?group)
    )
  )

  (:action change_owner_group
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owner ?f ?owner)
      (file_group ?f ?group)
    )
  )

  (:action change_group
    :parameters (?actor - user ?f - file ?group - group)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_group ?f ?group)
    )
  )

  (:action change_ownership_if_match
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?f ?owner ?group)
    )
  )

  (:action no_preserve_root
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (root_not_preserved ?f)
    )
  )

  (:action reference_ownership
    :parameters (?actor - user ?f - file ?ref - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?ref)
      (can_escalate ?actor)
    )
    :effect (and
      (file_ownership_referenced ?f ?ref)
    )
  )

  (:action recursive_ownership_change
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (ownership_changed_recursively ?f)
    )
  )

  (:action traverse_all_symlinks
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (symlinks_traversed ?f)
    )
  )

  (:action no_traverse_symlinks
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (symlinks_not_traversed ?f)
    )
  )

  (:action change_owner_group_reference
    :parameters (?actor - user ?rfile - file ?f - file)
    :precondition (and
      (file_exists ?rfile)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_change_owner_group_reference)
    )
  )

  (:action create_directory
    :parameters (?d - directory)
    :precondition (and
      (not (file_exists ?d))
    )
    :effect (and
      (file_exists ?d)
    )
  )

  (:action create_file
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action update_file_timestamp
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_modified ?f)
    )
  )

  (:action update_file_times
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
    )
  )

  (:action update_access_time
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_updated ?f)
    )
  )

  (:action update_modification_time
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_modification_time_updated ?f)
    )
  )

  (:action update_file_times_with_stamp
    :parameters (?f - file ?stamp - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
    )
  )

  (:action update_file_times_with_date
    :parameters (?f - file ?date - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
    )
  )

  (:action update_file_times_no_create
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
    )
  )

  (:action change_symlink_timestamp
    :parameters (?link - file)
    :precondition (and
      (file_exists ?link)
    )
    :effect (and
      (file_timestamp_changed ?link)
    )
  )

  (:action reference_file_times
    :parameters (?ref - file ?target - file)
    :precondition (and
      (file_exists ?ref)
      (file_exists ?target)
    )
    :effect (and
      (file_timestamp_changed ?target)
    )
  )

  (:action change_specific_timestamp
    :parameters (?target - file ?time_type - file)
    :precondition (and
      (file_exists ?target)
      (time_type_valid ?time_type)
    )
    :effect (and
      (file_timestamp_changed ?target)
    )
  )

  (:action enable_interface
    :parameters (?actor - user ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (not (interface_up ?iface))
      (can_escalate ?actor)
    )
    :effect (and
      (interface_up ?iface)
    )
  )

  (:action disable_interface
    :parameters (?actor - user ?iface - interface)
    :precondition (and
      (interface_up ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (not (interface_up ?iface))
    )
  )

  (:action output_human_readable_stats
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (human_readable_output_enabled)
    )
  )

  (:action batch_execute
    :parameters (?filename - file)
    :precondition (and
      (file_exists ?filename)
    )
    :effect (and
      (batch_execution_completed)
    )
  )

  (:action force_batch_execution
    :parameters (?filename - file)
    :precondition (and
      (file_exists ?filename)
    )
    :effect (and
      (batch_execution_completed)
      (non_zero_return_code)
    )
  )

  (:action output_stats
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (detailed_output_enabled)
    )
  )

  (:action output_details
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (very_detailed_output_enabled)
    )
  )

  (:action set_max_loops
    :parameters (?count - file)
    :precondition (and
    )
    :effect (and
      (max_loops_set ?count)
    )
  )

  (:action set_protocol_family
    :parameters (?family - file)
    :precondition (and
    )
    :effect (and
      (protocol_family_set ?family)
    )
  )

  (:action output_oneline
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (output_format_oneline)
    )
  )

  (:action switch_network_namespace
    :parameters (?actor - user ?netns - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (network_namespace_active ?netns)
    )
  )

  (:action execute_command_all_objects
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (command_executed_all_objects)
    )
  )

  (:action configure_color_output
    :parameters (?color_mode - file)
    :precondition (and
    )
    :effect (and
      (color_output_configured ?color_mode)
    )
  )

  (:action configure_addrlabel
    :parameters (?actor - user ?label - file)
    :precondition (and
      (file_exists ?label)
      (can_escalate ?actor)
    )
    :effect (and
      (addrlabel_configured ?label)
    )
  )

  (:action configure_fou
    :parameters (?actor - user ?port - port)
    :precondition (and
      (port_open ?port)
      (can_escalate ?actor)
    )
    :effect (and
      (fou_configured ?port)
    )
  )

  (:action configure_ila
    :parameters (?actor - user ?addr - file)
    :precondition (and
      (file_exists ?addr)
      (can_escalate ?actor)
    )
    :effect (and
      (ila_configured ?addr)
    )
  )

  (:action configure_ioam
    :parameters (?actor - user ?namespace - file)
    :precondition (and
      (file_exists ?namespace)
      (can_escalate ?actor)
    )
    :effect (and
      (ioam_configured ?namespace)
    )
  )

  (:action configure_l2tp
    :parameters (?actor - user ?tunnel - file)
    :precondition (and
      (file_exists ?tunnel)
      (can_escalate ?actor)
    )
    :effect (and
      (l2tp_configured ?tunnel)
    )
  )

  (:action configure_link
    :parameters (?actor - user ?device - file)
    :precondition (and
      (file_exists ?device)
      (can_escalate ?actor)
    )
    :effect (and
      (link_configured ?device)
    )
  )

  (:action configure_macsec
    :parameters (?actor - user ?device - file)
    :precondition (and
      (file_exists ?device)
      (can_escalate ?actor)
    )
    :effect (and
      (macsec_configured ?device)
    )
  )

  (:action configure_maddress
    :parameters (?actor - user ?addr - file)
    :precondition (and
      (file_exists ?addr)
      (can_escalate ?actor)
    )
    :effect (and
      (maddress_configured ?addr)
    )
  )

  (:action configure_monitor
    :parameters (?actor - user ?monitor - file)
    :precondition (and
      (file_exists ?monitor)
      (can_escalate ?actor)
    )
    :effect (and
      (monitor_configured ?monitor)
    )
  )

  (:action configure_mptcp
    :parameters (?actor - user ?path - file)
    :precondition (and
      (file_exists ?path)
      (can_escalate ?actor)
    )
    :effect (and
      (mptcp_configured ?path)
    )
  )

  (:action configure_mroute
    :parameters (?actor - user ?route - file)
    :precondition (and
      (file_exists ?route)
      (can_escalate ?actor)
    )
    :effect (and
      (mroute_configured ?route)
    )
  )

  (:action configure_mrule
    :parameters (?actor - user ?rule - file)
    :precondition (and
      (file_exists ?rule)
      (can_escalate ?actor)
    )
    :effect (and
      (mrule_configured ?rule)
    )
  )

  (:action configure_neigh
    :parameters (?actor - user ?entry - file)
    :precondition (and
      (file_exists ?entry)
      (can_escalate ?actor)
    )
    :effect (and
      (neigh_configured ?entry)
    )
  )

  (:action configure_netns
    :parameters (?actor - user ?namespace - file)
    :precondition (and
      (file_exists ?namespace)
      (can_escalate ?actor)
    )
    :effect (and
      (netns_configured ?namespace)
    )
  )

  (:action configure_route
    :parameters (?actor - user ?route - file)
    :precondition (and
      (file_exists ?route)
      (can_escalate ?actor)
    )
    :effect (and
      (route_configured ?route)
    )
  )

  (:action configure_rule
    :parameters (?actor - user ?rule - file)
    :precondition (and
      (file_exists ?rule)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_configured ?rule)
    )
  )

  (:action configure_tunnel
    :parameters (?actor - user ?tunnel - file)
    :precondition (and
      (file_exists ?tunnel)
      (can_escalate ?actor)
    )
    :effect (and
      (tunnel_configured ?tunnel)
    )
  )

  (:action configure_xfrm
    :parameters (?actor - user ?policy - file)
    :precondition (and
      (file_exists ?policy)
      (can_escalate ?actor)
    )
    :effect (and
      (xfrm_configured ?policy)
    )
  )

  (:action manage_ipv6_segment_routing
    :parameters (?actor - user ?sr - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (segment_routing_configured ?sr)
    )
  )

  (:action manage_tcp_metrics
    :parameters (?actor - user ?tcp_metrics - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (tcp_metrics_configured ?tcp_metrics)
    )
  )

  (:action manage_tokenized_interface_identifiers
    :parameters (?actor - user ?token - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (tokenized_interface_configured ?token)
    )
  )

  (:action manage_tunnel
    :parameters (?actor - user ?tunnel - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (tunnel_configured ?tunnel)
    )
  )

  (:action manage_tuntap_devices
    :parameters (?actor - user ?tuntap - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (tuntap_device_configured ?tuntap)
    )
  )

  (:action manage_vrf_devices
    :parameters (?actor - user ?vrf - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (vrf_device_configured ?vrf)
    )
  )

  (:action manage_ipsec_policies
    :parameters (?actor - user ?xfrm - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (ipsec_policy_configured ?xfrm)
    )
  )

  (:action bring_up_interface
    :parameters (?actor - user ?x - interface)
    :precondition (and
      (interface_exists ?x)
      (not (interface_up ?x))
      (can_escalate ?actor)
    )
    :effect (and
      (interface_up ?x)
    )
  )

  (:action bring_down_interface
    :parameters (?actor - user ?x - interface)
    :precondition (and
      (interface_exists ?x)
      (interface_up ?x)
      (can_escalate ?actor)
    )
    :effect (and
      (not (interface_up ?x))
    )
  )

  (:action add_ip_command
    :parameters (?actor - user ?cmd - file)
    :precondition (and
      (not (command_exists ?cmd))
      (can_escalate ?actor)
    )
    :effect (and
      (command_exists ?cmd)
    )
  )

  (:action block_traffic
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (not (firewall_rule_exists ?rule))
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?rule)
      (traffic_blocked ?rule)
    )
  )

  (:action allow_traffic
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (traffic_blocked ?rule)
      (can_escalate ?actor)
    )
    :effect (and
      (not (traffic_blocked ?rule))
    )
  )

  (:action open_port
    :parameters (?actor - user ?p - port)
    :precondition (and
      (not (port_allowed ?p))
      (can_escalate ?actor)
    )
    :effect (and
      (port_allowed ?p)
    )
  )

  (:action configure_firewall
    :parameters (?actor - user ?table - file ?chain - file ?rule_spec - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_modified ?table ?chain ?rule_spec)
    )
  )

  (:action insert_firewall_rule
    :parameters (?actor - user ?table - file ?chain - file ?rulenum - file ?rule_spec - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_inserted ?table ?chain ?rulenum ?rule_spec)
    )
  )

  (:action replace_firewall_rule
    :parameters (?actor - user ?table - file ?chain - file ?rulenum - file ?rule_spec - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_replaced ?table ?chain ?rulenum ?rule_spec)
    )
  )

  (:action delete_firewall_rule
    :parameters (?actor - user ?table - file ?chain - file ?rulenum - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_deleted ?table ?chain ?rulenum)
    )
  )

  (:action flush_firewall_rules
    :parameters (?actor - user ?table - file ?chain - file ?rulenum - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rules_flushed ?table ?chain ?rulenum)
    )
  )

  (:action create_firewall_chain
    :parameters (?actor - user ?table - file ?chain - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_chain_created ?table ?chain)
    )
  )

  (:action delete_firewall_chain
    :parameters (?actor - user ?table - file ?chain - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_chain_deleted ?table ?chain)
    )
  )

  (:action set_firewall_policy
    :parameters (?actor - user ?table - file ?chain - file ?policy - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_policy_set ?table ?chain ?policy)
    )
  )

  (:action rename_firewall_chain
    :parameters (?actor - user ?table - file ?old_chain - file ?new_chain - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_chain_renamed ?table ?old_chain ?new_chain)
    )
  )

  (:action configure_firewall_rules
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_configured ?rule)
    )
  )

  (:action define_firewall_table
    :parameters (?actor - user ?table - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_table_defined ?table)
    )
  )

  (:action add_firewall_rule
    :parameters (?actor - user ?rule - firewall_rule ?chain - firewall_rule)
    :precondition (and
      (firewall_chain_added ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_added ?rule)
    )
  )

  (:action accept_packets
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (firewall_rule_added ?rule)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_acceptance_set ?rule)
    )
  )

  (:action drop_packets
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (firewall_rule_added ?rule)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_drop_set ?rule)
    )
  )

  (:action return_packets
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (firewall_rule_added ?rule)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_return_set ?rule)
    )
  )

  (:action set_packet_table
    :parameters (?actor - user ?table - file)
    :precondition (and
      (table_exists ?table)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_table_set ?table)
    )
  )

  (:action configure_connection_tracking_exemption
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action alter_forwarded_packets
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action alter_outgoing_packets
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action register_high_priority_rule
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action configure_mandatory_access_control
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action append_iptables_rule
    :parameters (?actor - user ?chain - directory ?rule_spec - file)
    :precondition (and
      (file_exists ?rule_spec)
      (can_escalate ?actor)
    )
    :effect (and
      (iptables_rule_appended ?chain ?rule_spec)
    )
  )

  (:action delete_iptables_rule
    :parameters (?actor - user ?chain - directory ?rule_spec - file)
    :precondition (and
      (rule_exists ?chain ?rule_spec)
      (can_escalate ?actor)
    )
    :effect (and
      (not (rule_exists ?chain ?rule_spec))
    )
  )

  (:action insert_iptables_rule
    :parameters (?actor - user ?chain - directory ?rulenum - port ?rule_spec - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_exists ?chain ?rule_spec)
    )
  )

  (:action replace_iptables_rule
    :parameters (?actor - user ?chain - file ?rule_num - file ?rule_spec - file)
    :precondition (and
      (firewall_rule_exists ?chain ?rule_num)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_modified ?chain ?rule_num)
    )
  )

  (:action flush_chain
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_flushed ?chain)
    )
  )

  (:action zero_counters
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_counters_zeroed ?chain)
    )
  )

  (:action create_chain
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (not (firewall_rule_exists ?chain))
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?chain)
    )
  )

  (:action delete_chain
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (not (firewall_rule_referenced ?chain))
      (can_escalate ?actor)
    )
    :effect (and
      (not (firewall_rule_exists ?chain))
    )
  )

  (:action set_chain_policy
    :parameters (?actor - user ?chain - firewall_rule ?target - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_policy_set ?chain ?target)
    )
  )

  (:action rename_chain
    :parameters (?actor - user ?old_chain - firewall_rule ?new_chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?old_chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_renamed ?old_chain ?new_chain)
    )
  )

  (:action allow_mixed_ip_rules
    :parameters (?actor - user ?rule_file - file)
    :precondition (and
      (file_exists ?rule_file)
      (can_escalate ?actor)
    )
    :effect (and
      (ipv4_ipv6_rules_allowed ?rule_file)
    )
  )

  (:action set_protocol
    :parameters (?actor - user ?protocol - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (protocol_set ?protocol)
    )
  )

  (:action set_iptables_mask
    :parameters (?actor - user ?mask - port)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (port_allowed ?mask)
    )
  )

  (:action invert_iptables_address
    :parameters (?actor - user ?addr - port)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?addr)
    )
  )

  (:action set_iptables_match
    :parameters (?actor - user ?match - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (port_allowed ?match)
    )
  )

  (:action set_iptables_target
    :parameters (?actor - user ?target - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (port_allowed ?target)
    )
  )

  (:action apply_firewall_rule
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?rule)
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action match_interface
    :parameters (?actor - user ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_matched_interface ?iface)
    )
  )

  (:action set_out_interface
    :parameters (?actor - user ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (out_interface_set ?iface)
    )
  )

  (:action set_out_interface_wildcard
    :parameters (?actor - user ?iface_prefix - interface)
    :precondition (and
      (interface_exists ?iface_prefix)
      (can_escalate ?actor)
    )
    :effect (and
      (out_interface_wildcard_set ?iface_prefix)
    )
  )

  (:action match_fragmented_packets
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (fragmented_packets_matched)
    )
  )

  (:action match_head_fragments
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (head_fragments_matched)
    )
  )

  (:action set_counters
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?rule)
      (can_escalate ?actor)
    )
    :effect (and
      (counters_initialized ?rule)
    )
  )

  (:action use_custom_modprobe
    :parameters (?actor - user ?cmd - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (modprobe_command_set ?cmd)
    )
  )

  (:action exit_success
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (exit_code ?obj_0)
    )
  )

  (:action exit_invalid_params
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (exit_code ?obj_2)
    )
  )

  (:action exit_incompatibility
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (exit_code ?obj_3)
    )
  )

  (:action exit_resource_error
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (exit_code ?obj_4)
    )
  )

  (:action exit_other_error
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (exit_code ?obj_1)
    )
  )

  (:action exit_setuid_error
    :parameters (?obj - file)
    :precondition (and
      (setuid_to_root)
    )
    :effect (and
      (exit_code ?obj_111)
    )
  )

  (:action add_chain_rule
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_modified ?chain)
    )
  )

  (:action insert_chain_rule
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_modified ?chain)
    )
  )

  (:action replace_chain_rule
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_modified ?chain)
    )
  )

  (:action delete_chain_rule
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_modified ?chain)
    )
  )

  (:action flush_chains
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_flushed ?chain)
    )
  )

  (:action append_firewall_rule
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?chain)
    )
  )

  (:action delete_firewall_rule_by_number
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (not (firewall_rule_exists ?chain))
    )
  )

  (:action change_firewall_chain_policy
    :parameters (?actor - user ?chain - firewall_rule ?policy - file)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?chain)
    )
  )

  (:action execute_privileged
    :parameters (?u - user ?cmd - process)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?u)
      (not (requires_env_preservation ?cmd))
    )
    :effect (and
      (executed_as_root ?cmd)
    )
  )

  (:action execute_as_user
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (command_executed ?cmd)
    )
  )

  (:action run_additional_command
    :parameters (?cmd - file)
    :precondition (and
      (session_record_exists)
    )
    :effect (and
      (command_executed ?cmd)
    )
  )

  (:action remove_timestamp
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (timestamp_removed ?user)
    )
  )

  (:action reset_timestamp
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (timestamp_reset ?user)
    )
  )

  (:action authenticate_user
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (authenticated ?user)
    )
  )

  (:action preserve_session
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (session_preserved ?user)
    )
  )

  (:action edit_file
    :parameters (?actor - user ?file - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (file_edited ?file)
    )
  )

  (:action copy_back_and_remove_temp
    :parameters (?file - file)
    :precondition (and
      (file_edited ?file)
    )
    :effect (and
      (file_updated ?file)
    )
  )

  (:action run_as_user
    :parameters (?actor - user ?user - user ?command - process)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (process_running ?command)
    )
  )

  (:action change_directory
    :parameters (?actor - user ?directory - directory ?command - process)
    :precondition (and
      (directory_exists ?directory)
      (can_escalate ?actor)
    )
    :effect (and
      (process_running ?command)
    )
  )

  (:action invalidate_timestamp
    :parameters (?actor - user ?file - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (timestamp_invalidated ?file)
    )
  )

  (:action modify_environment_with_pam
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (environment_modified_by_pam ?user)
    )
  )

  (:action reset_resource_limits
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (resource_limits_reset ?user)
    )
  )

  (:action execute_command_as_user
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (command_executed_as_user ?user ?cmd)
    )
  )

  (:action start_login_shell
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (shell_login ?user)
    )
  )

  (:action change_home_directory
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_changed ?user)
    )
  )

  (:action set_login_shell
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (login_shell_set ?user)
    )
  )

  (:action preserve_environment
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (environment_preserved ?user)
    )
  )

  (:action create_pty
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (pty_created ?user)
    )
  )

  (:action set_root_path
    :parameters (?actor - user ?rootpath - directory ?supath - directory)
    :precondition (and
      (user_exists ?root)
      (can_escalate ?actor)
    )
    :effect (and
      (path_set_for_root ?rootpath ?supath)
    )
  )

  (:action initialize_path
    :parameters (?actor - user ?path - directory)
    :precondition (and
      (user_exists ?root)
      (always_set_path ?true)
      (can_escalate ?actor)
    )
    :effect (and
      (path_initialized ?path)
    )
  )

  (:action configure_su_pam
    :parameters (?actor - user ?config - file)
    :precondition (and
      (file_exists ?config)
      (can_escalate ?actor)
    )
    :effect (and
      (pam_configured ?config)
    )
  )

  (:action change_user
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_critical ?user)
    )
  )

  (:action add_user_to_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (not (member_of ?u ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (member_of ?u ?g)
    )
  )

  (:action lock_user
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (not (user_locked ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_locked ?u)
    )
  )

  (:action unlock_user
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (user_locked ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_locked ?u))
    )
  )

  (:action modify_user_account
    :parameters (?actor - user ?login - user)
    :precondition (and
      (user_exists ?login)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?login)
    )
  )

  (:action update_user_comment
    :parameters (?actor - user ?login - user ?comment - file)
    :precondition (and
      (user_exists ?login)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?login)
    )
  )

  (:action set_account_expiration
    :parameters (?actor - user ?login - user ?expire_date - file)
    :precondition (and
      (user_exists ?login)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?login)
    )
  )

  (:action change_primary_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (user_primary_group ?user ?group)
    )
  )

  (:action change_supplementary_groups
    :parameters (?actor - user ?user - user ?groups - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (user_supplementary_groups ?user ?groups)
    )
  )

  (:action append_supplementary_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_group ?user ?group)
    )
  )

  (:action change_login_name
    :parameters (?actor - user ?user - user ?new_login - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?new_login)
    )
  )

  (:action lock_user_password
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (user_locked ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_locked ?user)
    )
  )

  (:action move_home_directory
    :parameters (?actor - user ?user - user ?new_home - directory)
    :precondition (and
      (user_exists ?user)
      (directory_exists ?new_home)
      (can_escalate ?actor)
    )
    :effect (and
      (user_home_directory ?user ?new_home)
    )
  )

  (:action adapt_file_ownership
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (file_ownership_adapted ?user)
    )
  )

  (:action change_user_id_non_unique
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_id_non_unique ?user)
    )
  )

  (:action change_user_password
    :parameters (?actor - user ?user - user ?password - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_password_changed ?user)
    )
  )

  (:action remove_user_from_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_in_group ?user ?group))
    )
  )

  (:action apply_chroot_changes
    :parameters (?actor - user ?chroot_dir - directory)
    :precondition (and
      (directory_exists ?chroot_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_chroot ?chroot_dir)
    )
  )

  (:action apply_prefix_changes
    :parameters (?actor - user ?prefix_dir - directory)
    :precondition (and
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_prefix ?prefix_dir)
    )
  )

  (:action change_user_shell
    :parameters (?actor - user ?user - user ?shell - file)
    :precondition (and
      (user_exists ?user)
      (file_exists ?shell)
      (can_escalate ?actor)
    )
    :effect (and
      (user_shell_changed ?user ?shell)
    )
  )

  (:action change_user_uid
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_uid_changed ?user ?uid)
    )
  )

  (:action add_subordinate_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uids_added ?user ?first ?last)
    )
  )

  (:action remove_subordinate_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (subordinate_uids_added ?user ?first ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uids_removed ?user ?first ?last)
    )
  )

  (:action add_subordinate_gids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gids_added ?user ?first ?last)
    )
  )

  (:action remove_subordinate_gids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (user_has_subordinate_gids ?user ?first ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_has_subordinate_gids ?user ?first ?last))
    )
  )

  (:action set_selinux_user
    :parameters (?actor - user ?user - user ?seuser - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_selinux_user ?user ?seuser)
    )
  )

  (:action set_selinux_range
    :parameters (?actor - user ?user - user ?range - file)
    :precondition (and
      (user_exists ?user)
      (selinux_user_set ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_range_set ?user ?range)
    )
  )

  (:action create_mail_spool
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (create_mail_spool)
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_exists ?user)
    )
  )

  (:action delete_mail_spool
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (mail_spool_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (mail_spool_exists ?user))
    )
  )

  (:action move_mail_spool
    :parameters (?actor - user ?user - user ?new_home - directory)
    :precondition (and
      (user_exists ?user)
      (mail_spool_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_moved ?user ?new_home)
    )
  )

  (:action allocate_subordinate_uids
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (subordinate_uids_allocated ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uids_allocated ?user)
    )
  )

  (:action allocate_subordinate_gids
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (subordinate_gids_allocated ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gids_allocated ?user)
    )
  )

  (:action append_user_to_groups
    :parameters (?actor - user ?user - user ?groups - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_group ?user ?groups)
    )
  )

  (:action allow_bad_names
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_bad_name ?user)
    )
  )

  (:action set_gecos_field
    :parameters (?actor - user ?user - user ?comment - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_gecos ?user ?comment)
    )
  )

  (:action set_home_directory
    :parameters (?actor - user ?user - user ?home - directory)
    :precondition (and
      (user_exists ?user)
      (directory_exists ?home)
      (can_escalate ?actor)
    )
    :effect (and
      (user_home_directory ?user ?home)
    )
  )

  (:action set_password_inactive
    :parameters (?actor - user ?user - user ?inactive - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_password_inactive ?user ?inactive)
    )
  )

  (:action set_primary_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (user_primary_group ?user ?group)
    )
  )

  (:action set_user_groups
    :parameters (?actor - user ?user - user ?groups - group)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_groups_set ?user ?groups)
    )
  )

  (:action change_user_login
    :parameters (?actor - user ?user - user ?new_login - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_login_changed ?user ?new_login)
    )
  )

  (:action lock_user_account
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (user_locked ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_locked ?user)
    )
  )

  (:action set_user_shell
    :parameters (?actor - user ?user - user ?shell - file)
    :precondition (and
      (user_exists ?user)
      (file_exists ?shell)
      (can_escalate ?actor)
    )
    :effect (and
      (user_shell_set ?user ?shell)
    )
  )

  (:action set_user_uid
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action add_sub_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action remove_sub_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action add_sub_gids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action remove_sub_gids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action create_user
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
    )
  )

  (:action set_user_comment
    :parameters (?actor - user ?user - user ?comment - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_comment_set ?user ?comment)
    )
  )

  (:action set_password_inactive_days
    :parameters (?actor - user ?user - user ?days - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_inactive_days_set ?user ?days)
    )
  )

  (:action add_subids_for_system
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subids_updated ?user)
    )
  )

  (:action add_user_to_existing_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_group ?user ?group)
    )
  )

  (:action create_user_with_group
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (group_exists ?user)
      (user_in_group ?user ?user)
    )
  )

  (:action add_user_to_supplementary_groups
    :parameters (?actor - user ?user - user ?groups - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_group ?user ?groups)
    )
  )

  (:action skip_log_init
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_in_lastlog ?user))
      (not (user_in_faillog ?user))
    )
  )

  (:action create_user_no_home
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action create_user_no_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (not (user_exists ?user))
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action create_user_non_unique
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action create_user_with_password
    :parameters (?actor - user ?user - user ?password - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action create_system_account
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (user_locked ?user)
    )
  )

  (:action create_home_directory
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_exists ?user)
    )
  )

  (:action update_subuid_subgid
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_updated ?user)
      (subgid_updated ?user)
    )
  )

  (:action apply_chroot
    :parameters (?actor - user ?chroot_dir - directory)
    :precondition (and
      (directory_exists ?chroot_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_chroot ?chroot_dir)
    )
  )

  (:action apply_prefix
    :parameters (?actor - user ?prefix_dir - directory)
    :precondition (and
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_prefix ?prefix_dir)
    )
  )

  (:action create_user_group
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (group_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?user)
      (user_in_group ?user ?user)
    )
  )

  (:action set_home_base_dir
    :parameters (?actor - user ?base_dir - directory)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (home_base_dir_set ?base_dir)
    )
  )

  (:action set_default_group
    :parameters (?actor - user ?group - group)
    :precondition (and
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (default_group_set ?group)
    )
  )

  (:action set_default_shell
    :parameters (?actor - user ?shell - file)
    :precondition (and
      (file_exists ?shell)
      (can_escalate ?actor)
    )
    :effect (and
      (default_shell_set ?shell)
    )
  )

  (:action place_default_user_files
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action set_group_id_range
    :parameters (?actor - user ?min - file ?max - file)
    :precondition (and
      (min ?max)
      (min ?obj_1)
      (max ?obj_60000)
      (can_escalate ?actor)
    )
    :effect (and
      (group_id_range_set ?min ?max)
    )
  )

  (:action set_home_directory_mode
    :parameters (?actor - user ?mode - file)
    :precondition (and
      (mode ?obj_0)
      (mode ?obj_777)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_mode_set ?mode)
    )
  )

  (:action set_lastlog_uid_max
    :parameters (?actor - user ?uid - user)
    :precondition (and
      (user_exists ?uid)
      (can_escalate ?actor)
    )
    :effect (and
      (lastlog_uid_max_set ?uid)
    )
  )

  (:action set_mail_dir
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (mail_dir_set ?dir)
    )
  )

  (:action set_mail_file
    :parameters (?actor - user ?file - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (mail_file_set ?file)
    )
  )

  (:action set_max_members_per_group
    :parameters (?actor - user ?max - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (max_members_per_group_set ?max)
    )
  )

  (:action limit_group_members
    :parameters (?actor - user ?group - group ?max_members - file)
    :precondition (and
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (group_member_limit_set ?group ?max_members)
    )
  )

  (:action set_password_max_days
    :parameters (?actor - user ?user - user ?max_days - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_max_days_set ?user ?max_days)
    )
  )

  (:action set_password_min_days
    :parameters (?actor - user ?user - user ?min_days - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_min_days_set ?user ?min_days)
    )
  )

  (:action allocate_sub_gid
    :parameters (?actor - user ?user - user ?min - file ?max - file ?count - file)
    :precondition (and
      (user_exists ?user)
      (not (sub_gid_allocated ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (sub_gid_allocated ?user)
    )
  )

  (:action allocate_sub_uid
    :parameters (?actor - user ?user - user ?min - file ?max - file ?count - file)
    :precondition (and
      (user_exists ?user)
      (not (sub_uid_allocated ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (sub_uid_allocated ?user)
    )
  )

  (:action set_umask
    :parameters (?mask - directory)
    :precondition (and
    )
    :effect (and
      (umask_set ?mask)
    )
  )

  (:action remove_empty_group
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (group_exists ?user)
      (group_empty ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?user))
    )
  )

  (:action add_user
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (not (user_critical ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action skip_user_group_creation
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?user))
    )
  )

  (:action create_non_unique_user
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action chroot_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (chrooted ?dir)
    )
  )

  (:action set_prefix_directory
    :parameters (?actor - user ?prefix - directory)
    :precondition (and
      (directory_exists ?prefix)
      (can_escalate ?actor)
    )
    :effect (and
      (prefix_set ?prefix)
    )
  )

  (:action use_extra_users
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (extra_users_enabled)
    )
  )

  (:action create_group
    :parameters (?actor - user ?g - group)
    :precondition (and
      (not (group_exists ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?g)
    )
  )

  (:action create_group_with_gid
    :parameters (?actor - user ?group - group ?gid - file)
    :precondition (and
      (not (group_exists ?group))
      (not (gid_used ?gid))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
      (gid_used ?gid)
    )
  )

  (:action create_group_with_non_unique_gid
    :parameters (?actor - user ?group - group ?gid - file)
    :precondition (and
      (not (group_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
      (gid_used ?gid)
    )
  )

  (:action set_group_password
    :parameters (?actor - user ?g - group ?password - file)
    :precondition (and
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (group_password_set ?g)
    )
  )

  (:action create_system_group
    :parameters (?actor - user ?g - group)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?g)
      (group_is_system ?g)
    )
  )

  (:action chroot_group_operation
    :parameters (?actor - user ?g - group ?chroot_dir - directory)
    :precondition (and
      (directory_exists ?chroot_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (group_operation_in_chroot ?g ?chroot_dir)
    )
  )

  (:action apply_config_changes
    :parameters (?actor - user ?prefix_dir - directory)
    :precondition (and
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?prefix_dir)
    )
  )

  (:action add_users_to_group
    :parameters (?actor - user ?users - user ?group - group)
    :precondition (and
      (group_exists ?group)
      (user_exists ?users)
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_group ?users ?group)
    )
  )

  (:action split_group
    :parameters (?actor - user ?group - group ?max_members - file)
    :precondition (and
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (group_split ?group)
    )
  )

  (:action add_group
    :parameters (?actor - user ?group - group)
    :precondition (and
      (not (group_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
    )
  )

  (:action delete_user
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (not (user_critical ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u))
    )
  )

  (:action force_delete_user
    :parameters (?actor - user ?login - user)
    :precondition (and
      (user_exists ?login)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?login))
    )
  )

  (:action apply_changes_chroot
    :parameters (?actor - user ?chroot_dir - directory)
    :precondition (and
      (directory_exists ?chroot_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_chroot ?chroot_dir)
    )
  )

  (:action apply_changes_prefix
    :parameters (?actor - user ?prefix_dir - directory)
    :precondition (and
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_prefix ?prefix_dir)
    )
  )

  (:action remove_selinux_user_mapping
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_user_mapping_removed ?user)
    )
  )

  (:action remove_user_jobs
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (cron_job_exists ?user))
      (not (at_job_exists ?user))
      (not (print_job_exists ?user))
    )
  )

  (:action remove_print_jobs
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (print_job_removed ?user)
    )
  )

  (:action force_remove_user
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
    )
  )

  (:action force_user_removal
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (user_removed ?usr)
    )
  )

  (:action remove_user_home
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_removed ?usr)
      (mail_spool_removed ?usr)
    )
  )

  (:action use_extra_users_database
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (extra_users_database_enabled)
    )
  )

)