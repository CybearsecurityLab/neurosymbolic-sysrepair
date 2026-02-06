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
    (packages_installed)
    (unnecessary_packages_removed)
    (cache_exists)
    (cache_cleared)
    (obsolete_cache_cleared)
    (build_dependencies_installed ?x0 - object)
    (source_downloaded ?x0 - object)
    (apt_install_recommends_disabled)
    (apt_install_suggests_enabled)
    (packages_downloaded)
    (package_missing ?x0 - object)
    (build_profiles_activated ?x0 - object)
    (package_holds_ignored ?x0 - object)
    (allow_unauthenticated)
    (allow_downgrades)
    (allow_remove_essential)
    (allow_change_held_packages)
    (apt_default_release_set ?x0 - object)
    (apt_trivial_only_enabled)
    (package_auto_marked ?x0 - object)
    (abort_on_remove ?x0 - object)
    (unused_dependencies_removed ?x0 - object)
    (package_accepted_as_source ?x0 - object)
    (diff_downloaded ?x0 - object)
    (dsc_downloaded ?x0 - object)
    (tar_downloaded ?x0 - object)
    (arch_dependencies_processed ?x0 - object)
    (indep_dependencies_processed ?x0 - object)
    (authentication_ignored ?x0 - object)
    (allow_insecure_repositories)
    (allow_releaseinfo_change)
    (source_file_added ?x0 - object)
    (error_on_any_enabled)
    (update_run_before_command)
    (apt_config_option_set ?x0 - object)
    (apt_color_set ?x0 - object)
    (directory_exists ?x0 - object)
    (state_stored ?x0 - object)
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
    (cohort_created ?x0 - object)
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
    (snap_connection_forgotten ?x0 - object)
    (snap_downloaded ?x0 - object)
    (snapshot_exported ?x0 - object)
    (quota_group_exists ?x0 - object)
    (journal_quota_set ?x0 - object ?x1 - object)
    (quota_group_removed ?x0 - object)
    (memory_limit_increased ?x0 - object)
    (cpu_limit_set ?x0 - object ?x1 - object)
    (cpu_set_modified ?x0 - object ?x1 - object)
    (threads_limit_less_than ?x0 - object ?x1 - object)
    (threads_limit_increased ?x0 - object ?x1 - object)
    (threads_limit_greater_than ?x0 - object ?x1 - object)
    (threads_limit_decreased ?x0 - object ?x1 - object)
    (snap_tried ?x0 - object)
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
    (assertion_signed ?x0 - object)
    (device_image_prepared ?x0 - object)
    (key_exists)
    (public_key_exported ?x0 - object)
    (quota_group_updated ?x0 - object)
    (none)
    (service_loaded ?x0 - object)
    (service_masked ?x0 - object)
    (pager_secure ?x0 - object)
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
    (unit_masked ?x0 - object)
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
    (file_without_trailing_slash ?x0 - object)
    (backup_suffix_override ?x0 - object)
    (file_in_directory ?x0 - object ?x1 - object)
    (file_as_normal ?x0 - object)
    (file_update_control ?x0 - object)
    (selinux_context_set ?x0 - object)
    (backup_disabled)
    (backup_method_numbered)
    (backup_method_existing)
    (backup_method_simple)
    (file_backed_up ?x0 - object)
    (update_mode_set ?x0 - object)
    (symbolic_link_exists ?x0 - object)
    (file_symlink_followed ?x0 - object ?x1 - object)
    (filesystem_boundary_respected ?x0 - object ?x1 - object)
    (selinux_context_default ?x0 - object)
    (security_context_set ?x0 - object ?x1 - object)
    (file_sparse ?x0 - object)
    (files_replaced ?x0 - object)
    (no_files_replaced ?x0 - object)
    (lightweight_copy ?x0 - object)
    (file_contents_copied ?x0 - object ?x1 - object)
    (symlink_followed ?x0 - object ?x1 - object)
    (hard_link_created ?x0 - object ?x1 - object)
    (symlink_dereferenced ?x0 - object ?x1 - object)
    (file_copied_to_directory ?x0 - object ?x1 - object)
    (selinux_context_set_custom ?x0 - object ?x1 - object)
    (files_not_replaced ?x0 - object ?x1 - object)
    (skipped_files_fail ?x0 - object ?x1 - object)
    (files_replaced_if_older ?x0 - object ?x1 - object)
    (reflink_supported)
    (files_reflinked ?x0 - object ?x1 - object)
    (files_copied_standard ?x0 - object ?x1 - object)
    (version_control_set ?x0 - object)
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
    (file_mode_changed ?x0 - object ?x1 - object)
    (file_executable ?x0 - object)
    (restricted_deletion_flag_set ?x0 - object)
    (errors_suppressed ?x0 - object)
    (link_dereferenced ?x0 - object)
    (link_not_dereferenced ?x0 - object)
    (mode_referenced ?x0 - object ?x1 - object)
    (changes_recursive ?x0 - object)
    (file_accessible ?x0 - object)
    (file_mode_copied ?x0 - object ?x1 - object)
    (file_mode_referenced ?x0 - object ?x1 - object)
    (file_permissions_recursive ?x0 - object)
    (file_is_symbolic_link ?x0 - object)
    (symbolic_link_traversed ?x0 - object)
    (no_symbolic_links_traversed ?x0 - object)
    (file_owner ?x0 - object ?x1 - object)
    (file_group ?x0 - object ?x1 - object)
    (root_not_preserved ?x0 - object)
    (file_owned_by_reference ?x0 - object ?x1 - object)
    (ownership_applied_recursively ?x0 - object)
    (all_links_traversed ?x0 - object)
    (no_links_traversed ?x0 - object)
    (owner_changed_recursive ?x0 - object ?x1 - object)
    (owner_changed ?x0 - object ?x1 - object)
    (group_changed ?x0 - object ?x1 - object)
    (ownership_changed ?x0 - object)
    (ownership_changed_recursively ?x0 - object)
    (file_access_time_updated ?x0 - object)
    (file_modification_time_updated ?x0 - object)
    (file_timestamp_changed ?x0 - object)
    (valid_time_type ?x0 - object)
    (protocol_family_set ?x0 - object)
    (output_format_oneline)
    (network_namespace_exists ?x0 - object)
    (current_network_namespace ?x0 - object)
    (command_supports_all_objects ?x0 - object)
    (command_executed_on_all_objects ?x0 - object)
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
    (segment_routing_exists ?x0 - object)
    (segment_routing_configured ?x0 - object)
    (tcp_metrics_exists ?x0 - object)
    (tcp_metrics_configured ?x0 - object)
    (token_exists ?x0 - object)
    (token_configured ?x0 - object)
    (tunnel_exists ?x0 - object)
    (tuntap_exists ?x0 - object)
    (tuntap_configured ?x0 - object)
    (vrf_exists ?x0 - object)
    (vrf_configured ?x0 - object)
    (xfrm_exists ?x0 - object)
    (ip_command_exists ?x0 - object)
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
    (firewall_rule_added ?x0 - object ?x1 - object)
    (table_exists ?x0 - object)
    (table_selected ?x0 - object)
    (connection_tracking_exempt ?x0 - object)
    (packet_altered ?x0 - object)
    (mandatory_access_control_enabled ?x0 - object)
    (chain_exists ?x0 - object)
    (chain_flushed ?x0 - object)
    (counters_zeroed ?x0 - object)
    (chain_referenced ?x0 - object)
    (empty_chains_deleted)
    (chain_policy_set ?x0 - object ?x1 - object)
    (chain_renamed ?x0 - object ?x1 - object)
    (ipv4_ipv6_rules_merged ?x0 - object)
    (header_exists ?x0 - object)
    (header_matched ?x0 - object)
    (firewall_rule_destination_set ?x0 - object ?x1 - object)
    (firewall_rule_target_set ?x0 - object)
    (firewall_rule_goto_set ?x0 - object)
    (firewall_rule_input_interface_set ?x0 - object)
    (packet_sent_via ?x0 - object)
    (fragment_rule_applied)
    (firewall_rule_counter_set ?x0 - object ?x1 - object ?x2 - object)
    (lock_available)
    (lock_acquired)
    (numeric_output_enabled)
    (iptables_extension_loaded ?x0 - object)
    (packet_framework_enabled ?x0 - object)
    (mangle_table_exists ?x0 - object)
    (owner_match_exists ?x0 - object)
    (mark_exists ?x0 - object)
    (tos_target_exists ?x0 - object)
    (tos_match_exists ?x0 - object)
    (reject_target_exists ?x0 - object)
    (ulog_nfqueue_target_exists ?x0 - object)
    (libiptc_exists ?x0 - object)
    (ttl_dscp_ecn_match_exists ?x0 - object)
    (firewall_rule_flushed ?x0 - object)
    (firewall_rule_counters_zeroed ?x0 - object)
    (firewall_rule_policy_set ?x0 - object ?x1 - object)
    (chain_jumped ?x0 - object)
    (extended_match_applied ?x0 - object)
    (table_set ?x0 - object)
    (verbose_mode_enabled)
    (wait_time_set ?x0 - object)
    (line_numbers_enabled)
    (numbers_expanded)
    (fragment_matching_enabled)
    (modprobe_command_set ?x0 - object)
    (command_executed ?x0 - object)
    (session_record_exists)
    (user_primary_group ?x0 - object ?x1 - object)
    (login_shell_running ?x0 - object)
    (session_cache_removed ?x0 - object)
    (session_timestamp_reset ?x0 - object)
    (prompt_override ?x0 - object)
    (stdin_input_read)
    (shell_exists ?x0 - object)
    (shell_running ?x0 - object)
    (file_edited ?x0 - object)
    (user_is_root ?x0 - object)
    (temp_file_exists ?x0 - object)
    (temp_file_owner ?x0 - object ?x1 - object)
    (temp_file_edited ?x0 - object)
    (file_device_special ?x0 - object)
    (command_executed_as_user ?x0 - object)
    (sudo_timestamp_refreshed)
    (file_edited_as_user ?x0 - object ?x1 - object)
    (user_home_directory_set ?x0 - object)
    (login_shell_set ?x0 - object)
    (environment_preserved ?x0 - object)
    (pty_created ?x0 - object)
    (environment_reset ?x0 - object)
    (process_terminated ?x0 - object)
    (delay ?x0 - object)
    (auth_failure_delay_set ?x0 - object)
    (lastlog_updated ?x0 - object)
    (user_supplementary_groups ?x0 - object ?x1 - object)
    (user_in_group ?x0 - object ?x1 - object)
    (user_home_directory ?x0 - object ?x1 - object)
    (file_ownership_adapted ?x0 - object)
    (user_id_non_unique ?x0 - object)
    (user_password_changed ?x0 - object)
    (changes_applied_in_chroot ?x0 - object)
    (changes_applied_with_prefix ?x0 - object)
    (user_shell_changed ?x0 - object ?x1 - object)
    (user_uid_changed ?x0 - object ?x1 - object)
    (subordinate_uids_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_uids_removed ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gids_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gids_removed ?x0 - object ?x1 - object ?x2 - object)
    (selinux_user_set ?x0 - object ?x1 - object)
    (selinux_range_set ?x0 - object ?x1 - object)
    (crontab_owner_changed ?x0 - object)
    (nis_server_updated ?x0 - object)
    (mail_spool_exists ?x0 - object)
    (mail_spool_moved ?x0 - object)
    (group_line_length_limited ?x0 - object)
    (user_has_subordinate_group_ids ?x0 - object)
    (member_of_group ?x0 - object ?x1 - object)
    (duplicate_uid_allowed ?x0 - object)
    (password_set ?x0 - object)
    (prefix_directory_set ?x0 - object ?x1 - object)
    (user_removed_from_groups ?x0 - object ?x1 - object)
    (chroot_directory_set ?x0 - object ?x1 - object)
    (uid_set ?x0 - object ?x1 - object)
    (user_expired ?x0 - object)
    (password_inactive_days_set ?x0 - object ?x1 - object)
    (subids_updated ?x0 - object)
    (primary_group_set ?x0 - object ?x1 - object)
    (password_aging_disabled ?x0 - object)
    (log_init_skipped ?x0 - object)
    (home_directory_exists ?x0 - object)
    (user_group_exists ?x0 - object)
    (uid_exists ?x0 - object)
    (configuration_applied ?x0 - object)
    (user_uid_set ?x0 - object)
    (default_group_set ?x0 - object)
    (default_shell_set ?x0 - object)
    (integer ?x0 - object)
    (greater_than ?x0 - object ?x1 - object)
    (gid_range_set ?x0 - object ?x1 - object)
    (mail_spool_managed ?x0 - object)
    (password_max_age_set ?x0 - object)
    (password_min_age_set ?x0 - object)
    (password_warning_age_set ?x0 - object)
    (subordinate_uids_allocated ?x0 - object)
    (uid_min_set ?x0 - object)
    (uid_max_set ?x0 - object)
    (umask_set ?x0 - object)
    (usergroups_enab_set ?x0 - object)
    (hook_executed ?x0 - object)
    (skel_files_copied ?x0 - object)
    (subgid_configured ?x0 - object ?x1 - object)
    (subuid_configured ?x0 - object ?x1 - object)
    (group_file_updated ?x0 - object)
    (selinux_user_mapping_updated ?x0 - object)
    (no_user_group_created ?x0 - object)
    (gid_used ?x0 - object)
    (group_password_set ?x0 - object)
    (group_operation_in_chroot ?x0 - object ?x1 - object)
    (group_split ?x0 - object)
    (nis_group_exists ?x0 - object)
    (ldap_group_exists ?x0 - object)
    (changes_applied_in_prefix ?x0 - object)
    (selinux_user_mapping_removed ?x0 - object)
    (group_members_count ?x0 - object ?x1 - object)
    (chrooted ?x0 - object)
    (extra_users_enabled)
    (selinux_user_removed ?x0 - object)
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
    :parameters (?actor - user ?option - file)
    :precondition (and
      (file_exists ?option)
      (can_escalate ?actor)
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

  (:action satisfy_dependencies
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_configured ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action upgrade_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_list_updated)
      (network_available)
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
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (system_upgraded)
    )
  )

  (:action autoremove_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (packages_installed)
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
      (cache_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (obsolete_cache_cleared)
    )
  )

  (:action upgrade_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_outdated ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (not (package_outdated ?pkg))
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

  (:action install_dependencies
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
    :parameters (?actor - user ?pkg - package ?distro - file)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action downgrade_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_outdated ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?pkg)
    )
  )

  (:action fetch_source_package
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

  (:action build_dependencies
    :parameters (?actor - user ?src - package)
    :precondition (and
      (package_exists ?src)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (build_dependencies_installed ?src)
    )
  )

  (:action download_source
    :parameters (?src - package)
    :precondition (and
      (package_exists ?src)
      (network_available)
    )
    :effect (and
      (source_downloaded ?src)
    )
  )

  (:action unsatisfy_dependencies
    :parameters (?actor - user ?dep - package)
    :precondition (and
      (package_installed ?dep)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?dep))
    )
  )

  (:action download_package
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (file_exists ?pkg)
    )
  )

  (:action disable_recommended_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (apt_install_recommends_disabled)
    )
  )

  (:action enable_suggested_packages
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

  (:action ignore_missing
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_missing ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_ignore_missing)
    )
  )

  (:action hold_back_packages
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_outdated ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?pkg)
    )
  )

  (:action disable_package_download
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?pkg)
    )
  )

  (:action simulate_apt_action
    :parameters (?pkg - package)
    :precondition (and
      (package_installed ?pkg)
    )
    :effect (and
      (not (package_reverted ?pkg))
    )
  )

  (:action compile_source_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action activate_build_profiles
    :parameters (?actor - user ?profiles - directory)
    :precondition (and
      (file_exists ?profiles)
      (can_escalate ?actor)
    )
    :effect (and
      (build_profiles_activated ?profiles)
    )
  )

  (:action ignore_package_holds
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_holds_ignored ?pkg)
    )
  )

  (:action allow_new_packages_upgrade
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action no_upgrade
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?pkg))
    )
  )

  (:action only_upgrade
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action force_yes
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (allow_unauthenticated)
      (allow_downgrades)
      (allow_remove_essential)
      (allow_change_held_packages)
    )
  )

  (:action purge
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action set_default_release
    :parameters (?actor - user ?release - file)
    :precondition (and
      (file_exists ?release)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_default_release_set ?release)
    )
  )

  (:action set_trivial_only
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (apt_trivial_only_enabled)
    )
  )

  (:action mark_auto
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_auto_marked ?pkg)
    )
  )

  (:action abort_on_remove
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (abort_on_remove ?pkg)
    )
  )

  (:action autoremove
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (unused_dependencies_removed ?pkg)
    )
  )

  (:action accept_source_package_names
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_exists ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_accepted_as_source ?pkg)
    )
  )

  (:action download_diff_only
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_exists ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (diff_downloaded ?pkg)
    )
  )

  (:action download_dsc_only
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_exists ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (dsc_downloaded ?pkg)
    )
  )

  (:action download_tar_only
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_exists ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (tar_downloaded ?pkg)
    )
  )

  (:action process_arch_dependencies
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_exists ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (arch_dependencies_processed ?pkg)
    )
  )

  (:action process_indep_dependencies
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_exists ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (indep_dependencies_processed ?pkg)
    )
  )

  (:action ignore_unauthenticated
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_exists ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (authentication_ignored ?pkg)
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

  (:action set_apt_color
    :parameters (?color - file)
    :precondition (and
    )
    :effect (and
      (apt_color_set ?color)
    )
  )

  (:action configure_apt_fragments
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?f)
    )
  )

  (:action configure_apt_preferences
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?f)
    )
  )

  (:action configure_apt_preferences_fragments
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?f)
    )
  )

  (:action configure_apt_cache
    :parameters (?actor - user ?d - directory)
    :precondition (and
      (directory_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?d)
    )
  )

  (:action configure_apt_cache_partial
    :parameters (?actor - user ?d - directory)
    :precondition (and
      (directory_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?d)
    )
  )

  (:action configure_apt_lists
    :parameters (?actor - user ?d - directory)
    :precondition (and
      (directory_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?d)
    )
  )

  (:action store_state_information
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (state_stored ?dir)
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
    :parameters (?actor - user ?app - service ?alias - service)
    :precondition (and
      (service_exists ?app)
      (can_escalate ?actor)
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

  (:action create_cohort
    :parameters (?actor - user ?snaps - package)
    :precondition (and
      (package_installed ?snaps)
      (can_escalate ?actor)
    )
    :effect (and
      (cohort_created ?snaps)
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

  (:action disconnect_snap_forget
    :parameters (?connection - file)
    :precondition (and
      (file_exists ?connection)
    )
    :effect (and
      (snap_connection_forgotten ?connection)
    )
  )

  (:action download_snap
    :parameters (?snap_name - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (snap_downloaded ?snap_name)
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

  (:action set_journal_quota
    :parameters (?actor - user ?group - group ?size - file)
    :precondition (and
      (quota_group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_quota_set ?group ?size)
    )
  )

  (:action remove_quota_group
    :parameters (?actor - user ?group - group)
    :precondition (and
      (quota_group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (quota_group_removed ?group)
    )
  )

  (:action increase_memory_limit
    :parameters (?actor - user ?quota_group - group)
    :precondition (and
      (quota_group_exists ?quota_group)
      (can_escalate ?actor)
    )
    :effect (and
      (memory_limit_increased ?quota_group)
    )
  )

  (:action set_cpu_limit
    :parameters (?actor - user ?quota_group - group ?percentage - file)
    :precondition (and
      (quota_group_exists ?quota_group)
      (can_escalate ?actor)
    )
    :effect (and
      (cpu_limit_set ?quota_group ?percentage)
    )
  )

  (:action modify_cpu_set
    :parameters (?actor - user ?quota_group - group ?cpu_set - file)
    :precondition (and
      (quota_group_exists ?quota_group)
      (can_escalate ?actor)
    )
    :effect (and
      (cpu_set_modified ?quota_group ?cpu_set)
    )
  )

  (:action increase_threads_limit
    :parameters (?actor - user ?quota_group - group ?new_limit - file)
    :precondition (and
      (quota_group_exists ?quota_group)
      (threads_limit_less_than ?quota_group ?new_limit)
      (can_escalate ?actor)
    )
    :effect (and
      (threads_limit_increased ?quota_group ?new_limit)
    )
  )

  (:action decrease_threads_limit
    :parameters (?actor - user ?quota_group - group ?new_limit - file)
    :precondition (and
      (quota_group_exists ?quota_group)
      (threads_limit_greater_than ?quota_group ?new_limit)
      (can_escalate ?actor)
    )
    :effect (and
      (threads_limit_decreased ?quota_group ?new_limit)
    )
  )

  (:action start_services
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
    :parameters (?actor - user ?snap - package ?channel - file)
    :precondition (and
      (package_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?snap)
    )
  )

  (:action try_snap
    :parameters (?actor - user ?snap_dir - directory)
    :precondition (and
      (file_exists ?snap_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_tried ?snap_dir)
    )
  )

  (:action snap_try
    :parameters (?actor - user ?snap - package)
    :precondition (and
      (package_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?snap)
    )
  )

  (:action snap_unalias
    :parameters (?actor - user ?alias - file)
    :precondition (and
      (file_exists ?alias)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?alias)
    )
  )

  (:action snap_unset
    :parameters (?actor - user ?option - file)
    :precondition (and
      (file_exists ?option)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?option)
    )
  )

  (:action unset_snap_config
    :parameters (?actor - user ?snap - service ?key - file)
    :precondition (and
      (service_exists ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (config_removed ?snap ?key)
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
    :parameters (?actor - user ?warning_id - firewall_rule)
    :precondition (and
      (warning_exists ?warning_id)
      (can_escalate ?actor)
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

  (:action remove_config_options
    :parameters (?actor - user ?key - file)
    :precondition (and
      (file_exists ?key)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_writable ?key))
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

  (:action sign_assertion
    :parameters (?assertion_file - file)
    :precondition (and
      (file_exists ?assertion_file)
    )
    :effect (and
      (assertion_signed ?assertion_file)
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

  (:action service_fails
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_failed ?svc)
    )
  )

  (:action deactivate_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
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
      (not (service_running ?svc))
      (can_escalate ?actor)
    )
    :effect (and
      (service_exists ?svc)
    )
  )

  (:action reload_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
    )
  )

  (:action refresh_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
    )
  )

  (:action view_unit_logs
    :parameters (?unit - service)
    :precondition (and
      (service_exists ?unit)
    )
    :effect (and
      (none)
    )
  )

  (:action start_bluetooth_service
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

  (:action load_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (not (service_loaded ?unit))
      (can_escalate ?actor)
    )
    :effect (and
      (service_loaded ?unit)
    )
  )

  (:action mask_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (not (service_masked ?unit))
      (can_escalate ?actor)
    )
    :effect (and
      (service_masked ?unit)
    )
  )

  (:action set_pager_secure
    :parameters (?secure - file)
    :precondition (and
    )
    :effect (and
      (pager_secure ?secure)
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
      (can_escalate ?actor)
    )
    :effect (and
      (service_failed ?unit)
    )
  )

  (:action clean_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?unit)
    )
  )

  (:action freeze_unit
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

  (:action thaw_unit
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

  (:action set_property_unit
    :parameters (?actor - user ?unit - service ?property - file ?value - file)
    :precondition (and
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?unit)
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

  (:action strip_trailing_slashes
    :parameters (?src - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_without_trailing_slash ?src)
    )
  )

  (:action override_backup_suffix
    :parameters (?suffix - file)
    :precondition (and
      (file_exists ?suffix)
    )
    :effect (and
      (backup_suffix_override ?suffix)
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

  (:action treat_as_normal_file
    :parameters (?dest - file)
    :precondition (and
      (file_exists ?dest)
    )
    :effect (and
      (file_as_normal ?dest)
    )
  )

  (:action control_file_updates
    :parameters (?update - file)
    :precondition (and
      (file_exists ?update)
    )
    :effect (and
      (file_update_control ?update)
    )
  )

  (:action set_selinux_context
    :parameters (?dest - file)
    :precondition (and
      (file_exists ?dest)
    )
    :effect (and
      (selinux_context_set ?dest)
    )
  )

  (:action disable_backups
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (backup_disabled)
    )
  )

  (:action enable_numbered_backups
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (backup_method_numbered)
    )
  )

  (:action enable_existing_backups
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (backup_method_existing)
    )
  )

  (:action enable_simple_backups
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (backup_method_simple)
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

  (:action no_clobber
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?dst)
    )
    :effect (and
      (not (file_exists ?dst))
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

  (:action replace_older_files
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (file_exists ?dst)
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

  (:action copy_files_to_directory
    :parameters (?sources - file ?directory - directory)
    :precondition (and
      (directory_exists ?directory)
      (file_exists ?sources)
    )
    :effect (and
      (file_exists ?sources)
    )
  )

  (:action copy_file_to_directory
    :parameters (?source - file ?directory - directory)
    :precondition (and
      (directory_exists ?directory)
      (file_exists ?source)
    )
    :effect (and
      (file_exists ?source)
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
      (file_symlink_followed ?src ?dst)
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

  (:action set_selinux_context_default
    :parameters (?actor - user ?dst - file)
    :precondition (and
      (file_exists ?dst)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_context_default ?dst)
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

  (:action inhibit_sparse_file
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

  (:action replace_no_files
    :parameters (?dest - directory ?source - directory)
    :precondition (and
      (directory_exists ?dest)
      (directory_exists ?source)
    )
    :effect (and
      (no_files_replaced ?dest)
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
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action prompt_before_removal
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (interactive_prompted ?f)
    )
  )

  (:action prompt_once_before_removal
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (count_files ?f ?obj_3)
    )
    :effect (and
      (interactive_prompted_once ?f)
    )
  )

  (:action remove_directory_recursively
    :parameters (?d - directory)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (directory_removed ?d)
    )
  )

  (:action remove_empty_directory
    :parameters (?d - directory)
    :precondition (and
      (directory_exists ?d)
      (directory_empty ?d)
    )
    :effect (and
      (directory_removed ?d)
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
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_mode_changed ?f ?mode)
    )
  )

  (:action change_permissions_symlink
    :parameters (?link - file)
    :precondition (and
      (file_exists ?link)
    )
    :effect (and
      (file_executable ?link)
    )
  )

  (:action set_symbolic_permissions
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action clear_directory_permissions
    :parameters (?d - directory ?mode - file)
    :precondition (and
      (file_exists ?d)
    )
    :effect (and
      (file_executable ?d)
    )
  )

  (:action set_restricted_deletion_flag
    :parameters (?actor - user ?d - directory)
    :precondition (and
      (file_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (restricted_deletion_flag_set ?d)
    )
  )

  (:action suppress_errors
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (errors_suppressed ?f)
    )
  )

  (:action dereference_link
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (link_dereferenced ?f)
    )
  )

  (:action no_dereference_link
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (link_not_dereferenced ?f)
    )
  )

  (:action reference_mode
    :parameters (?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
    )
    :effect (and
      (mode_referenced ?f ?rfile)
    )
  )

  (:action recursive_change
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (changes_recursive ?f)
    )
  )

  (:action traverse_symbolic_links
    :parameters (?path - file)
    :precondition (and
      (file_exists ?path)
    )
    :effect (and
      (file_accessible ?path)
    )
  )

  (:action traverse_all_symbolic_links
    :parameters (?path - file)
    :precondition (and
      (file_exists ?path)
    )
    :effect (and
      (file_accessible ?path)
    )
  )

  (:action do_not_traverse_symbolic_links
    :parameters (?path - file)
    :precondition (and
      (file_exists ?path)
    )
    :effect (and
      (file_accessible ?path)
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

  (:action change_ownership_conditional
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
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by_reference ?f ?rfile)
    )
  )

  (:action recursive_ownership
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (ownership_applied_recursively ?f)
    )
  )

  (:action traverse_all_links
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (all_links_traversed ?f)
    )
  )

  (:action no_traverse_links
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (no_links_traversed ?f)
    )
  )

  (:action change_owner_recursive
    :parameters (?actor - user ?owner - user ?path - directory)
    :precondition (and
      (file_exists ?path)
      (can_escalate ?actor)
    )
    :effect (and
      (owner_changed_recursive ?path ?owner)
    )
  )

  (:action change_owner_and_group
    :parameters (?actor - user ?owner - user ?group - group ?path - directory)
    :precondition (and
      (file_exists ?path)
      (can_escalate ?actor)
    )
    :effect (and
      (owner_changed ?path ?owner)
      (group_changed ?path ?group)
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

  (:action change_ownership_if_match
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (ownership_changed ?f)
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
      (valid_time_type ?time_type)
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

  (:action set_protocol_family
    :parameters (?actor - user ?family - file)
    :precondition (and
      (can_escalate ?actor)
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
      (network_namespace_exists ?netns)
      (can_escalate ?actor)
    )
    :effect (and
      (current_network_namespace ?netns)
    )
  )

  (:action execute_command_on_all_objects
    :parameters (?obj - file)
    :precondition (and
      (command_supports_all_objects ?true)
    )
    :effect (and
      (command_executed_on_all_objects ?true)
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
      (segment_routing_exists ?sr)
      (can_escalate ?actor)
    )
    :effect (and
      (segment_routing_configured ?sr)
    )
  )

  (:action manage_tcp_metrics
    :parameters (?actor - user ?tcp_metrics - file)
    :precondition (and
      (tcp_metrics_exists ?tcp_metrics)
      (can_escalate ?actor)
    )
    :effect (and
      (tcp_metrics_configured ?tcp_metrics)
    )
  )

  (:action manage_tokenized_interface_identifiers
    :parameters (?actor - user ?token - file)
    :precondition (and
      (token_exists ?token)
      (can_escalate ?actor)
    )
    :effect (and
      (token_configured ?token)
    )
  )

  (:action tunnel_over_ip
    :parameters (?actor - user ?tunnel - file)
    :precondition (and
      (tunnel_exists ?tunnel)
      (can_escalate ?actor)
    )
    :effect (and
      (tunnel_configured ?tunnel)
    )
  )

  (:action manage_tun_tap_devices
    :parameters (?actor - user ?tuntap - file)
    :precondition (and
      (tuntap_exists ?tuntap)
      (can_escalate ?actor)
    )
    :effect (and
      (tuntap_configured ?tuntap)
    )
  )

  (:action manage_vrf_devices
    :parameters (?actor - user ?vrf - file)
    :precondition (and
      (vrf_exists ?vrf)
      (can_escalate ?actor)
    )
    :effect (and
      (vrf_configured ?vrf)
    )
  )

  (:action manage_ipsec_policies
    :parameters (?actor - user ?xfrm - file)
    :precondition (and
      (xfrm_exists ?xfrm)
      (can_escalate ?actor)
    )
    :effect (and
      (xfrm_configured ?xfrm)
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
    :parameters (?version - file)
    :precondition (and
      (not (ip_command_exists ?version))
    )
    :effect (and
      (ip_command_exists ?version)
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
    :parameters (?actor - user ?chain - firewall_rule ?rule - firewall_rule)
    :precondition (and
      (firewall_table_defined ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_added ?rule ?chain)
    )
  )

  (:action set_packet_table
    :parameters (?actor - user ?table - file)
    :precondition (and
      (table_exists ?table)
      (can_escalate ?actor)
    )
    :effect (and
      (table_selected ?table)
    )
  )

  (:action configure_connection_tracking_exemption
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (connection_tracking_exempt ?rule)
    )
  )

  (:action alter_outgoing_packets
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_altered ?rule)
    )
  )

  (:action configure_mandatory_access_control
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (mandatory_access_control_enabled ?rule)
    )
  )

  (:action append_iptables_rule
    :parameters (?actor - user ?chain - file ?rule - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_added ?chain ?rule)
    )
  )

  (:action flush_chain
    :parameters (?actor - user ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (chain_flushed ?chain)
    )
  )

  (:action zero_counters
    :parameters (?actor - user ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (counters_zeroed ?chain)
    )
  )

  (:action create_chain
    :parameters (?actor - user ?chain - file)
    :precondition (and
      (not (chain_exists ?chain))
      (can_escalate ?actor)
    )
    :effect (and
      (chain_exists ?chain)
    )
  )

  (:action delete_chain
    :parameters (?actor - user ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (not (chain_referenced ?chain))
      (can_escalate ?actor)
    )
    :effect (and
      (not (chain_exists ?chain))
    )
  )

  (:action delete_empty_chains
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (empty_chains_deleted)
    )
  )

  (:action set_chain_policy
    :parameters (?actor - user ?chain - file ?target - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (chain_policy_set ?chain ?target)
    )
  )

  (:action rename_chain
    :parameters (?actor - user ?old_chain - file ?new_chain - file)
    :precondition (and
      (chain_exists ?old_chain)
      (can_escalate ?actor)
    )
    :effect (and
      (chain_renamed ?old_chain ?new_chain)
    )
  )

  (:action merge_ipv4_ipv6_rules
    :parameters (?actor - user ?rule_file - file)
    :precondition (and
      (file_exists ?rule_file)
      (can_escalate ?actor)
    )
    :effect (and
      (ipv4_ipv6_rules_merged ?rule_file)
    )
  )

  (:action match_hbh_header
    :parameters (?actor - user ?hdr - file)
    :precondition (and
      (header_exists ?hdr)
      (can_escalate ?actor)
    )
    :effect (and
      (header_matched ?hdr)
    )
  )

  (:action add_iptables_match
    :parameters (?actor - user ?match - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?match)
    )
  )

  (:action set_iptables_destination
    :parameters (?actor - user ?dst - firewall_rule ?mask - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?dst)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_destination_set ?dst ?mask)
    )
  )

  (:action set_rule_target
    :parameters (?actor - user ?target - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?target)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_target_set ?target)
    )
  )

  (:action goto_chain
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_goto_set ?chain)
    )
  )

  (:action set_input_interface
    :parameters (?actor - user ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_input_interface_set ?iface)
    )
  )

  (:action set_output_interface
    :parameters (?actor - user ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_sent_via ?iface)
    )
  )

  (:action set_fragment_rule
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (fragment_rule_applied)
    )
  )

  (:action set_counters
    :parameters (?actor - user ?rule - firewall_rule ?packets - file ?bytes - file)
    :precondition (and
      (firewall_rule_exists ?rule)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_counter_set ?rule ?packets ?bytes)
    )
  )

  (:action wait_for_lock
    :parameters (?actor - user ?seconds - file)
    :precondition (and
      (lock_available)
      (can_escalate ?actor)
    )
    :effect (and
      (lock_acquired)
    )
  )

  (:action numeric_output
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (numeric_output_enabled)
    )
  )

  (:action use_iptables_extensions
    :parameters (?actor - user ?extension - file)
    :precondition (and
      (file_exists ?extension)
      (can_escalate ?actor)
    )
    :effect (and
      (iptables_extension_loaded ?extension)
    )
  )

  (:action use_iptables_unsafely
    :parameters (?actor - user ?env - file)
    :precondition (and
      (file_exists ?env)
      (can_escalate ?actor)
    )
    :effect (and
      (vulnerable ?env)
    )
  )

  (:action configure_packet_filtering
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (not (traffic_blocked ?rule))
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action configure_nat
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (not (port_allowed ?rule))
      (can_escalate ?actor)
    )
    :effect (and
      (port_allowed ?rule)
    )
  )

  (:action apply_masq_rule
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (not (traffic_blocked ?rule))
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action lobby_for_packet_framework
    :parameters (?framework - file)
    :precondition (and
      (file_exists ?framework)
    )
    :effect (and
      (packet_framework_enabled ?framework)
    )
  )

  (:action write_mangle_table
    :parameters (?actor - user ?table - file)
    :precondition (and
      (not (file_exists ?table))
      (can_escalate ?actor)
    )
    :effect (and
      (mangle_table_exists ?table)
    )
  )

  (:action write_owner_match
    :parameters (?actor - user ?match - file)
    :precondition (and
      (not (file_exists ?match))
      (can_escalate ?actor)
    )
    :effect (and
      (owner_match_exists ?match)
    )
  )

  (:action write_mark
    :parameters (?actor - user ?mark - file)
    :precondition (and
      (not (file_exists ?mark))
      (can_escalate ?actor)
    )
    :effect (and
      (mark_exists ?mark)
    )
  )

  (:action write_tos_target
    :parameters (?actor - user ?target - file)
    :precondition (and
      (not (file_exists ?target))
      (can_escalate ?actor)
    )
    :effect (and
      (tos_target_exists ?target)
    )
  )

  (:action write_tos_match
    :parameters (?actor - user ?match - file)
    :precondition (and
      (not (file_exists ?match))
      (can_escalate ?actor)
    )
    :effect (and
      (tos_match_exists ?match)
    )
  )

  (:action write_reject_target
    :parameters (?actor - user ?target - file)
    :precondition (and
      (not (file_exists ?target))
      (can_escalate ?actor)
    )
    :effect (and
      (reject_target_exists ?target)
    )
  )

  (:action write_ulog_nfqueue_target
    :parameters (?actor - user ?target - file)
    :precondition (and
      (not (file_exists ?target))
      (can_escalate ?actor)
    )
    :effect (and
      (ulog_nfqueue_target_exists ?target)
    )
  )

  (:action write_libiptc
    :parameters (?actor - user ?lib - file)
    :precondition (and
      (not (file_exists ?lib))
      (can_escalate ?actor)
    )
    :effect (and
      (libiptc_exists ?lib)
    )
  )

  (:action write_ttl_dscp_ecn
    :parameters (?actor - user ?match - file)
    :precondition (and
      (not (file_exists ?match))
      (can_escalate ?actor)
    )
    :effect (and
      (ttl_dscp_ecn_match_exists ?match)
    )
  )

  (:action delete_iptables_rule
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (traffic_blocked ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (not (traffic_blocked ?chain))
    )
  )

  (:action delete_iptables_rule_by_num
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file)
    :precondition (and
      (traffic_blocked ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (not (traffic_blocked ?chain))
    )
  )

  (:action insert_iptables_rule
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?chain)
    )
  )

  (:action replace_iptables_rule
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file)
    :precondition (and
      (traffic_blocked ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?chain)
    )
  )

  (:action flush_iptables_chain
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_flushed ?chain)
    )
  )

  (:action zero_iptables_counters
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_counters_zeroed ?chain)
    )
  )

  (:action create_iptables_chain
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (not (firewall_rule_exists ?chain))
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?chain)
    )
  )

  (:action delete_iptables_chain
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (not (firewall_rule_exists ?chain))
    )
  )

  (:action set_iptables_policy
    :parameters (?actor - user ?chain - firewall_rule ?target - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_policy_set ?chain ?target)
    )
  )

  (:action rename_iptables_chain
    :parameters (?actor - user ?old_chain - firewall_rule ?new_chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?old_chain)
      (not (firewall_rule_exists ?new_chain))
      (can_escalate ?actor)
    )
    :effect (and
      (not (firewall_rule_exists ?old_chain))
      (firewall_rule_exists ?new_chain)
    )
  )

  (:action jump_to_chain
    :parameters (?actor - user ?chain - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (chain_jumped ?chain)
    )
  )

  (:action extended_match
    :parameters (?actor - user ?match - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (extended_match_applied ?match)
    )
  )

  (:action set_table
    :parameters (?actor - user ?table - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (table_set ?table)
    )
  )

  (:action set_verbose
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (verbose_mode_enabled)
    )
  )

  (:action set_wait_time
    :parameters (?actor - user ?seconds - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (wait_time_set ?seconds)
    )
  )

  (:action enable_line_numbers
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (line_numbers_enabled)
    )
  )

  (:action expand_numbers
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (numbers_expanded)
    )
  )

  (:action match_fragments
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (fragment_matching_enabled)
    )
  )

  (:action modprobe_command
    :parameters (?actor - user ?command - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (modprobe_command_set ?command)
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

  (:action run_command_without_reauth
    :parameters (?cmd - file)
    :precondition (and
      (session_record_exists)
    )
    :effect (and
      (command_executed ?cmd)
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

  (:action run_login_shell
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (login_shell_running ?user)
    )
  )

  (:action remove_session_cache
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (session_cache_removed ?user)
    )
  )

  (:action reset_session_timestamp
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (session_timestamp_reset ?user)
    )
  )

  (:action override_prompt
    :parameters (?actor - user ?prompt - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (prompt_override ?prompt)
    )
  )

  (:action read_from_stdin
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (stdin_input_read)
    )
  )

  (:action run_shell
    :parameters (?actor - user ?shell - file)
    :precondition (and
      (shell_exists ?shell)
      (can_escalate ?actor)
    )
    :effect (and
      (shell_running ?shell)
    )
  )

  (:action edit_files
    :parameters (?actor - user ?file - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (file_edited ?file)
    )
  )

  (:action create_temp_file_copies
    :parameters (?f - file ?u - user)
    :precondition (and
      (file_exists ?f)
      (user_exists ?u)
      (not (user_is_root ?u))
    )
    :effect (and
      (temp_file_exists ?f)
      (temp_file_owner ?f ?u)
    )
  )

  (:action edit_temp_files
    :parameters (?f - file ?u - user)
    :precondition (and
      (temp_file_exists ?f)
      (temp_file_owner ?f ?u)
    )
    :effect (and
      (temp_file_edited ?f)
    )
  )

  (:action apply_temp_file_changes
    :parameters (?f - file)
    :precondition (and
      (temp_file_edited ?f)
    )
    :effect (and
      (file_modified ?f)
      (not (temp_file_exists ?f))
    )
  )

  (:action edit_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (not (file_device_special ?f))
    )
    :effect (and
      (file_edited ?f)
    )
  )

  (:action run_as_user
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (command_executed_as_user ?user)
    )
  )

  (:action refresh_sudo_timestamp
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (sudo_timestamp_refreshed)
    )
  )

  (:action edit_file_as_user
    :parameters (?user - user ?file - file)
    :precondition (and
      (user_exists ?user)
      (file_exists ?file)
    )
    :effect (and
      (file_edited_as_user ?user ?file)
    )
  )

  (:action reset_resource_limits
    :parameters (?actor - user ?pr - process)
    :precondition (and
      (process_running ?pr)
      (can_escalate ?actor)
    )
    :effect (and
      (requires_env_preservation ?pr)
    )
  )

  (:action start_login_shell
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (login_shell_running ?user)
    )
  )

  (:action initialize_environment
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (requires_env_preservation ?user)
    )
  )

  (:action change_home_directory
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_home_directory_set ?user)
    )
  )

  (:action set_login_shell
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (login_shell_set ?user)
    )
  )

  (:action preserve_environment
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (environment_preserved ?user)
    )
  )

  (:action create_pty
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (pty_created ?user)
    )
  )

  (:action reset_environment
    :parameters (?actor - user ?var - file)
    :precondition (and
      (file_exists ?var)
      (can_escalate ?actor)
    )
    :effect (and
      (environment_reset ?var)
    )
  )

  (:action terminate_child
    :parameters (?actor - user ?signal - file)
    :precondition (and
      (process_running ?signal)
      (can_escalate ?actor)
    )
    :effect (and
      (process_terminated ?signal)
    )
  )

  (:action delay_on_auth_failure
    :parameters (?delay - file)
    :precondition (and
      (delay ?obj_0)
    )
    :effect (and
      (auth_failure_delay_set ?delay)
    )
  )

  (:action update_lastlog
    :parameters (?actor - user ?config - file)
    :precondition (and
      (file_exists ?config)
      (can_escalate ?actor)
    )
    :effect (and
      (lastlog_updated ?config)
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
      (changes_applied_with_prefix ?prefix_dir)
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

  (:action unlock_user_password
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (user_locked ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_locked ?user))
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
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gids_removed ?user ?first ?last)
    )
  )

  (:action set_selinux_user
    :parameters (?actor - user ?user - user ?seuser - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_user_set ?user ?seuser)
    )
  )

  (:action set_selinux_range
    :parameters (?actor - user ?user - user ?serange - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_range_set ?user ?serange)
    )
  )

  (:action change_crontab_owner
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (crontab_owner_changed ?user)
    )
  )

  (:action modify_nis_server
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (nis_server_updated ?user)
    )
  )

  (:action create_mail_spool
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (mail_spool_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_exists ?user)
    )
  )

  (:action move_mail_spool
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (mail_spool_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_moved ?user)
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

  (:action limit_group_line_length
    :parameters (?actor - user ?limit - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_line_length_limited ?limit)
    )
  )

  (:action allocate_subordinate_group_ids
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (user_has_subordinate_group_ids ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_subordinate_group_ids ?user)
    )
  )

  (:action append_user_to_groups
    :parameters (?actor - user ?user - user ?groups - group)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of_group ?user ?groups)
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

  (:action allow_duplicate_uid
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (duplicate_uid_allowed ?user)
    )
  )

  (:action set_encrypted_password
    :parameters (?actor - user ?user - user ?password - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_set ?user)
    )
  )

  (:action set_prefix_directory
    :parameters (?actor - user ?user - user ?prefix_dir - directory)
    :precondition (and
      (user_exists ?user)
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (prefix_directory_set ?user ?prefix_dir)
    )
  )

  (:action remove_from_supplemental_groups
    :parameters (?actor - user ?user - user ?groups - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (user_removed_from_groups ?user ?groups)
    )
  )

  (:action set_chroot_directory
    :parameters (?actor - user ?user - user ?chroot_dir - directory)
    :precondition (and
      (user_exists ?user)
      (directory_exists ?chroot_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (chroot_directory_set ?user ?chroot_dir)
    )
  )

  (:action set_uid
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (uid_set ?user ?uid)
    )
  )

  (:action add_subgids
    :parameters (?actor - user ?first - group ?last - group)
    :precondition (and
      (group_exists ?first)
      (group_exists ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of ?first ?last)
    )
  )

  (:action remove_subgids
    :parameters (?actor - user ?first - group ?last - group)
    :precondition (and
      (group_exists ?first)
      (group_exists ?last)
      (member_of ?first ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (not (member_of ?first ?last))
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

  (:action create_user_with_home
    :parameters (?actor - user ?user - user ?home_dir - directory)
    :precondition (and
      (not (user_exists ?user))
      (not (directory_exists ?home_dir))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (directory_exists ?home_dir)
    )
  )

  (:action create_user_with_comment
    :parameters (?actor - user ?user - user ?comment - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action create_user_with_expiration
    :parameters (?actor - user ?user - user ?expire_date - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (user_expired ?user)
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

  (:action set_primary_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (primary_group_set ?user ?group)
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

  (:action disable_password_aging
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_aging_disabled ?user)
    )
  )

  (:action skip_log_init
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (log_init_skipped ?user)
    )
  )

  (:action create_home_directory
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (home_directory_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_exists ?user)
    )
  )

  (:action skip_user_group_creation
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_group_exists ?group))
    )
  )

  (:action create_non_unique_user
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (uid_exists ?uid)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action create_system_user
    :parameters (?actor - user ?user - user)
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
    )
  )

  (:action apply_configuration_changes
    :parameters (?actor - user ?prefix_dir - directory)
    :precondition (and
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (configuration_applied ?prefix_dir)
    )
  )

  (:action set_user_uid
    :parameters (?actor - user ?uid - user)
    :precondition (and
      (user_exists ?uid)
      (can_escalate ?actor)
    )
    :effect (and
      (user_uid_set ?uid)
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

  (:action set_gid_range
    :parameters (?actor - user ?min_gid - file ?max_gid - file)
    :precondition (and
      (integer ?min_gid)
      (integer ?max_gid)
      (greater_than ?max_gid ?min_gid)
      (can_escalate ?actor)
    )
    :effect (and
      (gid_range_set ?min_gid ?max_gid)
    )
  )

  (:action manage_mail_spool
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_managed ?user)
    )
  )

  (:action set_max_password_age
    :parameters (?actor - user ?days - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (password_max_age_set ?days)
    )
  )

  (:action set_min_password_age
    :parameters (?actor - user ?days - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (password_min_age_set ?days)
    )
  )

  (:action set_password_warning_age
    :parameters (?actor - user ?days - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (password_warning_age_set ?days)
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

  (:action create_system_group
    :parameters (?actor - user ?group - group)
    :precondition (and
      (not (group_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
    )
  )

  (:action set_uid_min
    :parameters (?actor - user ?min - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (uid_min_set ?min)
    )
  )

  (:action set_uid_max
    :parameters (?actor - user ?max - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (uid_max_set ?max)
    )
  )

  (:action set_umask
    :parameters (?actor - user ?mask - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (umask_set ?mask)
    )
  )

  (:action set_usergroups_enab
    :parameters (?actor - user ?enabled - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (usergroups_enab_set ?enabled)
    )
  )

  (:action run_useradd_hook
    :parameters (?actor - user ?script - file ?action_type - file ?subject - user)
    :precondition (and
      (file_exists ?script)
      (user_exists ?subject)
      (can_escalate ?actor)
    )
    :effect (and
      (hook_executed ?script)
    )
  )

  (:action copy_skel_files
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (skel_files_copied ?user)
    )
  )

  (:action configure_subgid
    :parameters (?actor - user ?user - user ?gid - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?gid)
      (can_escalate ?actor)
    )
    :effect (and
      (subgid_configured ?user ?gid)
    )
  )

  (:action configure_subuid
    :parameters (?actor - user ?user - user ?uid - user)
    :precondition (and
      (user_exists ?user)
      (user_exists ?uid)
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_configured ?user ?uid)
    )
  )

  (:action update_group_file
    :parameters (?actor - user ?group - group)
    :precondition (and
      (user_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (group_file_updated ?group)
    )
  )

  (:action update_selinux_user_mapping
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_user_mapping_updated ?user)
    )
  )

  (:action no_user_group
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (no_user_group_created ?user)
    )
  )

  (:action non_unique_user
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
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

  (:action add_users_to_group
    :parameters (?actor - user ?group - group ?users - user)
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
      (not (group_split ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (group_split ?group)
    )
  )

  (:action secure_group_account
    :parameters (?actor - user ?group - group)
    :precondition (and
      (not (group_exists ?group))
      (not (nis_group_exists ?group))
      (not (ldap_group_exists ?group))
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
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
    )
  )

  (:action remove_user_home
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
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

  (:action limit_group_members
    :parameters (?actor - user ?group - group)
    :precondition (and
      (group_exists ?group)
      (group_members_count ?group) ?max_members_per_group)
      (can_escalate ?actor)
    )
    :effect (and
      (group_split ?group)
    )
  )

  (:action run_userdel_cmd
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
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

  (:action use_extra_users
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (extra_users_enabled)
    )
  )

  (:action remove_selinux_user
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_user_removed ?user)
    )
  )

)