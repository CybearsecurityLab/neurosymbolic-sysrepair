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
    (package_reverted ?x0 - object)
    (package_enabled ?x0 - object)
    (assertion_exists ?x0 - object)
    (valid_assertion ?x0 - object)
    (verified_signature ?x0 - object)
    (snap_exists ?x0 - object)
    (app_exists_in_snap ?x0 - object ?x1 - object)
    (alias_exists ?x0 - object)
    (connected ?x0 - object ?x1 - object ?x2 - object ?x3 - object)
    (slot_connected ?x0 - object ?x1 - object)
    (cohort_keys_created)
    (cohort_created ?x0 - object)
    (home_directory_migrated)
    (stacktraces_obtained)
    (state_file_exists)
    (state_inspected)
    (timings_available)
    (timings_inspected)
    (snapshot_exported ?x0 - object)
    (snapshot_exists ?x0 - object)
    (quota_group_exists ?x0 - object)
    (snap_in_group ?x0 - object ?x1 - object)
    (subgroup_of ?x0 - object ?x1 - object)
    (memory_limit_set_to ?x0 - object ?x1 - object)
    (cpu_limit_set_to ?x0 - object ?x1 - object)
    (cpu_quota_set ?x0 - object ?x1 - object)
    (modified_cpu_set ?x0 - object ?x1 - object)
    (threads_limit_set ?x0 - object)
    (threads_limit_increased ?x0 - object ?x1 - object)
    (threads_limit_decreased ?x0 - object ?x1 - object)
    (journal_limit_set ?x0 - object)
    (journal_limit_modified ?x0 - object ?x1 - object)
    (journal_namespace_set ?x0 - object)
    (snap_aliases_removed ?x0 - object)
    (snap_installed ?x0 - object)
    (aliases_preferred ?x0 - object)
    (user_authenticated)
    (snapshot_saved)
    (snapshot_imported)
    (device_rebooted)
    (warnings_exist)
    (warnings_acknowledged)
    (debug_info_collected)
    (file_executable ?x0 - object)
    (disk_image_operated ?x0 - object)
    (applied_image_policy ?x0 - object)
    (selected_namespace ?x0 - object)
    (cursor_written_to_file ?x0 - object)
    (boots_lookup_from_beginning ?x0 - object)
    (boots_lookup_from_end ?x0 - object)
    (output_format_set ?x0 - object)
    (catalog_updated)
    (keys_generated)
    (systemd_lesscharset_set ?x0 - object)
    (pagersecure_enabled)
    (filtered_logs ?x0 - object)
    (systemd_color_output ?x0 - object)
    (systemd_urlify_output ?x0 - object)
    (directory_exists ?x0 - object)
    (directory_contents_copied ?x0 - object ?x1 - object)
    (symbolic_link_created ?x0 - object ?x1 - object)
    (sparse_file_created ?x0 - object)
    (cloned_file_created ?x0 - object)
    (file_copied ?x0 - object ?x1 - object)
    (updated_file_copied ?x0 - object ?x1 - object)
    (trailing_slashes_removed ?x0 - object)
    (file_copied_to_directory ?x0 - object ?x1 - object)
    (backup_file_created_with_suffix ?x0 - object)
    (selinux_context_default ?x0 - object)
    (selinux_context_custom ?x0 - object ?x1 - object)
    (same_filesystem ?x0 - object ?x1 - object)
    (file_copied_within_fs ?x0 - object ?x1 - object)
    (attributes_copied ?x0 - object ?x1 - object ?x2 - object)
    (sparse_file_copied ?x0 - object ?x1 - object)
    (preserved_attributes ?x0 - object ?x1 - object)
    (follows_symlink ?x0 - object)
    (full_source_name_copied ?x0 - object)
    (reflinked_copy_created ?x0 - object)
    (selinux_smack_context_set ?x0 - object)
    (sparse_file ?x0 - object)
    (has_zero_sequence ?x0 - object)
    (non_sparse_file ?x0 - object)
    (updated_file ?x0 - object)
    (file_updated ?x0 - object)
    (file_backup_created ?x0 - object)
    (output_version_information)
    (user_in_group ?x0 - object)
    (set_group_id_bit ?x0 - object)
    (set_user_id_bit ?x0 - object)
    (clear_group_id_bit ?x0 - object)
    (sticky_bit_set ?x0 - object)
    (sticky_bit_cleared ?x0 - object)
    (file_has_mode ?x0 - object ?x1 - object)
    (owner_of ?x0 - object ?x1 - object)
    (group_of ?x0 - object ?x1 - object)
    (owned_by ?x0 - object ?x1 - object)
    (group_owned_by ?x0 - object ?x1 - object)
    (current_owner_matches ?x0 - object ?x1 - object)
    (current_group_matches ?x0 - object ?x1 - object)
    (new_owner ?x0 - object ?x1 - object)
    (new_group ?x0 - object ?x1 - object)
    (preserve_root_disabled)
    (preserve_root_enabled)
    (new_owner_from_ref ?x0 - object ?x1 - object)
    (new_group_from_ref ?x0 - object ?x1 - object)
    (recursively_operated_on ?x0 - object)
    (is_symbolic_link ?x0 - object)
    (points_to_directory ?x0 - object)
    (traversed_symlink ?x0 - object)
    (all_symlinks_traversed)
    (no_symlinks_traversed)
    (file_group ?x0 - object ?x1 - object ?x2 - object)
    (directory_mode_set ?x0 - object)
    (selinux_context_set ?x0 - object)
    (custom_selinux_context_set ?x0 - object)
    (file_accessed ?x0 - object)
    (file_modified ?x0 - object)
    (same_timestamps ?x0 - object ?x1 - object)
    (timestamp_set ?x0 - object ?x1 - object)
    (file_time_attribute_set ?x0 - object ?x1 - object)
    (tcp_pacing_rate_set ?x0 - object)
    (tcp_max_pacing_rate_set ?x0 - object)
    (tcp_rcv_space_set ?x0 - object)
    (tcp_ulp_mptcp_configured ?x0 - object)
    (tcp_ulp_rem_token_set ?x0 - object)
    (tcp_ulp_loc_token_set ?x0 - object)
    (tcp_ulp_sn_set ?x0 - object)
    (tcp_ulp_sfseq_set ?x0 - object)
    (tcp_ulp_ssnoff_set ?x0 - object)
    (tcp_ulp_maplen_set ?x0 - object)
    (sockets_diagnosed ?x0 - object)
    (device_matched ?x0 - object ?x1 - object)
    (fwmark_matched ?x0 - object ?x1 - object)
    (cgroup_matched ?x0 - object ?x1 - object)
    (autobound_matched ?x0 - object)
    (tcp_state ?x0 - object ?x1 - object)
    (socket_in_state ?x0 - object ?x1 - object)
    (tcp_timer_set ?x0 - object)
    (keepalive_active ?x0 - object)
    (timewait_active ?x0 - object)
    (socket_type ?x0 - object ?x1 - object)
    (accept_flag ?x0 - object)
    (waitdata_flag ?x0 - object)
    (nospace_flag ?x0 - object)
    (listening)
    (disconnecting)
    (free)
    (connecting)
    (unknown)
    (primary_group ?x0 - object ?x1 - object)
    (path_initialized ?x0 - object)
    (pam_lastlog_updated ?x0 - object)
    (updated_default_user_info)
    (password_inactive ?x0 - object ?x1 - object)
    (subuids_updated ?x0 - object)
    (subgids_updated ?x0 - object)
    (member_of_group ?x0 - object ?x1 - object)
    (primary_group_of ?x0 - object ?x1 - object)
    (home_directory_created ?x0 - object)
    (login_def_overridden ?x0 - object ?x1 - object)
    (no_lastlog_entry ?x0 - object)
    (no_faillog_entry ?x0 - object)
    (entry_in_lastlog ?x0 - object)
    (entry_in_faillog ?x0 - object)
    (env_variable_set ?x0 - object)
    (create_home_enabled)
    (has_uid ?x0 - object ?x1 - object)
    (password_set ?x0 - object)
    (changes_applied_in_chroot ?x0 - object)
    (changes_applied_with_prefix ?x0 - object)
    (user_shell_set ?x0 - object ?x1 - object)
    (default_updated ?x0 - object)
    (default_base_dir_set ?x0 - object)
    (default_expire_date_set ?x0 - object)
    (default_inactive_set ?x0 - object)
    (password_warn_age_set ?x0 - object ?x1 - object)
    (subordinate_gids_allocated ?x0 - object)
    (subordinate_uids_allocated ?x0 - object)
    (system_user_created ?x0 - object)
    (regular_user_created ?x0 - object)
    (system_group_created ?x0 - object)
    (umask_set ?x0 - object)
    (usergroups_enab ?x0 - object)
    (subid_entry_added ?x0 - object)
    (all_groups_exist ?x0 - object)
    (supplementary_groups_set ?x0 - object ?x1 - object)
    (home_directory_not_set ?x0 - object)
    (no_user_group_created ?x0 - object)
    (duplicate_user_created ?x0 - object)
    (home_directory ?x0 - object)
    (permissions_updated ?x0 - object)
    (non_unique_uid ?x0 - object ?x1 - object)
    (subordinate_uid_range_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gid_range_added ?x0 - object ?x1 - object ?x2 - object)
    (selinux_user_mapped ?x0 - object)
    (nis_updated ?x0 - object)
    (max_members_per_group ?x0 - object)
    (append_group ?x0 - object ?x1 - object)
    (subordinate_uids_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gids_added ?x0 - object ?x1 - object ?x2 - object)
    (if ?x0 - object ?x1 - object ?x2 - object ?x3 - object ?x4 - object ?x5 - object ?x6 - object ?x7 - object ?x8 - object ?x9 - object ?x10 - object)
    (applied_changes_in_chroot ?x0 - object ?x1 - object)
    (applied_changes_in_prefix ?x0 - object ?x1 - object)
    (selinux_mapped ?x0 - object)
    (mail_spool_managed ?x0 - object)
    (gid ?x0 - object ?x1 - object)
    (login_config_overridden ?x0 - object ?x1 - object)
    (gid_range_correct ?x0 - object)
    (changes_applied_in_prefix ?x0 - object)
    (users_added_to_group ?x0 - object ?x1 - object)
    (sys_gid_range_set ?x0 - object ?x1 - object)
    (gid_used ?x0 - object)
    (can_update_group_file)
    (extrausers_enabled)
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

  (:action install_package_version
    :parameters (?actor - user ?pkg - package ?version - file)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (not (package_outdated ?pkg))
    )
  )

  (:action install_package_release
    :parameters (?actor - user ?pkg - package ?release - file)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (not (package_outdated ?pkg))
    )
  )

  (:action reinstall_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (not (package_outdated ?pkg))
    )
  )

  (:action purge_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
      (not (package_configured ?pkg))
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
      (not (package_outdated ?pkg))
    )
  )

  (:action download_source_package
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action install_build_dependencies
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action download_package_files
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (package_configured ?pkg)
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
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (not (package_reverted))
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted)
    )
  )

  (:action ack_assertion
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured)
    )
  )

  (:action add_assertion
    :parameters (?actor - user ?a - file)
    :precondition (and
      (not (assertion_exists ?a))
      (valid_assertion ?a)
      (verified_signature ?a)
      (can_escalate ?actor)
    )
    :effect (and
      (assertion_exists ?a)
    )
  )

  (:action create_alias
    :parameters (?actor - user ?snap - file ?app - file ?alias - file)
    :precondition (and
      (snap_exists ?snap)
      (app_exists_in_snap ?app ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (alias_exists ?alias)
    )
  )

  (:action connect_plug_slot
    :parameters (?actor - user ?snap1 - file ?plug - file ?snap2 - file ?slot - file)
    :precondition (and
      (service_exists ?snap1)
      (service_exists ?snap2)
      (can_escalate ?actor)
    )
    :effect (and
      (connected ?snap1 ?plug ?snap2 ?slot)
    )
  )

  (:action connect_plug_to_snap
    :parameters (?actor - user ?snap1 - file ?plug - file ?snap2 - file)
    :precondition (and
      (service_exists ?snap1)
      (service_exists ?snap2)
      (can_escalate ?actor)
    )
    :effect (and
      (connected ?snap1 ?plug ?snap2)
    )
  )

  (:action snap_connect
    :parameters (?actor - user ?snap - file ?plug - file)
    :precondition (and
      (not (slot_connected ?snap ?plug))
      (can_escalate ?actor)
    )
    :effect (and
      (slot_connected ?snap ?plug)
    )
  )

  (:action create_cohort_keys
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (cohort_keys_created)
    )
  )

  (:action create_cohort
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (package_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (cohort_created ?snap)
    )
  )

  (:action migrate_home_directory
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (home_directory_migrated)
    )
  )

  (:action obtain_stacktraces
    :parameters (?obj - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (stacktraces_obtained)
    )
  )

  (:action inspect_state_file
    :parameters (?obj - file)
    :precondition (and
      (state_file_exists)
    )
    :effect (and
      (state_inspected)
    )
  )

  (:action inspect_timings
    :parameters (?obj - file)
    :precondition (and
      (timings_available)
    )
    :effect (and
      (timings_inspected)
    )
  )

  (:action disconnect_plug_slot
    :parameters (?actor - user ?plug - file ?slot - file)
    :precondition (and
      (package_installed ?plug)
      (package_installed ?slot)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?plug))
      (not (process_running ?plug))
    )
  )

  (:action disconnect_plug_or_slot
    :parameters (?actor - user ?snap - file ?plug_or_slot - file)
    :precondition (and
      (package_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?snap))
      (not (process_running ?snap))
    )
  )

  (:action forget_connection
    :parameters (?conn - file)
    :precondition (and
      (service_exists ?conn)
    )
    :effect (and
      (not (traffic_blocked ?conn))
    )
  )

  (:action install_from_candidate_channel
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (not (package_installed ?snap))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?snap)
    )
  )

  (:action install_from_stable_channel
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (not (package_installed ?snap))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?snap)
    )
  )

  (:action download_snap_revision
    :parameters (?snap - file ?rev - file)
    :precondition (and
      (not (package_installed ?snap))
    )
    :effect (and
      (package_installed ?snap)
    )
  )

  (:action download_with_basename
    :parameters (?snap - file ?rev - file ?base - file)
    :precondition (and
      (not (package_installed ?snap))
    )
    :effect (and
      (package_installed ?snap)
    )
  )

  (:action download_to_directory
    :parameters (?snap - file ?dir - directory)
    :precondition (and
      (not (package_installed ?snap))
    )
    :effect (and
      (package_installed ?snap)
    )
  )

  (:action download_only_components
    :parameters (?snap - file ?comp - file)
    :precondition (and
      (not (package_installed ?snap))
    )
    :effect (and
      (package_installed ?snap)
    )
  )

  (:action download_from_cohort
    :parameters (?snap - file ?coh - file)
    :precondition (and
      (not (package_installed ?snap))
    )
    :effect (and
      (package_installed ?snap)
    )
  )

  (:action export_snapshot
    :parameters (?actor - user ?filename - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (snapshot_exported ?filename)
    )
  )

  (:action delete_snapshot
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (snapshot_exists ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (not (snapshot_exists ?snap))
    )
  )

  (:action remove_snap_from_quota_group
    :parameters (?actor - user ?group - file ?snap - file)
    :precondition (and
      (quota_group_exists ?group)
      (snap_in_group ?snap ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (not (snap_in_group ?snap ?group))
    )
  )

  (:action add_service_to_sub_group
    :parameters (?actor - user ?svc - service ?subgroup - file ?parentgroup - file)
    :precondition (and
      (service_exists ?svc)
      (quota_group_exists ?parentgroup)
      (subgroup_of ?subgroup ?parentgroup)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_in_group ?snap_for_svc ?subgroup)
    )
  )

  (:action remove_sub_group_from_quota_group
    :parameters (?actor - user ?subgroup - file ?parentgroup - file)
    :precondition (and
      (quota_group_exists ?parentgroup)
      (subgroup_of ?subgroup ?parentgroup)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subgroup_of ?subgroup ?parentgroup))
    )
  )

  (:action increase_memory_limit
    :parameters (?actor - user ?g - group ?new_limit - file)
    :precondition (and
      (group_exists ?g)
      (not (memory_limit_set_to ?g ?new_limit))
      (can_escalate ?actor)
    )
    :effect (and
      (memory_limit_set_to ?g ?new_limit)
    )
  )

  (:action increase_cpu_limit
    :parameters (?actor - user ?g - group ?new_limit - file)
    :precondition (and
      (group_exists ?g)
      (not (cpu_limit_set_to ?g ?new_limit))
      (can_escalate ?actor)
    )
    :effect (and
      (cpu_limit_set_to ?g ?new_limit)
    )
  )

  (:action set_cpu_quota
    :parameters (?actor - user ?group - file ?percentage - file)
    :precondition (and
      (quota_group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (cpu_quota_set ?group ?percentage)
    )
  )

  (:action modify_cpu_set
    :parameters (?actor - user ?group - file ?cpu_list - file)
    :precondition (and
      (quota_group_exists ?group)
      (cpu_quota_set ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (modified_cpu_set ?group ?cpu_list)
    )
  )

  (:action increase_threads_limit
    :parameters (?actor - user ?group - file ?new_limit - file)
    :precondition (and
      (quota_group_exists ?group)
      (threads_limit_set ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (threads_limit_increased ?group ?new_limit)
    )
  )

  (:action decrease_threads_limit
    :parameters (?actor - user ?group - file ?new_limit - file)
    :precondition (and
      (quota_group_exists ?group)
      (threads_limit_set ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (threads_limit_decreased ?group ?new_limit)
    )
  )

  (:action modify_journal_limit
    :parameters (?actor - user ?group - file ?new_limit - file)
    :precondition (and
      (quota_group_exists ?group)
      (journal_limit_set ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_limit_modified ?group ?new_limit)
    )
  )

  (:action set_journal_namespace
    :parameters (?actor - user ?group - file ?new_limit - file)
    :precondition (and
      (quota_group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_namespace_set ?group)
    )
  )

  (:action set_quota
    :parameters (?actor - user ?qg - file ?svc - file ?memory - file ?cpu - file ?cpuset - file ?threads - file ?journalsize - file ?journalratelimit - file ?parent - file)
    :precondition (and
      (service_exists ?svc)
      (not (package_reverted ?svc))
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?svc)
    )
  )

  (:action start_services
    :parameters (?actor - user ?svc - file)
    :precondition (and
      (service_exists ?svc)
      (not (service_running ?svc))
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
    )
  )

  (:action start_snap_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (not (service_running ?svc))
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
      (service_enabled ?svc)
    )
  )

  (:action stop_snap_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_running ?svc)
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?svc))
      (not (service_enabled ?svc))
    )
  )

  (:action switch_snap_channel
    :parameters (?snap - file ?channel - file)
    :precondition (and
      (service_exists ?snap)
    )
    :effect (and
      (package_configured ?snap)
      (not (vulnerable ?snap))
    )
  )

  (:action disable_service_on_boot
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (not (service_enabled ?svc))
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_enabled ?svc))
    )
  )

  (:action try_snap
    :parameters (?actor - user ?snap_path - file)
    :precondition (and
      (file_exists ?snap_path)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?snap_path)
      (service_running ?snap_path)
    )
  )

  (:action unalias_snap
    :parameters (?name - file)
    :precondition (and
    )
    :effect (and
      (snap_aliases_removed ?name)
    )
  )

  (:action unset_configuration
    :parameters (?snap - file ?option - file)
    :precondition (and
      (package_installed ?snap)
    )
    :effect (and
      (not (package_configured ?snap))
    )
  )

  (:action configure_snap
    :parameters (?snap - package)
    :precondition (and
      (package_installed ?snap)
    )
    :effect (and
      (package_configured ?snap)
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

  (:action set_alias
    :parameters (?alias_name - file ?command - file)
    :precondition (and
    )
    :effect (and
      (alias_exists ?alias_name)
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

  (:action prefer_aliases
    :parameters (?snap - file)
    :precondition (and
      (snap_installed ?snap)
    )
    :effect (and
      (aliases_preferred ?snap)
    )
  )

  (:action login_snap
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (user_authenticated)
    )
  )

  (:action logout_snap
    :parameters (?obj - file)
    :precondition (and
      (user_authenticated)
    )
    :effect (and
      (not (user_authenticated))
    )
  )

  (:action save_snapshot
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (snapshot_saved)
    )
  )

  (:action import_snapshot
    :parameters (?source_file - file)
    :precondition (and
    )
    :effect (and
      (snapshot_imported)
    )
  )

  (:action reboot_device
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (device_rebooted)
    )
  )

  (:action acknowledge_warnings
    :parameters (?obj - file)
    :precondition (and
      (warnings_exist)
    )
    :effect (and
      (warnings_acknowledged)
    )
  )

  (:action run_debug_commands
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (debug_info_collected)
    )
  )

  (:action download_snap
    :parameters (?snap - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (package_installed ?snap)
    )
  )

  (:action export_key
    :parameters (?key - file)
    :precondition (and
    )
    :effect (and
      (file_exists ?key)
    )
  )

  (:action set_quota_group
    :parameters (?actor - user ?group - file ?size - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (quota_group_exists ?group)
    )
  )

  (:action remove_quota_group
    :parameters (?actor - user ?group - file)
    :precondition (and
      (quota_group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (not (quota_group_exists ?group))
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

  (:action add_exe_match
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (not (file_executable ?f))
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action add_comm_match
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (not (file_executable ?f))
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action grant_access_to_system_journal
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of ?u ?g)
    )
  )

  (:action operate_on_disk_image
    :parameters (?actor - user ?image - file ?policy - file ?namespace - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (disk_image_operated ?image)
      (applied_image_policy ?policy)
      (selected_namespace ?namespace)
    )
  )

  (:action write_cursor_to_file
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (cursor_written_to_file ?file)
    )
  )

  (:action lookup_boots_from_beginning
    :parameters (?offset - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (boots_lookup_from_beginning ?offset)
    )
  )

  (:action lookup_boots_from_end
    :parameters (?offset - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (boots_lookup_from_end ?offset)
    )
  )

  (:action negate_boot_filter
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (process_running ?all)
    )
  )

  (:action set_output_format
    :parameters (?format - file)
    :precondition (and
    )
    :effect (and
      (output_format_set ?format)
    )
  )

  (:action set_output_short
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (output_format_set ?short)
    )
  )

  (:action set_output_short_full
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (output_format_set ?short-full)
    )
  )

  (:action update_catalog
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (catalog_updated)
    )
  )

  (:action setup_keys
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (keys_generated)
    )
  )

  (:action set_systemd_lesscharset
    :parameters (?charset - file)
    :precondition (and
    )
    :effect (and
      (systemd_lesscharset_set ?charset)
    )
  )

  (:action enable_pagersecure_mode
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (pagersecure_enabled)
    )
  )

  (:action disable_pagersecure_mode
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (not (pagersecure_enabled))
    )
  )

  (:action filter_journal
    :parameters (?match - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (filtered_logs ?match)
    )
  )

  (:action set_systemd_color_output
    :parameters (?color - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (systemd_color_output ?color)
    )
  )

  (:action set_systemd_urlify_output
    :parameters (?urlify - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (systemd_urlify_output ?urlify)
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
    :parameters (?srcs - file ?dir - directory)
    :precondition (and
      (file_exists ?srcs)
    )
    :effect (and
      (file_exists ?concatenate ?dir ?basename_?srcs)
    )
  )

  (:action recursive_copy_special_files
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?concatenate ?dest ?basename_?src)
    )
  )

  (:action backup_file
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?dest)
    )
    :effect (and
      (file_exists ?concatenate ?dest)
    )
  )

  (:action copy_attributes_only
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (not (file_executable ?dest))
    )
  )

  (:action change_permissions_to_executable
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action force_copy_file
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (not (file_executable ?dst))
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action no_clobber_copy_file
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (not (file_exists ?dst))
    )
  )

  (:action recursive_copy
    :parameters (?src - directory ?dest - directory)
    :precondition (and
      (directory_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (directory_contents_copied ?src ?dest)
    )
  )

  (:action create_symbolic_link
    :parameters (?target - file ?link_path - file)
    :precondition (and
      (file_exists ?target)
    )
    :effect (and
      (symbolic_link_created ?link_path ?target)
    )
  )

  (:action remove_destination_before_copying
    :parameters (?dest - file)
    :precondition (and
      (file_exists ?dest)
    )
    :effect (and
      (not (file_exists ?dest))
    )
  )

  (:action create_sparse_file
    :parameters (?file - file ?when - file)
    :precondition (and
      (not (file_exists ?file))
    )
    :effect (and
      (sparse_file_created ?file)
    )
  )

  (:action clone_copy
    :parameters (?src - file ?dest - file ?when - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (cloned_file_created ?dest)
    )
  )

  (:action copy_to_normal_file
    :parameters (?src - file ?dest - file)
    :precondition (and
      (not (directory_exists ?dest))
    )
    :effect (and
      (file_copied ?src ?dest)
    )
  )

  (:action update_existing_files
    :parameters (?src - file ?dest - directory ?update - file)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (updated_file_copied ?src ?dest)
    )
  )

  (:action strip_trailing_slashes
    :parameters (?src - directory)
    :precondition (and
      (directory_exists ?src)
    )
    :effect (and
      (trailing_slashes_removed ?src)
    )
  )

  (:action copy_into_directory
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied_to_directory ?src ?dest)
    )
  )

  (:action override_backup_suffix
    :parameters (?file - file ?suffix - file)
    :precondition (and
      (not (file_exists ?file))
    )
    :effect (and
      (backup_file_created_with_suffix ?file)
    )
  )

  (:action set_selinux_context_default
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (selinux_context_default ?f)
    )
  )

  (:action set_selinux_context_custom
    :parameters (?f - file ?ctx - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (selinux_context_custom ?f ?ctx)
    )
  )

  (:action copy_within_filesystem
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (same_filesystem ?src ?dest)
    )
    :effect (and
      (file_copied_within_fs ?src ?dest)
    )
  )

  (:action copy_with_attributes
    :parameters (?src - file ?dest - file ?attr_list - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (attributes_copied ?src ?dest ?attr_list)
    )
  )

  (:action copy_sparse_file
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (sparse_file_copied ?src ?dest)
    )
  )

  (:action copy_file_no_sparse
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_executable ?dest)
      (not (vulnerable ?dest))
    )
  )

  (:action copy_file_all_update
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_executable ?dest)
      (not (vulnerable ?dest))
    )
  )

  (:action copy_file_none_update
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (not (vulnerable ?dest))
    )
  )

  (:action copy_file_older_update
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (not (vulnerable ?dest))
    )
  )

  (:action copy_file_reflink
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (not (vulnerable ?dest))
    )
  )

  (:action copy_file_reflink_always
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (not (vulnerable ?dest))
    )
  )

  (:action standard_copy
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (requires_env_preservation ?dest))
    )
    :effect (and
      (file_copied ?src ?dest)
    )
  )

  (:action copy_files_to_directory_with_t_option
    :parameters (?src - file ?dest_dir - directory)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?concatenate ?dest_dir ?basename_?src)
    )
  )

  (:action copy_file_attributes_only
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (not (file_executable ?dest))
    )
  )

  (:action copy_file_with_backup
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?concatenate ?dest)
    )
  )

  (:action copy_file_archive
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
      (not (file_executable ?dest))
    )
  )

  (:action copy_contents
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (not (file_writable ?dest))
    )
    :effect (and
      (file_executable ?src)
    )
  )

  (:action force_copy
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (not (file_writable ?dest))
    )
    :effect (and
      (file_executable ?src)
    )
  )

  (:action interactive_copy
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (not (file_writable ?dest))
    )
    :effect (and
      (file_executable ?src)
    )
  )

  (:action hard_link_files
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (not (file_writable ?dest))
    )
    :effect (and
      (file_executable ?src)
    )
  )

  (:action no_clobber_copy
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (not (file_writable ?dest))
    )
    :effect (and
      (file_executable ?src)
    )
  )

  (:action make_executable
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action preserve_attributes
    :parameters (?f - file ?attrs - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (preserved_attributes ?f ?attrs)
    )
  )

  (:action remove_destination_before_copy
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
      (not (follows_symlink ?src))
    )
  )

  (:action copy_with_full_source_name
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (full_source_name_copied ?dest)
    )
  )

  (:action reflink_copy
    :parameters (?src - file ?dest - file ?when - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (reflinked_copy_created ?dest)
    )
  )

  (:action set_selinux_smack_context
    :parameters (?file - file ?ctx - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (selinux_smack_context_set ?file)
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

  (:action create_sparse_file_with_zeros
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (sparse_file ?dest)
      (has_zero_sequence ?dest)
    )
  )

  (:action create_non_sparse_file
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (non_sparse_file ?dest)
    )
  )

  (:action update_destination_files
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dest)
    )
    :effect (and
      (updated_file ?dest)
    )
  )

  (:action lightweight_copy
    :parameters (?src_file - file ?dest_file - file)
    :precondition (and
      (file_exists ?src_file)
      (not (file_exists ?dest_file))
    )
    :effect (and
      (file_exists ?dest_file)
    )
  )

  (:action update_copy
    :parameters (?src_file - file ?dest_file - file)
    :precondition (and
      (file_exists ?src_file)
      (file_exists ?dest_file)
    )
    :effect (and
      (file_updated ?dest_file)
    )
  )

  (:action backup_copy
    :parameters (?src_file - file ?dest_file - file)
    :precondition (and
      (file_exists ?src_file)
      (not (file_exists ?dest_file))
    )
    :effect (and
      (file_backup_created ?dest_file)
    )
  )

  (:action create_numbered_backup
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (file_exists ?dest))
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action create_simple_backup
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (file_exists ?dest))
    )
    :effect (and
      (file_exists ?dest)
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

  (:action remove_file_or_directory
    :parameters (?file_path - file)
    :precondition (and
      (file_exists ?file_path)
    )
    :effect (and
      (not (file_exists ?file_path))
    )
  )

  (:action force_remove_file_or_directory
    :parameters (?file_path - file)
    :precondition (and
    )
    :effect (and
      (not (file_exists ?file_path))
    )
  )

  (:action remove_file_interactive_always
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action remove_file_interactive_once
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action remove_file_interactive_when
    :parameters (?f - file ?when - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action remove_directory_recursive_one_file_system
    :parameters (?d - directory)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (not (directory_exists ?d))
    )
  )

  (:action remove_file_preserve_root
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action remove_file_preserve_root_all
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action remove_directory_recursive
    :parameters (?d - directory)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (not (directory_exists ?d))
    )
  )

  (:action remove_empty_directory
    :parameters (?d - directory)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (not (directory_exists ?d))
    )
  )

  (:action remove_file_verbose
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action output_version_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (output_version_information)
    )
  )

  (:action remove_special_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action securely_delete_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
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

  (:action remove_file_force
    :parameters (?f - file)
    :precondition (and
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action remove_file_interactive
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action recursively_remove_hierarchy
    :parameters (?dir - directory)
    :precondition (and
      (file_exists ?dir)
    )
    :effect (and
      (not (file_exists ?dir))
    )
  )

  (:action remove_root_recursively
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (file_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?dir))
    )
  )

  (:action recursively_remove_directory_contents
    :parameters (?dir - directory)
    :precondition (and
      (file_exists ?dir)
    )
    :effect (and
      (not (file_exists ?dir))
    )
  )

  (:action preserve_root_and_device_hierarchy
    :parameters (?dir - directory)
    :precondition (and
      (file_exists ?dir)
    )
    :effect (and
      (not (file_exists ?dir))
    )
  )

  (:action recursively_remove_directory_contents_verbose
    :parameters (?dir - directory)
    :precondition (and
      (file_exists ?dir)
    )
    :effect (and
      (not (file_exists ?dir))
    )
  )

  (:action remove_file_relative_path
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action shred_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action change_file_mode_bits
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_executable ?f)
      (file_readable ?f)
      (file_writable ?f)
    )
  )

  (:action change_permissions_pointed_to_file
    :parameters (?link - file ?target - file)
    :precondition (and
      (file_exists ?link)
      (not (file_executable ?target))
    )
    :effect (and
      (file_executable ?target)
    )
  )

  (:action clear_set_group_id_bit
    :parameters (?f - file ?gid - file)
    :precondition (and
      (file_exists ?f)
      (not (user_in_group ?gid))
    )
    :effect (and
      (not (set_group_id_bit ?f))
    )
  )

  (:action change_directory_permissions
    :parameters (?dir - directory)
    :precondition (and
      (file_exists ?dir)
    )
    :effect (and
      (set_user_id_bit ?dir)
      (set_group_id_bit ?dir)
    )
  )

  (:action toggle_set_bits
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (file_exists ?dir)
    )
    :effect (and
      (set_user_id_bit ?dir)
      (clear_group_id_bit ?dir)
    )
  )

  (:action toggle_sticky_bit
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (file_exists ?dir)
    )
    :effect (and
      (sticky_bit_set ?dir)
      (sticky_bit_cleared ?dir)
    )
  )

  (:action change_file_mode
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_has_mode ?f ?mode)
    )
  )

  (:action change_file_mode_reference
    :parameters (?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
    )
    :effect (and
      (action_completed_change_file_mode_reference)
    )
  )

  (:action change_file_permissions
    :parameters (?file - file ?mode - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (file_executable ?file)
    )
  )

  (:action change_permissions_reference
    :parameters (?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
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

  (:action chown_file
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (owner_of ?f ?owner)
      (group_of ?f ?group)
    )
  )

  (:action change_owner_group
    :parameters (?actor - user ?f - file ?owner - user ?group - group ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by ?f ?owner)
      (group_owned_by ?f ?group)
    )
  )

  (:action change_owner_group_reference
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_change_owner_group_reference)
    )
  )

  (:action change_group_only
    :parameters (?actor - user ?f - file ?group - group)
    :precondition (and
      (file_exists ?f)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (group_owned_by ?f ?group)
    )
  )

  (:action change_owner_group_dereference
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by ?f ?owner)
      (group_owned_by ?f ?group)
    )
  )

  (:action change_owner_group_no_dereference
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by ?f ?owner)
      (group_owned_by ?f ?group)
    )
  )

  (:action chown_if_match
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (current_owner_matches ?f ?owner)
      (current_group_matches ?f ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (new_owner ?f ?owner)
      (new_group ?f ?group)
    )
  )

  (:action disable_preserve_root
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (preserve_root_disabled)
    )
  )

  (:action enable_preserve_root
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (preserve_root_enabled)
    )
  )

  (:action chown_reference
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?rfile)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (new_owner_from_ref ?f ?rfile)
      (new_group_from_ref ?f ?rfile)
    )
  )

  (:action operate_recursively
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (recursively_operated_on ?dir)
    )
  )

  (:action traverse_symlink_dir
    :parameters (?symlink - file)
    :precondition (and
      (is_symbolic_link ?symlink)
      (points_to_directory ?symlink)
    )
    :effect (and
      (traversed_symlink ?symlink)
    )
  )

  (:action traverse_all_symlinks
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (all_symlinks_traversed)
    )
  )

  (:action do_not_traverse_symlinks
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (no_symlinks_traversed)
    )
  )

  (:action recursive_change_owner
    :parameters (?actor - user ?dir - directory ?owner - user)
    :precondition (and
      (file_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_locked ?owner))
    )
  )

  (:action chown_file_reference
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_chown_file_reference)
    )
  )

  (:action change_ownership
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of ?owner ?group)
    )
  )

  (:action change_ownership_from
    :parameters (?actor - user ?f - file ?owner - user ?group - group ?current_owner - user ?current_group - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?current_owner)
      (group_exists ?current_group)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of ?owner ?group)
    )
  )

  (:action traverse_symlink
    :parameters (?dir - directory ?option - file)
    :precondition (and
      (file_exists ?dir)
    )
    :effect (and
      (not (requires_env_preservation ?dir))
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

  (:action create_directory_with_mode
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (not (directory_exists ?dir))
    )
    :effect (and
      (directory_exists ?dir)
      (directory_mode_set ?dir)
    )
  )

  (:action create_directory_with_parents
    :parameters (?dir - directory)
    :precondition (and
      (not (directory_exists ?dir))
    )
    :effect (and
      (directory_exists ?dir)
    )
  )

  (:action create_directory_with_verbose
    :parameters (?dir - directory)
    :precondition (and
      (not (directory_exists ?dir))
    )
    :effect (and
      (directory_exists ?dir)
    )
  )

  (:action create_directory_with_selinux_context
    :parameters (?dir - directory)
    :precondition (and
      (not (directory_exists ?dir))
    )
    :effect (and
      (directory_exists ?dir)
      (selinux_context_set ?dir)
    )
  )

  (:action create_directory_with_custom_selinux_context
    :parameters (?dir - directory ?ctx - file)
    :precondition (and
      (not (directory_exists ?dir))
    )
    :effect (and
      (directory_exists ?dir)
      (custom_selinux_context_set ?dir)
    )
  )

  (:action set_directory_mode
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_mode_set ?dir ?mode)
    )
  )

  (:action create_parent_directories
    :parameters (?dir - directory)
    :precondition (and
      (not (directory_exists ?dir))
    )
    :effect (and
      (directory_exists ?dir)
    )
  )

  (:action set_selinux_context
    :parameters (?dir - directory ?ctx - file)
    :precondition (and
      (not (file_exists ?dir))
    )
    :effect (and
      (file_owned_by ?dir ?ctx)
    )
  )

  (:action create_directory_verbose
    :parameters (?dir - directory)
    :precondition (and
      (not (file_exists ?dir))
    )
    :effect (and
      (file_exists ?dir)
    )
  )

  (:action create_directory_default_selinux
    :parameters (?dir - directory)
    :precondition (and
      (not (file_exists ?dir))
    )
    :effect (and
      (file_exists ?dir)
    )
  )

  (:action create_directory_specified_context
    :parameters (?dir - directory ?ctx - file)
    :precondition (and
      (not (file_exists ?dir))
    )
    :effect (and
      (file_owned_by ?dir ?ctx)
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

  (:action touch_file
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_accessed ?f)
      (file_modified ?f)
    )
  )

  (:action touch_no_create
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_accessed ?f)
      (file_modified ?f)
    )
  )

  (:action touch_access_time
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_accessed ?f)
    )
  )

  (:action touch_modification_time
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_modified ?f)
    )
  )

  (:action touch_with_date
    :parameters (?f - file ?date - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_accessed ?f)
      (file_modified ?f)
    )
  )

  (:action touch_no_dereference
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_accessed ?f)
      (file_modified ?f)
    )
  )

  (:action set_file_times_reference
    :parameters (?f - file ?ref - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?ref)
    )
    :effect (and
      (same_timestamps ?f ?ref)
    )
  )

  (:action set_file_times_timestamp
    :parameters (?f - file ?stamp - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (timestamp_set ?f ?stamp)
    )
  )

  (:action change_file_time_attribute
    :parameters (?f - file ?word - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_time_attribute_set ?f ?word)
    )
  )

  (:action create_file_if_not_exist
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action update_mtime
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_modified ?f)
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

  (:action set_pacing_rate
    :parameters (?actor - user ?pacing_rate - file ?max_pacing_rate - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (tcp_pacing_rate_set ?pacing_rate)
      (tcp_max_pacing_rate_set ?max_pacing_rate)
    )
  )

  (:action set_rcv_space
    :parameters (?actor - user ?rcv_space - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (tcp_rcv_space_set ?rcv_space)
    )
  )

  (:action configure_tcp_ulp_mptcp
    :parameters (?actor - user ?flags - file ?rem_token - file ?loc_token - file ?sn - file ?ssn - file ?off - file ?maplen - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (tcp_ulp_mptcp_configured ?flags)
      (tcp_ulp_rem_token_set ?rem_token)
      (tcp_ulp_loc_token_set ?loc_token)
      (tcp_ulp_sn_set ?sn)
      (tcp_ulp_sfseq_set ?ssn)
      (tcp_ulp_ssnoff_set ?off)
      (tcp_ulp_maplen_set ?maplen)
    )
  )

  (:action switch_network_namespace
    :parameters (?nsname - interface)
    :precondition (and
      (network_available)
    )
    :effect (and
      (network_available)
    )
  )

  (:action diagnose_sockets_from_file
    :parameters (?file - file)
    :precondition (and
    )
    :effect (and
      (sockets_diagnosed ?file)
    )
  )

  (:action match_device
    :parameters (?actor - user ?dev - file ?conn - file)
    :precondition (and
      (not (traffic_blocked ?conn))
      (can_escalate ?actor)
    )
    :effect (and
      (device_matched ?conn ?dev)
    )
  )

  (:action match_fwmark
    :parameters (?actor - user ?mask - file ?conn - file)
    :precondition (and
      (not (traffic_blocked ?conn))
      (can_escalate ?actor)
    )
    :effect (and
      (fwmark_matched ?conn ?mask)
    )
  )

  (:action match_cgroup
    :parameters (?actor - user ?path - file ?conn - file)
    :precondition (and
      (not (traffic_blocked ?conn))
      (can_escalate ?actor)
    )
    :effect (and
      (cgroup_matched ?conn ?path)
    )
  )

  (:action match_autobound
    :parameters (?actor - user ?conn - file)
    :precondition (and
      (not (traffic_blocked ?conn))
      (can_escalate ?actor)
    )
    :effect (and
      (autobound_matched ?conn)
    )
  )

  (:action configure_link_address
    :parameters (?actor - user ?addr - file ?dev - interface)
    :precondition (and
      (interface_exists ?dev)
      (can_escalate ?actor)
    )
    :effect (and
      (port_allowed ?addr)
    )
  )

  (:action configure_netlink_address
    :parameters (?actor - user ?addr - file ?port - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (port_allowed ?port)
    )
  )

  (:action configure_vsock_address
    :parameters (?actor - user ?cid - file ?port - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (port_allowed ?port)
    )
  )

  (:action configure_inet_address
    :parameters (?actor - user ?addr - file ?family - interface)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (port_allowed ?addr)
    )
  )

  (:action read_filter_information
    :parameters (?actor - user ?file - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?file)
    )
  )

  (:action set_tcp_state
    :parameters (?actor - user ?p - port ?s - file)
    :precondition (and
      (port_open ?p)
      (can_escalate ?actor)
    )
    :effect (and
      (tcp_state ?p ?s)
    )
  )

  (:action change_socket_state
    :parameters (?s - file)
    :precondition (and
      (not (socket_in_state ?s ?close))
    )
    :effect (and
      (socket_in_state ?s ?new_state)
    )
  )

  (:action start_listening_socket
    :parameters (?p - port ?u - user ?pid - process)
    :precondition (and
      (not (port_open ?p))
      (user_exists ?u)
      (network_available)
    )
    :effect (and
      (port_open ?p)
    )
  )

  (:action shutdown_socket
    :parameters (?actor - user ?p - port ?u - user ?pid - process)
    :precondition (and
      (port_open ?p)
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (port_open ?p))
    )
  )

  (:action listen_for_connections
    :parameters (?p - port ?u - user ?pid - process)
    :precondition (and
      (not (port_open ?p))
      (user_exists ?u)
      (network_available)
    )
    :effect (and
      (port_open ?p)
    )
  )

  (:action set_tcp_timer
    :parameters (?actor - user ?p - port ?u - user ?pid - process ?timer - file)
    :precondition (and
      (port_open ?p)
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (tcp_timer_set ?p)
    )
  )

  (:action disable_tcp_timer
    :parameters (?actor - user ?p - port ?u - user ?pid - process)
    :precondition (and
      (tcp_timer_set ?p)
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (tcp_timer_set ?p))
    )
  )

  (:action activate_keepalive_timer
    :parameters (?sock - file)
    :precondition (and
      (not (keepalive_active ?sock))
    )
    :effect (and
      (keepalive_active ?sock)
    )
  )

  (:action activate_timewait_timer
    :parameters (?sock - file)
    :precondition (and
      (not (timewait_active ?sock))
    )
    :effect (and
      (timewait_active ?sock)
    )
  )

  (:action change_socket_type_to_datagram
    :parameters (?sock - file)
    :precondition (and
      (not (socket_type ?sock ?sock_dgram))
    )
    :effect (and
      (socket_type ?sock ?sock_dgram)
    )
  )

  (:action change_socket_type_to_stream
    :parameters (?sock - file)
    :precondition (and
      (not (socket_type ?sock ?sock_stream))
    )
    :effect (and
      (socket_type ?sock ?sock_stream)
    )
  )

  (:action change_socket_type_to_raw
    :parameters (?sock - file)
    :precondition (and
      (not (socket_type ?sock ?sock_raw))
    )
    :effect (and
      (socket_type ?sock ?sock_raw)
    )
  )

  (:action activate_accept_flag
    :parameters (?sock - file)
    :precondition (and
      (not (accept_flag ?sock))
    )
    :effect (and
      (accept_flag ?sock)
    )
  )

  (:action activate_waitdata_flag
    :parameters (?sock - file)
    :precondition (and
      (not (waitdata_flag ?sock))
    )
    :effect (and
      (waitdata_flag ?sock)
    )
  )

  (:action activate_nospace_flag
    :parameters (?sock - file)
    :precondition (and
      (not (nospace_flag ?sock))
    )
    :effect (and
      (nospace_flag ?sock)
    )
  )

  (:action use_raw_socket
    :parameters (?actor - user ?s - file)
    :precondition (and
      (not (service_running ?s))
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?s)
    )
  )

  (:action set_socket_listening
    :parameters (?actor - user ?s - file)
    :precondition (and
      (not (service_running ?s))
      (can_escalate ?actor)
    )
    :effect (and
      (listening)
    )
  )

  (:action set_socket_connected
    :parameters (?actor - user ?s - file)
    :precondition (and
      (not (service_running ?s))
      (can_escalate ?actor)
    )
    :effect (and
      (connected)
    )
  )

  (:action set_socket_disconnecting
    :parameters (?actor - user ?s - file)
    :precondition (and
      (not (service_running ?s))
      (can_escalate ?actor)
    )
    :effect (and
      (disconnecting)
    )
  )

  (:action set_socket_free
    :parameters (?actor - user ?s - file)
    :precondition (and
      (not (service_running ?s))
      (can_escalate ?actor)
    )
    :effect (and
      (free)
    )
  )

  (:action set_socket_connecting
    :parameters (?actor - user ?s - file)
    :precondition (and
      (not (service_running ?s))
      (can_escalate ?actor)
    )
    :effect (and
      (connecting)
    )
  )

  (:action set_socket_unknown
    :parameters (?actor - user ?s - file)
    :precondition (and
      (not (service_running ?s))
      (can_escalate ?actor)
    )
    :effect (and
      (unknown)
    )
  )

  (:action execute_privileged
    :parameters (?u - user ?cmd - process)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?u)
    )
    :effect (and
      (executed_as_root ?cmd)
    )
  )

  (:action set_primary_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (member_of ?u ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (primary_group ?u ?g)
    )
  )

  (:action add_supplementary_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (not (member_of ?u ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (member_of ?u ?g)
    )
  )

  (:action terminate_child_process
    :parameters (?child - process ?signal - file)
    :precondition (and
      (process_running ?child)
    )
    :effect (and
      (not (process_running ?child))
    )
  )

  (:action change_path_environment
    :parameters (?env - process)
    :precondition (and
      (requires_env_preservation ?env)
    )
    :effect (and
      (path_initialized ?env)
    )
  )

  (:action execute_su_with_login_and_preserve_environment
    :parameters (?user - user ?env - process)
    :precondition (and
      (requires_env_preservation ?env)
      (user_exists ?user)
    )
    :effect (and
      (path_initialized ?env)
    )
  )

  (:action execute_su_without_login_and_preserve_environment
    :parameters (?user - user ?env - process)
    :precondition (and
      (requires_env_preservation ?env)
      (user_exists ?user)
    )
    :effect (and
      (path_initialized ?env)
    )
  )

  (:action update_pam_lastlog
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (pam_lastlog_updated ?f)
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

  (:action update_default_user_info
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (updated_default_user_info)
    )
  )

  (:action add_user_with_comment
    :parameters (?actor - user ?user - user ?comment - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action add_user_with_expire_date
    :parameters (?actor - user ?user - user ?expire_date - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action set_password_inactivity_period
    :parameters (?actor - user ?u - user ?inactive_days - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (password_inactive ?u ?inactive_days)
    )
  )

  (:action update_subids_for_system_account
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (subuids_updated ?u)
      (subgids_updated ?u)
    )
  )

  (:action add_user
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (not (user_exists ?u))
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (member_of_group ?u ?g)
    )
  )

  (:action add_user_with_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (not (user_exists ?u))
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (primary_group_of ?u ?g)
    )
  )

  (:action add_user_with_supplementary_groups
    :parameters (?actor - user ?u - user ?g1 - group ?g2 - group ?gn - group)
    :precondition (and
      (not (user_exists ?u))
      (group_exists ?g1)
      (group_exists ?g2)
      (group_exists ?gn)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (member_of_group ?u ?g1)
      (member_of_group ?u ?g2)
      (member_of_group ?u ?gn)
    )
  )

  (:action create_user_with_skeleton
    :parameters (?actor - user ?username - user ?skel_dir - directory)
    :precondition (and
      (not (user_exists ?username))
      (directory_exists ?skel_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?username)
      (home_directory_created ?username)
    )
  )

  (:action override_login_defs
    :parameters (?actor - user ?key - file ?value - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (login_def_overridden ?key ?value)
    )
  )

  (:action create_user_no_log_init
    :parameters (?actor - user ?username - user)
    :precondition (and
      (not (user_exists ?username))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?username)
      (no_lastlog_entry ?username)
      (no_faillog_entry ?username)
    )
  )

  (:action reset_user_logs
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (entry_in_lastlog ?u))
      (not (entry_in_faillog ?u))
    )
  )

  (:action preserve_user_logs
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (env_variable_set ?log_init_no)
      (can_escalate ?actor)
    )
    :effect (and
      (entry_in_lastlog ?u)
      (entry_in_faillog ?u)
    )
  )

  (:action set_create_home
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (create_home_enabled)
    )
  )

  (:action add_user_no_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (not (user_exists ?user))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (member_of ?user ?group)
    )
  )

  (:action add_user_non_unique_uid
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (not (user_exists ?user))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (has_uid ?user ?uid)
    )
  )

  (:action set_initial_password
    :parameters (?actor - user ?user - user ?password - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_set ?user)
    )
  )

  (:action create_system_account
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (user_locked ?u)
    )
  )

  (:action create_home_directory
    :parameters (?actor - user ?u - user ?d - directory)
    :precondition (and
      (user_exists ?u)
      (not (file_exists ?d))
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?d)
    )
  )

  (:action apply_changes_chroot
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (file_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_chroot ?dir)
    )
  )

  (:action apply_changes_prefix
    :parameters (?dir - directory)
    :precondition (and
      (file_exists ?dir)
    )
    :effect (and
      (changes_applied_with_prefix ?dir)
    )
  )

  (:action set_shell_path
    :parameters (?actor - user ?u - user ?s - file)
    :precondition (and
      (user_exists ?u)
      (file_exists ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (user_shell_set ?u ?s)
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

  (:action set_user_id
    :parameters (?actor - user ?u - user ?uid - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?uid))
    )
  )

  (:action set_selinux_user
    :parameters (?actor - user ?u - user ?seuser - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?seuser))
    )
  )

  (:action update_default_values
    :parameters (?actor - user ?option - file ?value - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_updated ?option)
    )
  )

  (:action set_home_directory_prefix
    :parameters (?actor - user ?base_dir - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_base_dir_set ?base_dir)
    )
  )

  (:action set_account_expiry_date
    :parameters (?actor - user ?expire_date - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_expire_date_set ?expire_date)
    )
  )

  (:action set_inactive_days
    :parameters (?actor - user ?inactive - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_inactive_set ?inactive)
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

  (:action change_password
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (not (vulnerable ?u))
    )
  )

  (:action remove_user_from_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (member_of ?u ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (not (member_of ?u ?g))
    )
  )

  (:action set_password_warn_age
    :parameters (?actor - user ?user - user ?age - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_warn_age_set ?user ?age)
    )
  )

  (:action allocate_subordinate_group_ids
    :parameters (?actor - user ?user - user ?min - file ?max - file ?count - file)
    :precondition (and
      (user_exists ?user)
      (not (subordinate_gids_allocated ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gids_allocated ?user)
    )
  )

  (:action allocate_subordinate_user_ids
    :parameters (?actor - user ?user - user ?min - file ?max - file ?count - file)
    :precondition (and
      (user_exists ?user)
      (not (subordinate_uids_allocated ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uids_allocated ?user)
    )
  )

  (:action create_system_user
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (system_user_created ?u)
    )
  )

  (:action create_regular_user
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (regular_user_created ?u)
    )
  )

  (:action create_system_group
    :parameters (?actor - user ?g - group)
    :precondition (and
      (not (group_exists ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?g)
      (system_group_created ?g)
    )
  )

  (:action set_umask
    :parameters (?mask - file)
    :precondition (and
    )
    :effect (and
      (umask_set ?mask)
    )
  )

  (:action remove_user_and_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (member_of ?user ?group)
      (usergroups_enab ?yes)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
      (not (member_of ?user ?group))
    )
  )

  (:action add_subids_for_system_user
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (not (user_exists ?u))
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of ?u ?g)
      (subid_entry_added ?u)
    )
  )

  (:action set_supplementary_groups
    :parameters (?actor - user ?u - user ?gs - file)
    :precondition (and
      (not (user_exists ?u))
      (all_groups_exist ?gs)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of ?u ?gs)
      (supplementary_groups_set ?u ?gs)
    )
  )

  (:action no_create_home_directory
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_not_set ?u)
    )
  )

  (:action no_create_user_group
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (no_user_group_created ?u)
    )
  )

  (:action create_duplicate_users
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (duplicate_user_created ?u)
    )
  )

  (:action create_user_group
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (not (group_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?u)
      (member_of ?u ?u)
    )
  )

  (:action change_primary_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of ?u ?g)
    )
  )

  (:action append_user_to_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of ?u ?g)
    )
  )

  (:action change_username
    :parameters (?actor - user ?old_user - user ?new_user - user)
    :precondition (and
      (user_exists ?old_user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?old_user))
      (user_exists ?new_user)
    )
  )

  (:action lock_password
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_locked ?u)
    )
  )

  (:action move_home_directory
    :parameters (?actor - user ?u - user ?d - directory)
    :precondition (and
      (user_exists ?u)
      (directory_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (not (home_directory ?u))
      (home_directory ?u ?d)
    )
  )

  (:action update_user_properties
    :parameters (?actor - user ?u - user ?f - file)
    :precondition (and
      (user_exists ?u)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (owner_of ?f ?u)
      (permissions_updated ?f)
    )
  )

  (:action set_non_unique_uid
    :parameters (?actor - user ?u - user ?uid - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (non_unique_uid ?u ?uid)
    )
  )

  (:action set_user_password
    :parameters (?actor - user ?u - user ?encrypted_password - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (password_set ?u)
    )
  )

  (:action unlock_user_password
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (not (user_locked ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_locked ?u))
    )
  )

  (:action change_home_directory_ownership
    :parameters (?actor - user ?f - file ?u - user)
    :precondition (and
      (user_exists ?u)
      (file_exists ?f)
      (not (traffic_blocked ?network))
      (interface_up)
      (can_escalate ?actor)
    )
    :effect (and
      (requires_env_preservation ?f)
      (member_of ?u)
    )
  )

  (:action change_file_ownership_outside_home_directory
    :parameters (?actor - user ?f - file ?u - user)
    :precondition (and
      (user_exists ?u)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (requires_env_preservation ?f)
      (member_of ?u)
    )
  )

  (:action unlock_account
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

  (:action add_subordinate_uids
    :parameters (?actor - user ?u - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uid_range_added ?u ?first ?last)
    )
  )

  (:action remove_subordinate_uids
    :parameters (?actor - user ?u - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?u)
      (subordinate_uid_range_added ?u ?first ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subordinate_uid_range_added ?u ?first ?last))
    )
  )

  (:action add_subordinate_gids
    :parameters (?actor - user ?u - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gid_range_added ?u ?first ?last)
    )
  )

  (:action remove_subordinate_gids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (subordinate_gid_range_added ?user ?first ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subordinate_gid_range_added ?user ?first ?last))
    )
  )

  (:action unset_selinux_user
    :parameters (?actor - user ?login - user)
    :precondition (and
      (user_exists ?login)
      (selinux_user_mapped ?login)
      (can_escalate ?actor)
    )
    :effect (and
      (not (selinux_user_mapped ?login))
    )
  )

  (:action change_owner_crontab_at_jobs
    :parameters (?actor - user ?f - file ?u - user)
    :precondition (and
      (file_exists ?f)
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (owner_of ?f ?u)
    )
  )

  (:action modify_nis_server
    :parameters (?actor - user ?server - interface ?u - user)
    :precondition (and
      (interface_exists ?server)
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (nis_updated ?server)
    )
  )

  (:action set_max_members_per_group
    :parameters (?actor - user ?max_num - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (max_members_per_group ?max_num)
    )
  )

  (:action modify_user
    :parameters (?actor - user ?login - user ?group - group)
    :precondition (and
      (user_exists ?login)
      (not (user_locked ?login))
      (can_escalate ?actor)
    )
    :effect (and
      (append_group ?login ?group)
    )
  )

  (:action lock_user_account
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

  (:action change_supplementary_groups
    :parameters (?actor - user ?u - user ?gs - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of ?u ?gs)
    )
  )

  (:action remove_user_from_groups
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (member_of ?u ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (not (member_of ?u ?g))
    )
  )

  (:action unlock_user_account
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

  (:action add_subuids_range
    :parameters (?actor - user ?u - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uids_added ?u ?first ?last)
    )
  )

  (:action remove_subuids_range
    :parameters (?actor - user ?u - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?u)
      (subordinate_uids_added ?u ?first ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subordinate_uids_added ?u ?first ?last))
    )
  )

  (:action add_subgids_range
    :parameters (?actor - user ?u - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gids_added ?u ?first ?last)
    )
  )

  (:action remove_subgids_range
    :parameters (?actor - user ?u - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?u)
      (subordinate_gids_added ?u ?first ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subordinate_gids_added ?u ?first ?last))
    )
  )

  (:action delete_user_account
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u))
      (not (user_locked ?u))
    )
  )

  (:action delete_user_account_forcefully
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u))
      (not (user_locked ?u))
    )
  )

  (:action remove_user
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (not (user_locked ?u))
      (not (group_exists ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u))
    )
  )

  (:action chroot_changes
    :parameters (?actor - user ?u - user ?chroot_dir - directory)
    :precondition (and
      (user_exists ?u)
      (directory_exists ?chroot_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (applied_changes_in_chroot ?u ?chroot_dir)
    )
  )

  (:action prefix_changes
    :parameters (?actor - user ?u - user ?prefix_dir - directory)
    :precondition (and
      (user_exists ?u)
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (applied_changes_in_prefix ?u ?prefix_dir)
    )
  )

  (:action remove_selinux_mapping
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (selinux_mapped ?u))
    )
  )

  (:action manage_mail_spool
    :parameters (?actor - user ?u - user ?m - file ?f - file)
    :precondition (and
      (user_exists ?u)
      (directory_exists ?m)
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_managed ?u)
    )
  )

  (:action userdel_with_command
    :parameters (?actor - user ?username - user)
    :precondition (and
      (user_exists ?username)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?username))
    )
  )

  (:action force_delete_user
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u))
    )
  )

  (:action delete_user_with_home
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u))
    )
  )

  (:action delete_selinux_mapping
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?selinux_user_mapping ?u))
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

  (:action force_add_group
    :parameters (?actor - user ?groupname - file ?gid - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?groupname)
      (gid ?groupname ?gid)
    )
  )

  (:action override_login_config
    :parameters (?actor - user ?key - file ?value - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (login_config_overridden ?key ?value)
    )
  )

  (:action set_group_password
    :parameters (?actor - user ?grp - group ?pwd - file)
    :precondition (and
      (not (user_locked ?grp))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_locked ?grp))
    )
  )

  (:action create_non_unique_group
    :parameters (?actor - user ?newgroup - group ?gid - file)
    :precondition (and
      (not (user_exists ?newgroup))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?newgroup)
    )
  )

  (:action add_group
    :parameters (?actor - user ?grp - group ?gid - file)
    :precondition (and
      (not (group_exists ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
      (gid_range_correct ?gid)
    )
  )

  (:action chroot_apply_changes
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_chroot ?dir)
    )
  )

  (:action prefix_apply_changes
    :parameters (?actor - user ?prefix_dir - directory)
    :precondition (and
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_prefix ?prefix_dir)
    )
  )

  (:action add_users_to_group
    :parameters (?actor - user ?grp - group ?users - file)
    :precondition (and
      (group_exists ?grp)
      (can_escalate ?actor)
    )
    :effect (and
      (users_added_to_group ?grp ?users)
    )
  )

  (:action set_sys_gid_range
    :parameters (?actor - user ?sys_min - file ?sys_max - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (sys_gid_range_set ?sys_min ?sys_max)
    )
  )

  (:action add_system_group
    :parameters (?actor - user ?grp - group ?gid - file)
    :precondition (and
      (not (gid_used ?gid))
      (not (group_exists ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
      (gid_used ?gid)
    )
  )

  (:action update_group_file
    :parameters (?actor - user ?grp - group ?gid - file)
    :precondition (and
      (not (can_update_group_file))
      (can_escalate ?actor)
    )
    :effect (and
      (can_update_group_file)
    )
  )

  (:action add_group_with_gid
    :parameters (?actor - user ?group - group ?gid - file)
    :precondition (and
      (not (user_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?group)
    )
  )

  (:action add_group_with_password
    :parameters (?actor - user ?group - group ?password - file)
    :precondition (and
      (not (user_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?group)
    )
  )

  (:action add_group_non_unique_gid
    :parameters (?actor - user ?group - group ?gid - file)
    :precondition (and
      (not (user_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?group)
    )
  )

  (:action add_group_force
    :parameters (?actor - user ?group - group)
    :precondition (and
      (not (user_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?group)
    )
  )

  (:action add_group_with_key_value
    :parameters (?actor - user ?group - group ?key - file ?value - file)
    :precondition (and
      (not (user_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?group)
    )
  )

  (:action add_group_with_chroot
    :parameters (?actor - user ?group - group ?chroot_dir - file)
    :precondition (and
      (not (user_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?group)
    )
  )

  (:action add_group_with_prefix
    :parameters (?actor - user ?group - group ?prefix - file)
    :precondition (and
      (not (user_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?group)
    )
  )

  (:action enable_extra_users_db
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (extrausers_enabled)
    )
  )

)