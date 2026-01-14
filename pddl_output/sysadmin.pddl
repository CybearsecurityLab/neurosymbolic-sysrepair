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
    (pending_change_exists)
    (system_ready)
    (assertion_added)
    (assertion_valid ?x0 - object)
    (signature_verified ?x0 - object)
    (assertion_in_database ?x0 - object)
    (snap_application_exists ?x0 - object)
    (alias_setup ?x0 - object)
    (snap_installed ?x0 - object)
    (plug_exists ?x0 - object ?x1 - object)
    (slot_exists ?x0 - object ?x1 - object)
    (plug_connected ?x0 - object ?x1 - object ?x2 - object)
    (plug_auto_connected ?x0 - object ?x1 - object)
    (snap_exists ?x0 - object)
    (connected ?x0 - object ?x1 - object)
    (all_snaps_exist ?x0 - object)
    (cohort_keys_created ?x0 - object)
    (query_executed)
    (home_migrated)
    (snap_in_cohort ?x0 - object ?x1 - object)
    (directory_exists ?x0 - object)
    (snap_in_development_mode ?x0 - object)
    (security_confinement_disabled ?x0 - object)
    (security_confinement_enabled ?x0 - object)
    (snap_aliases_exist ?x0 - object)
    (config_pending)
    (configuration_complete)
    (warnings_listed)
    (warnings_silenced)
    (snaps_refreshed)
    (snap_channel_switched ?x0 - object ?x1 - object)
    (change_pending ?x0 - object)
    (change_aborted ?x0 - object)
    (configured ?x0 - object ?x1 - object)
    (alias_exists ?x0 - object)
    (logged_in)
    (snapshot_exists ?x0 - object)
    (restored_from_snapshot ?x0 - object)
    (contains_snapshot ?x0 - object ?x1 - object)
    (device_exists ?x0 - object)
    (mode_available ?x0 - object)
    (current_mode ?x0 - object)
    (current_system ?x0 - object)
    (warnings_exist)
    (no_warnings)
    (command_executed ?x0 - object)
    (snap_tested ?x0 - object)
    (assertion_signed ?x0 - object)
    (device_prepared ?x0 - object)
    (key_exported ?x0 - object)
    (quota_group_exists ?x0 - object)
    (file_backup ?x0 - object)
    (file_numbered_backup ?x0 - object)
    (file_simple_backup ?x0 - object)
    (file_updated ?x0 - object)
    (file_in_directory ?x0 - object ?x1 - object)
    (file_copied ?x0 - object)
    (file_executable ?x0 - object)
    (security_context_set ?x0 - object)
    (files_updated ?x0 - object)
    (backup_created ?x0 - object)
    (version_control_set ?x0 - object)
    (file_permission_changed ?x0 - object)
    (file_permission_added ?x0 - object)
    (file_permission_removed ?x0 - object)
    (file_permission_set_exclusively ?x0 - object)
    (file_permission_set_for_users ?x0 - object)
    (is_symbolic_link ?x0 - object)
    (gid_matches_effective_or_supplementary_groups ?x0 - object ?x1 - object)
    (set_group_id_cleared ?x0 - object)
    (is_directory ?x0 - object)
    (set_user_id_bit_set ?x0 - object)
    (set_group_id_bit_set ?x0 - object)
    (restricted_deletion_flag_set ?x0 - object)
    (sticky_bit_set ?x0 - object)
    (file_mode_set ?x0 - object ?x1 - object)
    (file_mode_set_from_ref ?x0 - object ?x1 - object)
    (directory_has_mode ?x0 - object ?x1 - object)
    (files_have_mode ?x0 - object ?x1 - object)
    (file_has_mode ?x0 - object ?x1 - object ?x2 - object)
    (owned_by_user ?x0 - object ?x1 - object)
    (owned_by_group ?x0 - object ?x1 - object)
    (file_owner ?x0 - object ?x1 - object)
    (file_group ?x0 - object ?x1 - object)
    (preserve_root)
    (owned_by ?x0 - object ?x1 - object)
    (group_owned_by ?x0 - object ?x1 - object)
    (recursively_operate)
    (symlink_traversed ?x0 - object)
    (directory_mode_set ?x0 - object ?x1 - object)
    (directory_has_default_selinux_context ?x0 - object)
    (directory_has_custom_security_context ?x0 - object ?x1 - object)
    (file_access_time_updated ?x0 - object)
    (file_modification_time_updated ?x0 - object)
    (file_times_set ?x0 - object)
    (file_access_time_changed ?x0 - object)
    (file_modification_time_changed ?x0 - object)
    (symlink_access_time_changed ?x0 - object)
    (symlink_modification_time_changed ?x0 - object)
    (file_modified ?x0 - object)
    (credential_cache_enabled ?x0 - object ?x1 - object)
    (authenticated_for_sudo ?x0 - object ?x1 - object)
    (command_executed_with_privileges ?x0 - object)
    (command_executed_with_privileges_in_background ?x0 - object)
    (password_prompt_with_bell ?x0 - object)
    (password_read_with_askpass ?x0 - object)
    (cmd_exists ?x0 - object)
    (file_descriptors_closed ?x0 - object)
    (command_executed_in_directory ?x0 - object)
    (environment_preserved)
    (temporary_copies_made ?x0 - object)
    (editing_temporary_files ?x0 - object)
    (cannot_edit_unauthorized_files ?x0 - object)
    (is_symlink ?x0 - object)
    (is_device_special ?x0 - object)
    (primary_group_set ?x0 - object ?x1 - object)
    (home_set ?x0 - object)
    (command_executed_on_host ?x0 - object ?x1 - object)
    (login_shell_running ?x0 - object)
    (shell_executed ?x0 - object)
    (file_edited_by ?x0 - object ?x1 - object)
    (cmd_executed_by_group ?x0 - object ?x1 - object)
    (directory_is_writable_by_user ?x0 - object)
    (file_editing_blocked ?x0 - object)
    (symbolic_link_exists ?x0 - object)
    (link_editing_blocked ?x0 - object)
    (password_timeout_extended)
    (sudoedit_supported)
    (process_running_in_dir ?x0 - object ?x1 - object)
    (home_variable_set ?x0 - object)
    (timestamp_file_exists)
    (timestamp_file_valid)
    (process_running_in_chroot ?x0 - object)
    (selinux_enabled)
    (process_running_with_role ?x0 - object ?x1 - object)
    (selinux_context_set ?x0 - object)
    (command_terminated ?x0 - object)
    (password_read)
    (supplementary_group_of_user ?x0 - object ?x1 - object)
    (login_shell_started ?x0 - object)
    (session_has_pty ?x0 - object)
    (session_running_shell ?x0 - object ?x1 - object)
    (user_shell_set ?x0 - object ?x1 - object)
    (path_set_for_user ?x0 - object ?x1 - object)
    (fail_delay_set ?x0 - object)
    (always_set_path ?x0 - object)
    (path_initialized ?x0 - object)
    (current_user ?x0 - object)
    (primary_group ?x0 - object)
    (login_shell ?x0 - object)
    (current_shell ?x0 - object)
    (new_pty ?x0 - object)
    (default_user_updated)
    (account_expires_on ?x0 - object ?x1 - object)
    (home_directory_set ?x0 - object ?x1 - object)
    (comment_set ?x0 - object ?x1 - object)
    (password_inactive_period ?x0 - object ?x1 - object)
    (subids_updated ?x0 - object)
    (primary_group_of ?x0 - object ?x1 - object)
    (home_directory_created ?x0 - object)
    (login_def_overridden ?x0 - object ?x1 - object)
    (no_lastlog_faillog_entry ?x0 - object)
    (lastlog_reset ?x0 - object)
    (faillog_reset ?x0 - object)
    (user_in_group ?x0 - object ?x1 - object)
    (user_has_uid ?x0 - object ?x1 - object)
    (user_has_password ?x0 - object)
    (account_locked ?x0 - object)
    (user_belongs_to_group ?x0 - object ?x1 - object)
    (subuid_updated_for_user ?x0 - object)
    (subgid_updated_for_user ?x0 - object)
    (changes_applied_in_chroot_dir ?x0 - object ?x1 - object)
    (changes_applied_in_prefix_dir ?x0 - object ?x1 - object)
    (user_has_seuser ?x0 - object ?x1 - object)
    (default_base_directory_set ?x0 - object)
    (group_id_range_set ?x0 - object ?x1 - object)
    (home_mode_set ?x0 - object)
    (lastlog_uid_max_set ?x0 - object)
    (mail_spool_directory_set ?x0 - object)
    (mail_file_location_set ?x0 - object)
    (user_modified ?x0 - object)
    (max_members_per_group ?x0 - object ?x1 - object)
    (pass_max_days ?x0 - object ?x1 - object)
    (password_min_days_set ?x0 - object ?x1 - object)
    (password_warn_age_set ?x0 - object ?x1 - object)
    (subordinate_gid_range_set ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_ids_allocated ?x0 - object ?x1 - object ?x2 - object ?x3 - object)
    (default_umask_set ?x0 - object)
    (group_removed_if_empty ?x0 - object)
    (scripts_executed_during_user_addition ?x0 - object)
    (scripts_executed ?x0 - object)
    (default_user_configured)
    (badnames_allowed)
    (btrfs_subvolume_home_enabled)
    (gecos_set ?x0 - object)
    (account_expired ?x0 - object)
    (subuid_entry_added ?x0 - object ?x1 - object)
    (home_directory_exists ?x0 - object)
    (no_home_directory_created ?x0 - object)
    (no_user_group_created ?x0 - object)
    (unique_user ?x0 - object)
    (non_unique_user_created ?x0 - object)
    (groups_exist ?x0 - object)
    (supplementary_groups_set ?x0 - object ?x1 - object)
    (no_log_entry_created ?x0 - object)
    (user_has_shell ?x0 - object ?x1 - object)
    (extra_users_db_used)
    (user_comment_updated ?x0 - object)
    (user_home_changed ?x0 - object ?x1 - object)
    (user_expire_date_set ?x0 - object ?x1 - object)
    (password_grace_period_set ?x0 - object ?x1 - object)
    (password_locked ?x0 - object)
    (home_directory_moved ?x0 - object)
    (ownership_adapted ?x0 - object)
    (modes_copied ?x0 - object)
    (acl_copied ?x0 - object)
    (extended_attributes_copied ?x0 - object)
    (uid_non_unique ?x0 - object)
    (password_updated ?x0 - object)
    (password_unlocked ?x0 - object)
    (subuids_added ?x0 - object ?x1 - object ?x2 - object)
    (subgids_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gid_range_removed ?x0 - object ?x1 - object ?x2 - object)
    (selinux_user_removed ?x0 - object)
    (file_owned_by_user ?x0 - object ?x1 - object)
    (nis_user_updated ?x0 - object)
    (user_updated ?x0 - object)
    (mail_spool_exists ?x0 - object)
    (subordinate_gids_allocated ?x0 - object)
    (subordinate_uids_allocated ?x0 - object)
    (password_inactivates_on ?x0 - object ?x1 - object)
    (login_changed_to ?x0 - object ?x1 - object)
    (home_dir_moved ?x0 - object ?x1 - object)
    (duplicate_uid_allowed)
    (user_shell ?x0 - object ?x1 - object)
    (user_uid ?x0 - object ?x1 - object)
    (subordinate_uids_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_uids_removed ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gids_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gids_removed ?x0 - object ?x1 - object ?x2 - object)
    (if ?x0 - object ?x1 - object ?x2 - object ?x3 - object ?x4 - object ?x5 - object)
    (selinux_user_mapped ?x0 - object)
    (mailbox_exists ?x0 - object)
    (mailbox_modified ?x0 - object)
    (mail_spool_created ?x0 - object)
    (cron_job_exists ?x0 - object)
    (at_job_exists ?x0 - object)
    (print_job_exists ?x0 - object)
    (group_info_updated ?x0 - object)
    (login_config_updated ?x0 - object)
    (user_info_updated ?x0 - object)
    (subgid_updated ?x0 - object)
    (subuid_updated ?x0 - object)
    (selinux_user_mapping_exists ?x0 - object)
    (login_config_overridden ?x0 - object)
    (group_default_set ?x0 - object)
    (non_unique_gid_set ?x0 - object)
    (group_has_password ?x0 - object)
    (system_group_id_min_set ?x0 - object)
    (system_group_id_max_set ?x0 - object)
    (gid_available ?x0 - object)
    (system_group_added ?x0 - object)
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
      (pending_change_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (not (pending_change_exists))
    )
  )

  (:action ack_assertion
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_ready)
      (can_escalate ?actor)
    )
    :effect (and
      (assertion_added)
    )
  )

  (:action add_assertion
    :parameters (?actor - user ?assertion - file)
    :precondition (and
      (file_exists ?assertion)
      (assertion_valid ?assertion)
      (signature_verified ?assertion)
      (can_escalate ?actor)
    )
    :effect (and
      (assertion_in_database ?assertion)
    )
  )

  (:action setup_alias
    :parameters (?snap_app - file ?alias - file)
    :precondition (and
      (snap_application_exists ?snap_app)
    )
    :effect (and
      (alias_setup ?alias)
    )
  )

  (:action connect_plug_to_slot
    :parameters (?actor - user ?snap - file ?plug - file ?slot - file)
    :precondition (and
      (snap_installed ?snap)
      (plug_exists ?snap ?plug)
      (slot_exists ?snap ?slot)
      (can_escalate ?actor)
    )
    :effect (and
      (plug_connected ?snap ?plug ?slot)
    )
  )

  (:action auto_connect_plug_to_slot
    :parameters (?actor - user ?snap - file ?plug - file)
    :precondition (and
      (snap_installed ?snap)
      (plug_exists ?snap ?plug)
      (can_escalate ?actor)
    )
    :effect (and
      (plug_auto_connected ?snap ?plug)
    )
  )

  (:action connect_snap_plug
    :parameters (?actor - user ?snap - file ?plug - file ?slot - file)
    :precondition (and
      (snap_exists ?snap)
      (plug_exists ?plug)
      (slot_exists ?slot)
      (can_escalate ?actor)
    )
    :effect (and
      (connected ?plug ?slot)
    )
  )

  (:action create_cohort_keys
    :parameters (?actor - user ?snaps - file)
    :precondition (and
      (all_snaps_exist ?snaps)
      (can_escalate ?actor)
    )
    :effect (and
      (cohort_keys_created ?snaps)
    )
  )

  (:action execute_raw_query
    :parameters (?obj - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (query_executed)
    )
  )

  (:action migrate_home_directory
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (home_migrated)
    )
  )

  (:action install_from_candidate_channel
    :parameters (?actor - user ?snap - package)
    :precondition (and
      (not (package_installed ?snap))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?snap)
    )
  )

  (:action switch_cohort
    :parameters (?actor - user ?snap - package ?cohort - file)
    :precondition (and
      (package_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_in_cohort ?snap ?cohort)
    )
  )

  (:action leave_cohort
    :parameters (?actor - user ?snap - package)
    :precondition (and
      (package_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (not (snap_in_cohort ?snap))
    )
  )

  (:action install_test_snap
    :parameters (?actor - user ?package - package ?snap_dir - directory)
    :precondition (and
      (directory_exists ?snap_dir)
      (not (package_installed ?package))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?package)
    )
  )

  (:action try_no_wait
    :parameters (?actor - user ?package - package ?snap_dir - directory)
    :precondition (and
      (directory_exists ?snap_dir)
      (not (package_installed ?package))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?package)
    )
  )

  (:action set_snap_development_mode
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_in_development_mode ?snap)
      (security_confinement_disabled ?snap)
    )
  )

  (:action set_snap_enforced_confinement_mode
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (security_confinement_enabled ?snap)
      (not (snap_in_development_mode ?snap))
    )
  )

  (:action unalias_snap
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (not (snap_aliases_exist ?snap))
    )
  )

  (:action unset_snap_config
    :parameters (?actor - user ?snap - file ?config_option - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (not (configures ?snap ?config_option))
    )
  )

  (:action wait_for_configuration
    :parameters (?obj - file)
    :precondition (and
      (config_pending)
    )
    :effect (and
      (configuration_complete)
    )
  )

  (:action silence_warnings
    :parameters (?obj - file)
    :precondition (and
      (warnings_listed)
    )
    :effect (and
      (warnings_silenced)
    )
  )

  (:action refresh_snaps
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (snaps_refreshed)
    )
  )

  (:action switch_snap_channel
    :parameters (?actor - user ?snap - file ?channel - interface)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_channel_switched ?snap ?channel)
    )
  )

  (:action abort_change
    :parameters (?actor - user ?change_id - interface)
    :precondition (and
      (change_pending ?change_id)
      (can_escalate ?actor)
    )
    :effect (and
      (change_aborted ?change_id)
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

  (:action connect_plug_slot
    :parameters (?actor - user ?plug - file ?slot - file)
    :precondition (and
      (interface_exists ?plug)
      (interface_exists ?slot)
      (can_escalate ?actor)
    )
    :effect (and
      (connected ?plug ?slot)
    )
  )

  (:action disconnect_plug_slot
    :parameters (?actor - user ?plug - file ?slot - file)
    :precondition (and
      (connected ?plug ?slot)
      (can_escalate ?actor)
    )
    :effect (and
      (not (connected ?plug ?slot))
    )
  )

  (:action unset_configuration_option
    :parameters (?actor - user ?config - file ?option - file)
    :precondition (and
      (configured ?config ?option)
      (can_escalate ?actor)
    )
    :effect (and
      (not (configured ?config ?option))
    )
  )

  (:action create_alias
    :parameters (?actor - user ?alias - file ?cmd - file)
    :precondition (and
      (not (alias_exists ?alias))
      (can_escalate ?actor)
    )
    :effect (and
      (alias_exists ?alias)
    )
  )

  (:action remove_alias
    :parameters (?actor - user ?alias - file)
    :precondition (and
      (alias_exists ?alias)
      (can_escalate ?actor)
    )
    :effect (and
      (not (alias_exists ?alias))
    )
  )

  (:action login_snap_store
    :parameters (?obj - file)
    :precondition (and
      (not (logged_in))
    )
    :effect (and
      (logged_in)
    )
  )

  (:action logout_snap_store
    :parameters (?obj - file)
    :precondition (and
      (logged_in)
    )
    :effect (and
      (not (logged_in))
    )
  )

  (:action save_snapshot
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (not (snapshot_exists ?snap))
      (can_escalate ?actor)
    )
    :effect (and
      (snapshot_exists ?snap)
    )
  )

  (:action restore_snapshot
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (snapshot_exists ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (restored_from_snapshot ?snap)
    )
  )

  (:action forget_snapshot
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (snapshot_exists ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (not (snapshot_exists ?snap))
    )
  )

  (:action export_snapshot
    :parameters (?actor - user ?snap - file ?file - file)
    :precondition (and
      (snapshot_exists ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?file)
      (contains_snapshot ?file ?snap)
    )
  )

  (:action import_snapshot
    :parameters (?actor - user ?file - file ?snap - file)
    :precondition (and
      (file_exists ?file)
      (contains_snapshot ?file ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snapshot_exists ?snap)
    )
  )

  (:action reboot_device
    :parameters (?actor - user ?system - file ?mode - file)
    :precondition (and
      (device_exists ?system)
      (mode_available ?mode)
      (can_escalate ?actor)
    )
    :effect (and
      (current_mode ?mode)
      (current_system ?system)
    )
  )

  (:action okay_warnings
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (warnings_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (no_warnings)
    )
  )

  (:action download_snap
    :parameters (?snap - file)
    :precondition (and
      (not (snap_installed ?snap))
      (network_available)
    )
    :effect (and
      (snap_installed ?snap)
    )
  )

  (:action run_snap_command
    :parameters (?cmd - file ?args - file)
    :precondition (and
      (snap_installed ?cmd)
    )
    :effect (and
      (command_executed ?cmd)
    )
  )

  (:action try_snap
    :parameters (?snap - file)
    :precondition (and
      (not (snap_installed ?snap))
    )
    :effect (and
      (snap_tested ?snap)
    )
  )

  (:action sign_assertion
    :parameters (?assertion - file)
    :precondition (and
      (file_exists ?assertion)
    )
    :effect (and
      (assertion_signed ?assertion)
    )
  )

  (:action prepare_device_image
    :parameters (?image - file)
    :precondition (and
      (not (device_prepared ?image))
    )
    :effect (and
      (device_prepared ?image)
    )
  )

  (:action export_key
    :parameters (?key - file)
    :precondition (and
      (not (key_exported ?key))
    )
    :effect (and
      (key_exported ?key)
    )
  )

  (:action set_quota_group
    :parameters (?actor - user ?group - file ?size - file)
    :precondition (and
      (not (quota_group_exists ?group))
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

  (:action change_permissions
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_writable ?f)
    )
  )

  (:action backup_file
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (file_backup ?src)
    )
  )

  (:action numbered_backup_file
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (file_numbered_backup ?src)
    )
  )

  (:action simple_backup_file
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (file_simple_backup ?src)
    )
  )

  (:action update_file_if_older
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dest)
    )
    :effect (and
      (file_updated ?dest)
    )
  )

  (:action move_files_to_directory
    :parameters (?src - file ?dir - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dir)
    )
    :effect (and
      (not (file_exists ?src))
      (file_in_directory ?src ?dir)
    )
  )

  (:action move_files_to_target
    :parameters (?src - file ?dir - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dir)
    )
    :effect (and
      (not (file_exists ?src))
      (file_in_directory ?src ?dir)
    )
  )

  (:action copy_file_with_debug
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_copied ?dest)
      (file_executable ?dest)
    )
  )

  (:action copy_file_force
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_copied ?dest)
      (file_executable ?dest)
    )
  )

  (:action copy_file_interactive
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_copied ?dest)
      (file_executable ?dest)
    )
  )

  (:action copy_file_no_clobber
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (file_exists ?dest))
    )
    :effect (and
      (file_copied ?dest)
    )
  )

  (:action copy_file_no_copy_on_rename_fail
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_copied ?dest)
      (file_executable ?dest)
    )
  )

  (:action copy_file_strip_trailing_slashes
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_copied ?dest)
      (file_executable ?dest)
    )
  )

  (:action copy_file_with_suffix
    :parameters (?src - file ?dest - file ?suffix - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_copied ?dest)
      (file_executable ?dest)
    )
  )

  (:action copy_file_update
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_copied ?dest)
      (file_executable ?dest)
    )
  )

  (:action copy_file_verbose
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_copied ?dest)
      (file_executable ?dest)
    )
  )

  (:action set_security_context
    :parameters (?dest_file - file)
    :precondition (and
      (file_exists ?dest_file)
    )
    :effect (and
      (security_context_set ?dest_file)
    )
  )

  (:action update_files
    :parameters (?src - file ?dest_dir - directory)
    :precondition (and
      (directory_exists ?dest_dir)
      (file_exists ?src)
    )
    :effect (and
      (files_updated ?dest_dir)
    )
  )

  (:action create_backup
    :parameters (?file - file ?backup_suffix - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (backup_created ?file)
    )
  )

  (:action set_version_control_method
    :parameters (?method - file ?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (version_control_set ?file)
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
    :parameters (?target - file)
    :precondition (and
      (file_exists ?target)
    )
    :effect (and
      (not (file_exists ?target))
      (not (directory_exists ?target))
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
    :parameters (?f - file ?mode - file)
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

  (:action remove_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action force_remove_file
    :parameters (?f - file)
    :precondition (and
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action interactive_remove_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action interactive_remove_multiple_files
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action interactive_remove_file_with_when
    :parameters (?f - file ?when - file)
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
      (directory_exists ?dir)
    )
    :effect (and
      (not (directory_exists ?dir))
    )
  )

  (:action remove_root_directory
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (directory_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (not (directory_exists))
    )
  )

  (:action preserve_root_directory_all
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (directory_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_exists)
    )
  )

  (:action remove_hierarchy_one_file_system
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (not (directory_exists ?dir))
    )
  )

  (:action remove_with_verbose_output
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (not (file_exists ?file))
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

  (:action change_file_permissions_for_users
    :parameters (?f - file ?users - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_permission_changed ?f)
    )
  )

  (:action add_file_mode_bits
    :parameters (?f - file ?users - file ?bits - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_permission_added ?f)
    )
  )

  (:action remove_file_mode_bits
    :parameters (?f - file ?users - file ?bits - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_permission_removed ?f)
    )
  )

  (:action set_file_mode_bits_exclusively
    :parameters (?f - file ?users - file ?bits - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_permission_set_exclusively ?f)
    )
  )

  (:action set_file_mode_bits_for_users
    :parameters (?f - file ?users - file ?bits - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_permission_set_for_users ?f)
    )
  )

  (:action change_permissions_pointed_to_file
    :parameters (?link - file ?target - file)
    :precondition (and
      (file_exists ?target)
      (is_symbolic_link ?link)
    )
    :effect (and
      (file_executable ?target)
    )
  )

  (:action clear_set_group_id_bit
    :parameters (?f - file ?gid - group)
    :precondition (and
      (file_exists ?f)
      (not (gid_matches_effective_or_supplementary_groups ?f ?gid))
    )
    :effect (and
      (set_group_id_cleared ?f)
    )
  )

  (:action preserve_id_bits
    :parameters (?d - directory ?mode - file)
    :precondition (and
      (file_exists ?d)
      (is_directory ?d)
    )
    :effect (and
      (set_user_id_bit_set ?d)
      (set_group_id_bit_set ?d)
    )
  )

  (:action clear_id_bits
    :parameters (?d - directory ?mode - file)
    :precondition (and
      (file_exists ?d)
      (is_directory ?d)
    )
    :effect (and
      (not (set_user_id_bit_set ?d))
      (not (set_group_id_bit_set ?d))
    )
  )

  (:action set_restricted_deletion_flag
    :parameters (?d - directory)
    :precondition (and
      (file_exists ?d)
      (is_directory ?d)
    )
    :effect (and
      (restricted_deletion_flag_set ?d)
    )
  )

  (:action clear_restricted_deletion_flag
    :parameters (?d - directory)
    :precondition (and
      (file_exists ?d)
      (is_directory ?d)
    )
    :effect (and
      (not (restricted_deletion_flag_set ?d))
    )
  )

  (:action set_sticky_bit
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (not (is_directory ?f))
    )
    :effect (and
      (sticky_bit_set ?f)
    )
  )

  (:action clear_sticky_bit
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (not (is_directory ?f))
    )
    :effect (and
      (not (sticky_bit_set ?f))
    )
  )

  (:action change_mode
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_mode_set ?f ?mode)
    )
  )

  (:action change_mode_reference
    :parameters (?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
    )
    :effect (and
      (file_mode_set_from_ref ?f ?rfile)
    )
  )

  (:action change_permissions_recursive
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_has_mode ?dir ?mode)
      (files_have_mode ?dir ?mode)
    )
  )

  (:action change_permissions_reference
    :parameters (?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
    )
    :effect (and
      (action_completed_change_permissions_reference)
    )
  )

  (:action change_permissions_no_preserve_root
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_has_mode ?dir ?mode)
      (files_have_mode ?dir ?mode)
    )
  )

  (:action change_permissions_verbose
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_has_mode ?f ?mode)
    )
  )

  (:action change_permissions_preserve_root
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_has_mode ?dir ?mode)
      (files_have_mode ?dir ?mode)
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
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by_user ?f ?owner)
      (owned_by_group ?f ?group)
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

  (:action chown_chgrp
    :parameters (?actor - user ?f - file ?o - user ?g - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?o)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owner ?f ?o)
      (file_group ?f ?g)
    )
  )

  (:action chgrp_files
    :parameters (?actor - user ?f - file ?g - group)
    :precondition (and
      (file_exists ?f)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (file_group ?f ?g)
    )
  )

  (:action chown_files
    :parameters (?actor - user ?f - file ?o - user)
    :precondition (and
      (file_exists ?f)
      (user_exists ?o)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owner ?f ?o)
    )
  )

  (:action chown_reference
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_chown_reference)
    )
  )

  (:action disable_preserve_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (preserve_root))
    )
  )

  (:action enable_preserve_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (preserve_root)
    )
  )

  (:action change_owner_and_group
    :parameters (?actor - user ?owner - user ?group - group ?f - file)
    :precondition (and
      (user_exists ?owner)
      (group_exists ?group)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by ?f ?owner)
      (group_owned_by ?f ?group)
    )
  )

  (:action change_owner_recursive
    :parameters (?actor - user ?owner - user ?f - directory)
    :precondition (and
      (user_exists ?owner)
      (directory_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by ?f ?owner)
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
      (file_owner ?f ?owner)
      (file_group ?f ?group)
    )
  )

  (:action set_reference_ownership
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_set_reference_ownership)
    )
  )

  (:action operate_recursively
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (recursively_operate)
    )
  )

  (:action traverse_symlink
    :parameters (?dir - directory ?option - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (symlink_traversed ?dir)
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

  (:action set_default_selinux_context
    :parameters (?dir - directory)
    :precondition (and
      (not (directory_exists ?dir))
    )
    :effect (and
      (directory_has_default_selinux_context ?dir)
    )
  )

  (:action set_custom_security_context
    :parameters (?dir - directory ?ctx - file)
    :precondition (and
      (not (directory_exists ?dir))
    )
    :effect (and
      (directory_has_custom_security_context ?dir ?ctx)
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
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
    )
  )

  (:action touch_no_create
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
    )
  )

  (:action touch_access_time_only
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_access_time_updated ?f)
    )
  )

  (:action touch_modification_time_only
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_modification_time_updated ?f)
    )
  )

  (:action touch_no_dereference
    :parameters (?symlink - file)
    :precondition (and
      (not (file_exists ?symlink))
    )
    :effect (and
      (file_access_time_updated ?symlink)
      (file_modification_time_updated ?symlink)
    )
  )

  (:action touch_with_date
    :parameters (?f - file ?date_string - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
    )
  )

  (:action set_file_time_reference
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dest)
    )
    :effect (and
      (file_times_set ?dest)
    )
  )

  (:action set_file_time_stamp
    :parameters (?f - file ?stamp - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_times_set ?f)
    )
  )

  (:action set_file_access_time
    :parameters (?f - file ?time - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_times_set ?f)
    )
  )

  (:action set_file_modify_time
    :parameters (?f - file ?time - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_times_set ?f)
    )
  )

  (:action change_file_times
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_changed ?f)
      (file_modification_time_changed ?f)
    )
  )

  (:action reference_file_times
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dest)
    )
    :effect (and
      (file_access_time_changed ?dest)
      (file_modification_time_changed ?dest)
    )
  )

  (:action change_symlink_times
    :parameters (?symlink - file)
    :precondition (and
      (file_exists ?symlink)
    )
    :effect (and
      (symlink_access_time_changed ?symlink)
      (symlink_modification_time_changed ?symlink)
    )
  )

  (:action change_access_time
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_changed ?f)
    )
  )

  (:action change_modification_time
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_modification_time_changed ?f)
    )
  )

  (:action set_custom_time
    :parameters (?f - file ?stamp - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_changed ?f)
      (file_modification_time_changed ?f)
    )
  )

  (:action set_custom_date_string
    :parameters (?f - file ?date - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_changed ?f)
      (file_modification_time_changed ?f)
    )
  )

  (:action set_custom_time_word
    :parameters (?f - file ?word - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_changed ?f)
      (file_modification_time_changed ?f)
    )
  )

  (:action update_file_modification_time
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

  (:action enable_credential_caching
    :parameters (?user - user ?duration - file)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (credential_cache_enabled ?user ?duration)
    )
  )

  (:action authenticate_user_for_sudo
    :parameters (?user - user ?auth_method - file)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (authenticated_for_sudo ?user ?auth_method)
    )
  )

  (:action sudo_command
    :parameters (?cmd - file ?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (command_executed_with_privileges ?cmd)
    )
  )

  (:action sudo_background_command
    :parameters (?cmd - file ?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (command_executed_with_privileges_in_background ?cmd)
    )
  )

  (:action bell_prompt
    :parameters (?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (password_prompt_with_bell ?user)
    )
  )

  (:action askpass_password
    :parameters (?user - user ?askpass_program - file)
    :precondition (and
      (can_escalate ?user)
      (file_exists ?askpass_program)
    )
    :effect (and
      (password_read_with_askpass ?user)
    )
  )

  (:action close_file_descriptors
    :parameters (?actor - user ?num - file ?cmd - file)
    :precondition (and
      (cmd_exists ?cmd)
      (can_escalate ?actor)
    )
    :effect (and
      (file_descriptors_closed ?num)
    )
  )

  (:action run_command_in_directory
    :parameters (?actor - user ?directory - directory ?cmd - file)
    :precondition (and
      (cmd_exists ?cmd)
      (directory_exists ?directory)
      (can_escalate ?actor)
    )
    :effect (and
      (command_executed_in_directory ?directory)
    )
  )

  (:action preserve_environment_variables
    :parameters (?actor - user ?cmd - file)
    :precondition (and
      (cmd_exists ?cmd)
      (can_escalate ?actor)
    )
    :effect (and
      (environment_preserved)
    )
  )

  (:action edit_files
    :parameters (?actor - user ?files - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (temporary_copies_made ?files)
      (editing_temporary_files ?files)
    )
  )

  (:action restore_temporary_files
    :parameters (?temp_f - file ?orig_f - file)
    :precondition (and
      (file_exists ?temp_f)
      (not (file_exists ?orig_f))
    )
    :effect (and
      (file_exists ?orig_f)
    )
  )

  (:action remove_temporary_files
    :parameters (?temp_f - file)
    :precondition (and
      (file_exists ?temp_f)
    )
    :effect (and
      (not (file_exists ?temp_f))
    )
  )

  (:action restrict_file_editing
    :parameters (?f - file ?user - user)
    :precondition (and
      (file_exists ?f)
      (not (user_critical ?user))
    )
    :effect (and
      (cannot_edit_unauthorized_files ?f)
    )
  )

  (:action restrict_symbolic_link_editing
    :parameters (?link - file ?user - user)
    :precondition (and
      (is_symlink ?link)
      (not (user_critical ?user))
    )
    :effect (and
      (cannot_edit_unauthorized_files ?link)
    )
  )

  (:action restrict_device_file_editing
    :parameters (?dev - file ?user - user)
    :precondition (and
      (is_device_special ?dev)
      (not (user_critical ?user))
    )
    :effect (and
      (cannot_edit_unauthorized_files ?dev)
    )
  )

  (:action create_file_if_not_exists
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action set_primary_group
    :parameters (?actor - user ?user - user ?grp - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?grp)
      (can_escalate ?actor)
    )
    :effect (and
      (primary_group_set ?user ?grp)
    )
  )

  (:action set_home_env
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (home_set ?user)
    )
  )

  (:action run_remote_command
    :parameters (?actor - user ?host - interface ?cmd - file)
    :precondition (and
      (network_available)
      (interface_exists ?host)
      (can_escalate ?actor)
    )
    :effect (and
      (command_executed_on_host ?cmd ?host)
    )
  )

  (:action run_login_shell
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (login_shell_running ?user)
    )
  )

  (:action sudo_execute_command
    :parameters (?cmd - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
    )
    :effect (and
      (command_executed ?cmd)
    )
  )

  (:action run_shell_with_sudo
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
    )
    :effect (and
      (shell_executed ?cmd)
    )
  )

  (:action edit_file_as_user
    :parameters (?user - user ?f - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
    )
    :effect (and
      (file_edited_by ?f ?user)
    )
  )

  (:action edit_file_as_user_with_group_privileges
    :parameters (?user - user ?group - group ?f - file)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?user)
    )
    :effect (and
      (file_edited_by ?f ?user)
      (cmd_executed_by_group command ?group)
    )
  )

  (:action edit_file_in_writable_directory
    :parameters (?actor - user ?file - file ?dir - directory)
    :precondition (and
      (file_exists ?file)
      (directory_is_writable_by_user ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (file_editing_blocked ?file)
    )
  )

  (:action edit_symbolic_link
    :parameters (?actor - user ?link - file)
    :precondition (and
      (symbolic_link_exists ?link)
      (can_escalate ?actor)
    )
    :effect (and
      (link_editing_blocked ?link)
    )
  )

  (:action add_user_to_passwd_database
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action extend_password_timeout
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (not (password_timeout_extended))
      (can_escalate ?actor)
    )
    :effect (and
      (password_timeout_extended)
    )
  )

  (:action enable_sudoedit_support
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (not (sudoedit_supported))
      (can_escalate ?actor)
    )
    :effect (and
      (sudoedit_supported)
    )
  )

  (:action sudo_with_directory_change
    :parameters (?cmd - process ?dir - directory ?user - user)
    :precondition (and
      (network_available)
      (user_exists ?user)
    )
    :effect (and
      (process_running_in_dir ?cmd ?dir)
    )
  )

  (:action execute_shell_script_with_sudo
    :parameters (?script - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (file_executable ?script)
    )
    :effect (and
      (process_running script)
    )
  )

  (:action execute_command_as_user
    :parameters (?cmd - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action sudo_edit_file
    :parameters (?file - file ?user - user)
    :precondition (and
      (can_escalate ?user)
      (file_exists ?file)
    )
    :effect (and
      (file_modified ?file)
    )
  )

  (:action sudo_chdir_command
    :parameters (?cmd - file ?dir - directory ?user - user)
    :precondition (and
      (can_escalate ?user)
      (directory_exists ?dir)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action sudo_preserve_env_command
    :parameters (?cmd - file ?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action sudo_set_home_command
    :parameters (?cmd - file ?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (process_running ?cmd)
      (home_variable_set ?user)
    )
  )

  (:action sudo_group_command
    :parameters (?cmd - file ?user - user ?grp - group)
    :precondition (and
      (can_escalate ?user)
      (group_exists ?grp)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action remove_timestamp_file
    :parameters (?obj - file)
    :precondition (and
      (timestamp_file_exists)
    )
    :effect (and
      (not (timestamp_file_exists))
    )
  )

  (:action reset_timestamp_file
    :parameters (?obj - file)
    :precondition (and
      (timestamp_file_exists)
    )
    :effect (and
      (not (timestamp_file_valid))
    )
  )

  (:action chroot_directory
    :parameters (?actor - user ?dir - directory ?cmd - file)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (process_running_in_chroot ?cmd)
    )
  )

  (:action set_selinux_role
    :parameters (?actor - user ?role - file ?cmd - file)
    :precondition (and
      (selinux_enabled)
      (can_escalate ?actor)
    )
    :effect (and
      (process_running_with_role ?cmd ?role)
    )
  )

  (:action run_shell_as_user
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action run_command_as_user
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action set_selinux_context
    :parameters (?actor - user ?f - file ?selinux_type - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_context_set ?f)
    )
  )

  (:action set_command_timeout
    :parameters (?cmd - file ?timeout - file)
    :precondition (and
      (process_running ?cmd)
    )
    :effect (and
      (command_terminated ?cmd)
    )
  )

  (:action read_password_stdin
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (password_read)
    )
  )

  (:action configure_pam_for_su
    :parameters (?actor - user ?config - file ?svc - service)
    :precondition (and
      (file_exists ?config)
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (configures ?config ?svc)
    )
  )

  (:action run_privileged_user_command
    :parameters (?cmd - file ?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action execute_command_with_su
    :parameters (?cmd - file ?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action add_supplementary_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (supplementary_group_of_user ?user ?group)
    )
  )

  (:action start_login_shell
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (login_shell_started ?user)
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

  (:action create_pseudo_terminal
    :parameters (?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (session_has_pty ?user)
    )
  )

  (:action run_specified_shell
    :parameters (?shell - file ?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (session_running_shell ?user ?shell)
    )
  )

  (:action set_shell
    :parameters (?actor - user ?user - user ?shell - file)
    :precondition (and
      (user_exists ?user)
      (file_executable ?shell)
      (can_escalate ?actor)
    )
    :effect (and
      (user_shell_set ?user ?shell)
    )
  )

  (:action execute_session_command
    :parameters (?cmd - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (command_executed ?cmd)
    )
  )

  (:action set_path_for_user
    :parameters (?user - user ?path - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (path_set_for_user ?user ?path)
    )
  )

  (:action set_fail_delay
    :parameters (?actor - user ?delay - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (fail_delay_set ?delay)
    )
  )

  (:action set_always_set_path
    :parameters (?actor - user ?setting - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (always_set_path ?setting)
    )
  )

  (:action initialize_path
    :parameters (?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (path_initialized ?user)
    )
  )

  (:action switch_user
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (can_escalate ?user)
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (current_user ?user)
      (primary_group ?group)
    )
  )

  (:action switch_to_login_shell
    :parameters (?actor - user ?user - user)
    :precondition (and
      (can_escalate ?user)
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (current_user ?user)
      (login_shell true)
    )
  )

  (:action switch_shell_as_user
    :parameters (?actor - user ?user - user ?shell - file)
    :precondition (and
      (can_escalate ?user)
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (current_user ?user)
      (current_shell ?shell)
    )
  )

  (:action switch_with_pty
    :parameters (?actor - user ?user - user)
    :precondition (and
      (can_escalate ?user)
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (current_user ?user)
      (new_pty true)
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

  (:action add_user
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action update_default_user_info
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (default_user_updated)
    )
  )

  (:action expire_user_account
    :parameters (?actor - user ?user - user ?expire_date - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (account_expires_on ?user ?expire_date)
    )
  )

  (:action set_home_directory
    :parameters (?actor - user ?user - user ?home_dir - directory)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_set ?user ?home_dir)
    )
  )

  (:action set_user_comment
    :parameters (?actor - user ?user - user ?comment - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (comment_set ?user ?comment)
    )
  )

  (:action set_password_inactivity_period
    :parameters (?actor - user ?usr - user ?inactive - file)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (password_inactive_period ?usr ?inactive)
    )
  )

  (:action update_subuids_for_system_account
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (subids_updated ?usr)
    )
  )

  (:action set_primary_group_for_user
    :parameters (?actor - user ?usr - user ?grp - group)
    :precondition (and
      (user_exists ?usr)
      (group_exists ?grp)
      (can_escalate ?actor)
    )
    :effect (and
      (primary_group_of ?usr ?grp)
    )
  )

  (:action create_group_for_user
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (not (group_exists ?usr))
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?usr)
      (primary_group_of ?usr ?usr)
    )
  )

  (:action set_primary_group_for_new_user
    :parameters (?actor - user ?usr - user ?gid - group)
    :precondition (and
      (not (user_exists ?usr))
      (group_exists ?gid)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?usr)
      (primary_group_of ?usr ?gid)
    )
  )

  (:action set_default_primary_group_for_new_user
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (not (user_exists ?usr))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?usr)
      (primary_group_of ?usr obj_100)
    )
  )

  (:action create_user_with_home
    :parameters (?actor - user ?u - user ?skel_dir - directory)
    :precondition (and
      (not (user_exists ?u))
      (directory_exists ?skel_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (home_directory_created ?u)
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
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (no_lastlog_faillog_entry ?u)
    )
  )

  (:action reset_user_entries
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (lastlog_reset ?u)
      (faillog_reset ?u)
    )
  )

  (:action create_home_directory
    :parameters (?actor - user ?u - user ?h - directory)
    :precondition (and
      (user_exists ?u)
      (not (directory_exists ?h))
      (can_escalate ?actor)
    )
    :effect (and
      (directory_exists ?h)
    )
  )

  (:action no_create_home_directory
    :parameters (?actor - user ?u - user ?h - directory)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (directory_exists ?h))
    )
  )

  (:action add_user_no_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (not (user_exists ?user))
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (user_in_group ?user ?group)
    )
  )

  (:action add_user_non_unique_uid
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (user_has_uid ?user ?uid)
    )
  )

  (:action set_initial_password
    :parameters (?actor - user ?user - user ?password - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_password ?user)
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
      (account_locked ?user)
    )
  )

  (:action create_system_account_with_home_directory
    :parameters (?actor - user ?user - user ?group - group ?dir - directory)
    :precondition (and
      (not (user_exists ?user))
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (directory_exists ?dir)
      (user_belongs_to_group ?user ?group)
    )
  )

  (:action create_system_account_with_home_directory_and_update_subuids
    :parameters (?actor - user ?user - user ?group - group ?dir - directory)
    :precondition (and
      (not (user_exists ?user))
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (directory_exists ?dir)
      (user_belongs_to_group ?user ?group)
      (subuid_updated_for_user ?user)
      (subgid_updated_for_user ?user)
    )
  )

  (:action apply_changes_in_chroot_dir
    :parameters (?actor - user ?chroot_dir - directory ?cmd - file)
    :precondition (and
      (directory_exists ?chroot_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_chroot_dir ?cmd ?chroot_dir)
    )
  )

  (:action apply_changes_to_config_files_under_prefix_dir
    :parameters (?actor - user ?prefix_dir - directory ?cmd - file)
    :precondition (and
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_prefix_dir ?cmd ?prefix_dir)
    )
  )

  (:action set_user_shell
    :parameters (?user - user ?shell - file)
    :precondition (and
      (user_exists ?user)
      (file_exists ?shell)
    )
    :effect (and
      (user_shell_set ?user ?shell)
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
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (user_has_uid ?user ?uid)
    )
  )

  (:action set_selinux_user
    :parameters (?actor - user ?user - user ?seuser - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (user_has_seuser ?user ?seuser)
    )
  )

  (:action update_default_user_values
    :parameters (?actor - user ?base_dir - directory ?username - user)
    :precondition (and
      (can_escalate ?username)
      (can_escalate ?actor)
    )
    :effect (and
      (default_base_directory_set ?base_dir)
      (user_exists ?username)
    )
  )

  (:action set_home_directory_permissions
    :parameters (?actor - user ?dir - directory ?user - user)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_mode_set ?dir mode)
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

  (:action set_group_id_range
    :parameters (?actor - user ?min - file ?max - file)
    :precondition (and
      (not (group_id_range_set ?min ?max))
      (can_escalate ?actor)
    )
    :effect (and
      (group_id_range_set ?min ?max)
    )
  )

  (:action set_home_directory_mode
    :parameters (?actor - user ?mode - file)
    :precondition (and
      (not (home_mode_set ?mode))
      (can_escalate ?actor)
    )
    :effect (and
      (home_mode_set ?mode)
    )
  )

  (:action set_lastlog_uid_max
    :parameters (?actor - user ?max_id - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (lastlog_uid_max_set ?max_id)
    )
  )

  (:action set_mail_spool_directory
    :parameters (?actor - user ?dir - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_directory_set ?dir)
    )
  )

  (:action set_mail_file_location
    :parameters (?actor - user ?file - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (mail_file_location_set ?file)
    )
  )

  (:action modify_user
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (user_modified ?usr)
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

  (:action set_max_members_per_group
    :parameters (?actor - user ?grp - group ?max - file)
    :precondition (and
      (group_exists ?grp)
      (can_escalate ?actor)
    )
    :effect (and
      (max_members_per_group ?grp ?max)
    )
  )

  (:action set_pass_max_days
    :parameters (?actor - user ?usr - user ?max - file)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (pass_max_days ?usr ?max)
    )
  )

  (:action set_pass_min_days
    :parameters (?actor - user ?days - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_min_days_set ?user ?days)
    )
  )

  (:action set_pass_warn_age
    :parameters (?actor - user ?warn_days - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_warn_age_set ?user ?warn_days)
    )
  )

  (:action set_sub_gid_range
    :parameters (?actor - user ?min - file ?max - file ?count - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gid_range_set ?min ?max ?count)
    )
  )

  (:action create_user_with_subordinate_ids
    :parameters (?actor - user ?user - user ?sub_uid_min - file ?sub_uid_max - file ?sub_uid_count - file)
    :precondition (and
      (not (user_exists ?user))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (subordinate_ids_allocated ?user ?sub_uid_min ?sub_uid_max ?sub_uid_count)
    )
  )

  (:action create_system_group
    :parameters (?actor - user ?group - group ?sys_gid_min - file ?sys_gid_max - file)
    :precondition (and
      (not (group_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
    )
  )

  (:action create_system_user
    :parameters (?actor - user ?user - user ?sys_uid_min - file ?sys_uid_max - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action create_regular_user
    :parameters (?actor - user ?user - user ?uid_min - file ?uid_max - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action set_default_umask
    :parameters (?actor - user ?umask - file ?user - file)
    :precondition (and
      (can_escalate ?user)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (default_umask_set ?umask)
    )
  )

  (:action remove_user_group_if_empty
    :parameters (?actor - user ?user - file ?group - file)
    :precondition (and
      (can_escalate ?user)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (group_removed_if_empty ?group)
    )
  )

  (:action create_user_group
    :parameters (?actor - user ?user - file)
    :precondition (and
      (can_escalate ?user)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?user)
    )
  )

  (:action execute_user_addition_scripts
    :parameters (?actor - user ?user - file ?script - file)
    :precondition (and
      (can_escalate ?user)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (scripts_executed_during_user_addition ?script)
    )
  )

  (:action execute_pre_user_scripts
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (scripts_executed pre)
    )
  )

  (:action execute_post_user_scripts
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (scripts_executed post)
    )
  )

  (:action configure_default_user_settings
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (default_user_configured)
    )
  )

  (:action allow_bad_names
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (badnames_allowed)
    )
  )

  (:action set_base_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (not (directory_exists ?dir))
      (can_escalate ?actor)
    )
    :effect (and
      (directory_exists ?dir)
    )
  )

  (:action use_btrfs_subvolume_home
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (btrfs_subvolume_home_enabled)
    )
  )

  (:action set_gecos_field
    :parameters (?actor - user ?login - user ?comment - file)
    :precondition (and
      (user_exists ?login)
      (can_escalate ?actor)
    )
    :effect (and
      (gecos_set ?login)
    )
  )

  (:action set_account_expiration_date
    :parameters (?actor - user ?login - user ?date - file)
    :precondition (and
      (user_exists ?login)
      (can_escalate ?actor)
    )
    :effect (and
      (account_expired ?login)
    )
  )

  (:action add_subuids_for_system_user
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_entry_added ?user ?group)
    )
  )

  (:action skip_home_directory_creation
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (home_directory_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (no_home_directory_created ?user)
    )
  )

  (:action skip_user_group_creation
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (group_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (no_user_group_created ?user)
    )
  )

  (:action create_duplicate_users
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (not (unique_user ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (non_unique_user_created ?user)
    )
  )

  (:action set_supplementary_groups
    :parameters (?actor - user ?user - user ?groups - file)
    :precondition (and
      (user_exists ?user)
      (groups_exist ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (supplementary_groups_set ?user ?groups)
    )
  )

  (:action skip_log_init
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (logged_in ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (no_log_entry_created ?user)
    )
  )

  (:action create_group_with_same_name_as_user
    :parameters (?actor - user ?group - group ?user - user)
    :precondition (and
      (not (group_exists ?group))
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
      (depends_on ?user ?group)
    )
  )

  (:action set_login_shell
    :parameters (?user - user ?shell - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (user_has_shell ?user ?shell)
    )
  )

  (:action set_encrypted_password
    :parameters (?actor - user ?user - user ?password - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_password ?user)
    )
  )

  (:action set_user_uid
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (user_exists ?user)
      (not (user_has_uid ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_uid ?user)
    )
  )

  (:action set_selinux_user_mapping
    :parameters (?actor - user ?user - user ?seuser - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_seuser ?user)
    )
  )

  (:action use_extra_users_database
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (extra_users_db_used)
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
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_modified ?user)
    )
  )

  (:action update_user_comment
    :parameters (?actor - user ?user - user ?comment - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_comment_updated ?user)
    )
  )

  (:action change_user_home_directory
    :parameters (?actor - user ?user - user ?new_dir - directory)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_home_changed ?user ?new_dir)
    )
  )

  (:action set_user_expire_date
    :parameters (?actor - user ?user - user ?expire_date - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_expire_date_set ?user ?expire_date)
    )
  )

  (:action set_password_grace_period
    :parameters (?actor - user ?user - user ?inactive_days - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_grace_period_set ?user ?inactive_days)
    )
  )

  (:action append_user_to_group
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

  (:action rename_user
    :parameters (?actor - user ?old_login - user ?new_login - user)
    :precondition (and
      (user_exists ?old_login)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?old_login))
      (user_exists ?new_login)
    )
  )

  (:action lock_user_password
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_locked ?user)
    )
  )

  (:action move_user_home_directory
    :parameters (?actor - user ?user - user ?new_home - directory)
    :precondition (and
      (user_exists ?user)
      (not (directory_exists ?new_home))
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_moved ?user)
    )
  )

  (:action modify_user_properties
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (ownership_adapted ?u)
      (modes_copied ?u)
      (acl_copied ?u)
      (extended_attributes_copied ?u)
    )
  )

  (:action set_non_unique_uid
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (uid_non_unique ?u)
    )
  )

  (:action set_user_password
    :parameters (?actor - user ?u - user ?p - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (password_updated ?u)
    )
  )

  (:action unlock_password
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_unlocked ?user)
    )
  )

  (:action add_subordinate_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subuids_added ?user ?first ?last)
    )
  )

  (:action remove_subordinate_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (subuids_added ?user ?first ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subuids_added ?user ?first ?last))
    )
  )

  (:action add_subordinate_gids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subgids_added ?user ?first ?last)
    )
  )

  (:action remove_subordinate_gids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gid_range_removed ?user ?first ?last)
    )
  )

  (:action remove_selinux_user_mapping
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_user_removed ?user)
    )
  )

  (:action change_owner_crontab_at_jobs
    :parameters (?actor - user ?owner - user ?file - file)
    :precondition (and
      (user_exists ?owner)
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by_user ?file ?owner)
    )
  )

  (:action update_nis_server
    :parameters (?actor - user ?user - user ?nis_server - interface)
    :precondition (and
      (user_exists ?user)
      (interface_exists ?nis_server)
      (can_escalate ?actor)
    )
    :effect (and
      (nis_user_updated ?user)
    )
  )

  (:action update_user_info
    :parameters (?actor - user ?old_user - user ?new_user - user)
    :precondition (and
      (user_exists ?old_user)
      (not (service_running ?old_user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_updated ?new_user)
    )
  )

  (:action create_mail_spool
    :parameters (?actor - user ?user - user ?dir - directory)
    :precondition (and
      (user_exists ?user)
      (not (mail_spool_exists ?dir))
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_exists ?dir)
    )
  )

  (:action delete_mail_spool
    :parameters (?actor - user ?user - user ?dir - directory)
    :precondition (and
      (mail_spool_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (not (mail_spool_exists ?dir))
    )
  )

  (:action remove_user_from_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_in_group ?user ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_in_group ?user ?group))
    )
  )

  (:action allocate_subordinate_group_ids
    :parameters (?actor - user ?user - user ?gid_min - file ?gid_max - file ?gid_count - file)
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
    :parameters (?actor - user ?user - user ?uid_min - file ?uid_max - file ?uid_count - file)
    :precondition (and
      (not (subordinate_uids_allocated ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uids_allocated ?user)
    )
  )

  (:action set_password_inactive_after_expiration
    :parameters (?actor - user ?u - user ?inactive - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (password_inactivates_on ?u ?inactive)
    )
  )

  (:action change_login_name
    :parameters (?actor - user ?u - user ?newlogin - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (login_changed_to ?u ?newlogin)
    )
  )

  (:action lock_user_account
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (account_locked ?u)
    )
  )

  (:action move_home_directory_contents
    :parameters (?actor - user ?u - user ?dir - directory)
    :precondition (and
      (user_exists ?u)
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (home_dir_moved ?u ?dir)
    )
  )

  (:action allow_duplicate_uid
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (duplicate_uid_allowed)
    )
  )

  (:action remove_user_from_groups
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

  (:action change_user_shell
    :parameters (?actor - user ?user - user ?shell - file)
    :precondition (and
      (user_exists ?user)
      (file_executable ?shell)
      (can_escalate ?actor)
    )
    :effect (and
      (user_shell ?user ?shell)
    )
  )

  (:action change_user_uid
    :parameters (?actor - user ?user - user ?new_uid - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_uid ?user ?new_uid)
    )
  )

  (:action unlock_user_account
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (account_locked ?user))
    )
  )

  (:action add_subordinate_uids_range
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uids_added ?user ?first ?last)
    )
  )

  (:action remove_subordinate_uids_range
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uids_removed ?user ?first ?last)
    )
  )

  (:action add_subordinate_gids_range
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gids_added ?user ?first ?last)
    )
  )

  (:action remove_subordinate_gids_range
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gids_removed ?user ?first ?last)
    )
  )

  (:action delete_user_account
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
      (not (user_critical ?user))
    )
  )

  (:action remove_user
    :parameters (?actor - user ?usr - user ?grp - group)
    :precondition (and
      (user_exists ?usr)
      (not (user_critical ?usr))
      (can_escalate ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?usr))
    )
  )

  (:action remove_user_files_and_home
    :parameters (?actor - user ?usr - user ?grp - group)
    :precondition (and
      (user_exists ?usr)
      (not (user_critical ?usr))
      (can_escalate ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?usr))
    )
  )

  (:action chroot_apply_changes
    :parameters (?actor - user ?dir - directory ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (configures dir ?usr)
    )
  )

  (:action prefix_apply_changes
    :parameters (?actor - user ?dir - directory ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (configures dir ?usr)
    )
  )

  (:action remove_selinux_mapping
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (selinux_user_mapped ?user))
    )
  )

  (:action manage_mailbox
    :parameters (?mail - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (mailbox_exists ?mail)
    )
    :effect (and
      (mailbox_modified ?mail)
    )
  )

  (:action manage_mail_spool
    :parameters (?user - user ?mail - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (mail_spool_created ?mail)
      (not (mail_spool_exists ?mail))
    )
  )

  (:action userdel_with_command
    :parameters (?actor - user ?usr - user ?cmd - file)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?usr))
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

  (:action manage_user_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_in_group ?user ?group))
      (not (group_exists ?group))
    )
  )

  (:action update_group_file
    :parameters (?actor - user ?file - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (group_info_updated ?file)
    )
  )

  (:action update_login_defs
    :parameters (?actor - user ?file - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (login_config_updated ?file)
    )
  )

  (:action update_passwd_file
    :parameters (?actor - user ?file - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (user_info_updated ?file)
    )
  )

  (:action run_pre_delete_scripts
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (scripts_executed ?u)
    )
  )

  (:action run_post_delete_scripts
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (scripts_executed ?u)
    )
  )

  (:action update_subgid_file
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (subgid_updated ?u)
    )
  )

  (:action update_subuid_file
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_updated ?u)
    )
  )

  (:action delete_user_group
    :parameters (?actor - user ?grp - group ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (group_exists ?grp)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?grp))
    )
  )

  (:action terminate_user_processes
    :parameters (?actor - user ?proc - process ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (process_running ?proc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?proc))
    )
  )

  (:action delete_user_force
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u))
    )
  )

  (:action delete_user_selinux_mapping
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (selinux_user_mapping_exists ?u))
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

  (:action force_add_group
    :parameters (?actor - user ?groupname - file ?gid - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?groupname)
    )
  )

  (:action override_login_config
    :parameters (?actor - user ?key - file ?value - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (login_config_overridden ?key)
    )
  )

  (:action set_group_defaults
    :parameters (?actor - user ?gid_min - file ?gid_max - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_default_set ?gid_min)
      (group_default_set ?gid_max)
    )
  )

  (:action create_non_unique_group
    :parameters (?actor - user ?group - group ?gid - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
      (non_unique_gid_set ?gid)
    )
  )

  (:action set_group_password
    :parameters (?actor - user ?group - group ?password - file)
    :precondition (and
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (group_has_password ?group)
    )
  )

  (:action set_system_group_id_range
    :parameters (?actor - user ?sys_min - file ?sys_max - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_group_id_min_set ?sys_min)
      (system_group_id_max_set ?sys_max)
    )
  )

  (:action add_system_group
    :parameters (?actor - user ?group - group ?gid - file)
    :precondition (and
      (not (group_exists ?group))
      (gid_available ?gid)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
      (system_group_added ?group)
    )
  )

  (:action create_group_force
    :parameters (?actor - user ?grp - group)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

  (:action create_group_with_gid
    :parameters (?actor - user ?grp - group ?gid - file)
    :precondition (and
      (not (group_exists ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

  (:action create_group_non_unique
    :parameters (?actor - user ?grp - group ?gid - file)
    :precondition (and
      (not (group_exists ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

  (:action create_group_with_prefix
    :parameters (?actor - user ?grp - group ?prefix_dir - directory)
    :precondition (and
      (not (group_exists ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

  (:action create_group_chroot
    :parameters (?actor - user ?grp - group ?chroot_dir - directory)
    :precondition (and
      (not (group_exists ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

)