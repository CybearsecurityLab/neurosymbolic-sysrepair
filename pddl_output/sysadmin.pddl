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
  )
    ; Dynamically Discovered Predicates
    (snap_channel_switched ?x - object ?y - object)
    (user_no_longer_has_subgids ?x - object ?y - object)
    (alias_created ?x - object ?y - object)
    (group_not_created ?x - object ?y - object)
    (defs_not_set ?x - object ?y - object)
    (unit_enabled ?x - object ?y - object)
    (self_terminated ?x - object ?y - object)
    (package_cleaned ?x - object ?y - object)
    (journal_files_removed ?x - object ?y - object)
    (unavailable_packages_forgetten ?x - object ?y - object)
    (jobs_canceled ?x - object ?y - object)
    (snap_config_unset ?x - object ?y - object)
    (new_directory_exists ?x - object ?y - object)
    (SYS_GID_MAX ?x - object ?y - object)
    (package_selections_cleared ?x - object ?y - object)
    (file_downloaded ?x - object ?y - object)
    (network_link_configured ?x - object ?y - object)
    (nis_config_modified ?x - object ?y - object)
    (alias_removed ?x - object ?y - object)
    (process_running ?x - object ?y - object)
    (directory_preserves_permissions ?x - object ?y - object)
    (root_not_preserved ?x - object ?y - object)
    (minimum_password_change_interval_set ?x - object ?y - object)
    (user_allocated_subordinate_uids ?x - object ?y - object)
    (pending_change ?x - object ?y - object)
    (logging_stopped ?x - object ?y - object)
    (cron_jobs_removed ?x - object ?y - object)
    (file_copied ?x - object ?y - object)
    (new_package_versions_available ?x - object ?y - object)
    (overwrite_not_prompted ?x - object ?y - object)
    (socket_exists ?x - object ?y - object)
    (file_followed ?x - object ?y - object)
    (port_valid ?x - object ?y - object)
    (group_allocated_system_gid ?x - object ?y - object)
    (directory_restricted_deletion ?x - object ?y - object)
    (home_directory_created ?x - object ?y - object)
    (user_account_modified_or_deleted ?x - object ?y - object)
    (firmware_setup ?x - object ?y - object)
    (file_moved ?x - object ?y - object)
    (home_dir_exists ?x - object ?y - object)
    (package_held ?x - object ?y - object)
    (subuids_assigned ?x - object ?y - object)
    (boot_loader_entry ?x - object ?y - object)
    (recursive_operation_failed ?x - object ?y - object)
    (file_removed ?x - object ?y - object)
    (system_powered_off ?x - object ?y - object)
    (set_of_snaps ?x - object ?y - object)
    (package_recorded ?x - object ?y - object)
    (package_autoremoved ?x - object ?y - object)
    (config_options_unset ?x - object ?y - object)
    (interface_exists ?x - object ?y - object)
    (proper_permissions ?x - object ?y - object)
    (rlimit_rtprio ?x - object ?y - object)
    (host_syntax_modified ?x - object ?y - object)
    (dir_empty ?x - object ?y - object)
    (journal_directory_changed ?x - object ?y - object)
    (package_downloaded ?x - object ?y - object)
    (package_autocleaned ?x - object ?y - object)
    (sources_list_valid ?x - object ?y - object)
    (journal_access_granted ?x - object ?y - object)
    (uid_valid ?x - object ?y - object)
    (image_exists ?x - object ?y - object)
    (unit_file_modified ?x - object ?y - object)
    (new_group_set ?x - object ?y - object)
    (package_list_updated ?x - object ?y - object)
    (subuser_ids_set ?x - object ?y - object)
    (unit_edited ?x - object ?y - object)
    (file_sticky_bit ?x - object ?y - object)
    (child_terminated ?x - object ?y - object)
    (unique_names_not_required ?x - object ?y - object)
    (snap_in_development_mode ?x - object ?y - object)
    (file_writable ?x - object ?y - object)
    (secure_user_info_modified ?x - object ?y - object)
    (verbose_mode_set ?x - object ?y - object)
    (available_packages_info_updated ?x - object ?y - object)
    (journal_messages_synced ?x - object ?y - object)
    (repository_added ?x - object ?y - object)
    (connection_established ?x - object ?y - object)
    (lastlog_entries_updated ?x - object ?y - object)
    (subgroup_ids_set ?x - object ?y - object)
    (disk_usage_reduced ?x - object ?y - object)
    (mail_spool_removed ?x - object ?y - object)
    (subgid_range_valid ?x - object ?y - object)
    (network_link_exists ?x - object ?y - object)
    (port_allowed ?x - object ?y - object)
    (usergroups_enabled ?x - object ?y - object)
    (user_modified ?x - object ?y - object)
    (file_accessed ?x - object ?y - object)
    (file_owned_by ?x - object ?y - object)
    (file_attribute_set ?x - object ?y - object)
    (user_not_executing_processes ?x - object ?y - object)
    (package_removed ?x - object ?y - object)
    (system_rebooted ?x - object ?y - object)
    (file_modification_time_updated ?x - object ?y - object)
    (system_user ?x - object ?y - object)
    (user_account_expired ?x - object ?y - object)
    (group_member ?x - object ?y - object)
    (package_upgraded ?x - object ?y - object)
    (file_executable ?x - object ?y - object)
    (password_policy_respected ?x - object ?y - object)
    (file_linked ?x - object ?y - object)
    (shell_passes_cmd ?x - object ?y - object)
    (proper_selinux_context ?x - object ?y - object)
    (output_format_set ?x - object ?y - object)
    (at_jobs_removed ?x - object ?y - object)
    (unicode_enabled ?x - object ?y - object)
    (user_changed ?x - object ?y - object)
    (match ?x - object ?y - object)
    (home_directory_not_created ?x - object ?y - object)
    (file ?x - object ?y - object)
    (manager_reloaded ?x - object ?y - object)
    (rlimit_nice ?x - object ?y - object)
    (package_version_set ?x - object ?y - object)
    (system_suspended ?x - object ?y - object)
    (GID_MIN ?x - object ?y - object)
    (interface_up ?x - object ?y - object)
    (sparse_files_inhibited ?x - object ?y - object)
    (option_exists ?x - object ?y - object)
    (file_renamed ?x - object ?y - object)
    (user_exists ?x - object ?y - object)
    (pseudo_terminal_enabled ?x - object ?y - object)
    (password_expiration_limit_set ?x - object ?y - object)
    (file_system_matches ?x - object ?y - object)
    (state_allocated ?x - object ?y - object)
    (user_has_subgids ?x - object ?y - object)
    (group_password_set ?x - object ?y - object)
    (unit_exists ?x - object ?y - object)
    (files_to_update ?x - object ?y - object)
    (journal_output_modified ?x - object ?y - object)
    (unit_running ?x - object ?y - object)
    (reflink_option_specified ?x - object ?y - object)
    (protocol_family_set ?x - object ?y - object)
    (member_of ?x - object ?y - object)
    (dir_exists ?x - object ?y - object)
    (file_persisted ?x - object ?y - object)
    (package_configured ?x - object ?y - object)
    (package_exists ?x - object ?y - object)
    (socket_closed ?x - object ?y - object)
    (subgid_updated ?x - object ?y - object)
    (log_level_set ?x - object ?y - object)
    (crontab_files_present ?x - object ?y - object)
    (eq ?x - object ?y - object)
    (user_removed ?x - object ?y - object)
    (max_members_per_group ?x - object ?y - object)
    (user_info_modified ?x - object ?y - object)
    (option_set ?x - object ?y - object)
    (process_exited ?x - object ?y - object)
    (configuration_variables_set ?x - object ?y - object)
    (subids_added ?x - object ?y - object)
    (dependency_exists ?x - object ?y - object)
    (symbolic_link ?x - object ?y - object)
    (rlimit_nofile ?x - object ?y - object)
    (filesystem_mounted ?x - object ?y - object)
    (cohort_keys_created ?x - object ?y - object)
    (system_hibernated_and_suspended ?x - object ?y - object)
    (single_line_output ?x - object ?y - object)
    (group_entry_split ?x - object ?y - object)
    (time_valid ?x - object ?y - object)
    (fast_mode ?x - object ?y - object)
    (file_not_overwritten ?x - object ?y - object)
    (wide_output_enabled ?x - object ?y - object)
    (numeric_host_addresses_enabled ?x - object ?y - object)
    (unit_file_exists ?x - object ?y - object)
    (systemd_running ?x - object ?y - object)
    (subuid_updated ?x - object ?y - object)
    (files_updated ?x - object ?y - object)
    (snap_running ?x - object ?y - object)
    (channel_available ?x - object ?y - object)
    (repository_configured ?x - object ?y - object)
    (package_installed ?x - object ?y - object)
    (file_updated ?x - object ?y - object)
    (unique_names_required ?x - object ?y - object)
    (shell_set ?x - object ?y - object)
    (default_target ?x - object ?y - object)
    (no_password_defined ?x - object ?y - object)
    (snap_config_valid ?x - object ?y - object)
    (backup_suffix_set ?x - object ?y - object)
    (no ?x - object ?y - object)
    (group_exists ?x - object ?y - object)
    (session_running ?x - object ?y - object)
    (user_allocated_system_uids ?x - object ?y - object)
    (system_hibernated ?x - object ?y - object)
    (assertion_added ?x - object ?y - object)
    (new_owner_set ?x - object ?y - object)
    (units_loaded ?x - object ?y - object)
    (operation_specified ?x - object ?y - object)
    (plug_exists ?x - object ?y - object)
    (journal_flushed ?x - object ?y - object)
    (mail_dir_updated ?x - object ?y - object)
    (file_attributes_equal ?x - object ?y - object)
    (file_sparse ?x - object ?y - object)
    (file_contents_equal ?x - object ?y - object)
    (executed_as_root ?x - object ?y - object)
    (image_policy_set ?x - object ?y - object)
    (journal_source_modified ?x - object ?y - object)
    (setting_changed ?x - object ?y - object)
    (is_source_archive ?x - object ?y - object)
    (files_unpacked ?x - object ?y - object)
    (user_account_inactive ?x - object ?y - object)
    (directory_created ?x - object ?y - object)
    (read_only_bind_mount_created ?x - object ?y - object)
    (service_enabled ?x - object ?y - object)
    (nis_server_present ?x - object ?y - object)
    (file_access_time_updated ?x - object ?y - object)
    (umask_set ?x - object ?y - object)
    (slot_exists ?x - object ?y - object)
    (account_created ?x - object ?y - object)
    (root_filesystem_changed ?x - object ?y - object)
    (user_in_group ?x - object ?y - object)
    (user_mapped_to_seuser ?x - object ?y - object)
    (change_aborted ?x - object ?y - object)
    (config_read ?x - object ?y - object)
    (snap_removed ?x - object ?y - object)
    (service_running ?x - object ?y - object)
    (consistent_with_database ?x - object ?y - object)
    (system_units_edited ?x - object ?y - object)
    (session_exists ?x - object ?y - object)
    (family_supported ?x - object ?y - object)
    (rlimit_fsize ?x - object ?y - object)
    (GID_MAX ?x - object ?y - object)
    (primary_group_set ?x - object ?y - object)
    (selinux_user_mapping_exists ?x - object ?y - object)
    (LASTLOG_UID_MAX_set ?x - object ?y - object)
    (user_locked ?x - object ?y - object)
    (package_selections_set ?x - object ?y - object)
    (variable_set ?x - object ?y - object)
    (user_supplementary_groups ?x - object ?y - object)
    (file_used ?x - object ?y - object)
    (group_non_unique ?x - object ?y - object)
    (file_modified ?x - object ?y - object)
    (path_initialized ?x - object ?y - object)
    (marked_units_restarted ?x - object ?y - object)
    (group_line_length_limit ?x - object ?y - object)
    (package_triggers-pending ?x - object ?y - object)
    (operation_performed_recursively ?x - object ?y - object)
    (pager_options_modified ?x - object ?y - object)
    (user_login ?x - object ?y - object)
    (available_packages_info_merged ?x - object ?y - object)
    (no_clobber_mode ?x - object ?y - object)
    (new_account ?x - object ?y - object)
    (traffic_blocked ?x - object ?y - object)
    (supplementary_groups_set ?x - object ?y - object)
    (source_package_fetched ?x - object ?y - object)
    (network_namespace_switched ?x - object ?y - object)
    (journal_namespace_set ?x - object ?y - object)
    (package_index_outdated ?x - object ?y - object)
    (secure_group_info_modified ?x - object ?y - object)
    (directory_exists ?x - object ?y - object)
    (socket_established ?x - object ?y - object)
    (numeric_output ?x - object ?y - object)
    (package_manually_installed ?x - object ?y - object)
    (pager_enabled ?x - object ?y - object)
    (configures ?x - object ?y - object)
    (timestamp_format_changed ?x - object ?y - object)
    (file_directory ?x - object ?y - object)
    (dependency_added ?x - object ?y - object)
    (print_jobs_removed ?x - object ?y - object)
    (defs_set_to_yes ?x - object ?y - object)
    (can_escalate ?x - object ?y - object)
    (assertion_valid ?x - object ?y - object)
    (file_not_copied ?x - object ?y - object)
    (system_upgraded ?x - object ?y - object)
    (file_readable ?x - object ?y - object)
    (user_password_locked ?x - object ?y - object)
    (available_packages_info_cleared ?x - object ?y - object)
    (child_running ?x - object ?y - object)
    (firewall_rule_exists ?x - object ?y - object)
    (password_warning_enabled ?x - object ?y - object)
    (numeric_addresses_enabled ?x - object ?y - object)
    (service_exists ?x - object ?y - object)
    (dir_removed ?x - object ?y - object)
    (file_grouped_by ?x - object ?y - object)
    (mnt_point_available ?x - object ?y - object)
    (security_context_set ?x - object ?y - object)
    (SYS_GID_MIN ?x - object ?y - object)
    (journal_files_operated_on ?x - object ?y - object)
    (snap_exists ?x - object ?y - object)
    (package_index_up_to_date ?x - object ?y - object)
    (user_home_directory ?x - object ?y - object)
    (journal_rotated ?x - object ?y - object)
    (boot_loader_menu ?x - object ?y - object)
    (snap_installed ?x - object ?y - object)
    (filesystem_root_changed ?x - object ?y - object)
    (log_directory_on_root_mount ?x - object ?y - object)
    (system_state_modified ?x - object ?y - object)
    (snap_aliases_disabled ?x - object ?y - object)
    (userspace_rebooted ?x - object ?y - object)
    (rlimit_as ?x - object ?y - object)
    (environment_updated ?x - object ?y - object)
    (package_build_dep ?x - object ?y - object)
    (network_available ?x - object ?y - object)
    (flag_set ?x - object ?y - object)
    (service_watchdog_set ?x - object ?y - object)
    (log_target_set ?x - object ?y - object)
    (backup_created ?x - object ?y - object)
    (address_valid ?x - object ?y - object)
    (package_distribution_set ?x - object ?y - object)
    (file_preserved ?x - object ?y - object)
    (config_applied ?x - object ?y - object)
    (state_free ?x - object ?y - object)
    (MAIL_DIR_set ?x - object ?y - object)
    (file_exists ?x - object ?y - object)
    (mail_spool_created_or_moved_or_deleted ?x - object ?y - object)
    (snap_no_longer_started_on_boot ?x - object ?y - object)
    (default_account_creation_values_modified ?x - object ?y - object)
    (account_locked ?x - object ?y - object)
    (crontab_files_owned_by ?x - object ?y - object)
    (verbose_enabled ?x - object ?y - object)
    (numeric_port_numbers_enabled ?x - object ?y - object)
    (no_header ?x - object ?y - object)
    (run_part_files_executed ?x - object ?y - object)
    (package_half_configured ?x - object ?y - object)
    (package_triggers-awaited ?x - object ?y - object)
    (manager_reexecuted ?x - object ?y - object)
    (fs_type_exists ?x - object ?y - object)
    (account_unlocked ?x - object ?y - object)
    (system_halted ?x - object ?y - object)
    (configuration_variables_missing ?x - object ?y - object)
    (journal_files_vacuumed ?x - object ?y - object)
    (fss_sealing_key_changed ?x - object ?y - object)
    (uid_neq_home_dir_uid ?x - object ?y - object)
    (home_directory_exists ?x - object ?y - object)
    (group_info_modified ?x - object ?y - object)
    (signature_verified ?x - object ?y - object)
    (version_control_set ?x - object ?y - object)
    (file_user_id_changed ?x - object ?y - object)
    (type_set ?x - object ?y - object)
    (su_version ?x - object ?y - object)
    (package_lists_updated ?x - object ?y - object)
    (port_available ?x - object ?y - object)
    (snap_refreshed ?x - object ?y - object)
    (time_format ?x - object ?y - object)
    (signal_received ?x - object ?y - object)
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

  (:action upgrade_packages
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (new_package_versions_available)
      (not (package_removed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_upgraded ?pkg)
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
    )
  )

  (:action download_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_downloaded ?pkg)
    )
  )

  (:action build_dep_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_build_dep ?pkg)
    )
  )

  (:action clean
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_cleaned ?pkg)
    )
  )

  (:action autoclean
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_autocleaned ?pkg)
    )
  )

  (:action autoremove
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_autoremoved ?pkg)
    )
  )

  (:action update_package_index
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_index_outdated)
      (sources_list_valid)
      (can_escalate ?actor)
    )
    :effect (and
      (package_index_up_to_date)
    )
  )

  (:action install_and_upgrade_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (new_package_versions_available)
      (not (package_removed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_upgraded ?pkg)
    )
  )

  (:action install_packages
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

  (:action update_package_list
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_list_updated)
    )
  )

  (:action install_package_with_version
    :parameters (?actor - user ?pkg - package ?ver - file)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_version_set ?pkg ?ver)
    )
  )

  (:action install_package_with_distribution
    :parameters (?actor - user ?pkg - package ?dist - file)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_distribution_set ?pkg ?dist)
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

  (:action change_permissions
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_writable ?f)
    )
  )

  (:action fetch_source_package
    :parameters (?actor - user ?pkg - package ?src - file)
    :precondition (and
      (package_exists ?pkg)
      (not (source_package_fetched ?src))
      (can_escalate ?actor)
    )
    :effect (and
      (source_package_fetched ?src)
    )
  )

  (:action add_repository_to_sources_list
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (repository_added ?repo)
    )
  )

  (:action download_file
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (is_source_archive ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_downloaded ?f)
    )
  )

  (:action configure_option
    :parameters (?actor - user ?opt - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (repository_configured ?repo)
    )
  )

  (:action update_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_lists_updated)
    )
  )

  (:action reinstall_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action autoremove_package
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_installed ?pkg)
      (not (package_needed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action dist_upgrade_package
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_installed ?pkg)
      (not (package_upgraded ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_upgraded ?pkg)
    )
  )

  (:action autoclean_package
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_installed ?pkg)
      (not (package_cleaned ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_cleaned ?pkg)
    )
  )

  (:action full_upgrade_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_list_updated)
      (not (system_upgraded))
      (can_escalate ?actor)
    )
    :effect (and
      (system_upgraded)
    )
  )

  (:action install_package_with_version_from_release
    :parameters (?actor - user ?pkg - package ?rel - file)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action mark_package_manual
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_manually_installed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_manually_installed ?pkg)
    )
  )

  (:action upgrade_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_upgraded ?pkg)
    )
  )

  (:action full_upgrade_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_removed ?pkg)
      (package_upgraded ?pkg)
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

  (:action start_package_configuration
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_configured ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_half_configured ?pkg)
    )
  )

  (:action await_package_trigger_processing
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_triggered ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_triggers-awaited ?pkg)
    )
  )

  (:action process_package_triggers
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_triggers-awaited ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_triggers-pending ?pkg)
    )
  )

  (:action hold_package_installation
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_held ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_held ?pkg)
    )
  )

  (:action unpack_package
    :parameters (?actor - user ?pkg - package ?dir - directory)
    :precondition (and
      (package_exists ?pkg)
      (file_directory ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (files_unpacked ?pkg
      ?dir)
    )
  )

  (:action remove_packages
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_removed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_removed ?pkg)
    )
  )

  (:action set_package_selections
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_selections_set ?selections)
    )
  )

  (:action clear_package_selections
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_selections_cleared)
    )
  )

  (:action record_availability
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (file_exists ?deb_file)
      (not (package_recorded ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_recorded ?pkg)
    )
  )

  (:action trigger_configuration
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

  (:action set_selections
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_selections_set ?sel)
    )
  )

  (:action clear_selections
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_selections_cleared)
    )
  )

  (:action update_avail
    :parameters (?actor - user ?file - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (available_packages_info_updated ?file)
    )
  )

  (:action merge_avail
    :parameters (?actor - user ?file - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (available_packages_info_merged ?file)
    )
  )

  (:action clear_avail
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (available_packages_info_cleared)
    )
  )

  (:action forget_old_unavail
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (unavailable_packages_forgetten)
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

  (:action abort_change
    :parameters (?actor - user ?change - file)
    :precondition (and
      (pending_change ?change)
      (can_escalate ?actor)
    )
    :effect (and
      (change_aborted ?change)
    )
  )

  (:action add_assertion
    :parameters (?actor - user ?assertion - file)
    :precondition (and
      (assertion_valid ?assertion)
      (signature_verified ?assertion)
      (consistent_with_database ?assertion)
      (can_escalate ?actor)
    )
    :effect (and
      (assertion_added ?assertion)
    )
  )

  (:action create_alias
    :parameters (?app - package ?alias - file)
    :precondition (and
    )
    :effect (and
      (alias_created ?app ?alias)
    )
  )

  (:action connect_snap_interface
    :parameters (?actor - user ?snap - interface ?plug - interface)
    :precondition (and
      (snap_exists ?snap)
      (plug_exists ?plug)
      (slot_exists ?slot)
      (match ?plug ?slot)
      (can_escalate ?actor)
    )
    :effect (and
      (connection_established ?snap ?plug ?slot)
    )
  )

  (:action create_cohort_keys
    :parameters (?actor - user ?snaps - file)
    :precondition (and
      (set_of_snaps ?snaps)
      (can_escalate ?actor)
    )
    :effect (and
      (cohort_keys_created ?snaps)
    )
  )

  (:action refresh_snap
    :parameters (?snap - file)
    :precondition (and
    )
    :effect (and
      (snap_refreshed ?some-snap)
    )
  )

  (:action switch_snap_channel
    :parameters (?snap - file ?channel - file)
    :precondition (and
      (snap_exists ?snap)
      (channel_available ?channel)
    )
    :effect (and
      (snap_channel_switched ?snap ?channel)
    )
  )

  (:action stop_snap_boot_start
    :parameters (?snap - file)
    :precondition (and
      (snap_exists ?snap)
      (snap_running ?snap)
    )
    :effect (and
      (snap_no_longer_started_on_boot ?snap)
    )
  )

  (:action set_snap_mode
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (snap_in_development_mode ?snap)
    )
  )

  (:action remove_alias
    :parameters (?actor - user ?alias - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (alias_removed ?alias)
    )
  )

  (:action remove_snap_aliases
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (snap_aliases_disabled ?snap)
    )
  )

  (:action unset_config_options
    :parameters (?actor - user ?snap - file ?option - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (config_options_unset ?snap ?option)
    )
  )

  (:action unset_snap_config
    :parameters (?actor - user ?snap - file ?user - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (snap_config_unset ?snap ?user)
    )
  )

  (:action enforce_snap_validation
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (snap_config_valid ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_config_valid ?snap)
    )
  )

  (:action forget_snap_validation
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (snap_config_valid ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_config_valid ?snap)
    )
  )

  (:action refresh_snap_install
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (snap_config_valid ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_config_valid ?snap)
    )
  )

  (:action set_time_format
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (time_format ?format)
    )
  )

  (:action set_unicode
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (unicode_enabled ?enabled)
    )
  )

  (:action set_verbose
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (verbose_enabled ?enabled)
    )
  )

  (:action install_snaps
    :parameters (?actor - user ?snaps - package)
    :precondition (and
      (not (snap_installed ?snap))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_installed ?snap)
    )
  )

  (:action remove_snaps
    :parameters (?actor - user ?snaps - package)
    :precondition (and
      (snap_installed ?snap)
      (not (snap_removed ?snap))
      (can_escalate ?actor)
    )
    :effect (and
      (snap_removed ?snap)
    )
  )

  (:action refresh_snaps
    :parameters (?actor - user ?snaps - package)
    :precondition (and
      (snap_installed ?snap)
      (not (snap_refreshed ?snap))
      (can_escalate ?actor)
    )
    :effect (and
      (snap_refreshed ?snap)
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

  (:action stop_services
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

  (:action restart_services
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

  (:action load_units
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (units_loaded)
      (can_escalate ?actor)
    )
    :effect (and
      (units_loaded)
    )
  )

  (:action add_dependency
    :parameters (?actor - user ?tgt - file ?unit - file)
    :precondition (and
      (dependency_exists ?tgt ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (dependency_added ?tgt ?unit)
    )
  )

  (:action edit_unit
    :parameters (?actor - user ?unit - file)
    :precondition (and
      (unit_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_edited ?unit)
    )
  )

  (:action set_default_target
    :parameters (?actor - user ?tgt - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_target ?tgt)
    )
  )

  (:action cancel_jobs
    :parameters (?actor - user ?jobs - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (jobs_canceled)
    )
  )

  (:action set_environment
    :parameters (?var - file ?value - file)
    :precondition (and
    )
    :effect (and
      (environment_updated)
    )
  )

  (:action unset_environment
    :parameters (?var - file)
    :precondition (and
    )
    :effect (and
      (environment_updated)
    )
  )

  (:action import_environment
    :parameters (?var - file)
    :precondition (and
    )
    :effect (and
      (environment_updated)
    )
  )

  (:action reload_manager
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (manager_reloaded)
    )
  )

  (:action reexec_manager
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (manager_reexecuted)
    )
  )

  (:action set_log_level
    :parameters (?actor - user ?level - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (log_level_set ?level)
    )
  )

  (:action set_log_target
    :parameters (?actor - user ?target - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (log_target_set ?target)
    )
  )

  (:action set_service_watchdog
    :parameters (?actor - user ?state - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (service_watchdog_set ?state)
    )
  )

  (:action shutdown_system
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

  (:action kexec_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_rebooted)
    )
  )

  (:action soft_reboot_userspace
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (userspace_rebooted)
    )
  )

  (:action exit_process
    :parameters (?EXIT_CODE - file)
    :precondition (and
    )
    :effect (and
      (process_exited)
    )
  )

  (:action switch_root_filesystem
    :parameters (?actor - user ?ROOT - file ?INIT - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (root_filesystem_changed)
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
      (can_escalate ?actor)
    )
    :effect (and
      (system_hibernated)
    )
  )

  (:action hybrid_sleep_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_hibernated_and_suspended)
    )
  )

  (:action configure_systemd
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (systemd_running)
      (can_escalate ?actor)
    )
    :effect (and
      (system_state_modified)
    )
  )

  (:action start_process
    :parameters (?actor - user ?p - process)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (process_running ?p)
    )
  )

  (:action stop_process
    :parameters (?actor - user ?p - process)
    :precondition (and
      (process_running ?p)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?p))
    )
  )

  (:action configure_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_state_modified)
    )
  )

  (:action enable_disable_unit
    :parameters (?actor - user ?unit - file)
    :precondition (and
      (unit_exists ?unit)
      (not (unit_enabled ?unit))
      (can_escalate ?actor)
    )
    :effect (and
      (unit_enabled ?unit)
    )
  )

  (:action start_stop_unit
    :parameters (?actor - user ?unit - file)
    :precondition (and
      (unit_exists ?unit)
      (not (unit_running ?unit))
      (can_escalate ?actor)
    )
    :effect (and
      (unit_running ?unit)
    )
  )

  (:action edit_system_units
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_units_edited ?)
    )
  )

  (:action edit_system_units_runtime
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_units_edited ?)
    )
  )

  (:action edit_system_units_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_units_edited ?)
    )
  )

  (:action edit_system_units_image
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_units_edited ?)
    )
  )

  (:action firmware_setup
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firmware_setup ?x)
    )
  )

  (:action boot_loader_menu
    :parameters (?actor - user ?time - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (boot_loader_menu ?x)
    )
  )

  (:action boot_loader_entry
    :parameters (?actor - user ?name - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (boot_loader_entry ?x)
    )
  )

  (:action change_timestamp_format
    :parameters (?actor - user ?format - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (timestamp_format_changed ?x)
    )
  )

  (:action create_read_only_bind_mount
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (read_only_bind_mount_created ?x)
    )
  )

  (:action create_directory_before_mounting
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (directory_created ?x)
    )
  )

  (:action restart_reload_marked_units
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (marked_units_restarted ?x)
    )
  )

  (:action edit_unit_file
    :parameters (?actor - user ?name - file ?time - file)
    :precondition (and
      (unit_file_exists ?name)
      (time_valid ?time)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_file_modified ?name
      ?time)
    )
  )

  (:action configure_journal
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_in_group ?u 'systemd-journal)
      (user_in_group ?u 'adm)
      (user_in_group ?u 'wheel')
      (can_escalate ?actor)
    )
    :effect (and
      (journal_access_granted ?u)
    )
  )

  (:action set_pager_options
    :parameters (?obj - file)
    :precondition (and
      (pager_enabled)
    )
    :effect (and
      (pager_options_modified)
    )
  )

  (:action set_journal_output
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (journal_output_modified)
    )
  )

  (:action set_journal_source
    :parameters (?system - user)
    :precondition (and
    )
    :effect (and
      (journal_source_modified)
    )
  )

  (:action change_journal_directory
    :parameters (?dir - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (journal_directory_changed ?dir)
    )
  )

  (:action operate_on_journal_files
    :parameters (?actor - user ?files - file ?root - directory ?image - file)
    :precondition (and
      (file_exists ?files)
      (directory_exists ?root)
      (image_exists ?image)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_files_operated_on ?files ?root ?image)
    )
  )

  (:action set_image_policy
    :parameters (?actor - user ?policy - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (image_policy_set ?policy)
    )
  )

  (:action set_journal_namespace
    :parameters (?actor - user ?namespace - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_namespace_set ?namespace)
    )
  )

  (:action change_filesystem_root
    :parameters (?actor - user ?root - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (filesystem_root_changed)
    )
  )

  (:action change_filesystem_root_image
    :parameters (?actor - user ?image - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (filesystem_root_changed)
    )
  )

  (:action setup_fss_key
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (fss_sealing_key_changed)
    )
  )

  (:action vacuum_disk
    :parameters (?actor - user ?size - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (disk_usage_reduced)
    )
  )

  (:action vacuum_files
    :parameters (?actor - user ?num - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_files_vacuumed)
    )
  )

  (:action vacuum_time
    :parameters (?actor - user ?time - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_files_removed)
    )
  )

  (:action sync_journal
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_messages_synced)
    )
  )

  (:action relinquish_logging
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (logging_stopped)
    )
  )

  (:action smart_relinquish_logging
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (log_directory_on_root_mount)
      (can_escalate ?actor)
    )
    :effect (and
      (logging_stopped)
    )
  )

  (:action flush_journal_data
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_flushed)
    )
  )

  (:action rotate_journal_files
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_rotated)
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

  (:action create_backup
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (backup_created ?file)
    )
  )

  (:action copy_special_file_contents
    :parameters (?src - file ?dst - file)
    :precondition (and
    )
    :effect (and
      (file_contents_equal ?src ?dst)
    )
  )

  (:action copy_file_attributes
    :parameters (?src - file ?dst - file)
    :precondition (and
    )
    :effect (and
      (file_attributes_equal ?src ?dst)
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

  (:action create_hard_link
    :parameters (?s - file ?d - file)
    :precondition (and
      (file_exists ?s)
      (not (file_exists ?d))
    )
    :effect (and
      (file_linked ?s ?d)
    )
  )

  (:action create_symbolic_link
    :parameters (?s - file ?d - file)
    :precondition (and
      (file_exists ?s)
      (not (file_exists ?d))
    )
    :effect (and
      (file_linked ?s ?d)
    )
  )

  (:action preserve_file_attributes
    :parameters (?f - file ?attr_list - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_preserved ?f ?attr_list)
    )
  )

  (:action follow_symbolic_links
    :parameters (?s - file)
    :precondition (and
      (file_exists ?s)
    )
    :effect (and
      (file_followed ?s)
    )
  )

  (:action prompt_before_overwrite
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_persisted ?f)
    )
  )

  (:action do_not_overwrite_existing_file
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_overwritten ?f))
    )
  )

  (:action update_file_attributes
    :parameters (?f - file ?attr_list - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_updated ?f ?attr_list)
    )
  )

  (:action do_not_follow_symbolic_links
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?s)
    )
    :effect (and
      (not (file_followed ?s))
    )
  )

  (:action preserve_file_mode_ownership_timestamps
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_preserved ?f ?mode ?ownership ?timestamps)
    )
  )

  (:action use_full_source_file_name_under_directory
    :parameters (?s - file ?d - directory)
    :precondition (and
      (file_exists ?s)
      (directory_exists ?d)
    )
    :effect (and
      (file_used ?s ?d)
    )
  )

  (:action copy_directory_recursive
    :parameters (?src - directory ?dst - directory)
    :precondition (and
      (file_exists ?src)
      (dir_exists ?dst)
    )
    :effect (and
      (file_copied ?src ?dst)
    )
  )

  (:action remove_destination_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_removed ?f)
    )
  )

  (:action create_sparse_file
    :parameters (?f - file ?when - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_sparse ?f ?when)
    )
  )

  (:action set_backup_suffix
    :parameters (?suffix - file)
    :precondition (and
    )
    :effect (and
      (backup_suffix_set ?suffix)
    )
  )

  (:action copy_to_directory
    :parameters (?src - directory ?dst - directory)
    :precondition (and
      (dir_exists ?src)
      (dir_exists ?dst)
    )
    :effect (and
      (file_copied ?src ?dst)
    )
  )

  (:action set_verbose_mode
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (verbose_mode_set)
    )
  )

  (:action change_security_context
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (security_context_set ?f)
    )
  )

  (:action set_sparse_option
    :parameters (?opt - file)
    :precondition (and
    )
    :effect (and
      (sparse_files_inhibited ?opt)
    )
  )

  (:action update_files
    :parameters (?obj - file)
    :precondition (and
      (operation_specified ?op)
      (files_to_update ?f)
    )
    :effect (and
      (files_updated ?f
      ?op)
    )
  )

  (:action copy_file_lightweight
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
      (reflink_option_specified ?opt)
    )
    :effect (and
      (file_copied ?f
      ?opt)
    )
  )

  (:action copy_file_with_attributes
    :parameters (?src - file ?dst - file)
    :precondition (and
    )
    :effect (and
      (file_exists ?dst)
      (file_contents_equal ?src ?dst)
    )
  )

  (:action copy_file_with_backup
    :parameters (?src - file ?dst - file)
    :precondition (and
    )
    :effect (and
      (file_exists ?dst)
      (file_contents_equal ?src ?dst)
    )
  )

  (:action copy_file_with_copy_contents
    :parameters (?src - file ?dst - file)
    :precondition (and
    )
    :effect (and
      (file_exists ?dst)
      (file_contents_equal ?src ?dst)
    )
  )

  (:action dereference_link
    :parameters (?src - file)
    :precondition (and
      (file_exists ?src)
      (symbolic_link ?src)
    )
    :effect (and
      (not (symbolic_link ?src))
    )
  )

  (:action do_not_overwrite_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (not (no_clobber_mode))
    )
    :effect (and
      (no_clobber_mode)
    )
  )

  (:action follow_command_line_link
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (symbolic_link ?f)
    )
    :effect (and
      (not (symbolic_link ?f))
    )
  )

  (:action copy_directory_symbolic_link
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (not (file_linked ?dst))
    )
    :effect (and
      (file_linked ?dst)
    )
  )

  (:action copy_files
    :parameters (?src - file ?dst - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dst)
    )
    :effect (and
      (file_exists ?dst/?)
    )
  )

  (:action set_file_attributes
    :parameters (?actor - user ?attr - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_attribute_set ?f ?attr)
    )
  )

  (:action detect_sparse_files
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (file_sparse ?f)
    )
  )

  (:action make_backup
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (eq ?src ?dst)
      (not (file_linked ?src ?dst))
    )
    :effect (and
      (file_linked ?src ?dst)
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

  (:action rename_file
    :parameters (?src - file ?dst - file)
    :precondition (and
    )
    :effect (and
      (file_renamed ?src ?dst)
    )
  )

  (:action move_file_to_directory
    :parameters (?src - file ?dst - directory)
    :precondition (and
    )
    :effect (and
      (file_moved ?src ?dst)
    )
  )

  (:action no_prompt_before_overwrite
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (overwrite_not_prompted ?file)
    )
  )

  (:action no_overwrite
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (file_not_overwritten ?file)
    )
  )

  (:action no_copy_if_renaming_fails
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (file_not_copied ?file)
    )
  )

  (:action strip_trailing_slashes
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (no file modifications)
    )
  )

  (:action move_files
    :parameters (?d - directory ?s - file)
    :precondition (and
    )
    :effect (and
      (file moved)
    )
  )

  (:action set_file_type
    :parameters (?d - directory ?s - file)
    :precondition (and
    )
    :effect (and
      (file type changed)
    )
  )

  (:action set_security_context
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (security_context_set ?dir)
    )
  )

  (:action set_permissions
    :parameters (?f - file ?mode - file)
    :precondition (and
    )
    :effect (and
      (file_executable ?f)
      (file_readable ?f)
      (file_writable ?f)
    )
  )

  (:action update_file
    :parameters (?src - file ?dest - file)
    :precondition (and
    )
    :effect (and
      (file_exists ?dest)
      (file_contents_equal ?src ?dest)
    )
  )

  (:action set_version_control
    :parameters (?method - file)
    :precondition (and
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

  (:action remove_files
    :parameters (?actor - user ?files - file)
    :precondition (and
      (file_exists ?f)
      (not (file_removed ?f))
      (can_escalate ?actor)
    )
    :effect (and
      (file_removed ?f)
    )
  )

  (:action remove_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (file_system_matches ?dir)
      (not (dir_empty ?dir))
      (can_escalate ?actor)
    )
    :effect (and
      (dir_removed ?dir)
    )
  )

  (:action remove_directory_recursive
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (file_system_matches ?dir)
      (not (dir_empty ?dir))
      (can_escalate ?actor)
    )
    :effect (and
      (dir_removed ?dir)
    )
  )

  (:action remove_empty_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (file_system_matches ?dir)
      (dir_empty ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (dir_removed ?dir)
    )
  )

  (:action preserve_permissions
    :parameters (?actor - user ?d - directory)
    :precondition (and
      (directory_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_preserves_permissions ?d)
    )
  )

  (:action set_sticky_bit
    :parameters (?actor - user ?f - file ?d - directory)
    :precondition (and
      (file_exists ?f)
      (directory_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (file_sticky_bit ?f)
      (directory_restricted_deletion ?d)
    )
  )

  (:action change_permissions_with_reference
    :parameters (?f - file ?rfile - file ?mode - file)
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

  (:action change_ownership
    :parameters (?actor - user ?uid - user ?home_dir - directory)
    :precondition (and
      (file_exists ?f)
      (uid_valid ?uid)
      (home_dir_exists ?home_dir)
      (uid_neq_home_dir_uid ?uid ?home_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?uid ?f)
      (file_user_id_changed ?uid ?f)
    )
  )

  (:action change_owner_group
    :parameters (?actor - user ?f - file ?o - user ?g - group)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?o)
      (file_grouped_by ?g)
    )
  )

  (:action preserve_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (root_not_preserved)
    )
  )

  (:action fail_recursive_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (recursive_operation_failed)
    )
  )

  (:action set_owner_from_reference
    :parameters (?actor - user ?r - file)
    :precondition (and
      (file_exists ?r)
      (can_escalate ?actor)
    )
    :effect (and
      (new_owner_set ?f)
      (new_group_set ?f)
    )
  )

  (:action recursive_operation
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (operation_performed_recursively)
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

  (:action make_directory
    :parameters (?dir - directory)
    :precondition (and
      (not (directory_exists ?dir))
    )
    :effect (and
      (directory_exists ?dir)
    )
  )

  (:action create_directories
    :parameters (?dir - directory)
    :precondition (and
      (not (directory_exists ?dir))
    )
    :effect (and
      (directory_exists ?dir)
      (file_executable ?dir)
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

  (:action change_timestamps
    :parameters (?f - file)
    :precondition (and
    )
    :effect (and
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
    )
  )

  (:action update_timestamps
    :parameters (?f - file)
    :precondition (and
    )
    :effect (and
      (file_modified ?f)
      (file_accessed ?f)
    )
  )

  (:action touch_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
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

  (:action set_protocol_family
    :parameters (?actor - user ?family - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (protocol_family_set ?family)
    )
  )

  (:action set_output_format
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (output_format_set ?format)
    )
  )

  (:action switch_network_namespace
    :parameters (?actor - user ?ns - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (network_namespace_switched ?ns)
    )
  )

  (:action set_interface_up
    :parameters (?actor - user ?int - interface)
    :precondition (and
      (interface_exists ?int)
      (not (interface_up ?int))
      (can_escalate ?actor)
    )
    :effect (and
      (interface_up ?int)
    )
  )

  (:action set_interface_down
    :parameters (?actor - user ?int - interface)
    :precondition (and
      (interface_exists ?int)
      (interface_up ?int)
      (can_escalate ?actor)
    )
    :effect (and
      (not (interface_up ?int))
    )
  )

  (:action hide_header
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (no_header)
    )
  )

  (:action one_line_output
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (single_line_output)
    )
  )

  (:action numeric_output
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (numeric_output)
    )
  )

  (:action set_option
    :parameters (?actor - user ?opt - file)
    :precondition (and
      (option_exists ?opt)
      (not (option_set ?opt))
      (can_escalate ?actor)
    )
    :effect (and
      (option_set ?opt)
    )
  )

  (:action kill_process
    :parameters (?actor - user ?p - process)
    :precondition (and
      (socket_exists ?s)
      (not (socket_closed ?s))
      (can_escalate ?actor)
    )
    :effect (and
      (socket_closed ?s)
    )
  )

  (:action modify_host_syntax
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (family_supported ?f)
      (address_valid ?a)
      (port_valid ?p)
      (can_escalate ?actor)
    )
    :effect (and
      (host_syntax_modified ?h)
    )
  )

  (:action configure_network_link
    :parameters (?actor - user ?addr - interface ?port - file)
    :precondition (and
      (network_link_exists ?addr)
      (port_available ?port)
      (can_escalate ?actor)
    )
    :effect (and
      (network_link_configured ?addr ?port)
    )
  )

  (:action set_wide_output
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (wide_output_enabled)
    )
  )

  (:action set_numeric_addresses
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (numeric_addresses_enabled)
    )
  )

  (:action set_numeric_host_addresses
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (numeric_host_addresses_enabled)
    )
  )

  (:action set_numeric_port_numbers
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (numeric_port_numbers_enabled)
    )
  )

  (:action set_socket_state
    :parameters (?state - file)
    :precondition (and
      (socket_exists)
      (not (socket_established))
    )
    :effect (and
      (socket_established)
    )
  )

  (:action change_socket_state
    :parameters (?sock - file)
    :precondition (and
      (socket_exists ?sock)
      (state_free ?sock)
    )
    :effect (and
      (state_allocated ?sock) or (state_not_allocated ?sock)
    )
  )

  (:action set_socket_flags
    :parameters (?sock - file ?flag - file)
    :precondition (and
      (socket_exists ?sock)
      (state_allocated ?sock)
    )
    :effect (and
      (flag_set ?sock ?flag)
    )
  )

  (:action set_socket_type
    :parameters (?sock - file ?type - file)
    :precondition (and
      (socket_exists ?sock)
      (state_allocated ?sock)
    )
    :effect (and
      (type_set ?sock ?type)
    )
  )

  (:action mount_filesystem
    :parameters (?actor - user ?mnt_point - directory ?fs_type - file)
    :precondition (and
      (fs_type_exists ?fs)
      (mnt_point_available)
      (can_escalate ?actor)
    )
    :effect (and
      (filesystem_mounted ?mnt_point ?fs)
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

  (:action set_limits
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (su_version >= 2.38)
      (can_escalate ?actor)
    )
    :effect (and
      (rlimit_nice ?x)
      (rlimit_rtprio ?y)
      (rlimit_fsize ?z)
      (rlimit_as ?w)
      (rlimit_nofile ?v)
    )
  )

  (:action pass_command_to_shell
    :parameters (?actor - user ?cmd - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (shell_passes_cmd ?x)
    )
  )

  (:action run_in_fast_mode
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (fast_mode ?x)
    )
  )

  (:action create_pseudo_terminal
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (pseudo_terminal_enabled)
    )
  )

  (:action set_shell
    :parameters (?shell - file)
    :precondition (and
    )
    :effect (and
      (shell_set)
    )
  )

  (:action set_session_command
    :parameters (?actor - user ?cmd - file)
    :precondition (and
      (session_exists ?s)
      (not (session_running ?s))
      (can_escalate ?actor)
    )
    :effect (and
      (session_running ?s)
    )
  )

  (:action terminate_process
    :parameters (?actor - user ?pid - process)
    :precondition (and
      (child_running ?pid)
      (signal_received ?pid)
      (can_escalate ?actor)
    )
    :effect (and
      (child_terminated ?pid)
      (self_terminated ?pid)
    )
  )

  (:action read_config_files
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (config_read ?file)
    )
  )

  (:action initialize_path
    :parameters (?obj - file)
    :precondition (and
      (not (path_initialized))
      (not (--login))
    )
    :effect (and
      (path_initialized)
    )
  )

  (:action switch_user
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_changed ?usr)
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
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?usr)
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

  (:action reset_user_entries
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_exists ?u)
      (not (user_in_lastlog ?u))
      (not (user_in_faillog ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_in_lastlog ?u))
      (not (user_in_faillog ?u))
    )
  )

  (:action create_home_directory
    :parameters (?actor - user ?d - directory)
    :precondition (and
      (directory_exists ?d)
      (proper_selinux_context ?d)
      (proper_permissions ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_created ?u
      ?d)
    )
  )

  (:action set_defs
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (defs_not_set)
      (can_escalate ?actor)
    )
    :effect (and
      (defs_set_to_yes)
    )
  )

  (:action create_system_account
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (account_exists ?user))
      (password_policy_respected)
      (can_escalate ?actor)
    )
    :effect (and
      (account_created ?user)
      (account_locked ?user)
      (no_password_defined ?user)
    )
  )

  (:action add_group_entry
    :parameters (?actor - user ?g - group)
    :precondition (and
      (not (group_exists ?g))
      (group_line_length_limit ?l)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?g)
      (group_line_length_limit ?l)
    )
  )

  (:action set_password_expiration_limit
    :parameters (?actor - user ?d - file)
    :precondition (and
      (not (password_expiration_limit_set ?d))
      (can_escalate ?actor)
    )
    :effect (and
      (password_expiration_limit_set ?d)
    )
  )

  (:action set_minimum_password_change_interval
    :parameters (?actor - user ?d - file)
    :precondition (and
      (not (minimum_password_change_interval_set ?d))
      (can_escalate ?actor)
    )
    :effect (and
      (minimum_password_change_interval_set ?d)
    )
  )

  (:action set_system_settings
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (file_exists ?f)
      (not (setting_changed ?s))
      (can_escalate ?actor)
    )
    :effect (and
      (setting_changed ?s)
    )
  )

  (:action set_password_restrictions
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (password_warning_enabled ?p)
    )
  )

  (:action set_subordinate_group_ids
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (file_exists ?f)
      (not (subgroup_ids_set ?s))
      (can_escalate ?actor)
    )
    :effect (and
      (subgroup_ids_set ?s)
    )
  )

  (:action set_subordinate_user_ids
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (file_exists ?f)
      (not (subuser_ids_set ?s))
      (can_escalate ?actor)
    )
    :effect (and
      (subuser_ids_set ?s)
    )
  )

  (:action allocate_user_ids
    :parameters (?actor - user ?count - file ?min - file ?max - file)
    :precondition (and
      (file_exists /etc/subuid)
      (not (user_has_subordinate_uids ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_allocated_subordinate_uids ?u)
    )
  )

  (:action allocate_system_user_ids
    :parameters (?actor - user ?count - file ?min - file ?max - file)
    :precondition (and
      (not (user_has_system_uids ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_allocated_system_uids ?u)
    )
  )

  (:action allocate_system_group_ids
    :parameters (?actor - user ?count - file ?min - file ?max - file)
    :precondition (and
      (not (group_has_system_gid ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (group_allocated_system_gid ?g)
    )
  )

  (:action set_umask
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (umask_set ?mask)
    )
  )

  (:action set_usergroups_enable
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (usergroups_enabled ?flag)
    )
  )

  (:action modify_user_account
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_info_modified ?info)
    )
  )

  (:action modify_group_account
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_info_modified ?info)
    )
  )

  (:action modify_secure_user_account
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (secure_user_info_modified ?info)
    )
  )

  (:action modify_secure_group_account
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (secure_group_info_modified ?info)
    )
  )

  (:action modify_default_account_creation_values
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_account_creation_values_modified ?values)
    )
  )

  (:action execute_run_part_files
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (run_part_files_executed ?files)
    )
  )

  (:action add_subids
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_user)
      (can_escalate ?actor)
    )
    :effect (and
      (subids_added)
    )
  )

  (:action set_group
    :parameters (?actor - user ?gid - group)
    :precondition (and
      (new_account)
      (can_escalate ?actor)
    )
    :effect (and
      (primary_group_set)
    )
  )

  (:action set_groups
    :parameters (?actor - user ?groups - file)
    :precondition (and
      (new_account)
      (can_escalate ?actor)
    )
    :effect (and
      (supplementary_groups_set)
    )
  )

  (:action create_home
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (new_account)
      (not (home_directory_exists))
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_created)
    )
  )

  (:action no_create_home
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (new_account)
      (home_directory_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_not_created)
    )
  )

  (:action no_user_group
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (new_account)
      (group_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (group_not_created)
    )
  )

  (:action non_unique
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (new_account)
      (unique_names_required)
      (can_escalate ?actor)
    )
    :effect (and
      (unique_names_not_required)
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

  (:action update_user
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_modified ?usr)
    )
  )

  (:action set_user_account_expiration_date
    :parameters (?actor - user ?date - file)
    :precondition (and
      (file_exists /etc/shadow)
      (can_escalate ?actor)
    )
    :effect (and
      (user_account_expired ?date)
    )
  )

  (:action set_user_account_inactive_period
    :parameters (?actor - user ?days - file)
    :precondition (and
      (file_exists /etc/shadow)
      (can_escalate ?actor)
    )
    :effect (and
      (user_account_inactive ?days)
    )
  )

  (:action change_groups
    :parameters (?actor - user ?g - group ?g1 - file ?g2 - file)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (not (primary_group_set ?u ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (primary_group_set ?u ?g)
      (group_member ?u ?g1)
      (group_member ?u ?g2)
      ...
    )
  )

  (:action append_group
    :parameters (?actor - user ?u - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_supplementary_groups ?u)
    )
  )

  (:action change_login
    :parameters (?actor - user ?old - file ?new - file)
    :precondition (and
      (user_exists ?old)
      (can_escalate ?actor)
    )
    :effect (and
      (user_login ?new)
    )
  )

  (:action lock_password
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_password_locked ?u)
    )
  )

  (:action move_home
    :parameters (?actor - user ?u - user ?new - directory)
    :precondition (and
      (user_exists ?u)
      (new_directory_exists ?new)
      (can_escalate ?actor)
    )
    :effect (and
      (user_home_directory ?new)
    )
  )

  (:action modify_user
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_not_executing_processes ?usr)
      (not (user_id_changed ?usr))
      (not (user_home_dir_changed ?usr))
      (can_escalate ?actor)
    )
    :effect (and
      (user_modified ?usr)
    )
  )

  (:action remove_user_from_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (user_in_group ?u ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_in_group ?u ?g))
    )
  )

  (:action unlock_account
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (account_locked)
      (can_escalate ?actor)
    )
    :effect (and
      (account_unlocked)
    )
  )

  (:action add_subuids
    :parameters (?actor - user ?range - file)
    :precondition (and
      (user_exists)
      (not (subuids_assigned ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (subuids_assigned ?user)
    )
  )

  (:action del_subuids
    :parameters (?actor - user ?range - file)
    :precondition (and
      (user_exists)
      (subuids_assigned ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subuids_assigned ?user))
    )
  )

  (:action add_subgids
    :parameters (?actor - user ?rg - file ?uid - user)
    :precondition (and
      (user_exists ?uid)
      (subgid_range_valid ?rg)
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_subgids ?uid ?rg)
    )
  )

  (:action del_subgids
    :parameters (?actor - user ?rg - file ?uid - user)
    :precondition (and
      (user_exists ?uid)
      (subgid_range_valid ?rg)
      (can_escalate ?actor)
    )
    :effect (and
      (user_no_longer_has_subgids ?uid ?rg)
    )
  )

  (:action set_selinux_user
    :parameters (?actor - user ?seuser - file ?uid - user)
    :precondition (and
      (user_exists ?uid)
      (can_escalate ?actor)
    )
    :effect (and
      (user_mapped_to_seuser ?uid ?seuser)
    )
  )

  (:action change_crontab_owner
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (crontab_files_present)
      (can_escalate ?actor)
    )
    :effect (and
      (crontab_files_owned_by ?usr)
    )
  )

  (:action modify_nis_config
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (nis_server_present)
      (can_escalate ?actor)
    )
    :effect (and
      (nis_config_modified ?usr)
    )
  )

  (:action update_lastlog_entries
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (LASTLOG_UID_MAX_set)
      (not (user_id_changed ?usr))
      (can_escalate ?actor)
    )
    :effect (and
      (lastlog_entries_updated ?usr)
    )
  )

  (:action update_mail_dir
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (MAIL_DIR_set)
      (can_escalate ?actor)
    )
    :effect (and
      (mail_dir_updated ?usr)
    )
  )

  (:action set_variable
    :parameters (?var - file ?val - file)
    :precondition (and
    )
    :effect (and
      (variable_set ?var ?val)
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

  (:action remove_user
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (user_removed ?usr)
      (file_removed ?f)
      (mail_spool_removed ?ms)
    )
  )

  (:action remove_selinux_user_mapping
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (selinux_user_mapping_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (no selinux_user_mapping)
    )
  )

  (:action configure_tool
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (configuration_variables_missing)
      (can_escalate ?actor)
    )
    :effect (and
      (configuration_variables_set)
    )
  )

  (:action manage_mail_spool
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_account_modified_or_deleted)
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_created_or_moved_or_deleted)
    )
  )

  (:action set_group_limit
    :parameters (?actor - user ?max_members_per_group - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_entry_split ?f)
    )
  )

  (:action remove_jobs
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (cron_jobs_removed ?usr)
      (at_jobs_removed ?usr)
      (print_jobs_removed ?usr)
    )
  )

  (:action update_subgroup_ids
    :parameters (?actor - user ?u - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (subgid_updated ?u)
    )
  )

  (:action update_subuser_ids
    :parameters (?actor - user ?u - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_updated ?u)
    )
  )

  (:action add_group
    :parameters (?actor - user ?g - group)
    :precondition (and
      (not (group_exists ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?g)
    )
  )

  (:action set_group_defaults
    :parameters (?actor - user ?gid_min - file ?gid_max - file ?password - file ?non_unique - file ?system - file)
    :precondition (and
      (group_exists ?gid)
      (not (group_password_set ?gid))
      (can_escalate ?actor)
    )
    :effect (and
      (group_password_set ?gid)
      (group_non_unique ?gid)
    )
  )

  (:action set_gids
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (GID_MIN ?x)
      (GID_MAX ?y)
    )
  )

  (:action set_max_members_per_group
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (max_members_per_group ?x)
    )
  )

  (:action set_sys_gids
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (SYS_GID_MIN ?x)
      (SYS_GID_MAX ?y)
    )
  )

)