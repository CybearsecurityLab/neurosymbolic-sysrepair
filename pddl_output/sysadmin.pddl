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
    (json_output_enabled ?x - object ?y - object)
    (package_selected_for_install ?x - object ?y - object)
    (subgid_range_valid ?x - object ?y - object)
    (package_selections_cleared ?x - object ?y - object)
    (operation_recursive ?x - object ?y - object)
    (watchdog_state_set ?x - object ?y - object)
    (package_build_deps_installed ?x - object ?y - object)
    (journal_files_operated ?x - object ?y - object)
    (variable_set ?x - object ?y - object)
    (user_modified ?x - object ?y - object)
    (scripts_run ?x - object ?y - object)
    (log_init_not_performed ?x - object ?y - object)
    (unit_file_modified ?x - object ?y - object)
    (rate_units_IEC ?x - object ?y - object)
    (config_read ?x - object ?y - object)
    (log_to_temporary_file_system ?x - object ?y - object)
    (package_selections_set ?x - object ?y - object)
    (file_executable ?x - object ?y - object)
    (package_list_updated ?x - object ?y - object)
    (file_unpacked ?x - object ?y - object)
    (marked_units_restarted ?x - object ?y - object)
    (child_terminated ?x - object ?y - object)
    (user_password_unlocked ?x - object ?y - object)
    (socket_established ?x - object ?y - object)
    (boot_start_enabled ?x - object ?y - object)
    (release_info_changed ?x - object ?y - object)
    (read_only_bind_mount_created ?x - object ?y - object)
    (user_shell_set ?x - object ?y - object)
    (empty_dir ?x - object ?y - object)
    (home_directory_exists ?x - object ?y - object)
    (slot_exists ?x - object ?y - object)
    (port_allowed ?x - object ?y - object)
    (since_version ?x - object ?y - object)
    (apt_sources_list_valid ?x - object ?y - object)
    (symlink_overridden ?x - object ?y - object)
    (traffic_blocked ?x - object ?y - object)
    (session_created ?x - object ?y - object)
    (new_owner_set ?x - object ?y - object)
    (socket_exists ?x - object ?y - object)
    (subuids_assigned ?x - object ?y - object)
    (host_syntax_modified ?x - object ?y - object)
    (cron_jobs_removed ?x - object ?y - object)
    (package_cleaned ?x - object ?y - object)
    (file_removed ?x - object ?y - object)
    (selinux_user_mapping_exists ?x - object ?y - object)
    (snaps_exists ?x - object ?y - object)
    (dependency_exists ?x - object ?y - object)
    (architecture_removed ?x - object ?y - object)
    (backup_created ?x - object ?y - object)
    (configuration_variables_set ?x - object ?y - object)
    (option_set ?x - object ?y - object)
    (group_gid_set ?x - object ?y - object)
    (journal_access_granted ?x - object ?y - object)
    (cohort_keys_created ?x - object ?y - object)
    (package_hold ?x - object ?y - object)
    (file_access_time_updated ?x - object ?y - object)
    (package_half_configured ?x - object ?y - object)
    (directory_has_sticky_bit ?x - object ?y - object)
    (supplementary_groups_set ?x - object ?y - object)
    (subids_added ?x - object ?y - object)
    (full_path_used ?x - object ?y - object)
    (dir_exists ?x - object ?y - object)
    (copy_performed ?x - object ?y - object)
    (GID_MAX ?x - object ?y - object)
    (package_index_up_to_date ?x - object ?y - object)
    (executed_as_root ?x - object ?y - object)
    (file_grouped_by ?x - object ?y - object)
    (assert_consistent_with_database ?x - object ?y - object)
    (proper_permissions ?x - object ?y - object)
    (file_accessed ?x - object ?y - object)
    (home_directory_not_created ?x - object ?y - object)
    (group_members ?x - object ?y - object)
    (file_owned_by ?x - object ?y - object)
    (configures ?x - object ?y - object)
    (password_expiration_warning ?x - object ?y - object)
    (assert_signature_verified ?x - object ?y - object)
    (file_grouped_as ?x - object ?y - object)
    (home_directory_created ?x - object ?y - object)
    (sys_gid_max ?x - object ?y - object)
    (SYS_GID_MIN ?x - object ?y - object)
    (refcnt_set ?x - object ?y - object)
    (group_entry_split ?x - object ?y - object)
    (pretty_json_output_enabled ?x - object ?y - object)
    (shell_set ?x - object ?y - object)
    (path_initialized ?x - object ?y - object)
    (SYS_GID_MAX ?x - object ?y - object)
    (system_unit_files_modified ?x - object ?y - object)
    (sparse_files_disabled ?x - object ?y - object)
    (file_writable ?x - object ?y - object)
    (default_target ?x - object ?y - object)
    (action_executed ?x - object ?y - object)
    (network_namespace_set ?x - object ?y - object)
    (address_valid ?x - object ?y - object)
    (child_running ?x - object ?y - object)
    (timer_set ?x - object ?y - object)
    (rlimit_nofile ?x - object ?y - object)
    (mail_dir_changed ?x - object ?y - object)
    (file_copied ?x - object ?y - object)
    (file_updated ?x - object ?y - object)
    (all ?x - object ?y - object)
    (file_user_id_changed ?x - object ?y - object)
    (packages_updated ?x - object ?y - object)
    (user_prompted ?x - object ?y - object)
    (new_group_set ?x - object ?y - object)
    (protocol_set ?x - object ?y - object)
    (at_jobs_removed ?x - object ?y - object)
    (gid_valid ?x - object ?y - object)
    (string_valid ?x - object ?y - object)
    (protocol_family_set ?x - object ?y - object)
    (system_user ?x - object ?y - object)
    (file_downloaded ?x - object ?y - object)
    (available_packages_info_cleared ?x - object ?y - object)
    (available_packages_info_merged ?x - object ?y - object)
    (user_primary_group ?x - object ?y - object)
    (unit_edited ?x - object ?y - object)
    (snap_exists ?x - object ?y - object)
    (default_values_modified ?x - object ?y - object)
    (non_negative ?x - object ?y - object)
    (can_escalate ?x - object ?y - object)
    (network_available ?x - object ?y - object)
    (package_installed ?x - object ?y - object)
    (service_running ?x - object ?y - object)
    (package_configured ?x - object ?y - object)
    (sys_gid_min ?x - object ?y - object)
    (unique_names_not_required ?x - object ?y - object)
    (same_file ?x - object ?y - object)
    (problems_encountered ?x - object ?y - object)
    (system_rebooted ?x - object ?y - object)
    (package_index_outdated ?x - object ?y - object)
    (interface_up ?x - object ?y - object)
    (group_defaults_set ?x - object ?y - object)
    (wide_output_enabled ?x - object ?y - object)
    (account_locked ?x - object ?y - object)
    (dir_removed ?x - object ?y - object)
    (file_has_sticky_bit ?x - object ?y - object)
    (user_in_group ?x - object ?y - object)
    (package_reinstalled ?x - object ?y - object)
    (journal_files_rotated ?x - object ?y - object)
    (length(?n ?x - object ?y - object)
    (system_powered_off ?x - object ?y - object)
    (repository_valid ?x - object ?y - object)
    (password_expiration_grace_period ?x - object ?y - object)
    (system_suspended ?x - object ?y - object)
    (file_attributes_equal ?x - object ?y - object)
    (mail_spool_created_or_updated_or_deleted ?x - object ?y - object)
    (proper_selinux_context ?x - object ?y - object)
    (system_hibernated_and_suspended ?x - object ?y - object)
    (preserved_attributes ?x - object ?y - object)
    (numeric_addresses_enabled ?x - object ?y - object)
    (directory_preserves_permissions ?x - object ?y - object)
    (group_line_reached ?x - object ?y - object)
    (user_expire_date_updated ?x - object ?y - object)
    (umask_set ?x - object ?y - object)
    (instance_exited ?x - object ?y - object)
    (problems_overridden ?x - object ?y - object)
    (file_exists ?x - object ?y - object)
    (time_valid ?x - object ?y - object)
    (defs_set ?x - object ?y - object)
    (alias_not_exists ?x - object ?y - object)
    (config_options_removed ?x - object ?y - object)
    (account_unlocked ?x - object ?y - object)
    (timestamp_format_changed ?x - object ?y - object)
    (user_supplementary_groups ?x - object ?y - object)
    (plug_exists ?x - object ?y - object)
    (sys_uid_max ?x - object ?y - object)
    (option_exists ?x - object ?y - object)
    (channel_available ?x - object ?y - object)
    (self_terminated ?x - object ?y - object)
    (disk_image_operated ?x - object ?y - object)
    (no_password_defined ?x - object ?y - object)
    (system_upgraded ?x - object ?y - object)
    (file_contents_equal ?x - object ?y - object)
    (files_moved ?x - object ?y - object)
    (print_jobs_removed ?x - object ?y - object)
    (selinux_user_set ?x - object ?y - object)
    (package_manually_installed ?x - object ?y - object)
    (unit_file_exists ?x - object ?y - object)
    (user_changed ?x - object ?y - object)
    (initial_files_copied ?x - object ?y - object)
    (password_policy_respected ?x - object ?y - object)
    (package_upgraded ?x - object ?y - object)
    (journal_source ?x - object ?y - object)
    (package_cache_cleaned ?x - object ?y - object)
    (system_halted ?x - object ?y - object)
    (badname_enabled ?x - object ?y - object)
    (architecture_added ?x - object ?y - object)
    (package_compiled ?x - object ?y - object)
    (pseudo_terminal_enabled ?x - object ?y - object)
    (unit_enabled ?x - object ?y - object)
    (configuration_variables_missing ?x - object ?y - object)
    (service_exists ?x - object ?y - object)
    (system_files_updated ?x - object ?y - object)
    (group_exists ?x - object ?y - object)
    (package_cache_autocleaned ?x - object ?y - object)
    (journal_data_flushed ?x - object ?y - object)
    (signal_received ?x - object ?y - object)
    (rlimit_rtprio ?x - object ?y - object)
    (file_modification_time_updated ?x - object ?y - object)
    (max_members_per_group ?x - object ?y - object)
    (manager_reexecuted ?x - object ?y - object)
    (dependencies_ignored ?x - object ?y - object)
    (script_executed ?x - object ?y - object)
    (root_filesystem_changed ?x - object ?y - object)
    (file_renamed ?x - object ?y - object)
    (user_account_expired ?x - object ?y - object)
    (numeric_port_numbers_enabled ?x - object ?y - object)
    (groupname_set ?x - object ?y - object)
    (file_modified ?x - object ?y - object)
    (snap_installed ?x - object ?y - object)
    (output_format_single_line ?x - object ?y - object)
    (config_applied ?x - object ?y - object)
    (user_account_modified_or_deleted ?x - object ?y - object)
    (user_password_locked ?x - object ?y - object)
    (alias_created ?x - object ?y - object)
    (base_directory_set ?x - object ?y - object)
    (sys_uid_min ?x - object ?y - object)
    (member_of ?x - object ?y - object)
    (snap_updated ?x - object ?y - object)
    (lastlog_uid_max_changed ?x - object ?y - object)
    (file_linked_to ?x - object ?y - object)
    (password_changed_recently ?x - object ?y - object)
    (new_account ?x - object ?y - object)
    (snap_refreshed ?x - object ?y - object)
    (user_subgids_updated ?x - object ?y - object)
    (assert_valid ?x - object ?y - object)
    (link_created ?x - object ?y - object)
    (problems_refused ?x - object ?y - object)
    (file_has_default_SELinux_context ?x - object ?y - object)
    (user_removed ?x - object ?y - object)
    (symbolic_link ?x - object ?y - object)
    (unavailable_packages_forgetten ?x - object ?y - object)
    (no ?x - object ?y - object)
    (sources_list_valid ?x - object ?y - object)
    (package_triggers-awaited ?x - object ?y - object)
    (unit_exists ?x - object ?y - object)
    (package_triggers-pending ?x - object ?y - object)
    (log_threshold_set ?x - object ?y - object)
    (unique ?x - object ?y - object)
    (package_exists ?x - object ?y - object)
    (system_hibernated ?x - object ?y - object)
    (package_removed ?x - object ?y - object)
    (snap_in_development_mode ?x - object ?y - object)
    (assert_added ?x - object ?y - object)
    (file_attr_set ?x - object ?y - object)
    (account_created ?x - object ?y - object)
    (package_recorded ?x - object ?y - object)
    (log_target_set ?x - object ?y - object)
    (user_uid_set ?x - object ?y - object)
    (filesystem_mounted ?x - object ?y - object)
    (applied_config_sent ?x - object ?y - object)
    (rlimit_as ?x - object ?y - object)
    (password_expired ?x - object ?y - object)
    (dependency_added ?x - object ?y - object)
    (socket_closed ?x - object ?y - object)
    (alias_removed ?x - object ?y - object)
    (verbose_mode_enabled ?x - object ?y - object)
    (directory_removed ?x - object ?y - object)
    (family_supported ?x - object ?y - object)
    (journal_namespace_set ?x - object ?y - object)
    (directory_executable ?x - object ?y - object)
    (new_package_versions_available ?x - object ?y - object)
    (dpkg_b_available ?x - object ?y - object)
    (unit_running ?x - object ?y - object)
    (rlimit_fsize ?x - object ?y - object)
    (last_change_of_type ?x - object ?y - object)
    (firewall_rule_exists ?x - object ?y - object)
    (directory_exists ?x - object ?y - object)
    (file_replacement_controlled ?x - object ?y - object)
    (group_account_modified ?x - object ?y - object)
    (user_home_directory_changed ?x - object ?y - object)
    (fss_sealing_key_changed ?x - object ?y - object)
    (service_enabled ?x - object ?y - object)
    (userspace_rebooted ?x - object ?y - object)
    (user_comment_updated ?x - object ?y - object)
    (manager_reloaded ?x - object ?y - object)
    (image_policy_set ?x - object ?y - object)
    (user_locked ?x - object ?y - object)
    (GID_MIN ?x - object ?y - object)
    (sources_list_edited ?x - object ?y - object)
    (connection_exists ?x - object ?y - object)
    (boot_start_disabled ?x - object ?y - object)
    (directory_created ?x - object ?y - object)
    (numeric_host_addresses_enabled ?x - object ?y - object)
    (snap_channel_switched ?x - object ?y - object)
    (log_directory_on_root_mount ?x - object ?y - object)
    (group_key_set ?x - object ?y - object)
    (files_copied ?x - object ?y - object)
    (new_version_available ?x - object ?y - object)
    (port_valid ?x - object ?y - object)
    (backup_suffix_set ?x - object ?y - object)
    (operation_stopped ?x - object ?y - object)
    (user_deleted ?x - object ?y - object)
    (interface_exists ?x - object ?y - object)
    (presets_applied ?x - object ?y - object)
    (primary_group_set ?x - object ?y - object)
    (available_packages_info_updated ?x - object ?y - object)
    (package_downloaded ?x - object ?y - object)
    (repository_exists ?x - object ?y - object)
    (user_exists ?x - object ?y - object)
    (rlimit_nice ?x - object ?y - object)
    (aliases_disabled ?x - object ?y - object)
    (systemd_configured ?x - object ?y - object)
    (netlink_socket_receive_buffer_size ?x - object ?y - object)
    (usergroups_enabled ?x - object ?y - object)
    (fss_sealing_key_exists ?x - object ?y - object)
    (subgids_assigned ?x - object ?y - object)
    (user_allocated_subordinate_uids ?x - object ?y - object)
    (journal_entry ?x - object ?y - object)
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
      (package_build_deps_installed ?pkg)
    )
  )

  (:action clean
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_cache_cleaned)
    )
  )

  (:action autoclean
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_cache_autocleaned)
    )
  )

  (:action autoremove
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_removed ?pkg)
    )
  )

  (:action update_package_index
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (apt_sources_list_valid)
      (package_index_outdated)
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

  (:action remove_packages
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (file_exists /var/lib/dpkg/status)
      (can_escalate ?actor)
    )
    :effect (and
      (package_removed ?pkg)
      (file_removed ?f)
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

  (:action download_source_package
    :parameters (?actor - user ?pkg - file)
    :precondition (and
      (package_exists ?pkg)
      (sources_list_valid)
      (can_escalate ?actor)
    )
    :effect (and
      (package_downloaded ?pkg)
    )
  )

  (:action compile_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_exists ?pkg)
      (dpkg_b_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_compiled ?pkg)
    )
  )

  (:action download_file
    :parameters (?actor - user ?f - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_downloaded ?f)
    )
  )

  (:action update_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (packages_updated)
    )
  )

  (:action configure_repositories
    :parameters (?actor - user ?repo - file)
    :precondition (and
      (repository_exists ?repo)
      (not (repository_valid ?repo))
      (can_escalate ?actor)
    )
    :effect (and
      (repository_valid ?repo)
    )
  )

  (:action configure_release_info_change
    :parameters (?actor - user ?repo - file)
    :precondition (and
      (repository_exists ?repo)
      (not (release_info_changed ?repo))
      (can_escalate ?actor)
    )
    :effect (and
      (release_info_changed ?repo)
    )
  )

  (:action reinstall_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_reinstalled ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_reinstalled ?pkg)
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

  (:action edit_sources_list
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (sources_list_edited)
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
      (not (package_upgraded ?pkg))
    )
  )

  (:action full_upgrade_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (not (package_upgraded ?pkg))
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

  (:action upgrade_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (new_version_available ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg
      new_version ?pkg)
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
      (package_selected_for_install ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_hold ?pkg)
    )
  )

  (:action unpack_package
    :parameters (?actor - user ?pkg - package ?dir - directory)
    :precondition (and
      (file_exists ?pkg)
      (dir_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (file_unpacked ?new_files)
      (file_removed ?old_files)
      (script_executed ?trigger_scripts)
    )
  )

  (:action set_package_selections
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_selections_set ?p)
    )
  )

  (:action clear_package_selections
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_selections_cleared ?p)
    )
  )

  (:action record_availability
    :parameters (?actor - user ?pkg - package)
    :precondition (and
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

  (:action add_architecture
    :parameters (?arch - file)
    :precondition (and
    )
    :effect (and
      (architecture_added ?arch)
    )
  )

  (:action remove_architecture
    :parameters (?arch - file)
    :precondition (and
    )
    :effect (and
      (architecture_removed ?arch)
    )
  )

  (:action ignore_dependencies
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (dependencies_ignored ?pkg)
    )
  )

  (:action force_override
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (problems_overridden)
    )
  )

  (:action stop_on_problems
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (problems_encountered)
    )
  )

  (:action refuse_continue
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (problems_refused)
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

  (:action add_assertion
    :parameters (?actor - user ?assert - file)
    :precondition (and
      (assert_valid ?assert)
      (assert_signature_verified ?assert)
      (assert_consistent_with_database ?assert)
      (can_escalate ?actor)
    )
    :effect (and
      (assert_added ?assert)
    )
  )

  (:action create_alias
    :parameters (?app - file ?alias - file)
    :precondition (and
      (alias_not_exists ?alias)
    )
    :effect (and
      (alias_created ?app ?alias)
    )
  )

  (:action connect_interface
    :parameters (?snap - interface ?plug - interface)
    :precondition (and
      (snap_exists ?snap)
      (plug_exists ?plug)
      (slot_exists ?slot)
      (not (connection_exists ?snap ?plug))
    )
    :effect (and
      (connection_exists ?snap ?plug)
    )
  )

  (:action create_cohort_keys
    :parameters (?snaps - package)
    :precondition (and
      (snaps_exists ?snaps)
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

  (:action disable_boot_start
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (snap_exists ?snap)
      (boot_start_enabled ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (boot_start_disabled ?snap)
    )
  )

  (:action select_last_change
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (last_change_of_type ?change)
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

  (:action remove_aliases
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (aliases_disabled ?snap)
    )
  )

  (:action unset_config
    :parameters (?actor - user ?snap - file ?option - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (config_options_removed ?snap
      ?option)
    )
  )

  (:action install_snaps
    :parameters (?actor - user ?snaps - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (snap_installed ?snaps)
    )
  )

  (:action remove_snaps
    :parameters (?actor - user ?snaps - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (snap_installed ?snaps))
    )
  )

  (:action refresh_snaps
    :parameters (?actor - user ?snaps - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (snap_updated ?snaps)
    )
  )

  (:action start_services
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
    )
  )

  (:action stop_services
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?svc))
    )
  )

  (:action restart_services
    :parameters (?actor - user ?svc - service)
    :precondition (and
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
      (log_threshold_set ?level)
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

  (:action set_watchdog_state
    :parameters (?actor - user ?state - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (watchdog_state_set ?state)
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

  (:action exit_instance
    :parameters (?EXIT_CODE - file)
    :precondition (and
    )
    :effect (and
      (instance_exited)
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
      (systemd_configured)
      (can_escalate ?actor)
    )
    :effect (and
      (systemd_configured)
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
      (system_unit_files_modified)
    )
  )

  (:action edit_system_units_runtime
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_unit_files_modified)
    )
  )

  (:action override_symlinks
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (symlink_overridden)
    )
  )

  (:action execute_immediately
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (action_executed)
    )
  )

  (:action apply_presets
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (presets_applied)
    )
  )

  (:action edit_system_units_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_unit_files_modified)
    )
  )

  (:action edit_system_units_image
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_unit_files_modified)
    )
  )

  (:action set_image_policy
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (image_policy_set)
    )
  )

  (:action change_timestamp_format
    :parameters (?actor - user ?format - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (timestamp_format_changed)
    )
  )

  (:action create_read_only_bind_mount
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (read_only_bind_mount_created)
    )
  )

  (:action create_directory_before_mounting
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (directory_created)
    )
  )

  (:action restart_reload_marked_units
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (marked_units_restarted)
    )
  )

  (:action edit_unit_files
    :parameters (?actor - user ?name - file ?time - file)
    :precondition (and
      (unit_file_exists ?name)
      (time_valid ?time)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_file_modified ?name)
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

  (:action write_to_journal
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (journal_entry ?entry)
    )
  )

  (:action set_journal_source
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_source ?source)
    )
  )

  (:action operate_on_journal_files
    :parameters (?actor - user ?jfiles - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_files_operated ?jfiles)
    )
  )

  (:action operate_on_disk_image
    :parameters (?actor - user ?img - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (disk_image_operated ?img)
    )
  )

  (:action set_journal_namespace
    :parameters (?actor - user ?ns - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_namespace_set ?ns)
    )
  )

  (:action change_fss_sealing_key
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (fss_sealing_key_exists)
      (not (fss_sealing_key_changed))
      (can_escalate ?actor)
    )
    :effect (and
      (fss_sealing_key_changed)
    )
  )

  (:action relinquish_log
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (log_to_temporary_file_system)
    )
  )

  (:action smart_relinquish_log
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (log_directory_on_root_mount)
      (can_escalate ?actor)
    )
    :effect (and
      (log_to_temporary_file_system)
    )
  )

  (:action flush_journal_data
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_data_flushed)
    )
  )

  (:action rotate_journal_files
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_files_rotated)
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
    :parameters (?f - file ?b - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?b)
    )
    :effect (and
      (file_exists ?b)
      (file_contents_equal ?f ?b)
    )
  )

  (:action copy_special_file_contents
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (file_contents_equal ?src ?dst)
    )
  )

  (:action copy_attributes_only
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_attributes_equal ?f)
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
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
      (not (file_exists ?link))
    )
    :effect (and
      (file_exists ?link)
      (file_linked_to ?f ?link)
    )
  )

  (:action follow_symbolic_link
    :parameters (?src - file)
    :precondition (and
      (file_exists ?src)
      (symbolic_link ?src)
    )
    :effect (and
      (not (symbolic_link ?src))
    )
  )

  (:action preserve_file_attributes
    :parameters (?f - file ?attr - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (preserved_attributes ?f ?attr)
    )
  )

  (:action do_not_overwrite_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_overwritten ?f))
    )
  )

  (:action prompt_before_overwrite
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (user_prompted ?f)
    )
  )

  (:action remove_existing_file_and_try_again
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (not (file_overwritten ?f))
    )
    :effect (and
      (file_removed ?f)
    )
  )

  (:action use_full_source_file_name_under_directory
    :parameters (?src - file ?dir - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dir)
    )
    :effect (and
      (full_path_used ?src ?dir)
    )
  )

  (:action copy_directory
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

  (:action create_symbolic_link
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (link_created ?src ?dst)
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
      (file_exists ?src)
      (dir_exists ?dst)
    )
    :effect (and
      (files_copied ?src ?dst)
    )
  )

  (:action enable_verbose_mode
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (verbose_mode_enabled)
    )
  )

  (:action set_security_context
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_has_default_SELinux_context ?f)
    )
  )

  (:action set_sparse_creation
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (sparse_files_disabled)
    )
  )

  (:action set_file_replacement
    :parameters (?op - file)
    :precondition (and
    )
    :effect (and
      (file_replacement_controlled)
    )
  )

  (:action set_copy_type
    :parameters (?type - file)
    :precondition (and
    )
    :effect (and
      (copy_performed)
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
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
      (symbolic_link ?f)
    )
    :effect (and
      (not (symbolic_link ?f))
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

  (:action remove_existing_file
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
      (not (file_exists ?dst))
    )
    :effect (and
      (file_removed ?f)
      (file_copied ?f ?dst)
    )
  )

  (:action ignore_symbolic_links
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
      (symbolic_link ?f)
    )
    :effect (and
      (not (symbolic_link ?f))
    )
  )

  (:action follow_symbolic_links
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
      (symbolic_link ?f)
    )
    :effect (and
      (not (symbolic_link ?f))
    )
  )

  (:action create_hard_links
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
      (not (file_exists ?link))
    )
    :effect (and
      (file_exists ?link)
      (file_linked_to ?f ?link)
    )
  )

  (:action always_dereference_links
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
      (symbolic_link ?f)
    )
    :effect (and
      (not (symbolic_link ?f))
    )
  )

  (:action copy_files
    :parameters (?src - file ?dst - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dst)
    )
    :effect (and
      (file_exists ?dst/?.?src)
    )
  )

  (:action update_files
    :parameters (?all - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_updated ?f)
    )
  )

  (:action set_file_attributes
    :parameters (?attr - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_attr_set ?f ?attr)
    )
  )

  (:action make_backup
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (same_file ?src ?dest)
    )
    :effect (and
      (backup_created ?src ?dest)
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

  (:action move_files_to_directory
    :parameters (?files - file ?dir - directory)
    :precondition (and
    )
    :effect (and
      (files_moved ?files ?dir)
    )
  )

  (:action set_permissions
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action update_file_contents
    :parameters (?f - file ?content - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_contents_equal ?f {content})
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

  (:action force_delete_file
    :parameters (?file - file)
    :precondition (and
      (file_exists ?f)
      (not (is_directory ?f))
    )
    :effect (and
      (file_removed ?f)
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

  (:action prompt_before_removal
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (file_exists ?f)
      (not (file_removed ?f))
      (can_escalate ?actor)
    )
    :effect (and
      (file_removed ?f)
    )
  )

  (:action prompt_once_before_removal
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (file_exists ?f)
      (not (file_removed ?f))
      (can_escalate ?actor)
    )
    :effect (and
      (file_removed ?f)
    )
  )

  (:action prompt_always_before_removal
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (file_exists ?f)
      (not (file_removed ?f))
      (can_escalate ?actor)
    )
    :effect (and
      (file_removed ?f)
    )
  )

  (:action remove_directories_recursive
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (dir_exists ?d)
      (not (dir_removed ?d))
      (can_escalate ?actor)
    )
    :effect (and
      (dir_removed ?d)
    )
  )

  (:action remove_empty_directories
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (dir_exists ?d)
      (empty_dir ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (dir_removed ?d)
    )
  )

  (:action remove_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (file_exists ?dir)
      (not (is_directory_empty ?dir))
      (can_escalate ?actor)
    )
    :effect (and
      (directory_removed ?dir)
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
      (file_has_sticky_bit ?f)
      (directory_has_sticky_bit ?d)
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

  (:action recursive_change_permissions
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_executable ?dir)
      (file_executable ?f) for all files in ?dir
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
    :parameters (?actor - user ?f - file ?o - user ?g - group)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?o ?f)
      (file_grouped_as ?g ?f)
    )
  )

  (:action change_owner_group
    :parameters (?actor - user ?f - file ?o - user ?g - group)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?o ?f)
      (file_grouped_by ?g ?f)
    )
  )

  (:action preserve_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (operation_stopped ?)
    )
  )

  (:action recursive_operation
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (operation_recursive ?)
    )
  )

  (:action reference_ownership
    :parameters (?actor - user ?rfile - file)
    :precondition (and
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (new_owner_set ?rfile)
      (new_group_set ?rfile)
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
      (output_format_single_line)
    )
  )

  (:action set_network_namespace
    :parameters (?actor - user ?ns - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (network_namespace_set ?ns)
    )
  )

  (:action set_socket_receive_buffer_size
    :parameters (?actor - user ?size - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (netlink_socket_receive_buffer_size ?size)
    )
  )

  (:action set_rate_units
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (rate_units_IEC)
    )
  )

  (:action output_json
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (json_output_enabled)
    )
  )

  (:action output_pretty_json
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (pretty_json_output_enabled)
    )
  )

  (:action send_applied_config
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (applied_config_sent)
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
    :parameters (?f - file ?a - file ?p - port)
    :precondition (and
      (family_supported ?f)
      (address_valid ?a)
      (port_valid ?p)
    )
    :effect (and
      (host_syntax_modified ?f ?a ?p)
    )
  )

  (:action set_verbose_mode
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (verbose_mode_enabled)
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

  (:action set_timer
    :parameters (?actor - user ?t - file)
    :precondition (and
      (socket_exists ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (timer_set ?s ?t)
    )
  )

  (:action set_protocol
    :parameters (?actor - user ?p - file)
    :precondition (and
      (socket_exists ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (protocol_set ?s ?p)
    )
  )

  (:action set_refcnt
    :parameters (?actor - user ?r - file)
    :precondition (and
      (socket_exists ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (refcnt_set ?s ?r)
    )
  )

  (:action mount_filesystem
    :parameters (?actor - user ?mnt_point - directory ?fs_type - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (filesystem_mounted ?mnt_point)
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

  (:action switch_user
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_changed ?usr)
    )
  )

  (:action set_limits
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (since_version 2.38)
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
      (shell_set ?shell)
    )
  )

  (:action set_session_command
    :parameters (?actor - user ?cmd - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (session_created ?s)
    )
  )

  (:action terminate_process
    :parameters (?actor - user ?pid - process)
    :precondition (and
      (child_running ?pid)
      (signal_received ?sig)
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
      (group_exists ?usr)
    )
  )

  (:action configure_user
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (system_files_updated)
      (home_directory_created)
      (initial_files_copied)
    )
  )

  (:action set_badname_option
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (badname_enabled)
    )
  )

  (:action set_base_dir
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (base_directory_set ?dir)
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

  (:action set_user_primary_group
    :parameters (?actor - user ?usr - user ?grp - group)
    :precondition (and
      (user_exists ?usr)
      (group_exists ?grp)
      (can_escalate ?actor)
    )
    :effect (and
      (user_primary_group ?usr ?grp)
    )
  )

  (:action set_user_supplementary_groups
    :parameters (?actor - user ?usr - user ?grp - group)
    :precondition (and
      (user_exists ?usr)
      (group_exists ?grp)
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_group ?usr ?grp)
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
      (not (defs_set))
      (can_escalate ?actor)
    )
    :effect (and
      (defs_set)
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
      (not (group_line_reached ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (group_line_reached ?g)
    )
  )

  (:action set_password_expiration_limit
    :parameters (?actor - user ?days - file)
    :precondition (and
      (not (password_expired ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (password_expired ?user)
    )
  )

  (:action set_minimum_password_change_interval
    :parameters (?actor - user ?days - file)
    :precondition (and
      (not (password_changed_recently ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (password_changed_recently ?user)
    )
  )

  (:action set_password_expiration_warning
    :parameters (?actor - user ?days - file)
    :precondition (and
      (password_expiration_warning ?x)
      (can_escalate ?actor)
    )
    :effect (and
      (password_expiration_warning ?x)
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

  (:action set_gid_range
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (sys_gid_min ?min)
      (sys_gid_max ?max)
    )
  )

  (:action set_uid_range
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (sys_uid_min ?min)
      (sys_uid_max ?max)
    )
  )

  (:action set_umask
    :parameters (?actor - user ?num - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (umask_set ?num)
    )
  )

  (:action set_usergroups_enable
    :parameters (?actor - user ?bool - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (usergroups_enabled ?bool)
    )
  )

  (:action modify_user_account
    :parameters (?actor - user ?login - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_modified ?login)
    )
  )

  (:action modify_group_account
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_account_modified)
    )
  )

  (:action modify_default_values
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_values_modified)
    )
  )

  (:action run_scripts_during_user_addition
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (scripts_run)
    )
  )

  (:action run_scripts_during_user_deletion
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (scripts_run)
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

  (:action no_log_init
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (new_account)
      (can_escalate ?actor)
    )
    :effect (and
      (log_init_not_performed)
    )
  )

  (:action non_unique
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (new_account)
      (can_escalate ?actor)
    )
    :effect (and
      (unique_names_not_required)
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

  (:action append_to_group
    :parameters (?actor - user ?g - group ?u - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_group ?u ?g)
    )
  )

  (:action update_comment
    :parameters (?actor - user ?c - file ?u - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_comment_updated ?u ?c)
    )
  )

  (:action change_home_directory
    :parameters (?actor - user ?h - directory ?u - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_home_directory_changed ?u ?h)
    )
  )

  (:action update_expire_date
    :parameters (?actor - user ?e - file ?u - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_expire_date_updated ?u ?e)
    )
  )

  (:action set_user_expiration
    :parameters (?actor - user ?date - file)
    :precondition (and
      (file_exists /etc/shadow)
      (can_escalate ?actor)
    )
    :effect (and
      (user_account_expired ?date)
    )
  )

  (:action set_password_expiration_grace_period
    :parameters (?actor - user ?days - file)
    :precondition (and
      (file_exists /etc/shadow)
      (can_escalate ?actor)
    )
    :effect (and
      (password_expiration_grace_period ?days)
    )
  )

  (:action change_groups
    :parameters (?actor - user ?uid - user ?gid - group ?gids - file)
    :precondition (and
      (user_exists ?uid)
      (group_exists ?gid)
      (all (?g in ?gids) (group_exists ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (user_primary_group ?uid ?gid)
      (user_supplementary_groups ?uid ?gids)
    )
  )

  (:action change_user_settings
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_locked ?usr)
      (user_home_directory_changed ?usr)
    )
  )

  (:action lock_user_account
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (not (user_locked ?usr))
      (can_escalate ?actor)
    )
    :effect (and
      (user_locked ?usr)
    )
  )

  (:action modify_user
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (not (process_running ?usr))
      (not (nis_changes_needed))
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

  (:action change_user_shell
    :parameters (?actor - user ?u - user ?s - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_shell_set ?u ?s)
    )
  )

  (:action change_user_uid
    :parameters (?actor - user ?u - user ?uid - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_uid_set ?u ?uid)
    )
  )

  (:action change_uid
    :parameters (?actor - user ?uid - file)
    :precondition (and
      (non_negative ?uid)
      (unique ?uid
      -o)
      (can_escalate ?actor)
    )
    :effect (and
      (file_user_id_changed ?f) for all files owned by the user and located in their home directory
    )
  )

  (:action unlock_password
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_password_locked)
      (can_escalate ?actor)
    )
    :effect (and
      (user_password_unlocked)
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
    :parameters (?actor - user ?first-last - file)
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
    :parameters (?actor - user ?first-last - file)
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
    :parameters (?actor - user ?first-last - file)
    :precondition (and
      (user_exists)
      (not (subgids_assigned ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (subgids_assigned ?user)
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
      (user_subgids_updated ?uid ?rg)
    )
  )

  (:action set_selinux_user
    :parameters (?actor - user ?seuser - file ?uid - user)
    :precondition (and
      (user_exists ?uid)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_user_set ?uid ?seuser)
    )
  )

  (:action change_lastlog_uid_max
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (lastlog_uid_max_changed)
    )
  )

  (:action change_mail_dir
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (mail_dir_changed)
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
      (mail_spool_created_or_updated_or_deleted)
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

  (:action run_userdel_cmd
    :parameters (?actor - user ?user - process)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_removed ?user)
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

  (:action run_scripts
    :parameters (?actor - user ?scripts - directory)
    :precondition (and
      (user_exists ?u)
      (not (user_deleted ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_deleted ?u)
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

  (:action change_groupname
    :parameters (?actor - user ?g - group ?n - file)
    :precondition (and
      (group_exists ?g)
      (string_valid ?n)
      (length(?n) <= 32)
      (can_escalate ?actor)
    )
    :effect (and
      (groupname_set ?g ?n)
    )
  )

  (:action change_group_gid
    :parameters (?actor - user ?g - group ?g - file)
    :precondition (and
      (group_exists ?g)
      (gid_valid ?gid)
      (can_escalate ?actor)
    )
    :effect (and
      (group_gid_set ?g ?gid)
    )
  )

  (:action set_group_key
    :parameters (?actor - user ?g - group ?k - file)
    :precondition (and
      (group_exists ?g)
      (string_valid ?k)
      (can_escalate ?actor)
    )
    :effect (and
      (group_key_set ?g ?k)
    )
  )

  (:action set_group_defaults
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (group_exists ?gid)
      (not (group_defaults_set ?gid))
      (can_escalate ?actor)
    )
    :effect (and
      (group_defaults_set ?gid)
    )
  )

  (:action add_users_to_group
    :parameters (?actor - user ?users - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_members ?gid ?users)
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