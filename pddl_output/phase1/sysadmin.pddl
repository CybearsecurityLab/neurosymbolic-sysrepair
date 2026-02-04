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
    (sources_list_modified)
    (package_info_updated)
    (packages_upgraded)
    (packages_full_upgraded)
    (dependencies_satisfied ?x0 - object)
    (sources_list_updated)
    (source_files_downloaded ?x0 - object)
    (build_dependencies_installed ?x0 - object)
    (package_files_downloaded ?x0 - object)
    (cache_exists)
    (cache_cleaned)
    (cache_dist_cleaned)
    (cache_autocleaned)
    (package_lists_updated)
    (unused_packages_exist)
    (package_cache_exists)
    (package_downloaded ?x0 - object)
    (system_upgraded)
    (package_reverted ?x0 - object)
    (package_enabled ?x0 - object)
    (can_read_system_journal ?x0 - object)
    (directory_exists ?x0 - object)
    (journal_directory_modified ?x0 - object)
    (journal_file_modified ?x0 - object)
    (can_read_private_journal ?x0 - object)
    (can_read_other_user_journal ?x0 - object)
    (journal_operated_on ?x0 - object)
    (file_glob_specified ?x0 - object)
    (path_exists ?x0 - object)
    (journalctl_operates_on_specified_paths ?x0 - object)
    (journalctl_root_set_to ?x0 - object)
    (journalctl_image_set_to ?x0 - object)
    (disk_image_exists ?x0 - object)
    (file_systems_mounted ?x0 - object)
    (log_data_extracted ?x0 - object)
    (journal_records_exist)
    (filtered_journal_records ?x0 - object)
    (pager_secure_mode_enabled ?x0 - object)
    (pager_used ?x0 - object)
    (less_charset_set ?x0 - object)
    (environment_variable_set ?x0 - object ?x1 - object)
    (pager_disabled)
    (secure_mode_enabled)
    (colors_enabled)
    (base_16_colors_enabled)
    (base_256_colors_enabled)
    (urlify_setting ?x0 - object)
    (disk_usage_below ?x0 - object)
    (journal_files_left ?x0 - object)
    (journal_files_removed_older_than ?x0 - object)
    (journal_synchronized_to_disk)
    (logging_to_temporary_file_system)
    (logging_to_temporary_file_system_if_not_root_mount)
    (journal_data_flushed_to_var)
    (journal_files_rotated)
    (catalog_updated)
    (fss_keys_generated)
    (file_has_mode ?x0 - object ?x1 - object)
    (is_symbolic_link ?x0 - object)
    (file_executable ?x0 - object)
    (group_matches_effective_gid ?x0 - object ?x1 - object)
    (group_matches_supplementary_gids ?x0 - object ?x1 - object)
    (set_group_id_cleared ?x0 - object)
    (directory_setuid ?x0 - object)
    (directory_setgid ?x0 - object)
    (directory_sticky_bit ?x0 - object)
    (file_mode_set ?x0 - object ?x1 - object)
    (directory_has_mode ?x0 - object ?x1 - object)
    (output_diagnostic ?x0 - object)
    (no_special_treatment_root)
    (fail_on_recursive_root)
    (owned_by_user ?x0 - object ?x1 - object)
    (owned_by_group ?x0 - object ?x1 - object)
    (file_owner ?x0 - object ?x1 - object)
    (file_group ?x0 - object ?x1 - object)
    (preserve_root)
    (directory_owner ?x0 - object ?x1 - object)
    (directory_group ?x0 - object ?x1 - object)
    (directory_traversed ?x0 - object)
    (directory_mode_set ?x0 - object ?x1 - object)
    (directory_selinux_context_set ?x0 - object ?x1 - object)
    (default_selinux_context_set ?x0 - object)
    (custom_security_context_set ?x0 - object)
    (file_access_time_updated ?x0 - object)
    (file_modification_time_updated ?x0 - object)
    (file_time_set ?x0 - object ?x1 - object)
    (file_time_attribute_set ?x0 - object ?x1 - object)
    (file_modified_at ?x0 - object ?x1 - object)
    (pam_configured ?x0 - object)
    (user_executed_command ?x0 - object ?x1 - object)
    (resource_limits_reset ?x0 - object)
    (user_primary_group ?x0 - object ?x1 - object)
    (user_supplementary_group ?x0 - object ?x1 - object)
    (shell_is_login ?x0 - object)
    (environment_preserved ?x0 - object)
    (session_has_pty ?x0 - object)
    (session_runs_shell ?x0 - object)
    (shell_executed ?x0 - object)
    (current_user_is ?x0 - object)
    (login_shell_active ?x0 - object)
    (command_executed ?x0 - object)
    (active_shell_is ?x0 - object)
    (primary_group_is ?x0 - object)
    (pseudo_terminal_created ?x0 - object)
    (default_new_user_updated)
    (default_values_set)
    (account_expires_on ?x0 - object ?x1 - object)
    (subuids_updated ?x0 - object)
    (subgids_updated ?x0 - object)
    (all_groups_exist ?x0 - object)
    (user_in_groups ?x0 - object ?x1 - object)
    (home_exists ?x0 - object)
    (acls_copied ?x0 - object)
    (extended_attributes_copied ?x0 - object)
    (login_def_key_exists ?x0 - object)
    (login_def_value_set ?x0 - object)
    (lastlog_exists ?x0 - object)
    (faillog_exists ?x0 - object)
    (lastlog_entry ?x0 - object)
    (faillog_entry ?x0 - object)
    (home_directory_set ?x0 - object ?x1 - object)
    (user_in_group ?x0 - object ?x1 - object)
    (user_has_uid ?x0 - object ?x1 - object)
    (password_set_for_user ?x0 - object)
    (account_locked ?x0 - object)
    (changes_applied_in_chroot ?x0 - object)
    (changes_applied_in_prefix ?x0 - object)
    (user_shell_set ?x0 - object ?x1 - object)
    (user_has_selinux_user ?x0 - object ?x1 - object)
    (default_value_set ?x0 - object ?x1 - object)
    (home_directory_created ?x0 - object)
    (home_directory_mode_set ?x0 - object)
    (gid_min_set ?x0 - object)
    (gid_max_set ?x0 - object)
    (mail_spool_created ?x0 - object)
    (mail_spool_location_set ?x0 - object)
    (group_has_max_members ?x0 - object ?x1 - object)
    (password_has_max_days ?x0 - object ?x1 - object)
    (password_min_days ?x0 - object ?x1 - object)
    (password_warn_age ?x0 - object ?x1 - object)
    (subordinate_gid_min ?x0 - object)
    (subordinate_gid_max ?x0 - object)
    (subordinate_gid_count ?x0 - object)
    (sys_gid_range_valid ?x0 - object ?x1 - object)
    (system_group_created ?x0 - object ?x1 - object ?x2 - object)
    (sys_uid_range_valid ?x0 - object ?x1 - object)
    (system_user_created ?x0 - object ?x1 - object ?x2 - object)
    (uid_range_valid ?x0 - object ?x1 - object)
    (regular_user_created ?x0 - object ?x1 - object ?x2 - object)
    (file_mode_creation_mask ?x0 - object)
    (selinux_mapping_updated ?x0 - object)
    (default_user_config_set)
    (user_has_inactive_period ?x0 - object ?x1 - object)
    (user_has_gecos_field ?x0 - object ?x1 - object)
    (user_has_base_directory ?x0 - object ?x1 - object)
    (user_has_btrfs_subvolume_home ?x0 - object)
    (badname_check_disabled ?x0 - object)
    (subuid_entry_added ?x0 - object)
    (subgid_entry_added ?x0 - object)
    (primary_group_assigned ?x0 - object ?x1 - object)
    (supplementary_groups_assigned ?x0 - object ?x1 - object)
    (no_home_directory_created ?x0 - object)
    (no_user_group_created ?x0 - object)
    (non_unique_user_created ?x0 - object)
    (user_has_shell ?x0 - object ?x1 - object)
    (user_has_password ?x0 - object ?x1 - object)
    (user_has_seuser ?x0 - object ?x1 - object)
    (extra_users_db_used)
    (user_modified ?x0 - object)
    (user_comment_updated ?x0 - object)
    (user_home_changed ?x0 - object)
    (home_directory_moved ?x0 - object)
    (primary_group_changed ?x0 - object ?x1 - object)
    (supplementary_groups_changed ?x0 - object ?x1 - object)
    (password_locked ?x0 - object)
    (ownership_updated ?x0 - object)
    (acl_copied ?x0 - object)
    (non_unique_uid_set ?x0 - object)
    (password_updated ?x0 - object)
    (changes_applied_in_chroot_dir ?x0 - object)
    (changes_applied_in_prefix_dir ?x0 - object)
    (user_shell_changed ?x0 - object ?x1 - object)
    (user_uid_changed ?x0 - object ?x1 - object)
    (password_unlocked ?x0 - object)
    (file_owner_changed ?x0 - object)
    (subuid_range_added ?x0 - object ?x1 - object ?x2 - object)
    (subgid_range_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gids_added ?x0 - object ?x1 - object ?x2 - object)
    (selinux_user_mapped ?x0 - object)
    (process_running_by_user ?x0 - object)
    (user_has_new_id ?x0 - object ?x1 - object)
    (user_has_new_name ?x0 - object ?x1 - object)
    (user_has_new_home_directory ?x0 - object ?x1 - object)
    (lastlog_updated ?x0 - object)
    (mail_directory_set ?x0 - object)
    (mail_spool_deleted ?x0 - object)
    (user_shell ?x0 - object ?x1 - object)
    (user_uid ?x0 - object ?x1 - object)
    (mail_spool_moved ?x0 - object)
    (cron_job_exists ?x0 - object)
    (at_job_exists ?x0 - object)
    (print_job_exists ?x0 - object)
    (group_contains_member ?x0 - object ?x1 - object)
    (scripts_executed ?x0 - object)
    (subgid_updated ?x0 - object)
    (subuid_updated ?x0 - object)
    (selinux_user_mapping_exists ?x0 - object)
    (gid_unique ?x0 - object)
    (group_gid ?x0 - object)
    (group_default_min ?x0 - object)
    (group_default_max ?x0 - object)
    (group_has_password ?x0 - object)
    (sys_gid_min_set ?x0 - object)
    (sys_gid_max_set ?x0 - object)
    (gid_available ?x0 - object)
    (group_has_gid ?x0 - object ?x1 - object)
    (group_file_updated)
    (gid_in_use ?x0 - object)
    (prefix_directory ?x0 - object ?x1 - object)
    (extra_users_db_enabled)
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

  (:action edit_sources_list
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (sources_list_modified)
    )
  )

  (:action update_package_info
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_info_updated)
    )
  )

  (:action upgrade_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (package_info_updated)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_upgraded)
    )
  )

  (:action full_upgrade_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (package_info_updated)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_full_upgraded)
    )
  )

  (:action install_package_before_upgrade
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (package_info_updated)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (packages_upgraded)
    )
  )

  (:action reinstall_package
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

  (:action install_package_release
    :parameters (?actor - user ?pkg - package ?release - file)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action satisfy_dependencies
    :parameters (?actor - user ?dependencies - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (dependencies_satisfied ?dependencies)
    )
  )

  (:action edit_sources
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (sources_list_updated)
    )
  )

  (:action download_source
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (source_files_downloaded ?pkg)
    )
  )

  (:action install_build_dependencies
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (build_dependencies_installed ?pkg)
    )
  )

  (:action download_package_files
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (package_files_downloaded ?pkg)
    )
  )

  (:action clean_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (cache_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (cache_cleaned)
    )
  )

  (:action distclean_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (cache_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (cache_dist_cleaned)
    )
  )

  (:action autoclean_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (cache_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (cache_autocleaned)
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

  (:action autoremove_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (unused_packages_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (not (unused_packages_exist))
    )
  )

  (:action clean_package_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_cache_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_cache_exists))
    )
  )

  (:action download_package
    :parameters (?pkg - package)
    :precondition (and
      (not (package_downloaded ?pkg))
      (network_available)
    )
    :effect (and
      (package_downloaded ?pkg)
    )
  )

  (:action upgrade_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (system_upgraded)
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

  (:action grant_access_to_system_journal
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (can_read_system_journal ?user)
    )
  )

  (:action modify_journal_files_set
    :parameters (?directory - directory ?file - file ?user - user ?system - service)
    :precondition (and
      (directory_exists ?directory)
      (file_exists ?file)
    )
    :effect (and
      (journal_directory_modified ?directory)
      (journal_file_modified ?file)
    )
  )

  (:action access_private_journal
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (can_read_private_journal ?user)
    )
  )

  (:action access_system_journal
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (can_read_system_journal ?user)
    )
  )

  (:action access_other_users_journals
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (can_read_other_user_journal ?user)
    )
  )

  (:action specify_journal_directory
    :parameters (?dir - directory)
    :precondition (and
      (network_available)
      (directory_exists ?dir)
    )
    :effect (and
      (journal_operated_on ?dir)
    )
  )

  (:action specify_file_glob
    :parameters (?glob - file)
    :precondition (and
      (network_available)
      (file_exists ?glob)
    )
    :effect (and
      (file_glob_specified ?glob)
    )
  )

  (:action operate_on_journal_files
    :parameters (?glob - file ?root_directory - directory ?image_path - file)
    :precondition (and
      (file_exists ?glob)
      (directory_exists ?root_directory)
      (path_exists ?image_path)
    )
    :effect (and
      (journalctl_operates_on_specified_paths ?glob)
      (journalctl_root_set_to ?root_directory)
      (journalctl_image_set_to ?image_path)
    )
  )

  (:action set_journal_root
    :parameters (?root_directory - directory)
    :precondition (and
      (directory_exists ?root_directory)
    )
    :effect (and
      (journalctl_root_set_to ?root_directory)
    )
  )

  (:action set_journal_image
    :parameters (?image_path - file)
    :precondition (and
      (path_exists ?image_path)
    )
    :effect (and
      (journalctl_image_set_to ?image_path)
    )
  )

  (:action operate_on_disk_image
    :parameters (?actor - user ?image - file ?policy - file ?namespace - file)
    :precondition (and
      (disk_image_exists ?image)
      (can_escalate ?actor)
    )
    :effect (and
      (file_systems_mounted ?image)
      (log_data_extracted ?image)
    )
  )

  (:action filter_journal_since_date
    :parameters (?date - file)
    :precondition (and
      (journal_records_exist)
    )
    :effect (and
      (filtered_journal_records ?date)
    )
  )

  (:action filter_journal_until_date
    :parameters (?date - file)
    :precondition (and
      (journal_records_exist)
    )
    :effect (and
      (filtered_journal_records ?date)
    )
  )

  (:action set_pager_secure_mode
    :parameters (?mode - file ?pager - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (pager_secure_mode_enabled ?mode)
      (pager_used ?pager)
    )
  )

  (:action set_less_charset
    :parameters (?charset - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (less_charset_set ?charset)
    )
  )

  (:action set_environment_variable
    :parameters (?var - file ?value - file)
    :precondition (and
    )
    :effect (and
      (environment_variable_set ?var ?value)
    )
  )

  (:action disable_pager
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (pager_disabled)
    )
  )

  (:action enable_secure_mode_pager
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (secure_mode_enabled)
    )
  )

  (:action disable_secure_mode_pager
    :parameters (?obj - file)
    :precondition (and
      (secure_mode_enabled)
    )
    :effect (and
      (not (secure_mode_enabled))
    )
  )

  (:action enable_colors_output
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (colors_enabled)
    )
  )

  (:action enable_base_16_colors_output
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (base_16_colors_enabled)
    )
  )

  (:action enable_base_256_colors_output
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (base_256_colors_enabled)
    )
  )

  (:action disable_colors_output
    :parameters (?obj - file)
    :precondition (and
      (colors_enabled)
    )
    :effect (and
      (not (colors_enabled))
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

  (:action set_systemd_urlify
    :parameters (?setting - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (urlify_setting ?setting)
    )
  )

  (:action reduce_disk_usage
    :parameters (?actor - user ?bytes - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (disk_usage_below ?bytes)
    )
  )

  (:action leave_journal_files
    :parameters (?actor - user ?int - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_files_left ?int)
    )
  )

  (:action remove_old_journal_files
    :parameters (?actor - user ?time - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_files_removed_older_than ?time)
    )
  )

  (:action synchronize_journal
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_synchronized_to_disk)
    )
  )

  (:action stop_logging_to_disk
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (logging_to_temporary_file_system)
    )
  )

  (:action smart_relinquish_var
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (logging_to_temporary_file_system_if_not_root_mount)
    )
  )

  (:action flush_journal_data
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_data_flushed_to_var)
    )
  )

  (:action rotate_journal_files
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_files_rotated)
    )
  )

  (:action update_catalog_database
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (catalog_updated)
    )
  )

  (:action generate_fss_key_pair
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (fss_keys_generated)
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
      (not (directory_exists ?file_path))
    )
  )

  (:action force_remove_file_or_directory
    :parameters (?file_path - file)
    :precondition (and
    )
    :effect (and
      (not (file_exists ?file_path))
      (not (directory_exists ?file_path))
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

  (:action remove_directory_recursive_one_file_system
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (not (directory_exists ?dir))
    )
  )

  (:action remove_directory_recursive
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (not (directory_exists ?dir))
    )
  )

  (:action remove_empty_directory
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (not (directory_exists ?dir))
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

  (:action remove_directory_recursively
    :parameters (?d - directory)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (not (directory_exists ?d))
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

  (:action remove_special_file_relative_path
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

  (:action once_interactive_remove_file
    :parameters (?files - file)
    :precondition (and
      (file_exists ?files)
    )
    :effect (and
      (not (file_exists ?files))
    )
  )

  (:action custom_interactive_remove_file
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

  (:action recursively_remove_directory_contents
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (not (directory_exists ?dir))
    )
  )

  (:action recursively_remove_hierarchy_one_file_system
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

  (:action remove_special_file_path
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

  (:action change_file_permissions
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_has_mode ?f ?mode)
    )
  )

  (:action change_permissions_pointed_to_file
    :parameters (?link - file ?target - file)
    :precondition (and
      (file_exists ?link)
      (is_symbolic_link ?link)
    )
    :effect (and
      (file_executable ?target)
    )
  )

  (:action clear_set_group_id_bit
    :parameters (?f - file ?gid - file)
    :precondition (and
      (file_exists ?f)
      (not (group_matches_effective_gid ?f ?gid))
      (not (group_matches_supplementary_gids ?f ?gid))
    )
    :effect (and
      (set_group_id_cleared ?f)
    )
  )

  (:action change_directory_permissions
    :parameters (?dir - directory)
    :precondition (and
      (file_exists ?dir)
    )
    :effect (and
      (directory_setuid ?dir)
      (directory_setgid ?dir)
      (directory_sticky_bit ?dir)
    )
  )

  (:action clear_directory_setuid_setgid_bits
    :parameters (?dir - directory)
    :precondition (and
      (file_exists ?dir)
      (directory_setuid ?dir)
      (directory_setgid ?dir)
    )
    :effect (and
      (not (directory_setuid ?dir))
      (not (directory_setgid ?dir))
    )
  )

  (:action toggle_directory_sticky_bit
    :parameters (?dir - directory)
    :precondition (and
      (file_exists ?dir)
    )
    :effect (and
      (directory_sticky_bit ?dir)
      (not (directory_sticky_bit ?dir))
    )
  )

  (:action change_mode
    :parameters (?file - file ?mode - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (file_mode_set ?file ?mode)
    )
  )

  (:action change_mode_reference
    :parameters (?file - file ?rfile - file)
    :precondition (and
      (file_exists ?file)
      (file_exists ?rfile)
    )
    :effect (and
      (action_completed_change_mode_reference)
    )
  )

  (:action change_permissions_recursive
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_has_mode ?dir ?mode)
    )
  )

  (:action change_permissions_reference
    :parameters (?f - file ?ref_file - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?ref_file)
    )
    :effect (and
      (action_completed_change_permissions_reference)
    )
  )

  (:action change_permissions_verbose
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_has_mode ?f ?mode)
      (output_diagnostic ?f)
    )
  )

  (:action change_permissions_no_preserve_root
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_has_mode ?dir ?mode)
      (no_special_treatment_root)
    )
  )

  (:action change_permissions_preserve_root
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_has_mode ?dir ?mode)
      (fail_on_recursive_root)
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

  (:action chown_chgrp
    :parameters (?actor - user ?owner - user ?group - group ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owner ?f ?owner)
      (file_group ?f ?group)
    )
  )

  (:action chgrp_only
    :parameters (?actor - user ?group - group ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_group ?f ?group)
    )
  )

  (:action chown_reference
    :parameters (?actor - user ?rfile - file ?f - file)
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

  (:action chown_reference_file
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_chown_reference_file)
    )
  )

  (:action traverse_symlink_directory_h
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owner ?f ?owner)
    )
  )

  (:action traverse_symlink_directory_l
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owner ?f ?owner)
    )
  )

  (:action do_not_traverse_symlink_directory_p
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owner ?f ?owner)
    )
  )

  (:action chown_recursive
    :parameters (?actor - user ?owner - user ?group - group ?f - file)
    :precondition (and
      (user_exists ?owner)
      (group_exists ?group)
      (directory_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_owner ?f ?owner)
      (directory_group ?f ?group)
    )
  )

  (:action chown_file_reference
    :parameters (?actor - user ?rfile - file ?f - file)
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
      (file_owner ?f ?owner)
      (file_group ?f ?group)
    )
  )

  (:action recursive_operation
    :parameters (?actor - user ?dir - directory ?owner - user ?group - group)
    :precondition (and
      (directory_exists ?dir)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_owner ?dir ?owner)
      (directory_group ?dir ?group)
    )
  )

  (:action change_ownership_reference
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_change_ownership_reference)
    )
  )

  (:action no_preserve_root
    :parameters (?actor - user ?dir - directory ?owner - user ?group - group)
    :precondition (and
      (directory_exists ?dir)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_owner ?dir ?owner)
      (directory_group ?dir ?group)
    )
  )

  (:action preserve_root
    :parameters (?actor - user ?dir - directory ?owner - user ?group - group)
    :precondition (and
      (directory_exists ?dir)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_owner ?dir ?owner)
      (directory_group ?dir ?group)
    )
  )

  (:action conditional_change_ownership
    :parameters (?actor - user ?f - file ?current_owner - user ?current_group - group ?new_owner - user ?new_group - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?current_owner)
      (group_exists ?current_group)
      (user_exists ?new_owner)
      (group_exists ?new_group)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owner ?f ?new_owner)
      (file_group ?f ?new_group)
    )
  )

  (:action traverse_symlinks
    :parameters (?dir - directory ?option - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_traversed ?dir)
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

  (:action set_directory_selinux_context
    :parameters (?dir - directory ?context - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_selinux_context_set ?dir ?context)
    )
  )

  (:action set_default_selinux_context
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (default_selinux_context_set ?dir)
    )
  )

  (:action set_custom_security_context
    :parameters (?dir - directory ?ctx - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (custom_security_context_set ?dir)
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

  (:action no_create_touch
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
    )
  )

  (:action set_timestamp_with_string
    :parameters (?f - file ?timestamp - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
    )
  )

  (:action update_symlink_timestamps
    :parameters (?symlink - file)
    :precondition (and
      (file_exists ?symlink)
    )
    :effect (and
      (file_access_time_updated ?symlink)
      (file_modification_time_updated ?symlink)
    )
  )

  (:action set_file_times_from_reference
    :parameters (?f - file ?ref - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?ref)
    )
    :effect (and
      (file_time_set ?f ?ref)
    )
  )

  (:action set_file_time_to_timestamp
    :parameters (?f - file ?stamp - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_time_set ?f ?stamp)
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

  (:action create_file_if_not_exists
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action update_file_modification_time
    :parameters (?f - file ?t - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_modified_at ?f ?t)
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

  (:action switch_user
    :parameters (?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action switch_user_with_args
    :parameters (?user - user ?args - file)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action switch_user_with_login_option
    :parameters (?user - user ?args - file)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action configure_pam_for_su
    :parameters (?actor - user ?config - file)
    :precondition (and
      (file_exists ?config)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (pam_configured ?config)
    )
  )

  (:action switch_user_with_runuser
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (process_running ?cmd)
      (user_executed_command ?user ?cmd)
    )
  )

  (:action switch_user_with_setpriv
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (process_running ?cmd)
      (user_executed_command ?user ?cmd)
    )
  )

  (:action reset_resource_limits_with_su
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (process_running ?cmd)
      (resource_limits_reset ?cmd)
    )
  )

  (:action execute_command_with_su
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (process_running ?cmd)
      (user_executed_command ?user ?cmd)
    )
  )

  (:action fast_mode_with_su
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (process_running ?cmd)
      (user_executed_command ?user ?cmd)
    )
  )

  (:action change_user_group
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

  (:action add_supplementary_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (user_supplementary_group ?user ?group)
    )
  )

  (:action start_shell_login
    :parameters (?shell - file ?user - user)
    :precondition (and
      (file_exists ?shell)
      (user_exists ?user)
    )
    :effect (and
      (shell_is_login ?shell)
    )
  )

  (:action preserve_environment
    :parameters (?shell - file ?user - user)
    :precondition (and
      (file_exists ?shell)
      (user_exists ?user)
    )
    :effect (and
      (environment_preserved ?shell)
    )
  )

  (:action create_pseudo_terminal
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (session_has_pty ?user)
    )
  )

  (:action run_specified_shell
    :parameters (?shell - file ?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (session_runs_shell ?user)
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

  (:action login_shell_with_su
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (shell_executed ?user)
    )
  )

  (:action preserve_environment_with_su
    :parameters (?cmd - process ?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (environment_preserved ?user)
    )
  )

  (:action configure_pam_su_behavior
    :parameters (?actor - user ?config_file - file ?module - file)
    :precondition (and
      (file_exists ?config_file)
      (not (pam_configured ?module))
      (can_escalate ?actor)
    )
    :effect (and
      (pam_configured ?module)
    )
  )

  (:action switch_to_login_shell
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (current_user_is ?user)
      (login_shell_active ?true)
    )
  )

  (:action execute_command_as_user
    :parameters (?user - user ?command - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (current_user_is ?user)
      (command_executed ?true)
    )
  )

  (:action switch_shell_as_user
    :parameters (?user - user ?shell - file)
    :precondition (and
      (user_exists ?user)
      (file_executable ?shell)
    )
    :effect (and
      (current_user_is ?user)
      (active_shell_is ?shell)
    )
  )

  (:action switch_user_with_pty
    :parameters (?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
    )
    :effect (and
      (current_user_is ?user)
      (primary_group_is ?group)
      (pseudo_terminal_created ?true)
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
      (group_exists ?user)
    )
  )

  (:action update_default_user_info
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (default_new_user_updated)
    )
  )

  (:action set_default_useradd
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (default_values_set)
    )
  )

  (:action set_home_directory
    :parameters (?actor - user ?user - user ?home_dir - directory)
    :precondition (and
      (user_exists ?user)
      (not (configures ?home_dir ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (configures ?home_dir ?user)
    )
  )

  (:action set_user_expiration_date
    :parameters (?actor - user ?user - user ?expire_date - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (account_expires_on ?user ?expire_date)
    )
  )

  (:action update_subids_for_system_account
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subuids_updated ?user)
      (subgids_updated ?user)
    )
  )

  (:action add_supplementary_groups_to_user
    :parameters (?actor - user ?user - user ?groups - file)
    :precondition (and
      (user_exists ?user)
      (all_groups_exist ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_groups ?user ?groups)
    )
  )

  (:action create_home_directory
    :parameters (?actor - user ?user - user ?skel_dir - directory)
    :precondition (and
      (not (home_exists ?user))
      (directory_exists ?skel_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (home_exists ?user)
      (acls_copied ?user)
      (extended_attributes_copied ?user)
    )
  )

  (:action override_login_defs_defaults
    :parameters (?actor - user ?key - file ?value - file)
    :precondition (and
      (not (login_def_key_exists ?key))
      (can_escalate ?actor)
    )
    :effect (and
      (login_def_key_exists ?key)
      (login_def_value_set ?value)
    )
  )

  (:action no_log_init
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (lastlog_exists ?user))
      (not (faillog_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (not (lastlog_exists ?user))
      (not (faillog_exists ?user))
    )
  )

  (:action reset_user_logs
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (lastlog_entry ?user))
      (not (faillog_entry ?user))
    )
  )

  (:action no_create_home_directory
    :parameters (?actor - user ?user - user ?dir - directory)
    :precondition (and
      (not (directory_exists ?dir))
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (home_directory_set ?user ?dir))
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
      (password_set_for_user ?user)
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
    :parameters (?actor - user ?user - user ?home_dir - directory)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (directory_exists ?home_dir)
    )
  )

  (:action create_system_account_with_home_directory_and_update_subfiles
    :parameters (?actor - user ?user - user ?home_dir - directory)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (directory_exists ?home_dir)
    )
  )

  (:action apply_changes_in_chroot_directory
    :parameters (?actor - user ?chroot_dir - directory)
    :precondition (and
      (directory_exists ?chroot_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_chroot ?chroot_dir)
    )
  )

  (:action apply_changes_to_prefix_directory
    :parameters (?actor - user ?prefix_dir - directory)
    :precondition (and
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_prefix ?prefix_dir)
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
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (user_has_selinux_user ?user ?seuser)
    )
  )

  (:action update_useradd_defaults
    :parameters (?actor - user ?option - file ?value - file)
    :precondition (and
      (network_available)
      (user_exists ?root)
      (can_escalate ?actor)
    )
    :effect (and
      (default_value_set ?option ?value)
    )
  )

  (:action set_home_mode
    :parameters (?actor - user ?mode - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (home_directory_created ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_mode_set ?user)
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

  (:action set_gid_range
    :parameters (?actor - user ?min - file ?max - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (gid_min_set ?min)
      (gid_max_set ?max)
    )
  )

  (:action create_user_home_directory
    :parameters (?actor - user ?u - user ?h - directory)
    :precondition (and
      (not (directory_exists ?h))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_exists ?h)
      (user_exists ?u)
    )
  )

  (:action set_home_directory_mode
    :parameters (?actor - user ?h - directory ?m - file)
    :precondition (and
      (directory_exists ?h)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_mode_set ?h)
    )
  )

  (:action create_mail_spool_directory
    :parameters (?actor - user ?m - directory ?u - user)
    :precondition (and
      (not (directory_exists ?m))
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_exists ?m)
      (mail_spool_created ?u)
    )
  )

  (:action set_mail_spool_location
    :parameters (?h - directory ?m - file)
    :precondition (and
      (directory_exists ?h)
    )
    :effect (and
      (mail_spool_location_set ?m)
    )
  )

  (:action modify_user
    :parameters (?actor - user ?user - user ?mail_dir - directory ?mail_file - file)
    :precondition (and
      (user_exists ?user)
      (directory_exists ?mail_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (configures ?mail_file ?user)
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
    :parameters (?actor - user ?max_members - file ?group - group)
    :precondition (and
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (group_has_max_members ?group ?max_members)
    )
  )

  (:action set_password_max_days
    :parameters (?actor - user ?user - user ?max_days - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_has_max_days ?user ?max_days)
    )
  )

  (:action set_pass_min_days
    :parameters (?actor - user ?days - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_min_days ?user ?days)
    )
  )

  (:action set_pass_warn_age
    :parameters (?actor - user ?warn_days - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_warn_age ?user ?warn_days)
    )
  )

  (:action set_sub_gid_range
    :parameters (?actor - user ?min - file ?max - file ?count - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gid_min ?min)
      (subordinate_gid_max ?max)
      (subordinate_gid_count ?count)
    )
  )

  (:action create_system_group
    :parameters (?actor - user ?group - group ?sys_gid_min - file ?sys_gid_max - file)
    :precondition (and
      (not (group_exists ?group))
      (sys_gid_range_valid ?sys_gid_min ?sys_gid_max)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
      (system_group_created ?group ?sys_gid_min ?sys_gid_max)
    )
  )

  (:action create_system_user
    :parameters (?actor - user ?user - user ?sys_uid_min - file ?sys_uid_max - file)
    :precondition (and
      (not (user_exists ?user))
      (sys_uid_range_valid ?sys_uid_min ?sys_uid_max)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (system_user_created ?user ?sys_uid_min ?sys_uid_max)
    )
  )

  (:action create_regular_user
    :parameters (?actor - user ?user - user ?uid_min - file ?uid_max - file)
    :precondition (and
      (not (user_exists ?user))
      (uid_range_valid ?uid_min ?uid_max)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (regular_user_created ?user ?uid_min ?uid_max)
    )
  )

  (:action set_umask
    :parameters (?umask - file)
    :precondition (and
    )
    :effect (and
      (file_mode_creation_mask ?umask)
    )
  )

  (:action add_user_with_defaults
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (not (user_exists ?user))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (group_exists ?group)
      (file_mode_creation_mask ?obj_022)
    )
  )

  (:action add_user_with_custom_settings
    :parameters (?actor - user ?user - user ?group - group ?home_mode - file ?umask - file)
    :precondition (and
      (not (user_exists ?user))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (group_exists ?group)
      (file_mode_creation_mask ?umask)
    )
  )

  (:action remove_user_and_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
      (not (group_exists ?group))
    )
  )

  (:action update_selinux_mapping
    :parameters (?actor - user ?username - user)
    :precondition (and
      (user_exists ?username)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_mapping_updated ?username)
    )
  )

  (:action set_default_user_config
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (default_user_config_set)
    )
  )

  (:action set_password_inactivity_period
    :parameters (?actor - user ?login - user ?inactive - file)
    :precondition (and
      (not (user_exists ?login))
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_inactive_period ?login ?inactive)
    )
  )

  (:action set_gecos_field
    :parameters (?actor - user ?login - user ?comment - file)
    :precondition (and
      (not (user_exists ?login))
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_gecos_field ?login ?comment)
    )
  )

  (:action set_base_directory_for_home
    :parameters (?actor - user ?login - user ?base_dir - directory)
    :precondition (and
      (not (user_exists ?login))
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_base_directory ?login ?base_dir)
    )
  )

  (:action set_btrfs_subvolume_home
    :parameters (?actor - user ?login - user)
    :precondition (and
      (not (user_exists ?login))
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_btrfs_subvolume_home ?login)
    )
  )

  (:action disable_badname_check
    :parameters (?actor - user ?login - user)
    :precondition (and
      (not (user_exists ?login))
      (can_escalate ?actor)
    )
    :effect (and
      (badname_check_disabled ?login)
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
      (subuid_entry_added ?user)
      (subgid_entry_added ?user)
    )
  )

  (:action create_user_with_primary_group
    :parameters (?actor - user ?user - user ?gid - group)
    :precondition (and
      (not (user_exists ?user))
      (group_exists ?gid)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (primary_group_assigned ?user ?gid)
    )
  )

  (:action create_user_with_supplementary_groups
    :parameters (?actor - user ?user - user ?groups - file)
    :precondition (and
      (not (user_exists ?user))
      (all_groups_exist ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (supplementary_groups_assigned ?user ?groups)
    )
  )

  (:action create_user_with_home_directory
    :parameters (?actor - user ?user - user ?skel_dir - directory)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (home_directory_created ?user)
    )
  )

  (:action create_user_without_home_directory
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (no_home_directory_created ?user)
    )
  )

  (:action create_user_without_user_group
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (no_user_group_created ?user)
    )
  )

  (:action create_user_with_duplicate_id
    :parameters (?actor - user ?user - user ?gid - group)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (non_unique_user_created ?user)
    )
  )

  (:action create_user_group
    :parameters (?actor - user ?group - group ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (group_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
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
      (user_has_password ?user ?password)
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
      (user_has_seuser ?user ?seuser)
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

  (:action add_user_to_groups
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
    :parameters (?actor - user ?user - user ?new_home - directory)
    :precondition (and
      (user_exists ?user)
      (not (directory_exists ?new_home))
      (can_escalate ?actor)
    )
    :effect (and
      (user_home_changed ?user)
    )
  )

  (:action move_user_home_directory_contents
    :parameters (?actor - user ?user - user ?new_home - directory)
    :precondition (and
      (user_exists ?user)
      (file_exists ?current_home)
      (not (directory_exists ?new_home))
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_moved ?user)
    )
  )

  (:action set_user_account_expiration_date
    :parameters (?actor - user ?user - user ?expire_date - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (account_expires_on ?user ?expire_date)
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
      (primary_group_changed ?user ?group)
    )
  )

  (:action change_supplementary_groups
    :parameters (?actor - user ?user - user ?groups - file)
    :precondition (and
      (user_exists ?user)
      (all_groups_exist ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (supplementary_groups_changed ?user ?groups)
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

  (:action change_user_login
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
      (directory_exists ?new_home)
    )
  )

  (:action update_user_properties
    :parameters (?actor - user ?user - user ?new_uid - file ?password - file)
    :precondition (and
      (user_exists ?user)
      (not (user_critical ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (ownership_updated ?user)
      (acl_copied ?user)
      (extended_attributes_copied ?user)
    )
  )

  (:action set_non_unique_user_id
    :parameters (?actor - user ?user - user ?new_uid - file)
    :precondition (and
      (user_exists ?user)
      (not (user_critical ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (non_unique_uid_set ?user)
    )
  )

  (:action set_user_password
    :parameters (?actor - user ?user - user ?encrypted_password - file)
    :precondition (and
      (user_exists ?user)
      (not (user_critical ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (password_updated ?user)
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

  (:action chroot_changes
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_chroot_dir ?dir)
    )
  )

  (:action prefix_changes
    :parameters (?actor - user ?prefix_dir - directory)
    :precondition (and
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_prefix_dir ?prefix_dir)
    )
  )

  (:action change_shell
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

  (:action change_user_id
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
      (can_escalate ?actor)
    )
    :effect (and
      (password_unlocked ?user)
    )
  )

  (:action change_file_ownership_outside_home
    :parameters (?actor - user ?file - file ?new_user_id - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owner_changed ?file)
    )
  )

  (:action add_subuids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_range_added ?user ?first ?last)
    )
  )

  (:action remove_subuids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (subuid_range_added ?user ?first ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subuid_range_added ?user ?first ?last))
    )
  )

  (:action add_subgids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subgid_range_added ?user ?first ?last)
    )
  )

  (:action add_subordinate_gids
    :parameters (?actor - user ?user - user ?first_gid - file ?last_gid - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gids_added ?user ?first_gid ?last_gid)
    )
  )

  (:action remove_subordinate_gids
    :parameters (?actor - user ?user - user ?first_gid - file ?last_gid - file)
    :precondition (and
      (user_exists ?user)
      (subordinate_gids_added ?user ?first_gid ?last_gid)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subordinate_gids_added ?user ?first_gid ?last_gid))
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

  (:action modify_user_properties
    :parameters (?actor - user ?user - user ?new_uid - file ?new_username - file ?new_home_dir - directory)
    :precondition (and
      (user_exists ?user)
      (not (process_running_by_user ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_new_id ?user ?new_uid)
      (user_has_new_name ?user ?new_username)
      (user_has_new_home_directory ?user ?new_home_dir)
    )
  )

  (:action update_lastlog_entries
    :parameters (?actor - user ?uid_limit - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (lastlog_updated ?uid_limit)
    )
  )

  (:action configure_mail_directory
    :parameters (?actor - user ?mail_dir - directory)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (mail_directory_set ?mail_dir)
    )
  )

  (:action create_user_account
    :parameters (?actor - user ?user - user ?mail_dir - directory ?mail_file - file)
    :precondition (and
      (not (user_exists ?user))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (mail_spool_created ?mail_dir)
    )
  )

  (:action delete_user_account
    :parameters (?actor - user ?user - user ?mail_dir - directory ?mail_file - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
      (mail_spool_deleted ?mail_dir)
    )
  )

  (:action lock_user_account
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (account_locked ?user)
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
      (home_directory_moved ?user ?new_home)
    )
  )

  (:action remove_user_from_groups
    :parameters (?actor - user ?user - user ?groups - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_in_group ?user ?groups))
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
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_uid ?user ?uid)
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

  (:action add_subuids_range
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_range_added ?user ?first ?last)
    )
  )

  (:action del_subuids_range
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (subuid_range_added ?user ?first ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subuid_range_added ?user ?first ?last))
    )
  )

  (:action add_subgids_range
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subgid_range_added ?user ?first ?last)
    )
  )

  (:action del_subgids_range
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (subgid_range_added ?user ?first ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subgid_range_added ?user ?first ?last))
    )
  )

  (:action remove_user
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (not (user_critical ?user))
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
      (not (group_exists ?group))
    )
  )

  (:action remove_user_home_and_mail
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (user_critical ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (not (directory_exists ?home_dir))
      (not (file_exists ?mail_spool))
    )
  )

  (:action remove_selinux_user_mapping
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (selinux_user_mapped ?user))
    )
  )

  (:action move_mail_spool
    :parameters (?actor - user ?old_path - file ?new_path - directory ?user - user)
    :precondition (and
      (file_exists ?old_path)
      (not (directory_exists ?new_path))
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?old_path))
      (mail_spool_moved ?user)
    )
  )

  (:action remove_user_and_run_command
    :parameters (?actor - user ?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
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
      (not (group_contains_member ?group ?user))
      (not (group_exists ?group))
    )
  )

  (:action remove_group_account_info
    :parameters (?actor - user ?group - group)
    :precondition (and
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?group))
    )
  )

  (:action remove_user_account_info
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
    )
  )

  (:action run_pre_delete_scripts
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (scripts_executed ?usr)
    )
  )

  (:action run_post_delete_scripts
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (not (user_exists ?usr))
      (can_escalate ?actor)
    )
    :effect (and
      (scripts_executed ?usr)
    )
  )

  (:action update_subgid_file
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (subgid_updated ?usr)
    )
  )

  (:action update_subuid_file
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_updated ?usr)
    )
  )

  (:action delete_user_account_force
    :parameters (?actor - user ?user - user ?process - process)
    :precondition (and
      (user_exists ?user)
      (process_running ?process)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
      (not (group_exists ?user))
    )
  )

  (:action delete_user_group
    :parameters (?actor - user ?group - group ?user - user)
    :precondition (and
      (group_exists ?group)
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?group))
    )
  )

  (:action delete_user_group_force
    :parameters (?actor - user ?group - group ?user - user)
    :precondition (and
      (group_exists ?group)
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?group))
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
      (not (can_escalate ?user))
    )
  )

  (:action delete_selinux_mapping
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (selinux_user_mapping_exists ?user))
    )
  )

  (:action add_group
    :parameters (?actor - user ?groupname - file ?gid - file)
    :precondition (and
      (not (group_exists ?groupname))
      (length_?groupname ?obj_32)
      (gid_unique ?gid)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?groupname)
      (group_gid ?groupname)
    )
  )

  (:action force_add_group
    :parameters (?actor - user ?groupname - file ?gid - file)
    :precondition (and
      (length_?groupname ?obj_32)
      (gid_unique ?gid)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?groupname)
      (group_gid ?groupname)
    )
  )

  (:action set_group_defaults
    :parameters (?actor - user ?min_gid - file ?max_gid - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_default_min ?min_gid)
      (group_default_max ?max_gid)
    )
  )

  (:action create_non_unique_group
    :parameters (?actor - user ?group - group ?gid - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
      (group_gid ?group ?gid)
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

  (:action add_users_to_group
    :parameters (?actor - user ?users - file ?group - group)
    :precondition (and
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_group ?users ?group)
    )
  )

  (:action set_sys_gid_range
    :parameters (?actor - user ?sys_min - file ?sys_max - file)
    :precondition (and
      (not (sys_gid_min_set ?sys_min))
      (not (sys_gid_max_set ?sys_max))
      (can_escalate ?actor)
    )
    :effect (and
      (sys_gid_min_set ?sys_min)
      (sys_gid_max_set ?sys_max)
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
      (group_has_gid ?group ?gid)
    )
  )

  (:action update_group_file
    :parameters (?obj - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (group_file_updated)
    )
  )

  (:action add_group_with_gid
    :parameters (?actor - user ?group - group ?gid - file)
    :precondition (and
      (not (group_exists ?group))
      (not (gid_in_use ?gid))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
      (group_has_gid ?group ?gid)
    )
  )

  (:action add_group_non_unique_gid
    :parameters (?actor - user ?group - group ?gid - file)
    :precondition (and
      (not (group_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
      (group_has_gid ?group ?gid)
    )
  )

  (:action add_group_with_prefix_and_chroot
    :parameters (?actor - user ?group - group ?prefix_dir - file ?chroot_dir - file)
    :precondition (and
      (not (group_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
      (prefix_directory ?group ?prefix_dir)
    )
  )

  (:action use_extra_users_db
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (extra_users_db_enabled)
    )
  )

)