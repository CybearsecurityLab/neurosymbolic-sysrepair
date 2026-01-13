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
    (package_index_updated)
    (all_packages_up_to_date)
    (package_updated ?x0 - object)
    (package_version ?x0 - object ?x1 - object)
    (package_from_dist ?x0 - object ?x1 - object)
    (package_policy_set ?x0 - object)
    (source_fetched ?x0 - object)
    (source_package_downloaded ?x0 - object)
    (binary_package_compiled ?x0 - object)
    (build_dependencies_satisfied ?x0 - object)
    (dependency_satisfied ?x0 - object)
    (dependency_conflicted ?x0 - object)
    (package_downloaded ?x0 - object)
    (repository_cleared)
    (cache_cleaned)
    (lists_cleaned)
    (default_release_set ?x0 - object)
    (operations_trivial)
    (diff_downloaded ?x0 - object)
    (dsc_downloaded ?x0 - object)
    (tar_downloaded ?x0 - object)
    (arch_build_deps_processed ?x0 - object)
    (indep_build_deps_processed ?x0 - object)
    (unauthenticated_packages_allowed)
    (insecure_repositories_allowed)
    (releaseinfo_changes_allowed)
    (source_configured ?x0 - object)
    (sources_updated)
    (progress_reporting_enabled)
    (release_info_changes_allowed)
    (error_policy_set_to_any)
    (preferences_configured ?x0 - object)
    (package_lists_updated)
    (system_upgraded)
    (unused_packages_exist)
    (dependencies_resolved)
    (build_dependencies_configured)
    (dependencies_satisfied)
    (downloaded_files_exist)
    (old_downloaded_files_exist)
    (source_files_downloaded)
    (binary_files_downloaded)
    (changelog_downloaded)
    (package_list_updated)
    (package_info_updated)
    (some_packages_removed)
    (package_marked_explicit ?x0 - object)
    (source_downloaded ?x0 - object)
    (build_dependencies_installed ?x0 - object)
    (sources_list_updated)
    (package_reverted ?x0 - object)
    (package_enabled ?x0 - object)
    (change_pending)
    (assertion_exists)
    (valid_assertion ?x0 - object)
    (verified_signature ?x0 - object)
    (application_exists ?x0 - object)
    (alias_setup ?x0 - object ?x1 - object)
    (snap_installed ?x0 - object)
    (plug_connected ?x0 - object ?x1 - object)
    (connection_exists ?x0 - object ?x1 - object)
    (all_snaps_installed ?x0 - object)
    (cohort_keys_created ?x0 - object)
    (feature_tags_retrieved)
    (lsm_info_retrieved)
    (snaps_migrated)
    (installed_from_channel ?x0 - object ?x1 - object)
    (in_cohort ?x0 - object ?x1 - object)
    (directory_exists ?x0 - object)
    (snap_in_development_mode ?x0 - object)
    (snap_confinement_enabled ?x0 - object)
    (snap_alias_exists ?x0 - object)
    (validation_set_exists)
    (validation_set_enforcing)
    (snaps_satisfy_constraints)
    (snaps_refreshed)
    (snap_channel_switched ?x0 - object ?x1 - object)
    (connected ?x0 - object ?x1 - object)
    (configured ?x0 - object ?x1 - object)
    (alias_exists ?x0 - object)
    (user_logged_in)
    (snapshot_exists ?x0 - object)
    (device_rebooted ?x0 - object)
    (warning_exists)
    (snap_downloaded ?x0 - object)
    (snap_packed ?x0 - object)
    (snap_tested ?x0 - object)
    (assertion_signed ?x0 - object)
    (device_image_prepared ?x0 - object)
    (public_key_exported ?x0 - object)
    (quota_group_set ?x0 - object)
    (quota_group_exists ?x0 - object)
    (can_read_system_journal ?x0 - object)
    (journal_directory_modified ?x0 - object)
    (journal_file_added ?x0 - object)
    (journal_viewed_with_header)
    (exists_matching_glob ?x0 - object)
    (journalctl_operates_on ?x0 - object)
    (journalctl_operates_under_root ?x0 - object)
    (journalctl_operates_on_image ?x0 - object)
    (disk_image_exists ?x0 - object)
    (policy_set_for_image ?x0 - object)
    (data_collected ?x0 - object)
    (cursor_written_to_file ?x0 - object ?x1 - object)
    (environment_variable_set ?x0 - object ?x1 - object)
    (pager_disabled)
    (systemd_colors_enabled ?x0 - object)
    (filtered_logs ?x0 - object)
    (journal_entry_viewed ?x0 - object)
    (local_container_operated)
    (journals_merged)
    (alternate_root_operated)
    (journal_files_exist)
    (disk_usage_below ?x0 - object)
    (number_of_journal_files ?x0 - object)
    (journals_older_than_removed ?x0 - object)
    (unwritten_messages_exist)
    (messages_synced_to_disk)
    (logging_enabled)
    (log_temporary_file_system)
    (log_directory_on_root)
    (messages_flushed_to_var)
    (journals_rotated)
    (file_copied ?x0 - object ?x1 - object)
    (special_file_copied ?x0 - object ?x1 - object)
    (attributes_copied ?x0 - object ?x1 - object)
    (can_write_to_file ?x0 - object)
    (user_prompted)
    (hard_link_created ?x0 - object ?x1 - object)
    (symbolic_link_exists ?x0 - object)
    (source_followed ?x0 - object)
    (mode_preserved ?x0 - object)
    (ownership_preserved ?x0 - object)
    (timestamps_preserved ?x0 - object)
    (attributes_preserved ?x0 - object)
    (attributes_not_preserved ?x0 - object)
    (full_path_copied ?x0 - object ?x1 - object)
    (directory_copied ?x0 - object ?x1 - object)
    (symbolic_link_created ?x0 - object ?x1 - object)
    (sparse_file_created ?x0 - object)
    (file_updated ?x0 - object ?x1 - object)
    (default_security_context_set ?x0 - object)
    (custom_security_context_set ?x0 - object ?x1 - object)
    (stayed_on_same_filesystem ?x0 - object ?x1 - object)
    (is_sparse ?x0 - object)
    (sparse_option_set ?x0 - object)
    (files_replaced ?x0 - object)
    (copy_method ?x0 - object)
    (backup_suffix_set ?x0 - object)
    (file_copied_to_directory ?x0 - object ?x1 - object)
    (file_copied_to_directory_with_archive ?x0 - object ?x1 - object)
    (file_copied_to_directory_with_backup ?x0 - object ?x1 - object)
    (file_copied_to_directory_with_backup_no_arg ?x0 - object ?x1 - object)
    (special_file_copied_to_directory ?x0 - object ?x1 - object)
    (directory_contents_copied ?x0 - object ?x1 - object)
    (file_copied_without_link_dereference ?x0 - object ?x1 - object)
    (trailing_slashes_removed ?x0 - object)
    (full_source_copied_under_directory ?x0 - object ?x1 - object)
    (file_copied_within_fs ?x0 - object ?x1 - object)
    (selinux_context_set_default ?x0 - object)
    (selinux_context_set_custom ?x0 - object ?x1 - object)
    (owned_by_user ?x0 - object ?x1 - object)
    (owned_by_group ?x0 - object ?x1 - object)
    (timestamp_updated ?x0 - object)
    (updated_file ?x0 - object)
    (file_is_older ?x0 - object ?x1 - object)
    (data_blocks_shared ?x0 - object ?x1 - object)
    (file_backup_created ?x0 - object)
    (file_moved ?x0 - object ?x1 - object)
    (security_context_set ?x0 - object)
    (is_empty ?x0 - object)
    (file_mode_changed ?x0 - object)
    (is_symbolic_link ?x0 - object)
    (points_to ?x0 - object ?x1 - object)
    (file_executable ?x0 - object)
    (is_directory ?x0 - object)
    (exists_in ?x0 - object ?x1 - object)
    (processes_link ?x0 - object)
    (directory_mode_set ?x0 - object ?x1 - object)
    (directory_bit_set ?x0 - object ?x1 - object)
    (directory_bit_unset ?x0 - object ?x1 - object)
    (sticky_bit_set ?x0 - object)
    (sticky_bit_unset ?x0 - object)
    (file_has_mode ?x0 - object ?x1 - object)
    (can_change_permissions_recursively)
    (same_ownership_as ?x0 - object ?x1 - object)
    (file_owned_by_user ?x0 - object ?x1 - object)
    (file_belongs_to_group ?x0 - object ?x1 - object)
    (preserve_root)
    (recursively_operated_on ?x0 - object)
    (traversed_link_to_directory ?x0 - object)
    (all_links_traversed)
    (owned_by ?x0 - object ?x1 - object)
    (belongs_to_group ?x0 - object ?x1 - object)
    (owned_by_all_files_in_directory ?x0 - object ?x1 - object)
    (same_owner_as_reference ?x0 - object ?x1 - object)
    (same_group_as_reference ?x0 - object ?x1 - object)
    (operation_performed_on_directory ?x0 - object ?x1 - object)
    (selinux_context_set_to_default ?x0 - object)
    (file_access_time_updated ?x0 - object)
    (file_modification_time_updated ?x0 - object)
    (file_time_set_from ?x0 - object ?x1 - object)
    (file_time_set_to ?x0 - object ?x1 - object)
    (file_access_time_set_to ?x0 - object ?x1 - object)
    (file_modification_time_set_to ?x0 - object ?x1 - object)
    (file_access_time_changed ?x0 - object)
    (file_modification_time_changed ?x0 - object)
    (symlink_exists ?x0 - object)
    (symlink_access_time_changed ?x0 - object)
    (symlink_modification_time_changed ?x0 - object)
    (file_modified_time_updated ?x0 - object)
    (routing_updated)
    (commands_executed ?x0 - object)
    (statistics_human_readable)
    (object_exists ?x0 - object)
    (command_executed ?x0 - object)
    (command_executed_on_all ?x0 - object)
    (color_output_configured ?x0 - object)
    (network_namespace_exists ?x0 - object)
    (ioam_namespace_exists ?x0 - object)
    (ioam_schema_exists ?x0 - object)
    (neighbour_cache_entry_exists ?x0 - object)
    (tuntap_device_exists ?x0 - object)
    (neighbour_cache_operation_set ?x0 - object)
    (tcp_metric_configured ?x0 - object)
    (tokenized_interface_identifier_set ?x0 - object)
    (mptcp_path_manager_configured ?x0 - object)
    (multicast_routing_policy_configured ?x0 - object)
    (routing_policy_configured ?x0 - object)
    (interface_statistics_configured ?x0 - object)
    (routing_table_entry_configured ?x0 - object)
    (multicast_routing_cache_configured ?x0 - object)
    (multicast_address_configured ?x0 - object)
    (l2tp_tunnel_configured ?x0 - object)
    (ip_tunnel_configured ?x0 - object)
    (network_device_configured ?x0 - object)
    (vrf_configured ?x0 - object)
    (ipsec_policy_configured ?x0 - object)
    (network_object_modified ?x0 - object)
    (network_objects_modified)
    (masquerade_enabled)
    (file_modified ?x0 - object)
    (working_directory_changed_to ?x0 - object)
    (environment_preserved)
    (file_edited_by_user ?x0 - object)
    (is_unauthorized_edit ?x0 - object)
    (sudoers_modified ?x0 - object)
    (follows_symlink ?x0 - object)
    (editable_in_writable_dir ?x0 - object)
    (editable_device_file ?x0 - object)
    (primary_group_of_user ?x0 - object ?x1 - object)
    (home_set ?x0 - object ?x1 - object)
    (shell_running_as_user ?x0 - object ?x1 - object)
    (file_edited_by_user_and_group ?x0 - object ?x1 - object ?x2 - object)
    (directory_writable_by_user ?x0 - object)
    (file_edited ?x0 - object)
    (symbolic_link_followed ?x0 - object)
    (file_owned_by_root ?x0 - object)
    (file_setuid ?x0 - object)
    (process_has_no_new_privileges_flag ?x0 - object)
    (password_timeout_expired)
    (platform_supports_sudoedit)
    (working_directory_changed ?x0 - object)
    (home_variable_set ?x0 - object)
    (background_process_running ?x0 - object)
    (command_run_as_group ?x0 - object)
    (supplementary_group_of_user ?x0 - object ?x1 - object)
    (shell_is_login ?x0 - object)
    (session_has_pty ?x0 - object)
    (shell_running_for_user ?x0 - object ?x1 - object)
    (config_file_read ?x0 - object)
    (fail_delay_set ?x0 - object)
    (env_path_set ?x0 - object)
    (always_set_path_configured ?x0 - object)
    (path_initialized ?x0 - object)
    (user_in_group ?x0 - object ?x1 - object)
    (default_user_updated)
    (home_directory_set ?x0 - object ?x1 - object)
    (comment_set ?x0 - object ?x1 - object)
    (account_expired_on ?x0 - object ?x1 - object)
    (default_home_base_set ?x0 - object)
    (default_values_set)
    (user_expiry_date_set ?x0 - object ?x1 - object)
    (password_inactive_period_set ?x0 - object ?x1 - object)
    (subuids_updated ?x0 - object)
    (primary_group_set ?x0 - object ?x1 - object)
    (home_exists ?x0 - object)
    (files_copied_from_skel ?x0 - object ?x1 - object)
    (login_def_set ?x0 - object ?x1 - object)
    (no_lastlog_entry ?x0 - object)
    (no_faillog_entry ?x0 - object)
    (lastlog_entry ?x0 - object)
    (faillog_entry ?x0 - object)
    (uid_exists ?x0 - object)
    (has_uid ?x0 - object ?x1 - object)
    (has_password ?x0 - object ?x1 - object)
    (home_directory_created ?x0 - object)
    (subuid_updated ?x0 - object)
    (subgid_updated ?x0 - object)
    (changes_applied_in_chroot ?x0 - object)
    (changes_applied_under_prefix ?x0 - object)
    (user_shell_set ?x0 - object ?x1 - object)
    (user_has_uid ?x0 - object ?x1 - object)
    (selinux_user_set ?x0 - object)
    (has_selinux_user ?x0 - object ?x1 - object)
    (config_file_exists ?x0 - object)
    (login_def_configured ?x0 - object ?x1 - object)
    (lastlog_uid_max_set ?x0 - object)
    (mail_dir_set ?x0 - object)
    (mail_file_set ?x0 - object)
    (user_modified ?x0 - object)
    (max_members_per_group ?x0 - object ?x1 - object)
    (pass_max_days ?x0 - object ?x1 - object)
    (password_min_days_set ?x0 - object ?x1 - object)
    (password_warn_age_set ?x0 - object ?x1 - object)
    (subordinate_gid_min_set ?x0 - object)
    (subordinate_gid_max_set ?x0 - object)
    (subordinate_gid_count_set ?x0 - object)
    (default_umask_set ?x0 - object)
    (member_of_any_other_groups ?x0 - object)
    (script_executed ?x0 - object)
    (default_base_directory_set ?x0 - object)
    (default_comment_set ?x0 - object)
    (default_home_directory_set ?x0 - object)
    (default_expire_date_set ?x0 - object)
    (default_inactive_period_set ?x0 - object)
    (subuid_added ?x0 - object ?x1 - object)
    (home_directory_not_created ?x0 - object)
    (no_user_group_created ?x0 - object)
    (non_unique_user_created ?x0 - object)
    (user_comment_updated ?x0 - object)
    (user_home_set ?x0 - object)
    (user_expire_set ?x0 - object)
    (inactive_period_set ?x0 - object ?x1 - object)
    (password_locked ?x0 - object)
    (home_directory ?x0 - object ?x1 - object)
    (ownership_adapted ?x0 - object)
    (modes_copied ?x0 - object)
    (acl_copied ?x0 - object)
    (extended_attributes_copied ?x0 - object)
    (uid_non_unique ?x0 - object)
    (user_id_set ?x0 - object ?x1 - object)
    (changes_applied_in_chroot_dir ?x0 - object)
    (changes_applied_in_prefix_dir ?x0 - object)
    (password_unlocked ?x0 - object)
    (uid_equal ?x0 - object ?x1 - object)
    (subordinate_uid_range_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gid_range_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gids_added ?x0 - object ?x1 - object ?x2 - object)
    (selinux_user_mapped ?x0 - object)
    (subordinate_gids_allocated ?x0 - object)
    (subordinate_uids_allocated ?x0 - object)
    (account_locked ?x0 - object)
    (account_expires_on ?x0 - object ?x1 - object)
    (password_inactivates_after_expiration ?x0 - object ?x1 - object)
    (login_of_user ?x0 - object ?x1 - object)
    (home_directory_of_user ?x0 - object ?x1 - object)
    (gecos_of_user ?x0 - object ?x1 - object)
    (non_unique_uid_of_user ?x0 - object ?x1 - object)
    (bad_name_of_user ?x0 - object ?x1 - object)
    (mail_spool_action ?x0 - object)
    (executed_userdel_cmd ?x0 - object ?x1 - object)
    (cron_job_exists ?x0 - object)
    (at_job_exists ?x0 - object)
    (print_job_exists ?x0 - object)
    (updated_group_file ?x0 - object)
    (updated_passwd_file ?x0 - object)
    (script_exists ?x0 - object)
    (updated_subordinate_group_ids ?x0 - object)
    (updated_subordinate_user_ids ?x0 - object)
    (group_default_set ?x0 - object)
    (group_has_gid ?x0 - object ?x1 - object)
    (group_has_password ?x0 - object)
    (gid_min ?x0 - object)
    (gid_max ?x0 - object)
    (sys_gid_min ?x0 - object)
    (sys_gid_max ?x0 - object)
    (gid_available ?x0 - object)
    (system_group_added ?x0 - object)
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

  (:action upgrade_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (package_index_updated)
      (can_escalate ?actor)
    )
    :effect (and
      (all_packages_up_to_date)
    )
  )

  (:action upgrade_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_updated ?pkg)
    )
  )

  (:action install_and_upgrade_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_updated ?pkg)
    )
  )

  (:action remove_package_if_installed
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
      (package_version ?pkg ?version)
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
      (package_from_dist ?pkg ?dist)
    )
  )

  (:action set_package_policy
    :parameters (?actor - user ?pkg - package ?policy - file)
    :precondition (and
      (file_exists ?policy)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_policy_set ?pkg)
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

  (:action fetch_source_package
    :parameters (?src - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (source_fetched ?src)
    )
  )

  (:action download_source_package
    :parameters (?pkg - package ?dir - directory)
    :precondition (and
      (network_available)
      (not (source_package_downloaded ?pkg))
    )
    :effect (and
      (source_package_downloaded ?pkg)
    )
  )

  (:action compile_to_binary_deb
    :parameters (?src_pkg - package ?arch - interface)
    :precondition (and
      (source_package_downloaded ?src_pkg)
      (not (binary_package_compiled ?src_pkg))
    )
    :effect (and
      (binary_package_compiled ?src_pkg)
    )
  )

  (:action satisfy_build_dependencies
    :parameters (?actor - user ?src_pkg - package ?host_arch - file)
    :precondition (and
      (source_package_downloaded ?src_pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (build_dependencies_satisfied ?src_pkg)
    )
  )

  (:action satisfy_dependencies
    :parameters (?actor - user ?dep_string - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (dependency_satisfied ?dep_string)
      (not (dependency_conflicted ?dep_string))
    )
  )

  (:action download_package
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (package_downloaded ?pkg)
    )
  )

  (:action clear_repository
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (repository_cleared)
    )
  )

  (:action autoclean_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (cache_cleaned)
    )
  )

  (:action clean_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (cache_cleaned)
    )
  )

  (:action cleanup_lists
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (lists_cleaned)
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

  (:action set_default_release
    :parameters (?release - file)
    :precondition (and
    )
    :effect (and
      (default_release_set ?release)
    )
  )

  (:action trivial_operations_only
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (operations_trivial)
    )
  )

  (:action download_diff_only
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (diff_downloaded ?pkg)
    )
  )

  (:action download_dsc_only
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (dsc_downloaded ?pkg)
    )
  )

  (:action download_tar_only
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (tar_downloaded ?pkg)
    )
  )

  (:action process_arch_only
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (arch_build_deps_processed ?pkg)
    )
  )

  (:action process_indep_only
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (indep_build_deps_processed ?pkg)
    )
  )

  (:action allow_unauthenticated
    :parameters (?obj - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (unauthenticated_packages_allowed)
    )
  )

  (:action allow_insecure_repositories
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (insecure_repositories_allowed)
    )
  )

  (:action allow_releaseinfo_change
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (releaseinfo_changes_allowed)
    )
  )

  (:action add_source_file
    :parameters (?actor - user ?src_file - file ?src_type - file)
    :precondition (and
      (not (source_configured ?src_file))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (configures ?src_file ?src_type)
    )
  )

  (:action update_sources
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (sources_updated)
    )
  )

  (:action enable_progress_reporting
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (progress_reporting_enabled)
    )
  )

  (:action allow_release_info_change
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (release_info_changes_allowed)
    )
  )

  (:action set_error_policy_any
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (error_policy_set_to_any)
    )
  )

  (:action set_configuration_option
    :parameters (?config_item - file ?value - file)
    :precondition (and
      (file_exists ?config_item)
    )
    :effect (and
      (configures ?config_item ?value)
    )
  )

  (:action set_apt_config_file
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (configures apt_config ?file)
    )
  )

  (:action configure_package_preferences
    :parameters (?actor - user ?pref_file - file ?pkg - package)
    :precondition (and
      (file_exists ?pref_file)
      (not (preferences_configured ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (preferences_configured ?pkg)
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

  (:action perform_upgrade
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (package_lists_updated)
      (can_escalate ?actor)
    )
    :effect (and
      (system_upgraded)
    )
  )

  (:action remove_unused_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (unused_packages_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (not (unused_packages_exist))
    )
  )

  (:action distribution_upgrade
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (package_lists_updated)
      (can_escalate ?actor)
    )
    :effect (and
      (system_upgraded)
      (dependencies_resolved)
    )
  )

  (:action follow_dselect_selections
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (package_lists_updated)
      (can_escalate ?actor)
    )
    :effect (and
      (system_upgraded)
    )
  )

  (:action configure_build_dependencies
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (build_dependencies_configured)
    )
  )

  (:action satisfy_dependency_strings
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (dependencies_satisfied)
    )
  )

  (:action erase_downloaded_archives
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (downloaded_files_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (not (downloaded_files_exist))
    )
  )

  (:action erase_old_downloaded_archives
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (old_downloaded_files_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (not (old_downloaded_files_exist))
    )
  )

  (:action download_source_archives
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (source_files_downloaded)
    )
  )

  (:action download_binary_package
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (binary_files_downloaded)
    )
  )

  (:action download_changelog
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (changelog_downloaded)
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

  (:action full_upgrade_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_info_updated)
      (can_escalate ?actor)
    )
    :effect (and
      (system_upgraded)
      (some_packages_removed)
    )
  )

  (:action mark_package_explicitly_installed
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_marked_explicit ?pkg)
    )
  )

  (:action download_source
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (source_downloaded ?pkg)
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
      (package_downloaded ?pkg)
    )
  )

  (:action edit_sources_list
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (sources_list_updated)
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
      (change_pending)
      (can_escalate ?actor)
    )
    :effect (and
      (not (change_pending))
    )
  )

  (:action ack_assertion
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (not (assertion_exists))
      (can_escalate ?actor)
    )
    :effect (and
      (assertion_exists)
    )
  )

  (:action add_assertion
    :parameters (?actor - user ?assertion - file)
    :precondition (and
      (not (assertion_exists ?assertion))
      (valid_assertion ?assertion)
      (verified_signature ?assertion)
      (can_escalate ?actor)
    )
    :effect (and
      (assertion_exists ?assertion)
    )
  )

  (:action setup_alias
    :parameters (?actor - user ?app - file ?alias - file)
    :precondition (and
      (application_exists ?app)
      (can_escalate ?actor)
    )
    :effect (and
      (alias_setup ?app ?alias)
    )
  )

  (:action connect_plug_to_slot
    :parameters (?actor - user ?snap - file ?plug - file ?slot - file)
    :precondition (and
      (snap_installed ?snap)
      (not (plug_connected ?snap ?plug))
      (can_escalate ?actor)
    )
    :effect (and
      (plug_connected ?snap ?plug)
    )
  )

  (:action snap_connect_plug_to_slot
    :parameters (?actor - user ?plug - interface ?slot - interface)
    :precondition (and
      (not (connection_exists ?plug ?slot))
      (can_escalate ?actor)
    )
    :effect (and
      (connection_exists ?plug ?slot)
    )
  )

  (:action create_cohort_keys
    :parameters (?actor - user ?snaps - file)
    :precondition (and
      (all_snaps_installed ?snaps)
      (can_escalate ?actor)
    )
    :effect (and
      (cohort_keys_created ?snaps)
    )
  )

  (:action retrieve_feature_tags
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (feature_tags_retrieved)
    )
  )

  (:action retrieve_lsm_status
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (lsm_info_retrieved)
    )
  )

  (:action migrate_snaps_directory
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (snaps_migrated)
    )
  )

  (:action install_from_channel
    :parameters (?actor - user ?snap - file ?channel - file)
    :precondition (and
      (not (package_installed ?snap))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?snap)
      (installed_from_channel ?snap ?channel)
    )
  )

  (:action switch_cohort
    :parameters (?actor - user ?snap - file ?cohort - file)
    :precondition (and
      (package_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (in_cohort ?snap ?cohort)
    )
  )

  (:action leave_cohort
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (package_installed ?snap)
      (in_cohort ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (not (in_cohort ?snap))
    )
  )

  (:action try_no_wait
    :parameters (?actor - user ?snap_package - package ?snap_dir - directory)
    :precondition (and
      (not (package_installed ?snap_package))
      (directory_exists ?snap_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?snap_package)
      (service_running ?snap_package)
    )
  )

  (:action set_snap_mode_development
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_in_development_mode ?snap)
      (not (snap_confinement_enabled ?snap))
    )
  )

  (:action set_snap_mode_confinement
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_confinement_enabled ?snap)
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
      (not (snap_alias_exists ?snap))
    )
  )

  (:action unset_snap_config
    :parameters (?actor - user ?snap - file ?config - file)
    :precondition (and
      (snap_installed ?snap)
      (configures ?config ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (not (configures ?config ?snap))
    )
  )

  (:action forget_validation_set
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (validation_set_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (not (validation_set_exists))
    )
  )

  (:action refresh_validation_snaps
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (validation_set_enforcing)
      (can_escalate ?actor)
    )
    :effect (and
      (snaps_satisfy_constraints)
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
    :parameters (?actor - user ?snap - file ?channel - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_channel_switched ?snap ?channel)
    )
  )

  (:action abort_change
    :parameters (?actor - user ?change - file)
    :precondition (and
      (change_pending ?change)
      (can_escalate ?actor)
    )
    :effect (and
      (not (change_pending ?change))
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

  (:action set_alias
    :parameters (?actor - user ?alias - file ?cmd - file)
    :precondition (and
      (not (alias_exists ?alias))
      (can_escalate ?actor)
    )
    :effect (and
      (alias_exists ?alias)
    )
  )

  (:action unalias
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
      (not (user_logged_in))
    )
    :effect (and
      (user_logged_in)
    )
  )

  (:action logout_snap_store
    :parameters (?obj - file)
    :precondition (and
      (user_logged_in)
    )
    :effect (and
      (not (user_logged_in))
    )
  )

  (:action save_snapshot
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (snapshot_exists ?snap)
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

  (:action import_snapshot
    :parameters (?actor - user ?file - file ?snap - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (snapshot_exists ?snap)
    )
  )

  (:action reboot_device
    :parameters (?actor - user ?system - file ?mode - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (device_rebooted ?system)
    )
  )

  (:action okay_warnings
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (warning_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (not (warning_exists))
    )
  )

  (:action download_snap
    :parameters (?snap - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (snap_downloaded ?snap)
    )
  )

  (:action pack_snap
    :parameters (?dir - directory ?snap - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (snap_packed ?snap)
    )
  )

  (:action run_snap_command
    :parameters (?cmd - process ?snap - file)
    :precondition (and
      (snap_installed ?snap)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action try_snap
    :parameters (?snap - file)
    :precondition (and
      (snap_downloaded ?snap)
    )
    :effect (and
      (snap_tested ?snap)
    )
  )

  (:action sign_assertion
    :parameters (?assert - file)
    :precondition (and
      (file_exists ?assert)
    )
    :effect (and
      (assertion_signed ?assert)
    )
  )

  (:action prepare_device_image
    :parameters (?image - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (device_image_prepared ?image)
    )
  )

  (:action export_key
    :parameters (?key - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (public_key_exported ?key)
    )
  )

  (:action set_quota_group
    :parameters (?actor - user ?group - file ?snap - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (quota_group_set ?group)
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
    :parameters (?actor - user ?directory - directory ?file - file)
    :precondition (and
      (directory_exists ?directory)
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_directory_modified ?directory)
      (journal_file_added ?file)
    )
  )

  (:action view_journal_files_with_header
    :parameters (?obj - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (journal_viewed_with_header)
    )
  )

  (:action operate_on_journal_files
    :parameters (?glob - file ?root_directory - directory)
    :precondition (and
      (directory_exists ?root_directory)
      (exists_matching_glob ?glob)
    )
    :effect (and
      (journalctl_operates_on ?glob)
    )
  )

  (:action operate_on_journal_hierarchy
    :parameters (?root_directory - directory)
    :precondition (and
      (directory_exists ?root_directory)
    )
    :effect (and
      (journalctl_operates_under_root ?root_directory)
    )
  )

  (:action operate_on_disk_image
    :parameters (?image - file)
    :precondition (and
      (file_exists ?image)
    )
    :effect (and
      (journalctl_operates_on_image ?image)
    )
  )

  (:action set_image_policy
    :parameters (?actor - user ?image - file ?policy - file)
    :precondition (and
      (disk_image_exists ?image)
      (not (policy_set_for_image ?image))
      (can_escalate ?actor)
    )
    :effect (and
      (policy_set_for_image ?image)
    )
  )

  (:action collect_data_from_namespace
    :parameters (?actor - user ?namespace - file)
    :precondition (and
      (not (data_collected ?namespace))
      (can_escalate ?actor)
    )
    :effect (and
      (data_collected ?namespace)
    )
  )

  (:action write_cursor_to_file
    :parameters (?file - file ?cursor - directory)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (cursor_written_to_file ?file ?cursor)
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
      (environment_variable_set systemd_pagersecure obj_0)
    )
    :effect (and
      (pager_disabled)
    )
  )

  (:action set_systemd_colors
    :parameters (?mode - file)
    :precondition (and
    )
    :effect (and
      (systemd_colors_enabled ?mode)
    )
  )

  (:action filter_journal
    :parameters (?field - file ?value - file)
    :precondition (and
      (not (filtered_logs ?field))
    )
    :effect (and
      (filtered_logs ?field)
    )
  )

  (:action filter_journal_multiple_fields
    :parameters (?field1 - file ?value1 - file ?field2 - file ?value2 - file)
    :precondition (and
      (not (filtered_logs ?field1))
      (not (filtered_logs ?field2))
    )
    :effect (and
      (filtered_logs ?field1)
      (filtered_logs ?field2)
    )
  )

  (:action view_journal_entries
    :parameters (?unit1 - service ?unit2 - service)
    :precondition (and
      (service_exists ?unit1)
      (service_exists ?unit2)
    )
    :effect (and
      (journal_entry_viewed ?unit1)
      (journal_entry_viewed ?unit2)
    )
  )

  (:action view_journal_entries_with_pid
    :parameters (?unit - service ?pid - process ?unit2 - service)
    :precondition (and
      (service_exists ?unit)
      (process_running ?pid)
      (service_exists ?unit2)
    )
    :effect (and
      (journal_entry_viewed ?unit)
      (journal_entry_viewed ?unit2)
    )
  )

  (:action view_unit_journal_entries
    :parameters (?name - service)
    :precondition (and
      (service_exists ?name)
    )
    :effect (and
      (journal_entry_viewed ?name)
    )
  )

  (:action operate_on_container
    :parameters (?actor - user ?container - interface)
    :precondition (and
      (network_available)
      (interface_exists ?container)
      (can_escalate ?actor)
    )
    :effect (and
      (local_container_operated)
    )
  )

  (:action merge_journals
    :parameters (?obj - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (journals_merged)
    )
  )

  (:action operate_on_alternate_root
    :parameters (?actor - user ?root - directory)
    :precondition (and
      (network_available)
      (directory_exists ?root)
      (can_escalate ?actor)
    )
    :effect (and
      (alternate_root_operated)
    )
  )

  (:action reduce_disk_usage
    :parameters (?actor - user ?bytes - file)
    :precondition (and
      (journal_files_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (disk_usage_below ?bytes)
    )
  )

  (:action leave_journal_files
    :parameters (?actor - user ?num - file)
    :precondition (and
      (journal_files_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (number_of_journal_files ?num)
    )
  )

  (:action remove_old_journals
    :parameters (?actor - user ?time - file)
    :precondition (and
      (journal_files_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (journals_older_than_removed ?time)
    )
  )

  (:action synchronize_journal
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (unwritten_messages_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (messages_synced_to_disk)
    )
  )

  (:action stop_logging_to_disk
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (logging_enabled)
      (can_escalate ?actor)
    )
    :effect (and
      (log_temporary_file_system)
    )
  )

  (:action conditional_stop_logging_to_disk
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (logging_enabled)
      (not (log_directory_on_root))
      (can_escalate ?actor)
    )
    :effect (and
      (log_temporary_file_system)
    )
  )

  (:action flush_journal_data
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (unwritten_messages_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (messages_flushed_to_var)
    )
  )

  (:action rotate_journal_files
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (journal_files_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (journals_rotated)
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

  (:action copy_files_and_directories
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied ?source ?dest)
    )
  )

  (:action recursive_copy_special_files
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (special_file_copied ?source ?dest)
    )
  )

  (:action copy_file_attributes_only
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (attributes_copied ?source ?dest)
    )
  )

  (:action force_copy_or_remove
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?dest)
      (not (can_write_to_file ?dest))
    )
    :effect (and
      (not (file_exists ?dest))
      (file_copied ?src ?dest)
    )
  )

  (:action prompt_before_overwrite
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?dest)
      (not (can_write_to_file ?dest))
    )
    :effect (and
      (user_prompted)
      (file_copied ?src ?dest)
    )
  )

  (:action create_hard_link
    :parameters (?src - file ?dest - file)
    :precondition (and
      (not (file_exists ?dest))
    )
    :effect (and
      (hard_link_created ?src ?dest)
    )
  )

  (:action prevent_overwrite
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?dest)
    )
    :effect (and
      (not (file_copied ?src ?dest))
    )
  )

  (:action do_not_follow_links
    :parameters (?src - file ?dest - file)
    :precondition (and
      (symbolic_link_exists ?src)
    )
    :effect (and
      (not (source_followed ?src))
      (file_copied ?src ?dest)
    )
  )

  (:action preserve_mode_ownership_timestamps
    :parameters (?src - file ?dest - file)
    :precondition (and
      (not (file_exists ?dest))
    )
    :effect (and
      (mode_preserved ?src)
      (ownership_preserved ?src)
      (timestamps_preserved ?src)
    )
  )

  (:action preserve_specified_attributes
    :parameters (?src - file ?dest - file ?attr_list - file)
    :precondition (and
      (not (file_exists ?dest))
    )
    :effect (and
      (attributes_preserved ?attr_list)
    )
  )

  (:action do_not_preserve_specified_attributes
    :parameters (?src - file ?dest - file ?attr_list - file)
    :precondition (and
      (not (file_exists ?dest))
    )
    :effect (and
      (attributes_not_preserved ?attr_list)
    )
  )

  (:action use_full_source_file_name_under_directory
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (not (directory_exists ?dest))
    )
    :effect (and
      (full_path_copied ?src ?dest)
    )
  )

  (:action recursive_copy_directory
    :parameters (?src_dir - directory ?dest_dir - directory)
    :precondition (and
      (directory_exists ?src_dir)
      (directory_exists ?dest_dir)
    )
    :effect (and
      (directory_copied ?src_dir ?dest_dir)
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

  (:action copy_to_file
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_copied ?src ?dest)
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

  (:action update_existing_files
    :parameters (?src - file ?dest - file ?update - file)
    :precondition (and
      (file_exists ?dest)
    )
    :effect (and
      (file_updated ?src ?dest)
    )
  )

  (:action set_default_security_context
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (default_security_context_set ?f)
    )
  )

  (:action set_custom_security_context
    :parameters (?actor - user ?f - file ?ctx - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (custom_security_context_set ?f ?ctx)
    )
  )

  (:action stay_on_filesystem
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (stayed_on_same_filesystem ?src ?dest)
    )
  )

  (:action force_sparse_file_creation
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (is_sparse ?dest)
    )
  )

  (:action set_sparse_option
    :parameters (?option - file)
    :precondition (and
    )
    :effect (and
      (sparse_option_set ?option)
    )
  )

  (:action replace_all_files
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (files_replaced all)
    )
  )

  (:action skip_files
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (files_replaced none)
    )
  )

  (:action replace_older_files
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (files_replaced older)
    )
  )

  (:action reflink_copy
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (copy_method reflink)
    )
  )

  (:action standard_copy
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (copy_method standard)
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

  (:action copy_files
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied_to_directory ?source ?dest)
    )
  )

  (:action copy_files_archive
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied_to_directory_with_archive ?source ?dest)
    )
  )

  (:action copy_files_with_backup
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied_to_directory_with_backup ?source ?dest)
    )
  )

  (:action copy_files_with_backup_no_arg
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied_to_directory_with_backup_no_arg ?source ?dest)
    )
  )

  (:action copy_special_file_contents
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (special_file_copied_to_directory ?source ?dest)
    )
  )

  (:action overwrite_file_forcefully
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?dest)
    )
    :effect (and
      (not (file_exists ?dest))
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

  (:action copy_without_dereferencing_links
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_copied_without_link_dereference ?src ?dest)
    )
  )

  (:action preserve_file_attributes
    :parameters (?f - file ?attrs - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (attributes_preserved ?f attrs)
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

  (:action copy_with_parents
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (full_source_copied_under_directory ?src ?dest)
    )
  )

  (:action copy_files_to_directory
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied ?src ?dest)
    )
  )

  (:action copy_files_to_file
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_copied ?src ?dest)
    )
  )

  (:action update_files
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (file_updated ?src ?dest)
    )
  )

  (:action update_files_older
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (file_updated ?src ?dest)
    )
  )

  (:action copy_within_filesystem
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied_within_fs ?src ?dest)
    )
  )

  (:action set_selinux_context_default
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (selinux_context_set_default ?f)
    )
  )

  (:action set_selinux_context_custom
    :parameters (?f - file ?ctx - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (selinux_context_set_custom ?f ?ctx)
    )
  )

  (:action change_ownership
    :parameters (?actor - user ?f - file ?user - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by_user ?f ?user)
      (owned_by_group ?f ?group)
    )
  )

  (:action change_timestamps
    :parameters (?f - file ?timestamp - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (timestamp_updated ?f)
    )
  )

  (:action update_destination_files
    :parameters (?src - file ?dest - file ?update - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dest)
    )
    :effect (and
      (updated_file ?dest)
    )
  )

  (:action update_file_if_older
    :parameters (?src_file - file ?dest_file - file)
    :precondition (and
      (file_exists ?src_file)
      (file_exists ?dest_file)
      (file_is_older ?dest_file ?src_file)
    )
    :effect (and
      (file_updated ?dest_file)
    )
  )

  (:action fallback_copy
    :parameters (?src_file - file ?dest_file - file)
    :precondition (and
      (not (data_blocks_shared ?src_file ?dest_file))
      (file_exists ?src_file)
    )
    :effect (and
      (file_copied ?dest_file)
    )
  )

  (:action backup_file
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (not (file_exists ?dest))
    )
    :effect (and
      (file_backup_created ?source)
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
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (not (file_exists ?dest))
    )
    :effect (and
      (not (file_exists ?source))
      (file_exists ?dest)
    )
  )

  (:action force_overwrite
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (file_exists ?dest)
    )
    :effect (and
      (not (file_exists ?dest))
      (file_exists ?source)
    )
  )

  (:action interactive_overwrite
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (file_exists ?dest)
    )
    :effect (and
      (not (file_exists ?dest))
      (file_exists ?source)
    )
  )

  (:action no_clobber
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (not (file_exists ?dest))
    )
    :effect (and
      (file_exists ?source)
    )
  )

  (:action no_copy_on_rename_fail
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (not (file_exists ?dest))
    )
    :effect (and
      (file_exists ?source)
    )
  )

  (:action move_file_or_rename
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (not (file_exists ?dest))
    )
    :effect (and
      (file_moved ?source ?dest)
    )
  )

  (:action make_backup
    :parameters (?file - file ?backup_file - file)
    :precondition (and
      (file_exists ?file)
      (not (file_exists ?backup_file))
    )
    :effect (and
      (file_backup_created ?file ?backup_file)
    )
  )

  (:action make_backup_no_arg
    :parameters (?file - file ?backup_file - file)
    :precondition (and
      (file_exists ?file)
      (not (file_exists ?backup_file))
    )
    :effect (and
      (file_backup_created ?file ?backup_file)
    )
  )

  (:action copy_file_no_clobber
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (file_exists ?dest))
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action copy_file_interactive
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (file_exists ?dest))
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action move_files_to_file
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (file_exists ?dest))
    )
    :effect (and
      (not (file_exists ?src))
      (file_exists ?dest)
    )
  )

  (:action copy_file_verbose
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action copy_file_no_copy_on_rename_fail
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (not (file_exists ?dest))
    )
  )

  (:action set_security_context
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (security_context_set ?f)
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
    :parameters (?item - file)
    :precondition (and
      (file_exists ?item) or directory_exists ?item)
    )
    :effect (and
      (not (file_exists ?item))
      (not (directory_exists ?item))
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

  (:action remove_file_interactive_when
    :parameters (?f - file ?when - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action remove_directory_recursive_same_filesystem
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (not (directory_exists ?dir))
    )
  )

  (:action remove_directory_no_preserve_root
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (not (directory_exists ?dir))
    )
  )

  (:action remove_directory_preserve_root
    :parameters (?actor - user ?dir - directory ?preserve - file)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
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
      (is_empty ?dir)
    )
    :effect (and
      (not (directory_exists ?dir))
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

  (:action shred_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action change_file_access_control
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_mode_changed ?f)
    )
  )

  (:action change_permissions_pointed_to_file
    :parameters (?link - file ?target - file)
    :precondition (and
      (is_symbolic_link ?link)
      (points_to ?link ?target)
    )
    :effect (and
      (file_executable ?target)
    )
  )

  (:action ignore_symbolic_links_during_traversal
    :parameters (?dir - directory ?link - file)
    :precondition (and
      (is_directory ?dir)
      (exists_in ?link ?dir)
    )
    :effect (and
      (not (processes_link ?link))
    )
  )

  (:action change_directory_permissions
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_mode_set ?dir ?mode)
    )
  )

  (:action modify_directory_special_bits
    :parameters (?dir - directory ?bit - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_bit_set ?dir ?bit)
      (not (directory_bit_unset ?dir ?bit))
    )
  )

  (:action apply_sticky_bit
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (sticky_bit_set ?dir)
      (not (sticky_bit_unset ?dir))
    )
  )

  (:action change_mode
    :parameters (?file - file ?mode - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (file_has_mode ?file ?mode)
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

  (:action inherit_mode_from_reference
    :parameters (?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
    )
    :effect (and
      (action_completed_inherit_mode_from_reference)
    )
  )

  (:action prevent_recursive_on_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (directory_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (not (can_change_permissions_recursively))
    )
  )

  (:action allow_recursive_on_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (directory_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (can_change_permissions_recursively)
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
      (same_ownership_as ?f ?rfile)
    )
  )

  (:action change_ownership_and_group
    :parameters (?actor - user ?f - file ?owner - user ?group - group ?rfile - file)
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

  (:action change_group_only
    :parameters (?actor - user ?f - file ?group - group)
    :precondition (and
      (file_exists ?f)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by_group ?f ?group)
    )
  )

  (:action change_ownership_and_group_to_reference
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_change_ownership_and_group_to_reference)
    )
  )

  (:action change_owner_group
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by_user ?f ?owner)
      (file_belongs_to_group ?f ?group)
    )
  )

  (:action disable_preserve_root
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (not (preserve_root))
    )
  )

  (:action enable_preserve_root
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (preserve_root)
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

  (:action use_reference_file_owner_group
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_use_reference_file_owner_group)
    )
  )

  (:action traverse_symbolic_link_directory
    :parameters (?link - directory)
    :precondition (and
      (symbolic_link_exists ?link)
    )
    :effect (and
      (traversed_link_to_directory ?link)
    )
  )

  (:action traverse_all_symbolic_links
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (all_links_traversed)
    )
  )

  (:action do_not_traverse_symbolic_links
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (not (all_links_traversed))
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
      (belongs_to_group ?f ?group)
    )
  )

  (:action change_owner_recursive
    :parameters (?actor - user ?owner - user ?dir - directory)
    :precondition (and
      (user_exists ?owner)
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by_all_files_in_directory ?dir ?owner)
    )
  )

  (:action change_ownership_reference
    :parameters (?actor - user ?file - file ?reference_file - file)
    :precondition (and
      (file_exists ?file)
      (file_exists ?reference_file)
      (can_escalate ?actor)
    )
    :effect (and
      (same_owner_as_reference ?file ?reference_file)
      (same_group_as_reference ?file ?reference_file)
    )
  )

  (:action recursive_operation
    :parameters (?dir - directory ?operation - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (operation_performed_on_directory ?dir ?operation)
    )
  )

  (:action use_reference_ownership
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_use_reference_ownership)
    )
  )

  (:action conditional_change_ownership
    :parameters (?actor - user ?f - file ?current_owner - user ?current_group - group ?new_owner - user ?new_group - group)
    :precondition (and
      (file_exists ?f)
      (owned_by_user ?f ?current_owner)
      (owned_by_group ?f ?current_group)
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by_user ?f ?new_owner)
      (owned_by_group ?f ?new_group)
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
      (directory_exists ?dir)
    )
    :effect (and
      (selinux_context_set_to_default ?dir)
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

  (:action touch_access_only
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_updated ?f)
    )
  )

  (:action touch_modification_only
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_modification_time_updated ?f)
    )
  )

  (:action set_file_time_reference
    :parameters (?src_file - file ?dest_file - file)
    :precondition (and
      (file_exists ?src_file)
      (file_exists ?dest_file)
    )
    :effect (and
      (file_time_set_from ?dest_file ?src_file)
    )
  )

  (:action set_file_time_stamp
    :parameters (?f - file ?stamp - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_time_set_to ?f ?stamp)
    )
  )

  (:action set_file_access_time
    :parameters (?f - file ?word - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_set_to ?f ?word)
    )
  )

  (:action set_file_modification_time
    :parameters (?f - file ?word - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_modification_time_set_to ?f ?word)
    )
  )

  (:action ensure_file_exists
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_exists ?f)
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
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (file_access_time_changed ?dst)
      (file_modification_time_changed ?dst)
    )
  )

  (:action no_dereference_link
    :parameters (?link - file)
    :precondition (and
      (symlink_exists ?link)
    )
    :effect (and
      (symlink_access_time_changed ?link)
      (symlink_modification_time_changed ?link)
    )
  )

  (:action change_access_time_only
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_changed ?f)
    )
  )

  (:action change_modification_time_only
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_modification_time_changed ?f)
    )
  )

  (:action update_file_timestamp
    :parameters (?f - file ?timestamp - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_modified_time_updated ?f)
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

  (:action manipulate_routing
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (routing_updated)
    )
  )

  (:action execute_batch_commands
    :parameters (?actor - user ?filename - file)
    :precondition (and
      (file_exists ?filename)
      (can_escalate ?actor)
    )
    :effect (and
      (commands_executed ?filename)
    )
  )

  (:action output_human_readable_statistics
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (statistics_human_readable)
    )
  )

  (:action execute_command_in_netns
    :parameters (?actor - user ?netns - interface ?obj - file ?cmd - file)
    :precondition (and
      (interface_exists ?netns)
      (object_exists ?obj)
      (can_escalate ?actor)
    )
    :effect (and
      (command_executed ?cmd)
    )
  )

  (:action execute_command_on_all_objects
    :parameters (?obj - file ?cmd - file)
    :precondition (and
      (object_exists ?obj)
    )
    :effect (and
      (command_executed_on_all ?cmd)
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

  (:action manage_netns
    :parameters (?actor - user ?netns - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (network_namespace_exists ?netns)
    )
  )

  (:action manage_ioam_namespace_schema
    :parameters (?actor - user ?ioam_ns - file ?ioam_schema - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (ioam_namespace_exists ?ioam_ns)
      (ioam_schema_exists ?ioam_schema)
    )
  )

  (:action manage_neighbour_cache_entry
    :parameters (?actor - user ?neigh - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (neighbour_cache_entry_exists ?neigh)
    )
  )

  (:action manage_tuntap_device
    :parameters (?actor - user ?tuntap - file ?iface - interface)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (tuntap_device_exists ?tuntap)
    )
  )

  (:action manage_neighbour_cache_operation
    :parameters (?actor - user ?ntable - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (neighbour_cache_operation_set ?ntable)
    )
  )

  (:action manage_tcp_metrics
    :parameters (?actor - user ?tcp_metric - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (tcp_metric_configured ?tcp_metric)
    )
  )

  (:action manage_tokenized_interface_identifier
    :parameters (?actor - user ?token - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (tokenized_interface_identifier_set ?token)
    )
  )

  (:action manage_mptcp_path_manager
    :parameters (?actor - user ?mptcp - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (mptcp_path_manager_configured ?mptcp)
    )
  )

  (:action manage_multicast_routing_policy_database
    :parameters (?actor - user ?mrule - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (multicast_routing_policy_configured ?mrule)
    )
  )

  (:action manage_routing_policy_database
    :parameters (?actor - user ?rule - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (routing_policy_configured ?rule)
    )
  )

  (:action manage_interface_statistics
    :parameters (?actor - user ?stats - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (interface_statistics_configured ?stats)
    )
  )

  (:action manage_routing_table_entry
    :parameters (?actor - user ?route - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (routing_table_entry_configured ?route)
    )
  )

  (:action manage_multicast_routing_cache_entry
    :parameters (?actor - user ?mroute - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (multicast_routing_cache_configured ?mroute)
    )
  )

  (:action manage_multicast_address
    :parameters (?actor - user ?maddress - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (multicast_address_configured ?maddress)
    )
  )

  (:action manage_l2tp_tunnel
    :parameters (?actor - user ?l2tp - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (l2tp_tunnel_configured ?l2tp)
    )
  )

  (:action manage_ip_tunnel
    :parameters (?actor - user ?tunnel - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (ip_tunnel_configured ?tunnel)
    )
  )

  (:action manage_network_device
    :parameters (?actor - user ?link - file ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (network_device_configured ?link)
    )
  )

  (:action manage_vrf
    :parameters (?actor - user ?vrf - interface)
    :precondition (and
      (interface_exists ?vrf)
      (can_escalate ?actor)
    )
    :effect (and
      (vrf_configured ?vrf)
    )
  )

  (:action manage_ipsec_policy
    :parameters (?actor - user ?policy - firewall_rule)
    :precondition (and
      (not (firewall_rule_exists ?policy))
      (can_escalate ?actor)
    )
    :effect (and
      (ipsec_policy_configured ?policy)
    )
  )

  (:action bring_up_interface
    :parameters (?actor - user ?interface - interface)
    :precondition (and
      (interface_exists ?interface)
      (not (port_open ?interface))
      (can_escalate ?actor)
    )
    :effect (and
      (port_open ?interface)
    )
  )

  (:action bring_down_interface
    :parameters (?actor - user ?interface - interface)
    :precondition (and
      (interface_exists ?interface)
      (port_open ?interface)
      (can_escalate ?actor)
    )
    :effect (and
      (not (port_open ?interface))
    )
  )

  (:action manage_network_object
    :parameters (?obj_type - file ?cmd - file)
    :precondition (and
      (network_available)
    )
    :effect (and
      (network_object_modified ?obj_type)
    )
  )

  (:action execute_network_batch_commands
    :parameters (?filename - file)
    :precondition (and
      (network_available)
      (file_exists ?filename)
    )
    :effect (and
      (network_objects_modified)
    )
  )

  (:action enable_masquerade
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (masquerade_enabled)
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

  (:action sudo_command
    :parameters (?cmd - process ?target_user - user)
    :precondition (and
      (user_exists ?target_user)
      (can_escalate ?target_user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action sudo_command_as_superuser
    :parameters (?cmd - process)
    :precondition (and
      (can_escalate root)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action sudo_command_with_env_vars
    :parameters (?env_var - file ?cmd - process ?target_user - user)
    :precondition (and
      (user_exists ?target_user)
      (can_escalate ?target_user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action sudo_edit_file
    :parameters (?file - file ?target_user - user)
    :precondition (and
      (user_exists ?target_user)
      (can_escalate ?target_user)
    )
    :effect (and
      (file_modified ?file)
    )
  )

  (:action background_sudo_command
    :parameters (?cmd - process ?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action askpass_sudo_command
    :parameters (?cmd - process ?user - user ?askpass_program - file)
    :precondition (and
      (can_escalate ?user)
      (file_exists ?askpass_program)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action change_working_directory
    :parameters (?actor - user ?dir - directory ?cmd - file)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (working_directory_changed_to ?dir)
    )
  )

  (:action preserve_environment_variables
    :parameters (?actor - user ?cmd - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (environment_preserved)
    )
  )

  (:action edit_files_with_sudo
    :parameters (?user - user ?files - file)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (file_edited_by_user ?files)
    )
  )

  (:action edit_sudoers_file
    :parameters (?actor - user ?f - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (not (is_unauthorized_edit ?f))
      (can_escalate ?actor)
    )
    :effect (and
      (sudoers_modified ?f)
    )
  )

  (:action restore_original_file
    :parameters (?temp_f - file ?orig_f - file)
    :precondition (and
      (file_exists ?temp_f)
      (not (file_exists ?orig_f))
    )
    :effect (and
      (file_exists ?orig_f)
      (not (file_exists ?temp_f))
    )
  )

  (:action enforce_edit_restrictions
    :parameters (?actor - user ?f - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (is_unauthorized_edit ?f)
    )
  )

  (:action prevent_following_symlinks
    :parameters (?actor - user ?f - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (follows_symlink ?f))
    )
  )

  (:action prevent_editing_writable_directory_files
    :parameters (?actor - user ?f - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (editable_in_writable_dir ?f))
    )
  )

  (:action prevent_editing_device_files
    :parameters (?actor - user ?dev - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (editable_device_file ?dev))
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
      (primary_group_of_user ?user ?grp)
    )
  )

  (:action set_home_env
    :parameters (?actor - user ?user - user ?home - directory)
    :precondition (and
      (user_exists ?user)
      (directory_exists ?home)
      (can_escalate ?actor)
    )
    :effect (and
      (home_set ?user ?home)
    )
  )

  (:action run_login_shell
    :parameters (?actor - user ?user - user ?cmd - process)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (shell_running_as_user ?cmd ?user)
    )
  )

  (:action sudo_execute_command
    :parameters (?cmd - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action run_shell_with_sudo
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action edit_file_as_user_group
    :parameters (?actor - user ?f - file ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (file_edited_by_user_and_group ?f ?u ?g)
    )
  )

  (:action edit_file_in_writable_directory
    :parameters (?actor - user ?file - file ?dir - directory)
    :precondition (and
      (not (directory_writable_by_user ?dir))
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (file_edited ?file)
    )
  )

  (:action edit_symbolic_link
    :parameters (?actor - user ?link - file ?target - file)
    :precondition (and
      (not (symbolic_link_followed ?link))
      (file_exists ?target)
      (can_escalate ?actor)
    )
    :effect (and
      (file_edited ?target)
    )
  )

  (:action set_sudo_permissions
    :parameters (?actor - user ?f - file)
    :precondition (and
      (not (file_owned_by_root ?f))
      (not (file_setuid ?f))
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by_root ?f)
      (file_setuid ?f)
    )
  )

  (:action disable_no_new_privileges_flag
    :parameters (?actor - user ?proc - process)
    :precondition (and
      (process_running ?proc)
      (process_has_no_new_privileges_flag ?proc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_has_no_new_privileges_flag ?proc))
    )
  )

  (:action add_user_to_passwd_database
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
    )
  )

  (:action reset_password_timeout
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (password_timeout_expired)
      (can_escalate ?actor)
    )
    :effect (and
      (not (password_timeout_expired))
    )
  )

  (:action enable_sudoedit_support
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (not (platform_supports_sudoedit))
      (can_escalate ?actor)
    )
    :effect (and
      (platform_supports_sudoedit)
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

  (:action sudo_chdir
    :parameters (?d - directory ?user - user)
    :precondition (and
      (can_escalate ?user)
      (directory_exists ?d)
    )
    :effect (and
      (working_directory_changed ?d)
    )
  )

  (:action sudo_preserve_env
    :parameters (?cmd - process ?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (environment_preserved ?cmd)
    )
  )

  (:action sudo_set_home
    :parameters (?cmd - process ?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (home_variable_set ?cmd)
    )
  )

  (:action sudo_background_command
    :parameters (?cmd - process ?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (background_process_running ?cmd)
    )
  )

  (:action sudo_group_command
    :parameters (?cmd - process ?user - user ?grp - group)
    :precondition (and
      (can_escalate ?user)
      (group_exists ?grp)
    )
    :effect (and
      (command_run_as_group ?cmd)
    )
  )

  (:action run_shell_as_user
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action switch_user
    :parameters (?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (user_exists ?user)
      (not (user_critical ?user))
    )
  )

  (:action switch_user_with_args
    :parameters (?user - user ?args - file)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (user_exists ?user)
      (not (user_critical ?user))
    )
  )

  (:action configure_pam_for_su
    :parameters (?actor - user ?config_file - file ?service - file)
    :precondition (and
      (file_exists ?config_file)
      (service_exists ?service)
      (can_escalate ?actor)
    )
    :effect (and
      (configures ?config_file ?service)
    )
  )

  (:action run_privileged_command
    :parameters (?cmd - file ?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action set_privileged_command
    :parameters (?cmd - file ?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action execute_command_with_su
    :parameters (?cmd - file ?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action execute_fast_su_command
    :parameters (?cmd - file ?user - user)
    :precondition (and
      (user_exists ?user)
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
      (shell_is_login ?user)
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

  (:action run_shell
    :parameters (?shell - file ?user - user)
    :precondition (and
      (can_escalate ?user)
      (file_exists ?shell)
    )
    :effect (and
      (shell_running_for_user ?shell ?user)
    )
  )

  (:action terminate_child_and_self
    :parameters (?p - process)
    :precondition (and
      (process_running ?p)
    )
    :effect (and
      (not (process_running ?p))
    )
  )

  (:action kill_child
    :parameters (?p - process)
    :precondition (and
      (process_running ?p)
    )
    :effect (and
      (not (process_running ?p))
    )
  )

  (:action read_config_files
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (config_file_read ?f)
    )
  )

  (:action set_fail_delay
    :parameters (?actor - user ?delay - file ?config - file)
    :precondition (and
      (config_file_read ?config)
      (can_escalate ?actor)
    )
    :effect (and
      (fail_delay_set ?delay)
    )
  )

  (:action set_env_path
    :parameters (?actor - user ?path - file ?config - file)
    :precondition (and
      (config_file_read ?config)
      (can_escalate ?actor)
    )
    :effect (and
      (env_path_set ?path)
    )
  )

  (:action set_always_set_path
    :parameters (?actor - user ?setting - file ?config - file)
    :precondition (and
      (config_file_read ?config)
      (can_escalate ?actor)
    )
    :effect (and
      (always_set_path_configured ?setting)
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

  (:action add_supplemental_group
    :parameters (?supp_group - group ?user - user)
    :precondition (and
      (can_escalate ?user)
      (user_exists ?user)
      (group_exists ?supp_group)
    )
    :effect (and
      (user_in_group ?user ?supp_group)
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
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (default_user_updated)
    )
  )

  (:action add_user
    :parameters (?actor - user ?user - user ?home_dir - directory ?comment - file)
    :precondition (and
      (not (user_exists ?user))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (home_directory_set ?user ?home_dir)
      (comment_set ?user ?comment)
    )
  )

  (:action set_account_expiration
    :parameters (?actor - user ?user - user ?expire_date - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (account_expired_on ?user ?expire_date)
    )
  )

  (:action set_default_home_base
    :parameters (?actor - user ?base_dir - directory)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (default_home_base_set ?base_dir)
    )
  )

  (:action set_default_user_creation_values
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (default_values_set)
    )
  )

  (:action set_user_expiry_date
    :parameters (?actor - user ?u - user ?d - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_expiry_date_set ?u ?d)
    )
  )

  (:action set_password_inactive_period
    :parameters (?actor - user ?u - user ?i - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (password_inactive_period_set ?u ?i)
    )
  )

  (:action update_subuids_for_system_account
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (subuids_updated ?u)
    )
  )

  (:action set_user_primary_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (primary_group_set ?u ?g)
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
      (files_copied_from_skel ?user ?skel_dir)
    )
  )

  (:action set_login_def
    :parameters (?actor - user ?key - file ?value - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (login_def_set ?key ?value)
    )
  )

  (:action disable_log_init
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (no_lastlog_entry ?user)
      (no_faillog_entry ?user)
    )
  )

  (:action reset_user_logs
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (lastlog_entry ?u))
      (not (faillog_entry ?u))
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

  (:action create_user_without_group
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

  (:action create_user_with_non_unique_uid
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (not (user_exists ?user))
      (uid_exists ?uid)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (has_uid ?user ?uid)
    )
  )

  (:action set_user_password
    :parameters (?actor - user ?user - user ?password - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (has_password ?user ?password)
    )
  )

  (:action create_system_account
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (not (user_exists ?user))
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (user_critical ?user)
      (not (can_escalate ?user))
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
      (home_directory_created ?dir)
      (user_in_group ?user ?group)
    )
  )

  (:action update_subid_files_for_account
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_updated ?user)
      (subgid_updated ?group)
    )
  )

  (:action apply_changes_in_chroot_directory
    :parameters (?actor - user ?chroot_dir - directory ?config_file - file)
    :precondition (and
      (directory_exists ?chroot_dir)
      (file_exists ?config_file)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_chroot ?chroot_dir)
    )
  )

  (:action apply_changes_under_prefix_directory
    :parameters (?actor - user ?prefix_dir - directory ?config_file - file)
    :precondition (and
      (directory_exists ?prefix_dir)
      (file_exists ?config_file)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_under_prefix ?prefix_dir)
    )
  )

  (:action set_user_shell_path
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

  (:action create_user_group
    :parameters (?actor - user ?user - user ?grp - group)
    :precondition (and
      (not (group_exists ?grp))
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
      (user_in_group ?user ?grp)
    )
  )

  (:action set_user_id
    :parameters (?actor - user ?uid - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (user_has_uid ?user ?uid))
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_uid ?user ?uid)
    )
  )

  (:action set_selinux_user
    :parameters (?actor - user ?seuser - file ?user - user)
    :precondition (and
      (not (selinux_user_set ?user))
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_user_set ?user)
      (has_selinux_user ?user ?seuser)
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

  (:action set_home_directory_mode
    :parameters (?actor - user ?u - user ?m - file)
    :precondition (and
      (user_exists ?u)
      (home_directory_created ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_mode_set ?u ?m)
    )
  )

  (:action configure_login_defs
    :parameters (?actor - user ?var - file ?value - file)
    :precondition (and
      (config_file_exists ?var)
      (can_escalate ?actor)
    )
    :effect (and
      (login_def_configured ?var ?value)
    )
  )

  (:action configure_lastlog_uid_max
    :parameters (?actor - user ?cfg - file ?uid_limit - file)
    :precondition (and
      (configures ?cfg lastlog_config)
      (not (lastlog_uid_max_set ?cfg))
      (can_escalate ?actor)
    )
    :effect (and
      (lastlog_uid_max_set ?cfg)
    )
  )

  (:action set_mail_spool_directory
    :parameters (?actor - user ?cfg - file ?dir - file)
    :precondition (and
      (configures ?cfg mail_config)
      (not (mail_dir_set ?cfg))
      (can_escalate ?actor)
    )
    :effect (and
      (mail_dir_set ?cfg)
    )
  )

  (:action set_mail_file_location
    :parameters (?actor - user ?cfg - file ?file - file)
    :precondition (and
      (configures ?cfg mail_config)
      (not (mail_file_set ?cfg))
      (can_escalate ?actor)
    )
    :effect (and
      (mail_file_set ?cfg)
    )
  )

  (:action modify_user
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_modified ?u)
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
    :parameters (?actor - user ?g - group ?n - file)
    :precondition (and
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (max_members_per_group ?g ?n)
    )
  )

  (:action set_pass_max_days
    :parameters (?actor - user ?u - user ?n - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (pass_max_days ?u ?n)
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
      (subordinate_gid_min_set ?min)
      (subordinate_gid_max_set ?max)
      (subordinate_gid_count_set ?count)
    )
  )

  (:action create_system_group
    :parameters (?actor - user ?group - group ?gid - file)
    :precondition (and
      (not (group_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
    )
  )

  (:action create_system_user
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action create_regular_user
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action set_default_umask
    :parameters (?actor - user ?umask - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_umask_set ?umask)
    )
  )

  (:action remove_user_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (not (member_of_any_other_groups ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?g))
      (not (user_in_group ?u ?g))
    )
  )

  (:action execute_user_addition_scripts
    :parameters (?actor - user ?scripts - file ?u - user)
    :precondition (and
      (user_exists ?u)
      (file_exists ?scripts)
      (can_escalate ?actor)
    )
    :effect (and
      (script_executed ?scripts)
    )
  )

  (:action configure_default_user
    :parameters (?actor - user ?base_dir - directory ?comment - file ?home_dir - directory ?expire_date - file ?inactive - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (default_base_directory_set ?base_dir)
      (default_comment_set ?comment)
      (default_home_directory_set ?home_dir)
      (default_expire_date_set ?expire_date)
      (default_inactive_period_set ?inactive)
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
      (subuid_added ?user ?group)
    )
  )

  (:action disable_home_directory_creation
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_not_created ?user)
    )
  )

  (:action disable_user_group_creation
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (no_user_group_created ?user)
    )
  )

  (:action allow_duplicate_users
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (non_unique_user_created ?user)
    )
  )

  (:action add_system_user
    :parameters (?actor - user ?user - user ?uid - file ?password - file ?shell - file ?group - group)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (user_critical ?user)
      (configures ?password ?user)
      (configures ?shell ?user)
      (depends_on ?group ?user)
    )
  )

  (:action add_user_group
    :parameters (?actor - user ?group - group ?user - user)
    :precondition (and
      (not (group_exists ?group))
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
      (depends_on ?group ?user)
    )
  )

  (:action set_selinux_user_mapping
    :parameters (?actor - user ?user - user ?seuser - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (configures ?seuser ?user)
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

  (:action set_user_home_directory
    :parameters (?actor - user ?user - user ?home_dir - directory)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_home_set ?user)
    )
  )

  (:action set_user_expire_date
    :parameters (?actor - user ?user - user ?expire_date - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_expire_set ?user)
    )
  )

  (:action set_inactive_period
    :parameters (?actor - user ?user - user ?days - file)
    :precondition (and
      (user_exists ?user)
      (file_exists shadow_file)
      (can_escalate ?actor)
    )
    :effect (and
      (inactive_period_set ?user ?days)
    )
  )

  (:action change_primary_group
    :parameters (?actor - user ?user - user ?new_group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?new_group)
      (can_escalate ?actor)
    )
    :effect (and
      (primary_group_of_user ?user ?new_group)
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
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_locked ?user)
    )
  )

  (:action move_home_directory
    :parameters (?actor - user ?user - user ?old_dir - directory ?new_dir - directory)
    :precondition (and
      (user_exists ?user)
      (directory_exists ?old_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (not (home_directory ?user ?old_dir))
      (home_directory ?user ?new_dir)
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
    :parameters (?actor - user ?u - user ?uid - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (uid_non_unique ?u)
      (user_id_set ?u ?uid)
    )
  )

  (:action remove_user_from_group
    :parameters (?actor - user ?user - user ?grp - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?grp)
      (user_in_group ?user ?grp)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_in_group ?user ?grp))
    )
  )

  (:action chroot_apply_changes
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_chroot_dir ?dir)
    )
  )

  (:action prefix_apply_changes
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_prefix_dir ?dir)
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

  (:action unlock_user_password
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (not (password_unlocked ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (password_unlocked ?u)
    )
  )

  (:action change_user_id
    :parameters (?actor - user ?u - user ?new_uid - file)
    :precondition (and
      (user_exists ?u)
      (not (uid_equal ?u ?new_uid))
      (can_escalate ?actor)
    )
    :effect (and
      (uid_equal ?u ?new_uid)
    )
  )

  (:action change_file_ownership
    :parameters (?actor - user ?f - file ?u - user)
    :precondition (and
      (file_exists ?f)
      (not (owned_by_user ?f ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by_user ?f ?u)
    )
  )

  (:action add_subordinate_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uid_range_added ?user ?first ?last)
    )
  )

  (:action remove_subordinate_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (subordinate_uid_range_added ?user ?first ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subordinate_uid_range_added ?user ?first ?last))
    )
  )

  (:action add_subordinate_gids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gid_range_added ?user ?first ?last)
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
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uids_allocated ?user)
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

  (:action set_account_expiration_date
    :parameters (?actor - user ?user - user ?expire_date - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (account_expires_on ?user ?expire_date)
    )
  )

  (:action set_password_inactive_after_expiration
    :parameters (?actor - user ?user - user ?inactive_period - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_inactivates_after_expiration ?user ?inactive_period)
    )
  )

  (:action change_login_name
    :parameters (?actor - user ?old_user - user ?new_login - file)
    :precondition (and
      (user_exists ?old_user)
      (can_escalate ?actor)
    )
    :effect (and
      (login_of_user ?new_login ?old_user)
    )
  )

  (:action change_home_directory
    :parameters (?actor - user ?user - user ?new_home - directory)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_of_user ?user ?new_home)
    )
  )

  (:action set_gecos_field
    :parameters (?actor - user ?user - user ?comment - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (gecos_of_user ?user ?comment)
    )
  )

  (:action allow_non_unique_uid
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (non_unique_uid_of_user ?user ?uid)
    )
  )

  (:action allow_bad_names
    :parameters (?actor - user ?user - user ?new_login - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (bad_name_of_user ?new_login ?user)
    )
  )

  (:action set_login_shell
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

  (:action delete_user_account
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

  (:action remove_user
    :parameters (?actor - user ?usr - user ?grp - group)
    :precondition (and
      (user_exists ?usr)
      (not (user_critical ?usr))
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?usr))
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

  (:action manage_mail_spool
    :parameters (?actor - user ?user - user ?action - file)
    :precondition (and
      (user_exists ?user)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_action ?user)
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
      (executed_userdel_cmd ?cmd ?usr)
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

  (:action update_group_file
    :parameters (?actor - user ?group - file)
    :precondition (and
      (file_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (updated_group_file ?group)
    )
  )

  (:action update_passwd_file
    :parameters (?actor - user ?passwd - file)
    :precondition (and
      (file_exists ?passwd)
      (can_escalate ?actor)
    )
    :effect (and
      (updated_passwd_file ?passwd)
    )
  )

  (:action execute_user_deletion_scripts
    :parameters (?actor - user ?scripts - file ?u - user)
    :precondition (and
      (user_exists ?u)
      (script_exists ?scripts)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u))
      (not (user_critical ?u))
    )
  )

  (:action update_subordinate_group_ids
    :parameters (?actor - user ?subgid - file ?u - user)
    :precondition (and
      (user_exists ?u)
      (file_exists ?subgid)
      (can_escalate ?actor)
    )
    :effect (and
      (updated_subordinate_group_ids ?u)
    )
  )

  (:action update_subordinate_user_ids
    :parameters (?actor - user ?subuid - file ?u - user)
    :precondition (and
      (user_exists ?u)
      (file_exists ?subuid)
      (can_escalate ?actor)
    )
    :effect (and
      (updated_subordinate_user_ids ?u)
    )
  )

  (:action force_delete_user_group
    :parameters (?actor - user ?grp - group ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?grp))
    )
  )

  (:action add_group
    :parameters (?actor - user ?grp - group)
    :precondition (and
      (not (group_exists ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

  (:action force_add_group
    :parameters (?actor - user ?grp - group)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

  (:action set_group_defaults
    :parameters (?actor - user ?min_gid - file ?max_gid - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_default_set ?min_gid)
      (group_default_set ?max_gid)
    )
  )

  (:action create_non_unique_group
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

  (:action set_group_password
    :parameters (?actor - user ?group - group ?encrypted_password - file)
    :precondition (and
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (group_has_password ?group)
    )
  )

  (:action set_gid_range
    :parameters (?actor - user ?min - file ?max - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (gid_min ?min)
      (gid_max ?max)
    )
  )

  (:action set_sys_gid_range
    :parameters (?actor - user ?min - file ?max - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (sys_gid_min ?min)
      (sys_gid_max ?max)
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

  (:action add_users_to_group
    :parameters (?actor - user ?user - user ?grp - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?grp)
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_group ?user ?grp)
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