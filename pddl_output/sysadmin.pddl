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
    (config_files_exist ?x0 - object)
    (package_list_updated )
    (package_updates_exist )
    (packages_upgraded )
    (dependencies_resolved )
    (unused_dependencies_exist )
    (packages_removed )
    (dependencies_cleaned )
    (package_cache_exists )
    (package_cache_cleaned )
    (old_package_files_exist )
    (package_downloaded ?x0 - object)
    (source_package_downloaded ?x0 - object)
    (dependencies_installed ?x0 - object)
    (package_index_updated )
    (sources_list_valid )
    (newer_version_available ?x0 - object)
    (package_updated ?x0 - object)
    (package_exists ?x0 - object)
    (policy_applied_to_package ?x0 - object)
    (?policy )
    (package_reinstalled ?x0 - object)
    (source_fetched ?x0 - object)
    (source_repository_configured )
    (source_package_info_fetched ?x0 - object)
    (build_dependencies_installed )
    (binary_package_compiled ?x0 - object)
    (source_package_exists ?x0 - object)
    (build_dependencies_satisfied ?x0 - object)
    (apt_cache_updated )
    (dependencies_satisfied ?x0 - object)
    (apt_cache_exists )
    (cache_cleared )
    (directory_exists ?x0 - object)
    (cache_cleaned ?x0 - object)
    (lists_cleaned ?x0 - object)
    (package_marked_as_auto ?x0 - object)
    (package_to_be_removed )
    (cannot_remove_packages )
    (unused_dependency_exists )
    (no_unused_dependencies )
    (fetched_source_code ?x0 - object)
    (apt_config_exists )
    (valid_apt_option ?x0 - object)
    (configuration_set ?x0 - object ?x1 - object)
    (apt_config_set_to ?x0 - object)
    (root_privileges )
    (packages_installed ?x0 - object ?x1 - object ?x2 - object ?x3 - object)
    (package_lists_updated )
    (unused_packages_exist )
    (system_upgraded )
    (build_dependencies_configured ?x0 - object)
    (downloaded_files_exist )
    (old_downloaded_files_exist )
    (source_files_downloaded )
    (binary_files_downloaded )
    (all_packages_updated )
    (system_optimized )
    (package_info_updated )
    (system_up_to_date )
    (package_from_release ?x0 - object ?x1 - object)
    (automatically_installed ?x0 - object)
    (manually_installed ?x0 - object)
    (sources_file_exists )
    (sources_updated )
    (cache_exists )
    (cache_autocleaned )
    (cache_distcleaned )
    (valid_command ?x0 - object)
    (executed_subcommand ?x0 - object)
    (old_package_installed ?x0 - object)
    (new_package_to_install )
    (prerm_executed ?x0 - object)
    (script_exists ?x0 - object)
    (preinst_executed ?x0 - object)
    (files_unpacked ?x0 - object)
    (old_files_backed_up ?x0 - object)
    (postrm_executed ?x0 - object)
    (package_file_exists ?x0 - object)
    (package_reconfigured ?x0 - object)
    (triggers_pending ?x0 - object)
    (triggers_processed ?x0 - object)
    (packages_pending_configuration )
    (all_packages_configured )
    (package_availability_updated )
    (package_manager_available )
    (contains_package_selections ?x0 - object)
    (selections_exist )
    (no_selections )
    (selections_set )
    (packages_updated )
    (available_info_exists )
    (architecture_exists ?x0 - object)
    (package_reverted ?x0 - object)
    (package_enabled ?x0 - object)
    (change_pending ?x0 - object)
    (assertion_not_added )
    (assertion_added )
    (application_exists ?x0 - object)
    (alias_set ?x0 - object)
    (plug_exists ?x0 - object)
    (slot_exists ?x0 - object)
    (connected ?x0 - object ?x1 - object)
    (snap_installed ?x0 - object)
    (slot_matches_interface ?x0 - object ?x1 - object)
    (plug_connected_to_slot ?x0 - object ?x1 - object ?x2 - object ?x3 - object)
    (all_snaps_installed ?x0 - object)
    (cohort_keys_created ?x0 - object)
    (snap_installed_in_devmode )
    (snap_in_development_mode ?x0 - object)
    (snap_in_classic_mode ?x0 - object)
    (alias_exists ?x0 - object)
    (configuration_exists ?x0 - object ?x1 - object)
    (attribute_exists ?x0 - object ?x1 - object)
    (attribute_set ?x0 - object ?x1 - object)
    (validation_set_exists )
    (validation_set_enforced )
    (snaps_satisfy_validation )
    (snap_on_channel ?x0 - object ?x1 - object)
    (logged_in )
    (snapshot_exists ?x0 - object)
    (system_restored_from_snapshot ?x0 - object)
    (system_exists ?x0 - object)
    (mode_valid ?x0 - object)
    (device_rebooted_into_system_and_mode ?x0 - object ?x1 - object)
    (assertion_exists ?x0 - object)
    (snap_downloaded ?x0 - object)
    (snap_packed ?x0 - object)
    (command_executed ?x0 - object)
    (snap_unpacked ?x0 - object)
    (snap_tested ?x0 - object)
    (assertion_signed ?x0 - object)
    (device_image_prepared ?x0 - object)
    (public_key_exists )
    (key_exported ?x0 - object)
    (quota_group_exists ?x0 - object ?x1 - object ?x2 - object ?x3 - object)
    (quota_group_updated ?x0 - object)
    (journal_files_exist )
    (disk_usage_greater_than ?x0 - object)
    (disk_usage_less_than_or_equal_to ?x0 - object)
    (number_of_journal_files ?x0 - object)
    (no_journal_older_than ?x0 - object)
    (unwritten_journal_messages_exist )
    (all_journals_synced_to_disk )
    (journals_exist )
    (new_journal_files_created )
    (all_unwritten_data_flushed_to_disk )
    (logging_to_disk )
    (logging_to_temporary_file_system )
    (log_directory_not_on_root_mount )
    (catalog_exists )
    (catalog_updated )
    (keys_exist )
    (keys_generated )
    (file_copied_to ?x0 - object ?x1 - object)
    (files_exist ?x0 - object)
    (files_copied_to ?x0 - object ?x1 - object)
    (file_backed_up_to ?x0 - object ?x1 - object)
    (special_files_copied_to ?x0 - object ?x1 - object)
    (file_copied ?x0 - object ?x1 - object)
    (symbolic_link_created ?x0 - object ?x1 - object)
    (file_updated ?x0 - object ?x1 - object)
    (file_updated_if_older ?x0 - object ?x1 - object)
    (security_context_default ?x0 - object)
    (security_context_set ?x0 - object)
    (sparse_file_created ?x0 - object)
    (sparse_files_inhibited )
    (file_copied_lightweight ?x0 - object ?x1 - object)
    (file_copied_standard ?x0 - object ?x1 - object)
    (backup_suffix_set ?x0 - object)
    (file_copied_no_deref ?x0 - object ?x1 - object)
    (attributes_preserved ?x0 - object ?x1 - object ?x2 - object)
    (destination_removed_before_copy ?x0 - object ?x1 - object)
    (reflink_copied ?x0 - object ?x1 - object ?x2 - object)
    (file_copied_to_directory ?x0 - object ?x1 - object)
    (directory_exists_or_createable ?x0 - object)
    (file_copied_to_file ?x0 - object ?x1 - object)
    (files_updated ?x0 - object)
    (files_copied_within_filesystem ?x0 - object ?x1 - object)
    (selinux_context_set_to_default ?x0 - object)
    (selinux_context_set_to_custom ?x0 - object ?x1 - object)
    (file_owned_by_user ?x0 - object ?x1 - object)
    (file_owned_by_group ?x0 - object ?x1 - object)
    (file_has_timestamp ?x0 - object ?x1 - object)
    (file_older_than ?x0 - object ?x1 - object)
    (file_backed_up ?x0 - object)
    (backup_has_suffix ?x0 - object ?x1 - object)
    (backup_method_set ?x0 - object)
    (same_name ?x0 - object ?x1 - object)
    (file_backup_created ?x0 - object)
    (file_moved_forcefully ?x0 - object ?x1 - object)
    (file_moved_interactively ?x0 - object ?x1 - object)
    (file_not_moved_if_exists ?x0 - object ?x1 - object)
    (file_moved ?x0 - object)
    (file_not_copied_if_rename_fails ?x0 - object)
    (dest_is_directory ?x0 - object)
    (selinux_context_default ?x0 - object)
    (version_control_set )
    (dir_exists ?x0 - object)
    (is_empty_directory ?x0 - object)
    (is_empty ?x0 - object)
    (is_root_dir ?x0 - object)
    (same_filesystem ?x0 - object)
    (file_access_changed ?x0 - object)
    (symbolic_link_exists ?x0 - object)
    (target_exists ?x0 - object)
    (permissions_changed ?x0 - object)
    (group_matches_effective_gid ?x0 - object)
    (user_has_privileges )
    (set_group_id_cleared ?x0 - object)
    (directory_mode_set ?x0 - object ?x1 - object)
    (setuid_preserved ?x0 - object)
    (setgid_preserved ?x0 - object)
    (setuid_cleared ?x0 - object)
    (setgid_cleared ?x0 - object)
    (sticky_bit_set ?x0 - object)
    (restricted_deletion_flag_set ?x0 - object)
    (sticky_bit_cleared ?x0 - object)
    (restricted_deletion_flag_cleared ?x0 - object)
    (file_mode_set_from_ref ?x0 - object ?x1 - object)
    (directory_mode_set_recursively ?x0 - object ?x1 - object)
    (file_has_mode ?x0 - object ?x1 - object ?x2 - object)
    (same_owner ?x0 - object ?x1 - object)
    (same_group ?x0 - object ?x1 - object)
    (file_group ?x0 - object ?x1 - object)
    (file_grouped_to_group ?x0 - object ?x1 - object)
    (operation_performed_recursively_on_directory ?x0 - object ?x1 - object)
    (root_directory_not_special )
    (root_directory_special )
    (owner_and_group_from_reference_file ?x0 - object)
    (symbolic_links_traversed )
    (symbolic_links_not_traversed )
    (symbolic_links_to_directories_traversed )
    (file_in_group ?x0 - object ?x1 - object)
    (directory_owned_by ?x0 - object ?x1 - object)
    (same_owner_group ?x0 - object ?x1 - object)
    (selinux_context_set ?x0 - object)
    (custom_context_set ?x0 - object)
    (file_access_time_updated ?x0 - object)
    (file_modification_time_updated ?x0 - object)
    (file_access_time_set_to ?x0 - object)
    (file_modification_time_set_to ?x0 - object)
    (symlink_access_time_updated ?x0 - object)
    (symlink_modification_time_updated ?x0 - object)
    (file_time_set ?x0 - object)
    (file_accessed ?x0 - object)
    (file_modified ?x0 - object)
    (link_accessed ?x0 - object)
    (link_modified ?x0 - object)
    (file_modified_time_updated ?x0 - object)
    (iptables_installed )
    (ip6tables_installed )
    (firewall_rule_configured ?x0 - object)
    (rule_added ?x0 - object ?x1 - object)
    (packet_accepted ?x0 - object)
    (packet_dropped ?x0 - object)
    (module_loaded ?x0 - object)
    (kernel_supports_tables )
    (current_table_set_to ?x0 - object)
    (chain_exists ?x0 - object)
    (packet_creates_new_connection )
    (rule_applied ?x0 - object)
    (packet_incoming )
    (packet_altered ?x0 - object)
    (packet_destined_for_local_socket )
    (packet_locally_generated )
    (packet_about_to_go_out )
    (packet_needs_special_alteration )
    (target_available ?x0 - object)
    (exemption_configured ?x0 - object ?x1 - object)
    (rule_exists ?x0 - object)
    (mac_rule_enabled ?x0 - object ?x1 - object)
    (rule_appended_to_chain ?x0 - object ?x1 - object)
    (rule_replaced ?x0 - object)
    (rules_exist_in_chain ?x0 - object)
    (counters_reset ?x0 - object)
    (references_exist_to_chain ?x0 - object)
    (valid_target ?x0 - object)
    (policy_set ?x0 - object ?x1 - object)
    (chain_renamed ?x0 - object ?x1 - object)
    (traffic_filtered ?x0 - object)
    (rule_deleted ?x0 - object ?x1 - object)
    (rule_inserted ?x0 - object ?x1 - object ?x2 - object)
    (rule_added_to_chain ?x0 - object ?x1 - object)
    (rule_added_to_chain_jump ?x0 - object ?x1 - object)
    (rule_added_to_chain_with_match ?x0 - object ?x1 - object)
    (rule_added_to_chain_with_out_interface ?x0 - object ?x1 - object)
    (rule_added_to_chain_with_fragment_flag ?x0 - object)
    (rule_added_to_chain_with_counter ?x0 - object ?x1 - object ?x2 - object)
    (socket_exists ?x0 - object)
    (filters_applied ?x0 - object)
    (sockets_exist )
    (sockets_closed )
    (header_suppressed )
    (command_executed_by_user ?x0 - object)
    (?user )
    (permission_granted_to_execute ?x0 - object)
    (command_executed_by_root )
    (permission_granted_to_edit ?x0 - object)
    (file_edited_by ?x0 - object)
    (user_authenticated )
    (sudo_cache_exists )
    (updated_sudo_cache )
    (sudoers_updated )
    (file_edited ?x0 - object)
    (askpass_available )
    (user_has_password )
    (password_provided )
    (terminal_present )
    (askpass_used )
    (bell_rung )
    (command_exists ?x0 - object)
    (process_running_in_background ?x0 - object)
    (working_directory_changed_to ?x0 - object)
    (user_authorized )
    (policy_permits_preserve_env )
    (environment_variable_preserved ?x0 - object)
    (policy_permits_edit )
    (primary_group_set ?x0 - object ?x1 - object)
    (home_set ?x0 - object)
    (shell_running_as_login ?x0 - object)
    (system_running )
    (system_rebooted )
    (file_edited_by_user_and_group ?x0 - object ?x1 - object ?x2 - object)
    (file_viewed_by_group ?x0 - object ?x1 - object)
    (cached_credential_exists )
    (no_cached_credential )
    (owned_by_root ?x0 - object)
    (has_setuid_bit ?x0 - object)
    (process_has_no_new_privileges ?x0 - object)
    (timestamp_initialized )
    (timestamp_exists )
    (timestamp_erased )
    (timestamp_reset )
    (environment_preserved_for_command ?x0 - object)
    (command_run_with_group_privileges ?x0 - object)
    (home_directory_set_to_target_user ?x0 - object)
    (shell_running_as_user ?x0 - object)
    (current_user_is ?x0 - object)
    (environment_updated_for ?x0 - object)
    (root_user_exists )
    (process_running_with_privileges ?x0 - object)
    (command_executed_in_shell ?x0 - object)
    (environment_modified_by_pam )
    (supplementary_group_of_user ?x0 - object ?x1 - object)
    (shell_running_as_login_shell ?x0 - object)
    (session_has_pty )
    (shell_exists ?x0 - object)
    (session_running_shell ?x0 - object)
    (process_exists ?x0 - object)
    (signal_received ?x0 - object)
    (process_terminated ?x0 - object)
    (process_killed ?x0 - object)
    (effective_user ?x0 - object)
    (primary_group ?x0 - object)
    (shell_login_mode ?x0 - object)
    (shell_allowed_in_etc_shells ?x0 - object)
    (effective_shell ?x0 - object)
    (system_initialized )
    (default_user_info_updated )
    (has_home_directory ?x0 - object ?x1 - object)
    (has_comment ?x0 - object ?x1 - object)
    (account_expires_on ?x0 - object ?x1 - object)
    (variable_set ?x0 - object)
    (user_expiry_date_set ?x0 - object ?x1 - object)
    (password_inactive_period_set ?x0 - object ?x1 - object)
    (system_account ?x0 - object)
    (subuid_updated ?x0 - object)
    (subgid_updated ?x0 - object)
    (all_group_exist ?x0 - object)
    (user_in_groups ?x0 - object ?x1 - object)
    (home_directory_created ?x0 - object)
    (login_def_exists ?x0 - object)
    (login_def_value_set ?x0 - object ?x1 - object)
    (no_lastlog_entry ?x0 - object)
    (no_faillog_entry ?x0 - object)
    (logs_reset ?x0 - object)
    (owned_by_user ?x0 - object ?x1 - object)
    (user_in_group ?x0 - object ?x1 - object)
    (user_has_uid ?x0 - object ?x1 - object)
    (user_has_password_set ?x0 - object)
    (no_home_directory ?x0 - object)
    (system_user ?x0 - object)
    (changes_applied_in_chroot ?x0 - object)
    (changes_applied_in_prefix ?x0 - object)
    (user_shell_set ?x0 - object)
    (?shell )
    (unique_uid ?x0 - object)
    (non_negative ?x0 - object)
    (user_has_id ?x0 - object ?x1 - object)
    (user_has_selinux_user ?x0 - object ?x1 - object)
    (mail_spool_updated ?x0 - object)
    (member_in_group ?x0 - object ?x1 - object)
    (max_members_reached ?x0 - object)
    (new_group_entry_created ?x0 - object)
    (member_added_to_group ?x0 - object ?x1 - object)
    (password_age ?x0 - object ?x1 - object)
    (greater_than_or_equal_to ?x0 - object ?x1 - object)
    (password_changed ?x0 - object)
    (subuid_allocated ?x0 - object)
    (number_range_valid ?x0 - object ?x1 - object ?x2 - object)
    (system_group_exists ?x0 - object)
    (user_uid_set ?x0 - object ?x1 - object)
    (default_config_exists )
    (modified_default_config ?x0 - object)
    (password_has_inactive_period ?x0 - object ?x1 - object)
    (system_user_exists ?x0 - object)
    (subid_entry_added ?x0 - object ?x1 - object)
    (member_of_group ?x0 - object ?x1 - object)
    (home_directory_not_created ?x0 - object)
    (no_user_group_created ?x0 - object)
    (unique_user_required )
    (duplicate_user_allowed ?x0 - object)
    (valid_uid ?x0 - object)
    (valid_shell ?x0 - object)
    (?group )
    (valid_seuser ?x0 - object)
    (selinux_user_mapped ?x0 - object)
    (?seuser )
    (account_modified ?x0 - object)
    (user_comment_updated ?x0 - object)
    (home_directory_changed ?x0 - object ?x1 - object)
    (account_exists ?x0 - object)
    (shadow_file_exists )
    (account_disabled ?x0 - object)
    (password_grace_period_set ?x0 - object)
    (primary_group_of_user ?x0 - object ?x1 - object)
    (all_groups_exist ?x0 - object)
    (supplementary_groups_of_user ?x0 - object ?x1 - object)
    (password_locked ?x0 - object)
    (user_expire_set ?x0 - object ?x1 - object)
    (subuid_range_added ?x0 - object ?x1 - object)
    (subuid_range_exists ?x0 - object ?x1 - object)
    (subuid_range_removed ?x0 - object ?x1 - object)
    (subgid_range_added ?x0 - object ?x1 - object)
    (user_modified ?x0 - object)
    (nis_server_available )
    (nis_entry_exists ?x0 - object)
    (nis_entry_modified ?x0 - object ?x1 - object)
    (password_inactive_after_days ?x0 - object ?x1 - object)
    (account_locked ?x0 - object)
    (encrypted_password_set ?x0 - object)
    (changed_username_to ?x0 - object ?x1 - object)
    (non_unique_uid_set ?x0 - object ?x1 - object)
    (gecos_field_set ?x0 - object ?x1 - object)
    (groups_exist ?x0 - object)
    (account_unlocked ?x0 - object)
    (subgids_exist ?x0 - object ?x1 - object ?x2 - object)
    (subgids_added ?x0 - object ?x1 - object ?x2 - object)
    (home_directory_exists ?x0 - object)
    (group_exists_with_same_name ?x0 - object)
    (cron_job_exists ?x0 - object)
    (at_job_exists ?x0 - object)
    (print_job_exists ?x0 - object)
    (primary_group_used_by_other_user ?x0 - object)
    (password_encrypted ?x0 - object)
    (group_has_password ?x0 - object)
    (?password )
    (group_has_gid ?x0 - object)
    (?gid )
    (group_default_exists ?x0 - object)
    (group_default_value ?x0 - object)
    (?value )
    (all_users_exist ?x0 - object)
    (users_in_group ?x0 - object ?x1 - object)
    (gid_used ?x0 - object)
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
      (not (config_files_exist ?pkg))
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

  (:action upgrade_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (package_updates_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_upgraded)
    )
  )

  (:action upgrade_distro
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (package_updates_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_upgraded)
      (dependencies_resolved)
    )
  )

  (:action auto_remove_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (unused_dependencies_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_removed)
      (dependencies_cleaned)
    )
  )

  (:action clean_package_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_cache_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (package_cache_cleaned)
    )
  )

  (:action auto_clean_package_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (old_package_files_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (package_cache_cleaned)
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

  (:action download_source_package
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (source_package_downloaded ?pkg)
    )
  )

  (:action install_build_dependencies
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (dependencies_installed ?pkg)
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

  (:action install_package_before_upgrade
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
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
      (sources_list_valid)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg) and (package_version ?pkg version)
    )
  )

  (:action install_package_distribution
    :parameters (?actor - user ?pkg - package ?distribution - file)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (sources_list_valid)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg) and (package_from_distribution ?pkg distribution)
    )
  )

  (:action upgrade_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (newer_version_available ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_updated ?pkg)
    )
  )

  (:action set_package_policy
    :parameters (?actor - user ?pkg - package ?policy - file)
    :precondition (and
      (package_exists ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (policy_applied_to_package ?pkg
      ?policy)
    )
  )

  (:action reinstall_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reinstalled ?pkg)
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

  (:action fetch_source_package_info
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
      (source_repository_configured)
    )
    :effect (and
      (source_package_info_fetched ?pkg)
    )
  )

  (:action compile_package
    :parameters (?src - file)
    :precondition (and
      (source_package_downloaded ?src)
      (build_dependencies_installed)
    )
    :effect (and
      (binary_package_compiled ?src)
    )
  )

  (:action satisfy_build_dependencies
    :parameters (?actor - user ?pkg - package ?host_architecture - interface)
    :precondition (and
      (source_package_exists ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (build_dependencies_satisfied ?pkg)
    )
  )

  (:action satisfy_dependencies
    :parameters (?actor - user ?dependencies - file)
    :precondition (and
      (network_available)
      (apt_cache_updated)
      (can_escalate ?actor)
    )
    :effect (and
      (dependencies_satisfied ?dependencies)
    )
  )

  (:action clear_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (apt_cache_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (cache_cleared)
    )
  )

  (:action clean_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (directory_exists /var/cache/apt/archives)
      (directory_exists /var/cache/apt/archives/partial)
      (can_escalate ?actor)
    )
    :effect (and
      (cache_cleaned /var/cache/apt/archives)
      (cache_cleaned /var/cache/apt/archives/partial)
    )
  )

  (:action clean_lists
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (directory_exists /var/lib/apt/lists)
      (can_escalate ?actor)
    )
    :effect (and
      (lists_cleaned /var/lib/apt/lists)
    )
  )

  (:action mark_auto_installed
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_marked_as_auto ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_marked_as_auto ?pkg)
    )
  )

  (:action disable_package_removal
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (not (package_to_be_removed))
      (can_escalate ?actor)
    )
    :effect (and
      (cannot_remove_packages)
    )
  )

  (:action remove_unused_dependencies
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (unused_dependency_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (no_unused_dependencies)
    )
  )

  (:action fetch_source_only
    :parameters (?src - file)
    :precondition (and
      (source_package_exists ?src)
    )
    :effect (and
      (fetched_source_code ?src)
    )
  )

  (:action set_configuration_option
    :parameters (?opt - file ?val - file)
    :precondition (and
      (apt_config_exists)
      (valid_apt_option ?opt)
    )
    :effect (and
      (configuration_set ?opt ?val)
    )
  )

  (:action set_apt_config_file
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (apt_config_set_to ?file)
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

  (:action manage_package
    :parameters (?actor - user ?pkgs - file)
    :precondition (and
      (network_available)
      (root_privileges)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_installed ?pkgs) or (packages_removed ?pkgs)
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
      (package_lists_updated)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (system_upgraded)
    )
  )

  (:action follow_dselect_selections
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_lists_updated)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_upgraded)
    )
  )

  (:action configure_build_dependencies
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (build_dependencies_configured ?pkg)
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

  (:action full_upgrade
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (all_packages_updated)
      (system_optimized)
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

  (:action full_upgrade_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_info_updated)
      (not (system_up_to_date))
      (can_escalate ?actor)
    )
    :effect (and
      (system_up_to_date)
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
      (package_from_release ?pkg ?release)
    )
  )

  (:action mark_package_manual
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (automatically_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (manually_installed ?pkg)
    )
  )

  (:action edit_sources_list
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (sources_file_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (sources_updated)
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

  (:action distclean_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (cache_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (cache_distcleaned)
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

  (:action invoke_dpkg_subcommand
    :parameters (?subcmd - file ?options - file)
    :precondition (and
      (package_installed dpkg)
      (valid_command ?subcmd)
    )
    :effect (and
      (executed_subcommand ?subcmd)
    )
  )

  (:action execute_prerm_script
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (old_package_installed ?pkg)
      (new_package_to_install)
      (can_escalate ?actor)
    )
    :effect (and
      (prerm_executed ?pkg)
    )
  )

  (:action execute_preinst_script
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (new_package_to_install)
      (script_exists ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (preinst_executed ?pkg)
    )
  )

  (:action unpack_package_files
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (new_package_to_install)
      (can_escalate ?actor)
    )
    :effect (and
      (files_unpacked ?pkg)
      (old_files_backed_up ?pkg)
    )
  )

  (:action execute_postrm_script
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (old_package_installed ?pkg)
      (new_package_to_install)
      (can_escalate ?actor)
    )
    :effect (and
      (postrm_executed ?pkg)
    )
  )

  (:action unpack_package
    :parameters (?actor - user ?pkg_file - file)
    :precondition (and
      (package_file_exists ?pkg_file)
      (can_escalate ?actor)
    )
    :effect (and
      (files_unpacked ?pkg_file)
    )
  )

  (:action reconfigure_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_configured ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reconfigured ?pkg)
    )
  )

  (:action process_triggers
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (triggers_pending ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (triggers_processed ?pkg)
    )
  )

  (:action process_only_triggers
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (triggers_pending ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (triggers_processed ?pkg)
    )
  )

  (:action configure_pending_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (packages_pending_configuration)
      (can_escalate ?actor)
    )
    :effect (and
      (all_packages_configured)
    )
  )

  (:action remove_package_with_conffiles
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
      (not (config_files_exist ?pkg))
    )
  )

  (:action update_package_availability
    :parameters (?actor - user ?file - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (package_availability_updated)
    )
  )

  (:action merge_package_information
    :parameters (?actor - user ?file - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (package_availability_updated)
    )
  )

  (:action export_package_selections
    :parameters (?file - file)
    :precondition (and
      (package_manager_available)
    )
    :effect (and
      (file_exists ?file)
      (contains_package_selections ?file)
    )
  )

  (:action clear_selections
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (selections_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (no_selections)
    )
  )

  (:action set_selections
    :parameters (?actor - user ?file - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (selections_set)
    )
  )

  (:action dselect_upgrade
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (selections_set)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_updated)
    )
  )

  (:action clear_available_packages_info
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (available_info_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (not (available_info_exists))
    )
  )

  (:action add_architecture
    :parameters (?actor - user ?arch - file)
    :precondition (and
      (not (architecture_exists ?arch))
      (can_escalate ?actor)
    )
    :effect (and
      (architecture_exists ?arch)
    )
  )

  (:action remove_architecture
    :parameters (?actor - user ?arch - file)
    :precondition (and
      (architecture_exists ?arch)
      (can_escalate ?actor)
    )
    :effect (and
      (not (architecture_exists ?arch))
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

  (:action abort_change
    :parameters (?actor - user ?change_id - process)
    :precondition (and
      (change_pending ?change_id)
      (can_escalate ?actor)
    )
    :effect (and
      (not (change_pending ?change_id))
    )
  )

  (:action add_assertion
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (assertion_not_added)
      (can_escalate ?actor)
    )
    :effect (and
      (assertion_added)
    )
  )

  (:action set_alias
    :parameters (?actor - user ?app - file ?alias - file)
    :precondition (and
      (application_exists ?app)
      (can_escalate ?actor)
    )
    :effect (and
      (alias_set ?alias)
    )
  )

  (:action connect_plug_slot
    :parameters (?plug - interface ?slot - interface)
    :precondition (and
      (plug_exists ?plug)
      (slot_exists ?slot)
      (not (connected ?plug ?slot))
    )
    :effect (and
      (connected ?plug ?slot)
    )
  )

  (:action connect_plug_to_matching_slot
    :parameters (?actor - user ?snap1 - file ?plug - interface ?snap2 - file)
    :precondition (and
      (snap_installed ?snap1)
      (snap_installed ?snap2)
      (plug_exists ?snap1 ?plug)
      (slot_matches_interface ?snap2 ?plug)
      (can_escalate ?actor)
    )
    :effect (and
      (plug_connected_to_slot ?snap1 ?plug ?snap2 matching_slot)
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

  (:action install_snap_devmode
    :parameters (?actor - user ?snap_dir - directory)
    :precondition (and
      (directory_exists ?snap_dir)
      (not (snap_installed))
      (can_escalate ?actor)
    )
    :effect (and
      (snap_installed_in_devmode)
    )
  )

  (:action set_snap_mode
    :parameters (?actor - user ?snap - file ?mode - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_in_development_mode ?snap)
    )
  )

  (:action set_snap_classic_mode
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_in_classic_mode ?snap)
    )
  )

  (:action remove_alias
    :parameters (?actor - user ?snap - file ?alias - file)
    :precondition (and
      (snap_installed ?snap)
      (alias_exists ?alias)
      (can_escalate ?actor)
    )
    :effect (and
      (not (alias_exists ?alias))
    )
  )

  (:action remove_configuration_option
    :parameters (?actor - user ?snap - file ?option - file)
    :precondition (and
      (snap_installed ?snap)
      (configuration_exists ?snap ?option)
      (can_escalate ?actor)
    )
    :effect (and
      (not (configuration_exists ?snap ?option))
    )
  )

  (:action unset_snap_attribute
    :parameters (?actor - user ?snap - file ?attribute - file)
    :precondition (and
      (snap_installed ?snap)
      (attribute_exists ?snap ?attribute)
      (can_escalate ?actor)
    )
    :effect (and
      (not (attribute_set ?snap ?attribute))
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

  (:action refresh_snaps_for_validation
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (validation_set_enforced)
      (can_escalate ?actor)
    )
    :effect (and
      (snaps_satisfy_validation)
    )
  )

  (:action switch_snap_channel
    :parameters (?actor - user ?snap - file ?channel - port)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_on_channel ?snap ?channel)
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

  (:action disconnect_plug_slot
    :parameters (?plug - interface ?slot - interface)
    :precondition (and
      (connected ?plug ?slot)
    )
    :effect (and
      (not (connected ?plug ?slot))
    )
  )

  (:action unset_configuration_option
    :parameters (?option - file)
    :precondition (and
      (configuration_set ?option)
    )
    :effect (and
      (not (configuration_set ?option))
    )
  )

  (:action unalias
    :parameters (?alias - file)
    :precondition (and
      (alias_exists ?alias)
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
      (system_restored_from_snapshot ?snap)
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

  (:action reboot_device
    :parameters (?actor - user ?system - file ?mode - file)
    :precondition (and
      (system_exists ?system)
      (mode_valid ?mode)
      (can_escalate ?actor)
    )
    :effect (and
      (device_rebooted_into_system_and_mode ?system ?mode)
    )
  )

  (:action ack_assertion
    :parameters (?actor - user ?assert - file)
    :precondition (and
      (not (assertion_exists ?assert))
      (can_escalate ?actor)
    )
    :effect (and
      (assertion_exists ?assert)
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
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (snap_packed ?dir)
    )
  )

  (:action run_snap_command
    :parameters (?cmd - process)
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
      (snap_unpacked ?snap)
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
      (file_exists ?image)
    )
    :effect (and
      (device_image_prepared ?image)
    )
  )

  (:action export_key
    :parameters (?key - file)
    :precondition (and
      (public_key_exists)
    )
    :effect (and
      (key_exported ?key)
    )
  )

  (:action set_quota_group
    :parameters (?actor - user ?group - file)
    :precondition (and
      (not (quota_group_exists ?group)) OR (quota_group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (quota_group_updated ?group)
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

  (:action reduce_disk_usage
    :parameters (?actor - user ?bytes - file)
    :precondition (and
      (journal_files_exist)
      (disk_usage_greater_than ?bytes)
      (can_escalate ?actor)
    )
    :effect (and
      (disk_usage_less_than_or_equal_to ?bytes)
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
      (no_journal_older_than ?time)
    )
  )

  (:action synchronize_journals
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (unwritten_journal_messages_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (all_journals_synced_to_disk)
    )
  )

  (:action rotate_journals
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (journals_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (new_journal_files_created)
    )
  )

  (:action flush_journals
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (unwritten_journal_messages_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (all_unwritten_data_flushed_to_disk)
    )
  )

  (:action stop_logging_to_disk
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (logging_to_disk)
      (can_escalate ?actor)
    )
    :effect (and
      (logging_to_temporary_file_system)
    )
  )

  (:action conditional_stop_logging_to_disk
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (logging_to_disk)
      (log_directory_not_on_root_mount)
      (can_escalate ?actor)
    )
    :effect (and
      (logging_to_temporary_file_system)
    )
  )

  (:action update_catalog
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (catalog_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (catalog_updated)
    )
  )

  (:action setup_keys
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (not (keys_exist))
      (can_escalate ?actor)
    )
    :effect (and
      (keys_generated)
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

  (:action copy_file_or_directory
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied_to ?source ?dest)
    )
  )

  (:action copy_files_to_directory
    :parameters (?sources - file ?dest_dir - directory)
    :precondition (and
      (files_exist ?sources)
      (directory_exists ?dest_dir)
    )
    :effect (and
      (files_copied_to ?sources ?dest_dir)
    )
  )

  (:action backup_files
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (file_backed_up_to ?source ?dest)
    )
  )

  (:action recursive_copy_special_files
    :parameters (?sources - file ?dest_dir - directory)
    :precondition (and
      (files_exist ?sources)
      (directory_exists ?dest_dir)
    )
    :effect (and
      (special_files_copied_to ?sources ?dest_dir)
    )
  )

  (:action recursive_copy
    :parameters (?src - directory ?dest - directory)
    :precondition (and
      (directory_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied ?src ?dest)
    )
  )

  (:action remove_destination_before_copying
    :parameters (?f - file ?dest - directory)
    :precondition (and
      (file_exists ?f)
      (directory_exists ?dest)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action create_symbolic_link
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (symbolic_link_created ?src ?dest)
    )
  )

  (:action copy_into_directory
    :parameters (?src - file ?dest_dir - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest_dir)
    )
    :effect (and
      (file_copied ?src ?dest_dir)
    )
  )

  (:action copy_as_normal_file
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_copied ?src ?dest)
    )
  )

  (:action update_existing_files
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (file_updated ?src ?dest)
    )
  )

  (:action update_older_files
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (file_updated_if_older ?src ?dest)
    )
  )

  (:action set_security_context
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (security_context_default ?f)
    )
  )

  (:action set_security_context_to_ctx
    :parameters (?dir - directory ?ctx - file)
    :precondition (and
      (not (security_context_set ?dir))
    )
    :effect (and
      (security_context_set ?dir)
    )
  )

  (:action create_sparse_file
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (sparse_file_created ?dest)
    )
  )

  (:action set_sparse_option
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (sparse_files_inhibited)
    )
  )

  (:action reflink_copy
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (file_exists ?dest))
    )
    :effect (and
      (file_copied_lightweight ?src ?dest)
    )
  )

  (:action fallback_copy
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (file_exists ?dest))
    )
    :effect (and
      (file_copied_standard ?src ?dest)
    )
  )

  (:action standard_copy
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (file_exists ?dest))
    )
    :effect (and
      (file_copied_standard ?src ?dest)
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

  (:action no_dereference_copy
    :parameters (?src - file ?dst - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dst)
    )
    :effect (and
      (file_copied_no_deref ?src ?dst)
    )
  )

  (:action preserve_attributes_copy
    :parameters (?src - file ?dst - directory ?attr_list - file)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dst)
    )
    :effect (and
      (attributes_preserved ?src ?dst ?attr_list)
    )
  )

  (:action remove_destination_copy
    :parameters (?src - file ?dst - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dst)
    )
    :effect (and
      (destination_removed_before_copy ?src ?dst)
    )
  )

  (:action sparse_file_control_copy
    :parameters (?src - file ?dst - directory ?when - file)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dst)
    )
    :effect (and
      (sparse_file_created ?src ?dst ?when)
    )
  )

  (:action reflink_control_copy
    :parameters (?src - file ?dst - directory ?when - file)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dst)
    )
    :effect (and
      (reflink_copied ?src ?dst ?when)
    )
  )

  (:action copy_files
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied_to_directory ?src ?dest)
    )
  )

  (:action copy_file_no_target_dir
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (directory_exists_or_createable parent(?dest))
    )
    :effect (and
      (file_copied_to_file ?src ?dest)
    )
  )

  (:action update_files
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (directory_exists ?dest)
      (file_exists ?src)
    )
    :effect (and
      (files_updated ?dest)
    )
  )

  (:action copy_within_filesystem
    :parameters (?src - file ?dest - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (files_copied_within_filesystem ?src ?dest)
    )
  )

  (:action set_selinux_context_default
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (selinux_context_set_to_default ?file)
    )
  )

  (:action set_selinux_context_custom
    :parameters (?file - file ?ctx - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (selinux_context_set_to_custom ?file ?ctx)
    )
  )

  (:action change_ownership
    :parameters (?actor - user ?f - file ?user - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by_user ?f ?user)
      (file_owned_by_group ?f ?group)
    )
  )

  (:action change_timestamps
    :parameters (?f - file ?timestamp - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_has_timestamp ?f ?timestamp)
    )
  )

  (:action update_file_if_older
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dest)
      (file_older_than ?dest ?src)
    )
    :effect (and
      (file_updated ?dest)
    )
  )

  (:action backup_file_with_suffix
    :parameters (?f - file ?suffix - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_backed_up ?f)
      (backup_has_suffix ?f ?suffix)
    )
  )

  (:action set_backup_method
    :parameters (?method - file ?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (backup_method_set ?method)
    )
  )

  (:action backup_file
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (same_name ?source ?dest)
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

  (:action force_move_file
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (file_exists ?dest)
    )
    :effect (and
      (file_moved_forcefully ?source ?dest)
    )
  )

  (:action interactive_move_file
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (file_exists ?dest)
    )
    :effect (and
      (file_moved_interactively ?source ?dest)
    )
  )

  (:action no_clobber_move_file
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (file_exists ?dest)
    )
    :effect (and
      (file_not_moved_if_exists ?source ?dest)
    )
  )

  (:action no_copy_on_rename_fail
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (not (file_moved ?source))
    )
    :effect (and
      (file_not_copied_if_rename_fails ?source)
    )
  )

  (:action copy_file_force
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (dest_is_directory ?dest))
    )
    :effect (and
      (file_copied ?src ?dest)
    )
  )

  (:action copy_file_interactive
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (dest_is_directory ?dest))
    )
    :effect (and
      (file_copied ?src ?dest)
    )
  )

  (:action copy_file_no_clobber
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (dest_is_directory ?dest))
      (not (file_exists ?dest))
    )
    :effect (and
      (file_copied ?src ?dest)
    )
  )

  (:action move_files_to_directory
    :parameters (?src - file ?dest_dir - directory)
    :precondition (and
      (file_exists ?src)
      (directory_exists ?dest_dir)
    )
    :effect (and
      (file_moved ?src ?dest_dir)
    )
  )

  (:action copy_file_verbose
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (dest_is_directory ?dest))
    )
    :effect (and
      (file_copied ?src ?dest)
    )
  )

  (:action set_selinux_context
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (selinux_context_default ?f)
    )
  )

  (:action set_version_control_method
    :parameters (?method - file)
    :precondition (and
      (not (version_control_set))
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

  (:action remove_file_or_directory
    :parameters (?path - file)
    :precondition (and
      (exists ?path)
    )
    :effect (and
      (not (exists ?path))
    )
  )

  (:action remove_files_interactively
    :parameters (?files - file ?dirs - directory)
    :precondition (and
      (file_exists ?files)
      (dir_exists ?dirs)
    )
    :effect (and
      (not (file_exists ?files))
      (not (dir_exists ?dirs))
    )
  )

  (:action remove_files_without_preserving_root
    :parameters (?actor - user ?files - file ?dirs - directory)
    :precondition (and
      (file_exists ?files)
      (dir_exists ?dirs)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?files))
      (not (dir_exists ?dirs))
    )
  )

  (:action remove_files_preserving_root
    :parameters (?actor - user ?files - file ?dirs - directory)
    :precondition (and
      (file_exists ?files)
      (dir_exists ?dirs)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?files))
      (not (dir_exists ?dirs))
    )
  )

  (:action remove_empty_directories
    :parameters (?dirs - directory)
    :precondition (and
      (dir_exists ?dirs)
      (is_empty_directory ?dirs)
    )
    :effect (and
      (not (dir_exists ?dirs))
    )
  )

  (:action remove_files_verbose
    :parameters (?files - file ?dirs - directory)
    :precondition (and
      (file_exists ?files)
      (dir_exists ?dirs)
    )
    :effect (and
      (not (file_exists ?files))
      (not (dir_exists ?dirs))
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

  (:action remove_root_directory
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (directory_exists /)
      (can_escalate ?actor)
    )
    :effect (and
      (not (directory_exists /))
    )
  )

  (:action remove_directory_with_preserve_root_all
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (not (is_root_dir ?dir))
      (can_escalate ?actor)
    )
    :effect (and
      (not (directory_exists ?dir))
    )
  )

  (:action remove_directory_one_file_system
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (same_filesystem ?dir)
    )
    :effect (and
      (not (directory_exists ?dir))
    )
  )

  (:action change_file_access
    :parameters (?f - file ?ugoa - file ?operator - file ?rwxXst - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_changed ?f)
    )
  )

  (:action change_permissions_pointed_to_file
    :parameters (?link - file ?target - file)
    :precondition (and
      (symbolic_link_exists ?link)
      (target_exists ?target)
    )
    :effect (and
      (permissions_changed ?target)
    )
  )

  (:action clear_set_group_id_bit
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
      (not (group_matches_effective_gid ?file))
      (not (user_has_privileges))
    )
    :effect (and
      (set_group_id_cleared ?file)
    )
  )

  (:action preserve_bits
    :parameters (?d - directory ?mode - file)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (directory_mode_set ?d ?mode)
      (setuid_preserved ?d)
      (setgid_preserved ?d)
    )
  )

  (:action clear_bits
    :parameters (?d - directory ?mode - file)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (directory_mode_set ?d ?mode)
      (setuid_cleared ?d)
      (setgid_cleared ?d)
    )
  )

  (:action set_sticky_bit
    :parameters (?d - directory ?mode - file)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (sticky_bit_set ?d)
      (restricted_deletion_flag_set ?d)
    )
  )

  (:action clear_sticky_bit
    :parameters (?d - directory ?mode - file)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (sticky_bit_cleared ?d)
      (restricted_deletion_flag_cleared ?d)
    )
  )

  (:action change_permissions_reference
    :parameters (?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
    )
    :effect (and
      (file_mode_set_from_ref ?f ?rfile)
    )
  )

  (:action recursive_change_permissions
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_mode_set_recursively ?dir ?mode)
    )
  )

  (:action copy_permissions
    :parameters (?target_file - file ?reference_file - file)
    :precondition (and
      (file_exists ?target_file)
      (file_exists ?reference_file)
    )
    :effect (and
      (file_has_mode ?target_file (mode_of ?reference_file))
    )
  )

  (:action set_permissions_from_reference
    :parameters (?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
    )
    :effect (and
      (file_has_mode ?f (mode_of_file ?rfile))
    )
  )

  (:action change_permissions_no_preserve_root
    :parameters (?actor - user ?root - directory ?mode - file)
    :precondition (and
      (directory_exists ?root)
      (can_escalate ?actor)
    )
    :effect (and
      (file_has_mode ?root ?mode)
    )
  )

  (:action change_permissions_preserve_root
    :parameters (?actor - user ?root - directory ?mode - file)
    :precondition (and
      (directory_exists ?root)
      (can_escalate ?actor)
    )
    :effect (and
      (file_has_mode ?root ?mode)
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

  (:action copy_ownership
    :parameters (?actor - user ?src_file - file ?dst_file - file)
    :precondition (and
      (file_exists ?src_file)
      (file_exists ?dst_file)
      (can_escalate ?actor)
    )
    :effect (and
      (same_owner ?src_file ?dst_file)
      (same_group ?src_file ?dst_file)
    )
  )

  (:action change_group
    :parameters (?actor - user ?file - file ?group - group)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (file_group ?file ?group)
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
      (file_grouped_to_group ?f ?group)
    )
  )

  (:action recursive_operation
    :parameters (?dir - directory ?cmd - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (operation_performed_recursively_on_directory ?dir ?cmd)
    )
  )

  (:action no_preserve_root
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (root_directory_not_special)
    )
  )

  (:action preserve_root
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (root_directory_special)
    )
  )

  (:action reference_owner_group
    :parameters (?rfile - file)
    :precondition (and
      (file_exists ?rfile)
    )
    :effect (and
      (owner_and_group_from_reference_file ?rfile)
    )
  )

  (:action traverse_links
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (symbolic_links_traversed)
    )
  )

  (:action no_traverse_links
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (symbolic_links_not_traversed)
    )
  )

  (:action traverse_link_to_directory
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (symbolic_links_to_directories_traversed)
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
      (file_owned_by ?f ?owner)
      (file_in_group ?f ?group)
    )
  )

  (:action change_owner_recursive
    :parameters (?actor - user ?owner - user ?d - directory)
    :precondition (and
      (user_exists ?owner)
      (directory_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_owned_by ?d ?owner)
    )
  )

  (:action change_ownership_reference
    :parameters (?actor - user ?rfile - file ?f - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (same_owner_group ?f ?rfile)
    )
  )

  (:action inherit_ownership_from_reference
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by_user ?f (owner_of_file ?rfile))
      (file_grouped_to_group ?f (group_of_file ?rfile))
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
    :parameters (?mode - file ?dir - directory)
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

  (:action create_directory_with_custom_context
    :parameters (?ctx - file ?dir - directory)
    :precondition (and
      (not (directory_exists ?dir))
    )
    :effect (and
      (directory_exists ?dir)
      (custom_context_set ?dir)
    )
  )

  (:action change_directory_mode
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_mode_set ?dir ?mode)
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

  (:action update_timestamps
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f) | (not (file_exists ?f))
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

  (:action set_custom_timestamps
    :parameters (?f - file ?ts - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_set_to ?ts)
      (file_modification_time_set_to ?ts)
    )
  )

  (:action update_symlink_timestamps
    :parameters (?symlink - file)
    :precondition (and
      (symbolic_link_exists ?symlink)
    )
    :effect (and
      (symlink_access_time_updated ?symlink)
      (symlink_modification_time_updated ?symlink)
    )
  )

  (:action set_file_time_reference
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (file_time_set ?file)
    )
  )

  (:action set_file_time_stamp
    :parameters (?stamp - file ?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (file_time_set ?file)
    )
  )

  (:action set_file_time_attribute
    :parameters (?word - file ?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (file_time_set ?file)
    )
  )

  (:action set_file_date_string
    :parameters (?string - file ?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (file_time_set ?file)
    )
  )

  (:action update_file_times
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f) | (not (file_exists ?f))
    )
    :effect (and
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
    )
  )

  (:action update_file_time
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_accessed ?f)
      (file_modified ?f)
    )
  )

  (:action update_file_time_from_reference
    :parameters (?ref - file ?f - file)
    :precondition (and
      (file_exists ?ref)
      (file_exists ?f)
    )
    :effect (and
      (file_accessed ?f)
      (file_modified ?f)
    )
  )

  (:action update_file_time_with_timestamp
    :parameters (?stamp - file ?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_accessed ?f)
      (file_modified ?f)
    )
  )

  (:action update_symlink_time
    :parameters (?symlink - file)
    :precondition (and
      (symbolic_link_exists ?symlink)
    )
    :effect (and
      (link_accessed ?symlink)
      (link_modified ?symlink)
    )
  )

  (:action update_timestamp
    :parameters (?f - file)
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

  (:action configure_firewall_rule
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (iptables_installed)
      (ip6tables_installed)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_configured ?rule)
    )
  )

  (:action add_firewall_rule
    :parameters (?actor - user ?criteria - firewall_rule ?target - firewall_rule)
    :precondition (and
      (iptables_installed)
      (ip6tables_installed)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_added ?criteria ?target)
    )
  )

  (:action accept_packet
    :parameters (?actor - user ?packet - firewall_rule)
    :precondition (and
      (iptables_installed)
      (ip6tables_installed)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_accepted ?packet)
    )
  )

  (:action drop_packet
    :parameters (?actor - user ?packet - firewall_rule)
    :precondition (and
      (iptables_installed)
      (ip6tables_installed)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_dropped ?packet)
    )
  )

  (:action select_table
    :parameters (?actor - user ?table - firewall_rule)
    :precondition (and
      (module_loaded ?table)
      (kernel_supports_tables)
      (can_escalate ?actor)
    )
    :effect (and
      (current_table_set_to ?table)
    )
  )

  (:action apply_firewall_rule
    :parameters (?actor - user ?rule - firewall_rule ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (packet_creates_new_connection)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_applied ?rule)
    )
  )

  (:action alter_packet_prerouting
    :parameters (?actor - user ?packet - file ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (packet_incoming)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_altered ?packet)
    )
  )

  (:action alter_packet_input
    :parameters (?actor - user ?packet - file ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (packet_destined_for_local_socket)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_altered ?packet)
    )
  )

  (:action alter_packet_output
    :parameters (?actor - user ?packet - file ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (packet_locally_generated)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_altered ?packet)
    )
  )

  (:action alter_packet_postrouting
    :parameters (?actor - user ?packet - file ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (packet_about_to_go_out)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_altered ?packet)
    )
  )

  (:action alter_packet_specialized
    :parameters (?actor - user ?packet - file ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (packet_needs_special_alteration)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_altered ?packet)
    )
  )

  (:action configure_exemption_connection_tracking
    :parameters (?actor - user ?chain - firewall_rule ?target - firewall_rule)
    :precondition (and
      (chain_exists ?chain)
      (target_available ?target)
      (can_escalate ?actor)
    )
    :effect (and
      (exemption_configured ?chain ?target)
    )
  )

  (:action enable_mac_networking_rules
    :parameters (?actor - user ?rule - firewall_rule ?target - firewall_rule)
    :precondition (and
      (rule_exists ?rule)
      (target_available ?target)
      (can_escalate ?actor)
    )
    :effect (and
      (mac_rule_enabled ?rule ?target)
    )
  )

  (:action append_rule_to_chain
    :parameters (?actor - user ?chain - firewall_rule ?rule_specification - firewall_rule)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_appended_to_chain ?chain ?rule_specification)
    )
  )

  (:action delete_firewall_rule
    :parameters (?actor - user ?chain - firewall_rule ?rule_spec - firewall_rule)
    :precondition (and
      (rule_exists ?chain ?rule_spec)
      (can_escalate ?actor)
    )
    :effect (and
      (not (rule_exists ?chain ?rule_spec))
    )
  )

  (:action insert_firewall_rule
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file ?rule_spec - firewall_rule)
    :precondition (and
      (not (rule_exists ?chain rulenum))
      (can_escalate ?actor)
    )
    :effect (and
      (rule_exists ?chain ?rule_spec)
    )
  )

  (:action replace_firewall_rule
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file ?rulespec - file)
    :precondition (and
      (rule_exists ?rulenum)
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_replaced ?rulespec)
    )
  )

  (:action flush_chain
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (not (rules_exist_in_chain ?chain))
    )
  )

  (:action reset_counters
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (counters_reset ?chain)
    )
  )

  (:action create_chain
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (not (chain_exists ?chain))
      (can_escalate ?actor)
    )
    :effect (and
      (chain_exists ?chain)
    )
  )

  (:action delete_chain
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (chain_exists ?chain)
      (not (references_exist_to_chain ?chain))
      (can_escalate ?actor)
    )
    :effect (and
      (not (chain_exists ?chain))
    )
  )

  (:action set_policy
    :parameters (?actor - user ?chain - file ?target - firewall_rule)
    :precondition (and
      (chain_exists ?chain)
      (valid_target ?target)
      (can_escalate ?actor)
    )
    :effect (and
      (policy_set ?chain ?target)
    )
  )

  (:action rename_chain
    :parameters (?actor - user ?old_chain - file ?new_chain - file)
    :precondition (and
      (chain_exists ?old_chain)
      (not (chain_exists ?new_chain))
      (can_escalate ?actor)
    )
    :effect (and
      (chain_renamed ?old_chain ?new_chain)
    )
  )

  (:action filter_outgoing_traffic
    :parameters (?actor - user ?interface - interface ?negate - file)
    :precondition (and
      (interface_exists ?interface)
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_filtered ?interface)
    )
  )

  (:action delete_matching_rule_from_chain
    :parameters (?actor - user ?chain - firewall_rule ?rule_specification - file)
    :precondition (and
      (rule_exists ?chain ?rule_specification)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_deleted ?chain ?rule_specification)
    )
  )

  (:action delete_rule_by_number_from_chain
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file)
    :precondition (and
      (rule_exists ?chain ?rulenum)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_deleted ?chain ?rulenum)
    )
  )

  (:action insert_rule_into_chain
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file ?rule_specification - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_inserted ?chain ?rulenum ?rule_specification)
    )
  )

  (:action replace_rule_in_chain
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file ?rule_specification - file)
    :precondition (and
      (rule_exists ?chain ?rulenum)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_replaced ?chain ?rulenum ?rule_specification)
    )
  )

  (:action delete_rules
    :parameters (?actor - user ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (not (rules_exist_in_chain ?chain))
    )
  )

  (:action add_firewall_rule_jump_target
    :parameters (?actor - user ?target - firewall_rule ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_added_to_chain ?target ?chain)
    )
  )

  (:action add_firewall_rule_goto_chain
    :parameters (?actor - user ?chain - file ?target_chain - file)
    :precondition (and
      (chain_exists ?target_chain)
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_added_to_chain_jump target_chain ?chain)
    )
  )

  (:action add_firewall_rule_match_extension
    :parameters (?actor - user ?extension - firewall_rule ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_added_to_chain_with_match extension ?chain)
    )
  )

  (:action add_firewall_rule_out_interface
    :parameters (?actor - user ?interface - interface ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_added_to_chain_with_out_interface interface ?chain)
    )
  )

  (:action add_firewall_rule_match_fragment
    :parameters (?actor - user ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_added_to_chain_with_fragment_flag ?chain)
    )
  )

  (:action add_firewall_rule_set_counters
    :parameters (?actor - user ?pkts - file ?bytes - file ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_added_to_chain_with_counter pkts bytes ?chain)
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

  (:action close_socket
    :parameters (?actor - user ?socket_type - file)
    :precondition (and
      (socket_exists ?socket_type)
      (can_escalate ?actor)
    )
    :effect (and
      (not (socket_exists ?socket_type))
    )
  )

  (:action apply_filters_from_file
    :parameters (?actor - user ?filter_file - file)
    :precondition (and
      (file_exists ?filter_file)
      (file_readable ?filter_file)
      (can_escalate ?actor)
    )
    :effect (and
      (filters_applied FILTER)
    )
  )

  (:action forcibly_close_sockets
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (sockets_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (sockets_closed)
    )
  )

  (:action apply_filter_from_file
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (filters_applied)
    )
  )

  (:action suppress_header_line
    :parameters (?obj - file)
    :precondition (and
      (sockets_exist)
    )
    :effect (and
      (header_suppressed)
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

  (:action execute_command_as_user
    :parameters (?cmd - process ?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (command_executed_by_user ?cmd
      ?user)
    )
  )

  (:action execute_command_as_superuser
    :parameters (?cmd - file)
    :precondition (and
      (permission_granted_to_execute ?cmd)
    )
    :effect (and
      (command_executed_by_root)
    )
  )

  (:action edit_file_as_user
    :parameters (?file - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (permission_granted_to_edit ?file)
    )
    :effect (and
      (file_edited_by ?user)
    )
  )

  (:action update_sudo_cache
    :parameters (?obj - file)
    :precondition (and
      (user_authenticated)
      (sudo_cache_exists)
    )
    :effect (and
      (updated_sudo_cache)
    )
  )

  (:action edit_sudoers_file
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (file_exists /etc/sudoers)
      (can_escalate ?actor)
    )
    :effect (and
      (sudoers_updated)
    )
  )

  (:action edit_file_with_sudo
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_edited ?f)
    )
  )

  (:action run_askpass_program
    :parameters (?obj - file)
    :precondition (and
      (askpass_available)
      (user_has_password)
    )
    :effect (and
      (password_provided)
    )
  )

  (:action ring_bell_on_password_prompt
    :parameters (?obj - file)
    :precondition (and
      (terminal_present)
      (not (askpass_used))
    )
    :effect (and
      (bell_rung)
    )
  )

  (:action background_command
    :parameters (?actor - user ?cmd - process)
    :precondition (and
      (command_exists ?cmd)
      (can_escalate ?actor)
    )
    :effect (and
      (process_running_in_background ?cmd)
    )
  )

  (:action change_working_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (working_directory_changed_to ?dir)
    )
  )

  (:action preserve_environment_variables
    :parameters (?list - file)
    :precondition (and
      (user_authorized)
      (policy_permits_preserve_env)
    )
    :effect (and
      (environment_variable_preserved ?list)
    )
  )

  (:action edit_files_with_sudo
    :parameters (?files - file)
    :precondition (and
      (user_authorized)
      (policy_permits_edit)
    )
    :effect (and
      (file_edited ?files)
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

  (:action set_home_env_var
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
      (not (home_set ?user))
    )
    :effect (and
      (home_set ?user)
    )
  )

  (:action run_login_shell
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (shell_running_as_login ?user)
    )
  )

  (:action shutdown_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_running)
      (can_escalate ?actor)
    )
    :effect (and
      (system_rebooted)
    )
  )

  (:action edit_file_as_user_group
    :parameters (?actor - user ?user - user ?group - group ?file - file)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (file_edited_by_user_and_group ?file ?user ?group)
    )
  )

  (:action view_file_as_group
    :parameters (?actor - user ?group - group ?file - file)
    :precondition (and
      (group_exists ?group)
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (file_viewed_by_group ?file ?group)
    )
  )

  (:action clear_cached_credentials
    :parameters (?obj - file)
    :precondition (and
      (cached_credential_exists)
    )
    :effect (and
      (no_cached_credential)
    )
  )

  (:action set_owner_and_permissions
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (not (owned_by_root ?f))
      (not (has_setuid_bit ?f))
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by_root ?f)
      (has_setuid_bit ?f)
    )
  )

  (:action remove_no_new_privileges_flag
    :parameters (?actor - user ?p - process)
    :precondition (and
      (process_has_no_new_privileges ?p)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_has_no_new_privileges ?p))
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

  (:action init_timestamp
    :parameters (?obj - file)
    :precondition (and
      (user_authenticated)
    )
    :effect (and
      (timestamp_initialized)
    )
  )

  (:action erase_timestamp
    :parameters (?obj - file)
    :precondition (and
      (timestamp_exists)
    )
    :effect (and
      (timestamp_erased)
    )
  )

  (:action reset_timestamp
    :parameters (?obj - file)
    :precondition (and
      (timestamp_exists)
    )
    :effect (and
      (timestamp_reset)
    )
  )

  (:action preserve_environment
    :parameters (?actor - user ?cmd - process)
    :precondition (and
      (command_exists ?cmd)
      (can_escalate ?actor)
    )
    :effect (and
      (environment_preserved_for_command ?cmd)
    )
  )

  (:action run_command_as_group
    :parameters (?actor - user ?group - group ?cmd - process)
    :precondition (and
      (group_exists ?group)
      (command_exists ?cmd)
      (can_escalate ?actor)
    )
    :effect (and
      (command_run_with_group_privileges ?cmd)
    )
  )

  (:action set_home_directory
    :parameters (?actor - user ?user - user ?cmd - process)
    :precondition (and
      (user_exists ?user)
      (command_exists ?cmd)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_set_to_target_user ?user)
    )
  )

  (:action run_shell_as_user
    :parameters (?user - user ?cmd - process)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (shell_running_as_user ?user)
    )
  )

  (:action run_command_as_user
    :parameters (?user - user ?cmd - process)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (command_executed_by_user ?cmd ?user)
    )
  )

  (:action switch_user
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (current_user_is ?user)
      (environment_updated_for ?user)
    )
  )

  (:action switch_to_root
    :parameters (?obj - file)
    :precondition (and
      (root_user_exists)
    )
    :effect (and
      (current_user_is root)
      (environment_updated_for root)
    )
  )

  (:action switch_and_run_command
    :parameters (?user - user ?command - process)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (command_executed_by_user command ?user)
      (current_user_is ?user)
      (environment_updated_for ?user)
    )
  )

  (:action set_process_privileges
    :parameters (?cmd - process)
    :precondition (and
      (command_exists ?cmd)
    )
    :effect (and
      (process_running_with_privileges ?cmd)
    )
  )

  (:action execute_command_with_shell
    :parameters (?cmd - process)
    :precondition (and
      (command_exists ?cmd)
    )
    :effect (and
      (command_executed_in_shell ?cmd)
    )
  )

  (:action modify_environment_with_pam
    :parameters (?obj - file)
    :precondition (and
      (process_running)
    )
    :effect (and
      (environment_modified_by_pam)
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
      (shell_running_as_login_shell ?user)
    )
  )

  (:action create_pty
    :parameters (?obj - file)
    :precondition (and
      (not (session_has_pty))
    )
    :effect (and
      (session_has_pty)
    )
  )

  (:action run_shell
    :parameters (?shell - file)
    :precondition (and
      (shell_exists ?shell)
    )
    :effect (and
      (session_running_shell ?shell)
    )
  )

  (:action terminate_process
    :parameters (?p - process ?sig - file)
    :precondition (and
      (process_exists ?p)
      (signal_received ?sig)
    )
    :effect (and
      (process_terminated ?p)
    )
  )

  (:action kill_process
    :parameters (?p - process ?sig - file)
    :precondition (and
      (process_exists ?p)
      (signal_received ?sig)
    )
    :effect (and
      (process_killed ?p)
    )
  )

  (:action change_user_id
    :parameters (?user - user ?group - group ?suppgroup - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
    )
    :effect (and
      (effective_user ?user)
      (primary_group ?group)
    )
  )

  (:action login_shell
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (shell_login_mode ?user)
    )
  )

  (:action change_shell
    :parameters (?shell - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (shell_allowed_in_etc_shells ?shell)
    )
    :effect (and
      (effective_shell ?shell
      ?user)
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
      (system_initialized)
      (can_escalate ?actor)
    )
    :effect (and
      (default_user_info_updated)
    )
  )

  (:action add_user_with_home_dir
    :parameters (?actor - user ?user - user ?home_dir - directory)
    :precondition (and
      (not (user_exists ?user))
      (directory_exists ?home_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (has_home_directory ?user ?home_dir)
    )
  )

  (:action set_user_comment
    :parameters (?actor - user ?user - user ?comment - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (has_comment ?user ?comment)
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

  (:action set_user_expiry_date
    :parameters (?actor - user ?u - user ?expire_date - file)
    :precondition (and
      (user_exists ?u)
      (variable_set 'EXPIRE')
      (can_escalate ?actor)
    )
    :effect (and
      (user_expiry_date_set ?u ?expire_date)
    )
  )

  (:action set_password_inactive_period
    :parameters (?actor - user ?u - user ?inactive_days - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (password_inactive_period_set ?u ?inactive_days)
    )
  )

  (:action update_subid_files_for_system_account
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (system_account ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_updated ?u)
      (subgid_updated ?u)
    )
  )

  (:action set_primary_group_for_user
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

  (:action add_user_to_groups
    :parameters (?actor - user ?username - user ?groups - group)
    :precondition (and
      (user_exists ?username)
      (all_group_exist ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_groups ?username ?groups)
    )
  )

  (:action create_user_with_home
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

  (:action override_login_defs_defaults
    :parameters (?actor - user ?key - file ?value - file)
    :precondition (and
      (login_def_exists ?key)
      (can_escalate ?actor)
    )
    :effect (and
      (login_def_value_set ?key ?value)
    )
  )

  (:action create_user_without_log_init
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
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (logs_reset ?user)
    )
  )

  (:action create_home_directory
    :parameters (?actor - user ?home_dir - directory ?user - user)
    :precondition (and
      (not (directory_exists ?home_dir))
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_exists ?home_dir)
      (owned_by_user ?home_dir ?user)
    )
  )

  (:action skip_home_directory_creation
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (directory_exists /home/user))
    )
  )

  (:action create_user_without_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (not (group_exists ?group))
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (user_in_group ?user ?group)
    )
  )

  (:action create_user_with_non_unique_uid
    :parameters (?actor - user ?uid - file ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (exists (getent passwd uid))
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
      (not (user_has_password_set ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_password_set ?user)
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
      (no_home_directory ?user)
      (system_user ?user)
    )
  )

  (:action create_user_with_home_dir
    :parameters (?actor - user ?user - user ?home_directory - directory)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (directory_exists ?home_directory)
    )
  )

  (:action create_user_with_subid_updates
    :parameters (?actor - user ?user - user ?home_directory - directory)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (file_updated /etc/subuid)
      (file_updated /etc/subgid)
    )
  )

  (:action chroot_changes
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_chroot ?dir)
    )
  )

  (:action prefix_changes
    :parameters (?actor - user ?prefix_dir - directory)
    :precondition (and
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_prefix ?prefix_dir)
    )
  )

  (:action set_shell_path
    :parameters (?actor - user ?shell - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_shell_set ?user
      ?shell)
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
    :parameters (?actor - user ?uid - file ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (unique_uid ?uid)
      (non_negative ?uid)
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_id ?user ?uid)
    )
  )

  (:action set_selinux_user
    :parameters (?actor - user ?seuser - file ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_selinux_user ?user ?seuser)
    )
  )

  (:action manage_user_mail_spool
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_updated ?user)
    )
  )

  (:action split_group_entry
    :parameters (?actor - user ?group - group ?member - user)
    :precondition (and
      (group_exists ?group)
      (not (member_in_group ?member ?group))
      (max_members_reached ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (new_group_entry_created ?group)
      (member_added_to_group ?member ?group)
    )
  )

  (:action enforce_password_change
    :parameters (?actor - user ?user - user ?days - file)
    :precondition (and
      (password_age ?user ?days)
      (greater_than_or_equal_to ?days PASS_MAX_DAYS)
      (can_escalate ?actor)
    )
    :effect (and
      (password_changed ?user)
    )
  )

  (:action allocate_subordinate_user_ids
    :parameters (?actor - user ?user - user ?sub_uid_min - file ?sub_uid_max - file ?sub_uid_count - file)
    :precondition (and
      (not (subuid_allocated ?user))
      (file_exists /etc/subuid)
      (number_range_valid ?sub_uid_min ?sub_uid_max ?sub_uid_count)
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_allocated ?user)
    )
  )

  (:action create_system_group
    :parameters (?actor - user ?name - group)
    :precondition (and
      (not (group_exists ?name))
      (can_escalate ?actor)
    )
    :effect (and
      (system_group_exists ?name)
    )
  )

  (:action create_system_user
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (not (user_exists ?user))
      (number_range_valid ?uid SYS_UID_MIN SYS_UID_MAX)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (user_uid_set ?user ?uid)
    )
  )

  (:action create_regular_user
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (not (user_exists ?user))
      (number_range_valid ?uid UID_MIN UID_MAX)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (user_uid_set ?user ?uid)
    )
  )

  (:action modify_default_user_creation
    :parameters (?actor - user ?option - file)
    :precondition (and
      (default_config_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (modified_default_config ?option)
    )
  )

  (:action set_base_directory_for_home
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (not (directory_exists ?dir))
      (can_escalate ?actor)
    )
    :effect (and
      (directory_exists ?dir)
    )
  )

  (:action set_password_inactivity_period
    :parameters (?actor - user ?period - file ?login - user)
    :precondition (and
      (user_exists ?login)
      (can_escalate ?actor)
    )
    :effect (and
      (password_has_inactive_period ?login ?period)
    )
  )

  (:action add_subids_for_system_user
    :parameters (?actor - user ?user - user ?subid_range - file)
    :precondition (and
      (system_user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subid_entry_added ?user ?subid_range)
    )
  )

  (:action add_supplementary_groups
    :parameters (?actor - user ?groups - group ?login - user)
    :precondition (and
      (user_exists ?login)
      (not (member_of_group ?login ?groups))
      (can_escalate ?actor)
    )
    :effect (and
      (member_of_group ?login ?groups)
    )
  )

  (:action disable_home_creation
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
      (not (unique_user_required))
      (can_escalate ?actor)
    )
    :effect (and
      (duplicate_user_allowed ?user)
    )
  )

  (:action add_system_user
    :parameters (?actor - user ?user - user ?uid - file ?password - file ?shell - file ?user_group - file ?selinux_user - file)
    :precondition (and
      (not (user_exists ?user))
      (valid_uid ?uid)
      (valid_shell ?shell)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (system_account ?user)
    )
  )

  (:action add_user_group
    :parameters (?actor - user ?group - group ?user - user)
    :precondition (and
      (not (group_exists ?group))
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
      (user_in_group ?user
      ?group)
    )
  )

  (:action set_selinux_user_mapping
    :parameters (?actor - user ?user - user ?seuser - file)
    :precondition (and
      (user_exists ?user)
      (valid_seuser ?seuser)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_user_mapped ?user
      ?seuser)
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
      (account_modified ?user)
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
    :parameters (?actor - user ?user - user ?dir - directory)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_changed ?user ?dir)
    )
  )

  (:action set_user_account_expiration
    :parameters (?actor - user ?user - user ?expire_date - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (account_expires_on ?user ?expire_date)
    )
  )

  (:action disable_account
    :parameters (?actor - user ?user - user ?date - file)
    :precondition (and
      (account_exists ?user)
      (shadow_file_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (account_disabled ?user)
    )
  )

  (:action set_password_grace_period
    :parameters (?actor - user ?user - user ?inactive_days - file)
    :precondition (and
      (account_exists ?user)
      (shadow_file_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (password_grace_period_set ?user)
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
      (primary_group_of_user ?user ?group)
    )
  )

  (:action update_supplementary_groups
    :parameters (?actor - user ?user - user ?groups - file)
    :precondition (and
      (user_exists ?user)
      (all_groups_exist ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (supplementary_groups_of_user ?user ?groups)
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
      (not (directory_exists ?old_dir))
      (directory_exists ?new_dir)
    )
  )

  (:action remove_user_from_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (user_in_group ?user ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_in_group ?user ?group))
    )
  )

  (:action apply_changes_in_chroot
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_chroot ?dir)
    )
  )

  (:action apply_changes_in_prefix
    :parameters (?actor - user ?prefix - directory)
    :precondition (and
      (directory_exists ?prefix)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_prefix ?prefix)
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

  (:action change_file_ownership
    :parameters (?actor - user ?f - file ?u - user)
    :precondition (and
      (file_exists ?f)
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by_user ?f ?u)
    )
  )

  (:action unlock_password
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (password_locked ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (password_locked ?user))
    )
  )

  (:action set_expire_date
    :parameters (?actor - user ?user - user ?expire_value - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_expire_set ?user ?expire_value)
    )
  )

  (:action add_subordinate_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_range_added ?user first-last)
    )
  )

  (:action remove_subordinate_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (subuid_range_exists ?user first-last)
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_range_removed ?user first-last)
    )
  )

  (:action add_subordinate_gids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subgid_range_added ?user first-last)
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

  (:action modify_user
    :parameters (?actor - user ?login - user ?options - file)
    :precondition (and
      (user_exists ?login)
      (can_escalate ?actor)
    )
    :effect (and
      (user_modified ?login)
    )
  )

  (:action modify_nis_entry
    :parameters (?actor - user ?entry - file ?value - file)
    :precondition (and
      (nis_server_available)
      (nis_entry_exists ?entry)
      (can_escalate ?actor)
    )
    :effect (and
      (nis_entry_modified ?entry ?value)
    )
  )

  (:action set_password_inactive_after_expiration
    :parameters (?actor - user ?user - user ?inactive - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_inactive_after_days ?user ?inactive)
    )
  )

  (:action set_supplementary_groups
    :parameters (?actor - user ?user - user ?groups - file)
    :precondition (and
      (user_exists ?user)
      (all_groups_exist ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (supplementary_groups_of_user ?user ?groups)
    )
  )

  (:action lock_account
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (account_locked ?user)
    )
  )

  (:action set_encrypted_password
    :parameters (?actor - user ?user - user ?password - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (encrypted_password_set ?user)
    )
  )

  (:action change_login_name
    :parameters (?actor - user ?old_user - user ?new_login - file)
    :precondition (and
      (user_exists ?old_user)
      (can_escalate ?actor)
    )
    :effect (and
      (changed_username_to ?old_user ?new_login)
    )
  )

  (:action set_non_unique_uid
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (non_unique_uid_set ?user ?uid)
    )
  )

  (:action set_gecos_field
    :parameters (?actor - user ?user - user ?comment - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (gecos_field_set ?user ?comment)
    )
  )

  (:action remove_supplementary_groups
    :parameters (?actor - user ?user - user ?groups - group)
    :precondition (and
      (user_exists ?user)
      (groups_exist ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_in_group ?user ?groups))
    )
  )

  (:action set_shell
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
      (account_unlocked ?user)
    )
  )

  (:action remove_subordinate_gids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (subgids_exist ?user ?first ?last)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subgids_added ?user ?first ?last))
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

  (:action delete_user_account
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
      (not (home_directory_exists ?user))
    )
  )

  (:action delete_user_and_group
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (group_exists_with_same_name ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
      (not (group_exists_with_same_name ?user))
    )
  )

  (:action delete_user_home_and_mail
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (directory_exists /home/user)
      (file_exists mail_spool)
      (can_escalate ?actor)
    )
    :effect (and
      (not (directory_exists /home/user))
      (not (file_exists mail_spool))
    )
  )

  (:action remove_cron_jobs
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (not (cron_job_exists ?user))
    )
  )

  (:action remove_at_jobs
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (at_job_exists ?user))
    )
  )

  (:action remove_print_jobs
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (not (print_job_exists ?user))
    )
  )

  (:action delete_user_force
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
      (not (group_exists ?user))
    )
  )

  (:action delete_group_if_unused
    :parameters (?actor - user ?group - group ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (primary_group_used_by_other_user ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?group))
    )
  )

  (:action delete_group_force
    :parameters (?actor - user ?group - group ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?group))
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
    :parameters (?actor - user ?groupname - group)
    :precondition (and
      (not (group_exists ?groupname))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?groupname)
    )
  )

  (:action set_group_password
    :parameters (?actor - user ?group - group ?password - file)
    :precondition (and
      (group_exists ?group)
      (password_encrypted ?password)
      (can_escalate ?actor)
    )
    :effect (and
      (group_has_password ?group
      ?password)
    )
  )

  (:action create_group_non_unique
    :parameters (?actor - user ?name - group ?gid - file)
    :precondition (and
      (not (group_exists ?name))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?name)
      (group_has_gid ?name
      ?gid)
    )
  )

  (:action set_group_defaults
    :parameters (?actor - user ?key - file ?value - file)
    :precondition (and
      (group_default_exists ?key)
      (can_escalate ?actor)
    )
    :effect (and
      (group_default_value ?key
      ?value)
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
    :parameters (?actor - user ?grp - group ?user_list - file)
    :precondition (and
      (group_exists ?grp)
      (all_users_exist ?user_list)
      (can_escalate ?actor)
    )
    :effect (and
      (users_in_group ?grp ?user_list)
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
      (not (gid_used ?gid))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
      (group_has_gid ?grp ?gid)
    )
  )

  (:action create_group_non_unique_gid
    :parameters (?actor - user ?grp - group ?gid - file)
    :precondition (and
      (not (group_exists ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
      (group_has_gid ?grp ?gid)
    )
  )

)