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
    (same_owner_group_as ?x - object ?y - object)
    (file_not_overwritten ?x - object ?y - object)
    (masquerade_enabled ?x - object ?y - object)
    (selinux_context_set ?x - object ?y - object)
    (rule_matched_in_current_chain ?x - object ?y - object)
    (files_skipped_in_directory ?x - object ?y - object)
    (system_user ?x - object ?y - object)
    (account_exists ?x - object ?y - object)
    (rule_appended_to_chain ?x - object ?y - object)
    (file_overwritten ?x - object ?y - object)
    (package_from_release ?x - object ?y - object)
    (same_owner ?x - object ?y - object)
    (file_access_changed ?x - object ?y - object)
    (subordinate_gids_exist ?x - object ?y - object)
    (directory_mode_set ?x - object ?y - object)
    (stdout_is_terminal ?x - object ?y - object)
    (process_exists ?x - object ?y - object)
    (new_package_to_install ?x - object ?y - object)
    (file_owned_by_group ?x - object ?y - object)
    (packet_generated ?x - object ?y - object)
    (packet_arrived ?x - object ?y - object)
    (interface_up ?x - object ?y - object)
    (user_exists ?x - object ?y - object)
    (firewall_rule_configured ?x - object ?y - object)
    (subgid_updated ?x - object ?y - object)
    (files_exist ?x - object ?y - object)
    (sticky_bit_set ?x - object ?y - object)
    (version_control_set ?x - object ?y - object)
    (network_available ?x - object ?y - object)
    (user_has_selinux_user ?x - object ?y - object)
    (port_allowed ?x - object ?y - object)
    (counter_packets_set ?x - object ?y - object)
    (process_running_as_user ?x - object ?y - object)
    (rule_added_to_chain_jump_no_return ?x - object ?y - object)
    (sockets_exist ?x - object ?y - object)
    (dry_run_executed ?x - object ?y - object)
    (packet_accepted ?x - object ?y - object)
    (policy_set ?x - object ?y - object)
    (systemd_enabled ?x - object ?y - object)
    (file_copied ?x - object ?y - object)
    (packages_removed ?x - object ?y - object)
    (no_wall_message_executed ?x - object ?y - object)
    (catalog_exists ?x - object ?y - object)
    (rule_added_to_chain_with_interface ?x - object ?y - object)
    (file_exists ?x - object ?y - object)
    (default_target_set ?x - object ?y - object)
    (daemon_not_reloaded ?x - object ?y - object)
    (rule_exists_in_chain ?x - object ?y - object)
    (valid_timestamp ?x - object ?y - object)
    (mount_is_read_only ?x - object ?y - object)
    (service_reloaded ?x - object ?y - object)
    (package_index_updated ?x - object ?y - object)
    (unit_modified ?x - object ?y - object)
    (file_copied_lightweight ?x - object ?y - object)
    (manually_installed ?x - object ?y - object)
    (old_package_files_exist ?x - object ?y - object)
    (file_owned_by_user ?x - object ?y - object)
    (primary_group_id ?x - object ?y - object)
    (file_copied_or_not ?x - object ?y - object)
    (user_has_id ?x - object ?y - object)
    (changes_applied_in_chroot ?x - object ?y - object)
    (contains_package_selections ?x - object ?y - object)
    (effective_user_id ?x - object ?y - object)
    (executed_as_root ?x - object ?y - object)
    (service_not_running ?x - object ?y - object)
    (password_expired ?x - object ?y - object)
    (logging_to_var ?x - object ?y - object)
    (command_valid ?x - object ?y - object)
    (symbolic_links_not_traversed ?x - object ?y - object)
    (execution_frozen_for_units ?x - object ?y - object)
    (option_set ?x - object ?y - object)
    (logging_to_tmpfs ?x - object ?y - object)
    (service_running ?x - object ?y - object)
    (files_unpacked ?x - object ?y - object)
    (dependency_added ?x - object ?y - object)
    (rule_applied ?x - object ?y - object)
    (manager_running ?x - object ?y - object)
    (system_rebooted_with_kernel ?x - object ?y - object)
    (rules_exist ?x - object ?y - object)
    (command_exists ?x - object ?y - object)
    (command_executed_by ?x - object ?y - object)
    (group_has_gid ?x - object ?y - object)
    (package_marked_as_auto ?x - object ?y - object)
    (variable_set ?x - object ?y - object)
    (directory_exists ?x - object ?y - object)
    (subgid_range_added ?x - object ?y - object)
    (special_file_exists ?x - object ?y - object)
    (is_directory ?x - object ?y - object)
    (userspace_restarted ?x - object ?y - object)
    (sparse_file_created ?x - object ?y - object)
    (unit_exists ?x - object ?y - object)
    (all_files_in_directory_have_mode_except_root ?x - object ?y - object)
    (system_account ?x - object ?y - object)
    (using_extra_users_db ?x - object ?y - object)
    (useradd_command_exists ?x - object ?y - object)
    (security_context_default ?x - object ?y - object)
    (resource_limit_reset ?x - object ?y - object)
    (target_exists ?x - object ?y - object)
    (manager_configuration_reloaded ?x - object ?y - object)
    (all_packages_configured ?x - object ?y - object)
    (directory_created_for_mount ?x - object ?y - object)
    (package_file_exists ?x - object ?y - object)
    (iptables_installed ?x - object ?y - object)
    (all_units_preset ?x - object ?y - object)
    (packages_upgraded ?x - object ?y - object)
    (timestamp_set_to ?x - object ?y - object)
    (downloaded_files_exist ?x - object ?y - object)
    (automatically_installed ?x - object ?y - object)
    (requires_dependency_added ?x - object ?y - object)
    (package_info_exists ?x - object ?y - object)
    (package_reinstalled ?x - object ?y - object)
    (output_colored ?x - object ?y - object)
    (changes_applied_in_prefix ?x - object ?y - object)
    (symlink_accessed ?x - object ?y - object)
    (dependency_resolved ?x - object ?y - object)
    (file_moved ?x - object ?y - object)
    (prerm_executed ?x - object ?y - object)
    (all_other_units_stopped ?x - object ?y - object)
    (unwritten_journal_data_exists ?x - object ?y - object)
    (user_comment_set ?x - object ?y - object)
    (dir_exists ?x - object ?y - object)
    (group_default_set ?x - object ?y - object)
    (file_copied_with_suffix ?x - object ?y - object)
    (mac_rule_enabled ?x - object ?y - object)
    (traffic_blocked ?x - object ?y - object)
    (password_grace_period_set ?x - object ?y - object)
    (system_user_exists ?x - object ?y - object)
    (time_set_to_file ?x - object ?y - object)
    (file_copied_to ?x - object ?y - object)
    (table_exists ?x - object ?y - object)
    (root_directory_untouched ?x - object ?y - object)
    (has_permission_to_read_journal ?x - object ?y - object)
    (file_modification_time_updated ?x - object ?y - object)
    (packet_processed ?x - object ?y - object)
    (encrypted_password_set ?x - object ?y - object)
    (no_selections ?x - object ?y - object)
    (prefix_set ?x - object ?y - object)
    (shadow_file_exists ?x - object ?y - object)
    (unused_packages_exist ?x - object ?y - object)
    (cache_distcleaned ?x - object ?y - object)
    (user_exists_all_entries ?x - object ?y - object)
    (package_cache_exists ?x - object ?y - object)
    (kernel_configured_for_autoload ?x - object ?y - object)
    (lists_cleaned ?x - object ?y - object)
    (system_state_modified ?x - object ?y - object)
    (process_terminated ?x - object ?y - object)
    (dependencies_satisfied ?x - object ?y - object)
    (filters_applied_from_file ?x - object ?y - object)
    (extended_attributes_copied ?x - object ?y - object)
    (packet_dropped ?x - object ?y - object)
    (user_uid_set ?x - object ?y - object)
    (all_packages_updated ?x - object ?y - object)
    (clone_copied ?x - object ?y - object)
    (chain_exists ?x - object ?y - object)
    (file_backup_created ?x - object ?y - object)
    (supplementary_group_of_user ?x - object ?y - object)
    (group_exists ?x - object ?y - object)
    (file_copied_to_file ?x - object ?y - object)
    (kernel_available ?x - object ?y - object)
    (source_package_info_fetched ?x - object ?y - object)
    (selinux_context_set_to_default ?x - object ?y - object)
    (number_of_journal_files ?x - object ?y - object)
    (counters_reset ?x - object ?y - object)
    (valid_uid ?x - object ?y - object)
    (sources_file_exists ?x - object ?y - object)
    (file_access_time_updated ?x - object ?y - object)
    (wants_dependency_added ?x - object ?y - object)
    (package_from_distribution ?x - object ?y - object)
    (non_unique_uid_set ?x - object ?y - object)
    (out_interface_inverted ?x - object ?y - object)
    (current_root_is ?x - object ?y - object)
    (packages_marked_for_purge ?x - object ?y - object)
    (files_in_directory_owned_by ?x - object ?y - object)
    (non_unique_user_created ?x - object ?y - object)
    (selections_exist ?x - object ?y - object)
    (architecture_exists ?x - object ?y - object)
    (pseudo_terminal_created ?x - object ?y - object)
    (backup_type ?x - object ?y - object)
    (file_owned_by ?x - object ?y - object)
    (primary_group_of_user ?x - object ?y - object)
    (source_package_downloaded ?x - object ?y - object)
    (account_expires_on ?x - object ?y - object)
    (all_units_exist ?x - object ?y - object)
    (symlink_access_time_updated ?x - object ?y - object)
    (same_filesystem ?x - object ?y - object)
    (unique_uid ?x - object ?y - object)
    (chrooted_into ?x - object ?y - object)
    (package_availability_updated ?x - object ?y - object)
    (same_name ?x - object ?y - object)
    (file_readable ?x - object ?y - object)
    (selinux_context_default ?x - object ?y - object)
    (shell_exists ?x - object ?y - object)
    (path_bound_to_unit ?x - object ?y - object)
    (source_files_downloaded ?x - object ?y - object)
    (package_reconfigured ?x - object ?y - object)
    (file_writable ?x - object ?y - object)
    (environment_variables_unset ?x - object ?y - object)
    (groups_exist ?x - object ?y - object)
    (suspend_supported ?x - object ?y - object)
    (unit_cleaned ?x - object ?y - object)
    (user_home_set ?x - object ?y - object)
    (scheduled_action ?x - object ?y - object)
    (unit_reloaded ?x - object ?y - object)
    (owner_and_group_from_reference_file ?x - object ?y - object)
    (journalctl_installed ?x - object ?y - object)
    (cache_cleaned ?x - object ?y - object)
    (environment_modified_by_pam ?x - object ?y - object)
    (execution_resumed_for_units ?x - object ?y - object)
    (directory_owned_by ?x - object ?y - object)
    (build_dependencies_configured ?x - object ?y - object)
    (binary_files_downloaded ?x - object ?y - object)
    (group_defaults_exist ?x - object ?y - object)
    (group_has_password ?x - object ?y - object)
    (sockets_closed ?x - object ?y - object)
    (environment_variables_set ?x - object ?y - object)
    (session_running_shell ?x - object ?y - object)
    (output_interface_set ?x - object ?y - object)
    (processes_killed_in_unit ?x - object ?y - object)
    (user_shell_set ?x - object ?y - object)
    (current_user ?x - object ?y - object)
    (cache_cleared ?x - object ?y - object)
    (environment_editable ?x - object ?y - object)
    (child_exists ?x - object ?y - object)
    (firewall_rule_exists ?x - object ?y - object)
    (service_exists ?x - object ?y - object)
    (logs_reset ?x - object ?y - object)
    (postrm_executed ?x - object ?y - object)
    (files_updated_in_directory ?x - object ?y - object)
    (all_users_exist ?x - object ?y - object)
    (processes_running_in_units ?x - object ?y - object)
    (package_downloaded ?x - object ?y - object)
    (units_match_pattern ?x - object ?y - object)
    (log_threshold_set_for_service ?x - object ?y - object)
    (file_older_than ?x - object ?y - object)
    (symlink_modified ?x - object ?y - object)
    (file_grouped_to_group ?x - object ?y - object)
    (environment_preserved_for_user ?x - object ?y - object)
    (modes_copied ?x - object ?y - object)
    (hibernation_supported ?x - object ?y - object)
    (script_exists ?x - object ?y - object)
    (owned_by_user ?x - object ?y - object)
    (system_hibernated ?x - object ?y - object)
    (file_group ?x - object ?y - object)
    (password_inactive_period_set ?x - object ?y - object)
    (debug_info_printed ?x - object ?y - object)
    (subuid_updated ?x - object ?y - object)
    (comment_updated ?x - object ?y - object)
    (unit_reverted_to_vendor_version ?x - object ?y - object)
    (moved_home_directory ?x - object ?y - object)
    (package_info_updated ?x - object ?y - object)
    (journal_files_exist ?x - object ?y - object)
    (system_powered_off ?x - object ?y - object)
    (sources_updated ?x - object ?y - object)
    (package_cache_cleaned ?x - object ?y - object)
    (unit_active ?x - object ?y - object)
    (environment_variables_imported ?x - object ?y - object)
    (file_modified_time_updated ?x - object ?y - object)
    (shell_running_as_user ?x - object ?y - object)
    (service_watchdogs_set ?x - object ?y - object)
    (system_up_to_date ?x - object ?y - object)
    (package_installed ?x - object ?y - object)
    (members_exceed_limit ?x - object ?y - object)
    (package_updates_exist ?x - object ?y - object)
    (source_repository_configured ?x - object ?y - object)
    (uid_exists ?x - object ?y - object)
    (primary_group_set ?x - object ?y - object)
    (base_directory_set ?x - object ?y - object)
    (cache_exists ?x - object ?y - object)
    (configures ?x - object ?y - object)
    (file_has_mode ?x - object ?y - object)
    (nat_table_available ?x - object ?y - object)
    (header_suppressed ?x - object ?y - object)
    (dependencies_installed ?x - object ?y - object)
    (child_terminated ?x - object ?y - object)
    (object_valid ?x - object ?y - object)
    (command_executed_in_namespace ?x - object ?y - object)
    (old_downloaded_files_exist ?x - object ?y - object)
    (user_in_group ?x - object ?y - object)
    (time_attribute_set_to ?x - object ?y - object)
    (any_unit_exists ?x - object ?y - object)
    (user_locked ?x - object ?y - object)
    (home_directory_set ?x - object ?y - object)
    (source_fetched ?x - object ?y - object)
    (target_available ?x - object ?y - object)
    (signal_received ?x - object ?y - object)
    (systemd_running ?x - object ?y - object)
    (package_version ?x - object ?y - object)
    (resume_previous_chain_processing ?x - object ?y - object)
    (symbolic_link_exists ?x - object ?y - object)
    (rule_added_to_chain ?x - object ?y - object)
    (units_restarted_or_reloaded ?x - object ?y - object)
    (selections_set ?x - object ?y - object)
    (packet_altered ?x - object ?y - object)
    (has_home_directory ?x - object ?y - object)
    (self_terminated_with_signal ?x - object ?y - object)
    (subuid_range_removed ?x - object ?y - object)
    (packages_installed ?x - object ?y - object)
    (package_updated ?x - object ?y - object)
    (image_mounted_to_unit ?x - object ?y - object)
    (no_user_group_created ?x - object ?y - object)
    (shell_login_mode ?x - object ?y - object)
    (mount_point_not_exists ?x - object ?y - object)
    (system_initialized ?x - object ?y - object)
    (executed_subcommand ?x - object ?y - object)
    (catalog_updated ?x - object ?y - object)
    (rule_inserted_into_chain ?x - object ?y - object)
    (custom_context_set ?x - object ?y - object)
    (source_package_exists ?x - object ?y - object)
    (current_table_set_to ?x - object ?y - object)
    (processes_running_in_unit ?x - object ?y - object)
    (output_exists ?x - object ?y - object)
    (backup_created ?x - object ?y - object)
    (config_file_exists ?x - object ?y - object)
    (user_expire_date_set ?x - object ?y - object)
    (all_journals_synced_to_disk ?x - object ?y - object)
    (apt_cache_updated ?x - object ?y - object)
    (startup_completed ?x - object ?y - object)
    (counters_set_for_rule ?x - object ?y - object)
    (environment_initialized_for_user ?x - object ?y - object)
    (extra_users_db_available ?x - object ?y - object)
    (symlink_modification_time_updated ?x - object ?y - object)
    (rule_replaced_in_chain ?x - object ?y - object)
    (packages_updated ?x - object ?y - object)
    (system_halted ?x - object ?y - object)
    (set_group_id_cleared ?x - object ?y - object)
    (chain_policy_set ?x - object ?y - object)
    (home_directory_not_created ?x - object ?y - object)
    (system_powered_on ?x - object ?y - object)
    (sparse_files_inhibited ?x - object ?y - object)
    (rule_deleted_from_chain ?x - object ?y - object)
    (selinux_context_set_to_custom ?x - object ?y - object)
    (attributes_copied_to ?x - object ?y - object)
    (service_enabled ?x - object ?y - object)
    (default_policy_set ?x - object ?y - object)
    (rename_failed ?x - object ?y - object)
    (exists ?x - object ?y - object)
    (unit_preset ?x - object ?y - object)
    (user_prompted ?x - object ?y - object)
    (mail_spool_updated ?x - object ?y - object)
    (no_unused_dependencies ?x - object ?y - object)
    (link_copied_to ?x - object ?y - object)
    (process_running ?x - object ?y - object)
    (system_group_exists ?x - object ?y - object)
    (next_boot_in_entry ?x - object ?y - object)
    (user_expiry_date_set ?x - object ?y - object)
    (binary_package_compiled ?x - object ?y - object)
    (account_modified ?x - object ?y - object)
    (subid_entry_added ?x - object ?y - object)
    (package_configured ?x - object ?y - object)
    (permissions_changed ?x - object ?y - object)
    (USERGROUPS_ENAB=yes ?x - object ?y - object)
    (ip6tables_installed ?x - object ?y - object)
    (users_in_group ?x - object ?y - object)
    (package_manager_initialized ?x - object ?y - object)
    (gecos_field_set ?x - object ?y - object)
    (same_group ?x - object ?y - object)
    (account_disabled ?x - object ?y - object)
    (system_suspended ?x - object ?y - object)
    (process_running_with_privileges ?x - object ?y - object)
    (current_namespace_set ?x - object ?y - object)
    (namespace_exists ?x - object ?y - object)
    (logging_threshold_set ?x - object ?y - object)
    (keys_generated ?x - object ?y - object)
    (trailing_slashes_removed ?x - object ?y - object)
    (old_files_backed_up ?x - object ?y - object)
    (can_escalate ?x - object ?y - object)
    (number_range_valid ?x - object ?y - object)
    (triggers_pending ?x - object ?y - object)
    (subuid_range_added ?x - object ?y - object)
    (unit_masked ?x - object ?y - object)
    (directory_exists_or_createable ?x - object ?y - object)
    (mount_point_exists ?x - object ?y - object)
    (new_version_available ?x - object ?y - object)
    (password_encrypted ?x - object ?y - object)
    (job_cancelled ?x - object ?y - object)
    (password_changed ?x - object ?y - object)
    (login_name_changed ?x - object ?y - object)
    (ownership_adapted ?x - object ?y - object)
    (entry_exists ?x - object ?y - object)
    (all_unwritten_data_flushed_to_disk ?x - object ?y - object)
    (new_home_directory_set ?x - object ?y - object)
    (system_upgraded ?x - object ?y - object)
    (package_lists_updated ?x - object ?y - object)
    (file_accessed ?x - object ?y - object)
    (apt_config_set ?x - object ?y - object)
    (user_has_password ?x - object ?y - object)
    (file_copied_standard ?x - object ?y - object)
    (symlink_exists ?x - object ?y - object)
    (log_target_set_for_service ?x - object ?y - object)
    (session_has_pty ?x - object ?y - object)
    (password_inactive_after ?x - object ?y - object)
    (interface_exists ?x - object ?y - object)
    (path_exists ?x - object ?y - object)
    (default_user_settings_modified ?x - object ?y - object)
    (all_files_in_directory_have_mode ?x - object ?y - object)
    (file_has_timestamp ?x - object ?y - object)
    (no_faillog_entry ?x - object ?y - object)
    (file_copied_to_directory ?x - object ?y - object)
    (socket_exists ?x - object ?y - object)
    (all_groups_exist ?x - object ?y - object)
    (effective_shell ?x - object ?y - object)
    (files_copied_to ?x - object ?y - object)
    (default_value_set ?x - object ?y - object)
    (exemption_configured ?x - object ?y - object)
    (counter_bytes_set ?x - object ?y - object)
    (unit_file_edited ?x - object ?y - object)
    (build_environment_ready ?x - object ?y - object)
    (shell_allowed_by_etc_shells ?x - object ?y - object)
    (dirs_exist ?x - object ?y - object)
    (subuid_allocated ?x - object ?y - object)
    (special_bit_cleared ?x - object ?y - object)
    (password_locked ?x - object ?y - object)
    (unwritten_journal_messages_exist ?x - object ?y - object)
    (input_interface_set ?x - object ?y - object)
    (password_set ?x - object ?y - object)
    (package_built ?x - object ?y - object)
    (rule_exists ?x - object ?y - object)
    (filter_applied ?x - object ?y - object)
    (file_updated_if_older ?x - object ?y - object)
    (operates_on ?x - object ?y - object)
    (module_loaded ?x - object ?y - object)
    (is_empty ?x - object ?y - object)
    (apt_cache_exists ?x - object ?y - object)
    (all_lines_valid_user_entries ?x - object ?y - object)
    (unused_dependency_exists ?x - object ?y - object)
    (cache_autocleaned ?x - object ?y - object)
    (disk_usage_less_than_or_equal_to ?x - object ?y - object)
    (attributes_preserved ?x - object ?y - object)
    (packages_pending_configuration ?x - object ?y - object)
    (chain_is_empty ?x - object ?y - object)
    (command_line_valid ?x - object ?y - object)
    (package_list_updated ?x - object ?y - object)
    (valid_option ?x - object ?y - object)
    (default_user_info_updated ?x - object ?y - object)
    (link_created ?x - object ?y - object)
    (system_configurable ?x - object ?y - object)
    (new_group_entry_created ?x - object ?y - object)
    (acl_copied ?x - object ?y - object)
    (hard_link_created ?x - object ?y - object)
    (system_optimized ?x - object ?y - object)
    (no_home_directory ?x - object ?y - object)
    (root_privileges ?x - object ?y - object)
    (units_are_marked ?x - object ?y - object)
    (disk_usage_greater_than ?x - object ?y - object)
    (triggers_processed ?x - object ?y - object)
    (security_context_set ?x - object ?y - object)
    (new_journal_files_created ?x - object ?y - object)
    (symbolic_links_traversed ?x - object ?y - object)
    (directory_preserve_bits ?x - object ?y - object)
    (valid_seuser ?x - object ?y - object)
    (group_exists_with_same_name ?x - object ?y - object)
    (login_def_overridden ?x - object ?y - object)
    (backup_suffix_set ?x - object ?y - object)
    (packages_match ?x - object ?y - object)
    (special_file_copied_to ?x - object ?y - object)
    (next_boot_in_loader_menu ?x - object ?y - object)
    (file_modified ?x - object ?y - object)
    (full_path_preserved ?x - object ?y - object)
    (valid_command ?x - object ?y - object)
    (protocol_family_set ?x - object ?y - object)
    (is_empty_directory ?x - object ?y - object)
    (member_of ?x - object ?y - object)
    (selinux_user_mapped ?x - object ?y - object)
    (supplementary_groups_of_user ?x - object ?y - object)
    (newer_version_available ?x - object ?y - object)
    (system_rebooted ?x - object ?y - object)
    (image_exists ?x - object ?y - object)
    (special_bit_set ?x - object ?y - object)
    (file_updated ?x - object ?y - object)
    (all_jobs_exist ?x - object ?y - object)
    (system_hybrid_slept ?x - object ?y - object)
    (operation_performed_recursively_on_directory ?x - object ?y - object)
    (home_directory_created ?x - object ?y - object)
    (file_in_group ?x - object ?y - object)
    (unit_running ?x - object ?y - object)
    (preinst_executed ?x - object ?y - object)
    (file_has_same_mode_as_reference ?x - object ?y - object)
    (unit_linked ?x - object ?y - object)
    (logging_target_set ?x - object ?y - object)
    (failed_state_reset_for_unit ?x - object ?y - object)
    (command_executed_by_user ?x - object ?y - object)
    (subuid_range_exists ?x - object ?y - object)
    (property_set_for_unit ?x - object ?y - object)
    (files_copied_within_filesystem ?x - object ?y - object)
    (account_locked ?x - object ?y - object)
    (no_lastlog_entry ?x - object ?y - object)
    (symbolic_links_to_directories_traversed ?x - object ?y - object)
    (journals_exist ?x - object ?y - object)
    (root_directory_treated_normally ?x - object ?y - object)
    (unit_enabled ?x - object ?y - object)
    (sticky_bit_cleared ?x - object ?y - object)
    (old_package_installed ?x - object ?y - object)
    (no_journal_older_than ?x - object ?y - object)
    (upgradable_packages_exist ?x - object ?y - object)
    (member_of_group ?x - object ?y - object)
    (valid_time_attribute ?x - object ?y - object)
    (password_inactive_after_days ?x - object ?y - object)
    (system_running ?x - object ?y - object)
    (config_applied ?x - object ?y - object)
    (manager_reexecuted ?x - object ?y - object)
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

  (:action upgrade_system
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (package_updates_exist)
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
      (packages_removed)
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

  (:action clean_old_package_files
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

  (:action dist_upgrade
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_installed ?pkg)
      (new_version_available ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_updated ?pkg)
      (dependency_resolved)
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
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_version ?pkg ?version)
    )
  )

  (:action install_package_distribution
    :parameters (?actor - user ?pkg - package ?distribution - file)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_from_distribution ?pkg ?distribution)
    )
  )

  (:action set_package_policy
    :parameters (?actor - user ?pkg - package ?policy - file)
    :precondition (and
      (file_exists /etc/apt/preferences)
      (not (policy_set ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (policy_set ?pkg)
    )
  )

  (:action install_package_regex
    :parameters (?actor - user ?regex - file)
    :precondition (and
      (packages_match ?regex)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
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
      (build_environment_ready)
    )
    :effect (and
      (binary_package_compiled ?src)
    )
  )

  (:action satisfy_build_dependencies
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (source_package_exists ?pkg)
      (not (dependencies_satisfied ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (dependencies_satisfied ?pkg)
    )
  )

  (:action satisfy_dependencies
    :parameters (?actor - user ?deps - file)
    :precondition (and
      (network_available)
      (apt_cache_updated)
      (can_escalate ?actor)
    )
    :effect (and
      (dependencies_satisfied ?deps)
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

  (:action prevent_package_removal
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (not (package_to_be_removed))
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_removed))
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
      (source_fetched ?src)
    )
  )

  (:action set_configuration_option
    :parameters (?option - file ?value - file)
    :precondition (and
      (config_file_exists /etc/apt/apt.conf)
      (not (option_set ?option))
    )
    :effect (and
      (option_set ?option)
    )
  )

  (:action set_apt_config_file
    :parameters (?config_file - file)
    :precondition (and
      (file_exists ?config_file)
    )
    :effect (and
      (apt_config_set ?config_file)
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

  (:action auto_remove_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (exists (automatically_installed_package ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
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

  (:action auto_remove_unused_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (unused_packages_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (not (unused_packages_exist))
    )
  )

  (:action system_upgrade
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (upgradable_packages_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (system_upgraded)
    )
  )

  (:action full_system_upgrade
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (upgradable_packages_exist)
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

  (:action build_package
    :parameters (?src - directory)
    :precondition (and
      (directory_exists ?src)
    )
    :effect (and
      (package_built ?pkg)
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

  (:action install_package_from_file
    :parameters (?actor - user ?package-file - file)
    :precondition (and
      (file_exists ?package-file)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
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

  (:action unpack_package
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

  (:action unpack_package_file
    :parameters (?actor - user ?file - package ?dir - directory)
    :precondition (and
      (package_file_exists ?file)
      (dir_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (files_unpacked ?file)
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

  (:action purge_all_marked_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (packages_marked_for_purge)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
      (not (config_files_exist ?pkg)) for all marked packages
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
      (package_manager_initialized)
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

  (:action erase_package_info
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_info_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_info_exists))
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

  (:action try_reload_or_restart_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
      (service_reloaded ?svc)
    )
  )

  (:action reload_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (unit_exists ?unit)
      (unit_active ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_reloaded ?unit)
    )
  )

  (:action isolate_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (unit_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_running ?unit)
      (all_other_units_stopped)
    )
  )

  (:action kill_unit
    :parameters (?actor - user ?unit - service ?signal - file)
    :precondition (and
      (unit_exists ?unit)
      (processes_running_in_unit ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (processes_killed_in_unit ?unit)
    )
  )

  (:action clean_unit
    :parameters (?actor - user ?unit - service ?type - file)
    :precondition (and
      (unit_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_cleaned ?unit)
    )
  )

  (:action freeze_unit
    :parameters (?actor - user ?pattern - file)
    :precondition (and
      (units_match_pattern ?pattern)
      (processes_running_in_units ?pattern)
      (can_escalate ?actor)
    )
    :effect (and
      (execution_frozen_for_units ?pattern)
    )
  )

  (:action thaw_unit
    :parameters (?actor - user ?pattern - file)
    :precondition (and
      (units_match_pattern ?pattern)
      (execution_frozen_for_units ?pattern)
      (can_escalate ?actor)
    )
    :effect (and
      (execution_resumed_for_units ?pattern)
    )
  )

  (:action set_unit_property
    :parameters (?actor - user ?unit - service ?property - file ?value - file)
    :precondition (and
      (unit_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (property_set_for_unit ?unit ?property ?value)
    )
  )

  (:action bind_mount_path
    :parameters (?actor - user ?unit - file ?host_path - file ?target_path - file)
    :precondition (and
      (unit_exists ?unit)
      (path_exists ?host_path)
      (can_escalate ?actor)
    )
    :effect (and
      (path_bound_to_unit ?unit ?host_path ?target_path)
    )
  )

  (:action mount_image_into_unit
    :parameters (?actor - user ?unit - file ?image - file ?target_path - file ?options - file)
    :precondition (and
      (unit_exists ?unit)
      (image_exists ?image)
      (can_escalate ?actor)
    )
    :effect (and
      (image_mounted_to_unit ?unit ?image ?target_path)
    )
  )

  (:action set_service_log_level
    :parameters (?actor - user ?service - service ?level - file)
    :precondition (and
      (service_exists ?service)
      (can_escalate ?actor)
    )
    :effect (and
      (log_threshold_set_for_service ?service ?level)
    )
  )

  (:action set_service_log_target
    :parameters (?actor - user ?service - service ?target - file)
    :precondition (and
      (service_exists ?service)
      (can_escalate ?actor)
    )
    :effect (and
      (log_target_set_for_service ?service ?target)
    )
  )

  (:action reset_failed_units
    :parameters (?actor - user ?pattern - file)
    :precondition (and
      (unit_exists ?pattern)
      (can_escalate ?actor)
    )
    :effect (and
      (failed_state_reset_for_unit ?pattern)
    )
  )

  (:action enable_unit_file
    :parameters (?actor - user ?unit - file)
    :precondition (and
      (unit_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_enabled ?unit)
    )
  )

  (:action disable_unit_file
    :parameters (?actor - user ?unit - file)
    :precondition (and
      (unit_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (not (unit_enabled ?unit))
    )
  )

  (:action reenable_unit_file
    :parameters (?actor - user ?unit - file)
    :precondition (and
      (unit_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_enabled ?unit)
    )
  )

  (:action preset_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (unit_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_preset ?unit)
    )
  )

  (:action preset_all_units
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (any_unit_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (all_units_preset)
    )
  )

  (:action mask_unit
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (unit_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_masked ?unit)
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

  (:action link_unit_file
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
      (unit_modified ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_reverted_to_vendor_version ?unit)
    )
  )

  (:action add_wants_dependency
    :parameters (?actor - user ?target - service ?unit - service)
    :precondition (and
      (service_exists ?target)
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (wants_dependency_added ?target ?unit)
    )
  )

  (:action add_requires_dependency
    :parameters (?actor - user ?target - service ?unit - service)
    :precondition (and
      (service_exists ?target)
      (service_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (requires_dependency_added ?target ?unit)
    )
  )

  (:action add_dependency
    :parameters (?actor - user ?target - file ?units - file)
    :precondition (and
      (unit_exists ?target)
      (all_units_exist ?units)
      (can_escalate ?actor)
    )
    :effect (and
      (dependency_added ?target ?units)
    )
  )

  (:action edit_unit_file
    :parameters (?actor - user ?unit_files - file)
    :precondition (and
      (all_units_exist ?unit_files)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_file_edited ?unit_files)
    )
  )

  (:action set_default_target
    :parameters (?actor - user ?target - file)
    :precondition (and
      (unit_exists ?target)
      (can_escalate ?actor)
    )
    :effect (and
      (default_target_set ?target)
    )
  )

  (:action cancel_job
    :parameters (?actor - user ?jobs - file)
    :precondition (and
      (all_jobs_exist ?jobs)
      (can_escalate ?actor)
    )
    :effect (and
      (job_cancelled ?jobs)
    )
  )

  (:action set_environment_variable
    :parameters (?actor - user ?variables - file)
    :precondition (and
      (environment_editable)
      (can_escalate ?actor)
    )
    :effect (and
      (environment_variables_set ?variables)
    )
  )

  (:action unset_environment_variable
    :parameters (?actor - user ?variables - file)
    :precondition (and
      (environment_editable)
      (can_escalate ?actor)
    )
    :effect (and
      (environment_variables_unset ?variables)
    )
  )

  (:action import_environment_variable
    :parameters (?actor - user ?variables - file)
    :precondition (and
      (environment_editable)
      (can_escalate ?actor)
    )
    :effect (and
      (environment_variables_imported ?variables)
    )
  )

  (:action reload_systemd_manager
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (systemd_running)
      (can_escalate ?actor)
    )
    :effect (and
      (manager_configuration_reloaded)
    )
  )

  (:action reexec_systemd_manager
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (systemd_running)
      (can_escalate ?actor)
    )
    :effect (and
      (manager_reexecuted)
    )
  )

  (:action set_log_level
    :parameters (?actor - user ?level - file)
    :precondition (and
      (manager_running)
      (can_escalate ?actor)
    )
    :effect (and
      (logging_threshold_set ?level)
    )
  )

  (:action set_log_target
    :parameters (?actor - user ?target - file)
    :precondition (and
      (manager_running)
      (can_escalate ?actor)
    )
    :effect (and
      (logging_target_set ?target)
    )
  )

  (:action set_service_watchdogs_state
    :parameters (?actor - user ?bool - file)
    :precondition (and
      (manager_running)
      (can_escalate ?actor)
    )
    :effect (and
      (service_watchdogs_set ?bool)
    )
  )

  (:action shutdown_halt
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_running)
      (can_escalate ?actor)
    )
    :effect (and
      (system_halted)
      (not (system_running))
    )
  )

  (:action shutdown_poweroff
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_running)
      (can_escalate ?actor)
    )
    :effect (and
      (system_powered_off)
      (not (system_running))
    )
  )

  (:action shutdown_reboot
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_running)
      (can_escalate ?actor)
    )
    :effect (and
      (system_rebooted)
      (system_running)
    )
  )

  (:action shutdown_kexec
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_running)
      (kernel_available)
      (can_escalate ?actor)
    )
    :effect (and
      (system_rebooted_with_kernel)
      (system_running)
    )
  )

  (:action shutdown_soft_reboot
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_running)
      (can_escalate ?actor)
    )
    :effect (and
      (userspace_restarted)
      (system_running)
    )
  )

  (:action change_root_filesystem
    :parameters (?actor - user ?root - directory ?init - process)
    :precondition (and
      (directory_exists ?root)
      (not (current_root_is ?root))
      (can_escalate ?actor)
    )
    :effect (and
      (current_root_is ?root)
    )
  )

  (:action system_suspend
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_running)
      (suspend_supported)
      (can_escalate ?actor)
    )
    :effect (and
      (system_suspended)
      (not (system_running))
    )
  )

  (:action system_hibernate
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_running)
      (hibernation_supported)
      (can_escalate ?actor)
    )
    :effect (and
      (system_hibernated)
      (not (system_running))
    )
  )

  (:action system_hybrid_sleep
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_running)
      (suspend_supported)
      (hibernation_supported)
      (can_escalate ?actor)
    )
    :effect (and
      (system_hybrid_slept)
      (not (system_running))
    )
  )

  (:action suspend_then_hibernate
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_running)
      (can_escalate ?actor)
    )
    :effect (and
      (system_hibernated)
    )
  )

  (:action start_stop_unit_after_enabling_disabling
    :parameters (?actor - user ?unit - service ?action - file)
    :precondition (and
      (service_exists ?unit)
      (not (service_running ?unit))
      (systemd_enabled)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?unit) | (not (service_running ?unit))
    )
  )

  (:action dry_run_action
    :parameters (?verb - process)
    :precondition (and
      (command_exists ?verb)
    )
    :effect (and
      (dry_run_executed ?verb)
    )
  )

  (:action wait_until_service_stopped_after_restart
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (not (service_running ?svc))
      (can_escalate ?actor)
    )
    :effect (and
      (service_not_running ?svc)
    )
  )

  (:action wait_until_startup_completed
    :parameters (?obj - file)
    :precondition (and
      (systemd_enabled)
    )
    :effect (and
      (startup_completed)
    )
  )

  (:action no_wall_message_before_halt_poweroff_reboot
    :parameters (?actor - user ?verb - process)
    :precondition (and
      (command_exists ?verb)
      (can_escalate ?actor)
    )
    :effect (and
      (no_wall_message_executed ?verb)
    )
  )

  (:action no_reload_daemon_after_enabling_disabling_unit_files
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (systemd_enabled)
      (can_escalate ?actor)
    )
    :effect (and
      (daemon_not_reloaded)
    )
  )

  (:action boot_into_loader_menu
    :parameters (?actor - user ?time - file)
    :precondition (and
      (system_powered_on)
      (can_escalate ?actor)
    )
    :effect (and
      (next_boot_in_loader_menu ?time)
    )
  )

  (:action boot_into_entry
    :parameters (?actor - user ?name - file)
    :precondition (and
      (system_powered_on)
      (entry_exists ?name)
      (can_escalate ?actor)
    )
    :effect (and
      (next_boot_in_entry ?name)
    )
  )

  (:action create_read_only_bind_mount
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (mount_point_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (mount_is_read_only)
    )
  )

  (:action create_directory_before_mounting
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (mount_point_not_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_created_for_mount)
    )
  )

  (:action restart_marked_units
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (units_are_marked)
      (can_escalate ?actor)
    )
    :effect (and
      (units_restarted_or_reloaded)
    )
  )

  (:action schedule_system_action
    :parameters (?actor - user ?time - file ?action - process)
    :precondition (and
      (valid_timestamp ?time)
      (system_running)
      (can_escalate ?actor)
    )
    :effect (and
      (scheduled_action ?action
      ?time)
    )
  )

  (:action operate_on_directory
    :parameters (?dir - directory)
    :precondition (and
      (journalctl_installed)
      (has_permission_to_read_journal)
    )
    :effect (and
      (operates_on ?dir)
    )
  )

  (:action operate_on_file
    :parameters (?glob - file)
    :precondition (and
      (journalctl_installed)
      (has_permission_to_read_journal)
    )
    :effect (and
      (operates_on ?glob)
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
      (unwritten_journal_data_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (all_unwritten_data_flushed_to_disk)
    )
  )

  (:action stop_logging_to_disk
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (logging_to_var)
      (can_escalate ?actor)
    )
    :effect (and
      (logging_to_tmpfs)
    )
  )

  (:action conditional_stop_logging_to_disk
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (logging_to_var)
      (not (log_directory_on_root_mount))
      (can_escalate ?actor)
    )
    :effect (and
      (logging_to_tmpfs)
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

  (:action copy_attributes_only
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (attributes_copied_to ?source ?dest)
    )
  )

  (:action copy_with_backup
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied_to ?source ?dest)
      (backup_created ?source)
    )
  )

  (:action copy_with_backup_no_arg
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied_to ?source ?dest)
      (backup_created ?source)
    )
  )

  (:action copy_contents_of_special_files
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (special_file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (special_file_copied_to ?source ?dest)
    )
  )

  (:action copy_links_and_preserve
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (link_copied_to ?source ?dest)
      (attributes_preserved ?source ?dest)
    )
  )

  (:action copy_with_debug_info
    :parameters (?source - file ?dest - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?dest)
    )
    :effect (and
      (file_copied_to ?source ?dest)
      (debug_info_printed)
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

  (:action remove_destination_before_copy
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
      (link_created ?src ?dest)
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

  (:action overwrite_file_forcefully
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_overwritten ?f)
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

  (:action create_hard_link
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (hard_link_created ?dst)
    )
  )

  (:action prevent_overwrite
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_not_overwritten ?f)
    )
  )

  (:action remove_destination_before_copying
    :parameters (?dst - file)
    :precondition (and
      (file_exists ?dst)
    )
    :effect (and
      (not (file_exists ?dst))
    )
  )

  (:action no_dereference_source
    :parameters (?src - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (not (follows_link ?src))
    )
  )

  (:action preserve_attributes
    :parameters (?src - file ?dst - file ?attr_list - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (attributes_preserved ?src ?dst ?attr_list)
    )
  )

  (:action strip_trailing_slashes
    :parameters (?source - directory)
    :precondition (and
      (directory_exists ?source)
    )
    :effect (and
      (trailing_slashes_removed ?source)
    )
  )

  (:action sparse_file_control
    :parameters (?src - file ?dst - file ?when - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (sparse_file_created ?dst ?when)
    )
  )

  (:action preserve_full_source_path
    :parameters (?source - file ?directory - directory)
    :precondition (and
      (file_exists ?source)
      (directory_exists ?directory)
    )
    :effect (and
      (full_path_preserved ?source ?directory)
    )
  )

  (:action reflink_control
    :parameters (?src - file ?dst - file ?when - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (clone_copied ?dst ?when)
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
    :parameters (?src - directory ?dest - directory)
    :precondition (and
      (directory_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (files_updated_in_directory ?dest)
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
    :parameters (?actor - user ?f - file ?u - user ?g - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by_user ?f ?u)
      (file_owned_by_group ?f ?g)
    )
  )

  (:action change_timestamps
    :parameters (?f - file ?t - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_has_timestamp ?f {t})
    )
  )

  (:action create_non_sparse_file
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (not (file_is_sparse ?dest))
    )
  )

  (:action skip_files
    :parameters (?src - directory ?dest - directory)
    :precondition (and
      (directory_exists ?src)
      (directory_exists ?dest)
    )
    :effect (and
      (files_skipped_in_directory ?dest)
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

  (:action create_numbered_backup
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (backup_created ?f)
      (backup_type 'numbered')
    )
  )

  (:action create_simple_backup
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (backup_created ?f)
      (backup_type 'simple')
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
      (file_moved ?source ?dest)
      (file_overwritten ?dest)
    )
  )

  (:action interactive_move_file
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (file_exists ?dest)
    )
    :effect (and
      (file_moved ?source ?dest) OR (user_cancelled)
    )
  )

  (:action no_clobber_move_file
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
      (not (file_exists ?dest))
    )
    :effect (and
      (file_moved ?source ?dest) OR (move_skipped)
    )
  )

  (:action no_copy_on_rename_fail
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
    )
    :effect (and
      (rename_failed) OR (file_moved ?source ?dest)
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

  (:action copy_file_update
    :parameters (?src - file ?dest - file ?update - file)
    :precondition (and
      (file_exists ?src)
      (not (dest_is_directory ?dest))
    )
    :effect (and
      (file_updated ?src ?dest)
    )
  )

  (:action copy_file_no_target_directory
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (dest_is_directory ?dest))
    )
    :effect (and
      (file_copied ?src ?dest)
    )
  )

  (:action copy_file_strip_trailing_slashes
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (dest_is_directory ?dest))
    )
    :effect (and
      (file_copied ?src ?dest)
    )
  )

  (:action copy_file_suffix
    :parameters (?src - file ?dest - file ?suffix - file)
    :precondition (and
      (file_exists ?src)
      (not (dest_is_directory ?dest))
    )
    :effect (and
      (file_copied_with_suffix ?src ?dest)
    )
  )

  (:action copy_file_no_copy_on_rename_fail
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (not (dest_is_directory ?dest))
    )
    :effect (and
      (file_copied_or_not {src} {dest})
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
      (files_exist ?files)
      (dirs_exist ?dirs)
    )
    :effect (and
      (not (file_exists ?files))
      (not (directory_exists ?dirs))
    )
  )

  (:action remove_files_one_file_system
    :parameters (?files - file ?dirs - directory)
    :precondition (and
      (files_exist ?files)
      (dirs_exist ?dirs)
    )
    :effect (and
      (not (file_exists ?files))
      (not (directory_exists ?dirs))
    )
  )

  (:action remove_files_no_preserve_root
    :parameters (?actor - user ?files - file ?dirs - directory)
    :precondition (and
      (files_exist ?files)
      (dirs_exist ?dirs)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?files))
      (not (directory_exists ?dirs))
    )
  )

  (:action remove_files_preserve_root
    :parameters (?actor - user ?files - file ?dirs - directory)
    :precondition (and
      (files_exist ?files)
      (dirs_exist ?dirs)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?files))
      (not (directory_exists ?dirs))
    )
  )

  (:action remove_files_recursively
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (not (directory_exists ?dir))
    )
  )

  (:action remove_empty_directories
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (is_empty_directory ?dir)
    )
    :effect (and
      (not (directory_exists ?dir))
    )
  )

  (:action remove_files_verbose
    :parameters (?files - file ?dirs - directory)
    :precondition (and
      (files_exist ?files)
      (dirs_exist ?dirs)
    )
    :effect (and
      (not (file_exists ?files))
      (not (directory_exists ?dirs))
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
      (not (group_matches_user_effective_gid ?file))
      (not (user_has_privileges))
    )
    :effect (and
      (set_group_id_cleared ?file)
    )
  )

  (:action preserve_bits
    :parameters (?d - directory ?mode - file)
    :precondition (and
      (file_exists ?d)
      (is_directory ?d)
    )
    :effect (and
      (directory_preserve_bits ?d)
    )
  )

  (:action change_special_bits
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (special_bit_set ?f ?mode)
    )
  )

  (:action clear_special_bits_numeric_mode
    :parameters (?d - directory ?mode - file)
    :precondition (and
      (file_exists ?d)
      (is_directory ?d)
    )
    :effect (and
      (special_bit_cleared ?d)
    )
  )

  (:action set_sticky_bit
    :parameters (?d - directory ?mode - file)
    :precondition (and
      (file_exists ?d)
      (is_directory ?d)
    )
    :effect (and
      (sticky_bit_set ?d)
    )
  )

  (:action clear_sticky_bit
    :parameters (?d - directory ?mode - file)
    :precondition (and
      (file_exists ?d)
      (is_directory ?d)
    )
    :effect (and
      (sticky_bit_cleared ?d)
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
      (file_has_mode ?file (mode_of ?rfile))
    )
  )

  (:action recursive_change_mode
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (all_files_in_directory_have_mode ?dir ?mode)
    )
  )

  (:action copy_permissions
    :parameters (?src_file - file ?dst_file - file)
    :precondition (and
      (file_exists ?src_file)
      (file_exists ?dst_file)
    )
    :effect (and
      (file_has_mode ?dst_file (mode_of ?src_file))
    )
  )

  (:action recursive_change_permissions
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (all_files_in_directory_have_mode ?dir ?mode)
    )
  )

  (:action no_preserve_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (root_directory_treated_normally)
    )
  )

  (:action preserve_root
    :parameters (?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (all_files_in_directory_have_mode_except_root ?dir ?mode)
    )
  )

  (:action reference_mode_change
    :parameters (?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
    )
    :effect (and
      (file_has_same_mode_as_reference ?f ?rfile)
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

  (:action reference_owner_group
    :parameters (?actor - user ?rfile - file)
    :precondition (and
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (owner_and_group_from_reference_file ?rfile)
    )
  )

  (:action traverse_links
    :parameters (?obj - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (symbolic_links_traversed)
    )
  )

  (:action no_traverse_links
    :parameters (?obj - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (symbolic_links_not_traversed)
    )
  )

  (:action traverse_link_to_directory
    :parameters (?obj - file)
    :precondition (and
      (directory_exists ?dir)
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
      (files_in_directory_owned_by ?d ?owner)
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
      (same_owner_group_as ?f ?rfile)
    )
  )

  (:action preserve_root_directory
    :parameters (?obj - file)
    :precondition (and
      (directory_exists /)
    )
    :effect (and
      (root_directory_untouched /)
    )
  )

  (:action reference_ownership
    :parameters (?actor - user ?rfile - file ?f - file)
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

  (:action update_timestamps_no_create
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
    )
  )

  (:action update_timestamps_with_date
    :parameters (?date - file ?f - file)
    :precondition (and
      (file_exists ?f) | (not (file_exists ?f))
    )
    :effect (and
      (file_access_time_updated ?f)
      (file_modification_time_updated ?f)
    )
  )

  (:action update_timestamps_no_dereference
    :parameters (?f - file)
    :precondition (and
      (symlink_exists ?f)
    )
    :effect (and
      (symlink_access_time_updated ?f)
      (symlink_modification_time_updated ?f)
    )
  )

  (:action set_time_reference
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (time_set_to_file ?file)
    )
  )

  (:action set_time_stamp
    :parameters (?stamp - file)
    :precondition (and
      (valid_timestamp ?stamp)
    )
    :effect (and
      (timestamp_set_to ?stamp)
    )
  )

  (:action change_time_attribute
    :parameters (?attribute - file)
    :precondition (and
      (valid_time_attribute ?attribute)
    )
    :effect (and
      (time_attribute_set_to ?attribute)
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

  (:action create_file_if_not_exists
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f))
    )
    :effect (and
      (file_exists ?f)
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
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (file_accessed ?dst)
      (file_modified ?dst)
    )
  )

  (:action update_file_time_with_timestamp
    :parameters (?f - file ?stamp - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_accessed ?f)
      (file_modified ?f)
    )
  )

  (:action update_symlink_time
    :parameters (?link - file)
    :precondition (and
      (symlink_exists ?link)
    )
    :effect (and
      (symlink_accessed ?link)
      (symlink_modified ?link)
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

  (:action add_firewall_rule
    :parameters (?actor - user ?chain - firewall_rule ?rule_spec - firewall_rule)
    :precondition (and
      (table_exists ?t)
      (not (rule_exists_in_chain ?rulenum ?chain))
      (can_escalate ?actor)
    )
    :effect (and
      (rule_exists_in_chain ?rulenum ?chain)
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
      (table_exists ?t)
      (not (rule_exists_in_chain ?rulenum ?chain))
      (can_escalate ?actor)
    )
    :effect (and
      (rule_exists_in_chain ?rulenum ?chain)
    )
  )

  (:action replace_firewall_rule
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file ?rule_spec - firewall_rule)
    :precondition (and
      (table_exists ?t)
      (rule_exists_in_chain ?rulenum ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_exists_in_chain ?rulenum ?chain)
    )
  )

  (:action create_firewall_chain
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (table_exists ?t)
      (not (chain_exists ?chain))
      (can_escalate ?actor)
    )
    :effect (and
      (chain_exists ?chain)
    )
  )

  (:action delete_firewall_chain
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (table_exists ?t)
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (not (chain_exists ?chain))
    )
  )

  (:action set_default_policy
    :parameters (?actor - user ?chain - firewall_rule ?target - file)
    :precondition (and
      (table_exists ?t)
      (not (default_policy_set ?chain))
      (can_escalate ?actor)
    )
    :effect (and
      (default_policy_set ?chain)
    )
  )

  (:action rename_firewall_chain
    :parameters (?actor - user ?old_chain - firewall_rule ?new_chain - firewall_rule)
    :precondition (and
      (table_exists ?t)
      (chain_exists ?old_chain)
      (can_escalate ?actor)
    )
    :effect (and
      (not (chain_exists ?old_chain))
      (chain_exists ?new_chain)
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

  (:action return_chain
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (chain_exists ?current_chain)
      (rule_matched_in_current_chain)
      (can_escalate ?actor)
    )
    :effect (and
      (resume_previous_chain_processing)
    )
  )

  (:action select_table
    :parameters (?actor - user ?table - firewall_rule)
    :precondition (and
      (module_loaded ?table)
      (kernel_configured_for_autoload)
      (can_escalate ?actor)
    )
    :effect (and
      (current_table_set_to ?table)
    )
  )

  (:action process_packet
    :parameters (?actor - user ?packet - file ?chain - firewall_rule)
    :precondition (and
      (packet_arrived ?packet)
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_processed ?packet)
    )
  )

  (:action alter_packet_prerouting
    :parameters (?actor - user ?packet - file ?chain - firewall_rule)
    :precondition (and
      (packet_arrived ?packet)
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_altered ?packet)
    )
  )

  (:action alter_packet_input
    :parameters (?actor - user ?packet - file ?chain - firewall_rule)
    :precondition (and
      (packet_arrived ?packet)
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_altered ?packet)
    )
  )

  (:action alter_packet_output
    :parameters (?actor - user ?packet - file ?chain - firewall_rule)
    :precondition (and
      (packet_generated ?packet)
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_altered ?packet)
    )
  )

  (:action alter_packet_postrouting
    :parameters (?actor - user ?packet - file ?chain - firewall_rule)
    :precondition (and
      (packet_generated ?packet)
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_altered ?packet)
    )
  )

  (:action mangle_prerouting
    :parameters (?actor - user ?packet - file ?chain - firewall_rule)
    :precondition (and
      (packet_arrived ?packet)
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_altered ?packet)
    )
  )

  (:action mangle_output
    :parameters (?actor - user ?packet - file ?chain - firewall_rule)
    :precondition (and
      (packet_generated ?packet)
      (chain_exists ?chain)
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

  (:action enable_mandatory_access_control_rule
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
    :parameters (?actor - user ?chain - firewall_rule ?rule_specification - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_appended_to_chain ?chain ?rule_specification)
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

  (:action delete_empty_chains
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (table_exists ?t)
      (chain_is_empty ?c)
      (can_escalate ?actor)
    )
    :effect (and
      (not (chain_exists ?c))
    )
  )

  (:action set_policy
    :parameters (?actor - user ?chain - firewall_rule ?target - firewall_rule)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (chain_policy_set ?chain ?target)
    )
  )

  (:action rename_chain
    :parameters (?actor - user ?old_chain - firewall_rule ?new_chain - firewall_rule)
    :precondition (and
      (chain_exists ?old_chain)
      (not (chain_exists ?new_chain))
      (can_escalate ?actor)
    )
    :effect (and
      (not (chain_exists ?old_chain))
      (chain_exists ?new_chain)
    )
  )

  (:action insert_rule
    :parameters (?actor - user ?rule - firewall_rule ?ipv6_flag - file)
    :precondition (and
      (file_exists ?rules_file)
      (not (rule_applied ?rule))
      (can_escalate ?actor)
    )
    :effect (and
      (rule_applied ?rule)
    )
  )

  (:action invert_out_interface_rule
    :parameters (?actor - user ?interface - interface ?rule - firewall_rule)
    :precondition (and
      (not (rule_applied ?rule))
      (interface_exists ?interface)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_applied ?rule)
      (out_interface_inverted ?interface)
    )
  )

  (:action set_counters
    :parameters (?actor - user ?packets - file ?bytes - file)
    :precondition (and
      (rule_exists ?r)
      (can_escalate ?actor)
    )
    :effect (and
      (counter_packets_set ?r)
      (counter_bytes_set ?r)
    )
  )

  (:action set_input_interface
    :parameters (?actor - user ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (input_interface_set ?iface)
    )
  )

  (:action set_output_interface
    :parameters (?actor - user ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (output_interface_set ?iface)
    )
  )

  (:action enable_masquerading
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (nat_table_available)
      (can_escalate ?actor)
    )
    :effect (and
      (masquerade_enabled)
    )
  )

  (:action delete_matching_rule_from_chain
    :parameters (?actor - user ?chain - firewall_rule ?rule_specification - file)
    :precondition (and
      (rule_exists_in_chain ?chain ?rule_specification)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_deleted_from_chain ?chain ?rule_specification)
    )
  )

  (:action delete_rule_by_number_from_chain
    :parameters (?actor - user ?chain - firewall_rule ?rule_num - file)
    :precondition (and
      (rule_exists_in_chain ?chain ?rule_num)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_deleted_from_chain ?chain ?rule_num)
    )
  )

  (:action insert_rule_into_chain
    :parameters (?actor - user ?chain - firewall_rule ?rule_specification - file ?rulenum - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_inserted_into_chain ?chain ?rulenum ?rule_specification)
    )
  )

  (:action replace_rule_in_chain
    :parameters (?actor - user ?chain - firewall_rule ?rule_num - file ?new_rule - file)
    :precondition (and
      (rule_exists_in_chain ?chain ?rule_num)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_replaced_in_chain ?chain ?rule_num ?new_rule)
    )
  )

  (:action delete_rules
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (rules_exist ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (not (rules_exist ?chain))
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
    :parameters (?actor - user ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_added_to_chain_jump_no_return ?chain)
    )
  )

  (:action add_firewall_rule_out_interface
    :parameters (?actor - user ?interface - interface)
    :precondition (and
      (interface_exists ?interface)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_added_to_chain_with_interface ?interface)
    )
  )

  (:action set_firewall_rule_counters
    :parameters (?actor - user ?pkts - file ?bytes - file)
    :precondition (and
      (rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (counters_set_for_rule ?pkts ?bytes)
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
    :parameters (?proto - file)
    :precondition (and
      (command_line_valid)
    )
    :effect (and
      (protocol_family_set ?proto)
    )
  )

  (:action switch_network_namespace
    :parameters (?actor - user ?netns - file)
    :precondition (and
      (namespace_exists ?netns)
      (can_escalate ?actor)
    )
    :effect (and
      (current_namespace_set ?netns)
    )
  )

  (:action execute_command_in_network_namespace
    :parameters (?actor - user ?netns - file ?cmd - file)
    :precondition (and
      (namespace_exists ?netns)
      (command_valid ?cmd)
      (can_escalate ?actor)
    )
    :effect (and
      (command_executed_in_namespace ?cmd ?netns)
    )
  )

  (:action execute_command_in_network_namespace_short_form
    :parameters (?actor - user ?netns - file ?cmd - file)
    :precondition (and
      (namespace_exists ?netns)
      (command_valid ?cmd)
      (can_escalate ?actor)
    )
    :effect (and
      (command_executed_in_namespace ?cmd ?netns)
    )
  )

  (:action configure_color_output
    :parameters (?color_mode - file)
    :precondition (and
      (stdout_is_terminal) or (color_mode=always)
    )
    :effect (and
      (output_colored ?color_mode)
    )
  )

  (:action bring_up_interface
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

  (:action bring_down_interface
    :parameters (?actor - user ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (interface_up ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (not (interface_up ?iface))
    )
  )

  (:action execute_ip_command
    :parameters (?obj - file ?cmd - file)
    :precondition (and
      (object_valid ?obj)
      (command_valid ?cmd)
    )
    :effect (and
      (system_state_modified)
    )
  )

  (:action execute_ip_batch_commands
    :parameters (?filename - file)
    :precondition (and
      (file_exists ?filename)
      (file_readable ?filename)
    )
    :effect (and
      (system_state_modified)
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

  (:action apply_filter_file
    :parameters (?actor - user ?filter_file - file)
    :precondition (and
      (file_exists ?filter_file)
      (can_escalate ?actor)
    )
    :effect (and
      (filters_applied_from_file ?filter_file)
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
      (filter_applied ?file)
    )
  )

  (:action suppress_header_line
    :parameters (?obj - file)
    :precondition (and
      (output_exists)
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

  (:action switch_user
    :parameters (?user - user)
    :precondition (and
      (not (current_user ?user))
    )
    :effect (and
      (current_user ?user)
    )
  )

  (:action switch_to_root
    :parameters (?obj - file)
    :precondition (and
      (not (current_user 'root'))
    )
    :effect (and
      (current_user 'root')
    )
  )

  (:action switch_and_run_command
    :parameters (?user - user ?cmd - process)
    :precondition (and
      (not (current_user ?user))
    )
    :effect (and
      (command_executed_by ?cmd ?user)
    )
  )

  (:action run_command_as_user
    :parameters (?cmd - process ?user - user)
    :precondition (and
      (command_exists ?cmd)
      (user_exists ?user)
    )
    :effect (and
      (process_running_as_user ?cmd
      ?user)
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

  (:action reset_resource_limits
    :parameters (?obj - file)
    :precondition (and
      (process_running)
    )
    :effect (and
      (resource_limit_reset RLIMIT_NICE)
      (resource_limit_reset RLIMIT_RTPRIO)
      (resource_limit_reset RLIMIT_FSIZE)
      (resource_limit_reset RLIMIT_AS)
      (resource_limit_reset RLIMIT_NOFILE)
    )
  )

  (:action execute_command_with_shell
    :parameters (?cmd - process)
    :precondition (and
      (command_exists ?cmd)
    )
    :effect (and
      (process_running ?cmd)
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

  (:action set_primary_group
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
      (shell_running_as_user ?user)
      (environment_initialized_for_user ?user)
    )
  )

  (:action preserve_environment
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (environment_preserved_for_user ?user)
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
      (self_terminated_with_signal ?sig)
    )
  )

  (:action terminate_child_process
    :parameters (?p - process)
    :precondition (and
      (child_exists ?p)
      (not (child_terminated ?p))
    )
    :effect (and
      (child_terminated ?p)
    )
  )

  (:action change_user_id
    :parameters (?user - user ?group - group ?supplemental_group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
    )
    :effect (and
      (effective_user_id ?user)
      (primary_group_id ?group)
    )
  )

  (:action login_shell
    :parameters (?user - user)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (shell_login_mode true)
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

  (:action change_shell
    :parameters (?shell - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (shell_allowed_by_etc_shells ?shell)
    )
    :effect (and
      (effective_shell ?shell)
    )
  )

  (:action create_pseudo_terminal
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (pseudo_terminal_created true)
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
    :parameters (?actor - user ?login - user)
    :precondition (and
      (not (user_exists ?login))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?login)
      (home_directory_created ?dir)
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

  (:action set_user_home_directory
    :parameters (?actor - user ?user - user ?home_dir - directory)
    :precondition (and
      (user_exists ?user)
      (directory_exists ?home_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (user_home_set ?user ?home_dir)
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

  (:action create_group_for_user
    :parameters (?actor - user ?username - user ?groupname - group)
    :precondition (and
      (not (group_exists ?groupname))
      (USERGROUPS_ENAB=yes)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?groupname)
      (user_in_group ?username ?groupname)
    )
  )

  (:action add_user_to_groups
    :parameters (?actor - user ?username - user ?groups - file)
    :precondition (and
      (user_exists ?username)
      (all_groups_exist ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_group ?username ?g) for each group ?g in ?groups
    )
  )

  (:action create_user_with_home
    :parameters (?actor - user ?username - user ?SKEL_DIR - directory)
    :precondition (and
      (not (user_exists ?username))
      (directory_exists ?SKEL_DIR)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?username)
      (home_directory_created ?username)
    )
  )

  (:action override_login_defs_defaults
    :parameters (?actor - user ?KEY - file ?VALUE - file)
    :precondition (and
      (file_exists /etc/login.defs)
      (can_escalate ?actor)
    )
    :effect (and
      (login_def_overridden ?KEY ?VALUE)
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
      (not (directory_exists /home/{user}))
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
      (uid_exists ?uid)
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action set_initial_password
    :parameters (?actor - user ?password - file ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (user_has_password ?user))
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
      (no_home_directory ?user)
      (system_user ?user)
    )
  )

  (:action add_user_with_home_dir
    :parameters (?actor - user ?user - user ?home_directory - directory)
    :precondition (and
      (not (user_exists ?user))
      (directory_exists ?home_directory)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (has_home_directory ?user ?home_directory)
    )
  )

  (:action update_subid_files_for_user
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
    :parameters (?actor - user ?prefix_dir - directory ?user - user)
    :precondition (and
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_prefix ?prefix_dir)
    )
  )

  (:action set_user_shell
    :parameters (?actor - user ?shell - file ?user - user)
    :precondition (and
      (file_exists ?shell)
      (user_exists ?user)
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
    :parameters (?actor - user ?uid - file ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (unique_uid ?uid)
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

  (:action set_default_values
    :parameters (?actor - user ?option - file)
    :precondition (and
      (useradd_command_exists)
      (valid_option ?option)
      (can_escalate ?actor)
    )
    :effect (and
      (default_value_set ?option
      ?value)
    )
  )

  (:action batch_create_users
    :parameters (?actor - user ?file - file)
    :precondition (and
      (file_exists ?file)
      (all_lines_valid_user_entries ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists_all_entries ?file)
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
    :parameters (?actor - user ?group - group ?members - file)
    :precondition (and
      (group_exists ?group)
      (members_exceed_limit ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (new_group_entry_created ?group)
    )
  )

  (:action enforce_password_change
    :parameters (?actor - user ?user - user)
    :precondition (and
      (password_expired ?user)
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

  (:action modify_default_user_settings
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_configurable)
      (can_escalate ?actor)
    )
    :effect (and
      (default_user_settings_modified)
    )
  )

  (:action set_base_directory_for_home
    :parameters (?actor - user ?base_dir - directory)
    :precondition (and
      (not (directory_exists ?base_dir)) or (is_writable ?base_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (base_directory_set ?base_dir)
    )
  )

  (:action set_home_directory
    :parameters (?actor - user ?home_dir - directory)
    :precondition (and
      (not (directory_exists ?home_dir)) or (is_writable ?home_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_set ?home_dir)
    )
  )

  (:action set_account_expiration_date
    :parameters (?actor - user ?expire_date - file)
    :precondition (and
      (account_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (account_expires_on ?expire_date)
    )
  )

  (:action set_password_inactivity_period
    :parameters (?actor - user ?inactivity - file)
    :precondition (and
      (account_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (password_inactive_after ?inactivity)
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

  (:action create_non_unique_users
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (unique_user ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (non_unique_user_created ?user)
    )
  )

  (:action add_system_user
    :parameters (?actor - user ?user - user ?uid - file ?password - file ?shell - file ?user_group - file ?selinux_user - file ?chroot_dir - directory ?prefix_dir - directory)
    :precondition (and
      (not (user_exists ?user))
      (valid_uid ?uid)
      (shell_exists ?shell)
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

  (:action chroot_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (chrooted_into ?dir)
    )
  )

  (:action set_prefix_directory
    :parameters (?actor - user ?prefix_dir - directory)
    :precondition (and
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (prefix_set ?prefix_dir)
    )
  )

  (:action set_selinux_user_mapping
    :parameters (?actor - user ?seuser - file ?user - user)
    :precondition (and
      (not (selinux_user_mapped ?user))
      (valid_seuser ?seuser)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_user_mapped ?user
      ?seuser)
    )
  )

  (:action use_extra_users_database
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (extra_users_db_available)
      (can_escalate ?actor)
    )
    :effect (and
      (using_extra_users_db)
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
      (account_modified ?login)
    )
  )

  (:action update_comment_field
    :parameters (?actor - user ?login - user ?comment - file)
    :precondition (and
      (user_exists ?login)
      (can_escalate ?actor)
    )
    :effect (and
      (comment_updated ?login ?comment)
    )
  )

  (:action change_home_directory
    :parameters (?actor - user ?login - user ?home_dir - directory)
    :precondition (and
      (user_exists ?login)
      (can_escalate ?actor)
    )
    :effect (and
      (new_home_directory_set ?login ?home_dir)
    )
  )

  (:action move_home_directory
    :parameters (?actor - user ?login - user ?home_dir - directory)
    :precondition (and
      (user_exists ?login)
      (directory_exists ?home_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (moved_home_directory ?login ?home_dir)
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

  (:action modify_user
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (ownership_adapted ?f)
      (modes_copied ?f)
      (acl_copied ?f)
      (extended_attributes_copied ?f)
    )
  )

  (:action set_non_unique_uid
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_exists ?u)
      (not (unique_uid ?uid))
      (can_escalate ?actor)
    )
    :effect (and
      (non_unique_uid_set ?u)
    )
  )

  (:action set_password
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (password_set ?u)
    )
  )

  (:action remove_user_from_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (user_exists ?user)
      (group_exists ?group)
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
    :parameters (?actor - user ?user - user ?date - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_expire_date_set ?user ?date)
    )
  )

  (:action add_subordinate_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_range_added ?user {first}-{last})
    )
  )

  (:action remove_subordinate_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (subuid_range_exists ?user {first}-{last})
      (can_escalate ?actor)
    )
    :effect (and
      (subuid_range_removed ?user {first}-{last})
    )
  )

  (:action add_subordinate_gids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subgid_range_added ?user {first}-{last})
    )
  )

  (:action remove_subordinate_gids
    :parameters (?actor - user ?user - user ?first_gid - file ?last_gid - file)
    :precondition (and
      (user_exists ?user)
      (subordinate_gids_exist ?user ?first_gid ?last_gid)
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
      (encrypted_password_set ?user ?password)
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

  (:action set_login_name
    :parameters (?actor - user ?old_user - user ?new_login - file)
    :precondition (and
      (user_exists ?old_user)
      (can_escalate ?actor)
    )
    :effect (and
      (login_name_changed ?old_user ?new_login)
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

  (:action unlock_account
    :parameters (?actor - user ?user - user)
    :precondition (and
      (account_locked ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (account_locked ?user))
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
      (not (directory_exists /home/{user}))
      (not (file_exists /var/mail/{user}))
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
      (directory_exists /home/{user})
      (file_exists {mail_spool})
      (can_escalate ?actor)
    )
    :effect (and
      (not (directory_exists /home/{user}))
      (not (file_exists {mail_spool}))
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
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?usr))
      (not (group_exists ?usr))
    )
  )

  (:action delete_group_if_unused
    :parameters (?actor - user ?grp - group ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (not (primary_group_used_by_other_user ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?grp))
    )
  )

  (:action delete_group_force
    :parameters (?actor - user ?grp - group ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?grp))
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

  (:action delete_group
    :parameters (?actor - user ?grp - group)
    :precondition (and
      (group_exists ?grp)
      (not (user_in_group ?u ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?grp))
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
      (group_defaults_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (group_default_set ?key
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

)