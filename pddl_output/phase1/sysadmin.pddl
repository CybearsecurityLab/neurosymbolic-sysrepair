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
    (package_reverted ?x0 - object)
    (file_modified ?x0 - object)
    (option_modified ?x0 - object)
    (packages_upgraded)
    (system_upgraded)
    (packages_installed)
    (unnecessary_packages_removed)
    (cache_exists)
    (cache_cleared)
    (obsolete_cache_cleared)
    (package_exists ?x0 - object)
    (build_dependencies_installed ?x0 - object)
    (source_downloaded ?x0 - object)
    (package_downloaded ?x0 - object)
    (package_missing ?x0 - object)
    (download_disabled)
    (quiet_mode_enabled)
    (host_architecture_set ?x0 - object)
    (build_profiles_active ?x0 - object)
    (package_compiled ?x0 - object)
    (package_on_hold ?x0 - object)
    (cleaned_apt_lists)
    (snapshot_available ?x0 - object)
    (selected_snapshot ?x0 - object)
    (apt_default_release_set ?x0 - object)
    (apt_trivial_only_enabled)
    (package_auto_marked ?x0 - object)
    (abort_on_remove ?x0 - object)
    (unused_dependencies_removed ?x0 - object)
    (apt_get_only-source)
    (apt_get_diff-only)
    (apt_get_dsc-only)
    (apt_get_tar-only)
    (apt_get_arch-only)
    (apt_get_indep-only)
    (apt_get_allow-unauthenticated)
    (allow_insecure_repositories)
    (allow_releaseinfo_change)
    (source_file_added ?x0 - object)
    (error_on_any_enabled)
    (update_run_before_command)
    (config_file_used ?x0 - object)
    (configuration_loaded ?x0 - object)
    (apt_config_set ?x0 - object)
    (config_option_set ?x0 - object)
    (color_setting ?x0 - object)
    (file_executable ?x0 - object)
    (directory_exists ?x0 - object)
    (apt_state_directory_configured ?x0 - object)
    (apt_partial_state_directory_configured ?x0 - object)
    (package_lists_updated)
    (package_enabled ?x0 - object)
    (symbolic_link_exists ?x0 - object)
    (file_symlinked ?x0 - object ?x1 - object)
    (filesystem_boundary_respected ?x0 - object ?x1 - object)
    (selinux_context_set ?x0 - object)
    (security_context_set ?x0 - object ?x1 - object)
    (file_sparse ?x0 - object)
    (files_replaced ?x0 - object)
    (files_skipped ?x0 - object)
    (files_replaced_if_older ?x0 - object)
    (file_reflinked ?x0 - object)
    (same_name ?x0 - object ?x1 - object)
    (file_backed_up ?x0 - object)
    (file_contents_copied ?x0 - object ?x1 - object)
    (symlink_followed ?x0 - object ?x1 - object)
    (hard_link_created ?x0 - object ?x1 - object)
    (symlink_dereferenced ?x0 - object ?x1 - object)
    (backup_suffix_set ?x0 - object)
    (file_copied_to_directory ?x0 - object ?x1 - object)
    (file_update_controlled ?x0 - object)
    (selinux_context_set_custom ?x0 - object ?x1 - object)
    (files_not_replaced ?x0 - object ?x1 - object)
    (skipped_files_fail ?x0 - object ?x1 - object)
    (reflink_supported)
    (files_reflinked ?x0 - object ?x1 - object)
    (files_copied_standard ?x0 - object ?x1 - object)
    (version_control_set ?x0 - object)
    (file_in_directory ?x0 - object ?x1 - object)
    (backup_disabled)
    (backup_method_numbered)
    (backup_method_existing)
    (backup_method_simple)
    (update_mode_set ?x0 - object)
    (interactive_prompted ?x0 - object)
    (count_files ?x0 - object ?x1 - object)
    (interactive_prompted_once ?x0 - object)
    (valid_when ?x0 - object)
    (different_filesystem ?x0 - object)
    (skipped_directory ?x0 - object)
    (root_not_special ?x0 - object)
    (file)
    (root_preserved ?x0 - object)
    (directory_removed ?x0 - object)
    (directory_empty ?x0 - object)
    (dir_equals_root ?x0 - object)
    (separate_device ?x0 - object)
    (when_in_never_once_always ?x0 - object)
    (prompted_interactive ?x0 - object)
    (prompted_always ?x0 - object)
    (prompted_once ?x0 - object)
    (file_owner ?x0 - object ?x1 - object)
    (file_group ?x0 - object ?x1 - object)
    (file_ownership_changed ?x0 - object)
    (root_not_preserved ?x0 - object)
    (symlinks_traversed ?x0 - object)
    (symlinks_not_traversed ?x0 - object)
    (ownership_referenced ?x0 - object ?x1 - object)
    (file_mode_changed ?x0 - object)
    (user_has_privileges)
    (file_group_id_mismatch ?x0 - object)
    (setgid_bit_cleared ?x0 - object)
    (suid_bit_preserved ?x0 - object)
    (sgid_bit_preserved ?x0 - object)
    (suid_bit_cleared ?x0 - object)
    (sgid_bit_cleared ?x0 - object)
    (root_preservation_disabled)
    (root_preservation_enabled)
    (file_mode_referenced ?x0 - object)
    (permissions_changed_recursively ?x0 - object)
    (hierarchy_traversed ?x0 - object)
    (all_links_traversed ?x0 - object)
    (symbolic_links_skipped ?x0 - object)
    (file_traversed ?x0 - object)
    (file_not_traversed ?x0 - object)
    (file_access_time_updated ?x0 - object)
    (file_modification_time_updated ?x0 - object)
    (file_timestamp_changed ?x0 - object)
    (time_type_valid ?x0 - object)
    (protocol_family_set ?x0 - object)
    (output_oneline)
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
    (firewall_chain_exists ?x0 - object)
    (firewall_rule_added ?x0 - object ?x1 - object ?x2 - object)
    (packet_accepted ?x0 - object ?x1 - object)
    (packet_dropped ?x0 - object ?x1 - object)
    (chain_returned)
    (connection_tracking_exempt ?x0 - object)
    (netfilter_hook_registered ?x0 - object)
    (mandatory_access_control_enabled ?x0 - object)
    (firewall_rule_flushed ?x0 - object)
    (firewall_rule_counters_zeroed ?x0 - object)
    (firewall_rule_referenced ?x0 - object)
    (chain_empty ?x0 - object)
    (table_exists)
    (all_chains_empty)
    (valid_policy ?x0 - object)
    (chain_policy_set ?x0 - object ?x1 - object)
    (chain_renamed ?x0 - object ?x1 - object)
    (protocol_allowed ?x0 - object)
    (protocol_inverted ?x0 - object)
    (network_mask_set ?x0 - object)
    (address_sense_inverted ?x0 - object)
    (match_extension_specified ?x0 - object)
    (packet_processed ?x0 - object)
    (packet_filtering_rule_set ?x0 - object)
    (lock_obtained)
    (lock_exists)
    (numeric_output_enabled)
    (command_equals)
    (exact_output_enabled)
    (listing_rules)
    (line_numbers_enabled)
    (modprobe_command_set ?x0 - object)
    (module_loaded ?x0 - object)
    (iptables_setuid_to_root)
    (iptables_exit_code_111)
    (rule_exists ?x0 - object ?x1 - object)
    (firewall_rule_removed ?x0 - object)
    (firewall_rule_empty ?x0 - object)
    (firewall_rule_policy_changed ?x0 - object ?x1 - object)
    (target_loaded ?x0 - object)
    (chain_loaded ?x0 - object)
    (match_loaded ?x0 - object)
    (output_interface_set ?x0 - object)
    (table_set ?x0 - object)
    (wait_time_set ?x0 - object)
    (exact_values_enabled)
    (fragment_matching_enabled)
    (modules_inserted ?x0 - object)
    (command_executed ?x0 - object)
    (session_record_exists)
    (user_primary_group ?x0 - object ?x1 - object)
    (login_shell_running ?x0 - object)
    (session_cache_removed ?x0 - object)
    (session_timestamp_reset ?x0 - object)
    (user_is_root ?x0 - object)
    (temp_file_exists ?x0 - object)
    (temp_file_owner ?x0 - object ?x1 - object)
    (temp_file_edited ?x0 - object)
    (file_device_special ?x0 - object)
    (file_edited ?x0 - object)
    (command_executed_as_user ?x0 - object)
    (sudo_timestamp_refreshed)
    (file_edited_as_user ?x0 - object ?x1 - object)
    (directory_changed ?x0 - object)
    (login_shell_set ?x0 - object)
    (environment_preserved ?x0 - object)
    (pty_created ?x0 - object)
    (environment_reset ?x0 - object)
    (process_terminated ?x0 - object)
    (lastlog_updated ?x0 - object)
    (default_user_info_updated)
    (user_comment_set ?x0 - object)
    (user_expiration_set ?x0 - object)
    (user_in_group ?x0 - object ?x1 - object)
    (password_aging_disabled ?x0 - object)
    (log_init_skipped ?x0 - object)
    (home_directory_exists ?x0 - object)
    (user_group_exists ?x0 - object)
    (uid_exists ?x0 - object)
    (user_with_uid ?x0 - object ?x1 - object)
    (configuration_applied ?x0 - object)
    (uid_set ?x0 - object)
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
    (usergroups_ena_set ?x0 - object)
    (hook_executed ?x0 - object)
    (group_file_updated ?x0 - object)
    (selinux_user_mapping_updated ?x0 - object)
    (subid_entries_added ?x0 - object)
    (no_user_group_created ?x0 - object)
    (user_supplementary_groups ?x0 - object ?x1 - object)
    (user_home_directory ?x0 - object ?x1 - object)
    (file_ownership_adapted ?x0 - object)
    (user_id_non_unique ?x0 - object)
    (user_password_changed ?x0 - object)
    (user_shell_set ?x0 - object ?x1 - object)
    (user_not_in_group ?x0 - object ?x1 - object)
    (changes_applied_in_chroot ?x0 - object)
    (changes_applied_in_prefix ?x0 - object)
    (user_uid_set ?x0 - object ?x1 - object)
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
    (subordinate_group_ids_allocated ?x0 - object)
    (subordinate_gids_allocated ?x0 - object)
    (user_has_bad_name ?x0 - object)
    (user_gecos ?x0 - object ?x1 - object)
    (user_password_inactive ?x0 - object ?x1 - object)
    (user_groups_set ?x0 - object ?x1 - object)
    (user_login_changed ?x0 - object ?x1 - object)
    (gid_used ?x0 - object)
    (group_password_set ?x0 - object)
    (group_operation_in_chroot ?x0 - object ?x1 - object)
    (group_split ?x0 - object)
    (nis_group_exists ?x0 - object)
    (ldap_group_exists ?x0 - object)
    (selinux_user_mapping_removed ?x0 - object)
    (group_members_count ?x0 - object ?x1 - object)
    (at_job_exists ?x0 - object)
    (print_job_exists ?x0 - object)
    (chrooted ?x0 - object)
    (prefix_set ?x0 - object)
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
      (not (package_installed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
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

  (:action why_not_package
    :parameters (?pkg - package)
    :precondition (and
      (package_installed ?pkg)
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

  (:action change_default_options
    :parameters (?option - file)
    :precondition (and
      (file_exists ?option)
    )
    :effect (and
      (option_modified ?option)
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
      (package_installed ?pkg)
      (not (package_outdated ?pkg))
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

  (:action satisfy_dependency
    :parameters (?actor - user ?dep - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?dep)
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

  (:action download_only
    :parameters (?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (network_available)
    )
    :effect (and
      (package_downloaded ?pkg)
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

  (:action hold_back_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (package_outdated ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?pkg)
    )
  )

  (:action disable_download
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (download_disabled)
    )
  )

  (:action quiet_mode
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (quiet_mode_enabled)
    )
  )

  (:action set_host_architecture
    :parameters (?actor - user ?arch - directory)
    :precondition (and
      (not (host_architecture_set ?arch))
      (can_escalate ?actor)
    )
    :effect (and
      (host_architecture_set ?arch)
    )
  )

  (:action activate_build_profiles
    :parameters (?actor - user ?profiles - directory)
    :precondition (and
      (not (build_profiles_active ?profiles))
      (can_escalate ?actor)
    )
    :effect (and
      (build_profiles_active ?profiles)
    )
  )

  (:action compile_source
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_compiled ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_compiled ?pkg)
    )
  )

  (:action ignore_holds
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_on_hold ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_on_hold ?pkg)
    )
  )

  (:action allow_new_packages
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_outdated ?pkg)
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
      (package_installed ?pkg)
    )
  )

  (:action only_upgrade
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_outdated ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action allow_downgrades
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action cleanup_apt_lists
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (cleaned_apt_lists)
    )
  )

  (:action select_snapshot
    :parameters (?actor - user ?snapshot - file)
    :precondition (and
      (snapshot_available ?snapshot)
      (can_escalate ?actor)
    )
    :effect (and
      (selected_snapshot ?snapshot)
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

  (:action set_only_source
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (apt_get_only-source)
    )
  )

  (:action download_diff_only
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_get_diff-only)
    )
  )

  (:action download_dsc_only
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_get_dsc-only)
    )
  )

  (:action download_tar_only
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_get_tar-only)
    )
  )

  (:action process_arch_only
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_get_arch-only)
    )
  )

  (:action process_indep_only
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_get_indep-only)
    )
  )

  (:action allow_unauthenticated
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_get_allow-unauthenticated)
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

  (:action use_config_file
    :parameters (?config - file)
    :precondition (and
      (file_exists ?config)
    )
    :effect (and
      (config_file_used ?config)
    )
  )

  (:action read_default_config
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (configuration_loaded ?f)
    )
  )

  (:action set_apt_config
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (apt_config_set ?f)
    )
  )

  (:action set_config_option
    :parameters (?option - file)
    :precondition (and
      (file_exists ?option)
    )
    :effect (and
      (config_option_set ?option)
    )
  )

  (:action toggle_color
    :parameters (?state - file)
    :precondition (and
      (file_exists ?state)
    )
    :effect (and
      (color_setting ?state)
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
    :parameters (?actor - user ?fragment - file)
    :precondition (and
      (file_exists ?fragment)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?fragment)
    )
  )

  (:action configure_apt_preferences
    :parameters (?actor - user ?pref - file)
    :precondition (and
      (file_exists ?pref)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?pref)
    )
  )

  (:action configure_apt_preferences_fragments
    :parameters (?actor - user ?pref_fragment - file)
    :precondition (and
      (file_exists ?pref_fragment)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?pref_fragment)
    )
  )

  (:action cache_apt_archives
    :parameters (?actor - user ?archive - file)
    :precondition (and
      (file_exists ?archive)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?archive)
    )
  )

  (:action cache_apt_archives_partial
    :parameters (?actor - user ?partial_archive - file)
    :precondition (and
      (file_exists ?partial_archive)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?partial_archive)
    )
  )

  (:action cache_apt_lists
    :parameters (?actor - user ?list - file)
    :precondition (and
      (file_exists ?list)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?list)
    )
  )

  (:action configure_apt_state_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_state_directory_configured ?dir)
    )
  )

  (:action configure_apt_partial_state_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (apt_partial_state_directory_configured ?dir)
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
    )
    :effect (and
      (file_exists ?sources)
    )
  )

  (:action copy_file_to_directory
    :parameters (?source - file ?directory - directory)
    :precondition (and
      (directory_exists ?directory)
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

  (:action skip_files
    :parameters (?dest - directory ?source - directory)
    :precondition (and
      (directory_exists ?dest)
      (directory_exists ?source)
    )
    :effect (and
      (files_skipped ?dest)
    )
  )

  (:action replace_older_files
    :parameters (?dest - directory ?source - directory)
    :precondition (and
      (directory_exists ?dest)
      (directory_exists ?source)
    )
    :effect (and
      (files_replaced_if_older ?dest)
    )
  )

  (:action lightweight_copy
    :parameters (?dest - file ?source - file)
    :precondition (and
      (file_exists ?source)
    )
    :effect (and
      (file_reflinked ?dest)
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
      (file_exists ?dst)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action make_backup
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (file_exists ?dst~)
    )
  )

  (:action make_numbered_backup
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (file_exists ?dst.1)
    )
  )

  (:action make_simple_backup
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
    )
    :effect (and
      (file_exists ?dst~)
    )
  )

  (:action make_backup_force
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dst)
      (same_name ?src ?dst)
    )
    :effect (and
      (file_exists ?dst~)
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

  (:action rename_file
    :parameters (?source - file ?dest - file)
    :precondition (and
      (file_exists ?source)
    )
    :effect (and
      (file_exists ?dest)
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
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
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

  (:action prompt_according_to_when
    :parameters (?file - file ?when - file)
    :precondition (and
      (file_exists ?file)
      (valid_when ?when)
    )
    :effect (and
      (interactive_prompted ?file)
    )
  )

  (:action skip_different_filesystem
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (different_filesystem ?dir)
    )
    :effect (and
      (skipped_directory ?dir)
    )
  )

  (:action do_not_treat_root_special
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (root_not_special ?file)
    )
  )

  (:action do_not_remove_root
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
      (file)
    )
    :effect (and
      (root_preserved ?file)
    )
  )

  (:action remove_recursively
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_removed ?dir)
    )
  )

  (:action remove_empty_directories
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

  (:action remove_directory_recursively
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
      (directory_empty ?dir)
    )
    :effect (and
      (not (directory_exists ?dir))
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

  (:action change_group_only
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
      (can_escalate ?actor)
    )
    :effect (and
      (file_ownership_changed ?f)
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

  (:action use_reference_ownership
    :parameters (?actor - user ?f - file ?ref - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?ref)
      (can_escalate ?actor)
    )
    :effect (and
      (file_ownership_changed ?f)
    )
  )

  (:action recursive_ownership_change
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_ownership_changed ?f)
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

  (:action reference_ownership
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (ownership_referenced ?f ?rfile)
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
      (file_mode_changed ?f)
    )
  )

  (:action set_file_mode
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action clear_setgid_bit
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (not (user_has_privileges))
      (file_group_id_mismatch ?f)
    )
    :effect (and
      (setgid_bit_cleared ?f)
    )
  )

  (:action preserve_suid_sgid_bits
    :parameters (?d - directory)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (suid_bit_preserved ?d)
      (sgid_bit_preserved ?d)
    )
  )

  (:action clear_suid_sgid_bits_numeric
    :parameters (?d - directory)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (suid_bit_cleared ?d)
      (sgid_bit_cleared ?d)
    )
  )

  (:action dereference_symbolic_link
    :parameters (?link - file)
    :precondition (and
      (file_exists ?link)
    )
    :effect (and
      (file_modified ?link)
    )
  )

  (:action modify_symbolic_link
    :parameters (?link - file)
    :precondition (and
      (file_exists ?link)
    )
    :effect (and
      (file_modified ?link)
    )
  )

  (:action disable_root_preservation
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (root_preservation_disabled)
    )
  )

  (:action enable_root_preservation
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (root_preservation_enabled)
    )
  )

  (:action reference_file_mode
    :parameters (?rfile - file)
    :precondition (and
      (file_exists ?rfile)
    )
    :effect (and
      (file_mode_referenced ?rfile)
    )
  )

  (:action recursive_permission_change
    :parameters (?path - directory)
    :precondition (and
      (directory_exists ?path)
    )
    :effect (and
      (permissions_changed_recursively ?path)
    )
  )

  (:action traverse_symbolic_link_hierarchy
    :parameters (?link - file)
    :precondition (and
      (file_exists ?link)
    )
    :effect (and
      (hierarchy_traversed ?link)
    )
  )

  (:action traverse_all_symbolic_links
    :parameters (?link - file)
    :precondition (and
      (file_exists ?link)
    )
    :effect (and
      (all_links_traversed ?link)
    )
  )

  (:action skip_symbolic_links
    :parameters (?link - file)
    :precondition (and
      (file_exists ?link)
    )
    :effect (and
      (symbolic_links_skipped ?link)
    )
  )

  (:action change_mode
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_mode_changed ?f ?mode)
    )
  )

  (:action change_mode_reference
    :parameters (?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
    )
    :effect (and
      (file_mode_changed ?f ?rfile)
    )
  )

  (:action change_mode_recursive
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_mode_changed ?f ?mode)
    )
  )

  (:action traverse_symbolic_links
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_traversed ?f)
    )
  )

  (:action do_not_traverse_symbolic_links
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_not_traversed ?f)
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
      (output_oneline)
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
    :parameters (?actor - user ?table - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_configured ?table)
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
    :parameters (?actor - user ?table - firewall_rule ?chain - firewall_rule ?target - firewall_rule)
    :precondition (and
      (firewall_table_defined ?table)
      (firewall_chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_added ?table ?chain ?target)
    )
  )

  (:action accept_packet
    :parameters (?actor - user ?table - firewall_rule ?chain - firewall_rule)
    :precondition (and
      (firewall_table_defined ?table)
      (firewall_chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_accepted ?table ?chain)
    )
  )

  (:action drop_packet
    :parameters (?actor - user ?table - firewall_rule ?chain - firewall_rule)
    :precondition (and
      (firewall_table_defined ?table)
      (firewall_chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_dropped ?table ?chain)
    )
  )

  (:action return_from_chain
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (chain_returned)
    )
  )

  (:action configure_connection_tracking_exemption
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?rule)
      (can_escalate ?actor)
    )
    :effect (and
      (connection_tracking_exempt ?rule)
    )
  )

  (:action register_netfilter_hook
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (netfilter_hook_registered ?chain)
    )
  )

  (:action configure_mandatory_access_control
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?rule)
      (can_escalate ?actor)
    )
    :effect (and
      (mandatory_access_control_enabled ?rule)
    )
  )

  (:action append_iptables_rule
    :parameters (?actor - user ?chain - firewall_rule ?rule_spec - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_modified ?chain)
    )
  )

  (:action delete_iptables_rule
    :parameters (?actor - user ?chain - file ?rule_spec - file)
    :precondition (and
      (firewall_rule_exists ?rule_spec)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_deleted ?rule_spec)
    )
  )

  (:action insert_iptables_rule
    :parameters (?actor - user ?chain - file ?rulenum - file ?rule_spec - file)
    :precondition (and
      (firewall_rule_exists ?rule_spec)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_inserted ?rule_spec)
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

  (:action delete_referring_rules
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (not (chain_empty ?chain))
      (can_escalate ?actor)
    )
    :effect (and
      (chain_empty ?chain)
    )
  )

  (:action delete_empty_chains
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (table_exists)
      (can_escalate ?actor)
    )
    :effect (and
      (all_chains_empty)
    )
  )

  (:action set_chain_policy
    :parameters (?actor - user ?chain - firewall_rule ?target - file)
    :precondition (and
      (firewall_rule_exists ?chain)
      (valid_policy ?target)
      (can_escalate ?actor)
    )
    :effect (and
      (chain_policy_set ?chain ?target)
    )
  )

  (:action rename_chain
    :parameters (?actor - user ?old_chain - firewall_rule ?new_chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?old_chain)
      (can_escalate ?actor)
    )
    :effect (and
      (chain_renamed ?old_chain ?new_chain)
    )
  )

  (:action insert_rule_with_ipv4_option
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (not (traffic_blocked ?rule))
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action insert_rule_with_ipv6_option
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (not (traffic_blocked ?rule))
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action set_rule_protocol
    :parameters (?actor - user ?rule - firewall_rule ?protocol - file)
    :precondition (and
      (not (traffic_blocked ?rule))
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action set_protocol
    :parameters (?actor - user ?protocol - file)
    :precondition (and
      (file_exists ?protocol)
      (can_escalate ?actor)
    )
    :effect (and
      (protocol_allowed ?protocol)
    )
  )

  (:action invert_protocol_test
    :parameters (?actor - user ?protocol - file)
    :precondition (and
      (protocol_allowed ?protocol)
      (can_escalate ?actor)
    )
    :effect (and
      (protocol_inverted ?protocol)
    )
  )

  (:action match_all_protocols
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (protocol_allowed ?all)
    )
  )

  (:action set_network_mask
    :parameters (?actor - user ?mask - file)
    :precondition (and
      (file_exists ?mask)
      (can_escalate ?actor)
    )
    :effect (and
      (network_mask_set ?mask)
    )
  )

  (:action invert_address_sense
    :parameters (?actor - user ?address - file)
    :precondition (and
      (file_exists ?address)
      (can_escalate ?actor)
    )
    :effect (and
      (address_sense_inverted ?address)
    )
  )

  (:action specify_match_extension
    :parameters (?actor - user ?match - file)
    :precondition (and
      (file_exists ?match)
      (can_escalate ?actor)
    )
    :effect (and
      (match_extension_specified ?match)
    )
  )

  (:action jump_target
    :parameters (?actor - user ?target - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (packet_processed ?target)
    )
  )

  (:action goto_chain
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (packet_processed ?chain)
    )
  )

  (:action set_in_interface
    :parameters (?actor - user ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_filtering_rule_set ?iface)
    )
  )

  (:action set_out_interface
    :parameters (?actor - user ?iface - interface)
    :precondition (and
      (interface_exists ?iface)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_filtering_rule_set ?iface)
    )
  )

  (:action match_fragmented_packets
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action match_head_fragments
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action set_counters
    :parameters (?actor - user ?rule - firewall_rule ?packets - file ?bytes - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?rule)
    )
  )

  (:action obtain_lock
    :parameters (?actor - user ?seconds - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (lock_obtained)
    )
  )

  (:action wait_for_lock
    :parameters (?seconds - file)
    :precondition (and
      (lock_exists)
      (not (lock_obtained))
    )
    :effect (and
      (lock_obtained)
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

  (:action exact_output
    :parameters (?obj - file)
    :precondition (and
      (command_equals)
    )
    :effect (and
      (exact_output_enabled)
    )
  )

  (:action add_line_numbers
    :parameters (?obj - file)
    :precondition (and
      (listing_rules)
    )
    :effect (and
      (line_numbers_enabled)
    )
  )

  (:action set_modprobe_command
    :parameters (?command - file)
    :precondition (and
    )
    :effect (and
      (modprobe_command_set ?command)
    )
  )

  (:action load_iptables_modules
    :parameters (?actor - user ?module - file)
    :precondition (and
      (file_exists ?module)
      (can_escalate ?actor)
    )
    :effect (and
      (module_loaded ?module)
    )
  )

  (:action iptables_setuid_error
    :parameters (?obj - file)
    :precondition (and
      (iptables_setuid_to_root)
    )
    :effect (and
      (iptables_exit_code_111)
    )
  )

  (:action delete_iptables_rule_by_num
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file)
    :precondition (and
      (firewall_rule_exists ?chain)
      (rule_exists ?chain ?rulenum)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_removed ?chain)
    )
  )

  (:action replace_iptables_rule
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file)
    :precondition (and
      (firewall_rule_exists ?chain)
      (rule_exists ?chain ?rulenum)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_modified ?chain)
    )
  )

  (:action flush_rules
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_empty ?chain)
    )
  )

  (:action change_policy
    :parameters (?actor - user ?chain - firewall_rule ?target - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (firewall_rule_exists ?target)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_policy_changed ?chain ?target)
    )
  )

  (:action jump_to_target
    :parameters (?actor - user ?target - file)
    :precondition (and
      (file_exists ?target)
      (can_escalate ?actor)
    )
    :effect (and
      (target_loaded ?target)
    )
  )

  (:action jump_to_chain
    :parameters (?actor - user ?chain - file)
    :precondition (and
      (file_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (chain_loaded ?chain)
    )
  )

  (:action extended_match
    :parameters (?actor - user ?match - file)
    :precondition (and
      (file_exists ?match)
      (can_escalate ?actor)
    )
    :effect (and
      (match_loaded ?match)
    )
  )

  (:action set_output_interface
    :parameters (?actor - user ?interface - interface)
    :precondition (and
      (interface_exists ?interface)
      (can_escalate ?actor)
    )
    :effect (and
      (output_interface_set ?interface)
    )
  )

  (:action set_table
    :parameters (?actor - user ?table - file)
    :precondition (and
      (file_exists ?table)
      (can_escalate ?actor)
    )
    :effect (and
      (table_set ?table)
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

  (:action expand_numbers
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (exact_values_enabled)
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
      (file_exists ?command)
      (can_escalate ?actor)
    )
    :effect (and
      (modules_inserted ?command)
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

  (:action edit_files
    :parameters (?actor - user ?file - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (file_modified ?file)
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
      (directory_changed ?user)
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
      (default_user_info_updated)
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

  (:action create_user_default_home
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
    )
  )

  (:action set_user_comment
    :parameters (?actor - user ?user - user ?comment - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_comment_set ?user)
    )
  )

  (:action set_user_expiration
    :parameters (?actor - user ?user - user ?expire_date - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_expiration_set ?user)
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
    )
  )

  (:action create_user_with_default_group
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
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
      (user_exists ?user)
      (uid_exists ?uid)
      (can_escalate ?actor)
    )
    :effect (and
      (user_with_uid ?user ?uid)
    )
  )

  (:action set_password
    :parameters (?actor - user ?user - user ?password - file)
    :precondition (and
      (user_exists ?user)
      (user_locked ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_locked ?user))
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
      (user_locked ?user)
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
      (uid_set ?uid)
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

  (:action set_uid_range
    :parameters (?actor - user ?min - file ?max - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (uid_min_set ?min)
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

  (:action set_usergroups_ena
    :parameters (?actor - user ?enabled - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (usergroups_ena_set ?enabled)
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

  (:action update_group_file
    :parameters (?actor - user ?group - group)
    :precondition (and
      (group_exists ?group)
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

  (:action add_subids_for_system
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subid_entries_added ?user)
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

  (:action set_password_grace_period
    :parameters (?actor - user ?user - user ?days - file)
    :precondition (and
      (user_exists ?user)
      (file_exists ?days)
      (can_escalate ?actor)
    )
    :effect (and
      (user_locked ?user)
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

  (:action change_username
    :parameters (?actor - user ?old_login - user ?new_login - user)
    :precondition (and
      (user_exists ?old_login)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?new_login)
      (not (user_exists ?old_login))
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

  (:action change_user_shell
    :parameters (?actor - user ?user - user ?shell - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_shell_set ?user ?shell)
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
      (user_not_in_group ?user ?group)
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

  (:action change_user_uid
    :parameters (?actor - user ?user - user ?uid - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_uid_set ?user ?uid)
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

  (:action create_group_entry
    :parameters (?actor - user ?group - group)
    :precondition (and
      (not (group_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
    )
  )

  (:action allocate_subordinate_group_ids
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (subordinate_group_ids_allocated ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_group_ids_allocated ?user)
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
    :parameters (?actor - user ?g - group ?pwd - file)
    :precondition (and
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (group_password_set ?g)
    )
  )

  (:action chroot_group_operation
    :parameters (?actor - user ?g - group ?chroot - directory)
    :precondition (and
      (directory_exists ?chroot)
      (can_escalate ?actor)
    )
    :effect (and
      (group_operation_in_chroot ?g ?chroot)
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

  (:action delete_files_manually
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f))
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
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (print_job_exists ?user))
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

  (:action set_prefix
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