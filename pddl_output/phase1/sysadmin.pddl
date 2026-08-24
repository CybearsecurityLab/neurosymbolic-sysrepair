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
    (package_reverted ?x0 - object)
    (package_cache_exists)
    (package_hold_exists ?x0 - object)
    (package_marked_auto ?x0 - object)
    (package_authentication_ignored)
    (insecure_repositories_allowed)
    (package_enabled ?x0 - object)
    (package_on_hold ?x0 - object)
    (architecture_added ?x0 - object)
    (architecture_allowed ?x0 - object)
    (architecture_in_use ?x0 - object)
    (file_diverted ?x0 - object)
    (stat_override_exists ?x0 - object)
    (mac_security_applied ?x0 - object)
    (io_synced ?x0 - object)
    (filesystem_nodelalloc_enabled ?x0 - object)
    (dpkg_debug_enabled ?x0 - object)
    (dpkg_force_enabled ?x0 - object)
    (dpkg_admin_dir_set ?x0 - object)
    (dpkg_frontend_locked)
    (dpkg_passwd_path_set ?x0 - object)
    (dpkg_group_path_set ?x0 - object)
    (admin_dir_set ?x0 - object)
    (install_dir_set ?x0 - object)
    (pre_invoke_hook_set ?x0 - object)
    (post_invoke_hook_set ?x0 - object)
    (assertion_added ?x0 - object)
    (assertion_valid ?x0 - object)
    (assertion_signature_verified ?x0 - object)
    (assertion_in_database ?x0 - object)
    (snap_aliased ?x0 - object ?x1 - object)
    (snap_connected ?x0 - object ?x1 - object)
    (cohort_key_exists ?x0 - object)
    (interface_connected ?x0 - object ?x1 - object)
    (connection_state_remembered ?x0 - object)
    (package_confined ?x0 - object)
    (package_aliased ?x0 - object)
    (package_aliases_preferred ?x0 - object)
    (package_in_cohort ?x0 - object ?x1 - object)
    (package_in_quota_group ?x0 - object ?x1 - object)
    (snap_authenticated ?x0 - object)
    (system_warnings_exist)
    (directory_exists ?x0 - object)
    (snap_package_created ?x0 - object)
    (snap_metadata_valid ?x0 - object)
    (system_in_run_mode)
    (system_in_install_mode)
    (system_in_recover_mode)
    (system_in_factory_reset_mode)
    (snap_refresh_held ?x0 - object)
    (package_refresh_held ?x0 - object)
    (snap_devmode_enabled ?x0 - object)
    (snap_confined ?x0 - object)
    (snap_classic_mode ?x0 - object)
    (snap_in_cohort ?x0 - object)
    (device_remodeled ?x0 - object)
    (has_subgroups ?x0 - object)
    (snapshot_saved ?x0 - object ?x1 - object)
    (snapshot_created ?x0 - object)
    (memory_limit_increased ?x0 - object)
    (cpu_limit_set ?x0 - object)
    (cpu_limit_modified ?x0 - object)
    (threads_limit_increased ?x0 - object)
    (journal_limit_modified ?x0 - object)
    (quota_set ?x0 - object)
    (file_signed ?x0 - object)
    (validation_set_enforced ?x0 - object)
    (validation_set_monitored ?x0 - object)
    (service_has_persistent_state ?x0 - object)
    (service_has_runtime_data ?x0 - object)
    (service_frozen ?x0 - object)
    (service_log_target_set ?x0 - object ?x1 - object)
    (service_linked ?x0 - object)
    (service_masked ?x0 - object)
    (env_variable_set ?x0 - object)
    (env_variable_imported ?x0 - object)
    (manager_log_level_set ?x0 - object)
    (manager_log_target_set ?x0 - object)
    (service_watchdogs_enabled ?x0 - object)
    (system_mode_default)
    (system_mode_rescue)
    (system_mode_emergency)
    (system_halted)
    (file_executable ?x0 - object)
    (system_sleeping)
    (system_suspended)
    (system_hibernated)
    (system_hibernating)
    (pending_job_exists ?x0 - object)
    (job_irreversible ?x0 - object)
    (job_queued)
    (inhibitor_lock_active ?x0 - object)
    (firmware_setup_pending)
    (boot_loader_menu_pending)
    (boot_entry_selected ?x0 - object)
    (system_rebooting_with_arg ?x0 - object)
    (pager_secure_mode_enabled ?x0 - object)
    (pager_active ?x0 - object)
    (unit_path_bound ?x0 - object ?x1 - object)
    (unit_image_mounted ?x0 - object ?x1 - object)
    (service_log_target_configured ?x0 - object)
    (service_marked ?x0 - object)
    (fss_keys_setup ?x0 - object)
    (fss_keys_recreated ?x0 - object)
    (file_archived ?x0 - object)
    (journal_synced ?x0 - object)
    (journal_writing_to_var ?x0 - object)
    (journal_on_root_mount ?x0 - object)
    (journal_logs_flushed ?x0 - object)
    (logs_flushed_to_disk ?x0 - object)
    (journal_files_rotated ?x0 - object)
    (catalog_index_updated)
    (log_time_enabled ?x0 - object)
    (log_location_enabled ?x0 - object)
    (log_tid_enabled ?x0 - object)
    (pager_secure_enabled ?x0 - object)
    (systemd_colors_enabled ?x0 - object)
    (systemd_urlify_enabled ?x0 - object)
    (journal_rotated)
    (catalog_updated)
    (fss_keys_generated)
    (file_has_default_selinux_context ?x0 - object)
    (file_has_security_context ?x0 - object ?x1 - object)
    (file_is_sparse ?x0 - object)
    (file_reflinked ?x0 - object)
    (selinux_context_default ?x0 - object)
    (file_special_bits_set ?x0 - object)
    (file_sticky_bit_set ?x0 - object)
    (file_group_owned_by ?x0 - object ?x1 - object)
    (file_timestamp_updated ?x0 - object)
    (chain_exists ?x0 - object)
    (chain_policy_set ?x0 - object)
    (counters_zeroed ?x0 - object)
    (chain_has_rules ?x0 - object)
    (rule_counters_initialized ?x0 - object)
    (file_locked ?x0 - object)
    (session_timestamp_exists ?x0 - object)
    (file_modified ?x0 - object)
    (timestamp_invalidated ?x0 - object)
    (user_password_aging ?x0 - object)
    (user_logged_init ?x0 - object)
    (user_has_subids ?x0 - object)
    (user_comment_updated ?x0 - object)
    (user_home_directory ?x0 - object ?x1 - object)
    (user_modified ?x0 - object)
    (user_shell_changed ?x0 - object)
    (user_uid_changed ?x0 - object)
    (user_has_subuids ?x0 - object)
    (selinux_user_mapped ?x0 - object ?x1 - object)
    (selinux_range_defined ?x0 - object)
    (user_has_sub_gids ?x0 - object)
    (selinux_mapping_exists ?x0 - object)
    (user_has_cron_jobs ?x0 - object)
    (user_has_at_jobs ?x0 - object)
    (process_running_by_user ?x0 - object)
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

  (:action upgrade_packages
    :parameters (?actor - user ?obj - file ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?pkg))
    )
  )

  (:action dist_upgrade_packages
    :parameters (?actor - user ?obj - file ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?pkg))
    )
  )

  (:action autoremove_packages
    :parameters (?actor - user ?obj - file ?pkg - package)
    :precondition (and
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

  (:action upgrade_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_outdated ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?pkg))
    )
  )

  (:action dist_upgrade_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_outdated ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?pkg))
    )
  )

  (:action dselect_upgrade
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_outdated ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?pkg))
    )
  )

  (:action downgrade_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?pkg)
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

  (:action fetch_source_package
    :parameters (?pkg - package ?pkg_source - package)
    :precondition (and
      (network_available)
      (not (package_installed ?pkg))
    )
    :effect (and
      (file_exists ?pkg_source)
    )
  )

  (:action compile_source_package
    :parameters (?pkg - package ?pkg_source - package)
    :precondition (and
      (file_exists ?pkg_source)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action install_build_dependencies
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action download_package
    :parameters (?pkg - package ?pkg_file - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (file_exists ?pkg_file)
    )
  )

  (:action clean_package_cache
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_cache_exists))
    )
  )

  (:action apt_autoclean
    :parameters (?actor - user ?obj - file ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?pkg))
    )
  )

  (:action apt_distclean
    :parameters (?actor - user ?obj - file ?f - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action apt_autoremove
    :parameters (?actor - user ?obj - file ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action autoremove_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action autopurge_package
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

  (:action fix_broken_dependencies
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

  (:action disable_package_download
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (not (network_available))
    )
  )

  (:action ignore_package_holds
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_hold_exists ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_hold_exists ?pkg))
    )
  )

  (:action upgrade_with_new_pkgs
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

  (:action install_no_upgrade
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action remove_essential_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action mark_package_auto
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_marked_auto ?pkg)
    )
  )

  (:action allow_unauthenticated
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_authentication_ignored)
    )
  )

  (:action allow_insecure_repositories
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (insecure_repositories_allowed)
    )
  )

  (:action allow_releaseinfo_change
    :parameters (?actor - user ?repo - repository)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?repo)
    )
  )

  (:action update_package_lists
    :parameters (?actor - user ?obj - file ?p - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?p))
    )
  )

  (:action dist_upgrade
    :parameters (?actor - user ?obj - file ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?pkg))
    )
  )

  (:action clean_archives
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_clean_archives)
    )
  )

  (:action full_upgrade_packages
    :parameters (?actor - user ?obj - file ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?pkg))
    )
  )

  (:action mark_package_manual
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_enabled ?pkg)
    )
  )

  (:action edit_sources
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (file_writable ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?f)
    )
  )

  (:action update_package_list
    :parameters (?actor - user ?obj - file ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_outdated ?pkg))
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

  (:action hold_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_on_hold ?pkg)
    )
  )

  (:action deinstall_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action execute_prerm_script
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?pkg)
    )
  )

  (:action execute_preinst_script
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_enabled ?pkg)
    )
  )

  (:action unpack_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action execute_postrm_script
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action process_triggers
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action configure_pending_packages
    :parameters (?actor - user ?obj - file ?p - package)
    :precondition (and
      (package_outdated ?p)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?p)
    )
  )

  (:action run_postrm_script
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action update_package_availability
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (package_enabled ?f)
    )
  )

  (:action merge_package_availability
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (package_enabled ?f)
    )
  )

  (:action update_available_packages
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?f)
    )
  )

  (:action record_available_packages
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?f)
    )
  )

  (:action dselect_update
    :parameters (?actor - user ?obj - file ?p - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?p)
    )
  )

  (:action clear_available_packages
    :parameters (?actor - user ?obj - file ?p - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_configured ?p))
    )
  )

  (:action set_package_selections
    :parameters (?actor - user ?f - file ?p - package)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?p)
    )
  )

  (:action clear_package_selections
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action add_architecture
    :parameters (?actor - user ?arch - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (architecture_added ?arch)
    )
  )

  (:action remove_architecture
    :parameters (?actor - user ?arch - file)
    :precondition (and
      (architecture_allowed ?arch)
      (not (architecture_in_use ?arch))
      (can_escalate ?actor)
    )
    :effect (and
      (not (architecture_allowed ?arch))
    )
  )

  (:action build_deb_package
    :parameters (?dir - directory ?pkg - package)
    :precondition (and
      (file_exists ?dir)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action extract_control_info
    :parameters (?archive - file ?dir - directory)
    :precondition (and
      (file_exists ?archive)
      (not (file_exists ?dir))
    )
    :effect (and
      (file_exists ?dir)
    )
  )

  (:action extract_package_files
    :parameters (?archive - file ?dir - directory)
    :precondition (and
      (file_exists ?archive)
    )
    :effect (and
      (file_exists ?dir)
    )
  )

  (:action auto_deconfigure_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_configured ?pkg))
    )
  )

  (:action deconfigure_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_configured ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_configured ?pkg))
    )
  )

  (:action force_downgrade_package
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

  (:action force_package_action
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_on_hold ?pkg))
    )
  )

  (:action remove_reinstreq_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action remove_protected_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action force_install_break
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action force_install_conflict
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action install_missing_conffile
    :parameters (?actor - user ?f - file ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (file_exists ?f))
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action install_new_conffile
    :parameters (?actor - user ?f - file ?pkg - package)
    :precondition (and
      (file_exists ?f)
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
      (not (requires_env_preservation ?f))
    )
  )

  (:action keep_old_conffile
    :parameters (?actor - user ?f - file ?pkg - package)
    :precondition (and
      (file_exists ?f)
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action choose_default_conffile_action
    :parameters (?actor - user ?f - file ?pkg - package)
    :precondition (and
      (file_exists ?f)
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action overwrite_package_file
    :parameters (?actor - user ?f1 - file ?f2 - file)
    :precondition (and
      (file_exists ?f1)
      (file_exists ?f2)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f1))
      (file_exists ?f2)
    )
  )

  (:action overwrite_package_directory
    :parameters (?actor - user ?d - directory ?f - file)
    :precondition (and
      (file_exists ?d)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?d))
      (file_exists ?f)
    )
  )

  (:action overwrite_diverted_file
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (file_diverted ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_diverted ?f))
    )
  )

  (:action statoverride_add
    :parameters (?actor - user ?f - file ?u - user ?g - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (stat_override_exists ?f)
    )
  )

  (:action statoverride_remove
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (not (stat_override_exists ?f))
    )
  )

  (:action install_files_with_mac
    :parameters (?actor - user ?f - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
      (mac_security_applied ?f)
    )
  )

  (:action unpack_with_safe_io
    :parameters (?actor - user ?f - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
      (io_synced ?f)
    )
  )

  (:action mount_nodelalloc
    :parameters (?actor - user ?i - interface)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (filesystem_nodelalloc_enabled ?i)
    )
  )

  (:action install_package_ignore_verify
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action install_package_ignore_depends
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action install_package_ignore_arch
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action install_package_ignore_version
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action set_installation_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (file_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?dir)
    )
  )

  (:action set_root_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (file_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?dir)
    )
  )

  (:action dpkg_install
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (package_installed ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action filter_package_unpack
    :parameters (?actor - user ?pkg - package ?f - file)
    :precondition (and
      (package_installed ?pkg)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action set_dpkg_debug_mask
    :parameters (?mask - file)
    :precondition (and
    )
    :effect (and
      (dpkg_debug_enabled ?mask)
    )
  )

  (:action set_dpkg_force_flags
    :parameters (?flags - file)
    :precondition (and
    )
    :effect (and
      (dpkg_force_enabled ?flags)
    )
  )

  (:action set_dpkg_admin_dir
    :parameters (?dir - directory)
    :precondition (and
      (file_exists ?dir)
    )
    :effect (and
      (dpkg_admin_dir_set ?dir)
    )
  )

  (:action lock_dpkg_frontend
    :parameters (?lock - file)
    :precondition (and
    )
    :effect (and
      (dpkg_frontend_locked)
    )
  )

  (:action set_dpkg_passwd_path
    :parameters (?path - file)
    :precondition (and
      (file_exists ?path)
    )
    :effect (and
      (dpkg_passwd_path_set ?path)
    )
  )

  (:action set_dpkg_group_path
    :parameters (?path - file)
    :precondition (and
      (file_exists ?path)
    )
    :effect (and
      (dpkg_group_path_set ?path)
    )
  )

  (:action unpack_package_objects
    :parameters (?actor - user ?pkg - package ?f - file)
    :precondition (and
      (package_installed ?pkg)
      (not (file_exists ?f))
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action backup_filesystem_object
    :parameters (?actor - user ?f - file ?f_tmp - package)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f_tmp)
    )
  )

  (:action backup_modified_conffile
    :parameters (?actor - user ?f - file ?f_backup - package)
    :precondition (and
      (file_exists ?f)
      (file_writable ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f_backup)
    )
  )

  (:action backup_unmodified_conffile
    :parameters (?actor - user ?f - file ?f_backup - package)
    :precondition (and
      (file_exists ?f)
      (file_writable ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f_backup)
    )
  )

  (:action restore_backup
    :parameters (?actor - user ?f_backup - file ?f - file)
    :precondition (and
      (file_exists ?f_backup)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
      (not (file_exists ?f_backup))
    )
  )

  (:action remove_backups
    :parameters (?actor - user ?f_backup - file)
    :precondition (and
      (file_exists ?f_backup)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f_backup))
    )
  )

  (:action install_package_from_file
    :parameters (?actor - user ?pkg - package ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action backup_package_selections
    :parameters (?f - file)
    :precondition (and
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action merge_available_packages
    :parameters (?actor - user ?obj - file ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action dpkg_unpack
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?f)
    )
  )

  (:action dpkg_configure
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

  (:action dpkg_remove
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action dpkg_purge
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action clear_available_info
    :parameters (?actor - user ?obj - file ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_configured ?pkg))
    )
  )

  (:action forget_old_unavailable
    :parameters (?actor - user ?obj - file ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action set_admin_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (file_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (admin_dir_set ?dir)
    )
  )

  (:action set_install_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (file_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (install_dir_set ?dir)
    )
  )

  (:action set_pre_invoke_hook
    :parameters (?actor - user ?cmd - process)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (pre_invoke_hook_set ?cmd)
    )
  )

  (:action set_post_invoke_hook
    :parameters (?actor - user ?cmd - process)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (post_invoke_hook_set ?cmd)
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

  (:action snap_install
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

  (:action snap_configure
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action snap_refresh
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

  (:action snap_remove
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action snap_abort
    :parameters (?actor - user ?id - process)
    :precondition (and
      (process_running ?id)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?id))
    )
  )

  (:action snap_ack
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (assertion_added ?f)
    )
  )

  (:action add_assertion
    :parameters (?actor - user ?a - file)
    :precondition (and
      (file_exists ?a)
      (assertion_valid ?a)
      (assertion_signature_verified ?a)
      (can_escalate ?actor)
    )
    :effect (and
      (assertion_in_database ?a)
    )
  )

  (:action set_snap_alias
    :parameters (?actor - user ?snap - package ?alias - file)
    :precondition (and
      (package_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_aliased ?snap ?alias)
    )
  )

  (:action snap_connect
    :parameters (?actor - user ?plug_snap - package ?slot_snap - package)
    :precondition (and
      (package_installed ?plug_snap)
      (package_installed ?slot_snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_connected ?plug_snap ?slot_snap)
    )
  )

  (:action snap_create_cohort
    :parameters (?actor - user ?snap - package)
    :precondition (and
      (package_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?snap)
    )
  )

  (:action create_cohort
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (cohort_key_exists ?pkg)
    )
  )

  (:action migrate_snap_home
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (file_exists ?file_snap_home)
    )
  )

  (:action disconnect_snap_interface
    :parameters (?actor - user ?plug - interface ?slot - interface)
    :precondition (and
      (interface_exists ?plug)
      (interface_exists ?slot)
      (interface_connected ?plug ?slot)
      (can_escalate ?actor)
    )
    :effect (and
      (not (interface_connected ?plug ?slot))
    )
  )

  (:action disconnect_snap_connection
    :parameters (?actor - user ?conn - service)
    :precondition (and
      (service_running ?conn)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?conn))
      (connection_state_remembered ?conn)
    )
  )

  (:action disconnect_snap_connection_forget
    :parameters (?actor - user ?conn - service)
    :precondition (and
      (service_running ?conn)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?conn))
      (not (connection_state_remembered ?conn))
    )
  )

  (:action download_snap
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (file_exists ?pkg)
    )
  )

  (:action export_key
    :parameters (?pkg - package ?f - file)
    :precondition (and
      (package_installed ?pkg)
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action export_snapshot
    :parameters (?f - file)
    :precondition (and
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action forget_snapshot
    :parameters (?actor - user ?snap_id - file)
    :precondition (and
      (file_exists ?snap_id)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?snap_id))
    )
  )

  (:action import_snapshot
    :parameters (?actor - user ?snap - package)
    :precondition (and
      (not (package_installed ?snap))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?snap)
    )
  )

  (:action set_snap_classic_mode
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_confined ?pkg))
    )
  )

  (:action install_snap_revision
    :parameters (?actor - user ?pkg - package ?rev - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action install_dangerous_snap
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?f)
    )
  )

  (:action install_snap_unaliased
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (not (package_aliased ?pkg))
    )
  )

  (:action install_snap_prefer
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_aliases_preferred ?pkg)
    )
  )

  (:action install_snap_named
    :parameters (?actor - user ?f - file ?name - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?name)
    )
  )

  (:action install_snap_cohort
    :parameters (?actor - user ?pkg - package ?cohort - group)
    :precondition (and
      (network_available)
      (group_exists ?cohort)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_in_cohort ?pkg ?cohort)
    )
  )

  (:action install_snap_quota
    :parameters (?actor - user ?pkg - package ?qg - group)
    :precondition (and
      (network_available)
      (group_exists ?qg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_in_quota_group ?pkg ?qg)
    )
  )

  (:action snap_login
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
      (network_available)
    )
    :effect (and
      (snap_authenticated ?u)
      (file_exists ?file_snap_auth_json)
    )
  )

  (:action snap_logout
    :parameters (?u - user)
    :precondition (and
      (snap_authenticated ?u)
    )
    :effect (and
      (not (snap_authenticated ?u))
    )
  )

  (:action acknowledge_warnings
    :parameters (?obj - file)
    :precondition (and
      (system_warnings_exist)
    )
    :effect (and
      (not (system_warnings_exist))
    )
  )

  (:action pack_snap
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (snap_package_created ?dir)
    )
  )

  (:action snap_pack
    :parameters (?snap_dir - directory ?target_dir - directory ?snap_file - file)
    :precondition (and
      (file_exists ?snap_dir)
    )
    :effect (and
      (file_exists ?snap_file)
    )
  )

  (:action snap_check_skeleton
    :parameters (?snap_dir - directory)
    :precondition (and
      (file_exists ?snap_dir)
    )
    :effect (and
      (snap_metadata_valid ?snap_dir)
    )
  )

  (:action snap_prefer
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_enabled ?pkg)
    )
  )

  (:action snap_prepare_image
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action install_snap_component
    :parameters (?actor - user ?snap - package ?comp - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?comp)
    )
  )

  (:action reboot_system
    :parameters (?actor - user ?sys - service ?pr - package)
    :precondition (and
      (service_exists ?sys)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?pr))
    )
  )

  (:action reboot_run_mode
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_in_run_mode)
    )
  )

  (:action reboot_install_mode
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_in_install_mode)
    )
  )

  (:action reboot_recover_mode
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_in_recover_mode)
    )
  )

  (:action reboot_factory_reset_mode
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_in_factory_reset_mode)
    )
  )

  (:action hold_snap_refresh
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_refresh_held ?pkg)
    )
  )

  (:action snap_refresh_hold
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_refresh_held ?pkg)
    )
  )

  (:action install_snap_edge
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action install_snap_beta
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action install_snap_candidate
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action install_snap_stable
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action set_snap_devmode
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_devmode_enabled ?pkg)
      (not (snap_confined ?pkg))
    )
  )

  (:action set_snap_jailmode
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_confined ?pkg)
    )
  )

  (:action set_snap_classic
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_classic_mode ?pkg)
      (not (snap_confined ?pkg))
    )
  )

  (:action refresh_snap_revision
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

  (:action refresh_snap_cohort
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_in_cohort ?pkg)
    )
  )

  (:action leave_snap_cohort
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (not (snap_in_cohort ?pkg))
    )
  )

  (:action hold_refresh
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_refresh_held ?pkg)
    )
  )

  (:action unhold_refresh
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_refresh_held ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_refresh_held ?pkg))
    )
  )

  (:action remodel_device
    :parameters (?actor - user ?dev - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (device_remodeled ?dev)
    )
  )

  (:action remove_snap_revision
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?pkg)
    )
  )

  (:action purge_snap
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_installed ?pkg))
    )
  )

  (:action terminate_snap_processes
    :parameters (?actor - user ?pkg - package ?pr - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?pr))
    )
  )

  (:action remove_quota_group
    :parameters (?actor - user ?g - group)
    :precondition (and
      (group_exists ?g)
      (not (has_subgroups ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?g))
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

  (:action restore_snapshot
    :parameters (?actor - user ?snap - package)
    :precondition (and
      (package_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?snap)
    )
  )

  (:action restore_snap_snapshot
    :parameters (?actor - user ?snap - package ?snapshot - file)
    :precondition (and
      (package_installed ?snap)
      (file_exists ?snapshot)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?snap)
      (not (package_outdated ?snap))
    )
  )

  (:action revert_snap_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?pkg)
    )
  )

  (:action run_snap_command
    :parameters (?pkg - package ?cmd - process)
    :precondition (and
      (package_installed ?pkg)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action save_snap_snapshot
    :parameters (?actor - user ?s - service ?u - user)
    :precondition (and
      (service_exists ?s)
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (snapshot_saved ?s ?u)
    )
  )

  (:action snap_save
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (snapshot_created ?u)
    )
  )

  (:action snap_set_config
    :parameters (?s - service ?f - file)
    :precondition (and
      (service_exists ?s)
    )
    :effect (and
      (config_applied ?s)
    )
  )

  (:action set_snap_config
    :parameters (?actor - user ?s - service ?f - file)
    :precondition (and
      (service_exists ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?s)
    )
  )

  (:action unset_snap_config
    :parameters (?actor - user ?s - service ?f - file)
    :precondition (and
      (service_exists ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (not (config_applied ?s))
    )
  )

  (:action set_quota_group
    :parameters (?actor - user ?g - group ?s - service)
    :precondition (and
      (group_exists ?g)
      (service_exists ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of ?s ?g)
    )
  )

  (:action remove_subgroup_from_quota
    :parameters (?actor - user ?sg - group)
    :precondition (and
      (group_exists ?sg)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?sg))
    )
  )

  (:action place_service_in_subgroup
    :parameters (?actor - user ?s - service ?sg - group)
    :precondition (and
      (service_exists ?s)
      (group_exists ?sg)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of ?s ?sg)
    )
  )

  (:action increase_memory_limit
    :parameters (?actor - user ?qg - group)
    :precondition (and
      (group_exists ?qg)
      (can_escalate ?actor)
    )
    :effect (and
      (memory_limit_increased ?qg)
    )
  )

  (:action create_quota_group
    :parameters (?actor - user ?qg - group)
    :precondition (and
      (not (group_exists ?qg))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?qg)
    )
  )

  (:action set_cpu_limit
    :parameters (?actor - user ?qg - group)
    :precondition (and
      (group_exists ?qg)
      (can_escalate ?actor)
    )
    :effect (and
      (cpu_limit_set ?qg)
    )
  )

  (:action modify_cpu_set_limit
    :parameters (?actor - user ?g - group)
    :precondition (and
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (cpu_limit_modified ?g)
    )
  )

  (:action increase_threads_limit
    :parameters (?actor - user ?g - group)
    :precondition (and
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (threads_limit_increased ?g)
    )
  )

  (:action recreate_quota_group
    :parameters (?actor - user ?g - group)
    :precondition (and
      (not (group_exists ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?g)
    )
  )

  (:action modify_journal_limit
    :parameters (?actor - user ?g - group)
    :precondition (and
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_limit_modified ?g)
    )
  )

  (:action set_new_quota
    :parameters (?actor - user ?g - group)
    :precondition (and
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (quota_set ?g)
    )
  )

  (:action set_quota
    :parameters (?actor - user ?pkg - package ?g - group ?svc - service)
    :precondition (and
      (package_installed ?pkg)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
      (service_running ?svc)
    )
  )

  (:action sign_assertion
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_signed ?f)
    )
  )

  (:action snap_start_service
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
    :parameters (?actor - user ?pkg - package ?chan - file)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_configured ?pkg)
    )
  )

  (:action switch_snap_to_cohort
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_in_cohort ?pkg)
    )
  )

  (:action snap_try
    :parameters (?actor - user ?pkg - package ?dir - directory)
    :precondition (and
      (file_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_enabled ?pkg)
    )
  )

  (:action snap_unalias
    :parameters (?actor - user ?alias_or_snap - package)
    :precondition (and
      (package_installed ?alias_or_snap)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_enabled ?alias_or_snap))
    )
  )

  (:action snap_unset
    :parameters (?actor - user ?snap_name - package ?config_key - file)
    :precondition (and
      (package_installed ?snap_name)
      (file_exists ?config_key)
      (can_escalate ?actor)
    )
    :effect (and
      (not (package_configured ?snap_name))
    )
  )

  (:action enforce_validation_set
    :parameters (?actor - user ?vs - file)
    :precondition (and
      (file_exists ?vs)
      (can_escalate ?actor)
    )
    :effect (and
      (validation_set_enforced ?vs)
    )
  )

  (:action forget_validation_set
    :parameters (?actor - user ?vs - file)
    :precondition (and
      (file_exists ?vs)
      (can_escalate ?actor)
    )
    :effect (and
      (not (validation_set_enforced ?vs))
      (not (validation_set_monitored ?vs))
    )
  )

  (:action refresh_validation_sets
    :parameters (?actor - user ?vs - file ?pkg - package)
    :precondition (and
      (validation_set_enforced ?vs)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
    )
  )

  (:action silence_warnings
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_warnings_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (not (system_warnings_exist))
    )
  )

  (:action abort_change
    :parameters (?actor - user ?pr - process)
    :precondition (and
      (process_running ?pr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?pr))
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

  (:action connect_interface
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

  (:action disconnect_interface
    :parameters (?actor - user ?plug - interface ?slot - interface)
    :precondition (and
      (interface_exists ?plug)
      (interface_exists ?slot)
      (can_escalate ?actor)
    )
    :effect (and
      (not (interface_up ?plug))
      (not (interface_up ?slot))
    )
  )

  (:action set_config
    :parameters (?actor - user ?svc - service ?opt - file)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?svc)
    )
  )

  (:action unset_config
    :parameters (?actor - user ?svc - service ?opt - file)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (config_applied ?svc))
    )
  )

  (:action set_alias
    :parameters (?actor - user ?name - file ?target - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?name)
    )
  )

  (:action remove_alias
    :parameters (?actor - user ?name - file)
    :precondition (and
      (file_exists ?name)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?name))
    )
  )

  (:action prefer_alias
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_enabled ?pkg)
    )
  )

  (:action login_account
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (not (user_locked ?u))
    )
  )

  (:action logout_account
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (user_locked ?u)
    )
  )

  (:action save_snapshot
    :parameters (?actor - user ?s - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?s)
    )
  )

  (:action reboot_device
    :parameters (?actor - user ?s - service)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?s))
    )
  )

  (:action run_snap
    :parameters (?pkg - package ?pr - process)
    :precondition (and
      (package_installed ?pkg)
    )
    :effect (and
      (process_running ?pr)
    )
  )

  (:action try_snap
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_enabled ?pkg)
    )
  )

  (:action prepare_image
    :parameters (?actor - user ?f - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action remove_quota
    :parameters (?actor - user ?g - group)
    :precondition (and
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?g))
    )
  )

  (:action apply_validation_set
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?f)
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

  (:action unload_unit
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?svc))
    )
  )

  (:action reload_service_config
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?svc)
    )
  )

  (:action try_restart_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
    )
  )

  (:action reload_or_restart_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
      (config_applied ?svc)
    )
  )

  (:action try_reload_or_restart_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
      (config_applied ?svc)
    )
  )

  (:action isolate_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
    )
  )

  (:action kill_process
    :parameters (?actor - user ?pr - process)
    :precondition (and
      (process_running ?pr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?pr))
    )
  )

  (:action clean_unit_data
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (config_applied ?svc))
    )
  )

  (:action clear_unit_state
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (not (service_running ?svc))
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_has_persistent_state ?svc))
    )
  )

  (:action clear_unit_runtime_data
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (not (service_running ?svc))
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_has_runtime_data ?svc))
    )
  )

  (:action freeze_unit
    :parameters (?actor - user ?svc - service ?pr - package)
    :precondition (and
      (service_exists ?svc)
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?pr))
    )
  )

  (:action thaw_unit
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (service_frozen ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_frozen ?svc))
      (process_running ?svc)
    )
  )

  (:action set_unit_property
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?svc)
    )
  )

  (:action set_service_property
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?svc)
    )
  )

  (:action bind_unit_path
    :parameters (?actor - user ?svc - service ?path - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?svc)
    )
  )

  (:action bind_mount_object
    :parameters (?actor - user ?src - file ?dest - file ?svc - service)
    :precondition (and
      (file_exists ?src)
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?dest)
      (file_readable ?dest)
    )
  )

  (:action mount_image_to_unit
    :parameters (?actor - user ?unit - service ?image - file ?path - directory)
    :precondition (and
      (service_exists ?unit)
      (file_exists ?image)
      (file_exists ?path)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?path)
    )
  )

  (:action create_readonly_mount
    :parameters (?actor - user ?f - file ?d - directory)
    :precondition (and
      (file_exists ?f)
      (directory_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (file_readable ?f)
      (not (file_writable ?f))
    )
  )

  (:action create_mount_directory
    :parameters (?actor - user ?d - directory)
    :precondition (and
      (not (directory_exists ?d))
      (can_escalate ?actor)
    )
    :effect (and
      (directory_exists ?d)
    )
  )

  (:action mount_image
    :parameters (?actor - user ?svc - service ?img - file ?target - directory)
    :precondition (and
      (service_exists ?svc)
      (file_exists ?img)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
      (file_exists ?target)
    )
  )

  (:action set_service_log_level
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?svc)
    )
  )

  (:action change_service_log_target
    :parameters (?actor - user ?svc - service ?target - file)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_log_target_set ?svc ?target)
    )
  )

  (:action reset_failed_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (service_failed ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_failed ?svc))
    )
  )

  (:action reset_failed_state
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (service_failed ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_failed ?svc))
    )
  )

  (:action manage_unit_symlink
    :parameters (?actor - user ?f - file ?d - directory)
    :precondition (and
      (file_exists ?f)
      (interface_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action daemon_reload
    :parameters (?actor - user ?obj - file ?s - service)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?s)
    )
  )

  (:action reenable_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_enabled ?svc)
    )
  )

  (:action preset_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_enabled ?svc)
    )
  )

  (:action preset_all_units
    :parameters (?actor - user ?obj - file ?s - service)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (service_enabled ?s)
      (not (service_enabled ?s))
    )
  )

  (:action link_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (not (service_linked ?svc))
      (can_escalate ?actor)
    )
    :effect (and
      (service_linked ?svc)
    )
  )

  (:action mask_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_masked ?svc)
      (not (service_running ?svc))
      (not (service_enabled ?svc))
    )
  )

  (:action unmask_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (service_masked ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_masked ?svc))
    )
  )

  (:action link_unit_file
    :parameters (?actor - user ?f - file ?s - service)
    :precondition (and
      (file_exists ?f)
      (service_exists ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (service_enabled ?s)
    )
  )

  (:action revert_unit_file
    :parameters (?actor - user ?s - service)
    :precondition (and
      (service_exists ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?s)
    )
  )

  (:action add_unit_dependency
    :parameters (?actor - user ?target - service ?unit - service)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (depends_on ?target ?unit)
    )
  )

  (:action edit_unit_file
    :parameters (?actor - user ?svc - service ?f - file)
    :precondition (and
      (service_exists ?svc)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?svc)
    )
  )

  (:action create_drop_in_config
    :parameters (?actor - user ?svc - service ?f - file)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?svc)
      (file_exists ?f)
    )
  )

  (:action set_default_target
    :parameters (?actor - user ?target - service)
    :precondition (and
      (service_exists ?target)
      (can_escalate ?actor)
    )
    :effect (and
      (service_enabled ?target)
    )
  )

  (:action cancel_job
    :parameters (?actor - user ?job - process)
    :precondition (and
      (process_running ?job)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?job))
    )
  )

  (:action set_environment
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?svc)
    )
  )

  (:action set_manager_environment
    :parameters (?actor - user ?var - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (env_variable_set ?var)
    )
  )

  (:action unset_manager_environment
    :parameters (?actor - user ?var - file)
    :precondition (and
      (env_variable_set ?var)
      (can_escalate ?actor)
    )
    :effect (and
      (not (env_variable_set ?var))
    )
  )

  (:action import_environment
    :parameters (?actor - user ?var - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (env_variable_imported ?var)
    )
  )

  (:action reexecute_systemd_manager
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
    )
  )

  (:action set_manager_log_level
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (manager_log_level_set ?svc)
    )
  )

  (:action set_manager_log_target
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (manager_log_target_set ?svc)
    )
  )

  (:action set_service_watchdogs
    :parameters (?actor - user ?state - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (service_watchdogs_enabled ?state)
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
    :parameters (?actor - user ?target - service ?pr - package)
    :precondition (and
      (service_exists ?target)
      (can_escalate ?actor)
    )
    :effect (and
      (not (network_available))
      (not (process_running ?pr))
    )
  )

  (:action kexec_reboot
    :parameters (?actor - user ?obj - file ?pr - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?pr))
    )
  )

  (:action load_kernel
    :parameters (?actor - user ?k - process ?i - object)
    :precondition (and
      (network_available)
      (interface_up ?i)
      (can_escalate ?actor)
    )
    :effect (and
      (process_running ?k)
    )
  )

  (:action soft_reboot
    :parameters (?actor - user ?obj - file ?all_userspace_processes - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?all_userspace_processes))
    )
  )

  (:action exit_service_manager
    :parameters (?obj - file ?service_manager - service)
    :precondition (and
    )
    :effect (and
      (not (process_running ?service_manager))
    )
  )

  (:action switch_root
    :parameters (?actor - user ?dir - directory ?proc - process)
    :precondition (and
      (file_exists ?dir)
      (file_executable ?proc)
      (can_escalate ?actor)
    )
    :effect (and
      (process_running ?proc)
    )
  )

  (:action put_system_to_sleep
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
      (can_escalate ?actor)
    )
    :effect (and
      (system_hibernated)
    )
  )

  (:action suspend_then_hibernate
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?svc))
      (system_hibernating)
    )
  )

  (:action isolate_target
    :parameters (?actor - user ?target - service)
    :precondition (and
      (service_exists ?target)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?target)
    )
  )

  (:action fail_operation
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (pending_job_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_failed ?svc)
    )
  )

  (:action replace_pending_job
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (pending_job_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (pending_job_exists ?svc))
      (service_running ?svc)
    )
  )

  (:action replace_irreversibly_job
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (job_irreversible ?svc)
      (service_running ?svc)
    )
  )

  (:action flush_jobs
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (job_queued))
    )
  )

  (:action establish_inhibitor_lock
    :parameters (?u - user ?pr - process)
    :precondition (and
      (user_exists ?u)
      (process_running ?pr)
    )
    :effect (and
      (inhibitor_lock_active ?pr)
    )
  )

  (:action override_inhibitor_lock
    :parameters (?actor - user ?u - user ?pr - package)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (inhibitor_lock_active ?pr))
    )
  )

  (:action kill_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (not (service_running ?svc))
    )
  )

  (:action kill_service_process
    :parameters (?actor - user ?svc - service ?pr - process)
    :precondition (and
      (service_exists ?svc)
      (process_running ?pr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?pr))
    )
  )

  (:action send_signal
    :parameters (?actor - user ?pr - process ?sig - file)
    :precondition (and
      (process_running ?pr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?pr))
    )
  )

  (:action clean_resources
    :parameters (?actor - user ?svc - service ?res - file)
    :precondition (and
      (service_exists ?svc)
      (file_exists ?res)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?res))
    )
  )

  (:action edit_service_unit
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (service_exists ?svc)
    )
  )

  (:action hybrid_sleep_system
    :parameters (?actor - user ?obj - file ?pr - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?pr))
    )
  )

  (:action suspend_then_hibernate_system
    :parameters (?actor - user ?obj - file ?pr - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?pr))
    )
  )

  (:action kexec_system
    :parameters (?actor - user ?obj - file ?pr - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?pr))
    )
  )

  (:action edit_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?svc)
    )
  )

  (:action preset_all_services
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (service_enabled ?svc)
    )
  )

  (:action reboot_to_firmware_setup
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firmware_setup_pending)
    )
  )

  (:action set_boot_loader_menu
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (boot_loader_menu_pending)
    )
  )

  (:action set_boot_loader_entry
    :parameters (?actor - user ?entry - file)
    :precondition (and
      (file_exists ?entry)
      (can_escalate ?actor)
    )
    :effect (and
      (boot_entry_selected ?entry)
    )
  )

  (:action reboot_with_argument
    :parameters (?actor - user ?arg - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_rebooting_with_arg ?arg)
    )
  )

  (:action create_mount_destination
    :parameters (?actor - user ?f - file)
    :precondition (and
      (not (file_exists ?f))
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action restart_unit
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
    )
  )

  (:action reload_unit
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?svc)
    )
  )

  (:action enable_pager_secure_mode
    :parameters (?pr - process)
    :precondition (and
      (process_running ?pr)
    )
    :effect (and
      (pager_secure_mode_enabled ?pr)
    )
  )

  (:action disable_pager
    :parameters (?pr - process)
    :precondition (and
      (process_running ?pr)
    )
    :effect (and
      (not (pager_active ?pr))
    )
  )

  (:action disable_pager_secure_mode
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (can_escalate ?u)
    )
  )

  (:action reload_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (service_running ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?svc)
    )
  )

  (:action kill_service_processes
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

  (:action bind_mount_unit
    :parameters (?actor - user ?svc - service ?f - file)
    :precondition (and
      (service_exists ?svc)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_path_bound ?svc ?f)
    )
  )

  (:action mount_image_unit
    :parameters (?actor - user ?svc - service ?f - file)
    :precondition (and
      (service_exists ?svc)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (unit_image_mounted ?svc ?f)
    )
  )

  (:action set_service_log_target
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_log_target_configured ?svc)
    )
  )

  (:action revert_service
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (package_reverted ?svc)
    )
  )

  (:action add_wants_dependency
    :parameters (?actor - user ?target - service ?unit - service)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (depends_on ?target ?unit)
    )
  )

  (:action add_requires_dependency
    :parameters (?actor - user ?target - service ?unit - service)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (depends_on ?target ?unit)
    )
  )

  (:action set_environment_variable
    :parameters (?actor - user ?var - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?var)
    )
  )

  (:action unset_environment_variable
    :parameters (?actor - user ?var - file)
    :precondition (and
      (file_exists ?var)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?var))
    )
  )

  (:action daemon_reexec
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_daemon_reexec)
    )
  )

  (:action set_log_level
    :parameters (?actor - user ?level - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_set_log_level)
    )
  )

  (:action set_log_target
    :parameters (?actor - user ?target - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_set_log_target)
    )
  )

  (:action system_sleep
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_sleeping)
    )
  )

  (:action set_firmware_setup
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firmware_setup_pending)
    )
  )

  (:action create_directory_for_mount
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (not (file_exists ?dir))
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?dir)
    )
  )

  (:action restart_marked_units
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (service_marked ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (service_running ?svc)
    )
  )

  (:action edit_unit_drop_in
    :parameters (?actor - user ?svc - service ?f - file)
    :precondition (and
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (configures ?f ?svc)
      (config_applied ?svc)
    )
  )

  (:action schedule_system_action
    :parameters (?actor - user ?action - process)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (process_running ?action)
    )
  )

  (:action write_journal_cursor
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (file_writable ?f)
    )
    :effect (and
      (file_exists ?f)
      (file_writable ?f)
    )
  )

  (:action export_journal
    :parameters (?f - file)
    :precondition (and
      (service_running ?journald)
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action setup_fss_keys
    :parameters (?actor - user ?f - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
      (fss_keys_setup ?f)
    )
  )

  (:action recreate_fss_keys
    :parameters (?actor - user ?svc - service)
    :precondition (and
      (service_exists ?svc)
      (config_applied ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (fss_keys_recreated ?svc)
    )
  )

  (:action vacuum_journal_files
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action vacuum_journal_time
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action vacuum_journal_size
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action rotate_journal_files
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_archived ?f)
    )
  )

  (:action vacuum_journal
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action sync_journals
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_synced ?f)
    )
  )

  (:action relinquish_journal_var
    :parameters (?actor - user ?pr - process)
    :precondition (and
      (process_running ?pr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (journal_writing_to_var ?pr))
    )
  )

  (:action smart_relinquish_journal_var
    :parameters (?actor - user ?pr - process)
    :precondition (and
      (process_running ?pr)
      (not (journal_on_root_mount ?pr))
      (can_escalate ?actor)
    )
    :effect (and
      (not (journal_writing_to_var ?pr))
    )
  )

  (:action flush_journal
    :parameters (?actor - user ?pr - process)
    :precondition (and
      (process_running ?pr)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_writing_to_var ?pr)
      (journal_logs_flushed ?pr)
    )
  )

  (:action flush_journal_logs
    :parameters (?actor - user ?s - service)
    :precondition (and
      (service_running ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (logs_flushed_to_disk ?s)
    )
  )

  (:action rotate_journal_logs
    :parameters (?actor - user ?s - service)
    :precondition (and
      (service_running ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (journal_files_rotated ?s)
    )
  )

  (:action update_message_catalog
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (catalog_index_updated)
    )
  )

  (:action set_systemd_log_time
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (file_writable ?f)
    )
    :effect (and
      (log_time_enabled ?f)
    )
  )

  (:action set_systemd_log_location
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (file_writable ?f)
    )
    :effect (and
      (log_location_enabled ?f)
    )
  )

  (:action set_systemd_log_tid
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (file_writable ?f)
    )
    :effect (and
      (log_tid_enabled ?f)
    )
  )

  (:action set_pager_secure
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (pager_secure_enabled ?u)
    )
  )

  (:action set_systemd_colors
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (systemd_colors_enabled ?u)
    )
  )

  (:action set_systemd_urlify
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (systemd_urlify_enabled ?u)
    )
  )

  (:action sync_journal
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?journal_sync)
    )
  )

  (:action rotate_journal
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_rotated)
    )
  )

  (:action update_journal_catalog
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (catalog_updated)
    )
  )

  (:action setup_journal_keys
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

  (:action force_remove_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action create_hard_link
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dst)
    )
  )

  (:action copy_directory_recursive
    :parameters (?src - directory ?dest - directory)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action remove_destination_before_copy
    :parameters (?dest - file)
    :precondition (and
      (file_exists ?dest)
    )
    :effect (and
      (not (file_exists ?dest))
    )
  )

  (:action create_symbolic_link
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action copy_to_target_directory
    :parameters (?src - file ?dest_dir - directory)
    :precondition (and
    )
    :effect (and
      (file_exists ?src)
    )
  )

  (:action update_existing_files
    :parameters (?src - file ?dest - file)
    :precondition (and
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action set_selinux_context_default
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_has_default_selinux_context ?f)
    )
  )

  (:action set_selinux_context_custom
    :parameters (?actor - user ?f - file ?ctx - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_has_security_context ?f ?ctx)
    )
  )

  (:action create_sparse_file
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
      (file_is_sparse ?dest)
    )
  )

  (:action update_destination_files
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dest)
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action reflink_copy
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
      (file_reflinked ?dest)
    )
  )

  (:action backup_file
    :parameters (?src - file ?src_backup - package)
    :precondition (and
      (file_exists ?src)
      (file_writable ?src)
    )
    :effect (and
      (file_exists ?src_backup)
    )
  )

  (:action copy_files_to_directory
    :parameters (?src - file ?dir - directory)
    :precondition (and
    )
    :effect (and
      (file_exists ?src)
    )
  )

  (:action copy_recursive
    :parameters (?src - directory ?dest - directory)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
      (file_exists ?dest)
    )
  )

  (:action copy_to_directory
    :parameters (?src - file ?dir - directory ?src_in_dir - service)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dir)
    )
    :effect (and
      (file_exists ?src_in_dir)
    )
  )

  (:action set_selinux_context
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_context_default ?f)
    )
  )

  (:action replace_files
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dest)
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

  (:action move_to_directory
    :parameters (?src - file ?dir - directory)
    :precondition (and
    )
    :effect (and
      (not (file_exists ?src))
    )
  )

  (:action rename_file
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

  (:action replace_file
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dest)
    )
    :effect (and
      (not (file_exists ?dest))
      (file_exists ?src)
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

  (:action remove_directory
    :parameters (?d - directory)
    :precondition (and
      (file_exists ?d)
    )
    :effect (and
      (not (file_exists ?d))
    )
  )

  (:action remove_recursive
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action remove_empty_directory
    :parameters (?d - directory)
    :precondition (and
      (file_exists ?d)
    )
    :effect (and
      (not (file_exists ?d))
    )
  )

  (:action remove_directory_recursive
    :parameters (?d - directory)
    :precondition (and
      (file_exists ?d)
    )
    :effect (and
      (not (file_exists ?d))
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
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action add_file_permissions
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_readable ?f)
      (file_writable ?f)
      (file_executable ?f)
    )
  )

  (:action remove_file_permissions
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_readable ?f))
      (not (file_writable ?f))
      (not (file_executable ?f))
    )
  )

  (:action set_file_permissions
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_readable ?f)
      (file_writable ?f)
      (file_executable ?f)
    )
  )

  (:action change_file_permissions
    :parameters (?f - file ?u - user ?g - group)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_readable ?f)
      (file_writable ?f)
      (file_executable ?f)
    )
  )

  (:action chmod_symlink_target
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action clear_setgid_bit
    :parameters (?f - file ?u - user ?g - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?u)
      (not (member_of ?u ?g))
    )
    :effect (and
      (not (file_executable ?f))
    )
  )

  (:action set_directory_special_bits
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_special_bits_set ?f)
    )
  )

  (:action clear_directory_special_bits_numeric
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_special_bits_set ?f))
    )
  )

  (:action set_sticky_bit
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_sticky_bit_set ?f)
    )
  )

  (:action change_file_mode_reference
    :parameters (?f - file ?rf - file)
    :precondition (and
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action change_mode_recursive
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action chmod_reference
    :parameters (?f - file ?ref - file)
    :precondition (and
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

  (:action change_file_owner
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

  (:action change_file_ownership
    :parameters (?actor - user ?f - file ?u - user ?g - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?f ?u)
      (member_of ?f ?g)
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
      (file_owned_by ?f ?u)
      (member_of ?u ?g)
    )
  )

  (:action change_group
    :parameters (?actor - user ?f - file ?g - group)
    :precondition (and
      (file_exists ?f)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (file_group_owned_by ?f ?g)
    )
  )

  (:action change_owner_recursive
    :parameters (?actor - user ?d - directory ?u - user)
    :precondition (and
      (file_exists ?d)
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?d ?u)
    )
  )

  (:action change_owner_group
    :parameters (?actor - user ?f - file ?u - user ?g - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?f ?u)
      (member_of ?u ?g)
    )
  )

  (:action change_owner_group_reference
    :parameters (?actor - user ?f - file ?rf - file ?u - user)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rf)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?f ?u)
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

  (:action update_file_timestamps
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_exists ?f)
    )
  )

  (:action change_symlink_timestamp
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_timestamp_updated ?f)
    )
  )

  (:action reference_file_timestamp
    :parameters (?f_target - file ?f_ref - file)
    :precondition (and
      (file_exists ?f_target)
      (file_exists ?f_ref)
    )
    :effect (and
      (file_timestamp_updated ?f_target)
    )
  )

  (:action change_specific_timestamp
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_timestamp_updated ?f)
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

  (:action append_firewall_rule
    :parameters (?actor - user ?r - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?r)
      (traffic_blocked ?r)
    )
  )

  (:action delete_firewall_rule
    :parameters (?actor - user ?r - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?r)
      (can_escalate ?actor)
    )
    :effect (and
      (not (firewall_rule_exists ?r))
      (not (traffic_blocked ?r))
    )
  )

  (:action insert_firewall_rule
    :parameters (?actor - user ?r - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?r)
      (traffic_blocked ?r)
    )
  )

  (:action replace_firewall_rule
    :parameters (?actor - user ?r - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?r)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?r)
    )
  )

  (:action create_firewall_chain
    :parameters (?actor - user ?c - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (chain_exists ?c)
    )
  )

  (:action delete_firewall_chain
    :parameters (?actor - user ?c - file)
    :precondition (and
      (chain_exists ?c)
      (can_escalate ?actor)
    )
    :effect (and
      (not (chain_exists ?c))
    )
  )

  (:action set_chain_policy
    :parameters (?actor - user ?c - file)
    :precondition (and
      (chain_exists ?c)
      (can_escalate ?actor)
    )
    :effect (and
      (chain_policy_set ?c)
    )
  )

  (:action flush_firewall_chain
    :parameters (?actor - user ?c - file ?r - object)
    :precondition (and
      (chain_exists ?c)
      (can_escalate ?actor)
    )
    :effect (and
      (not (firewall_rule_exists ?r))
    )
  )

  (:action create_firewall_rule
    :parameters (?actor - user ?r - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?r)
    )
  )

  (:action zero_firewall_counters
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (counters_zeroed ?chain)
    )
  )

  (:action delete_chain
    :parameters (?actor - user ?r - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?r)
      (not (chain_has_rules ?r))
      (can_escalate ?actor)
    )
    :effect (and
      (not (firewall_rule_exists ?r))
    )
  )

  (:action add_firewall_rule
    :parameters (?actor - user ?r - firewall_rule)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?r)
    )
  )

  (:action set_firewall_rule_target
    :parameters (?actor - user ?r - firewall_rule ?t - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?r)
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?r)
    )
  )

  (:action set_firewall_rule_goto
    :parameters (?actor - user ?r - firewall_rule ?c - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?r)
      (firewall_rule_exists ?c)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?r)
    )
  )

  (:action set_rule_counters
    :parameters (?actor - user ?r - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?r)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_counters_initialized ?r)
    )
  )

  (:action lock_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
      (file_writable ?f)
    )
    :effect (and
      (file_locked ?f)
    )
  )

  (:action flush_chain
    :parameters (?actor - user ?r - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?r)
      (can_escalate ?actor)
    )
    :effect (and
      (not (firewall_rule_exists ?r))
    )
  )

  (:action create_chain
    :parameters (?actor - user ?r - firewall_rule)
    :precondition (and
      (not (firewall_rule_exists ?r))
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?r)
    )
  )

  (:action change_chain_policy
    :parameters (?actor - user ?r - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?r)
      (can_escalate ?actor)
    )
    :effect (and
      (traffic_blocked ?r)
    )
  )

  (:action rename_chain
    :parameters (?actor - user ?r_old - firewall_rule ?r_new - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?r_old)
      (not (firewall_rule_exists ?r_new))
      (can_escalate ?actor)
    )
    :effect (and
      (not (firewall_rule_exists ?r_old))
      (firewall_rule_exists ?r_new)
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

  (:action flush_ip_address
    :parameters (?actor - user ?i - interface)
    :precondition (and
      (interface_exists ?i)
      (interface_up ?i)
      (can_escalate ?actor)
    )
    :effect (and
      (not (interface_up ?i))
    )
  )

  (:action switch_network_namespace
    :parameters (?actor - user ?ns - interface)
    :precondition (and
      (interface_exists ?ns)
      (can_escalate ?actor)
    )
    :effect (and
      (interface_up ?ns)
    )
  )

  (:action manage_ila
    :parameters (?actor - user ?addr - file ?i - object)
    :precondition (and
      (interface_exists ?i)
      (can_escalate ?actor)
    )
    :effect (and
      (interface_up ?i)
    )
  )

  (:action manage_ioam
    :parameters (?actor - user ?ns - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?ns)
    )
  )

  (:action configure_l2tp
    :parameters (?actor - user ?tun - interface)
    :precondition (and
      (interface_exists ?tun)
      (can_escalate ?actor)
    )
    :effect (and
      (interface_up ?tun)
    )
  )

  (:action manage_mptcp
    :parameters (?actor - user ?pm - process)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (process_running ?pm)
    )
  )

  (:action manage_neighbour
    :parameters (?actor - user ?neigh - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?neigh)
    )
  )

  (:action manage_netns
    :parameters (?actor - user ?ns - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?ns)
    )
  )

  (:action manage_nexthop
    :parameters (?actor - user ?nh - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?nh)
    )
  )

  (:action manage_ntable
    :parameters (?actor - user ?tab - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?tab)
    )
  )

  (:action manage_route
    :parameters (?actor - user ?rt - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?rt)
    )
  )

  (:action add_network_object
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?obj)
    )
  )

  (:action delete_network_object
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (file_exists ?obj)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?obj))
    )
  )

  (:action manage_tuntap
    :parameters (?actor - user ?i - interface)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (interface_exists ?i)
    )
  )

  (:action manage_vrf
    :parameters (?actor - user ?v - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?v)
    )
  )

  (:action manage_xfrm
    :parameters (?actor - user ?p - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?p)
    )
  )

  (:action bring_up_interface
    :parameters (?actor - user ?i - interface)
    :precondition (and
      (interface_exists ?i)
      (not (interface_up ?i))
      (can_escalate ?actor)
    )
    :effect (and
      (interface_up ?i)
    )
  )

  (:action bring_down_interface
    :parameters (?actor - user ?i - interface)
    :precondition (and
      (interface_exists ?i)
      (interface_up ?i)
      (can_escalate ?actor)
    )
    :effect (and
      (not (interface_up ?i))
    )
  )

  (:action kill_sockets
    :parameters (?actor - user ?pr - process)
    :precondition (and
      (process_running ?pr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running ?pr))
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
    :parameters (?u - user ?pr - process)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?u)
    )
    :effect (and
      (executed_as_root ?pr)
    )
  )

  (:action edit_sudoers
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (file_writable ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?f)
    )
  )

  (:action remove_user_session_timestamp
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (not (session_timestamp_exists ?u))
    )
  )

  (:action reset_user_session_timestamp
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (not (session_timestamp_exists ?u))
    )
  )

  (:action sudoedit_file
    :parameters (?f - file ?u - user)
    :precondition (and
      (user_exists ?u)
      (file_exists ?f)
    )
    :effect (and
      (file_writable ?f)
    )
  )

  (:action create_temporary_copy
    :parameters (?actor - user ?f - file ?u - user ?f_tmp - package)
    :precondition (and
      (file_exists ?f)
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f_tmp)
      (file_owned_by ?f_tmp ?u)
    )
  )

  (:action edit_temporary_file
    :parameters (?f_tmp - file ?u - user)
    :precondition (and
      (file_exists ?f_tmp)
      (file_writable ?f_tmp)
      (user_exists ?u)
    )
    :effect (and
      (file_modified ?f_tmp)
    )
  )

  (:action restore_edited_file
    :parameters (?actor - user ?f_tmp - file ?f - file)
    :precondition (and
      (file_exists ?f_tmp)
      (file_exists ?f)
      (file_modified ?f_tmp)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_modified ?f_tmp))
      (file_modified ?f)
    )
  )

  (:action remove_temporary_file
    :parameters (?actor - user ?f_tmp - file)
    :precondition (and
      (file_exists ?f_tmp)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f_tmp))
    )
  )

  (:action run_as_user
    :parameters (?u - user ?pr - process)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (executed_as_root ?pr)
    )
  )

  (:action sudo_edit_file
    :parameters (?f - file ?u - user)
    :precondition (and
      (file_exists ?f)
      (user_exists ?u)
      (can_escalate ?u)
    )
    :effect (and
      (file_writable ?f)
    )
  )

  (:action remove_timestamp
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action reset_timestamp
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (timestamp_invalidated ?f)
    )
  )

  (:action edit_file_as_user
    :parameters (?u - user ?f - file)
    :precondition (and
      (user_exists ?u)
      (file_exists ?f)
    )
    :effect (and
      (file_writable ?f)
    )
  )

  (:action substitute_user
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (executed_as_root ?u)
    )
  )

  (:action set_privileges
    :parameters (?actor - user ?pr - process)
    :precondition (and
      (executed_as_root ?pr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (executed_as_root ?pr))
    )
  )

  (:action set_primary_group
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

  (:action set_supplementary_group
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

  (:action start_login_shell
    :parameters (?u - user ?shell_process - package)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (process_running ?shell_process)
    )
  )

  (:action switch_user_session
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (user_critical ?u)
    )
  )

  (:action switch_user_preserve_env
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (requires_env_preservation ?u)
    )
  )

  (:action switch_user_pty
    :parameters (?u - user)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (process_running ?u)
    )
  )

  (:action run_shell_as_user
    :parameters (?u - user ?sh - file)
    :precondition (and
      (user_exists ?u)
      (file_exists ?sh)
      (file_executable ?sh)
    )
    :effect (and
      (process_running ?sh)
    )
  )

  (:action execute_session_command
    :parameters (?u - user ?cmd - process)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action configure_pam_lastlog
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (file_writable ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (config_applied ?f)
    )
  )

  (:action switch_user
    :parameters (?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
    )
    :effect (and
      (member_of ?u ?g)
    )
  )

  (:action set_supplemental_group
    :parameters (?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
    )
    :effect (and
      (member_of ?u ?g)
    )
  )

  (:action execute_shell_command
    :parameters (?u - user ?cmd - process)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action run_specific_shell
    :parameters (?u - user ?sh - file)
    :precondition (and
      (user_exists ?u)
      (file_exists ?sh)
      (file_executable ?sh)
    )
    :effect (and
      (process_running ?sh)
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

  (:action expire_user_account
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_locked ?u)
    )
  )

  (:action add_user_to_groups
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

  (:action create_user_home_from_skel
    :parameters (?actor - user ?u - user ?dir - directory ?u_home - user)
    :precondition (and
      (user_exists ?u)
      (file_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?u_home)
    )
  )

  (:action create_user_no_password_aging
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (not (user_password_aging ?u))
    )
  )

  (:action create_user_no_log
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (not (user_logged_init ?u))
    )
  )

  (:action create_user_with_home
    :parameters (?actor - user ?u - user ?d - directory)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (file_exists ?d)
      (file_owned_by ?d ?u)
    )
  )

  (:action create_user_home
    :parameters (?actor - user ?u - user ?d - directory ?u_home - user)
    :precondition (and
      (user_exists ?u)
      (file_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?u_home)
    )
  )

  (:action create_user_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (not (group_exists ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?g)
      (member_of ?u ?g)
    )
  )

  (:action create_user_with_password
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (not (user_locked ?u))
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
    )
  )

  (:action set_user_shell
    :parameters (?actor - user ?u - user ?s - file)
    :precondition (and
      (user_exists ?u)
      (file_exists ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?s ?u)
    )
  )

  (:action set_user_uid
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
    )
  )

  (:action set_useradd_base_dir
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?file_etc_default_useradd)
    )
  )

  (:action set_useradd_expiredate
    :parameters (?actor - user ?date - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?file_etc_default_useradd)
    )
  )

  (:action set_useradd_inactive
    :parameters (?actor - user ?days - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?file_etc_default_useradd)
    )
  )

  (:action set_default_primary_group
    :parameters (?actor - user ?g - group)
    :precondition (and
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?g)
    )
  )

  (:action set_default_shell
    :parameters (?actor - user ?s - file)
    :precondition (and
      (file_exists ?s)
      (file_executable ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_set_default_shell)
    )
  )

  (:action batch_create_users
    :parameters (?actor - user ?f - file ?u - user)
    :precondition (and
      (file_exists ?f)
      (file_readable ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
    )
  )

  (:action manage_user_mail_spool
    :parameters (?actor - user ?u - user ?f - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
      (file_owned_by ?f ?u)
    )
  )

  (:action add_user
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
    )
  )

  (:action create_multiple_users
    :parameters (?actor - user ?f - file ?u - user)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
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

  (:action remove_user_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (member_of ?u ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u))
      (not (group_exists ?g))
    )
  )

  (:action add_subids
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_subids ?u)
    )
  )

  (:action set_supplementary_groups
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

  (:action update_user_comment
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_comment_updated ?u)
    )
  )

  (:action change_user_home
    :parameters (?actor - user ?u - user ?d - directory)
    :precondition (and
      (user_exists ?u)
      (directory_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (user_home_directory ?u ?d)
    )
  )

  (:action modify_user_account
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_modified ?u)
    )
  )

  (:action clear_account_expiration
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_locked ?u))
    )
  )

  (:action set_account_inactive_period
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_locked ?u))
    )
  )

  (:action disable_expired_password_immediately
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_locked ?u)
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

  (:action change_user_login
    :parameters (?actor - user ?u_old - user ?u_new - user)
    :precondition (and
      (user_exists ?u_old)
      (not (user_exists ?u_new))
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u_old))
      (user_exists ?u_new)
    )
  )

  (:action lock_user_password
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

  (:action move_user_home
    :parameters (?actor - user ?u - user ?f_new_home - file ?f_old_home - file)
    :precondition (and
      (user_exists ?u)
      (file_exists ?f_old_home)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f_old_home))
      (file_exists ?f_new_home)
    )
  )

  (:action set_user_password
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_locked ?u))
    )
  )

  (:action change_user_id
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
    )
  )

  (:action remove_user_from_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (member_of ?u ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (not (member_of ?u ?g))
    )
  )

  (:action change_user_shell
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_shell_changed ?u)
    )
  )

  (:action change_user_uid
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_uid_changed ?u)
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

  (:action add_subuids
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_subuids ?u)
    )
  )

  (:action remove_subuids
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (user_has_subuids ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_has_subuids ?u))
    )
  )

  (:action add_subordinate_gids
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

  (:action remove_subordinate_gids
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

  (:action set_selinux_user
    :parameters (?actor - user ?u - user ?su - user)
    :precondition (and
      (user_exists ?u)
      (user_exists ?su)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_user_mapped ?u ?su)
    )
  )

  (:action set_selinux_range
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_range_defined ?u)
    )
  )

  (:action change_crontab_owner
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

  (:action create_mail_spool
    :parameters (?actor - user ?u - user ?f - file)
    :precondition (and
      (user_exists ?u)
      (not (file_exists ?f))
      (can_escalate ?actor)
    )
    :effect (and
      (file_exists ?f)
      (file_owned_by ?f ?u)
    )
  )

  (:action move_mail_spool
    :parameters (?actor - user ?u - user ?f_old - file ?f_new - file)
    :precondition (and
      (user_exists ?u)
      (file_exists ?f_old)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f_old))
      (file_exists ?f_new)
      (file_owned_by ?f_new ?u)
    )
  )

  (:action delete_mail_spool
    :parameters (?actor - user ?u - user ?f - file)
    :precondition (and
      (user_exists ?u)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action allocate_sub_gids
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (file_exists ?file_etc_subuid)
      (not (user_has_sub_gids ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_sub_gids ?u)
    )
  )

  (:action create_users_batch
    :parameters (?actor - user ?f - file ?u - user)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
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

  (:action set_user_expiry
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_locked ?u)
    )
  )

  (:action update_user_groups
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

  (:action rename_user
    :parameters (?actor - user ?u_old - user ?u_new - user)
    :precondition (and
      (user_exists ?u_old)
      (not (user_exists ?u_new))
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u_old))
      (user_exists ?u_new)
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
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (selinux_mapping_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (selinux_mapping_exists ?u))
    )
  )

  (:action remove_user
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u))
    )
  )

  (:action remove_cron_jobs
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_has_cron_jobs ?u))
    )
  )

  (:action remove_at_jobs
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_has_at_jobs ?u))
    )
  )

  (:action create_user_with_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (not (user_exists ?u))
      (not (group_exists ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (group_exists ?g)
      (member_of ?u ?g)
    )
  )

  (:action remove_print_jobs
    :parameters (?u - user ?print_job - package)
    :precondition (and
      (user_exists ?u)
    )
    :effect (and
      (not (process_running ?print_job))
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

  (:action kill_user_processes
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running_by_user ?u))
    )
  )

  (:action userdel_delete_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (member_of ?u ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u))
      (not (group_exists ?g))
    )
  )

  (:action userdel_force_delete_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u))
      (not (group_exists ?g))
    )
  )

  (:action remove_user_home
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?u))
    )
  )

  (:action remove_selinux_mapping
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (selinux_mapping_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (selinux_mapping_exists ?u))
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
    )
  )

  (:action set_group_password
    :parameters (?actor - user ?g - group)
    :precondition (and
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_locked ?g))
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

)