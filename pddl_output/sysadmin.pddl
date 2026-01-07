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
    :parameters (?actor - user ?obj - file)
    :precondition (and
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
      (package_downloaded ?pkg)
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
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (repository_insecure ?repo)
      (can_escalate ?actor)
    )
    :effect (and
      (repository_secure ?repo)
      (apt_update_possible ?repo)
    )
  )

  (:action configure_release_info_change
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (release_info_changed ?repo)
      (can_escalate ?actor)
    )
    :effect (and
      (release_info_confirmed ?repo)
      (apt_update_possible ?repo)
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

  (:action satisfy_dependencies
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_installed ?pkg)
      (not (dependency_satisfied ?dep))
      (can_escalate ?actor)
    )
    :effect (and
      (dependency_satisfied ?dep)
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
      (package_upgraded ?pkg)
      (package_removed ?pkg)
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
      (not (package_triggers_pending ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_triggers_pending ?pkg)
    )
  )

  (:action trigger_package_processing
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (package_triggers_pending ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (package_configured ?pkg)
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
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_exists ?pkg)
      (not (package_configured ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_unpacked ?pkg)
    )
  )

  (:action remove_packages
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_purged ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_purged ?pkg)
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

  (:action trigger_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_triggered ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_triggered ?pkg)
    )
  )

  (:action set_selections
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_selected ?pkg)
    )
  )

  (:action clear_selections
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_deselected ?pkg)
    )
  )

  (:action update_avail
    :parameters (?actor - user ?file - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (avail_packages_updated ?file)
    )
  )

  (:action merge_avail
    :parameters (?actor - user ?file - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (avail_packages_merged ?file)
    )
  )

  (:action clear_avail
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (avail_packages_cleared)
    )
  )

  (:action forget_old_unavail
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (unavail_packages_forgetten)
    )
  )

  (:action status_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_status_displayed ?pkg)
    )
  )

  (:action audit_packages
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (packages_audited ?pkg)
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

  (:action assert_help
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (assertions_help_shown)
    )
  )

  (:action assert_feature
    :parameters (?feature - file)
    :precondition (and
    )
    :effect (and
      (feature_asserted ?feature)
    )
  )

  (:action validate_thing
    :parameters (?thing - file ?string - file)
    :precondition (and
    )
    :effect (and
      (validation_succeeded ?thing ?string)
    )
  )

  (:action compare_versions
    :parameters (?a - file ?op - file ?b - file)
    :precondition (and
    )
    :effect (and
      (versions_compared ?a ?op ?b)
    )
  )

  (:action force_help
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (forcing_help_shown)
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
      (not (dependency_added ?tgt ?unit))
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

  (:action get_default_target
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_target ?target)
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
    :parameters (?actor - user ?job - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (jobs_canceled ?jobs)
    )
  )

  (:action set_environment
    :parameters (?var - file ?value - file)
    :precondition (and
    )
    :effect (and
      (environment_set ?env)
    )
  )

  (:action unset_environment
    :parameters (?var - file)
    :precondition (and
    )
    :effect (and
      (environment_unset ?env)
    )
  )

  (:action import_environment
    :parameters (?var - file)
    :precondition (and
    )
    :effect (and
      (environment_imported ?env)
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
    :parameters (?actor - user ?unit - service)
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
    :parameters (?actor - user ?unit - service)
    :precondition (and
      (unit_exists ?unit)
      (not (unit_running ?unit))
      (can_escalate ?actor)
    )
    :effect (and
      (unit_running ?unit)
    )
  )

  (:action edit_user_unit_files
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_unit_files_modified)
    )
  )

  (:action edit_runtime_unit_files
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (runtime_unit_files_modified)
    )
  )

  (:action override_symlinks
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (symlinks_overridden)
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

  (:action change_journal_output_mode
    :parameters (?actor - user ?mode - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_output_mode ?mode)
    )
  )

  (:action boot_into_boot_loader_menu
    :parameters (?actor - user ?time - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (boot_loader_menu)
    )
  )

  (:action boot_into_boot_loader_entry
    :parameters (?actor - user ?name - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (boot_loader_entry)
    )
  )

  (:action change_timestamp_format
    :parameters (?actor - user ?format - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (timestamp_format ?format)
    )
  )

  (:action create_read_only_bind_mount
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (read_only_bind_mount)
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

  (:action dereference_links
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (device_node_synthesized)
    )
  )

  (:action synthesize_kernel_names
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (kernel_names_synthesized)
    )
  )

  (:action identify_parent_devices
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (parent_devices_identified)
    )
  )

  (:action restrict_log_entries
    :parameters (?obj - file)
    :precondition (and
      (boot_restricted)
    )
    :effect (and
      (log_entriesrestricted_to_current_boot)
    )
  )

  (:action configure_journal
    :parameters (?obj - file)
    :precondition (and
      (user_in_group ?u 'systemd-journal)
      (user_in_group ?u 'adm)
      (user_in_group ?u 'wheel)
    )
    :effect (and
      (journal_access_granted ?u)
    )
  )

  (:action set_journal_options
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_output_modified)
    )
  )

  (:action configure_pager
    :parameters (?obj - file)
    :precondition (and
      (pager_enabled)
      (tty_available)
    )
    :effect (and
      (output_paged ?x)
      (lines_colored ?y)
    )
  )

  (:action configure_journal_options
    :parameters (?obj - file)
    :precondition (and
      (journal_enabled)
      (system_running)
    )
    :effect (and
      (options_set ?x)
      (output_journalled ?y)
    )
  )

  (:action set_journal_settings
    :parameters (?obj - file)
    :precondition (and
      (persistent_logging_enabled)
      (journald_conf_set)
    )
    :effect (and
      (show_messages_all)
      (show_messages_user)
      (show_messages_machine)
      (show_messages_merge)
    )
  )

  (:action set_journal_directory
    :parameters (?dir - directory)
    :precondition (and
    )
    :effect (and
      (journal_operates_on_dir)
    )
  )

  (:action set_file_glob
    :parameters (?glob - file)
    :precondition (and
    )
    :effect (and
      (journal_operates_on_glob)
    )
  )

  (:action set_machine
    :parameters (?machine - file)
    :precondition (and
    )
    :effect (and
      (show_messages_machine)
    )
  )

  (:action set_merge
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (show_messages_merge)
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
    :parameters (?actor - user ?ns - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_namespace_set ?ns)
    )
  )

  (:action operate_on_container
    :parameters (?actor - user ?container - file)
    :precondition (and
      (container_exists ?container)
      (can_escalate ?actor)
    )
    :effect (and
      (container_operated ?container)
    )
  )

  (:action set_filtering_options
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (filtering_options_set)
    )
  )

  (:action change_output_mode
    :parameters (?actor - user ?out - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_output_mode ?out)
    )
  )

  (:action set_output_fields
    :parameters (?actor - user ?fields - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (output_fields ?fields)
    )
  )

  (:action change_fss_sealing_key
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (fss_sealing_key_exists)
      (not (fss_sealing_key_valid))
      (can_escalate ?actor)
    )
    :effect (and
      (fss_sealing_key_valid)
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
      (journal_synced)
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
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (backup_created ?file)
    )
  )

  (:action copy_file_attributes
    :parameters (?file - file)
    :precondition (and
      (file_exists ?file)
    )
    :effect (and
      (file_attributes_equal ?file ?dst)
    )
  )

  (:action create_backup_without_argument
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (backup_created ?file)
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

  (:action create_hard_link
    :parameters (?f - file ?src - file)
    :precondition (and
      (file_exists ?src)
      (not (file_exists ?f)) or (file_exists ?f and not (file_executable ?f))
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action copy_directory
    :parameters (?src - directory ?dst - directory)
    :precondition (and
    )
    :effect (and
      (file_exists ?dst)
      (file_contents_changed ?dst)
    )
  )

  (:action remove_file
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
    )
    :effect (and
      (link_created ?dst) (link_points_to ?dst ?src)
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
    )
    :effect (and
      (file_contents_changed ?dst)
    )
  )

  (:action change_security_context
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_security_context ?f)
    )
  )

  (:action make_sparse
    :parameters (?actor - user ?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (can_escalate ?actor)
    )
    :effect (and
      (file_sparse ?dest)
    )
  )

  (:action set_sparse_option
    :parameters (?opt - file)
    :precondition (and
    )
    :effect (and
      (sparse_files_inhibited)
    )
  )

  (:action set_update_option
    :parameters (?opt - file)
    :precondition (and
    )
    :effect (and
      (files_replaced)
    )
  )

  (:action set_reflink_option
    :parameters (?opt - file)
    :precondition (and
    )
    :effect (and
      (data_blocks_copied)
    )
  )

  (:action copy_file_with_attributes
    :parameters (?src - file ?dst - file)
    :precondition (and
    )
    :effect (and
      (file_exists ?dst)
      (file_size ?dst) = (file_size ?src)
    )
  )

  (:action copy_file_with_backup
    :parameters (?src - file ?dst - file)
    :precondition (and
    )
    :effect (and
      (file_exists ?dst)
      (file_size ?dst) = (file_size ?src)
    )
  )

  (:action copy_file_with_contents
    :parameters (?src - file ?dst - file)
    :precondition (and
    )
    :effect (and
      (file_exists ?dst)
      (file_size ?dst) = (file_size ?src)
    )
  )

  (:action dereference_link
    :parameters (?link - file)
    :precondition (and
      (file_exists ?link)
    )
    :effect (and
      (file_linked_to ?link ?dst)
    )
  )

  (:action explain_copy
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_copied ?f)
    )
  )

  (:action prompt_before_overwrite
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
      (not (file_copied ?f))
    )
    :effect (and
      (file_copied ?f)
    )
  )

  (:action do_not_overwrite_file
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
      (not (file_copied ?f))
    )
    :effect (and
      (file_copied ?f)
    )
  )

  (:action do_not_overwrite_file_and_do_not_fail
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
      (not (file_copied ?f))
    )
    :effect (and
      (file_copied ?f)
    )
  )

  (:action create_hard_link_instead_of_copying
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (not (file_exists ?dst))
    )
    :effect (and
      (file_linked_to ?src ?dst)
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
    :parameters (?f - file ?attr - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_has_attributes ?f ?attr)
    )
  )

  (:action update_files
    :parameters (?actor - user ?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dest)
      (can_escalate ?actor)
    )
    :effect (and
      (file_replaced ?src ?dest)
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
    :parameters (?f - file ?contents - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_contents_equal ?f {contents})
    )
  )

  (:action set_security_context
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (security_context_set ?f)
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

  (:action delete_file_recursive
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (not (is_directory ?dir))
      (can_escalate ?actor)
    )
    :effect (and
      (directory_removed ?dir)
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
      (file_system_matches ?f)
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
      (file_system_matches ?f)
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
      (file_system_matches ?f)
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
    :parameters (?actor - user ?f - file ?o - user ?g - group)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?o)
      (file_grouped_as ?g)
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

  (:action set_verbose_mode
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (verbose_mode true)
    )
  )

  (:action set_silent_mode
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (silent_mode true)
    )
  )

  (:action set_dereference_mode
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (dereference_mode true)
    )
  )

  (:action set_no_dereference_mode
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (no_dereference_mode true)
    )
  )

  (:action preserve_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (current_directory == '/')
      (can_escalate ?actor)
    )
    :effect (and
      (operation_aborted)
    )
  )

  (:action recursive_traversal
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (current_directory != '/')
      (can_escalate ?actor)
    )
    :effect (and
      (directory_traversed)
    )
  )

  (:action follow_symbolic_links
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (current_directory != '/')
      (can_escalate ?actor)
    )
    :effect (and
      (symbolic_link_followed)
    )
  )

  (:action skip_symbolic_links
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (current_directory != '/')
      (can_escalate ?actor)
    )
    :effect (and
      (symbolic_link_skipped)
    )
  )

  (:action fail_recursive_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (is_root)
      (can_escalate ?actor)
    )
    :effect (and
      (operation_failed)
    )
  )

  (:action reference_ownership
    :parameters (?actor - user ?r - file)
    :precondition (and
      (file_exists ?r)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?o ?f)
      (file_grouped_by ?g ?f)
    )
  )

  (:action recursive_operation
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (operation_recursive)
    )
  )

  (:action traverse_symbolic_links
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (symbolic_link_traversed ?f)
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
    :parameters (?actor - user ?f - file)
    :precondition (and
      (not (protocol_family_set ?f))
      (other_args_insufficient)
      (can_escalate ?actor)
    )
    :effect (and
      (protocol_family_set ?f)
    )
  )

  (:action set_output_format
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (output_format_set ?f)
    )
  )

  (:action resolve_dns_names
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (dns_names_resolved ?f)
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

  (:action set_socket_buffer_size
    :parameters (?actor - user ?size - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (socket_receive_buffer_size ?size)
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

  (:action set_output_format_json
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (output_format_json)
    )
  )

  (:action set_output_format_pretty
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (output_format_pretty)
    )
  )

  (:action send_kernel_configuration
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (kernel_configuration_sent)
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

  (:action modify_system_state
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (object_exists ?obj)
      (not (system_state_modified ?obj))
      (can_escalate ?actor)
    )
    :effect (and
      (system_state_modified ?obj)
    )
  )

  (:action hide_header
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (header_hidden)
    )
  )

  (:action resolve_numeric_addresses
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (numeric_addresses_resolved)
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

  (:action create_firewall_rule
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (rule_not_exists ?rule)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_exists ?rule)
    )
  )

  (:action set_host_syntax
    :parameters (?family - file)
    :precondition (and
      (host_syntax_supported ?family)
      (address_valid ?address)
      (port_valid ?port)
    )
    :effect (and
      (host_syntax_set ?family
      ?address
      ?port)
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

  (:action run_command_as_user
    :parameters (?actor - user ?cmd - file ?user - user)
    :precondition (and
      (user_permitted ?user)
      (security_policy_permits ?user ?cmd)
      (can_escalate ?actor)
    )
    :effect (and
      (command_executed ?cmd ?user)
    )
  )

  (:action update_credentials
    :parameters (?obj - file)
    :precondition (and
      (cached_credentials_available)
      (sudo_running)
    )
    :effect (and
      (credentials_updated)
    )
  )

  (:action edit_policy
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (security_policy_configured)
      (visudo_available)
      (can_escalate ?actor)
    )
    :effect (and
      (policy_updated)
    )
  )

  (:action log_attempts
    :parameters (?obj - file)
    :precondition (and
      (security_policy_configured)
      (audit_plugin_available)
    )
    :effect (and
      (attempts_logged)
    )
  )

  (:action log_io
    :parameters (?obj - file)
    :precondition (and
      (io_plugin_available)
      (sudo_running)
    )
    :effect (and
      (input_output_logged)
    )
  )

  (:action edit_config
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (sudo_available)
      (askpass_program_available)
      (can_escalate ?actor)
    )
    :effect (and
      (sudo_config_updated)
    )
  )

  (:action set_bell_option
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (sudo_available)
      (askpass_program_available)
      (can_escalate ?actor)
    )
    :effect (and
      (bell_option_set)
    )
  )

  (:action run_background
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (sudo_available)
      (askpass_program_available)
      (can_escalate ?actor)
    )
    :effect (and
      (command_run_in_background)
    )
  )

  (:action remove_temp_file
    :parameters (?obj - file)
    :precondition (and
      (file_exists ?f)
      (temporary ?f)
    )
    :effect (and
      (file_removed ?f)
    )
  )

  (:action enforce_restrictions
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (file_exists ?f)
      (symbolic_link ?f)
      (writable_directory ?d
      ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (restricted ?f
      ?u)
    )
  )

  (:action forbid_device_editing
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (file_exists ?f)
      (device_special_file ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (editing_forbidden ?f)
    )
  )

  (:action set_environment_variables
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (environment_variables_set ?env)
    )
  )

  (:action reset_timestamp_file
    :parameters (?actor - user ?file - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (timestamp_invalidated ?f)
    )
  )

  (:action set_non_interactive_mode
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (mode_set ?m)
    )
  )

  (:action preserve_group_vector
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_vector_preserved ?g)
    )
  )

  (:action set_password_prompt
    :parameters (?actor - user ?prompt - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (password_prompt_set ?p)
    )
  )

  (:action chroot_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (root_directory_changed ?d)
    )
  )

  (:action set_selinux_role
    :parameters (?actor - user ?role - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (SELinux_role_set ?r)
    )
  )

  (:action read_password_from_stdin
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (password_read ?p)
    )
  )

  (:action run_shell_as_target_user
    :parameters (?actor - user ?cmd - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (shell_run ?u
      ?c)
    )
  )

  (:action set_selinux_type
    :parameters (?actor - user ?type - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (SELinux_type_set ?t)
    )
  )

  (:action terminate_process
    :parameters (?pid - process)
    :precondition (and
    )
    :effect (and
      (process_terminated ?pid)
    )
  )

  (:action run_as_user
    :parameters (?user - user)
    :precondition (and
    )
    :effect (and
      (command_run_as_user ?user)
    )
  )

  (:action update_timestamp
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (timestamp_updated)
    )
  )

  (:action stop_processing
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (processing_stopped)
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
      (not (terminal_shared))
    )
    :effect (and
      (terminal_independent)
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
      (not (--preserve-environment))
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

  (:action override_defaults
    :parameters (?actor - user ?key=value - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (defaults_overridden ?key ?value)
    )
  )

  (:action skip_log_init
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_not_in_log ?)
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
      (not (system_user_exists ?user))
      (password_policy_respected)
      (can_escalate ?actor)
    )
    :effect (and
      (system_user_exists ?user)
      (no_aging_info_in_shadow ?user)
    )
  )

  (:action setup_mail_spool
    :parameters (?actor - user ?usr - user ?dir - directory ?file - file)
    :precondition (and
      (user_exists ?usr)
      (dir_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_created ?usr ?dir ?file)
    )
  )

  (:action set_max_members_per_group
    :parameters (?actor - user ?num - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (max_members_per_group ?num)
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
      (not (password_expiration_set ?days))
      (can_escalate ?actor)
    )
    :effect (and
      (password_expiration_set ?days)
    )
  )

  (:action set_minimum_password_change_interval
    :parameters (?actor - user ?days - file)
    :precondition (and
      (not (minimum_password_change_set ?days))
      (can_escalate ?actor)
    )
    :effect (and
      (minimum_password_change_set ?days)
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

  (:action allocate_subordinate_uids
    :parameters (?actor - user ?uid - file ?count - file)
    :precondition (and
      (file_exists /etc/subuid)
      (not (user_has_subordinate_uids ?uid))
      (can_escalate ?actor)
    )
    :effect (and
      (user_has_subordinate_uids ?uid)
    )
  )

  (:action set_default_subordinate_uids_values
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_SUB_UID_MIN 100000)
      (default_SUB_UID_MAX 600100000)
      (default_SUB_UID_COUNT 65536)
    )
  )

  (:action set_default_system_gid_values
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_SYS_GID_MIN 101)
      (default_SYS_GID_MAX {GID_MIN-1})
    )
  )

  (:action set_default_system_uid_values
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_SYS_UID_MIN 101)
      (default_SYS_UID_MAX {UID_MIN-1})
    )
  )

  (:action set_default_uid_values
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_UID_MIN 1000)
      (default_UID_MAX 60000)
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
      (duplicate_names_allowed)
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

  (:action update_user_account
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (user_modified ?usr)
    )
  )

  (:action update_user_comment
    :parameters (?actor - user ?usr - user ?cmnt - file)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (user_comment_updated ?usr ?cmnt)
    )
  )

  (:action update_user_home_directory
    :parameters (?actor - user ?usr - user ?hmdir - directory)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (user_home_directory_updated ?usr ?hmdir)
    )
  )

  (:action update_user_expire_date
    :parameters (?actor - user ?usr - user ?edate - file)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (user_expire_date_updated ?usr ?edate)
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
    :parameters (?actor - user ?g - group ?g1 - file ?g2 - file ?gn - file)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (not (primary_group_set ?u ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (primary_group_set ?u ?g)
      (group_member ?u ?g1)
      ...
      (group_member ?u ?gn)
    )
  )

  (:action change_user_info
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_login_changed ?u)
      (user_password_locked ?u)
      (user_home_directory_moved ?u)
    )
  )

  (:action lock_user_password
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (not (user_password_locked ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_password_locked ?u)
    )
  )

  (:action move_user_home_directory
    :parameters (?actor - user ?u - user ?d - directory)
    :precondition (and
      (user_exists ?u)
      (not (home_directory_moved ?u))
      (directory_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_moved ?u)
    )
  )

  (:action modify_user
    :parameters (?actor - user ?uid - user ?pw - file)
    :precondition (and
      (user_exists ?uid)
      (not (user_non_unique ?uid))
      (can_escalate ?actor)
    )
    :effect (and
      (user_non_unique ?uid)
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
    :parameters (?actor - user ?range - file)
    :precondition (and
      (group_exists)
      (not (subgids_assigned ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (subgids_assigned ?group)
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
      (not (user_has_subgids ?uid ?rg))
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
      (config_file_exists '/etc/login.defs')
      (can_escalate ?actor)
    )
    :effect (and
      (lastlog_uid_max_updated)
    )
  )

  (:action change_mail_dir
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (config_file_exists '/etc/login.defs')
      (can_escalate ?actor)
    )
    :effect (and
      (mail_dir_updated)
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

  (:action modify_user_account
    :parameters (?actor - user ?uid - user ?gid - group ?groups - file ?expire_date - file ?inactive - file ?lock - file ?login - file ?password - file)
    :precondition (and
      (user_exists ?uid)
      (not (account_locked ?uid))
      (can_escalate ?actor)
    )
    :effect (and
      (account_modified ?uid)
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
      (selinux_enabled)
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (no selinux user mapping for ?u)
    )
  )

  (:action configure_tool
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (tool_not_configured)
      (can_escalate ?actor)
    )
    :effect (and
      (tool configured)
    )
  )

  (:action manage_mail_spool
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_exists ?u)
      (mail_spool_needed)
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool created/updated/deleted for ?u)
    )
  )

  (:action set_group_limit
    :parameters (?actor - user ?num - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_entry_split ?num)
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

  (:action delete_nis_attributes
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (nis_client)
      (nis_attributes_set ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (nis_attributes_removed ?usr)
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

  (:action set_group_id
    :parameters (?actor - user ?gn - group ?GID - file)
    :precondition (and
      (group_exists ?gn)
      (GID >= 0)
      (unique_GID ?gn GID)
      (can_escalate ?actor)
    )
    :effect (and
      (group_ID_set ?gn GID)
    )
  )

  (:action override_group_id
    :parameters (?actor - user ?gn - group ?GID - file)
    :precondition (and
      (group_exists ?gn)
      (GID >= 0)
      (can_escalate ?actor)
    )
    :effect (and
      (group_ID_set ?gn GID)
      (unique_GID ?gn GID)
    )
  )

  (:action set_login_key
    :parameters (?actor - user ?KEY - file ?VALUE - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (login_key_set KEY VALUE)
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

  (:action set_gid_range
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (group_exists ?gid)
      (not (gid_range_set ?gid))
      (can_escalate ?actor)
    )
    :effect (and
      (gid_range_set ?gid)
    )
  )

  (:action set_group_password
    :parameters (?actor - user ?pwd - file)
    :precondition (and
      (group_exists ?gid)
      (not (group_password_set ?gid))
      (can_escalate ?actor)
    )
    :effect (and
      (group_password_set ?gid)
    )
  )

  (:action create_system_group
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (not (group_exists ?gid))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?gid)
    )
  )

  (:action set_sys_gid_range
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (sys_gid_min ?min)
      (sys_gid_max ?max)
    )
  )

)