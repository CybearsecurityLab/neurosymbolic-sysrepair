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

  (:action change_permissions
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_writable ?f)
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
      (package_build_deps ?pkg)
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

  (:action list_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (apt_configured)
      (sources_list_valid)
      (can_escalate ?actor)
    )
    :effect (and
      (package_list_updated)
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
      (not (repository_secure ?repo))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (repository_secure ?repo)
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

  (:action show_progress_during_update
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (update_progress_visible ?repo)
    )
  )

  (:action reinstall_packages
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_up_to_date ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_up_to_date ?pkg)
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
    :parameters (?actor - user ?str - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action clean_package
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
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

  (:action check_dependencies
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (package_installed ?pkg)
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action download_changelog
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (not (changelog_downloaded ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (changelog_downloaded ?pkg)
    )
  )

  (:action edit_sources
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_list_updated ?pkg)
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

  (:action upgrade_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (package_installed ?pkg)
      (not (package_upgraded ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (package_upgraded ?pkg)
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

  (:action process_package_triggers
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
    :parameters (?actor - user ?pkg - package ?dir - directory)
    :precondition (and
      (package_installed ?pkg)
      (not (package_configured ?pkg))
      (can_escalate ?actor)
    )
    :effect (and
      (file_unpacked ?new_files)
      (file_backup ?old_files)
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

  (:action list_available_packages
    :parameters (?pkgs - package)
    :precondition (and
    )
    :effect (and
      (available_package_list ?pkgs)
    )
  )

  (:action install_package_from_archive
    :parameters (?actor - user ?pkg - package ?media - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
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
      (package_selections_set)
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
      (available_packages_info_updated)
    )
  )

  (:action merge_avail
    :parameters (?actor - user ?file - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (available_packages_info_merged)
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

  (:action status_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_status_displayed)
    )
  )

  (:action print_avail
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (available_version_details_displayed)
    )
  )

  (:action listfiles
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (file_list_displayed)
    )
  )

  (:action search_packages
    :parameters (?actor - user ?file - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (package_list_displayed)
    )
  )

  (:action audit_packages
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (broken_package_list_displayed)
    )
  )

  (:action print_packages
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (packages_selected_for_installation)
    )
  )

  (:action print_pre_dependencies
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (pre_dependencies_to_unpack)
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

  (:action print_architecture
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (dpkg_architecture_printed)
    )
  )

  (:action print_foreign_architectures
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (foreign_architectures_printed)
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
    :parameters (?thing - file ?str - file)
    :precondition (and
    )
    :effect (and
      (thing_validated ?thing)
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

  (:action debug_help
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (debugging_help_shown)
    )
  )

  (:action show_help
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (help_message_shown)
    )
  )

  (:action show_version
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (version_shown)
    )
  )

  (:action add_assertion
    :parameters (?actor - user ?assertion - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action abort_change
    :parameters (?actor - user ?change - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action create_alias
    :parameters (?app - file ?alias - file)
    :precondition (and
    )
    :effect (and
      (alias_created ?app ?alias)
    )
  )

  (:action list_aliases
    :parameters (?snap - file)
    :precondition (and
    )
    :effect (and
      (aliases_listed ?snap)
    )
  )

  (:action list_changes
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (changes_listed)
    )
  )

  (:action display_system_changes
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (system_changes_displayed)
    )
  )

  (:action check_snapshot
    :parameters (?snap - file)
    :precondition (and
      (snapshot_exists ?snap)
      (data_integrity_valid ?snap)
    )
    :effect (and
      (data_integrity_valid ?snap)
    )
  )

  (:action connect_plug_to_slot
    :parameters (?snap - interface ?snap - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action list_components
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
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

  (:action list_connections
    :parameters (?snap - package)
    :precondition (and
      (snap_exists ?snap)
    )
    :effect (and
    )
  )

  (:action create_cohort_keys
    :parameters (?snaps - package)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action run_debug_commands
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action execute_raw_query
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action list_snaps
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action find_snap_by_name
    :parameters (?name - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action refresh_snap
    :parameters (?snap - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action switch_snap_channel
    :parameters (?snap - file ?channel - file)
    :precondition (and
    )
    :effect (and
      (snap_channel_switched ?snap ?channel)
    )
  )

  (:action stop_snap_boot_start
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (snap_boot_start_stopped ?snap)
    )
  )

  (:action display_apparmor_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_internal_tool_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_snap_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_feature_tags
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action list_tasks
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action set_snap_dir
    :parameters (?dir - directory)
    :precondition (and
      (dir_exists ?dir)
    )
    :effect (and
    )
  )

  (:action no_wait
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action set_devmode
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
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

  (:action unset_config
    :parameters (?actor - user ?snap - file ?option - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (config_options_removed ?snap ?option)
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

  (:action validate_snap_config
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (snap_config_valid ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_config_valid ?snap)
    )
  )

  (:action monitor_snap_validation
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (snap_config_valid ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_config_valid ?snap)
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

  (:action wait_for_config
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action list_warnings
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action watch_change
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (change_finished ?id)
    )
  )

  (:action get_email
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (email_shown ?user)
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

  (:action get_config
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action set_config
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action list_units
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (systemd_running)
      (can_escalate ?actor)
    )
    :effect (and
      (units_listed)
    )
  )

  (:action load_units
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_state ?state)
      (can_escalate ?actor)
    )
    :effect (and
      (loaded_units ?units)
    )
  )

  (:action list_automounts
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action list_path_units
    :parameters (?actor - user ?pats - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action list_socket_units
    :parameters (?actor - user ?pats - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action list_sockets
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action list_timer_units
    :parameters (?actor - user ?p - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action check_unit_status
    :parameters (?actor - user ?units - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (unit_active ?unit)
    )
  )

  (:action check_unit_status_failed
    :parameters (?actor - user ?units - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (unit_failed ?unit)
    )
  )

  (:action check_system_state
    :parameters (?obj - file)
    :precondition (and
      (no_preconditions)
    )
    :effect (and
      (system_state ?state)
    )
  )

  (:action add_dependency
    :parameters (?actor - user ?target - file ?unit - file)
    :precondition (and
      (unit_exists ?target)
      (unit_exists ?unit)
      (can_escalate ?actor)
    )
    :effect (and
      (dependency_added ?target ?unit)
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

  (:action list_machines
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action list_jobs
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action cancel_jobs
    :parameters (?actor - user ?job - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action show_environment
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action set_environment
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action unset_environment
    :parameters (?var - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action import_environment
    :parameters (?var - file)
    :precondition (and
    )
    :effect (and
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

  (:action set_system_manager
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (system_manager_available)
      (can_escalate ?actor)
    )
    :effect (and
      (connected_to_system_manager)
    )
  )

  (:action set_user_service_manager
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_service_manager_available)
      (can_escalate ?actor)
    )
    :effect (and
      (connected_to_user_service_manager)
    )
  )

  (:action remote_operation
    :parameters (?actor - user ?host - port)
    :precondition (and
      (remote_host_available ?host)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (connected_to_remote_host ?host)
    )
  )

  (:action local_container_operation
    :parameters (?actor - user ?container - file)
    :precondition (and
      (container_available ?container)
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (connected_to_local_container ?container)
    )
  )

  (:action list_units_by_type
    :parameters (?actor - user ?type - file)
    :precondition (and
      (units_available)
      (type_exists ?type)
      (can_escalate ?actor)
    )
    :effect (and
      (listed_units_of_type ?type)
    )
  )

  (:action list_units_by_state
    :parameters (?actor - user ?state - file)
    :precondition (and
      (units_available)
      (state_exists ?state)
      (can_escalate ?actor)
    )
    :effect (and
      (listed_units_of_state ?state)
    )
  )

  (:action list_properties_by_name
    :parameters (?actor - user ?name - file)
    :precondition (and
      (properties_available)
      (name_exists ?name)
      (can_escalate ?actor)
    )
    :effect (and
      (listed_properties_of_name ?name)
    )
  )

  (:action list_all_properties_and_units
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (properties_available)
      (units_available)
      (can_escalate ?actor)
    )
    :effect (and
      (listed_all_properties_and_units)
    )
  )

  (:action list_installed_units
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (units_available)
      (can_escalate ?actor)
    )
    :effect (and
      (listed_installed_units)
    )
  )

  (:action full_output
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (output_available)
      (can_escalate ?actor)
    )
    :effect (and
      (output_not_ellipsized)
    )
  )

  (:action list_units_recursive
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (units_available)
      (host_and_local_containers_available)
      (can_escalate ?actor)
    )
    :effect (and
      (listed_units_recursive)
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

  (:action show_system_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
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

  (:action wait_for_unit_operation
    :parameters (?actor - user ?unit - file)
    :precondition (and
      (unit_exists ?unit)
      (not (unit_running ?unit))
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action set_output_suppression
    :parameters (?bool - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action edit_system_units
    :parameters (?actor - user ?u - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_units_modified ?u)
    )
  )

  (:action edit_system_units_runtime
    :parameters (?actor - user ?u - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_units_modified ?u)
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

  (:action execute_action_immediately
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
    :parameters (?actor - user ?p - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_units_modified ?p)
    )
  )

  (:action edit_system_units_image
    :parameters (?actor - user ?i - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (system_units_modified ?i)
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

  (:action show_journal_entries
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (journal_entries_shown ?n)
    )
  )

  (:action set_journal_output_mode
    :parameters (?actor - user ?mode - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_output_mode ?mode)
    )
  )

  (:action show_firmware_setup_menu
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firmware_setup_menu)
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

  (:action print_unit_dependencies_list
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (unit_dependencies_list)
    )
  )

  (:action set_timestamp_format
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

  (:action query_log_entries
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action add_matches
    :parameters (?fp - file)
    :precondition (and
    )
    :effect (and
      (binary_executable ?fp)
      (script_executable ?fp)
      (device_kernel_device ?fp)
    )
  )

  (:action combine_matches
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action dereference_links
    :parameters (?obj - file)
    :precondition (and
      (environment_valid)
      (device_node_exists)
    )
    :effect (and
    )
  )

  (:action synthesize_kernel_names
    :parameters (?obj - file)
    :precondition (and
      (environment_valid)
      (device_node_exists)
    )
    :effect (and
    )
  )

  (:action identify_parent_devices
    :parameters (?obj - file)
    :precondition (and
      (environment_valid)
      (device_node_exists)
    )
    :effect (and
    )
  )

  (:action restrict_log_entries
    :parameters (?obj - file)
    :precondition (and
      (environment_valid)
      (device_node_exists)
    )
    :effect (and
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

  (:action set_journal_permissions
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

  (:action set_journal_source_options
    :parameters (?system - user)
    :precondition (and
    )
    :effect (and
      (journal_source_options_modified)
    )
  )

  (:action show_messages
    :parameters (?obj - file)
    :precondition (and
      (persistent_logging_enabled)
      (user_can_see_all_messages)
    )
    :effect (and
      (shows_messages)
    )
  )

  (:action show_machine_messages
    :parameters (?machine - file)
    :precondition (and
      (running_local_container ?container)
    )
    :effect (and
      (shows_messages_from_container)
    )
  )

  (:action show_merged_messages
    :parameters (?obj - file)
    :precondition (and
      (persistent_logging_enabled)
      (user_can_see_all_messages)
    )
    :effect (and
      (shows_merged_entries)
    )
  )

  (:action change_journal_directory
    :parameters (?dir - directory)
    :precondition (and
      (persistent_logging_enabled)
      (user_can_see_all_messages)
    )
    :effect (and
      (operates_on_specified_journal_directory)
    )
  )

  (:action show_file_messages
    :parameters (?file - file)
    :precondition (and
      (persistent_logging_enabled)
      (user_can_see_all_messages)
    )
    :effect (and
      (shows_entries_from_glob)
    )
  )

  (:action operate_on_journal_files
    :parameters (?actor - user ?files - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_files_operated ?files)
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

  (:action filter_journal_entries
    :parameters (?expr - file)
    :precondition (and
      (journal_entries_available)
    )
    :effect (and
    )
  )

  (:action show_logs
    :parameters (?filter - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action show_kernel_logs
    :parameters (?boot - file ?filter - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action show_live_logs
    :parameters (?service - file ?filter - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action query_journal
    :parameters (?obj - file)
    :precondition (and
      (journal_available)
    )
    :effect (and
      (journal_query_results ?results)
    )
  )

  (:action set_pager_control_options
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action set_fss_options
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action change_fss_sealing_key
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (fss_sealing_key_changed ?key)
      (fss_verification_key_specified ?key)
      (can_escalate ?actor)
    )
    :effect (and
      (fss_sealing_key_updated ?key)
    )
  )

  (:action display_help_text
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (help_text_displayed)
    )
  )

  (:action display_package_version
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (package_version_displayed)
    )
  )

  (:action list_field_names
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (field_names_listed)
    )
  )

  (:action list_field_values
    :parameters (?FIELD - file)
    :precondition (and
    )
    :effect (and
      (field_values_listed)
    )
  )

  (:action display_boot_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (boot_info_displayed)
    )
  )

  (:action display_disk_usage
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (disk_usage_displayed)
    )
  )

  (:action vacuum_disk_usage
    :parameters (?actor - user ?BYTES - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (disk_usage_reduced)
    )
  )

  (:action vacuum_journal_files
    :parameters (?actor - user ?INT - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_files_vacuumed)
    )
  )

  (:action vacuum_journal_time
    :parameters (?actor - user ?TIME - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_files_vacuumed)
    )
  )

  (:action verify_journal_consistency
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_files_verified)
    )
  )

  (:action sync_journal_messages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (journal_messages_synced)
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

  (:action show_journal_header
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action list_catalog
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action dump_catalog
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action update_catalog
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action setup_keys
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
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
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action debug_copy_file
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action create_hard_link
    :parameters (?f1 - file ?f2 - file)
    :precondition (and
      (file_exists ?f1)
      (file_exists ?f2)
    )
    :effect (and
    )
  )

  (:action follow_symbolic_link
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
    )
  )

  (:action preserve_file_attributes
    :parameters (?f - file ?attr - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
    )
  )

  (:action remove_file_and_retry
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
    )
  )

  (:action prompt_before_overwrite
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
    )
  )

  (:action do_not_overwrite_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
    )
  )

  (:action use_full_source_file_name
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
    )
    :effect (and
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

  (:action create_symbolic_link
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (dir_exists ?dst)
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
      (selinux_security_context_set ?f)
    )
  )

  (:action stay_on_file_system
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action set_sparse_creation
    :parameters (?none - file)
    :precondition (and
    )
    :effect (and
      (sparse_files_not_created)
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
      (lightweight_copy_performed)
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
    :parameters (?link - file)
    :precondition (and
      (file_exists ?link)
    )
    :effect (and
    )
  )

  (:action explain_copy
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action do_not_dereference_link
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action link_files
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (not (file_exists ?dst))
    )
    :effect (and
      (file_exists ?dst)
      (file_contents_equal ?src ?dst)
    )
  )

  (:action always_dereference_link
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action explain_copy_debug
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action set_sparse_file_control
    :parameters (?w - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action set_clone_control
    :parameters (?w - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action set_persistent_attributes
    :parameters (?a - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action unset_persistent_attributes
    :parameters (?a - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action strip_trailing_slashes
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action set_full_source_file_name
    :parameters (?d - directory)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action set_no_follow_symbolic_links
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action set_persistent_mode_ownership_timestamps
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action recursive_copy
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action set_clone_control_recursive
    :parameters (?w - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action remove_destination_file_forceless
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
    )
  )

  (:action create_symbolic_link_recursive
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
    :parameters (?actor - user ?f - file ?attr - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (has_attribute ?f ?attr)
    )
  )

  (:action update_files
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (file_exists ?f)
      (update_operation ?op)
      (can_escalate ?actor)
    )
    :effect (and
      (file_updated ?f
      ?op)
    )
  )

  (:action make_backup
    :parameters (?src - file ?dst - file)
    :precondition (and
      (file_exists ?src)
      (equal ?src ?dst)
      (regular_file ?src)
    )
    :effect (and
      (backup_created ?src)
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

  (:action move_files
    :parameters (?directory - directory ?sources - file)
    :precondition (and
    )
    :effect (and
      (files moved)
    )
  )

  (:action set_file_type
    :parameters (?dest - file)
    :precondition (and
    )
    :effect (and
      (file type set)
    )
  )

  (:action verbose_mode
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (verbose mode enabled)
    )
  )

  (:action set_security_context
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (security context set)
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

  (:action update_permissions
    :parameters (?f - file ?mode - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_executable ?f)
    )
  )

  (:action display_help
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (help_displayed)
    )
  )

  (:action display_version
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (version_displayed)
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

  (:action force_delete_file
    :parameters (?file - file)
    :precondition (and
      (file_exists ?f)
      (not (directory ?f))
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

  (:action remove_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_removed ?f)
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

  (:action set_silent_mode
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (silent_mode)
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

  (:action change_ownership_reference
    :parameters (?actor - user ?f - file ?r - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?r)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?o ?f)
      (file_grouped_by ?g ?f)
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

  (:action traverse_directory
    :parameters (?obj - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (directory_traversed ?dir)
    )
  )

  (:action follow_symbolic_links
    :parameters (?obj - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (symbolic_link_followed ?dir)
    )
  )

  (:action skip_symbolic_links
    :parameters (?obj - file)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
      (symbolic_link_skipped ?dir)
    )
  )

  (:action change_ownership_recursive
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
    :parameters (?actor - user ?o - user ?g - group ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
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

  (:action traverse_symbolic_links
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
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

  (:action print_message
    :parameters (?dir - directory)
    :precondition (and
      (directory_exists ?dir)
    )
    :effect (and
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

  (:action set_time
    :parameters (?f - file ?t - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_times_set ?f ?t)
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

  (:action add_firewall_rule
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?rule)
    )
  )

  (:action modify_firewall_rule
    :parameters (?actor - user ?rule - firewall_rule ?chain - file ?rulenum - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_exists ?rule)
    )
  )

  (:action delete_firewall_rule
    :parameters (?actor - user ?rule - firewall_rule ?chain - file ?rulenum - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (firewall_rule_exists ?rule))
    )
  )

  (:action list_firewall_rules
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action flush_firewall_rules
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action zero_firewall_rules
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action create_firewall_chain
    :parameters (?actor - user ?chain - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_chain_exists ?chain)
    )
  )

  (:action delete_firewall_chain
    :parameters (?actor - user ?chain - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (not (firewall_chain_exists ?chain))
    )
  )

  (:action set_firewall_policy
    :parameters (?actor - user ?chain - file ?target - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_policy_set ?chain ?target)
    )
  )

  (:action rename_firewall_chain
    :parameters (?actor - user ?old-chain - file ?new-chain - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_chain_renamed ?old-chain ?new-chain)
    )
  )

  (:action configure_firewall
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (table_exists ?t)
      (chain_exists ?c)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_added ?r)
    )
  )

  (:action set_table
    :parameters (?table - file)
    :precondition (and
    )
    :effect (and
      (table_set ?table)
    )
  )

  (:action list_tables
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (tables_listed)
    )
  )

  (:action consult_table
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action alter_packets
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (packet_exists ?p)
      (chain_matches ?c ?p)
      (can_escalate ?actor)
    )
    :effect (and
      (packet_altered ?p
      ?c)
    )
  )

  (:action configure_exemptions
    :parameters (?actor - user ?table - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (exemptions_configured ?)
    )
  )

  (:action register_hooks
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (hooks_registered ?)
    )
  )

  (:action configure_mac_rules
    :parameters (?actor - user ?table - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (mac_rules_configured ?)
    )
  )

  (:action implement_mac
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (mac_implemented ?)
    )
  )

  (:action configure_chains
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (chains_configured ?)
    )
  )

  (:action append_rules
    :parameters (?actor - user ?chain - file ?rule-specification - file)
    :precondition (and
      (chain_exists ?chain)
      (not (rules_appended_to ?chain))
      (can_escalate ?actor)
    )
    :effect (and
      (rules_appended_to ?chain)
    )
  )

  (:action insert_firewall_rule
    :parameters (?actor - user ?chain - file ?rule - file ?num - file)
    :precondition (and
      (rule_exists ?rule)
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_inserted ?rule)
      (chain_updated ?chain)
    )
  )

  (:action check_firewall_rule
    :parameters (?actor - user ?chain - file ?rule - file)
    :precondition (and
      (rule_exists ?rule)
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action replace_firewall_rule
    :parameters (?actor - user ?rulenum - file ?rule_specification - file)
    :precondition (and
      (rule_exists ?rulenum)
      (chain_selected)
      (can_escalate ?actor)
    )
    :effect (and
      (rule_replaced ?rulenum)
    )
  )

  (:action list_firewall_rules_verbose
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (rules_listed ?rulenum)
      (can_escalate ?actor)
    )
    :effect (and
      (rules_listed ?rulenum)
    )
  )

  (:action save_firewall_rules
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (rules_listed ?rulenum)
      (can_escalate ?actor)
    )
    :effect (and
      (rules_saved ?rulenum)
    )
  )

  (:action lock_file
    :parameters (?obj - file)
    :precondition (and
      (file_locked ?f)
      (not (exclusive_lock_held ?f))
    )
    :effect (and
      (exclusive_lock_held ?f)
    )
  )

  (:action display_numeric_output
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (numeric_output ?o)
    )
  )

  (:action display_exact_values
    :parameters (?obj - file)
    :precondition (and
      (packet_counter ?c)
      (byte_counter ?b)
    )
    :effect (and
      (exact_packet_counter ?c)
      (exact_byte_counter ?b)
    )
  )

  (:action display_line_numbers
    :parameters (?obj - file)
    :precondition (and
      (rule_list ?r)
    )
    :effect (and
      (line_numbers_displayed ?l)
    )
  )

  (:action load_modules
    :parameters (?cmd - file)
    :precondition (and
      (rule_addition ?r)
      (rule_insertion ?i)
    )
    :effect (and
      (modules_loaded ?m)
    )
  )

  (:action write_man_page
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action update_iptables
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action manage_firewall_rule
    :parameters (?actor - user ?rule - firewall_rule)
    :precondition (and
      (firewall_rule_exists ?rule)
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_rule_inserted ?rule
      ?chain) or (firewall_rule_deleted ?rule
      ?chain)
    )
  )

  (:action set_firewall_target
    :parameters (?actor - user ?chain - interface ?target - file)
    :precondition (and
      (firewall_chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (firewall_target_set ?chain
      ?target)
    )
  )

  (:action flush_rules
    :parameters (?actor - user ?chain - firewall_rule)
    :precondition (and
      (rules_exist ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (no_rules ?chain)
    )
  )

  (:action zero_counters
    :parameters (?actor - user ?chain - firewall_rule ?rulenum - file)
    :precondition (and
      (counters_exist ?chain ?rulenum)
      (can_escalate ?actor)
    )
    :effect (and
      (counters_zeroed ?chain ?rulenum)
    )
  )

  (:action create_chain
    :parameters (?actor - user ?chain - file)
    :precondition (and
      (no_chain ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (chain_created ?chain)
    )
  )

  (:action delete_chain
    :parameters (?actor - user ?chain - file)
    :precondition (and
      (chain_exists ?chain)
      (can_escalate ?actor)
    )
    :effect (and
      (no_chain ?chain)
    )
  )

  (:action change_policy
    :parameters (?actor - user ?chain - file ?target - file)
    :precondition (and
      (chain_exists ?chain)
      (policy_target_valid ?target)
      (can_escalate ?actor)
    )
    :effect (and
      (policy_changed ?chain ?target)
    )
  )

  (:action rename_chain
    :parameters (?actor - user ?old_chain - file ?new_chain - file)
    :precondition (and
      (chain_exists ?old_chain)
      (new_chain_valid ?new_chain)
      (can_escalate ?actor)
    )
    :effect (and
      (no_chain ?new_chain)
      (chain_renamed ?old_chain ?new_chain)
    )
  )

  (:action list_rules
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (rules_printed)
    )
  )

  (:action set_counters
    :parameters (?actor - user ?PKTS - file ?BYTES - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (counter_set ?PKTS ?BYTES)
    )
  )

  (:action insert_module
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (module_inserted ?command)
    )
  )

  (:action set_counter
    :parameters (?actor - user ?PKTS - file ?BYTES - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (counter_set ?PKTS ?BYTES)
    )
  )

  (:action insert_rule
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (rule_inserted ?command)
    )
  )

  (:action insert_chain
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (chain_inserted ?command)
    )
  )

  (:action display_socket_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (socket_info_available)
    )
  )

  (:action display_socket_details
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (socket_details_available)
    )
  )

  (:action hide_header
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (header_suppressed)
    )
  )

  (:action one_line_output
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (output_one_line)
    )
  )

  (:action no_resolve
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (service_names_not_resolved)
    )
  )

  (:action resolve_addresses
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (addresses_resolved)
    )
  )

  (:action display_all_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (all_sockets_displayed)
    )
  )

  (:action show_socket_memory_usage
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action show_socket_memory_usage_details
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action show_socket_memory_usage_details_rmem_alloc
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action show_socket_memory_usage_details_rcv_buf
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action show_socket_memory_usage_details_wmem_alloc
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action show_socket_memory_usage_details_snd_buf
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action show_socket_memory_usage_details_fwd_alloc
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action show_socket_memory_usage_details_wmem_queued
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action set_network_options
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
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

  (:action print_summary
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (summary_printed)
    )
  )

  (:action show_tos_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (tos_info_shown)
    )
  )

  (:action show_cgroup_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (cgroup_info_shown)
    )
  )

  (:action show_tipc_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (tipc_info_shown)
    )
  )

  (:action test_match
    :parameters (?host - file ?op - file ?family - file ?port - port)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action compare_port
    :parameters (?op - file ?family - file ?port - port)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action match_device
    :parameters (?actor - user ?dev - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action match_fwmark
    :parameters (?actor - user ?fwmark - firewall_rule)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action match_cgroup
    :parameters (?actor - user ?cgroup - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action match_autobound
    :parameters (?actor - user ?autobound - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
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

  (:action configure_network_link
    :parameters (?actor - user ?addr - file ?port - port)
    :precondition (and
      (network_link_exists ?addr ?port)
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action list_sockets_with_security_contexts
    :parameters (?proto - file ?security_contexts - file)
    :precondition (and
    )
    :effect (and
      (sockets_displayed ?)
    )
  )

  (:action list_processes
    :parameters (?src - file)
    :precondition (and
    )
    :effect (and
      (processes_displayed ?)
    )
  )

  (:action list_listening_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (listening_socket_list_displayed)
    )
  )

  (:action show_timer_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (timer_info_displayed)
    )
  )

  (:action show_extended_socket_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (extended_socket_info_displayed)
    )
  )

  (:action show_memory_usage
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (memory_usage_displayed)
    )
  )

  (:action show_process_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (process_info_displayed)
    )
  )

  (:action show_thread_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (thread_info_displayed)
    )
  )

  (:action show_tcp_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (tcp_info_displayed)
    )
  )

  (:action show_tipc_socket_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (tipc_socket_info_displayed)
    )
  )

  (:action show_summary
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (summary_displayed)
    )
  )

  (:action display_socket_events
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_security_contexts
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_task_and_socket_security_contexts
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action switch_network_namespace
    :parameters (?ns - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_ipv4_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_ipv6_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_packet_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_tcp_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_mptcp_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_sctp_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_udp_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_dccp_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_raw_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_unix_domain_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_tipc_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_vsock_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_xdp_sockets
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action run_command_as_user
    :parameters (?actor - user ?cmd - file ?user - user)
    :precondition (and
      (user_permitted ?user)
      (security_policy_satisfied)
      (can_escalate ?actor)
    )
    :effect (and
      (command_executed ?cmd
      ?user)
    )
  )

  (:action edit_file_as_user
    :parameters (?actor - user ?f - file ?user - user)
    :precondition (and
      (user_permitted ?user)
      (security_policy_satisfied)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (file_modified ?f
      ?user)
    )
  )

  (:action edit_sudoers
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (sudo_config_exists)
      (no_syntax_errors)
      (can_escalate ?actor)
    )
    :effect (and
      (sudo_config_updated)
    )
  )

  (:action run_command_with_sudo
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (sudo_config_valid)
      (user_authenticated)
      (can_escalate ?actor)
    )
    :effect (and
      (command_executed)
    )
  )

  (:action update_cached_credentials
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (cached_credentials_available)
      (user_authenticated)
      (can_escalate ?actor)
    )
    :effect (and
      (credentials_updated)
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

  (:action close_file_descriptors
    :parameters (?actor - user ?num - file)
    :precondition (and
      (security_policy_permits_closefrom_override)
      (user_has_permission_to_use_option)
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action change_directory
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (user_has_permission_to_specify_working_directory)
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action preserve_environment_variables
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action preserve_environment
    :parameters (?actor - user ?env - file)
    :precondition (and
      (user_permitted_to_preserve_env)
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action edit_files
    :parameters (?actor - user ?files - file)
    :precondition (and
      (user_authorized_by_policy)
      (files_to_edit)
      (can_escalate ?actor)
    )
    :effect (and
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
      (symbolic_link ?f)
      (writable_directory ?d)
      (user_not_root ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (editing_denied ?f)
    )
  )

  (:action forbid_device_editing
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (device_special_file ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (editing_denied ?f)
    )
  )

  (:action edit_and_install_file
    :parameters (?f - file ?temp_f - file)
    :precondition (and
      (not (file_exists ?temp_f))
    )
    :effect (and
      (file_exists ?f)
      (file_contents_changed ?f)
    )
  )

  (:action set_group
    :parameters (?g - group)
    :precondition (and
    )
    :effect (and
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

  (:action run_as_group
    :parameters (?actor - user ?g - group)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action set_home_variable
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action display_help_message
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action run_on_host
    :parameters (?actor - user ?h - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action run_login_shell
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action remove_timestamp_file
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action preserve_user_environment
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action ring_bell
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action reset_timestamp_file
    :parameters (?actor - user ?f - file)
    :precondition (and
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (timestamp_invalidated ?f)
    )
  )

  (:action list_privileges
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (privileges_listed ?)
    )
  )

  (:action set_non_interactive_mode
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (non_interactive_mode_set ?)
    )
  )

  (:action preserve_group_vector
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_vector_preserved ?)
    )
  )

  (:action set_password_prompt
    :parameters (?actor - user ?p - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (password_prompt_set ?p)
    )
  )

  (:action chroot_directory
    :parameters (?actor - user ?d - directory)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (root_directory_changed ?d)
    )
  )

  (:action set_selinux_role
    :parameters (?actor - user ?r - file)
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
      (password_read ?)
    )
  )

  (:action run_shell_as_target_user
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (shell_run ?)
    )
  )

  (:action set_selinux_type
    :parameters (?actor - user ?t - file)
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

  (:action list_user_privileges
    :parameters (?user - user)
    :precondition (and
    )
    :effect (and
      (privileges_displayed ?user)
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

  (:action display_version_info
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (version_info_displayed)
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

  (:action stop_processing_args
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (args_stopped)
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

  (:action pass_command_to_shell
    :parameters (?actor - user ?cmd - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action set_fast_mode
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action add_supplementary_group
    :parameters (?actor - user ?sg - group)
    :precondition (and
      (user_is_root)
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action login_shell
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
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
    :parameters (?cmd - file)
    :precondition (and
    )
    :effect (and
      (session_cmd_set ?cmd)
    )
  )

  (:action whitelist_environment
    :parameters (?list - file)
    :precondition (and
    )
    :effect (and
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
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (set_to_yes)
      (not (--login))
      (not (--preserve-environment))
      (can_escalate ?actor)
    )
    :effect (and
      (path_initialized)
    )
  )

  (:action update_user_defaults
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action set_user_comment
    :parameters (?actor - user ?user - user ?comment - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_comment ?user ?comment)
    )
  )

  (:action set_user_expire_date
    :parameters (?actor - user ?user - user ?expire_date - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_expire_date ?user ?expire_date)
    )
  )

  (:action add_user
    :parameters (?actor - user ?u - user ?e - file)
    :precondition (and
      (not (user_exists ?u))
      (default_expiry_date)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (user_expires_at ?e)
    )
  )

  (:action update_group
    :parameters (?actor - user ?g - group ?u - user)
    :precondition (and
      (group_exists ?g)
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action update_subuids_and_subgids
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action override_defaults
    :parameters (?actor - user ?key=value - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action skip_log_init
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
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

  (:action skip_home_creation
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_exists ?u)
      (not (CREATE_HOME))
      (can_escalate ?actor)
    )
    :effect (and
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

  (:action create_mail_spool
    :parameters (?actor - user ?usr - user ?dir - directory)
    :precondition (and
      (user_exists ?usr)
      (dir_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_created ?usr ?dir)
    )
  )

  (:action set_max_members_per_group
    :parameters (?actor - user ?num - file)
    :precondition (and
      (max_members_per_group_defined)
      (can_escalate ?actor)
    )
    :effect (and
      (max_members_per_group_set ?num)
    )
  )

  (:action add_group_entry
    :parameters (?actor - user ?g - group)
    :precondition (and
      (not (group_line_reached ?g))
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (group_line_reached ?g)
      (group_updated ?g)
    )
  )

  (:action set_password_max_days
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (not (password_max_days_set))
      (can_escalate ?actor)
    )
    :effect (and
      (password_max_days_set)
      (max_password_age ?x)
    )
  )

  (:action set_password_min_days
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (not (password_min_days_set))
      (can_escalate ?actor)
    )
    :effect (and
      (password_min_days_set)
      (min_password_age ?x)
    )
  )

  (:action set_system_settings
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action set_password_expiration_warning
    :parameters (?actor - user ?days - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (password_expires ?x
      ?y)
    )
  )

  (:action set_subordinate_group_id_range
    :parameters (?actor - user ?min - file ?max - file ?count - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (subgroup_ids_set ?x
      ?y
      ?z)
    )
  )

  (:action set_subordinate_user_id_range
    :parameters (?actor - user ?min - file ?max - file ?count - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (subuser_ids_set ?x
      ?y
      ?z)
    )
  )

  (:action allocate_user_ids
    :parameters (?actor - user ?count - file ?min - file ?max - file)
    :precondition (and
      (file_exists /etc/subuid)
      (not (user_has_subordinate_user_ids ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (allocated_user_ids ?user)
    )
  )

  (:action allocate_system_user_ids
    :parameters (?actor - user ?count - file ?min - file ?max - file)
    :precondition (and
      (not (user_has_subordinate_user_ids ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (allocated_system_user_ids ?user)
    )
  )

  (:action allocate_system_group_ids
    :parameters (?actor - user ?count - file ?min - file ?max - file)
    :precondition (and
      (not (group_has_subordinate_group_ids ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (allocated_system_group_ids ?group)
    )
  )

  (:action set_umask
    :parameters (?actor - user ?num - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action remove_group
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (group_empty ?group)
      (user_member_of ?user ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (group_removed ?group)
    )
  )

  (:action set_default_values
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action run_scripts
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action add_subids
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_exists ?u)
      (not (subid_entries_added ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (subid_entries_added ?u)
    )
  )

  (:action set_groups
    :parameters (?actor - user ?groups - file)
    :precondition (and
      (user_exists ?u)
      (not (supplementary_groups_set ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (supplementary_groups_set ?u)
    )
  )

  (:action create_home
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_exists ?u)
      (not (home_directory_created ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_created ?u)
    )
  )

  (:action no_create_home
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_exists ?u)
      (home_directory_created ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (not (home_directory_created ?u))
    )
  )

  (:action no_user_group
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?g))
    )
  )

  (:action non_unique
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_exists ?u)
      (not (unique_names ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (unique_names ?u)
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
      (user_comment ?u ?c)
    )
  )

  (:action change_home_directory
    :parameters (?actor - user ?h - directory ?u - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_home ?u ?h)
    )
  )

  (:action update_expire_date
    :parameters (?actor - user ?e - file ?u - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (user_expires ?u ?e)
    )
  )

  (:action set_account_expiration_date
    :parameters (?actor - user ?date - file)
    :precondition (and
      (file_exists /etc/shadow)
      (can_escalate ?actor)
    )
    :effect (and
      (account_expired ?date)
    )
  )

  (:action set_account_inactive_days
    :parameters (?actor - user ?days - file)
    :precondition (and
      (file_exists /etc/shadow)
      (can_escalate ?actor)
    )
    :effect (and
      (account_inactive ?days)
    )
  )

  (:action change_groups
    :parameters (?actor - user ?g - group ?g1 - file ?g2 - file)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (not (primary_group_of ?u ?g))
      (can_escalate ?actor)
    )
    :effect (and
      (primary_group_of ?u ?g)
      (member_of ?u ?g1)
      (member_of ?u ?g2)
      ...
    )
  )

  (:action append_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_group ?u ?g)
    )
  )

  (:action change_login_name
    :parameters (?actor - user ?o - file ?n - file)
    :precondition (and
      (user_exists ?o)
      (can_escalate ?actor)
    )
    :effect (and
      (user_login_name ?n)
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

  (:action move_home_directory
    :parameters (?actor - user ?o - file ?n - file)
    :precondition (and
      (user_exists ?o)
      (directory_exists ?n)
      (can_escalate ?actor)
    )
    :effect (and
      (user_home_directory ?n)
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
      (user_password_set ?pw)
    )
  )

  (:action remove_user_from_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (user_not_in_group ?u ?g)
    )
  )

  (:action change_user_shell
    :parameters (?actor - user ?u - user ?s - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_login_shell ?u ?s)
    )
  )

  (:action change_user_id
    :parameters (?actor - user ?u - user ?i - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (user_id ?u ?i)
    )
  )

  (:action prefix_directory
    :parameters (?actor - user ?p - directory)
    :precondition (and
      (directory_exists ?p)
      (can_escalate ?actor)
    )
    :effect (and
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

  (:action add_subordinate_uids
    :parameters (?actor - user ?uids - file)
    :precondition (and
      (user_exists)
      (not (subordinate_uids_assigned ?uids))
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uids_assigned ?uids)
    )
  )

  (:action remove_subordinate_uids
    :parameters (?actor - user ?uids - file)
    :precondition (and
      (user_exists)
      (subordinate_uids_assigned ?uids)
      (can_escalate ?actor)
    )
    :effect (and
      (not (subordinate_uids_assigned ?uids))
    )
  )

  (:action add_subordinate_gids
    :parameters (?actor - user ?gids - file)
    :precondition (and
      (user_exists)
      (not (subordinate_gids_assigned ?gids))
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gids_assigned ?gids)
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
      (lastlog_uid_max_changed)
    )
  )

  (:action change_mail_dir
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (config_file_exists '/etc/login.defs')
      (can_escalate ?actor)
    )
    :effect (and
      (mail_dir_changed)
    )
  )

  (:action set_variable
    :parameters (?var - file ?value - file)
    :precondition (and
    )
    :effect (and
      (variable_set ?var ?value)
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
      (configuration_needed)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (tool configured)
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

  (:action run_user_deletion_script
    :parameters (?actor - user ?cmd - file ?user - user)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
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

  (:action exit_with_value
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
    )
  )

  (:action check_file_systems
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (user_removed ?usr)
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action delete_nis_attributes
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_removed ?usr)
      (nis_client)
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

  (:action delete_group
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_removed ?usr)
      (group_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
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
    :parameters (?actor - user ?g - group ?GID - file)
    :precondition (and
      (group_exists ?g)
      (GID >= 0)
      (can_escalate ?actor)
    )
    :effect (and
      (group_GID_set ?g
      ?GID)
    )
  )

  (:action set_group_key
    :parameters (?actor - user ?KEY - file ?VALUE - file)
    :precondition (and
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (group_key_set ?g
      {KEY}
      {VALUE})
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
      (GID_MAX ?x)
      (GID_MIN ?y)
    )
  )

  (:action set_sys_gids
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (SYS_GID_MAX ?x)
      (SYS_GID_MIN ?y)
    )
  )

  (:action list_group_members
    :parameters (?g - group ?u - user)
    :precondition (and
      (group_exists ?g)
      (user_in_group ?u ?g)
    )
    :effect (and
    )
  )

  (:action use_extra_users_db
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
    )
  )

)