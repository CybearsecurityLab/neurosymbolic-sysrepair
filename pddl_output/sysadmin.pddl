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
    (package_info_updated)
    (packages_upgraded)
    (packages_full_upgraded)
    (removed_unnecessary_packages)
    (package_version ?x0 - object ?x1 - object)
    (package_config_exists ?x0 - object)
    (package_from_release ?x0 - object ?x1 - object)
    (dependencies_satisfied ?x0 - object)
    (conflicts_handled ?x0 - object)
    (sources_list_updated)
    (source_downloaded ?x0 - object)
    (build_dependencies_installed ?x0 - object)
    (package_downloaded ?x0 - object)
    (packages_cleaned_up)
    (packages_distcleaned_up)
    (packages_autocleaned_up)
    (system_upgraded)
    (sources_list_edited)
    (package_reverted ?x0 - object)
    (package_enabled ?x0 - object)
    (assertion_valid ?x0 - object)
    (signature_verified ?x0 - object)
    (assertion_in_database ?x0 - object)
    (snap_application_exists ?x0 - object)
    (alias_created ?x0 - object)
    (snap_installed ?x0 - object)
    (plug_connected ?x0 - object ?x1 - object ?x2 - object ?x3 - object)
    (snap_exists ?x0 - object)
    (snap_connected ?x0 - object ?x1 - object)
    (cohort_keys_created)
    (feature_tags_retrieved)
    (lsm_info_retrieved)
    (snaps_migrated)
    (stacktraces_obtained)
    (state_inspected)
    (snap_in_cohort ?x0 - object ?x1 - object)
    (directory_exists ?x0 - object)
    (snap_in_development_mode ?x0 - object)
    (security_confinement_disabled ?x0 - object)
    (security_confinement_enabled ?x0 - object)
    (snap_in_classic_mode ?x0 - object)
    (aliases_removed ?x0 - object)
    (config_removed ?x0 - object)
    (config_pending)
    (configuration_complete)
    (warnings_listed)
    (warnings_silenced)
    (snaps_refreshed)
    (snap_channel_switched ?x0 - object ?x1 - object)
    (change_pending ?x0 - object)
    (change_aborted ?x0 - object)
    (connected ?x0 - object ?x1 - object)
    (configuration_exists ?x0 - object)
    (configuration_value_set ?x0 - object ?x1 - object)
    (alias_exists ?x0 - object)
    (user_logged_in)
    (snapshot_exists ?x0 - object)
    (restored_from_snapshot ?x0 - object)
    (device_rebooted ?x0 - object ?x1 - object)
    (warnings_exist)
    (no_warnings)
    (assertion_added ?x0 - object ?x1 - object)
    (snap_tested ?x0 - object)
    (assertion_signed ?x0 - object)
    (device_image_prepared ?x0 - object)
    (cryptographic_key_exported ?x0 - object)
    (quota_group_exists ?x0 - object)
    (owned_by_user ?x0 - object ?x1 - object)
    (owned_by_group ?x0 - object ?x1 - object)
    (file_grouped_by ?x0 - object ?x1 - object)
    (root_not_preserved)
    (root_preserved)
    (recursion_enabled)
    (symbolic_link_traversal_enabled)
    (all_symbolic_link_traversal_enabled)
    (symbolic_link_traversal_disabled)
    (owned_by ?x0 - object ?x1 - object)
    (group_owned_by ?x0 - object ?x1 - object)
    (same_owner_as_reference ?x0 - object ?x1 - object)
    (same_group_as_reference ?x0 - object ?x1 - object)
    (file_owner ?x0 - object ?x1 - object ?x2 - object)
    (file_group ?x0 - object ?x1 - object ?x2 - object)
    (if ?x0 - object ?x1 - object)
    (directory_mode_set ?x0 - object)
    (directory_has_default_selinux_context ?x0 - object)
    (directory_has_custom_security_context ?x0 - object)
    (file_times_set ?x0 - object)
    (timestamp_updated ?x0 - object)
    (file_access_time_changed ?x0 - object)
    (file_modification_time_changed ?x0 - object)
    (file_access_time_copied ?x0 - object ?x1 - object)
    (file_modification_time_copied ?x0 - object ?x1 - object)
    (file_access_time_set_by_stamp ?x0 - object)
    (file_modification_time_set_by_stamp ?x0 - object)
    (file_time_type_changed ?x0 - object)
    (file_modified_at ?x0 - object ?x1 - object)
    (resource_limits_reset ?x0 - object)
    (primary_group_of_user ?x0 - object ?x1 - object)
    (supplementary_group_of_user ?x0 - object ?x1 - object)
    (shell_is_login ?x0 - object)
    (environment_preserved ?x0 - object)
    (path_initialized ?x0 - object)
    (pam_configured ?x0 - object)
    (service_updated ?x0 - object)
    (default_user_info_updated)
    (account_expires_on ?x0 - object ?x1 - object)
    (home_directory_set ?x0 - object ?x1 - object)
    (user_comment_set ?x0 - object ?x1 - object)
    (password_inactive_period_set ?x0 - object ?x1 - object)
    (subuids_updated ?x0 - object)
    (primary_group_set ?x0 - object ?x1 - object)
    (member_of_group ?x0 - object ?x1 - object)
    (home_directory_created ?x0 - object)
    (login_defs_overridden ?x0 - object)
    (no_lastlog_faillog_entry ?x0 - object)
    (lastlog_entry_exists ?x0 - object)
    (faillog_entry_exists ?x0 - object)
    (home_directory_exists ?x0 - object)
    (files_copied_from_skeleton ?x0 - object ?x1 - object)
    (user_in_group ?x0 - object ?x1 - object)
    (user_has_uid ?x0 - object ?x1 - object)
    (user_has_password ?x0 - object)
    (account_locked ?x0 - object)
    (password_invalid ?x0 - object)
    (password_valid ?x0 - object)
    (no_aging_info ?x0 - object)
    (user_belongs_to_group ?x0 - object ?x1 - object)
    (subuid_updated_for_user ?x0 - object)
    (subgid_updated_for_user ?x0 - object)
    (changes_applied_in_chroot_dir ?x0 - object ?x1 - object)
    (changes_applied_in_prefix_dir ?x0 - object ?x1 - object)
    (user_shell_set ?x0 - object ?x1 - object)
    (user_has_seuser ?x0 - object ?x1 - object)
    (default_base_directory_set ?x0 - object)
    (directory_mode ?x0 - object ?x1 - object)
    (group_id_min_set ?x0 - object)
    (group_id_max_set ?x0 - object)
    (create_home_set ?x0 - object)
    (home_mode_set ?x0 - object)
    (lastlog_uid_max_set ?x0 - object)
    (mail_spool_directory_set ?x0 - object)
    (mail_file_location_set ?x0 - object)
    (user_modified ?x0 - object)
    (group_max_members_set ?x0 - object ?x1 - object)
    (password_max_days_set ?x0 - object ?x1 - object)
    (password_min_days_set ?x0 - object ?x1 - object)
    (password_warn_age_set ?x0 - object ?x1 - object)
    (subordinate_gid_range_set ?x0 - object ?x1 - object ?x2 - object)
    (sys_gid_range_valid ?x0 - object ?x1 - object)
    (system_group_created ?x0 - object ?x1 - object ?x2 - object)
    (sys_uid_range_valid ?x0 - object ?x1 - object)
    (system_user_created ?x0 - object ?x1 - object ?x2 - object)
    (uid_range_valid ?x0 - object ?x1 - object)
    (regular_user_created ?x0 - object ?x1 - object ?x2 - object)
    (default_umask ?x0 - object)
    (script_executed ?x0 - object)
    (default_user_settings_configured)
    (bad_names_allowed)
    (home_directory_is_btrfs_subvolume)
    (gecos_field_set ?x0 - object)
    (account_has_expiration_date ?x0 - object)
    (subuid_entry_added ?x0 - object ?x1 - object)
    (no_user_group_created ?x0 - object)
    (unique_user ?x0 - object)
    (non_unique_user_created ?x0 - object)
    (groups_exist ?x0 - object)
    (supplementary_groups_set ?x0 - object ?x1 - object)
    (skeleton_directory_set ?x0 - object ?x1 - object)
    (logged_in ?x0 - object)
    (no_log_init ?x0 - object)
    (password_set ?x0 - object)
    (chrooted_into ?x0 - object)
    (selinux_user_mapped ?x0 - object)
    (extra_users_enabled)
    (password_grace_period_set ?x0 - object ?x1 - object)
    (password_locked ?x0 - object)
    (home_directory_moved ?x0 - object)
    (ownership_changed ?x0 - object ?x1 - object)
    (modes_copied ?x0 - object)
    (acl_copied ?x0 - object)
    (extended_attributes_copied ?x0 - object)
    (uid_set_non_unique ?x0 - object ?x1 - object)
    (password_unlocked ?x0 - object)
    (uid_equal ?x0 - object ?x1 - object)
    (owner_equal ?x0 - object ?x1 - object)
    (user_expire_date_set ?x0 - object ?x1 - object)
    (subordinate_uid_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_uid_removed ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gid_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gid_range_removed ?x0 - object ?x1 - object ?x2 - object)
    (selinux_user_removed ?x0 - object)
    (file_owned_by_user ?x0 - object ?x1 - object)
    (file_executable ?x0 - object)
    (max_members_reached ?x0 - object)
    (new_group_entry ?x0 - object)
    (subordinate_gids_allocated ?x0 - object)
    (subordinate_uids_allocated ?x0 - object)
    (password_inactivated_after ?x0 - object ?x1 - object)
    (login_name_set_to ?x0 - object ?x1 - object)
    (home_directory_set_to ?x0 - object ?x1 - object)
    (user_shell ?x0 - object ?x1 - object)
    (user_uid ?x0 - object ?x1 - object)
    (subordinate_uids_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_uids_removed ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gids_added ?x0 - object ?x1 - object ?x2 - object)
    (subordinate_gids_removed ?x0 - object ?x1 - object ?x2 - object)
    (mail_spool_exists ?x0 - object)
    (system_config_updated ?x0 - object)
    (mailbox_exists ?x0 - object)
    (mailbox_action ?x0 - object)
    (scripts_executed ?x0 - object)
    (process_running_by_user ?x0 - object)
    (primary_group_used_elsewhere ?x0 - object)
    (sys_gid_min ?x0 - object)
    (sys_gid_max ?x0 - object)
    (gid_available ?x0 - object)
    (assigned_gid ?x0 - object ?x1 - object)
    (group_creation_failed)
    (using_extra_users_db)
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
      (package_info_updated)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_full_upgraded)
      (removed_unnecessary_packages)
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
      (packages_upgraded)
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
      (not (package_config_exists ?pkg))
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

  (:action satisfy_dependencies
    :parameters (?actor - user ?deps - file ?conflicts - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (dependencies_satisfied ?deps)
      (conflicts_handled ?conflicts)
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

  (:action download_package
    :parameters (?pkg - package)
    :precondition (and
      (network_available)
    )
    :effect (and
      (package_downloaded ?pkg)
    )
  )

  (:action clean_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_cleaned_up)
    )
  )

  (:action distclean_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_distcleaned_up)
    )
  )

  (:action autoclean_packages
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (packages_autocleaned_up)
    )
  )

  (:action manage_package
    :parameters (?actor - user ?pkg - package)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?pkg)
      (not (package_installed ?pkg))
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

  (:action edit_sources_list
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (sources_list_edited)
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

  (:action add_assertion
    :parameters (?actor - user ?assertion - file)
    :precondition (and
      (file_exists ?assertion)
      (assertion_valid ?assertion)
      (signature_verified ?assertion)
      (can_escalate ?actor)
    )
    :effect (and
      (assertion_in_database ?assertion)
    )
  )

  (:action create_alias
    :parameters (?snap_app - file ?alias - file)
    :precondition (and
      (snap_application_exists ?snap_app)
    )
    :effect (and
      (alias_created ?alias)
    )
  )

  (:action connect_plug_to_slot
    :parameters (?actor - user ?snap1 - file ?plug - interface ?snap2 - file ?slot - interface)
    :precondition (and
      (snap_installed ?snap1)
      (snap_installed ?snap2)
      (can_escalate ?actor)
    )
    :effect (and
      (plug_connected ?snap1 ?plug ?snap2 ?slot)
    )
  )

  (:action connect_snap_plug
    :parameters (?actor - user ?snap - file ?plug - interface)
    :precondition (and
      (snap_exists ?snap)
      (interface_exists ?plug)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_connected ?snap ?plug)
    )
  )

  (:action create_cohort_keys
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (cohort_keys_created)
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

  (:action obtain_stacktraces
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (service_running snapd)
      (can_escalate ?actor)
    )
    :effect (and
      (stacktraces_obtained)
    )
  )

  (:action inspect_state_file
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (file_exists snapd_state)
      (can_escalate ?actor)
    )
    :effect (and
      (state_inspected)
    )
  )

  (:action install_from_candidate_channel
    :parameters (?actor - user ?snap - package)
    :precondition (and
      (not (package_installed ?snap))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?snap)
    )
  )

  (:action switch_cohort
    :parameters (?actor - user ?snap - package ?cohort - file)
    :precondition (and
      (package_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_in_cohort ?snap ?cohort)
    )
  )

  (:action leave_cohort
    :parameters (?actor - user ?snap - package)
    :precondition (and
      (package_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (not (snap_in_cohort ?snap))
    )
  )

  (:action install_snap_for_test
    :parameters (?actor - user ?snap_package - package ?snap_dir - directory)
    :precondition (and
      (directory_exists ?snap_dir)
      (not (package_installed ?snap_package))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?snap_package)
    )
  )

  (:action try_no_wait
    :parameters (?actor - user ?snap_package - package ?snap_dir - directory)
    :precondition (and
      (directory_exists ?snap_dir)
      (not (package_installed ?snap_package))
      (can_escalate ?actor)
    )
    :effect (and
      (package_installed ?snap_package)
    )
  )

  (:action set_snap_development_mode
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_in_development_mode ?snap)
      (security_confinement_disabled ?snap)
    )
  )

  (:action set_snap_enforced_confinement_mode
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (security_confinement_enabled ?snap)
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
      (security_confinement_disabled ?snap)
    )
  )

  (:action unalias_snap
    :parameters (?actor - user ?snap - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (aliases_removed ?snap)
    )
  )

  (:action unset_snap_config
    :parameters (?actor - user ?snap - file ?config_option - file)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (config_removed ?snap)
    )
  )

  (:action wait_for_configuration
    :parameters (?obj - file)
    :precondition (and
      (config_pending)
    )
    :effect (and
      (configuration_complete)
    )
  )

  (:action silence_warnings
    :parameters (?obj - file)
    :precondition (and
      (warnings_listed)
    )
    :effect (and
      (warnings_silenced)
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
    :parameters (?actor - user ?snap - file ?channel - directory)
    :precondition (and
      (snap_installed ?snap)
      (can_escalate ?actor)
    )
    :effect (and
      (snap_channel_switched ?snap ?channel)
    )
  )

  (:action abort_change
    :parameters (?actor - user ?change_id - directory)
    :precondition (and
      (change_pending ?change_id)
      (can_escalate ?actor)
    )
    :effect (and
      (change_aborted ?change_id)
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
    :parameters (?plug - interface ?slot - interface)
    :precondition (and
      (interface_exists ?plug)
      (interface_exists ?slot)
    )
    :effect (and
      (connected ?plug ?slot)
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

  (:action set_configuration_option
    :parameters (?option - file ?value - file)
    :precondition (and
      (configuration_exists ?option)
    )
    :effect (and
      (configuration_value_set ?option ?value)
    )
  )

  (:action unset_configuration_option
    :parameters (?option - file)
    :precondition (and
      (configuration_value_set ?option)
    )
    :effect (and
      (not (configuration_value_set ?option))
    )
  )

  (:action remove_alias
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
      (network_available)
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
      (restored_from_snapshot ?snap)
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
    :parameters (?actor - user ?system - interface ?mode - interface)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (device_rebooted ?system ?mode)
    )
  )

  (:action okay_warnings
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (warnings_exist)
      (can_escalate ?actor)
    )
    :effect (and
      (no_warnings)
    )
  )

  (:action ack_assertion
    :parameters (?actor - user ?assert_type - interface ?assert_value - interface)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (assertion_added ?assert_type ?assert_value)
    )
  )

  (:action download_snap
    :parameters (?snap - file)
    :precondition (and
      (not (snap_installed ?snap))
      (network_available)
    )
    :effect (and
      (snap_installed ?snap)
    )
  )

  (:action try_snap
    :parameters (?snap - file)
    :precondition (and
      (not (snap_installed ?snap))
    )
    :effect (and
      (snap_tested ?snap)
    )
  )

  (:action sign_assertion
    :parameters (?assert - file)
    :precondition (and
      (not (assertion_signed ?assert))
    )
    :effect (and
      (assertion_signed ?assert)
    )
  )

  (:action prepare_device_image
    :parameters (?image - file)
    :precondition (and
      (not (device_image_prepared ?image))
    )
    :effect (and
      (device_image_prepared ?image)
    )
  )

  (:action export_cryptographic_key
    :parameters (?key - file)
    :precondition (and
      (not (cryptographic_key_exported ?key))
    )
    :effect (and
      (cryptographic_key_exported ?key)
    )
  )

  (:action set_quota_group
    :parameters (?actor - user ?group - file)
    :precondition (and
      (not (quota_group_exists ?group))
      (can_escalate ?actor)
    )
    :effect (and
      (quota_group_exists ?group)
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
    :parameters (?target - file)
    :precondition (and
      (file_exists ?target)
    )
    :effect (and
      (not (file_exists ?target))
    )
  )

  (:action remove_directory_recursively
    :parameters (?dir - directory)
    :precondition (and
      (interface_exists ?dir)
    )
    :effect (and
      (not (interface_exists ?dir))
    )
  )

  (:action force_remove_file_or_directory
    :parameters (?target - file)
    :precondition (and
    )
    :effect (and
      (not (file_exists ?target))
    )
  )

  (:action force_remove_directory_recursively
    :parameters (?dir - directory)
    :precondition (and
    )
    :effect (and
      (not (interface_exists ?dir))
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

  (:action remove_file_interactive_once
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

  (:action remove_directory_recursive_one_file_system
    :parameters (?d - directory)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (not (directory_exists ?d))
    )
  )

  (:action remove_directory_recursive_no_preserve_root
    :parameters (?actor - user ?d - directory)
    :precondition (and
      (directory_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (not (directory_exists ?d))
    )
  )

  (:action remove_directory_recursive_preserve_root
    :parameters (?actor - user ?d - directory ?mode - file)
    :precondition (and
      (directory_exists ?d)
      (can_escalate ?actor)
    )
    :effect (and
      (not (directory_exists ?d))
    )
  )

  (:action remove_directory_recursive
    :parameters (?d - directory)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (not (directory_exists ?d))
    )
  )

  (:action remove_empty_directory
    :parameters (?d - directory)
    :precondition (and
      (directory_exists ?d)
    )
    :effect (and
      (not (directory_exists ?d))
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

  (:action interactive_remove_multiple_files
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
    )
  )

  (:action interactive_remove_file_with_when
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

  (:action shred_file
    :parameters (?f - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (not (file_exists ?f))
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
    :parameters (?actor - user ?f - file ?ref_file - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?ref_file)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_chown_file_reference)
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

  (:action change_group
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

  (:action change_ownership_and_group_with_dereference
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

  (:action change_ownership_and_group_without_dereferencing
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

  (:action change_owner_group
    :parameters (?actor - user ?f - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?f)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by ?f ?owner)
      (file_grouped_by ?f ?group)
    )
  )

  (:action disable_preserve_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (root_not_preserved)
    )
  )

  (:action enable_preserve_root
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (root_preserved)
    )
  )

  (:action set_reference_owner_group
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_set_reference_owner_group)
    )
  )

  (:action operate_recursively
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (recursion_enabled)
    )
  )

  (:action traverse_symbolic_links_to_directories
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (symbolic_link_traversal_enabled)
    )
  )

  (:action traverse_all_symbolic_links_to_directories
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (all_symbolic_link_traversal_enabled)
    )
  )

  (:action do_not_traverse_symbolic_links_to_directories
    :parameters (?obj - file)
    :precondition (and
    )
    :effect (and
      (symbolic_link_traversal_disabled)
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
      (group_owned_by ?f ?group)
    )
  )

  (:action change_owner_recursive
    :parameters (?actor - user ?owner - user ?f - directory)
    :precondition (and
      (user_exists ?owner)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by ?f ?owner)
    )
  )

  (:action change_ownership
    :parameters (?actor - user ?file - file ?owner - user ?group - group)
    :precondition (and
      (file_exists ?file)
      (user_exists ?owner)
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (owned_by_user ?file ?owner)
      (owned_by_group ?file ?group)
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

  (:action use_reference_file_ownership
    :parameters (?actor - user ?f - file ?rfile - file)
    :precondition (and
      (file_exists ?f)
      (file_exists ?rfile)
      (can_escalate ?actor)
    )
    :effect (and
      (action_completed_use_reference_file_ownership)
    )
  )

  (:action change_ownership_if_match
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
      (if file_owner ?f)
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
      (directory_mode_set ?dir)
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
      (not (directory_exists ?dir))
    )
    :effect (and
      (directory_has_default_selinux_context ?dir)
    )
  )

  (:action set_custom_security_context
    :parameters (?dir - directory ?ctx - file)
    :precondition (and
      (not (directory_exists ?dir))
    )
    :effect (and
      (directory_has_custom_security_context ?dir)
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

  (:action set_file_time_reference
    :parameters (?src - file ?tgt - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?tgt)
    )
    :effect (and
      (file_times_set ?tgt)
    )
  )

  (:action set_file_time_stamp
    :parameters (?f - file ?stamp - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_times_set ?f)
    )
  )

  (:action set_file_time_attribute
    :parameters (?f - file ?attribute - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_times_set ?f)
    )
  )

  (:action set_file_time_date_string
    :parameters (?f - file ?date - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_times_set ?f)
    )
  )

  (:action update_timestamps
    :parameters (?f - file)
    :precondition (and
      (not (exists ?f id_- file))
    )
    :effect (and
      (timestamp_updated ?f)
    )
  )

  (:action create_empty_file
    :parameters (?f - file)
    :precondition (and
      (not (file_exists ?f id_- file))
    )
    :effect (and
      (file_exists ?f)
      (timestamp_updated ?f)
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
    :parameters (?src - file ?dest - file)
    :precondition (and
      (file_exists ?src)
      (file_exists ?dest)
    )
    :effect (and
      (file_access_time_copied ?dest ?src)
      (file_modification_time_copied ?dest ?src)
    )
  )

  (:action set_file_times_with_stamp
    :parameters (?f - file ?stamp - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_access_time_set_by_stamp ?f)
      (file_modification_time_set_by_stamp ?f)
    )
  )

  (:action set_file_access_or_modification_time
    :parameters (?f - file ?time_type - file)
    :precondition (and
      (file_exists ?f)
    )
    :effect (and
      (file_time_type_changed ?f)
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

  (:action configure_pam_for_su
    :parameters (?actor - user ?config - file ?svc - service)
    :precondition (and
      (file_exists ?config)
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (configures ?config ?svc)
    )
  )

  (:action switch_user_with_runuser
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (process_running ?cmd)
    )
  )

  (:action switch_user_with_setpriv
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (process_running ?cmd)
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
    )
  )

  (:action fast_mode_with_su
    :parameters (?user - user ?cmd - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (process_running ?cmd)
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

  (:action initialize_path
    :parameters (?user - user)
    :precondition (and
      (can_escalate ?user)
    )
    :effect (and
      (path_initialized ?user)
    )
  )

  (:action configure_pam_lastlog
    :parameters (?actor - user ?config - file ?svc - service)
    :precondition (and
      (file_exists ?config)
      (service_exists ?svc)
      (can_escalate ?actor)
    )
    :effect (and
      (pam_configured ?config)
      (service_updated ?svc)
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
    )
  )

  (:action update_default_user_info
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (default_user_info_updated)
    )
  )

  (:action expire_user_account
    :parameters (?actor - user ?user - user ?expire_date - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (account_expires_on ?user ?expire_date)
    )
  )

  (:action set_home_directory
    :parameters (?actor - user ?user - user ?home_dir - directory)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_set ?user ?home_dir)
    )
  )

  (:action set_user_comment
    :parameters (?actor - user ?user - user ?comment - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_comment_set ?user ?comment)
    )
  )

  (:action set_password_inactivity_period
    :parameters (?actor - user ?u - user ?inactive - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (password_inactive_period_set ?u ?inactive)
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
    :parameters (?actor - user ?usr - user ?grp - group)
    :precondition (and
      (user_exists ?usr)
      (group_exists ?grp)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of_group ?usr ?grp)
    )
  )

  (:action create_user_with_home
    :parameters (?actor - user ?u - user ?skel_dir - directory)
    :precondition (and
      (not (user_exists ?u))
      (directory_exists ?skel_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (home_directory_created ?u)
    )
  )

  (:action create_user_with_override
    :parameters (?actor - user ?u - user ?key_value - file)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (login_defs_overridden ?key_value)
    )
  )

  (:action create_user_no_log_init
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?u)
      (no_lastlog_faillog_entry ?u)
    )
  )

  (:action reset_user_logs
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (lastlog_entry_exists ?user))
      (not (faillog_entry_exists ?user))
    )
  )

  (:action create_home_directory
    :parameters (?actor - user ?user - user ?skeleton_dir - directory)
    :precondition (and
      (not (home_directory_exists ?user))
      (directory_exists ?skeleton_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_exists ?user)
      (files_copied_from_skeleton ?user ?skeleton_dir)
    )
  )

  (:action skip_home_directory_creation
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (home_directory_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (not (home_directory_exists ?user))
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
      (user_has_password ?user)
    )
  )

  (:action create_system_account
    :parameters (?actor - user ?user - user ?password - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (account_locked ?user)
    )
  )

  (:action ensure_password_policy_compliance
    :parameters (?password - file)
    :precondition (and
      (not (password_invalid ?password))
    )
    :effect (and
      (password_valid ?password)
    )
  )

  (:action create_system_account_with_no_aging_info
    :parameters (?actor - user ?user - user ?password - file)
    :precondition (and
      (not (user_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (account_locked ?user)
      (no_aging_info ?user)
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
      (directory_exists ?dir)
      (user_belongs_to_group ?user ?group)
    )
  )

  (:action create_system_account_with_home_directory_and_update_subuids
    :parameters (?actor - user ?user - user ?group - group ?dir - directory)
    :precondition (and
      (not (user_exists ?user))
      (group_exists ?group)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (directory_exists ?dir)
      (user_belongs_to_group ?user ?group)
      (subuid_updated_for_user ?user)
      (subgid_updated_for_user ?user)
    )
  )

  (:action apply_changes_in_chroot_dir
    :parameters (?actor - user ?chroot_dir - directory ?cmd - file)
    :precondition (and
      (directory_exists ?chroot_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_chroot_dir ?cmd ?chroot_dir)
    )
  )

  (:action apply_changes_to_config_files_under_prefix_dir
    :parameters (?actor - user ?prefix_dir - directory ?cmd - file)
    :precondition (and
      (directory_exists ?prefix_dir)
      (can_escalate ?actor)
    )
    :effect (and
      (changes_applied_in_prefix_dir ?cmd ?prefix_dir)
    )
  )

  (:action set_user_shell
    :parameters (?user - user ?shell - file)
    :precondition (and
      (user_exists ?user)
      (file_exists ?shell)
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
      (can_escalate ?user)
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
      (can_escalate ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_exists ?user)
      (user_has_seuser ?user ?seuser)
    )
  )

  (:action update_default_user_values
    :parameters (?actor - user ?base_dir - directory)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_base_directory_set ?base_dir)
    )
  )

  (:action set_home_directory_mode
    :parameters (?actor - user ?dir - directory ?mode - file)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (directory_mode ?dir mode)
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

  (:action set_group_id_range
    :parameters (?actor - user ?min - file ?max - file)
    :precondition (and
      (not (group_id_min_set ?min))
      (not (group_id_max_set ?max))
      (can_escalate ?actor)
    )
    :effect (and
      (group_id_min_set ?min)
      (group_id_max_set ?max)
    )
  )

  (:action set_create_home_behavior
    :parameters (?actor - user ?behavior - file)
    :precondition (and
      (not (create_home_set ?behavior))
      (can_escalate ?actor)
    )
    :effect (and
      (create_home_set ?behavior)
    )
  )

  (:action set_home_mode
    :parameters (?actor - user ?mode - file)
    :precondition (and
      (not (home_mode_set ?mode))
      (can_escalate ?actor)
    )
    :effect (and
      (home_mode_set ?mode)
    )
  )

  (:action configure_lastlog_uid_max
    :parameters (?actor - user ?max_id - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (lastlog_uid_max_set ?max_id)
    )
  )

  (:action set_mail_spool_directory
    :parameters (?actor - user ?dir - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (mail_spool_directory_set ?dir)
    )
  )

  (:action set_mail_file_location
    :parameters (?actor - user ?file - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (mail_file_location_set ?file)
    )
  )

  (:action modify_user
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (user_modified ?usr)
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
    :parameters (?actor - user ?max - file ?grp - group)
    :precondition (and
      (group_exists ?grp)
      (can_escalate ?actor)
    )
    :effect (and
      (group_max_members_set ?grp ?max)
    )
  )

  (:action set_password_max_days
    :parameters (?actor - user ?usr - user ?days - file)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (password_max_days_set ?usr ?days)
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
      (subordinate_gid_range_set ?min ?max ?count)
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

  (:action set_default_umask
    :parameters (?actor - user ?umask - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (default_umask umask)
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
    )
  )

  (:action remove_user_group
    :parameters (?actor - user ?u - user ?g - group)
    :precondition (and
      (user_exists ?u)
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?g))
    )
  )

  (:action execute_useradd_scripts
    :parameters (?actor - user ?u - user ?s - file)
    :precondition (and
      (user_exists ?u)
      (file_exists ?s)
      (can_escalate ?actor)
    )
    :effect (and
      (script_executed ?s)
    )
  )

  (:action configure_default_user_settings
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (default_user_settings_configured)
    )
  )

  (:action allow_bad_names
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (bad_names_allowed)
    )
  )

  (:action set_base_directory_for_home
    :parameters (?actor - user ?base_dir - directory)
    :precondition (and
      (not (directory_exists ?base_dir))
      (can_escalate ?actor)
    )
    :effect (and
      (directory_exists ?base_dir)
    )
  )

  (:action use_btrfs_subvolume_for_home
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_is_btrfs_subvolume)
    )
  )

  (:action set_gecos_field
    :parameters (?actor - user ?login - user ?comment - file)
    :precondition (and
      (user_exists ?login)
      (can_escalate ?actor)
    )
    :effect (and
      (gecos_field_set ?login)
    )
  )

  (:action set_account_expiration_date
    :parameters (?actor - user ?login - user ?expire_date - file)
    :precondition (and
      (user_exists ?login)
      (can_escalate ?actor)
    )
    :effect (and
      (account_has_expiration_date ?login)
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
      (subuid_entry_added ?user ?group)
    )
  )

  (:action skip_user_group_creation
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (group_exists ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (no_user_group_created ?user)
    )
  )

  (:action create_duplicate_users
    :parameters (?actor - user ?user - user ?group - group)
    :precondition (and
      (not (unique_user ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (non_unique_user_created ?user)
    )
  )

  (:action set_supplementary_groups
    :parameters (?actor - user ?user - user ?groups - file)
    :precondition (and
      (user_exists ?user)
      (groups_exist ?groups)
      (can_escalate ?actor)
    )
    :effect (and
      (supplementary_groups_set ?user ?groups)
    )
  )

  (:action set_skeleton_directory
    :parameters (?actor - user ?skel_dir - directory ?user - user)
    :precondition (and
      (directory_exists ?skel_dir)
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (skeleton_directory_set ?user ?skel_dir)
    )
  )

  (:action skip_log_init
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (logged_in ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (no_log_init ?user)
    )
  )

  (:action set_shell
    :parameters (?user - user ?shell - file)
    :precondition (and
      (user_exists ?user)
    )
    :effect (and
      (user_shell_set ?user)
    )
  )

  (:action set_password
    :parameters (?actor - user ?user - user ?password - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_set ?user)
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

  (:action set_selinux_user_mapping
    :parameters (?actor - user ?user - user ?seuser - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_user_mapped ?user)
    )
  )

  (:action enable_extra_users_database
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (extra_users_enabled)
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

  (:action set_password_grace_period
    :parameters (?actor - user ?user - user ?grace_days - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_grace_period_set ?user ?grace_days)
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

  (:action rename_user
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
      (home_directory_moved ?user)
    )
  )

  (:action modify_user_properties
    :parameters (?actor - user ?u - user ?f - file)
    :precondition (and
      (user_exists ?u)
      (file_exists ?f)
      (can_escalate ?actor)
    )
    :effect (and
      (ownership_changed ?f ?u)
      (modes_copied ?f)
      (acl_copied ?f)
      (extended_attributes_copied ?f)
    )
  )

  (:action set_non_unique_uid
    :parameters (?actor - user ?u - user ?uid - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (uid_set_non_unique ?u ?uid)
    )
  )

  (:action set_user_password
    :parameters (?actor - user ?u - user ?encrypted_password - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (password_set ?u)
    )
  )

  (:action unlock_user_password
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (not (password_unlocked ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (password_unlocked ?user)
    )
  )

  (:action change_user_id
    :parameters (?actor - user ?user - user ?new_uid - file)
    :precondition (and
      (user_exists ?user)
      (not (uid_equal ?user ?new_uid))
      (can_escalate ?actor)
    )
    :effect (and
      (uid_equal ?user ?new_uid)
    )
  )

  (:action change_file_ownership
    :parameters (?actor - user ?file - file ?new_owner - user)
    :precondition (and
      (file_exists ?file)
      (not (owner_equal ?file ?new_owner))
      (can_escalate ?actor)
    )
    :effect (and
      (owner_equal ?file ?new_owner)
    )
  )

  (:action change_home_directory_ownership
    :parameters (?actor - user ?user - user ?home_dir - directory)
    :precondition (and
      (directory_exists ?home_dir)
      (not (owner_equal ?home_dir ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (owner_equal ?home_dir ?user)
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

  (:action add_subordinate_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uid_added ?user ?first ?last)
    )
  )

  (:action remove_subordinate_uids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uid_removed ?user ?first ?last)
    )
  )

  (:action add_subordinate_gids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gid_added ?user ?first ?last)
    )
  )

  (:action remove_subordinate_gids
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gid_range_removed ?user ?first ?last)
    )
  )

  (:action remove_selinux_user_mapping
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (selinux_user_removed ?user)
    )
  )

  (:action change_owner_crontab_at_jobs
    :parameters (?actor - user ?user - user ?file - file)
    :precondition (and
      (file_exists ?file)
      (can_escalate ?actor)
    )
    :effect (and
      (file_owned_by_user ?file ?user)
    )
  )

  (:action modify_user_details
    :parameters (?actor - user ?user - user)
    :precondition (and
      (not (process_running ?user))
      (can_escalate ?actor)
    )
    :effect (and
      (user_modified)
    )
  )

  (:action modify_user_account
    :parameters (?actor - user ?u - user ?m - file)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (file_executable ?m)
    )
  )

  (:action add_group_member
    :parameters (?actor - user ?g - group ?u - user)
    :precondition (and
      (group_exists ?g)
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (member_of_group ?u ?g)
    )
  )

  (:action split_group_entry
    :parameters (?actor - user ?g - group ?u - user)
    :precondition (and
      (member_of_group ?u ?g)
      (max_members_reached ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (new_group_entry ?g)
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
      (user_exists ?user)
      (not (subordinate_uids_allocated ?user))
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

  (:action set_password_inactive_after_expiration
    :parameters (?actor - user ?user - user ?inactive_days - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (password_inactivated_after user inactive_days)
    )
  )

  (:action set_login_name
    :parameters (?actor - user ?user - user ?new_login - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (login_name_set_to user new_login)
    )
  )

  (:action move_home_directory_contents
    :parameters (?actor - user ?user - user ?new_location - directory)
    :precondition (and
      (user_exists ?user)
      (home_directory_set_to user new_location)
      (can_escalate ?actor)
    )
    :effect (and
      (home_directory_moved user new_location)
    )
  )

  (:action remove_user_from_groups
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
    :parameters (?actor - user ?user - user ?new_uid - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_uid ?user ?new_uid)
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

  (:action add_subordinate_uids_range
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uids_added ?user ?first ?last)
    )
  )

  (:action remove_subordinate_uids_range
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_uids_removed ?user ?first ?last)
    )
  )

  (:action add_subordinate_gids_range
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gids_added ?user ?first ?last)
    )
  )

  (:action remove_subordinate_gids_range
    :parameters (?actor - user ?user - user ?first - file ?last - file)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (subordinate_gids_removed ?user ?first ?last)
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
    )
  )

  (:action force_delete_user_account
    :parameters (?actor - user ?user - user)
    :precondition (and
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?user))
      (not (home_directory_exists ?user))
      (not (mail_spool_exists ?user))
    )
  )

  (:action remove_user
    :parameters (?actor - user ?usr - user ?grp - group)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (user_exists ?usr))
    )
  )

  (:action chroot_apply_changes
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (system_config_updated ?dir)
    )
  )

  (:action prefix_apply_changes
    :parameters (?actor - user ?dir - directory)
    :precondition (and
      (directory_exists ?dir)
      (can_escalate ?actor)
    )
    :effect (and
      (system_config_updated ?dir)
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

  (:action manage_mailbox
    :parameters (?user - user ?action - file)
    :precondition (and
      (user_exists ?user)
      (mailbox_exists ?user)
    )
    :effect (and
      (mailbox_action ?user)
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
    )
  )

  (:action run_pre_delete_scripts
    :parameters (?actor - user ?u - user)
    :precondition (and
      (user_exists ?u)
      (can_escalate ?actor)
    )
    :effect (and
      (scripts_executed ?u)
    )
  )

  (:action run_post_delete_scripts
    :parameters (?actor - user ?u - user)
    :precondition (and
      (not (user_exists ?u))
      (can_escalate ?actor)
    )
    :effect (and
      (scripts_executed ?u)
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

  (:action kill_user_processes
    :parameters (?actor - user ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (process_running_by_user ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (process_running_by_user ?usr))
    )
  )

  (:action delete_user_group
    :parameters (?actor - user ?grp - group ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (not (primary_group_used_elsewhere ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?grp))
    )
  )

  (:action delete_user_group_force
    :parameters (?actor - user ?grp - group ?usr - user)
    :precondition (and
      (user_exists ?usr)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?grp))
    )
  )

  (:action delete_group
    :parameters (?actor - user ?g - group)
    :precondition (and
      (group_exists ?g)
      (can_escalate ?actor)
    )
    :effect (and
      (not (group_exists ?g))
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

  (:action set_group_gid
    :parameters (?actor - user ?grp - group ?gid - file)
    :precondition (and
      (not (group_exists ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

  (:action force_set_group_gid
    :parameters (?actor - user ?grp - group ?gid - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

  (:action set_group_key_value
    :parameters (?actor - user ?grp - group ?key - file ?value - file)
    :precondition (and
      (not (group_exists ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

  (:action set_sys_gid_range
    :parameters (?actor - user ?sys_min - file ?sys_max - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (sys_gid_min ?sys_min)
      (sys_gid_max ?sys_max)
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
      (assigned_gid ?group ?gid)
    )
  )

  (:action update_group_file
    :parameters (?actor - user ?group - group ?gid - file)
    :precondition (and
      (not (group_exists ?group))
      (gid_available ?gid)
      (network_available)
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?group)
      (assigned_gid ?group ?gid)
    )
  )

  (:action fail_update_group_file
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (not (network_available))
      (can_escalate ?actor)
    )
    :effect (and
      (group_creation_failed)
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
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

  (:action create_group_non_unique
    :parameters (?actor - user ?grp - group ?gid - file)
    :precondition (and
      (not (group_exists ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

  (:action create_group_chroot
    :parameters (?actor - user ?grp - group ?chroot_dir - directory)
    :precondition (and
      (not (group_exists ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

  (:action create_group_prefix
    :parameters (?actor - user ?grp - group ?prefix_dir - directory)
    :precondition (and
      (not (group_exists ?grp))
      (can_escalate ?actor)
    )
    :effect (and
      (group_exists ?grp)
    )
  )

  (:action add_users_to_group
    :parameters (?actor - user ?group - group ?user - user)
    :precondition (and
      (group_exists ?group)
      (user_exists ?user)
      (can_escalate ?actor)
    )
    :effect (and
      (user_in_group ?user ?group)
    )
  )

  (:action use_extra_users_database
    :parameters (?actor - user ?obj - file)
    :precondition (and
      (can_escalate ?actor)
    )
    :effect (and
      (using_extra_users_db)
    )
  )

)