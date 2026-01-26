(define (domain sysadmin)

  (:requirements :strips :typing :negative-preconditions)

  ;; Type Hierarchy (from shared common.type_hierarchy)
  (:types
    ; Base types

    ; Filesystem types
    filesystem_object - object
    directory file - filesystem_object
    configuration_file - file

    ; Execution types
    process service - object

    ; Package management types
    package repository - object

    ; Access control types
    group user - object
    human_user system_user - user

    ; Network types
    firewall_rule interface port - object
  )

  ;; Predicates
  (:predicates
    (can_escalate ?u - user)
    (directory_exists ?d - directory)
    (directory_is_empty ?d - directory)
    (file_exists ?f - file)
    (file_in_directory ?f - file ?d - directory)
    (file_is_directory ?f - file)
    (file_is_executable ?f - file)
    (file_is_group_owned_by ?f - file ?g - group)
    (file_is_owned_by ?f - file ?u - user)
    (file_is_readable ?f - file)
    (file_is_writable ?f - file)
    (file_readable ?sc - object)
    (firewall_rule_applied_to_port ?r - firewall_rule ?p - port)
    (firewall_rule_exists ?r - firewall_rule)
    (group_exists ?g - group)
    (has_user_privilege ?u - user ?p - object)
    (integer ?n - object)
    (interface_exists ?i - interface)
    (package_installed ?p - package)
    (package_removed ?p - package)
    (package_updated ?p - package)
    (port_assigned_to_interface ?p - port ?i - interface)
    (port_exists ?p - port)
    (process_belongs_to_group ?p - process ?g - group)
    (process_exists ?p - process)
    (process_has_env_preservation ?p - process)
    (process_niceness ?p - process ?n - object)
    (process_owned_by ?p - process ?u - user)
    (process_paused ?p - process)
    (process_priority ?p - process ?p - object)
    (process_running ?p - process)
    (process_terminated ?p - process)
    (repository_available ?r - repository)
    (requires_env_preservation ?p - object ?b - object)
    (sudo_command_executable ?sc - object)
    (sudo_command_exists ?sc - object)
    (sudo_command_readable ?sc - object)
    (sudo_command_writable ?sc - object)
    (traffic_allowed_on_port ?p - port)
    (user_exists ?u - user)
    (user_has_privilege ?u - user ?p - object)
    (network_available)
  )

  ;; Actions...

)