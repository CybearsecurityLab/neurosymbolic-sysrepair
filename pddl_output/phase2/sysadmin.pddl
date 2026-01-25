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
    (config_applied ?c - object ?s - object)
    (configures ?c - object ?s - object)
    (copy_content ?src - object ?dst - object)
    (copy_files_in_directory ?src - object ?sub - object)
    (copy_subdirectory ?src - object ?dst - object)
    (create_directory ?dst - directory)
    (create_file ?dst - file)
    (directory_contains_file ?src - object ?sub - object)
    (directory_empty ?d - directory)
    (directory_exists ?src - object)
    (file_executable ?f - file)
    (file_exists ?f - file)
    (file_in_directory ?f - file ?d - directory)
    (file_is_directory ?f - file)
    (file_owned_by ?f - file ?u - user)
    (file_readable ?f - file)
    (file_writable ?f - file)
    (firewall_rule_applied_to_port ?r - firewall_rule ?p - port)
    (firewall_rule_exists ?r - firewall_rule)
    (has_user_privilege ?u - user ?p - object)
    (interface_exists ?i - interface)
    (package_installed ?p - package)
    (package_removed ?p - package)
    (package_updated ?p - package)
    (port_assigned_to_interface ?p - port ?i - interface)
    (port_exists ?p - port)
    (process_exists ?p - process)
    (process_niceness ?p - object ?niceness - object)
    (process_owned_by ?p - process ?user - user)
    (process_paused ?p - process)
    (process_priority ?p - object ?priority - object)
    (process_running ?p - process)
    (process_terminated ?p - process)
    (rename_directory ?src - object ?dst - object)
    (rename_file ?src - object ?dst - object)
    (repository_available ?r - repository)
    (sudo_command_executable ?sc - object)
    (sudo_command_exists ?sc - object)
    (sudo_command_readable ?sc - object)
    (sudo_command_writable ?sc - object)
    (user_exists ?u - object)
    (user_has_privilege ?u - object ?p - object)
    (network_available)
  )

  ;; Actions...
)