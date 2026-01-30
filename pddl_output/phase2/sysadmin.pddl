(define (domain sysadmin)
  (:requirements :strips :typing)
  (:types server user)
  (:predicates
    (connected ?s - server)
    (has-access ?u - user ?s - server)
    (installed ?p - package ?s - server)))