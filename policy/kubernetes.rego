package main

deny[msg] {
  container := input.spec.template.spec.containers[_]
  not container.securityContext.runAsNonRoot
  msg := sprintf("Le conteneur %s tourne en root (interdit)", [container.name])
}
