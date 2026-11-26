locals {
  host_files = fileset("${path.module}/../../hosts", "*.yml")
  hosts = {
    for f in local.host_files :
    trimsuffix(f, ".yml") => yamldecode(file("${path.module}/../../hosts/${f}"))
  }
  edge_hosts = {
    for k, v in local.hosts :
    k => v
    if contains(keys(v), "edge")
  }

  registry_files = fileset("${path.module}/../../registry", "*.yml")
  registry = {
    for f in local.registry_files :
    trimsuffix(f, ".yml") => yamldecode(file("${path.module}/../../registry/${f}"))
  }
}
