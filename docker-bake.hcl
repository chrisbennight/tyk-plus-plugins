# The release images. The release workflow builds each target from the Git
# source of the tagged commit; `docker buildx bake release` builds them all
# locally.

group "release" {
  targets = ["gateway", "admin", "sandbox"]
}

# The release workflow fills this in with OCI labels and annotations, among
# them the source repository that GitHub uses to link each package to it.
target "docker-metadata-action" {}

target "gateway" {
  inherits = ["docker-metadata-action"]
  context  = "gateway"
  contexts = {
    mcp-pdp          = "plugins/mcp-pdp"
    sandbox-protocol = "sandbox/protocol"
  }
  platforms = ["linux/amd64"]
}

target "admin" {
  inherits = ["docker-metadata-action"]
  context  = "admin"
  contexts = {
    mcp-pdp          = "plugins/mcp-pdp"
    sandbox-protocol = "sandbox/protocol"
  }
  platforms = ["linux/amd64"]
}

target "sandbox" {
  inherits  = ["docker-metadata-action"]
  context   = "sandbox"
  target    = "release"
  platforms = ["linux/amd64"]
}
