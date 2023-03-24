// This is what is baked by GitHub Actions
group "default" { targets = ["regular", "debug", "scripts"] }

// Targets filled by GitHub Actions for each tag
target "docker-metadata-action" {}
target "docker-metadata-action-debug" {}
target "docker-metadata-action-scripts" {}

// This sets the platforms and is further extended by GitHub Actions to set the
// output and the cache locations
target "base" {
  platforms = [
    "linux/amd64",
    "linux/arm64",
    "linux/arm",
  ]
}

target "regular" {
  inherits = ["base", "docker-metadata-action"]
}

target "debug" {
  inherits = ["base", "docker-metadata-action-debug"]
  target = "debug"
}

target "scripts" {
  inherits = ["base", "docker-metadata-action-scripts"]
  target = "scripts"
}
