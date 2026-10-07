package ebpf

import "github.com/correlic/correlic-agent/internal/docker"

// DockerResolver is an alias for docker.Resolver.
type DockerResolver = docker.Resolver

// ContainerInfo is an alias for docker.ContainerInfo.
type ContainerInfo = docker.ContainerInfo

// NewDockerResolver delegates to docker.NewResolver.
var NewDockerResolver = docker.NewResolver
