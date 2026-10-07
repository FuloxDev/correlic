// Package docker provides Docker container metadata resolution via the Docker socket.
//
// DockerResolver maps container IDs (from /proc/PID/cgroup) to container names
// and image names by querying the Docker API over the Unix socket.
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/correlic/correlic-agent/internal/lineage"
)

// Resolver resolves container IDs to container metadata (name, image)
// via the Docker daemon Unix socket. It caches results to avoid repeated lookups.
type Resolver struct {
	mu     sync.RWMutex
	cache  map[string]*ContainerInfo
	client *http.Client
	logger *slog.Logger
}

// ContainerInfo holds Docker container metadata relevant to AI process detection.
type ContainerInfo struct {
	ID    string // full 64-char container ID
	Name  string // container name (without leading /)
	Image string // image name (e.g., "openclaw/agent:latest")
}

// DefaultDockerSocket is the standard Docker daemon socket path.
const DefaultDockerSocket = "/var/run/docker.sock"

// NewResolver creates a resolver that talks to the Docker daemon.
// Returns nil if the Docker socket is not accessible (non-Docker hosts).
func NewResolver(logger *slog.Logger) *Resolver {
	if logger == nil {
		logger = slog.Default()
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.DialTimeout("unix", DefaultDockerSocket, 2*time.Second)
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get("http://docker/v1.24/_ping")
	if err != nil {
		logger.Info("Docker socket not available, container name resolution disabled", "error", err)
		return nil
	}
	resp.Body.Close()

	logger.Info("Docker resolver initialized", "socket", DefaultDockerSocket)
	return &Resolver{
		cache:  make(map[string]*ContainerInfo),
		client: client,
		logger: logger,
	}
}

// Resolve looks up container metadata by container ID.
// Returns nil if the container is not found or Docker is unavailable.
func (dr *Resolver) Resolve(containerID string) *ContainerInfo {
	if dr == nil || containerID == "" {
		return nil
	}

	dr.mu.RLock()
	if info, ok := dr.cache[containerID]; ok {
		dr.mu.RUnlock()
		return info
	}
	dr.mu.RUnlock()

	info := dr.fetchContainer(containerID)
	if info == nil {
		return nil
	}

	dr.mu.Lock()
	dr.cache[containerID] = info
	if len(info.ID) >= 12 {
		dr.cache[info.ID[:12]] = info
	}
	dr.mu.Unlock()

	return info
}

func (dr *Resolver) fetchContainer(containerID string) *ContainerInfo {
	url := fmt.Sprintf("http://docker/v1.24/containers/%s/json", containerID)
	resp, err := dr.client.Get(url)
	if err != nil {
		dr.logger.Debug("Docker API query failed", "container_id", containerID, "error", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode != http.StatusNotFound {
			dr.logger.Debug("Docker API non-200", "container_id", containerID, "status", resp.StatusCode)
		}
		io.Copy(io.Discard, resp.Body)
		return nil
	}

	var inspect struct {
		ID     string `json:"Id"`
		Name   string `json:"Name"`
		Config struct {
			Image string `json:"Image"`
		} `json:"Config"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&inspect); err != nil {
		dr.logger.Debug("Docker API decode failed", "container_id", containerID, "error", err)
		return nil
	}

	name := strings.TrimPrefix(inspect.Name, "/")

	dr.logger.Debug("resolved container", "id", containerID, "name", name, "image", inspect.Config.Image)
	return &ContainerInfo{
		ID:    inspect.ID,
		Name:  name,
		Image: inspect.Config.Image,
	}
}

// CheckContainerPatterns checks if a container's name or image matches any AI pattern.
func (dr *Resolver) CheckContainerPatterns(containerID string, tracker *lineage.LineageTracker) bool {
	if dr == nil || containerID == "" || tracker == nil {
		return false
	}

	info := dr.Resolve(containerID)
	if info == nil {
		return false
	}

	if tracker.CheckPattern(info.Name) {
		dr.logger.Info("AI process detected via container name",
			"container_id", containerID, "name", info.Name)
		return true
	}

	if tracker.CheckPattern(info.Image) {
		dr.logger.Info("AI process detected via container image",
			"container_id", containerID, "image", info.Image)
		return true
	}

	if idx := strings.LastIndex(info.Image, ":"); idx > 0 {
		imageNoTag := info.Image[:idx]
		if tracker.CheckPattern(imageNoTag) {
			dr.logger.Info("AI process detected via container image (no tag)",
				"container_id", containerID, "image", imageNoTag)
			return true
		}
	}

	return false
}

// InvalidateContainer removes a container from the cache.
func (dr *Resolver) InvalidateContainer(containerID string) {
	if dr == nil || containerID == "" {
		return
	}
	dr.mu.Lock()
	defer dr.mu.Unlock()
	if info, ok := dr.cache[containerID]; ok {
		delete(dr.cache, containerID)
		if len(info.ID) >= 12 {
			delete(dr.cache, info.ID[:12])
		}
	}
}
