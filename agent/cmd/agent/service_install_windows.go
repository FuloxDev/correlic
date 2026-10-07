//go:build windows

package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	defaultServiceName = "CorrelicAgent"
	serviceDisplayName = "Correlic Security Agent"
	serviceDescription = "Monitors AI agent processes for security threats using ETW telemetry."
)

// handleServiceCommand processes "service install|uninstall|start|stop" subcommands.
// Returns true if a service command was handled and the process should exit.
func handleServiceCommand(logger *slog.Logger) bool {
	if len(os.Args) < 3 || os.Args[1] != "service" {
		return false
	}

	cmd := os.Args[2]

	switch cmd {
	case "install":
		if err := installService(logger); err != nil {
			logger.Error("service install failed", "error", err)
			os.Exit(1)
		}
		fmt.Println("Service installed successfully.")
		return true

	case "uninstall":
		if err := uninstallService(logger); err != nil {
			logger.Error("service uninstall failed", "error", err)
			os.Exit(1)
		}
		fmt.Println("Service uninstalled successfully.")
		return true

	case "start":
		if err := startService(logger); err != nil {
			logger.Error("service start failed", "error", err)
			os.Exit(1)
		}
		fmt.Println("Service started.")
		return true

	case "stop":
		if err := stopService(logger); err != nil {
			logger.Error("service stop failed", "error", err)
			os.Exit(1)
		}
		fmt.Println("Service stopped.")
		return true

	default:
		fmt.Fprintf(os.Stderr, "Unknown service command: %s\nUsage: correlic-agent service [install|uninstall|start|stop]\n", cmd)
		os.Exit(1)
		return true
	}
}

func installService(logger *slog.Logger) error {
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot determine executable path: %w", err)
	}
	exePath, err = filepath.Abs(exePath)
	if err != nil {
		return fmt.Errorf("cannot resolve absolute path: %w", err)
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Check if already installed.
	s, err := m.OpenService(defaultServiceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %q already exists", defaultServiceName)
	}

	s, err = m.CreateService(defaultServiceName, exePath, mgr.Config{
		DisplayName:  serviceDisplayName,
		Description:  serviceDescription,
		StartType:    mgr.StartAutomatic,
		ServiceType:  0x00000010, // SERVICE_WIN32_OWN_PROCESS
		ErrorControl: mgr.ErrorNormal,
	})
	if err != nil {
		return fmt.Errorf("cannot create service: %w", err)
	}
	defer s.Close()

	// Set recovery actions: restart on failure with 60s delay.
	err = s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 60_000_000_000}, // 60 seconds in nanoseconds
		{Type: mgr.ServiceRestart, Delay: 60_000_000_000},
		{Type: mgr.ServiceRestart, Delay: 60_000_000_000},
	}, 86400) // Reset failure count after 24 hours
	if err != nil {
		logger.Warn("failed to set recovery actions", "error", err)
	}

	logger.Info("service installed",
		"name", defaultServiceName,
		"exe", exePath,
		"start_type", "automatic",
	)
	return nil
}

func uninstallService(logger *slog.Logger) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(defaultServiceName)
	if err != nil {
		return fmt.Errorf("service %q not found: %w", defaultServiceName, err)
	}
	defer s.Close()

	err = s.Delete()
	if err != nil {
		return fmt.Errorf("cannot delete service: %w", err)
	}

	logger.Info("service uninstalled", "name", defaultServiceName)
	return nil
}

func startService(logger *slog.Logger) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(defaultServiceName)
	if err != nil {
		return fmt.Errorf("service %q not found: %w", defaultServiceName, err)
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return fmt.Errorf("cannot start service: %w", err)
	}

	logger.Info("service started", "name", defaultServiceName)
	return nil
}

func stopService(logger *slog.Logger) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(defaultServiceName)
	if err != nil {
		return fmt.Errorf("service %q not found: %w", defaultServiceName, err)
	}
	defer s.Close()

	_, err = s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("cannot stop service: %w", err)
	}

	logger.Info("service stopped", "name", defaultServiceName)
	return nil
}
