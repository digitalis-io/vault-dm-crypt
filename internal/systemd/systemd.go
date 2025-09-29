package systemd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"digitalisio/vault-dm-crypt/internal/errors"
	"digitalisio/vault-dm-crypt/internal/shell"
)

// Executor interface for command execution
type Executor interface {
	Execute(command string, args ...string) (string, error)
	ExecuteWithTimeout(timeout time.Duration, command string, args ...string) (string, error)
	ExecuteWithContext(ctx context.Context, command string, args ...string) (string, error)
	IsCommandAvailable(command string) bool
	ValidateCommands(commands []string) error
}

// Manager handles systemd service operations
type Manager struct {
	logger   *logrus.Logger
	executor Executor
}

// NewManager creates a new systemd manager
func NewManager(logger *logrus.Logger) *Manager {
	return &Manager{
		logger:   logger,
		executor: shell.NewExecutor(logger),
	}
}

// ServiceStatus represents the status of a systemd service
type ServiceStatus struct {
	Name      string
	Enabled   bool
	Active    bool
	Failed    bool
	UnitFile  string
	ExecStart string
}

// EnableService enables a systemd service instance
func (sm *Manager) EnableService(serviceName string) error {
	sm.logger.WithField("service", serviceName).Info("Enabling systemd service")

	_, err := sm.executor.Execute("systemctl", "enable", serviceName)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to enable service %s", serviceName))
	}

	sm.logger.WithField("service", serviceName).Info("Systemd service enabled successfully")
	return nil
}

// DisableService disables a systemd service instance
func (sm *Manager) DisableService(serviceName string) error {
	sm.logger.WithField("service", serviceName).Info("Disabling systemd service")

	_, err := sm.executor.Execute("systemctl", "disable", serviceName)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to disable service %s", serviceName))
	}

	sm.logger.WithField("service", serviceName).Info("Systemd service disabled successfully")
	return nil
}

// StartService starts a systemd service instance
func (sm *Manager) StartService(serviceName string) error {
	sm.logger.WithField("service", serviceName).Info("Starting systemd service")

	_, err := sm.executor.Execute("systemctl", "start", serviceName)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to start service %s", serviceName))
	}

	sm.logger.WithField("service", serviceName).Info("Systemd service started successfully")
	return nil
}

// StopService stops a systemd service instance
func (sm *Manager) StopService(serviceName string) error {
	sm.logger.WithField("service", serviceName).Info("Stopping systemd service")

	_, err := sm.executor.Execute("systemctl", "stop", serviceName)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to stop service %s", serviceName))
	}

	sm.logger.WithField("service", serviceName).Info("Systemd service stopped successfully")
	return nil
}

// GetServiceStatus retrieves the status of a systemd service
func (sm *Manager) GetServiceStatus(serviceName string) (*ServiceStatus, error) {
	sm.logger.WithField("service", serviceName).Debug("Getting systemd service status")

	status := &ServiceStatus{
		Name: serviceName,
	}

	// Check if service is enabled
	output, err := sm.executor.Execute("systemctl", "is-enabled", serviceName)
	if err == nil && strings.TrimSpace(output) == "enabled" {
		status.Enabled = true
	}

	// Check if service is active
	output, err = sm.executor.Execute("systemctl", "is-active", serviceName)
	if err == nil && strings.TrimSpace(output) == "active" {
		status.Active = true
	}

	// Check if service failed
	output, err = sm.executor.Execute("systemctl", "is-failed", serviceName)
	if err == nil && strings.TrimSpace(output) == "failed" {
		status.Failed = true
	}

	sm.logger.WithFields(logrus.Fields{
		"service": serviceName,
		"enabled": status.Enabled,
		"active":  status.Active,
		"failed":  status.Failed,
	}).Debug("Retrieved systemd service status")

	return status, nil
}

// ReloadDaemon reloads the systemd daemon configuration
func (sm *Manager) ReloadDaemon() error {
	sm.logger.Info("Reloading systemd daemon")

	_, err := sm.executor.Execute("systemctl", "daemon-reload")
	if err != nil {
		return errors.Wrap(err, "failed to reload systemd daemon")
	}

	sm.logger.Info("Systemd daemon reloaded successfully")
	return nil
}

// InstallServiceFile installs a systemd service file to the system
func (sm *Manager) InstallServiceFile(sourceFile, serviceName string) error {
	sm.logger.WithFields(logrus.Fields{
		"source_file":  sourceFile,
		"service_name": serviceName,
	}).Info("Installing systemd service file")

	// Determine target path
	systemdDir := "/etc/systemd/system"
	targetFile := filepath.Join(systemdDir, serviceName)

	// Check if source file exists
	if _, err := os.Stat(sourceFile); err != nil {
		return errors.Wrap(err, fmt.Sprintf("source service file not found: %s", sourceFile))
	}

	// Create systemd directory if it doesn't exist
	if err := os.MkdirAll(systemdDir, 0755); err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to create systemd directory: %s", systemdDir))
	}

	// Copy the service file
	_, err := sm.executor.Execute("cp", sourceFile, targetFile)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to copy service file from %s to %s", sourceFile, targetFile))
	}

	// Set proper permissions
	if err := os.Chmod(targetFile, 0644); err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to set permissions on %s", targetFile))
	}

	// Reload systemd daemon
	if err := sm.ReloadDaemon(); err != nil {
		return err
	}

	sm.logger.WithFields(logrus.Fields{
		"source_file": sourceFile,
		"target_file": targetFile,
	}).Info("Systemd service file installed successfully")

	return nil
}

// UninstallServiceFile removes a systemd service file from the system
func (sm *Manager) UninstallServiceFile(serviceName string) error {
	sm.logger.WithField("service_name", serviceName).Info("Uninstalling systemd service file")

	// Determine target path
	systemdDir := "/etc/systemd/system"
	targetFile := filepath.Join(systemdDir, serviceName)

	// Check if file exists
	if _, err := os.Stat(targetFile); os.IsNotExist(err) {
		sm.logger.WithField("service_file", targetFile).Debug("Service file does not exist")
		return nil
	}

	// Remove the service file
	if err := os.Remove(targetFile); err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to remove service file: %s", targetFile))
	}

	// Reload systemd daemon
	if err := sm.ReloadDaemon(); err != nil {
		return err
	}

	sm.logger.WithField("service_file", targetFile).Info("Systemd service file uninstalled successfully")
	return nil
}

// CreateDecryptServiceName creates a systemd service name for decrypting a specific UUID
func (sm *Manager) CreateDecryptServiceName(uuid string) string {
	// Clean the UUID to make it suitable for systemd service name
	cleanUUID := strings.ToLower(uuid)
	serviceName := fmt.Sprintf("vault-dm-crypt-decrypt@%s.service", cleanUUID)

	sm.logger.WithFields(logrus.Fields{
		"uuid":         uuid,
		"service_name": serviceName,
	}).Debug("Created decrypt service name")

	return serviceName
}

// EnableDecryptService enables automatic decryption for a UUID on boot
func (sm *Manager) EnableDecryptService(uuid string) error {
	serviceName := sm.CreateDecryptServiceName(uuid)

	sm.logger.WithFields(logrus.Fields{
		"uuid":    uuid,
		"service": serviceName,
	}).Info("Enabling decrypt service for UUID")

	if err := sm.EnableService(serviceName); err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to enable decrypt service for UUID %s", uuid))
	}

	sm.logger.WithField("uuid", uuid).Info("Decrypt service enabled successfully")
	return nil
}

// DisableDecryptService disables automatic decryption for a UUID
func (sm *Manager) DisableDecryptService(uuid string) error {
	serviceName := sm.CreateDecryptServiceName(uuid)

	sm.logger.WithFields(logrus.Fields{
		"uuid":    uuid,
		"service": serviceName,
	}).Info("Disabling decrypt service for UUID")

	if err := sm.DisableService(serviceName); err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to disable decrypt service for UUID %s", uuid))
	}

	sm.logger.WithField("uuid", uuid).Info("Decrypt service disabled successfully")
	return nil
}

// ValidateSystemdEnvironment checks if systemd is available and functional
func (sm *Manager) ValidateSystemdEnvironment() error {
	sm.logger.Debug("Validating systemd environment")

	// Check if systemctl command is available
	if !sm.executor.IsCommandAvailable("systemctl") {
		return errors.New("systemctl command not available")
	}

	// Check if systemd is running
	_, err := sm.executor.Execute("systemctl", "is-system-running")
	if err != nil {
		// systemd might be running but not fully operational
		sm.logger.WithError(err).Warn("systemd system state check returned error, but may still be functional")
	}

	// Check if we can communicate with systemd
	_, err = sm.executor.Execute("systemctl", "list-units", "--type=service", "--no-pager", "--no-legend", "--quiet")
	if err != nil {
		return errors.Wrap(err, "failed to communicate with systemd")
	}

	sm.logger.Debug("Systemd environment validated successfully")
	return nil
}

// GetJournalLogs retrieves journal logs for a specific service
func (sm *Manager) GetJournalLogs(serviceName string, lines int) (string, error) {
	sm.logger.WithFields(logrus.Fields{
		"service": serviceName,
		"lines":   lines,
	}).Debug("Retrieving journal logs")

	args := []string{
		"journalctl",
		"-u", serviceName,
		"--no-pager",
		"-n", fmt.Sprintf("%d", lines),
	}

	output, err := sm.executor.Execute(args[0], args[1:]...)
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("failed to get journal logs for service %s", serviceName))
	}

	sm.logger.WithField("service", serviceName).Debug("Retrieved journal logs successfully")
	return output, nil
}

// ListDecryptServices lists all vault-dm-crypt decrypt services
func (sm *Manager) ListDecryptServices() ([]string, error) {
	sm.logger.Debug("Listing vault-dm-crypt decrypt services")

	// List all systemd units matching our pattern
	output, err := sm.executor.Execute("systemctl", "list-units", "--all", "--no-pager", "--no-legend", "vault-dm-crypt-decrypt@*.service")
	if err != nil {
		return nil, errors.Wrap(err, "failed to list decrypt services")
	}

	// Parse the output to extract service names
	services := make([]string, 0)
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) > 0 && strings.HasPrefix(fields[0], "vault-dm-crypt-decrypt@") {
			services = append(services, fields[0])
		}
	}

	sm.logger.WithField("service_count", len(services)).Debug("Listed decrypt services")
	return services, nil
}
