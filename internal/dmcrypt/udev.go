package dmcrypt

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/axonops/vault-dm-crypt/pkg/errors"
)

// UdevManager handles udev operations for device discovery and management
type UdevManager struct {
	logger   *logrus.Logger
	executor CommandExecutor
}

// NewUdevManager creates a new udev manager
func NewUdevManager(logger *logrus.Logger) *UdevManager {
	return &UdevManager{
		logger:   logger,
		executor: NewCommandExecutor(logger),
	}
}

// TriggerRescan triggers udev to rescan a specific device
func (um *UdevManager) TriggerRescan(devicePath string) error {
	um.logger.WithField("device", devicePath).Debug("Triggering udev rescan")

	// Use udevadm trigger to rescan the device
	args := []string{"trigger", "--action=change", devicePath}

	_, err := um.executor.Execute("udevadm", args...)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to trigger udev rescan for %s", devicePath))
	}

	um.logger.WithField("device", devicePath).Debug("Udev rescan triggered successfully")
	return nil
}

// WaitForSettle waits for udev to settle after device changes
func (um *UdevManager) WaitForSettle(timeout time.Duration) error {
	um.logger.WithField("timeout", timeout).Debug("Waiting for udev to settle")

	// Use udevadm settle with timeout
	args := []string{"settle", fmt.Sprintf("--timeout=%d", int(timeout.Seconds()))}

	_, err := um.executor.ExecuteWithTimeout(timeout+5*time.Second, "udevadm", args...)
	if err != nil {
		return errors.Wrap(err, "failed to wait for udev settle")
	}

	um.logger.Debug("Udev settled successfully")
	return nil
}

// WaitForUUID waits for a UUID symlink to appear in /dev/disk/by-uuid/
func (um *UdevManager) WaitForUUID(uuid string, timeout time.Duration) error {
	um.logger.WithFields(logrus.Fields{
		"uuid":    uuid,
		"timeout": timeout,
	}).Debug("Waiting for UUID symlink to appear")

	uuidPath := fmt.Sprintf("/dev/disk/by-uuid/%s", uuid)

	// Poll for the UUID symlink to appear
	pollInterval := 100 * time.Millisecond
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		// Check if the UUID symlink exists
		args := []string{"info", "--query=path", "--name", uuidPath}
		_, err := um.executor.Execute("udevadm", args...)

		if err == nil {
			um.logger.WithFields(logrus.Fields{
				"uuid": uuid,
				"path": uuidPath,
			}).Debug("UUID symlink found")
			return nil
		}

		// Wait before next check
		time.Sleep(pollInterval)
	}

	return errors.New(fmt.Sprintf("timeout waiting for UUID symlink: %s", uuidPath))
}

// WaitForDevice waits for a device to appear and be ready
func (um *UdevManager) WaitForDevice(devicePath string, timeout time.Duration) error {
	um.logger.WithFields(logrus.Fields{
		"device":  devicePath,
		"timeout": timeout,
	}).Debug("Waiting for device to be ready")

	// Use udevadm settle with specific device
	args := []string{"settle", "--exit-if-exists=" + devicePath, fmt.Sprintf("--timeout=%d", int(timeout.Seconds()))}

	_, err := um.executor.ExecuteWithTimeout(timeout+5*time.Second, "udevadm", args...)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("timeout waiting for device: %s", devicePath))
	}

	um.logger.WithField("device", devicePath).Debug("Device is ready")
	return nil
}

// GetDeviceInfo retrieves udev information about a device
func (um *UdevManager) GetDeviceInfo(devicePath string) (map[string]string, error) {
	um.logger.WithField("device", devicePath).Debug("Getting device information from udev")

	// Use udevadm info to get device properties
	args := []string{"info", "--query=property", "--name", devicePath}

	output, err := um.executor.Execute("udevadm", args...)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("failed to get device info for %s", devicePath))
	}

	// Parse the output into a map
	info := make(map[string]string)
	lines := splitLines(output)

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Properties are in format KEY=VALUE
		if key, value, found := splitKeyValue(line, "="); found {
			info[key] = value
		}
	}

	um.logger.WithFields(logrus.Fields{
		"device":         devicePath,
		"property_count": len(info),
	}).Debug("Retrieved device information from udev")

	return info, nil
}

// RefreshDeviceDatabase refreshes the udev device database
func (um *UdevManager) RefreshDeviceDatabase() error {
	um.logger.Debug("Refreshing udev device database")

	// Use udevadm control to reload rules and trigger events
	_, err := um.executor.Execute("udevadm", "control", "--reload-rules")
	if err != nil {
		return errors.Wrap(err, "failed to reload udev rules")
	}

	_, err = um.executor.Execute("udevadm", "trigger")
	if err != nil {
		return errors.Wrap(err, "failed to trigger udev events")
	}

	um.logger.Debug("Udev device database refreshed")
	return nil
}

// ValidateUdevCommands checks if required udev commands are available
func (um *UdevManager) ValidateUdevCommands() error {
	requiredCommands := []string{"udevadm"}
	return um.executor.ValidateCommands(requiredCommands)
}

// Helper functions

// splitLines splits a string into lines and trims whitespace
func splitLines(s string) []string {
	lines := make([]string, 0)
	for _, line := range splitString(s, "\n") {
		trimmed := trimSpace(line)
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	return lines
}

// splitKeyValue splits a string on the first occurrence of separator
func splitKeyValue(s, sep string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			return trimSpace(s[:i]), trimSpace(s[i+len(sep):]), true
		}
	}
	return "", "", false
}

// splitString splits a string by separator
func splitString(s, sep string) []string {
	if s == "" {
		return []string{}
	}

	parts := make([]string, 0)
	start := 0

	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			parts = append(parts, s[start:i])
			start = i + len(sep)
		}
	}

	// Add the last part
	parts = append(parts, s[start:])
	return parts
}

// trimSpace removes leading and trailing whitespace
func trimSpace(s string) string {
	start := 0
	end := len(s)

	// Trim leading whitespace
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}

	// Trim trailing whitespace
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}

	return s[start:end]
}
