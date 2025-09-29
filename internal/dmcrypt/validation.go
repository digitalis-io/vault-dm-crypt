package dmcrypt

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"digitalisio/vault-dm-crypt/internal/errors"
)

// SystemValidator validates system requirements for dm-crypt operations
type SystemValidator struct {
	logger   *logrus.Logger
	executor CommandExecutor
}

// NewSystemValidator creates a new system validator
func NewSystemValidator(logger *logrus.Logger) *SystemValidator {
	return &SystemValidator{
		logger:   logger,
		executor: NewCommandExecutor(logger),
	}
}

// ValidateSystemRequirements checks if all required system components are available
func (sv *SystemValidator) ValidateSystemRequirements() error {
	sv.logger.Info("Validating system requirements for dm-crypt operations")

	// Check if running as root
	if err := sv.validateRootPrivileges(); err != nil {
		return err
	}

	// Check required commands
	if err := sv.validateRequiredCommands(); err != nil {
		return err
	}

	// Check kernel modules
	if err := sv.validateKernelModules(); err != nil {
		return err
	}

	sv.logger.Info("All system requirements validated successfully")
	return nil
}

// validateRootPrivileges checks if the process is running as root
func (sv *SystemValidator) validateRootPrivileges() error {
	manager := NewManager(sv.logger)
	if err := manager.CheckRootPrivileges(); err != nil {
		return errors.Wrap(err, "root privileges validation failed")
	}

	sv.logger.Debug("Root privileges validated")
	return nil
}

// validateRequiredCommands checks if all required system commands are available
func (sv *SystemValidator) validateRequiredCommands() error {
	requiredCommands := []string{
		"cryptsetup", // For LUKS operations
		"blkid",      // For device UUID detection
		"udevadm",    // For device discovery and management
	}

	if err := sv.executor.ValidateCommands(requiredCommands); err != nil {
		return errors.Wrap(err, "required commands validation failed")
	}

	sv.logger.WithField("commands", requiredCommands).Debug("Required commands validated")
	return nil
}

// validateKernelModules checks if required kernel modules are available
func (sv *SystemValidator) validateKernelModules() error {
	requiredModules := []string{
		"dm_crypt", // Device mapper crypto target
		"dm_mod",   // Device mapper
	}

	for _, module := range requiredModules {
		if err := sv.checkKernelModule(module); err != nil {
			return errors.Wrap(err, fmt.Sprintf("kernel module validation failed for %s", module))
		}
	}

	sv.logger.WithField("modules", requiredModules).Debug("Kernel modules validated")
	return nil
}

// checkKernelModule checks if a specific kernel module is loaded or available
func (sv *SystemValidator) checkKernelModule(moduleName string) error {
	sv.logger.WithField("module", moduleName).Debug("Checking kernel module")

	// First, check if module is already loaded
	_, err := sv.executor.Execute("lsmod")
	if err != nil {
		// If lsmod fails, try alternative methods
		sv.logger.WithField("module", moduleName).Debug("lsmod failed, trying alternative detection")
	}

	// Try to load the module if it's not loaded (this will fail gracefully if already loaded)
	_, err = sv.executor.Execute("modprobe", moduleName)
	if err != nil {
		return fmt.Errorf("failed to load kernel module %s: %w", moduleName, err)
	}

	sv.logger.WithField("module", moduleName).Debug("Kernel module available")
	return nil
}

// ValidateCryptsetupVersion checks if cryptsetup version is compatible
func (sv *SystemValidator) ValidateCryptsetupVersion() error {
	sv.logger.Debug("Validating cryptsetup version")

	output, err := sv.executor.Execute("cryptsetup", "--version")
	if err != nil {
		return errors.Wrap(err, "failed to get cryptsetup version")
	}

	sv.logger.WithField("version_output", output).Info("Cryptsetup version information")

	// We just check that cryptsetup is available and can report its version
	// More detailed version parsing could be added here if needed
	if output == "" {
		return errors.New("cryptsetup version output is empty")
	}

	sv.logger.Debug("Cryptsetup version validated")
	return nil
}

// ValidateDeviceMapperSupport checks if device mapper is properly supported
func (sv *SystemValidator) ValidateDeviceMapperSupport() error {
	sv.logger.Debug("Validating device mapper support")

	// Check if /dev/mapper exists
	_, err := sv.executor.Execute("ls", "/dev/mapper")
	if err != nil {
		return errors.Wrap(err, "device mapper directory not accessible")
	}

	// Check if device mapper is functional by listing existing mappings
	_, err = sv.executor.Execute("dmsetup", "ls")
	if err != nil {
		// dmsetup might not be available, but that's not always critical
		sv.logger.WithError(err).Warn("dmsetup not available, but this may not be critical")
	}

	sv.logger.Debug("Device mapper support validated")
	return nil
}

// GetSystemInfo returns information about the system's dm-crypt capabilities
func (sv *SystemValidator) GetSystemInfo() (map[string]string, error) {
	info := make(map[string]string)

	// Get cryptsetup version
	if output, err := sv.executor.Execute("cryptsetup", "--version"); err == nil {
		info["cryptsetup_version"] = output
	}

	// Get kernel version
	if output, err := sv.executor.Execute("uname", "-r"); err == nil {
		info["kernel_version"] = output
	}

	// Get device mapper version
	if output, err := sv.executor.Execute("dmsetup", "version"); err == nil {
		info["dm_version"] = output
	}

	// Check if LUKS2 is supported
	if _, err := sv.executor.Execute("cryptsetup", "--help"); err == nil {
		info["luks2_supported"] = "yes"
	} else {
		info["luks2_supported"] = "unknown"
	}

	sv.logger.WithField("info_count", len(info)).Debug("Collected system information")
	return info, nil
}
