package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/axonops/vault-dm-crypt/internal/config"
	"github.com/axonops/vault-dm-crypt/internal/dmcrypt"
	"github.com/axonops/vault-dm-crypt/internal/shell"
	"github.com/axonops/vault-dm-crypt/internal/systemd"
	"github.com/axonops/vault-dm-crypt/internal/vault"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	version        = "dev"
	cfgFile        string
	verbose        bool
	debug          bool
	retry          int
	logger         *logrus.Logger
	cfg            *config.Config
	vaultClient    *vault.Client
	dmcryptManager *dmcrypt.LUKSManager
	systemdManager *systemd.Manager
	validator      *dmcrypt.SystemValidator
)

func init() {
	logger = logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "vault-dm-crypt",
	Short: "Store and retrieve dm-crypt keys in HashiCorp Vault",
	Long: `vault-dm-crypt is a utility for encrypting block devices using dm-crypt/LUKS
with encryption keys securely stored in HashiCorp Vault.

This tool provides a secure way to manage encrypted volumes by:
- Generating strong encryption keys
- Storing keys in HashiCorp Vault
- Automatically mounting encrypted volumes on boot
- Supporting AppRole authentication for Vault access`,
	Version: version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Load configuration
		var err error
		cfg, err = config.Load(cfgFile)
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		// Override log level from flags if specified
		if debug {
			cfg.Logging.Level = "debug"
		} else if verbose {
			cfg.Logging.Level = "info"
		}

		// Configure logger based on config
		if err := configureLogger(cfg.Logging); err != nil {
			return fmt.Errorf("failed to configure logging: %w", err)
		}

		// Override retry timeout if specified
		if retry > 0 {
			cfg.Vault.RetryMax = retry
		}

		logger.WithFields(logrus.Fields{
			"vault_url":     cfg.Vault.URL,
			"vault_backend": cfg.Vault.Backend,
		}).Debug("Configuration loaded")

		// Initialize all managers
		var err2 error
		vaultClient, err2 = vault.NewClient(&cfg.Vault, logger)
		if err2 != nil {
			return fmt.Errorf("failed to initialize Vault client: %w", err2)
		}

		dmcryptManager = dmcrypt.NewLUKSManager(logger)
		systemdManager = systemd.NewManager(logger)
		validator = dmcrypt.NewSystemValidator(logger)

		logger.Debug("All managers initialized successfully")

		return nil
	},
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt <device>",
	Short: "Encrypt a block device",
	Long: `Encrypt a block device using LUKS with a key stored in Vault.

This command will:
1. Generate a random encryption key
2. Store the key in Vault at secret/vaultlocker/<uuid>
3. Format the device with LUKS encryption
4. Open the encrypted device
5. Enable systemd service for auto-mount on boot`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		device := args[0]
		force, _ := cmd.Flags().GetBool("force")

		logger.WithFields(logrus.Fields{
			"device": device,
			"force":  force,
		}).Info("Starting device encryption")

		// Validate system requirements
		if err := validator.ValidateSystemRequirements(); err != nil {
			return fmt.Errorf("system validation failed: %w", err)
		}

		// Validate device
		if err := dmcryptManager.ValidateDevice(device); err != nil {
			return fmt.Errorf("device validation failed: %w", err)
		}

		// Check if device is mounted
		mounted, err := dmcryptManager.IsDeviceMounted(device)
		if err != nil {
			return fmt.Errorf("failed to check device mount status: %w", err)
		}

		if mounted && !force {
			return fmt.Errorf("device %s is currently mounted. Use --force to encrypt anyway", device)
		}

		// Generate encryption key
		logger.Debug("Generating encryption key")
		key, err := dmcryptManager.GenerateKey()
		if err != nil {
			return fmt.Errorf("failed to generate encryption key: %w", err)
		}

		// Generate UUID for the device
		uuid := generateUUID()
		logger.WithField("uuid", uuid).Debug("Generated UUID for device")

		// Store key in Vault
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Vault.Timeout)
		defer cancel()

		logger.Debug("Storing encryption key in Vault")
		err = vaultClient.WithRetry(ctx, func() error {
			secretData := map[string]interface{}{
				"dmcrypt_key": key,
				"created_at":  time.Now().Format(time.RFC3339),
				"device":      device,
			}

			hostname, _ := os.Hostname()
			if hostname != "" {
				secretData["hostname"] = hostname
			}

			vaultPath := fmt.Sprintf("vaultlocker/%s", uuid)
			return vaultClient.WriteSecret(ctx, vaultPath, secretData)
		})

		if err != nil {
			// Clean up the key from memory
			dmcryptManager.SecureEraseKey(&key)
			return fmt.Errorf("failed to store key in Vault: %w", err)
		}

		logger.Info("Encryption key stored in Vault successfully")

		// Format device with LUKS
		logger.Info("Formatting device with LUKS encryption")
		err = dmcryptManager.FormatDevice(device, key, uuid)
		if err != nil {
			dmcryptManager.SecureEraseKey(&key)
			return fmt.Errorf("failed to format device with LUKS: %w", err)
		}

		logger.Info("Device formatted with LUKS successfully")

		// Open the LUKS device
		deviceName := dmcryptManager.GenerateDeviceName(uuid)
		logger.WithField("device_name", deviceName).Info("Opening LUKS device")

		err = dmcryptManager.OpenDevice(device, key, deviceName)
		if err != nil {
			dmcryptManager.SecureEraseKey(&key)
			return fmt.Errorf("failed to open LUKS device: %w", err)
		}

		mappedDevice := dmcryptManager.GetMappedDevicePath(deviceName)
		logger.WithField("mapped_device", mappedDevice).Info("LUKS device opened successfully")

		// Clean up the key from memory now that it's no longer needed
		dmcryptManager.SecureEraseKey(&key)

		// Enable systemd service for auto-decrypt on boot
		logger.Info("Enabling systemd service for automatic decryption on boot")
		err = systemdManager.EnableDecryptService(uuid)
		if err != nil {
			logger.WithError(err).Warn("Failed to enable systemd service - device will need manual decryption on boot")
		} else {
			logger.Info("Systemd service enabled successfully")
		}

		logger.WithFields(logrus.Fields{
			"device":        device,
			"uuid":          uuid,
			"mapped_device": mappedDevice,
		}).Info("Device encryption completed successfully")

		fmt.Printf("Device encrypted successfully:\n")
		fmt.Printf("  UUID: %s\n", uuid)
		fmt.Printf("  Mapped device: %s\n", mappedDevice)
		fmt.Printf("  Vault path: secret/vaultlocker/%s\n", uuid)

		return nil
	},
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt <uuid>",
	Short: "Decrypt and open an encrypted device",
	Long: `Decrypt and open a LUKS-encrypted device using a key from Vault.

This command will:
1. Retrieve the encryption key from Vault using the UUID
2. Open the LUKS device with the key
3. Create the device mapping`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		uuid := args[0]
		customName, _ := cmd.Flags().GetString("name")

		logger.WithFields(logrus.Fields{
			"uuid":        uuid,
			"custom_name": customName,
		}).Info("Starting device decryption")

		// Validate system requirements
		if err := validator.ValidateSystemRequirements(); err != nil {
			return fmt.Errorf("system validation failed: %w", err)
		}

		// Retrieve key from Vault
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Vault.Timeout)
		defer cancel()

		logger.Debug("Retrieving encryption key from Vault")
		var key string
		err := vaultClient.WithRetry(ctx, func() error {
			vaultPath := fmt.Sprintf("vaultlocker/%s", uuid)
			secretData, err := vaultClient.ReadSecret(ctx, vaultPath)
			if err != nil {
				return err
			}

			dmcryptKey, exists := secretData["dmcrypt_key"]
			if !exists {
				return fmt.Errorf("dmcrypt_key not found in secret")
			}

			keyStr, ok := dmcryptKey.(string)
			if !ok {
				return fmt.Errorf("dmcrypt_key is not a string")
			}

			key = keyStr
			return nil
		})

		if err != nil {
			return fmt.Errorf("failed to retrieve key from Vault: %w", err)
		}

		logger.Info("Encryption key retrieved from Vault successfully")

		// Validate the key format
		if err := dmcryptManager.ValidateKeyFormat(key); err != nil {
			dmcryptManager.SecureEraseKey(&key)
			return fmt.Errorf("invalid key format: %w", err)
		}

		// Generate device name
		var deviceName string
		if customName != "" {
			deviceName = customName
		} else {
			deviceName = dmcryptManager.GenerateDeviceName(uuid)
		}

		logger.WithField("device_name", deviceName).Debug("Using device name")

		// Find the device by UUID
		devicePath, err := findDeviceByUUID(uuid)
		if err != nil {
			dmcryptManager.SecureEraseKey(&key)
			return fmt.Errorf("failed to find device with UUID %s: %w", uuid, err)
		}

		logger.WithField("device_path", devicePath).Debug("Found device")

		// Check if device is already open
		mappedDevice := dmcryptManager.GetMappedDevicePath(deviceName)
		if _, err := os.Stat(mappedDevice); err == nil {
			dmcryptManager.SecureEraseKey(&key)
			logger.WithField("mapped_device", mappedDevice).Info("Device is already decrypted")
			fmt.Printf("Device already decrypted: %s\n", mappedDevice)
			return nil
		}

		// Open the LUKS device
		logger.Info("Opening LUKS device")
		err = dmcryptManager.OpenDevice(devicePath, key, deviceName)
		if err != nil {
			dmcryptManager.SecureEraseKey(&key)
			return fmt.Errorf("failed to open LUKS device: %w", err)
		}

		// Clean up the key from memory
		dmcryptManager.SecureEraseKey(&key)

		logger.WithFields(logrus.Fields{
			"device_path":   devicePath,
			"uuid":          uuid,
			"mapped_device": mappedDevice,
		}).Info("Device decryption completed successfully")

		fmt.Printf("Device decrypted successfully:\n")
		fmt.Printf("  UUID: %s\n", uuid)
		fmt.Printf("  Device: %s\n", devicePath)
		fmt.Printf("  Mapped device: %s\n", mappedDevice)

		return nil
	},
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "/etc/vault-dm-crypt/config.toml", "config file path")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "enable verbose output")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug output")
	rootCmd.PersistentFlags().IntVar(&retry, "retry", 30, "retry timeout in seconds for Vault connection")

	// Add subcommands
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)

	// Add flags specific to encrypt command
	encryptCmd.Flags().BoolP("force", "f", false, "force encryption even if device contains data")

	// Add flags specific to decrypt command
	decryptCmd.Flags().StringP("name", "n", "", "custom name for the device mapping")
}

// configureLogger sets up the logger based on configuration
func configureLogger(logConfig config.LoggingConfig) error {
	// Set log level
	level, err := logrus.ParseLevel(strings.ToLower(logConfig.Level))
	if err != nil {
		return fmt.Errorf("invalid log level %s: %w", logConfig.Level, err)
	}
	logger.SetLevel(level)

	// Set log format
	switch strings.ToLower(logConfig.Format) {
	case "json":
		logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	case "text":
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   true,
			TimestampFormat: "2006-01-02T15:04:05.000Z07:00",
		})
	default:
		return fmt.Errorf("invalid log format: %s", logConfig.Format)
	}

	// Set log output
	switch strings.ToLower(logConfig.Output) {
	case "stdout", "":
		logger.SetOutput(os.Stdout)
	case "stderr":
		logger.SetOutput(os.Stderr)
	default:
		// Assume it's a file path
		file, err := os.OpenFile(logConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("failed to open log file %s: %w", logConfig.Output, err)
		}
		logger.SetOutput(file)
	}

	return nil
}

// generateUUID generates a new UUID for the device
func generateUUID() string {
	// Generate a simple UUID-like string
	// In a real implementation, you might want to use a proper UUID library
	// or generate based on device characteristics
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		time.Now().Unix(),
		time.Now().Nanosecond()&0xFFFF,
		(time.Now().Nanosecond()>>16)&0xFFFF,
		(time.Now().Nanosecond()>>32)&0xFFFF,
		time.Now().UnixNano()&0xFFFFFFFFFFFF)
}

// findDeviceByUUID finds a device path by its UUID
func findDeviceByUUID(uuid string) (string, error) {
	logger.WithField("uuid", uuid).Debug("Looking for device by UUID")

	// Try the standard UUID path first
	uuidPath := fmt.Sprintf("/dev/disk/by-uuid/%s", uuid)
	if _, err := os.Stat(uuidPath); err == nil {
		// Follow the symlink to get the actual device path
		realPath, err := os.Readlink(uuidPath)
		if err == nil {
			// Convert relative path to absolute
			if !strings.HasPrefix(realPath, "/") {
				realPath = filepath.Join("/dev/disk/by-uuid", realPath)
				realPath, _ = filepath.Abs(realPath)
			}
			logger.WithFields(logrus.Fields{
				"uuid":        uuid,
				"uuid_path":   uuidPath,
				"device_path": realPath,
			}).Debug("Found device via UUID symlink")
			return realPath, nil
		}
	}

	// If UUID path doesn't work, try using blkid
	executor := shell.NewExecutor(logger)
	output, err := executor.Execute("blkid", "-U", uuid)
	if err == nil {
		devicePath := strings.TrimSpace(output)
		if devicePath != "" {
			logger.WithFields(logrus.Fields{
				"uuid":        uuid,
				"device_path": devicePath,
			}).Debug("Found device via blkid")
			return devicePath, nil
		}
	}

	return "", fmt.Errorf("device with UUID %s not found", uuid)
}
