package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"axonops/vault-dm-crypt/internal/config"
	"axonops/vault-dm-crypt/internal/dmcrypt"
	"axonops/vault-dm-crypt/internal/shell"
	"axonops/vault-dm-crypt/internal/systemd"
	"axonops/vault-dm-crypt/internal/vault"
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
		// Don't print the error again if it's already been printed by Cobra
		// Just exit with error code
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
		// Silence usage for runtime errors (not argument errors)
		cmd.SilenceUsage = true

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
		uuidStr := uuid.NewString()
		logger.WithField("uuid", uuidStr).Debug("Generated UUID for device")

		// Store key in Vault
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Vault.Timeout())
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

			vaultPath := fmt.Sprintf("vaultlocker/%s", uuidStr)
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
		err = dmcryptManager.FormatDevice(device, key, uuidStr)
		if err != nil {
			dmcryptManager.SecureEraseKey(&key)
			return fmt.Errorf("failed to format device with LUKS: %w", err)
		}

		logger.Info("Device formatted with LUKS successfully")

		// Open the LUKS device
		deviceName := dmcryptManager.GenerateDeviceName(uuidStr)
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
		err = systemdManager.EnableDecryptService(uuidStr)
		if err != nil {
			logger.WithError(err).Warn("Failed to enable systemd service - device will need manual decryption on boot")
		} else {
			logger.Info("Systemd service enabled successfully")
		}

		logger.WithFields(logrus.Fields{
			"device":        device,
			"uuid":          uuidStr,
			"mapped_device": mappedDevice,
		}).Info("Device encryption completed successfully")

		fmt.Printf("Device encrypted successfully:\n")
		fmt.Printf("  UUID: %s\n", uuidStr)
		fmt.Printf("  Mapped device: %s\n", mappedDevice)
		fmt.Printf("  Vault path: secret/vaultlocker/%s\n", uuidStr)

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
		// Silence usage for runtime errors (not argument errors)
		cmd.SilenceUsage = true

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
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Vault.Timeout())
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

var refreshAuthCmd = &cobra.Command{
	Use:   "refresh-auth",
	Short: "Check AppRole authentication status and refresh secret ID if needed",
	Long: `Check AppRole authentication status and manage secret ID lifecycle.

This command will:
1. Show current token and secret ID expiry information
2. Generate a new secret ID if requested (--refresh-secret-id) or conditionally (--refresh-if-expiring)
3. Optionally update the config file with the new secret ID

Since this is a one-shot process, token renewal is not needed as fresh tokens
are obtained on each run. The focus is on secret ID management for long-term credentials.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Silence usage for runtime errors (not argument errors)
		cmd.SilenceUsage = true

		// Get the expiry threshold from flags or environment
		thresholdMinutes, _ := cmd.Flags().GetFloat64("threshold-minutes")

		// Check environment variable if not set via flag
		if !cmd.Flags().Changed("threshold-minutes") {
			if envThreshold := os.Getenv("VAULT_DM_CRYPT_REFRESH_THRESHOLD_MINUTES"); envThreshold != "" {
				if parsed, err := time.ParseDuration(envThreshold + "m"); err == nil {
					thresholdMinutes = parsed.Minutes()
				}
			}
		}

		refreshSecretID, _ := cmd.Flags().GetBool("refresh-secret-id")
		refreshIfExpiring, _ := cmd.Flags().GetBool("refresh-if-expiring")
		updateConfig, _ := cmd.Flags().GetBool("update-config")
		statusOnly, _ := cmd.Flags().GetBool("status-only")

		threshold := time.Duration(thresholdMinutes * float64(time.Minute))

		// Validate flag combinations early
		if refreshSecretID && refreshIfExpiring {
			return fmt.Errorf("cannot use both --refresh-secret-id and --refresh-if-expiring together\nUse --refresh-secret-id to always refresh, or --refresh-if-expiring to refresh only when needed")
		}

		// Validate that approle_name is configured if refresh is requested
		if (refreshSecretID || refreshIfExpiring) && cfg.Vault.AppRoleName == "" {
			return fmt.Errorf("approle_name not configured - required for generating new secret IDs\nAdd 'approle_name = \"your-role-name\"' to the [vault] section of your config")
		}

		logger.WithFields(logrus.Fields{
			"threshold_minutes":   thresholdMinutes,
			"refresh_secret_id":   refreshSecretID,
			"refresh_if_expiring": refreshIfExpiring,
			"update_config":       updateConfig,
			"status_only":         statusOnly,
		}).Info("Checking authentication status")

		// Create context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Vault.Timeout())
		defer cancel()

		// First authenticate to get current token info
		if err := vaultClient.Authenticate(ctx); err != nil {
			return fmt.Errorf("failed to authenticate: %w", err)
		}

		// Get token information
		tokenInfo, err := vaultClient.GetTokenInfo(ctx)
		if err != nil {
			logger.WithError(err).Warn("Failed to get token info, will attempt refresh")
		} else {
			// Log token information
			ttl, _ := tokenInfo["ttl"].(json.Number)
			creationTime, _ := tokenInfo["creation_time"].(string)
			renewable, _ := tokenInfo["renewable"].(bool)

			logger.WithFields(logrus.Fields{
				"ttl_seconds":   ttl,
				"creation_time": creationTime,
				"renewable":     renewable,
				"expires_at":    vaultClient.GetTokenExpiry().Format(time.RFC3339),
			}).Info("Current token information")

			fmt.Printf("Token expires at: %s\n", vaultClient.GetTokenExpiry().Format(time.RFC3339))
		}

		// Get secret ID information if approle_name is configured
		if cfg.Vault.AppRoleName != "" {
			secretIDInfo, err := vaultClient.GetCurrentSecretIDInfo(ctx)
			if err != nil {
				logger.WithError(err).Warn("Failed to get secret ID info")
				fmt.Printf("Warning: Could not retrieve secret ID information: %v\n", err)
			} else {
				// Parse secret ID info
				creationTime, _ := secretIDInfo["creation_time"].(string)
				expirationTime, _ := secretIDInfo["expiration_time"].(string)
				secretIDTTL, _ := secretIDInfo["secret_id_ttl"].(json.Number)
				secretIDAccessor, _ := secretIDInfo["secret_id_accessor"].(string)

				logger.WithFields(logrus.Fields{
					"secret_id_accessor": secretIDAccessor,
					"creation_time":      creationTime,
					"expiration_time":    expirationTime,
					"secret_id_ttl":      secretIDTTL,
				}).Info("Current secret ID information")

				if expirationTime != "" {
					fmt.Printf("Secret ID expires at: %s\n", expirationTime)

					// Check if secret ID is expiring soon
					secretIDExpiring, err := vaultClient.IsSecretIDExpiringWithin(ctx, threshold)
					if err != nil {
						logger.WithError(err).Debug("Failed to check secret ID expiry")
					} else if secretIDExpiring {
						fmt.Printf("⚠️  Secret ID will expire within %v! Consider using --refresh-secret-id\n", threshold)
					}
				} else {
					fmt.Printf("Secret ID TTL: %s seconds (no expiration time available)\n", secretIDTTL)
				}
			}
		} else {
			fmt.Println("Note: approle_name not configured - cannot check secret ID expiry")
		}

		// If status-only was requested, exit here
		if statusOnly {
			fmt.Println("\nStatus check completed.")
			return nil
		}

		// Check if secret ID should be refreshed
		needsSecretIDRefresh := refreshSecretID

		// Handle conditional refresh based on expiry
		if refreshIfExpiring && cfg.Vault.AppRoleName != "" && !statusOnly {
			secretIDExpiring, err := vaultClient.IsSecretIDExpiringWithin(ctx, threshold)
			if err != nil {
				logger.WithError(err).Warn("Failed to check secret ID expiry")
				return fmt.Errorf("failed to check secret ID expiry: %w", err)
			} else if secretIDExpiring {
				logger.Info("Secret ID is expiring soon, refreshing due to --refresh-if-expiring")
				needsSecretIDRefresh = true
				fmt.Printf("🔄 Secret ID expires within %v, refreshing automatically\n", threshold)
			} else {
				logger.Info("Secret ID is not expiring soon, no refresh needed")
				fmt.Printf("✅ Secret ID is not expiring within %v, no refresh needed\n", threshold)
			}
		}

		// If we need to refresh secret ID, do it now
		if needsSecretIDRefresh {
			logger.Info("Generating new secret ID")
			newSecretID, err := vaultClient.RefreshSecretID(ctx)
			if err != nil {
				return fmt.Errorf("failed to refresh secret ID: %w", err)
			}

			logger.Info("Successfully generated new secret ID")

			if updateConfig {
				logger.WithField("config_path", cfgFile).Info("Updating config file with new secret ID")
				if err := config.UpdateSecretID(cfgFile, newSecretID); err != nil {
					return fmt.Errorf("failed to update config file: %w", err)
				}
				logger.Info("Config file updated successfully")
				fmt.Printf("✅ New secret ID saved to config: %s\n", cfgFile)
			} else {
				fmt.Printf("🆔 New secret ID generated:\n%s\n", newSecretID)
				fmt.Println("\n💡 To save to config file, use: --update-config")
				fmt.Println("   Or manually update your config file:")
				fmt.Printf("   secret_id = \"%s\"\n", newSecretID)
			}

			// Update in-memory config and re-authenticate to verify new secret ID works
			cfg.Vault.SecretID = newSecretID
			logger.Info("Testing new secret ID by re-authenticating")
			if err := vaultClient.Authenticate(ctx); err != nil {
				return fmt.Errorf("failed to authenticate with new secret ID: %w", err)
			}
			fmt.Println("✅ New secret ID verified successfully")
		}

		if statusOnly {
			fmt.Println("\n📊 Status check completed.")
		} else {
			fmt.Println("\n✅ Authentication management completed successfully.")
		}

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
	rootCmd.AddCommand(refreshAuthCmd)

	// Add flags specific to encrypt command
	encryptCmd.Flags().BoolP("force", "f", false, "force encryption even if device contains data")

	// Add flags specific to decrypt command
	decryptCmd.Flags().StringP("name", "n", "", "custom name for the device mapping")

	// Add flags specific to refresh-auth command
	refreshAuthCmd.Flags().Float64P("threshold-minutes", "t", 60.0, "minutes before expiry to trigger automatic secret ID refresh")
	refreshAuthCmd.Flags().BoolP("refresh-secret-id", "s", false, "generate new secret ID (requires approle_name in config)")
	refreshAuthCmd.Flags().BoolP("refresh-if-expiring", "r", false, "generate new secret ID only if current one expires within threshold")
	refreshAuthCmd.Flags().BoolP("update-config", "u", false, "update config file with new secret ID")
	refreshAuthCmd.Flags().Bool("status-only", false, "only show authentication status, don't perform any operations")
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
