package main

import (
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	cfgFile string
	verbose bool
	debug   bool
	retry   int
	logger  *logrus.Logger
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
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Set log level based on flags
		if debug {
			logger.SetLevel(logrus.DebugLevel)
		} else if verbose {
			logger.SetLevel(logrus.InfoLevel)
		} else {
			logger.SetLevel(logrus.WarnLevel)
		}
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
		logger.Infof("Encrypting device: %s", device)

		// TODO: Implement encryption logic
		// 1. Validate device exists and is unmounted
		// 2. Generate encryption key
		// 3. Store key in Vault
		// 4. Format device with LUKS
		// 5. Open LUKS device
		// 6. Enable systemd service

		return fmt.Errorf("encrypt command not yet implemented")
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
		logger.Infof("Decrypting device with UUID: %s", uuid)

		// TODO: Implement decryption logic
		// 1. Retrieve key from Vault
		// 2. Open LUKS device
		// 3. Return mapped device path

		return fmt.Errorf("decrypt command not yet implemented")
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