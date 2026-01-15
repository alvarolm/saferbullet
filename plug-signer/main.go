package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/alvarolm/saferbullet/plug-signer/signing"
	"github.com/spf13/cobra"
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "plug-signer <plugin-file>",
		Short: "Sign SilverBullet plugins with minisign",
		Long: `A simple CLI utility for signing SilverBullet plugins with minisign signatures.

The signature is embedded as a comment at the top of the plugin file:
  // signature|minisign|<base64-public-key>: <base64-signature>

Example:
  plug-signer my-plugin.plug.js --key ~/.minisign/mykey.key`,
		Args: cobra.ExactArgs(1),
		RunE: runSign,
	}

	rootCmd.Flags().StringP("key", "k", "", "Path to minisign private key file (required)")
	rootCmd.MarkFlagRequired("key")
	rootCmd.Flags().StringP("password", "p", "", "Private key password (prompts if not provided)")
	rootCmd.Flags().StringP("output", "o", "", "Output file path (default: overwrite input file)")
	rootCmd.Flags().BoolP("force", "f", false, "Skip overwrite confirmation")
	rootCmd.Flags().StringP("protocol", "r", "minisign", "Signing protocol to use")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runSign(cmd *cobra.Command, args []string) error {
	pluginPath := args[0]
	keyPath, _ := cmd.Flags().GetString("key")
	password, _ := cmd.Flags().GetString("password")
	outputPath, _ := cmd.Flags().GetString("output")
	force, _ := cmd.Flags().GetBool("force")
	protocol, _ := cmd.Flags().GetString("protocol")

	// Set output to input if not specified
	if outputPath == "" {
		outputPath = pluginPath
	}

	// Check if plugin file exists
	if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
		return fmt.Errorf("plugin file not found: %s", pluginPath)
	}

	// Read plugin file
	content, err := readPluginFile(pluginPath)
	if err != nil {
		return fmt.Errorf("failed to read plugin file %q: %w", pluginPath, err)
	}

	// Load private key
	privateKey, err := loadPrivateKey(keyPath, password, protocol)
	if err != nil {
		return err
	}

	// Sign the plugin
	signedContent, err := signing.Sign(content, privateKey, protocol)
	if err != nil {
		return fmt.Errorf("failed to sign plugin: %w", err)
	}

	// Confirm overwrite if output file exists and is different from input
	if outputPath == pluginPath && !force {
		fmt.Fprintf(os.Stderr, "Will overwrite %s. Press Enter to continue or Ctrl+C to cancel...", pluginPath)
		fmt.Scanln()
	}

	// Write signed plugin
	if err := writePluginFile(outputPath, signedContent); err != nil {
		return fmt.Errorf("failed to write signed plugin to %q: %w", outputPath, err)
	}

	// Print success message
	absPath, _ := filepath.Abs(outputPath)
	fmt.Printf("Successfully signed plugin: %s\n", absPath)

	return nil
}
