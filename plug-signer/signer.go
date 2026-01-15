package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"aead.dev/minisign"
	"github.com/alvarolm/saferbullet/plug-signer/signing"
	"golang.org/x/term"
)

// loadPrivateKey reads and decrypts a minisign private key from a file.
func loadPrivateKey(keyPath, password, protocol string) (privKey any, err error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	switch protocol {
	case signing.MinisignProtocol:

		// Prompt for password if not provided
		if password == "" {
			password, err = promptPassword("Enter private key password: ")
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve private key password: %w", err)
			}
		}

		// Try to decrypt the key
		privateKey, err := minisign.DecryptKey(password, keyBytes)
		if err != nil {
			// Check if it's a password error
			if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "decrypt") {
				return nil, errors.New("failed to decrypt private key (wrong password?)")
			}
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}
		return privateKey, nil

	default:
		return nil, fmt.Errorf("unsupported signing protocol: %s", protocol)
	}

}

// promptPassword securely prompts for a password without echoing to the terminal.
func promptPassword(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr) // Add newline after password input

	if err != nil {
		return "", fmt.Errorf("failed to read password: %w", err)
	}

	return string(passwordBytes), nil
}

// readPluginFile reads and validates a plugin file.
func readPluginFile(path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	if len(content) == 0 {
		return nil, errors.New("plugin file is empty")
	}

	return content, nil
}

// writePluginFile writes content to a file with appropriate permissions.
func writePluginFile(path string, content []byte) error {
	return os.WriteFile(path, content, 0644)
}
