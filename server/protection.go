package server

import (
	"errors"
	"os"
	"slices"

	"github.com/alvarolm/saferbullet/plug-signer/signing"

	"github.com/pelletier/go-toml/v2"
)

type publicKeyMetadata struct {
	Owner string `toml:"owner"`
	Info  string `toml:"info,omitempty"`
}

type protectionConfig struct {
	// List of trusted public keys for plugin signing
	// map[signing-protcol]map[protocol-encoded-public-key]PublicKeyMetadata
	TrustedPublicKeys map[string]map[string]publicKeyMetadata `toml:"trusted_public_keys"`

	AllowUnsignedPlugins bool `toml:"allow_unsigned_plugins"`
}

var userProtectionConfig *protectionConfig

func (p *protectionConfig) validateAndDecode() error {

	for protocol, pubkeys := range p.TrustedPublicKeys {

		if len(protocol) == 0 {
			return errors.New("signing protocol cannot be empty")
		}

		if !slices.Contains(signing.SupportedProtocols, protocol) {
			return errors.New("unknown signing protocol: " + protocol)
		}

		for pubkey, info := range pubkeys {

			if len(pubkey) == 0 {
				return errors.New("public key cannot be empty")
			}

			if err := signing.ValidFormattedPublicKey(protocol, pubkey); err != nil {
				return errors.New("invalid public key for protocol " + protocol + ": " + err.Error())
			}

			if len(info.Owner) == 0 {
				return errors.New("owner metadata cannot be empty for public key: " + pubkey)
			}

		}
	}

	return nil

}

func init() {

	configPath := os.Getenv("SB_PROTECTION_CONFIG")

	if len(configPath) == 0 {
		return
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		panic("failed to read protection config file: " + err.Error())
	}

	var config protectionConfig
	if err := toml.Unmarshal(data, &config); err != nil {
		panic("failed to parse protection config file: " + err.Error())
	}

	if err := config.validateAndDecode(); err != nil {
		panic("invalid protection config: " + err.Error())
	}

	userProtectionConfig = &config

}
