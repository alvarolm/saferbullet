package server

import (
	"errors"

	"github.com/alvarolm/saferbullet/plug-signer/signing"
)

/*

plugins are js files with .plug.js suffix
they can be signed, the signature must be embedded in the file as a comment, ideally at the top, like so:

myPlugin.plug.js:
// signature|<signing-protocol>|<base64-encoded-public-key>: <base64-encoded-signature>
<javascript code of the plugin>

- the signature is calculated over the entire file content, excluding the signature line itself.
- the signing-protocol indicates which signing protocol is used, currently only "minisign" is supported.
- the public key is used to look up the trusted public keys configured in the server.

*/

func verifyPlugin(fileContent []byte, mustBeSigned bool) error {

	var ErrVerificationSkipped = errors.New("signature verification skipped")

	err := signing.Verify(
		fileContent,
		func(signatures []*signing.ParsedSignature) error {

			if len(signatures) == 0 {
				if mustBeSigned {
					return errors.New("missing signature")
				}
				return ErrVerificationSkipped
			}

			if userProtectionConfig == nil {
				return errors.New("protection config not loaded")
			}

			// Find a signature from a trusted public key and verify it
			for _, parsed := range signatures {
				pubkeysMap, ok := userProtectionConfig.TrustedPublicKeys[parsed.Protocol]
				if !ok || len(pubkeysMap) == 0 {
					continue // No trusted keys for this protocol, try next signature
				}

				_, exists := pubkeysMap[string(parsed.PublicKeyText)]
				if !exists {
					continue // Key not trusted, try next signature
				}

				// Found a trusted signature, verify it cryptographically
				return signing.VerifySignature(fileContent, parsed)
			}

			// No trusted signature found
			return errors.New("no signature from a trusted public key")
		},
	)

	if err != nil {
		if errors.Is(err, ErrVerificationSkipped) {
			return nil
		}
	}
	return err

}
