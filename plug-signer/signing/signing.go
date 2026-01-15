package signing

import (
	"encoding/base64"
	"errors"
	"fmt"

	"aead.dev/minisign"
)

// Protocol constants
const (
	MinisignProtocol = "minisign"
)

// SupportedProtocols lists all supported signing protocols.
var SupportedProtocols = []string{MinisignProtocol}

func ValidFormattedPublicKey(protocol, pubKeyFormatted string) error {
	switch protocol {
	case MinisignProtocol:
		var pubKey minisign.PublicKey
		if err := pubKey.UnmarshalText([]byte(pubKeyFormatted)); err != nil {
			return fmt.Errorf("invalid minisign public key: %w", err)
		}
		return nil

	default:
		return fmt.Errorf("unsupported signing protocol: %s", protocol)
	}
}

// Sign signs plugin content with a minisign private key.
// It removes any existing signature with the same protocol and public key,
// preserves other signatures, signs the clean content, and prepends
// the new signature at the top.
func Sign(content []byte, privateKey any, protocol string) ([]byte, error) {
	var (
		signFunc   func(content []byte) ([]byte, error)
		pubKeyFunc func() ([]byte, error)
	)

	switch privKey := privateKey.(type) {
	case minisign.PrivateKey:

		if protocol != MinisignProtocol {
			return nil, fmt.Errorf("unsupported protocol %s for minisign private key", protocol)
		}

		signFunc = func(content []byte) ([]byte, error) {
			return minisign.Sign(privKey, content), nil
		}

		pubKeyFunc = func() ([]byte, error) {
			return privKey.Public().(minisign.PublicKey).MarshalText()
		}

	default:
		return nil, errors.New("unsupported private key type for signing")
	}

	// Get the public key for this private key
	pubKeyText, err := pubKeyFunc()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve public key: %w", err)
	}

	// Remove only signatures matching this protocol and public key
	cleanContent, preservedSignatures := removeMatchingSignature(content, protocol, pubKeyText)

	// Sign the clean content
	signature, err := signFunc(cleanContent)
	if err != nil {
		return nil, fmt.Errorf("failed to sign content: %w", err)
	}

	signatureLine := FormatSignatureLine(protocol, pubKeyText, signature)

	// Build final content: new signature + preserved signatures + clean content
	signedContent := make([]byte, 0, len(signatureLine)+len(preservedSignatures)+len(cleanContent))
	signedContent = append(signedContent, []byte(signatureLine)...)
	signedContent = append(signedContent, preservedSignatures...)
	signedContent = append(signedContent, cleanContent...)

	return signedContent, nil
}

// FormatSignatureLine creates the signature comment line.
// Format: // signature|<protocol>|<base64-pubkey>: <base64-signature>\n
func FormatSignatureLine(protocol string, pubKeyText, signature []byte) string {
	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyText)
	sigBase64 := base64.StdEncoding.EncodeToString(signature)
	return fmt.Sprintf("// signature|%s|%s: %s\n", protocol, pubKeyBase64, sigBase64)
}

// Verify verifies signatures using a configurable validator.
// The validator receives all parsed signatures and decides the verification policy
// (e.g., "at least one trusted key", "all must be valid", "specific key must sign").
func Verify(content []byte, signatureValidator func(sigs []*ParsedSignature) error) error {
	signatures, err := ParseSignatures(content)
	if err != nil {
		return fmt.Errorf("failed to parse signatures: %w", err)
	}

	if err := signatureValidator(signatures); err != nil {
		return fmt.Errorf("signature validation failed: %w", err)
	}

	return nil
}

// VerifySignature cryptographically verifies a single parsed signature against content.
// This is a helper for use within validator callbacks.
func VerifySignature(content []byte, sig *ParsedSignature) error {
	cleanContent := RemoveAllSignatures(content)

	switch sig.Protocol {
	case MinisignProtocol:
		var pubKey minisign.PublicKey
		if err := pubKey.UnmarshalText(sig.PublicKeyText); err != nil {
			return fmt.Errorf("failed to unmarshal minisign public key: %w", err)
		}

		if !minisign.Verify(pubKey, cleanContent, sig.Signature) {
			return errors.New("signature verification failed")
		}
		return nil

	default:
		return fmt.Errorf("unsupported signing protocol: %s", sig.Protocol)
	}
}
