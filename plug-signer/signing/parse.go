package signing

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
)

// ParsedSignature contains the extracted components of a plugin signature.
type ParsedSignature struct {
	Protocol        string // e.g., "minisign"
	PublicKeyBase64 string // base64-encoded public key text
	PublicKeyText   []byte // decoded public key text (e.g., "RWQ...")
	SignatureBase64 string // base64-encoded signature
	Signature       []byte // decoded raw signature bytes
	SignatureLine   string // the full original signature line
}

// ParseSignatures extracts all signatures from plugin content.
// Scans first 50 lines for signature comments in the format:
//
//	// signature|<protocol>|<base64-pubkey>: <base64-signature>
//
// Returns empty slice if no signatures are found (not an error).
// Returns an error if any signature comment is malformed.
func ParseSignatures(content []byte) ([]*ParsedSignature, error) {
	if len(content) == 0 {
		return nil, errors.New("content is empty")
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	lineCount := 0
	var signatures []*ParsedSignature

	for scanner.Scan() && lineCount < 50 {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)

		if !strings.HasPrefix(trimmedLine, "// signature|") {
			lineCount++
			continue
		}

		// Parse: // signature|protocol|pubkey: signature
		commentContent := strings.TrimSpace(strings.TrimPrefix(trimmedLine, "//"))

		parts := strings.SplitN(commentContent, ":", 2)
		if len(parts) != 2 {
			return nil, errors.New("invalid signature format: missing colon separator")
		}

		fields := strings.Split(strings.TrimSpace(parts[0]), "|")
		if len(fields) != 3 {
			return nil, errors.New("invalid signature format: expected 3 pipe-separated fields")
		}

		if fields[0] != "signature" {
			return nil, errors.New("invalid signature format: must start with 'signature'")
		}

		protocol := strings.TrimSpace(fields[1])
		if protocol == "" {
			return nil, errors.New("invalid signature format: missing signing protocol")
		}

		pubKeyBase64 := strings.TrimSpace(fields[2])
		pubKeyText, err := base64.StdEncoding.DecodeString(pubKeyBase64)
		if err != nil {
			return nil, errors.New("invalid base64 public key: " + err.Error())
		}

		if len(pubKeyText) == 0 {
			return nil, errors.New("invalid signature format: missing public key")
		}

		sigBase64 := strings.TrimSpace(parts[1])
		signature, err := base64.StdEncoding.DecodeString(sigBase64)
		if err != nil {
			return nil, errors.New("invalid base64 signature: " + err.Error())
		}

		signatures = append(signatures, &ParsedSignature{
			Protocol:        protocol,
			PublicKeyBase64: pubKeyBase64,
			PublicKeyText:   pubKeyText,
			SignatureBase64: sigBase64,
			Signature:       signature,
			SignatureLine:   line,
		})
		lineCount++
	}

	return signatures, nil
}

// RemoveAllSignatures removes all signature lines from content.
// Returns the clean content (unchanged if no signatures found or on error).
func RemoveAllSignatures(content []byte) []byte {
	signatures, err := ParseSignatures(content)
	if err != nil || len(signatures) == 0 {
		return content
	}

	// Collect signature lines to remove
	linesToRemove := make(map[string]struct{}, len(signatures))
	for _, sig := range signatures {
		linesToRemove[sig.SignatureLine] = struct{}{}
	}

	// Find where the signature block ends (track position after last signature)
	var result []byte
	pos := 0
	lineCount := 0

	for pos < len(content) && lineCount < 50 {
		// Find end of current line
		nextNewline := bytes.IndexByte(content[pos:], '\n')
		var lineEnd int
		if nextNewline == -1 {
			lineEnd = len(content)
		} else {
			lineEnd = pos + nextNewline
		}

		line := string(content[pos:lineEnd])

		if _, shouldRemove := linesToRemove[line]; !shouldRemove {
			result = append(result, content[pos:lineEnd]...)
			result = append(result, '\n')
		}

		if nextNewline == -1 {
			return result[:len(result)-1] // Remove trailing newline we added
		}

		pos = lineEnd + 1
		lineCount++
	}

	// Append remaining content as a block (after first 50 lines)
	if pos < len(content) {
		result = append(result, content[pos:]...)
	} else if len(result) > 0 && content[len(content)-1] != '\n' {
		// Remove trailing newline if original didn't have one
		result = result[:len(result)-1]
	}

	return result
}

// removeMatchingSignature removes signatures matching both the protocol and public key.
// Returns the clean content and the preserved signature lines (as bytes with newlines).
func removeMatchingSignature(content []byte, protocol string, pubKeyText []byte) ([]byte, []byte) {

	// 8KB should be enough for any header: "// signature|protocol|pubkey: "
	const maxSigntureSizeHeader = 8 * 1024

	pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyText)

	// Expected pattern: ... "signature|<protocol>|<pubkey>: <signature>"
	matchPattern := []byte("signature|" + protocol + "|" + pubKeyBase64 + ":")

	var preservedSigs []byte
	var cleanContent []byte

	pos := 0
	lineCount := 0
	foundNonSigLine := false

	for pos < len(content) && lineCount < 50 {
		lineStart := pos

		// Find end of current line
		newlineIdx := bytes.Index(content[pos:], []byte{'\n'})
		var lineEnd int
		var hasNewline bool

		if newlineIdx == -1 {
			// Last line without newline
			lineEnd = len(content)
			hasNewline = false
		} else {
			lineEnd = pos + newlineIdx
			hasNewline = true
		}

		line := content[lineStart:lineEnd]
		trimmed := bytes.TrimSpace(line)

		// trim line if its longer than maxSigntureSizeHeader
		if len(trimmed) > maxSigntureSizeHeader {
			trimmed = trimmed[:maxSigntureSizeHeader]
		}

		// Check if this is a signature line
		if len(trimmed) > 8 && bytes.HasPrefix(trimmed, []byte("//")) && bytes.Contains(trimmed, []byte("signature|")) {
			// Check if it matches the protocol and public key we're removing
			if !bytes.Contains(trimmed, matchPattern) {
				preservedSigs = append(preservedSigs, line...)
				preservedSigs = append(preservedSigs, '\n')
			}
		} else {
			// First non-signature line - capture rest of content
			foundNonSigLine = true
			cleanContent = append(cleanContent, content[lineStart:]...)
			break
		}

		if !hasNewline {
			break
		}

		pos = lineEnd + 1
		lineCount++
	}

	// If we scanned 50 lines of only signatures, append remaining content
	if !foundNonSigLine && pos < len(content) {
		cleanContent = append(cleanContent, content[pos:]...)
	}

	return cleanContent, preservedSigs
}
