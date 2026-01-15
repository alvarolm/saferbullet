package signing

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"

	"aead.dev/minisign"
)

func parseSignature(content []byte) (*ParsedSignature, error) {
	sigs, err := ParseSignatures(content)
	if err != nil {
		return nil, err
	}
	if len(sigs) == 0 {
		return nil, nil
	}
	return sigs[0], nil
}

func TestParseSignature(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		expectParsed  bool
		expectError   bool
		errorContains string
	}{
		{
			name:         "no signature",
			content:      "console.log('hello');\nexport default function() {}",
			expectParsed: false,
			expectError:  false,
		},
		{
			name:         "valid signature",
			content:      "// signature|minisign|dGVzdGtleQ==: dGVzdHNpZw==\nconsole.log('hello');",
			expectParsed: true,
			expectError:  false,
		},
		{
			name:          "empty content",
			content:       "",
			expectParsed:  false,
			expectError:   true,
			errorContains: "content is empty",
		},
		{
			name:          "missing colon separator",
			content:       "// signature|minisign|dGVzdGtleQ==\nconsole.log('hello');",
			expectParsed:  false,
			expectError:   true,
			errorContains: "missing colon separator",
		},
		{
			name:          "wrong number of fields",
			content:       "// signature|minisign: dGVzdHNpZw==\nconsole.log('hello');",
			expectParsed:  false,
			expectError:   true,
			errorContains: "expected 3 pipe-separated fields",
		},
		{
			name:          "missing protocol",
			content:       "// signature||dGVzdGtleQ==: dGVzdHNpZw==\nconsole.log('hello');",
			expectParsed:  false,
			expectError:   true,
			errorContains: "missing signing protocol",
		},
		{
			name:          "invalid base64 public key",
			content:       "// signature|minisign|not-valid-base64!: dGVzdHNpZw==\nconsole.log('hello');",
			expectParsed:  false,
			expectError:   true,
			errorContains: "invalid base64 public key",
		},
		{
			name:          "invalid base64 signature",
			content:       "// signature|minisign|dGVzdGtleQ==: not-valid-base64!\nconsole.log('hello');",
			expectParsed:  false,
			expectError:   true,
			errorContains: "invalid base64 signature",
		},
		{
			name:         "signature not in first 50 lines",
			content:      "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n20\n21\n22\n23\n24\n25\n26\n27\n28\n29\n30\n31\n32\n33\n34\n35\n36\n37\n38\n39\n40\n41\n42\n43\n44\n45\n46\n47\n48\n49\n50\n// signature|minisign|dGVzdGtleQ==: dGVzdHNpZw==\ncontent",
			expectParsed: false,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := parseSignature([]byte(tt.content))

			if tt.expectError {
				if err == nil {
					t.Errorf("ParseSignature() expected error containing %q, got no error", tt.errorContains)
					return
				}
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("ParseSignature() error = %q, expected to contain %q", err.Error(), tt.errorContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseSignature() unexpected error = %v", err)
				return
			}

			if tt.expectParsed && parsed == nil {
				t.Error("ParseSignature() expected parsed signature, got nil")
			}
			if !tt.expectParsed && parsed != nil {
				t.Errorf("ParseSignature() expected nil, got %+v", parsed)
			}
		})
	}
}

func TestRemoveSignature(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no signature",
			input:    "console.log('hello');\nexport default function() {}",
			expected: "console.log('hello');\nexport default function() {}",
		},
		{
			name:     "signature at top",
			input:    "// signature|minisign|dGVzdA==: c2ln\nconsole.log('hello');\n",
			expected: "console.log('hello');\n",
		},
		{
			name:     "signature with content before",
			input:    "// some comment\n// signature|minisign|dGVzdA==: c2ln\nconsole.log('hello');\n",
			expected: "// some comment\nconsole.log('hello');\n",
		},
		{
			name:     "signature not in first 50 lines - should not be removed",
			input:    "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\nline11\nline12\nline13\nline14\nline15\nline16\nline17\nline18\nline19\nline20\nline21\nline22\nline23\nline24\nline25\nline26\nline27\nline28\nline29\nline30\nline31\nline32\nline33\nline34\nline35\nline36\nline37\nline38\nline39\nline40\nline41\nline42\nline43\nline44\nline45\nline46\nline47\nline48\nline49\nline50\n// signature|minisign|dGVzdA==: c2ln\ncontent",
			expected: "line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\nline9\nline10\nline11\nline12\nline13\nline14\nline15\nline16\nline17\nline18\nline19\nline20\nline21\nline22\nline23\nline24\nline25\nline26\nline27\nline28\nline29\nline30\nline31\nline32\nline33\nline34\nline35\nline36\nline37\nline38\nline39\nline40\nline41\nline42\nline43\nline44\nline45\nline46\nline47\nline48\nline49\nline50\n// signature|minisign|dGVzdA==: c2ln\ncontent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveAllSignatures([]byte(tt.input))
			if string(result) != tt.expected {
				t.Errorf("RemoveSignature() = %q, want %q", string(result), tt.expected)
			}
		})
	}
}

func TestSign(t *testing.T) {
	// Generate a test key pair
	publicKey, privateKey, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	testContent := []byte("console.log('test plugin');\nexport default function() {}\n")

	// Sign the content
	signedContent, err := Sign(testContent, privateKey, MinisignProtocol)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify the signed content starts with signature comment
	if !bytes.HasPrefix(signedContent, []byte("// signature|minisign|")) {
		t.Error("Sign() result should start with signature comment")
	}

	// Parse and verify the signature
	parsed, err := parseSignature(signedContent)
	if err != nil {
		t.Fatalf("ParseSignature() error = %v", err)
	}
	if parsed == nil {
		t.Fatal("ParseSignature() returned nil")
	}

	if parsed.Protocol != MinisignProtocol {
		t.Errorf("Protocol = %q, want %q", parsed.Protocol, MinisignProtocol)
	}

	// Verify the signature is valid
	cleanContent := RemoveAllSignatures(signedContent)
	if !minisign.Verify(publicKey, cleanContent, parsed.Signature) {
		t.Error("Signature verification failed")
	}
}

func TestSignResigning(t *testing.T) {
	// Generate a test key pair
	_, privateKey, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Content with existing signature from a different key
	existingSignedContent := []byte("// signature|minisign|b2xkcHVia2V5: b2xkc2ln\nconsole.log('test');\n")

	// Sign the content with our key
	signedContent, err := Sign(existingSignedContent, privateKey, MinisignProtocol)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Should have two signatures (old one preserved, new one added)
	signatureCount := strings.Count(string(signedContent), "// signature|minisign|")
	if signatureCount != 2 {
		t.Errorf("Expected 2 signature lines (old preserved + new), got %d", signatureCount)
	}

	// Original content (without signatures) should be preserved
	if !strings.Contains(string(signedContent), "console.log('test');") {
		t.Error("Original content not preserved")
	}
}

func TestVerify(t *testing.T) {
	// Generate a test key pair
	publicKey, privateKey, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	testContent := []byte("console.log('test');\n")

	// Sign the content
	signedContent, err := Sign(testContent, privateKey, MinisignProtocol)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify should succeed with correct key
	if err := Verify(signedContent, func(sigs []*ParsedSignature) error {
		if len(sigs) == 0 {
			return errors.New("no signatures found")
		}
		expectedPubKey, _ := publicKey.MarshalText()
		for _, ps := range sigs {
			if bytes.Equal(ps.PublicKeyText, expectedPubKey) {
				return VerifySignature(signedContent, ps)
			}
		}
		return errors.New("public key does not match any signature")
	}); err != nil {
		t.Errorf("Verify() error = %v, expected nil", err)
	}

	// Generate a different key pair
	wrongPublicKey, _, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Verify should fail with wrong key
	if err := Verify(signedContent, func(sigs []*ParsedSignature) error {
		if len(sigs) == 0 {
			return errors.New("no signatures found")
		}
		expectedPubKey, _ := wrongPublicKey.MarshalText()
		for _, ps := range sigs {
			if bytes.Equal(ps.PublicKeyText, expectedPubKey) {
				return VerifySignature(signedContent, ps)
			}
		}
		return errors.New("public key does not match any signature")
	}); err == nil {
		t.Error("Verify() expected error with wrong key, got nil")
	}
}

func TestVerifyNoSignature(t *testing.T) {
	publicKey, _, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Content without signature
	content := []byte("console.log('test');\n")

	// Verify should fail
	err = Verify(content, func(sigs []*ParsedSignature) error {
		if len(sigs) == 0 {
			return errors.New("no signature found")
		}

		expectedPubKey, _ := publicKey.MarshalText()
		for _, ps := range sigs {
			if bytes.Equal(ps.PublicKeyText, expectedPubKey) {
				return VerifySignature(content, ps)
			}
		}
		return errors.New("public key does not match")
	})
	if err == nil {
		t.Error("Verify() expected error for unsigned content, got nil")
	}
	if !strings.Contains(err.Error(), "no signature found") {
		t.Errorf("Verify() error = %q, expected to contain 'no signature found'", err.Error())
	}
}

func TestFormatSignatureLine(t *testing.T) {
	pubKeyText := []byte("RWQtest")
	signature := []byte("testsig")

	line := FormatSignatureLine(MinisignProtocol, pubKeyText, signature)

	// Should start with comment prefix
	if !strings.HasPrefix(line, "// signature|minisign|") {
		t.Errorf("FormatSignatureLine() = %q, expected to start with '// signature|minisign|'", line)
	}

	// Should end with newline
	if !strings.HasSuffix(line, "\n") {
		t.Errorf("FormatSignatureLine() = %q, expected to end with newline", line)
	}

	// Should contain colon separator
	if !strings.Contains(line, ": ") {
		t.Errorf("FormatSignatureLine() = %q, expected to contain ': '", line)
	}
}

func TestParseSignatures(t *testing.T) {
	tests := []struct {
		name          string
		content       string
		expectCount   int
		expectError   bool
		errorContains string
	}{
		{
			name:        "no signatures",
			content:     "console.log('hello');\nexport default function() {}",
			expectCount: 0,
			expectError: false,
		},
		{
			name:        "single signature",
			content:     "// signature|minisign|dGVzdGtleQ==: dGVzdHNpZw==\nconsole.log('hello');",
			expectCount: 1,
			expectError: false,
		},
		{
			name:        "two signatures",
			content:     "// signature|minisign|dGVzdGtleTE=: dGVzdHNpZzE=\n// signature|minisign|dGVzdGtleTI=: dGVzdHNpZzI=\nconsole.log('hello');",
			expectCount: 2,
			expectError: false,
		},
		{
			name:        "three signatures",
			content:     "// signature|minisign|dGVzdGtleTE=: dGVzdHNpZzE=\n// signature|minisign|dGVzdGtleTI=: dGVzdHNpZzI=\n// signature|minisign|dGVzdGtleTM=: dGVzdHNpZzM=\nconsole.log('hello');",
			expectCount: 3,
			expectError: false,
		},
		{
			name:          "malformed signature in multi-sig",
			content:       "// signature|minisign|dGVzdGtleTE=: dGVzdHNpZzE=\n// signature|minisign: invalid\nconsole.log('hello');",
			expectCount:   0,
			expectError:   true,
			errorContains: "expected 3 pipe-separated fields",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigs, err := ParseSignatures([]byte(tt.content))

			if tt.expectError {
				if err == nil {
					t.Errorf("ParseSignatures() expected error containing %q, got no error", tt.errorContains)
					return
				}
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("ParseSignatures() error = %q, expected to contain %q", err.Error(), tt.errorContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseSignatures() unexpected error = %v", err)
				return
			}

			if len(sigs) != tt.expectCount {
				t.Errorf("ParseSignatures() returned %d signatures, expected %d", len(sigs), tt.expectCount)
			}
		})
	}
}

func TestRemoveAllSignatures(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "no signatures",
			input:    "console.log('hello');\nexport default function() {}",
			expected: "console.log('hello');\nexport default function() {}",
		},
		{
			name:     "single signature",
			input:    "// signature|minisign|dGVzdA==: c2ln\nconsole.log('hello');\n",
			expected: "console.log('hello');\n",
		},
		{
			name:     "two signatures",
			input:    "// signature|minisign|dGVzdDE=: c2lnMQ==\n// signature|minisign|dGVzdDI=: c2lnMg==\nconsole.log('hello');\n",
			expected: "console.log('hello');\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := RemoveAllSignatures([]byte(tt.input))
			if string(result) != tt.expected {
				t.Errorf("RemoveAllSignatures() = %q, want %q", string(result), tt.expected)
			}
		})
	}
}

func TestSignReplacesSameKey(t *testing.T) {
	// Generate a key pair
	_, privateKey, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	testContent := []byte("console.log('test');\n")

	// Sign once
	signed1, err := Sign(testContent, privateKey, MinisignProtocol)
	if err != nil {
		t.Fatalf("First Sign() error = %v", err)
	}

	// Sign again with same key
	signed2, err := Sign(signed1, privateKey, MinisignProtocol)
	if err != nil {
		t.Fatalf("Second Sign() error = %v", err)
	}

	// Should still have only one signature
	sigs, err := ParseSignatures(signed2)
	if err != nil {
		t.Fatalf("ParseSignatures() error = %v", err)
	}
	if len(sigs) != 1 {
		t.Errorf("Expected 1 signature after re-signing with same key, got %d", len(sigs))
	}
}

func TestVerifySignature(t *testing.T) {
	// Generate a test key pair
	publicKey, privateKey, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	testContent := []byte("console.log('test');\n")

	// Sign the content
	signedContent, err := Sign(testContent, privateKey, MinisignProtocol)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Parse the signature
	sigs, err := ParseSignatures(signedContent)
	if err != nil {
		t.Fatalf("ParseSignatures() error = %v", err)
	}
	if len(sigs) == 0 {
		t.Fatal("Expected at least one signature")
	}

	// Verify using the helper function
	err = VerifySignature(signedContent, sigs[0])
	if err != nil {
		t.Errorf("VerifySignature() error = %v, expected nil", err)
	}

	// Verify the public key matches
	expectedPubKey, _ := publicKey.MarshalText()
	if !bytes.Equal(sigs[0].PublicKeyText, expectedPubKey) {
		t.Error("Public key in signature does not match expected")
	}
}

func TestMultiSignatureSupport(t *testing.T) {
	// Generate three different key pairs
	pubKey1, privKey1, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair 1: %v", err)
	}

	pubKey2, privKey2, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair 2: %v", err)
	}

	pubKey3, privKey3, err := minisign.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair 3: %v", err)
	}

	testContent := []byte("console.log('multi-sig test');\n")

	// Sign with first key
	signed1, err := Sign(testContent, privKey1, MinisignProtocol)
	if err != nil {
		t.Fatalf("Sign with key 1 failed: %v", err)
	}

	// Sign with second key (should preserve first signature)
	signed2, err := Sign(signed1, privKey2, MinisignProtocol)
	if err != nil {
		t.Fatalf("Sign with key 2 failed: %v", err)
	}

	// Sign with third key (should preserve both previous signatures)
	signed3, err := Sign(signed2, privKey3, MinisignProtocol)
	if err != nil {
		t.Fatalf("Sign with key 3 failed: %v", err)
	}

	fmt.Println(string(signed3))

	// Parse all signatures
	sigs, err := ParseSignatures(signed3)
	if err != nil {
		t.Fatalf("ParseSignatures failed: %v", err)
	}

	// Should have 3 signatures
	if len(sigs) != 3 {
		t.Fatalf("Expected 3 signatures, got %d", len(sigs))
	}

	// Verify all three signatures are valid
	pubKeys := []minisign.PublicKey{pubKey1, pubKey2, pubKey3}
	verifiedCount := 0

	for _, sig := range sigs {
		for _, pubKey := range pubKeys {
			pubKeyText, _ := pubKey.MarshalText()
			if bytes.Equal(sig.PublicKeyText, pubKeyText) {
				if err := VerifySignature(signed3, sig); err != nil {
					t.Errorf("Signature verification failed for a key: %v", err)
				} else {
					verifiedCount++
				}
				break
			}
		}
	}

	if verifiedCount != 3 {
		t.Errorf("Expected 3 verified signatures, got %d", verifiedCount)
	}

	// Re-sign with key 1 (should replace only key 1's signature, preserve others)
	resigned1, err := Sign(signed3, privKey1, MinisignProtocol)
	if err != nil {
		t.Fatalf("Re-sign with key 1 failed: %v", err)
	}

	// Should still have 3 signatures
	sigs, err = ParseSignatures(resigned1)
	if err != nil {
		t.Fatalf("ParseSignatures after re-sign failed: %v", err)
	}

	if len(sigs) != 3 {
		t.Errorf("Expected 3 signatures after re-signing with key 1, got %d", len(sigs))
	}
}
