package server

import (
	"strings"
	"testing"
)

func TestVerifyPlugin(t *testing.T) {
	tests := []struct {
		name          string
		fileContent   []byte
		mustBeSigned  bool
		expectError   bool
		errorContains string
	}{
		{
			name:          "empty file",
			fileContent:   []byte(""),
			mustBeSigned:  false,
			expectError:   true,
			errorContains: "content is empty",
		},
		{
			name:          "unsigned plugin - signing optional",
			fileContent:   []byte("console.log('hello world');\nexport default function() {}"),
			mustBeSigned:  false,
			expectError:   false,
			errorContains: "",
		},
		{
			name:          "unsigned plugin - signing required",
			fileContent:   []byte("console.log('hello world');\nexport default function() {}"),
			mustBeSigned:  true,
			expectError:   true,
			errorContains: "missing signature",
		},
		{
			name:          "invalid signature format - missing colon",
			fileContent:   []byte("// signature|minisign|dGVzdGtleQ==\nconsole.log('hello');"),
			mustBeSigned:  false,
			expectError:   true,
			errorContains: "invalid signature format: missing colon separator",
		},
		{
			name:          "invalid signature format - wrong number of fields",
			fileContent:   []byte("// signature|minisign: dGVzdHNpZ25hdHVyZQ==\nconsole.log('hello');"),
			mustBeSigned:  false,
			expectError:   true,
			errorContains: "invalid signature format: expected 3 pipe-separated fields",
		},
		{
			name:          "invalid signature format - missing protocol",
			fileContent:   []byte("// signature||dGVzdGtleQ==: dGVzdHNpZ25hdHVyZQ==\nconsole.log('hello');"),
			mustBeSigned:  false,
			expectError:   true,
			errorContains: "invalid signature format: missing signing protocol",
		},
		{
			name:          "invalid signature format - invalid base64 public key",
			fileContent:   []byte("// signature|minisign|not-valid-base64!: dGVzdHNpZ25hdHVyZQ==\nconsole.log('hello');"),
			mustBeSigned:  false,
			expectError:   true,
			errorContains: "invalid base64 public key",
		},
		{
			name:          "invalid signature format - invalid base64 signature",
			fileContent:   []byte("// signature|minisign|dGVzdGtleQ==: not-valid-base64!\nconsole.log('hello');"),
			mustBeSigned:  false,
			expectError:   true,
			errorContains: "invalid base64 signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// empty protection config
			userProtectionConfig = &protectionConfig{
				TrustedPublicKeys: map[string]map[string]publicKeyMetadata{},
			}

			err := verifyPlugin(tt.fileContent, tt.mustBeSigned)

			if tt.expectError {
				if err == nil {
					t.Errorf("verifyPlugin() expected error containing %q, but got no error", tt.errorContains)
					return
				}
				if !strings.Contains(err.Error(), tt.errorContains) {
					t.Errorf("verifyPlugin() error = %q, expected to contain %q", err.Error(), tt.errorContains)
				}
			} else {
				if err != nil {
					t.Errorf("verifyPlugin() unexpected error = %v", err)
				}
			}
		})
	}
}
