package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetConfigFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     []string
		expected string
	}{
		{
			name:     "no arguments",
			args:     []string{},
			expected: "",
		},
		{
			name:     "conf flag with file",
			args:     []string{"-conf", "Corefile.test"},
			expected: "Corefile.test",
		},
		{
			name:     "conf flag in middle of args",
			args:     []string{"-dns.port", "5354", "-conf", "Corefile.local-dev", "-other", "flag"},
			expected: "Corefile.local-dev",
		},
		{
			name:     "conf flag at end without value",
			args:     []string{"-dns.port", "5354", "-conf"},
			expected: "",
		},
		{
			name:     "other flags only",
			args:     []string{"-dns.port", "5354", "-log.level", "debug"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := getConfigFileFromArgs(tt.args)
			if result != tt.expected {
				t.Errorf("getConfigFileFromArgs() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestIsMissingP2PForgePlugins(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		corefileContent string
		expected        bool
	}{
		{
			name: "valid corefile with both plugins",
			corefileContent: `libp2p.direct {
    log
    errors
    ipparser libp2p.direct
    acme libp2p.direct {
        registration-domain registration.libp2p.direct
        database-type badger test.db
    }
}`,
			expected: false,
		},
		{
			name: "missing acme plugin",
			corefileContent: `libp2p.direct {
    log
    errors
    ipparser libp2p.direct
}`,
			expected: true,
		},
		{
			name: "missing ipparser plugin",
			corefileContent: `libp2p.direct {
    log
    errors
    acme libp2p.direct {
        registration-domain registration.libp2p.direct
        database-type badger test.db
    }
}`,
			expected: true,
		},
		{
			name: "missing both plugins",
			corefileContent: `libp2p.direct {
    log
    errors
}`,
			expected: true,
		},
		{
			name:            "empty file",
			corefileContent: "",
			expected:        true,
		},
		{
			name: "plugins mentioned in comments only",
			corefileContent: `libp2p.direct {
    log
    errors
    # acme libp2p.direct
    # ipparser libp2p.direct
}`,
			expected: true,
		},
		{
			name: "plugins in different server blocks",
			corefileContent: `server1 {
    ipparser example.com
}
server2 {
    acme example.com
}`,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Create temporary file
			tmpDir := t.TempDir()
			tmpFile := filepath.Join(tmpDir, "Corefile.test")

			err := os.WriteFile(tmpFile, []byte(tt.corefileContent), 0644)
			if err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			result := isMissingP2PForgePlugins(tmpFile)
			if result != tt.expected {
				t.Errorf("isMissingP2PForgePlugins() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func TestIsMissingP2PForgePlugins_NonExistentFile(t *testing.T) {
	t.Parallel()

	// Test with non-existent file - should return false to let CoreDNS handle the error
	result := isMissingP2PForgePlugins("/path/that/does/not/exist")
	if result != false {
		t.Errorf("isMissingP2PForgePlugins() with non-existent file = %v, expected false", result)
	}
}

func TestShouldShowUsageGuidance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name              string
		args              []string
		createCorefile    bool
		corefileContent   string
		createDefaultFile bool
		expected          bool
	}{
		{
			name:              "no Corefile exists, no explicit config",
			args:              []string{},
			createCorefile:    false,
			createDefaultFile: false,
			expected:          true,
		},
		{
			name:              "valid default Corefile exists",
			args:              []string{},
			createCorefile:    true,
			createDefaultFile: false,
			corefileContent:   "libp2p.direct {\n    ipparser libp2p.direct\n    acme libp2p.direct\n}",
			expected:          false,
		},
		{
			name:              "invalid default Corefile exists",
			args:              []string{},
			createCorefile:    true,
			createDefaultFile: false,
			corefileContent:   "libp2p.direct {\n    log\n    errors\n}",
			expected:          true,
		},
		{
			name:              "explicit valid config file",
			args:              []string{"-conf", "Corefile.test"},
			createCorefile:    false,
			createDefaultFile: true,
			corefileContent:   "libp2p.direct {\n    ipparser libp2p.direct\n    acme libp2p.direct\n}",
			expected:          false,
		},
		{
			name:              "explicit invalid config file",
			args:              []string{"-conf", "Corefile.test"},
			createCorefile:    false,
			createDefaultFile: true,
			corefileContent:   "libp2p.direct {\n    log\n}",
			expected:          true,
		},
		{
			name:              "explicit non-existent config file",
			args:              []string{"-conf", "nonexistent.conf"},
			createCorefile:    false,
			createDefaultFile: false,
			expected:          false, // Let CoreDNS handle the missing file error
		},
		{
			name:              "explicit absolute path config file",
			args:              []string{"-conf", "/absolute/path/Corefile"},
			createCorefile:    false,
			createDefaultFile: false,
			expected:          false, // Absolute paths should not be modified
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Create temporary directory for test files
			tmpDir := t.TempDir()

			// Create files as needed using absolute paths in temp directory
			if tt.createCorefile {
				corefilePath := filepath.Join(tmpDir, "Corefile")
				err := os.WriteFile(corefilePath, []byte(tt.corefileContent), 0644)
				if err != nil {
					t.Fatalf("Failed to create Corefile: %v", err)
				}
			}

			if tt.createDefaultFile {
				filename := filepath.Join(tmpDir, "Corefile.test") // matches the -conf argument in test cases
				err := os.WriteFile(filename, []byte(tt.corefileContent), 0644)
				if err != nil {
					t.Fatalf("Failed to create test config file: %v", err)
				}
			}

			// Use the new testable function with custom working directory
			result := shouldShowUsageGuidanceWithOptions(tt.args, tmpDir)
			if result != tt.expected {
				t.Errorf("shouldShowUsageGuidanceWithOptions() = %v, expected %v", result, tt.expected)
			}
		})
	}
}
