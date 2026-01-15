package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadPluginFile(t *testing.T) {
	// Create a temp file
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "test.plug.js")

	// Test empty file
	if err := os.WriteFile(testFile, []byte(""), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := readPluginFile(testFile)
	if err == nil {
		t.Error("readPluginFile() expected error for empty file")
	}

	// Test valid file
	if err := os.WriteFile(testFile, []byte("console.log('test');"), 0644); err != nil {
		t.Fatal(err)
	}
	content, err := readPluginFile(testFile)
	if err != nil {
		t.Errorf("readPluginFile() error = %v", err)
	}
	if string(content) != "console.log('test');" {
		t.Errorf("readPluginFile() = %q, want %q", string(content), "console.log('test');")
	}

	// Test non-existent file
	_, err = readPluginFile(filepath.Join(tmpDir, "nonexistent.js"))
	if err == nil {
		t.Error("readPluginFile() expected error for non-existent file")
	}
}

func TestWritePluginFile(t *testing.T) {
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "output.plug.js")

	content := []byte("// signed content\nconsole.log('test');")
	if err := writePluginFile(testFile, content); err != nil {
		t.Errorf("writePluginFile() error = %v", err)
	}

	// Verify content was written
	readBack, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(readBack) != string(content) {
		t.Errorf("writePluginFile() wrote %q, want %q", string(readBack), string(content))
	}
}
