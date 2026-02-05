package resolver

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectLockfile(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "vigil-lockfile-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Test no lockfile
	lockType, lockPath := DetectLockfile(tmpDir)
	if lockType != LockfileNone {
		t.Errorf("Expected LockfileNone, got %v", lockType)
	}
	if lockPath != "" {
		t.Errorf("Expected empty path, got %s", lockPath)
	}

	// Test yarn.lock detection
	yarnLock := filepath.Join(tmpDir, "yarn.lock")
	if err := os.WriteFile(yarnLock, []byte("# yarn lockfile v1\n"), 0644); err != nil {
		t.Fatalf("Failed to create yarn.lock: %v", err)
	}
	lockType, lockPath = DetectLockfile(tmpDir)
	if lockType != LockfileYarn {
		t.Errorf("Expected LockfileYarn, got %v", lockType)
	}
	if lockPath != yarnLock {
		t.Errorf("Expected %s, got %s", yarnLock, lockPath)
	}

	// Remove yarn.lock and test pnpm-lock.yaml detection
	os.Remove(yarnLock)
	pnpmLock := filepath.Join(tmpDir, "pnpm-lock.yaml")
	if err := os.WriteFile(pnpmLock, []byte("lockfileVersion: 5\n"), 0644); err != nil {
		t.Fatalf("Failed to create pnpm-lock.yaml: %v", err)
	}
	lockType, lockPath = DetectLockfile(tmpDir)
	if lockType != LockfilePnpm {
		t.Errorf("Expected LockfilePnpm, got %v", lockType)
	}

	// Remove pnpm-lock.yaml and test package-lock.json detection
	os.Remove(pnpmLock)
	npmLock := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(npmLock, []byte(`{"lockfileVersion": 2}`), 0644); err != nil {
		t.Fatalf("Failed to create package-lock.json: %v", err)
	}
	lockType, lockPath = DetectLockfile(tmpDir)
	if lockType != LockfileNPM {
		t.Errorf("Expected LockfileNPM, got %v", lockType)
	}
}

func TestParseYarnV1Lock(t *testing.T) {
	yarnV1Content := `# yarn lockfile v1

lodash@^4.17.0:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz"
  integrity sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==

"@types/node@^14.0.0":
  version "14.18.63"
  resolved "https://registry.yarnpkg.com/@types/node/-/node-14.18.63.tgz"
  integrity sha512-fake-integrity==

express@^4.18.0, express@^4.17.0:
  version "4.18.2"
  resolved "https://registry.yarnpkg.com/express/-/express-4.18.2.tgz"
`

	tmpDir, err := os.MkdirTemp("", "vigil-yarn-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	yarnLock := filepath.Join(tmpDir, "yarn.lock")
	if err := os.WriteFile(yarnLock, []byte(yarnV1Content), 0644); err != nil {
		t.Fatalf("Failed to create yarn.lock: %v", err)
	}

	lockfile, err := ParseLockfile(yarnLock, LockfileYarn)
	if err != nil {
		t.Fatalf("Failed to parse yarn.lock: %v", err)
	}

	if lockfile.Type != LockfileYarn {
		t.Errorf("Expected LockfileYarn, got %v", lockfile.Type)
	}

	// Test lodash
	version, found := lockfile.GetLockedVersion("lodash", "^4.17.0")
	if !found {
		t.Error("lodash@^4.17.0 not found in lockfile")
	}
	if version != "4.17.21" {
		t.Errorf("Expected 4.17.21, got %s", version)
	}

	// Test scoped package
	version, found = lockfile.GetLockedVersion("@types/node", "^14.0.0")
	if !found {
		t.Error("@types/node@^14.0.0 not found in lockfile")
	}
	if version != "14.18.63" {
		t.Errorf("Expected 14.18.63, got %s", version)
	}

	// Test express (multiple constraints)
	version, found = lockfile.GetLockedVersion("express", "^4.18.0")
	if !found {
		t.Error("express@^4.18.0 not found in lockfile")
	}
	if version != "4.18.2" {
		t.Errorf("Expected 4.18.2, got %s", version)
	}
}

func TestParsePnpmLock(t *testing.T) {
	pnpmContent := `lockfileVersion: '6.0'

packages:

  /lodash@4.17.21:
    resolution: {integrity: sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==}
    dev: false

  /@types/node@14.18.63:
    resolution: {integrity: sha512-fake==}
    dev: true

  /express@4.18.2:
    resolution: {integrity: sha512-exp==}
    dev: false
`

	tmpDir, err := os.MkdirTemp("", "vigil-pnpm-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	pnpmLock := filepath.Join(tmpDir, "pnpm-lock.yaml")
	if err := os.WriteFile(pnpmLock, []byte(pnpmContent), 0644); err != nil {
		t.Fatalf("Failed to create pnpm-lock.yaml: %v", err)
	}

	lockfile, err := ParseLockfile(pnpmLock, LockfilePnpm)
	if err != nil {
		t.Fatalf("Failed to parse pnpm-lock.yaml: %v", err)
	}

	if lockfile.Type != LockfilePnpm {
		t.Errorf("Expected LockfilePnpm, got %v", lockfile.Type)
	}

	// Test lodash
	version, found := lockfile.GetLockedVersion("lodash", "^4.17.0")
	if !found {
		t.Error("lodash not found in lockfile")
	}
	if version != "4.17.21" {
		t.Errorf("Expected 4.17.21, got %s", version)
	}

	// Test scoped package
	version, found = lockfile.GetLockedVersion("@types/node", "^14.0.0")
	if !found {
		t.Error("@types/node not found in lockfile")
	}
	if version != "14.18.63" {
		t.Errorf("Expected 14.18.63, got %s", version)
	}
}

func TestParseNPMLock(t *testing.T) {
	npmContent := `{
  "name": "test-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "test-project",
      "version": "1.0.0"
    },
    "node_modules/lodash": {
      "version": "4.17.21",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
      "integrity": "sha512-v2kDE=="
    },
    "node_modules/@types/node": {
      "version": "14.18.63",
      "resolved": "https://registry.npmjs.org/@types/node/-/node-14.18.63.tgz",
      "integrity": "sha512-fake=="
    }
  }
}`

	tmpDir, err := os.MkdirTemp("", "vigil-npm-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	npmLock := filepath.Join(tmpDir, "package-lock.json")
	if err := os.WriteFile(npmLock, []byte(npmContent), 0644); err != nil {
		t.Fatalf("Failed to create package-lock.json: %v", err)
	}

	lockfile, err := ParseLockfile(npmLock, LockfileNPM)
	if err != nil {
		t.Fatalf("Failed to parse package-lock.json: %v", err)
	}

	if lockfile.Type != LockfileNPM {
		t.Errorf("Expected LockfileNPM, got %v", lockfile.Type)
	}

	// Test lodash
	version, found := lockfile.GetLockedVersion("lodash", "^4.17.0")
	if !found {
		t.Error("lodash not found in lockfile")
	}
	if version != "4.17.21" {
		t.Errorf("Expected 4.17.21, got %s", version)
	}

	// Test scoped package
	version, found = lockfile.GetLockedVersion("@types/node", "^14.0.0")
	if !found {
		t.Error("@types/node not found in lockfile")
	}
	if version != "14.18.63" {
		t.Errorf("Expected 14.18.63, got %s", version)
	}
}

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"lodash@^4.17.0", "lodash"},
		{"@types/node@^14.0.0", "@types/node"},
		{"npm:lodash@^4.17.0", "lodash"},
		{"@babel/core@npm:^7.0.0", "@babel/core"},
		{"express", "express"},
		{"@scope/pkg", "@scope/pkg"},
	}

	for _, tt := range tests {
		result := extractPackageName(tt.input)
		if result != tt.expected {
			t.Errorf("extractPackageName(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestParsePnpmPackagePath(t *testing.T) {
	tests := []struct {
		path        string
		wantName    string
		wantVersion string
	}{
		{"/lodash@4.17.21", "lodash", "4.17.21"},
		{"/@types/node@14.18.63", "@types/node", "14.18.63"},
		{"/@babel/core@7.23.0", "@babel/core", "7.23.0"},
		{"/react@18.2.0(typescript@5.0.0)", "react", "18.2.0"},
	}

	for _, tt := range tests {
		name, version := parsePnpmPackagePath(tt.path)
		if name != tt.wantName {
			t.Errorf("parsePnpmPackagePath(%q) name = %q, want %q", tt.path, name, tt.wantName)
		}
		if version != tt.wantVersion {
			t.Errorf("parsePnpmPackagePath(%q) version = %q, want %q", tt.path, version, tt.wantVersion)
		}
	}
}

func TestLockfileTypeName(t *testing.T) {
	tests := []struct {
		lockType LockfileType
		expected string
	}{
		{LockfileYarn, "yarn.lock"},
		{LockfilePnpm, "pnpm-lock.yaml"},
		{LockfileNPM, "package-lock.json"},
		{LockfileNone, "none"},
	}

	for _, tt := range tests {
		result := LockfileTypeName(tt.lockType)
		if result != tt.expected {
			t.Errorf("LockfileTypeName(%v) = %q, want %q", tt.lockType, result, tt.expected)
		}
	}
}
