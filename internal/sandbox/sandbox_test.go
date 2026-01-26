package sandbox

import (
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Timeout != 60*time.Second {
		t.Errorf("Timeout = %v, want 60s", cfg.Timeout)
	}
	if !cfg.NetworkAccess {
		t.Error("NetworkAccess should be true by default")
	}
	if cfg.MemoryLimit != "512m" {
		t.Errorf("MemoryLimit = %q, want %q", cfg.MemoryLimit, "512m")
	}
	if cfg.CPULimit != "1.0" {
		t.Errorf("CPULimit = %q, want %q", cfg.CPULimit, "1.0")
	}
}

func TestNew_WithNilConfig(t *testing.T) {
	s := New(nil)
	if s == nil {
		t.Fatal("New(nil) returned nil")
	}
	if s.timeout != DefaultTimeout {
		t.Errorf("timeout = %v, want %v", s.timeout, DefaultTimeout)
	}
}

func TestNew_WithCustomConfig(t *testing.T) {
	cfg := &Config{Timeout: 120 * time.Second}
	s := New(cfg)
	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.timeout != 120*time.Second {
		t.Errorf("timeout = %v, want 120s", s.timeout)
	}
}

func TestParseOutput_FullOutput(t *testing.T) {
	s := New(nil)
	result := &ExecutionResult{
		Stdout: `=== VIGIL ANALYSIS START ===
Package: test@1.0.0
=== INSTALL START ===
npm install output here
=== INSTALL END ===
=== SCRIPTS CHECK ===
node_modules/test/package.json
node_modules/other/package.json
=== FILES CREATED ===
node_modules/test/index.js
node_modules/test/lib/util.js
=== SUSPICIOUS PATTERNS ===
--- SHELL_ACCESS ---
node_modules/test/lib/exec.js
--- DYNAMIC_CODE ---
node_modules/test/eval.js
--- ENV_ACCESS ---
node_modules/test/config.js
--- SENSITIVE_FILES ---
node_modules/test/reader.js
=== END SUSPICIOUS ===
=== VIGIL ANALYSIS END ===`,
	}

	s.parseOutput(result)

	// Commands (scripts section)
	if len(result.Commands) != 2 {
		t.Errorf("Commands count = %d, want 2", len(result.Commands))
	}

	// Files written
	if len(result.FilesWritten) != 2 {
		t.Errorf("FilesWritten count = %d, want 2", len(result.FilesWritten))
	}

	// Suspicious files by category
	if len(result.SuspiciousFiles["shell_access"]) != 1 {
		t.Errorf("shell_access count = %d, want 1", len(result.SuspiciousFiles["shell_access"]))
	}
	if len(result.SuspiciousFiles["dynamic_code"]) != 1 {
		t.Errorf("dynamic_code count = %d, want 1", len(result.SuspiciousFiles["dynamic_code"]))
	}
	if len(result.SuspiciousFiles["env_access"]) != 1 {
		t.Errorf("env_access count = %d, want 1", len(result.SuspiciousFiles["env_access"]))
	}
	if len(result.SuspiciousFiles["sensitive_files"]) != 1 {
		t.Errorf("sensitive_files count = %d, want 1", len(result.SuspiciousFiles["sensitive_files"]))
	}
}

func TestParseOutput_EmptyOutput(t *testing.T) {
	s := New(nil)
	result := &ExecutionResult{Stdout: ""}

	s.parseOutput(result)

	if len(result.Commands) != 0 {
		t.Errorf("Commands count = %d, want 0", len(result.Commands))
	}
	if len(result.FilesWritten) != 0 {
		t.Errorf("FilesWritten count = %d, want 0", len(result.FilesWritten))
	}
	if result.SuspiciousFiles == nil {
		t.Error("SuspiciousFiles should be initialized (not nil)")
	}
}

func TestParseOutput_OnlyScriptsSection(t *testing.T) {
	s := New(nil)
	result := &ExecutionResult{
		Stdout: `=== SCRIPTS CHECK ===
node_modules/pkg-a/package.json
node_modules/pkg-b/package.json
=== FILES CREATED ===
=== SUSPICIOUS PATTERNS ===
=== END SUSPICIOUS ===`,
	}

	s.parseOutput(result)

	if len(result.Commands) != 2 {
		t.Errorf("Commands count = %d, want 2", len(result.Commands))
	}
	if len(result.FilesWritten) != 0 {
		t.Errorf("FilesWritten count = %d, want 0", len(result.FilesWritten))
	}
}

func TestParseOutput_SuspiciousFilesRequireNodeModulesPrefix(t *testing.T) {
	s := New(nil)
	result := &ExecutionResult{
		Stdout: `=== SUSPICIOUS PATTERNS ===
--- SHELL_ACCESS ---
node_modules/test/exec.js
/etc/passwd
some-random-line
--- ENV_ACCESS ---
node_modules/test/env.js
=== END SUSPICIOUS ===`,
	}

	s.parseOutput(result)

	// Only node_modules/ prefixed lines should be captured
	if len(result.SuspiciousFiles["shell_access"]) != 1 {
		t.Errorf("shell_access count = %d, want 1 (only node_modules/ lines)", len(result.SuspiciousFiles["shell_access"]))
	}
	if len(result.SuspiciousFiles["env_access"]) != 1 {
		t.Errorf("env_access count = %d, want 1", len(result.SuspiciousFiles["env_access"]))
	}
}
