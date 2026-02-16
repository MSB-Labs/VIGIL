package sandbox

import (
	"testing"
	"time"
)

func TestParseGoOutput(t *testing.T) {
	// Test output from Go analysis
	output := `=== VIGIL GO ANALYSIS START ===
Module: github.com/example/project@v1.0.0
Timestamp: 2024-01-01T12:00:00Z

=== MODULE FETCH START ===
go: downloading github.com/example/project v1.0.0

=== MODULE FETCH END ===

=== MODULE FILES CHECK ===
-rw-r--r--    1 root     root            31 Jan  1 12:00 go.mod
-rw-r--r--    1 root     root           123 Jan  1 12:00 go.sum

=== FILES CREATED ===
./main.go
./utils.go
./vendor/github.com/other/package/other.go

=== SUSPICIOUS PATTERNS ===

--- CGO_USAGE ---
./main.go:import "C"
./main.go:C.CString("test")

--- NATIVE_COMPILATION ---
./lib.a
./lib.so

--- MODULE_PROXY_USAGE ---
go.mod:replace github.com/example/project => github.com/custom/project v1.0.0-custom

--- BUILD_TIME_EXECUTION ---
./main.go:go:generate echo "build time"
./main.go:os/exec

--- UNSAFE_PACKAGE ---
./utils.go:import "unsafe"
./utils.go:unsafe.Pointer

--- REFLECTION_HEAVY ---
./utils.go:reflect.ValueOf

--- ASSEMBLY_CODE ---
./asm.s

--- EXTERNAL_LINKER ---
go.mod:-linkmode external

--- VENDOR_DIRECTORY ---
./vendor/

--- FILE_EMBEDDING ---
./main.go://go:embed config.json

--- PLUGIN_LOADING ---
./main.go:plugin.Open

--- SYSTEM_CALL_HEAVY ---
./main.go:syscall.Exit

--- NETWORK_ACTIVITY ---
./main.go:http.Get

--- FILE_SYSTEM_ACCESS ---
./main.go:os.Open("/etc/passwd")

--- ENVIRONMENT_ACCESS ---
./main.go:os.Getenv("GOPATH")

=== END SUSPICIOUS ===

=== VIGIL GO ANALYSIS END ===`

	result := &ExecutionResult{
		Stdout: output,
	}

	s := &Sandbox{}
	s.parseGoOutput(result)

	// Check that suspicious files were categorized correctly
	if len(result.SuspiciousFiles) == 0 {
		t.Error("Expected suspicious files to be parsed")
	}

	// Check specific categories
	if _, ok := result.SuspiciousFiles["cgo_usage"]; !ok {
		t.Error("Expected CGO usage category")
	}
	if _, ok := result.SuspiciousFiles["native_compilation"]; !ok {
		t.Error("Expected native compilation category")
	}
	if _, ok := result.SuspiciousFiles["module_proxy_usage"]; !ok {
		t.Error("Expected module proxy usage category")
	}
	if _, ok := result.SuspiciousFiles["build_time_execution"]; !ok {
		t.Error("Expected build time execution category")
	}
	if _, ok := result.SuspiciousFiles["unsafe_package"]; !ok {
		t.Error("Expected unsafe package category")
	}
	if _, ok := result.SuspiciousFiles["reflection_heavy"]; !ok {
		t.Error("Expected reflection heavy category")
	}
	if _, ok := result.SuspiciousFiles["assembly_code"]; !ok {
		t.Error("Expected assembly code category")
	}
	if _, ok := result.SuspiciousFiles["vendor_directory"]; !ok {
		t.Error("Expected vendor directory category")
	}
	if _, ok := result.SuspiciousFiles["file_embedding"]; !ok {
		t.Error("Expected file embedding category")
	}
	if _, ok := result.SuspiciousFiles["plugin_loading"]; !ok {
		t.Error("Expected plugin loading category")
	}
	if _, ok := result.SuspiciousFiles["system_call_heavy"]; !ok {
		t.Error("Expected system call heavy category")
	}
	if _, ok := result.SuspiciousFiles["network_activity"]; !ok {
		t.Error("Expected network activity category")
	}
	if _, ok := result.SuspiciousFiles["file_system_access"]; !ok {
		t.Error("Expected file system access category")
	}
	if _, ok := result.SuspiciousFiles["environment_access"]; !ok {
		t.Error("Expected environment access category")
	}

	// Check that module files were captured
	if len(result.Commands) == 0 {
		t.Error("Expected module files to be captured")
	}
	if !contains(result.Commands, "go.mod") {
		t.Error("Expected go.mod in commands")
	}
	if !contains(result.Commands, "go.sum") {
		t.Error("Expected go.sum in commands")
	}

	// Check that files were captured
	if len(result.FilesWritten) == 0 {
		t.Error("Expected files to be captured")
	}
	if !contains(result.FilesWritten, "./main.go") {
		t.Error("Expected main.go in files written")
	}
}

func TestParsePythonOutput(t *testing.T) {
	// Test output from Python analysis
	output := `=== VIGIL PYTHON ANALYSIS START ===
Package: requests@2.31.0
Timestamp: 2024-01-01T12:00:00Z

=== INSTALL START ===
Collecting requests==2.31.0
  Downloading requests-2.31.0-py3-none-any.whl (62 kB)

=== INSTALL END ===

=== SETUP CHECK ===
./setup.py
./pyproject.toml

=== FILES CREATED ===
./requests/__init__.py
./requests/api.py
./requests/models.py

=== SUSPICIOUS PATTERNS ===

--- SHELL_ACCESS ---
./requests/utils.py:subprocess.run

--- DYNAMIC_CODE ---
./requests/models.py:eval("test")

--- ENV_ACCESS ---
./requests/utils.py:os.environ["TEST"]

--- SENSITIVE_FILES ---
./requests/models.py:open("/etc/passwd")

--- NETWORK_ACCESS ---
./requests/api.py:requests.get

--- VENV_MANIPULATION ---
./setup.py:sys.prefix

--- PATH_MANIPULATION ---
./setup.py:sys.path.append

--- DYNAMIC_IMPORT ---
./requests/utils.py:importlib.import_module

--- IMPORT_HIJACKING ---
./requests/models.py:sys.modules["test"]

--- PIP_INSTALLATION ---
./setup.py:pip install

--- CONFIG_MODIFICATION ---
./setup.py:sitecustomize.py

--- CRYPTOGRAPHY_USAGE ---
./requests/utils.py:hashlib.sha256

--- DEBUGGER_DETECTION ---
./requests/models.py:sys.gettrace

--- WINDOWS_REGISTRY ---
./requests/utils.py:winreg.OpenKey

--- PROCESS_INJECTION ---
./requests/models.py:ctypes.windll.kernel32

--- INPUT_CONTROL ---
./requests/utils.py:keyboard.press

--- SYSTEM_INFO ---
./requests/models.py:platform.machine

--- FILE_ENCRYPTION ---
./requests/utils.py:encrypt("test")

--- MEMORY_OPERATIONS ---
./requests/models.py:ctypes.memmove

=== END SUSPICIOUS ===

=== VIGIL PYTHON ANALYSIS END ===`

	result := &ExecutionResult{
		Stdout: output,
	}

	s := &Sandbox{}
	s.parsePythonOutput(result)

	// Check that suspicious files were categorized correctly
	if len(result.SuspiciousFiles) == 0 {
		t.Error("Expected suspicious files to be parsed")
	}

	// Check specific categories
	if _, ok := result.SuspiciousFiles["shell_access"]; !ok {
		t.Error("Expected shell access category")
	}
	if _, ok := result.SuspiciousFiles["dynamic_code"]; !ok {
		t.Error("Expected dynamic code category")
	}
	if _, ok := result.SuspiciousFiles["env_access"]; !ok {
		t.Error("Expected environment access category")
	}
	if _, ok := result.SuspiciousFiles["sensitive_files"]; !ok {
		t.Error("Expected sensitive files category")
	}
	if _, ok := result.SuspiciousFiles["network_access"]; !ok {
		t.Error("Expected network access category")
	}
	if _, ok := result.SuspiciousFiles["venv_manipulation"]; !ok {
		t.Error("Expected venv manipulation category")
	}
	if _, ok := result.SuspiciousFiles["path_manipulation"]; !ok {
		t.Error("Expected path manipulation category")
	}
	if _, ok := result.SuspiciousFiles["dynamic_import"]; !ok {
		t.Error("Expected dynamic import category")
	}
	if _, ok := result.SuspiciousFiles["import_hijacking"]; !ok {
		t.Error("Expected import hijacking category")
	}
	if _, ok := result.SuspiciousFiles["pip_installation"]; !ok {
		t.Error("Expected pip installation category")
	}
	if _, ok := result.SuspiciousFiles["config_modification"]; !ok {
		t.Error("Expected config modification category")
	}
	if _, ok := result.SuspiciousFiles["cryptography_usage"]; !ok {
		t.Error("Expected cryptography usage category")
	}
	if _, ok := result.SuspiciousFiles["debugger_detection"]; !ok {
		t.Error("Expected debugger detection category")
	}
	if _, ok := result.SuspiciousFiles["windows_registry"]; !ok {
		t.Error("Expected windows registry category")
	}
	if _, ok := result.SuspiciousFiles["process_injection"]; !ok {
		t.Error("Expected process injection category")
	}
	if _, ok := result.SuspiciousFiles["input_control"]; !ok {
		t.Error("Expected input control category")
	}
	if _, ok := result.SuspiciousFiles["system_info"]; !ok {
		t.Error("Expected system info category")
	}
	if _, ok := result.SuspiciousFiles["file_encryption"]; !ok {
		t.Error("Expected file encryption category")
	}
	if _, ok := result.SuspiciousFiles["memory_operations"]; !ok {
		t.Error("Expected memory operations category")
	}

	// Check that setup files were captured
	if len(result.Commands) == 0 {
		t.Error("Expected setup files to be captured")
	}
	if !contains(result.Commands, "./setup.py") {
		t.Error("Expected setup.py in commands")
	}
	if !contains(result.Commands, "./pyproject.toml") {
		t.Error("Expected pyproject.toml in commands")
	}

	// Check that files were captured
	if len(result.FilesWritten) == 0 {
		t.Error("Expected files to be captured")
	}
	if !contains(result.FilesWritten, "./requests/__init__.py") {
		t.Error("Expected requests/__init__.py in files written")
	}
}

func TestParseOutput(t *testing.T) {
	// Test output from npm analysis
	output := `=== VIGIL ANALYSIS START ===
Package: lodash@4.17.21
Timestamp: 2024-01-01T12:00:00Z

=== INSTALL START ===
npm notice created a lockfile as package-lock.json. You should commit this file.
npm WARN test@1.0.0 No description
npm WARN test@1.0.0 No repository field.

=== INSTALL END ===

=== SCRIPTS CHECK ===
node_modules/lodash/package.json

=== FILES CREATED ===
node_modules/lodash/package.json
node_modules/lodash/index.js
node_modules/lodash/lodash.js

=== SUSPICIOUS PATTERNS ===

--- SHELL_ACCESS ---
node_modules/lodash/index.js:require('child_process')

--- DYNAMIC_CODE ---
node_modules/lodash/index.js:eval("test")

--- ENV_ACCESS ---
node_modules/lodash/index.js:process.env.TEST

--- SENSITIVE_FILES ---
node_modules/lodash/index.js:fs.readFileSync("/etc/passwd")

=== END SUSPICIOUS ===

=== VIGIL ANALYSIS END ===`

	result := &ExecutionResult{
		Stdout: output,
	}

	s := &Sandbox{}
	s.parseOutput(result)

	// Check that suspicious files were categorized correctly
	if len(result.SuspiciousFiles) == 0 {
		t.Error("Expected suspicious files to be parsed")
	}

	// Check specific categories
	if _, ok := result.SuspiciousFiles["shell_access"]; !ok {
		t.Error("Expected shell access category")
	}
	if _, ok := result.SuspiciousFiles["dynamic_code"]; !ok {
		t.Error("Expected dynamic code category")
	}
	if _, ok := result.SuspiciousFiles["env_access"]; !ok {
		t.Error("Expected environment access category")
	}
	if _, ok := result.SuspiciousFiles["sensitive_files"]; !ok {
		t.Error("Expected sensitive files category")
	}

	// Check that scripts were captured
	if len(result.Commands) == 0 {
		t.Error("Expected scripts to be captured")
	}
	if !contains(result.Commands, "node_modules/lodash/package.json") {
		t.Error("Expected lodash package.json in commands")
	}

	// Check that files were captured
	if len(result.FilesWritten) == 0 {
		t.Error("Expected files to be captured")
	}
	if !contains(result.FilesWritten, "node_modules/lodash/package.json") {
		t.Error("Expected lodash package.json in files written")
	}
}

// Helper function to check if a slice contains a string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	
	if cfg.Timeout != DefaultTimeout {
		t.Errorf("Expected timeout %v, got %v", DefaultTimeout, cfg.Timeout)
	}
	
	if !cfg.NetworkAccess {
		t.Error("Expected network access to be true by default")
	}
	
	if cfg.MemoryLimit != "512m" {
		t.Errorf("Expected memory limit '512m', got '%s'", cfg.MemoryLimit)
	}
	
	if cfg.CPULimit != "1.0" {
		t.Errorf("Expected CPU limit '1.0', got '%s'", cfg.CPULimit)
	}
}

func TestNewSandbox(t *testing.T) {
	cfg := &Config{
		Timeout:       30 * time.Second,
		NetworkAccess: false,
		MemoryLimit:   "256m",
		CPULimit:      "0.5",
	}
	
	s := New(cfg)
	
	if s.timeout != 30*time.Second {
		t.Errorf("Expected timeout 30s, got %v", s.timeout)
	}
	
	// Test with nil config
	s2 := New(nil)
	if s2.timeout != DefaultTimeout {
		t.Errorf("Expected default timeout, got %v", s2.timeout)
	}
}