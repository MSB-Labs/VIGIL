// Package sandbox manages isolated execution environments
// for running untrusted packages safely.
package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultTimeout for container operations
	DefaultTimeout = 60 * time.Second

	// SandboxImage is the Docker image used for analysis
	SandboxImage = "vigil-sandbox:latest"
	SandboxPythonImage = "vigil-python-sandbox:latest"
	SandboxGoImage = "vigil-go-sandbox:latest"

	// EmbeddedDockerfile is the built-in Dockerfile for the sandbox image
	EmbeddedDockerfile = `FROM node:20-alpine
RUN apk add --no-cache bash grep findutils coreutils
RUN adduser -D -s /bin/bash vigil
WORKDIR /home/vigil
USER vigil
ENV NPM_CONFIG_UPDATE_NOTIFIER=false
ENV NPM_CONFIG_FUND=false
ENV NO_UPDATE_NOTIFIER=1
CMD ["/bin/bash"]
`

	// EmbeddedPythonDockerfile is the built-in Dockerfile for Python sandbox
	EmbeddedPythonDockerfile = `FROM python:3.11-alpine
RUN apk add --no-cache bash grep findutils coreutils curl
RUN adduser -D -s /bin/bash vigil
WORKDIR /home/vigil
USER vigil
ENV PIP_NO_CACHE_DIR=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
CMD ["/bin/bash"]
`

	// EmbeddedGoDockerfile is the built-in Dockerfile for Go sandbox
	EmbeddedGoDockerfile = `FROM golang:1.21-alpine
RUN apk add --no-cache bash grep findutils coreutils curl git
RUN adduser -D -s /bin/bash vigil
WORKDIR /home/vigil
USER vigil
ENV GOPROXY=https://proxy.golang.org,direct
ENV GOSUMDB=sum.golang.org
CMD ["/bin/bash"]
`
)

// Sandbox manages Docker container lifecycle for package analysis
type Sandbox struct {
	timeout time.Duration
}

// Config holds sandbox configuration
type Config struct {
	Timeout       time.Duration
	NetworkAccess bool   // Allow network (for capturing, not blocking)
	MemoryLimit   string // e.g., "512m"
	CPULimit      string // e.g., "1.0"
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Timeout:       DefaultTimeout,
		NetworkAccess: true, // We want to capture network calls, not block them
		MemoryLimit:   "512m",
		CPULimit:      "1.0",
	}
}

// ExecutionResult holds the output from running a package in the sandbox
type ExecutionResult struct {
	ExitCode        int
	Stdout          string
	Stderr          string
	Duration        time.Duration
	NetworkCalls    []string            // Captured DNS/HTTP calls
	FilesWritten    []string            // Files created/modified
	EnvAccessed     []string            // Environment variables read
	Commands        []string            // Shell commands executed
	SuspiciousFiles map[string][]string // category -> file list
	Error           error
}

// New creates a new sandbox instance
func New(cfg *Config) *Sandbox {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Sandbox{
		timeout: cfg.Timeout,
	}
}

// CheckDocker verifies Docker is available and running
func CheckDocker() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker not available: %w", err)
	}
	return nil
}

// BuildImage builds the sandbox Docker image
func BuildImage(dockerfilePath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "build", "-t", SandboxImage, "-f", dockerfilePath, ".")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to build sandbox image: %w\n%s", err, stderr.String())
	}
	return nil
}

// BuildImageFromDefault builds the sandbox image using the embedded Dockerfile
func BuildImageFromDefault() error {
	tmpDir, err := os.MkdirTemp("", "vigil-build-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(EmbeddedDockerfile), 0644); err != nil {
		return fmt.Errorf("failed to write Dockerfile: %w", err)
	}

	return BuildImage(dockerfilePath)
}

// ImageExists checks if the sandbox image exists
func ImageExists() bool {
	cmd := exec.Command("docker", "image", "inspect", SandboxImage)
	return cmd.Run() == nil
}

// PythonImageExists checks if the Python sandbox image exists
func PythonImageExists() bool {
	cmd := exec.Command("docker", "image", "inspect", SandboxPythonImage)
	return cmd.Run() == nil
}

// BuildPythonImage builds the Python sandbox Docker image
func BuildPythonImage(dockerfilePath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "build", "-t", SandboxPythonImage, "-f", dockerfilePath, ".")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to build Python sandbox image: %w\n%s", err, stderr.String())
	}
	return nil
}

// BuildPythonImageFromDefault builds the Python sandbox image using the embedded Dockerfile
func BuildPythonImageFromDefault() error {
	tmpDir, err := os.MkdirTemp("", "vigil-python-build-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(EmbeddedPythonDockerfile), 0644); err != nil {
		return fmt.Errorf("failed to write Python Dockerfile: %w", err)
	}

	return BuildPythonImage(dockerfilePath)
}

// AnalyzePackage runs a package in the sandbox and captures behavior
func (s *Sandbox) AnalyzePackage(packageName, version string) (*ExecutionResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	start := time.Now()
	result := &ExecutionResult{}

	// Create container with the analysis script
	// The script will install the package and capture behavior
	script := fmt.Sprintf(`
set -e
echo "=== VIGIL ANALYSIS START ==="
echo "Package: %s@%s"
echo "Timestamp: $(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)"

# Create temp directory for installation
mkdir -p /tmp/pkg-test
cd /tmp/pkg-test

# Initialize a minimal package.json
echo '{"name":"test","version":"1.0.0"}' > package.json

# Capture network calls using a simple DNS log
echo "=== INSTALL START ==="

# Install the package and capture output
npm install %s@%s 2>&1 | tee /tmp/install.log

echo "=== INSTALL END ==="

# Check for postinstall scripts in node_modules
echo "=== SCRIPTS CHECK ==="
find node_modules -name "package.json" -exec grep -l "postinstall\|preinstall" {} \; 2>/dev/null || true

# List files created
echo "=== FILES CREATED ==="
find node_modules -type f -name "*.js" | head -50

# Detect suspicious patterns by category
echo "=== SUSPICIOUS PATTERNS ==="

echo "--- SHELL_ACCESS ---"
grep -rl 'require.*child_process' node_modules --include="*.js" 2>/dev/null | head -10 || true

echo "--- DYNAMIC_CODE ---"
grep -rl 'eval(' node_modules --include="*.js" 2>/dev/null | head -10 || true

echo "--- ENV_ACCESS ---"
grep -rl 'process\.env' node_modules --include="*.js" 2>/dev/null | head -10 || true

echo "--- SENSITIVE_FILES ---"
grep -rl '/etc/passwd\|/etc/shadow\|\.ssh/\|\.aws/\|\.npmrc' node_modules --include="*.js" 2>/dev/null | head -10 || true

echo "=== END SUSPICIOUS ==="

echo "=== VIGIL ANALYSIS END ==="
`, packageName, version, packageName, version)

	// Run container
	args := []string{
		"run",
		"--rm",
		"--network=bridge", // Allow network for now (to capture calls)
		"--memory=512m",
		"--cpus=1.0",
		"--security-opt=no-new-privileges",
		SandboxImage,
		"/bin/sh", "-c", script,
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result.Duration = time.Since(start)
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = fmt.Errorf("analysis timed out after %v", s.timeout)
		} else {
			result.Error = err
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
	}

	// Parse output for behavioral indicators
	s.parseOutput(result)

	return result, nil
}

// parseOutput extracts behavioral data from the analysis output
func (s *Sandbox) parseOutput(result *ExecutionResult) {
	lines := strings.Split(result.Stdout, "\n")
	result.SuspiciousFiles = make(map[string][]string)

	inSection := ""
	suspiciousCategory := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Track sections
		switch line {
		case "=== SCRIPTS CHECK ===":
			inSection = "scripts"
			continue
		case "=== FILES CREATED ===":
			inSection = "files"
			continue
		case "=== SUSPICIOUS PATTERNS ===":
			inSection = "suspicious"
			continue
		case "=== END SUSPICIOUS ===":
			inSection = ""
			suspiciousCategory = ""
			continue
		case "=== INSTALL START ===", "=== INSTALL END ===", "=== VIGIL ANALYSIS START ===", "=== VIGIL ANALYSIS END ===":
			inSection = ""
			continue
		}

		// Track suspicious subcategories
		if inSection == "suspicious" {
			switch line {
			case "--- SHELL_ACCESS ---":
				suspiciousCategory = "shell_access"
				continue
			case "--- DYNAMIC_CODE ---":
				suspiciousCategory = "dynamic_code"
				continue
			case "--- ENV_ACCESS ---":
				suspiciousCategory = "env_access"
				continue
			case "--- SENSITIVE_FILES ---":
				suspiciousCategory = "sensitive_files"
				continue
			}
		}

		if line == "" {
			continue
		}

		switch inSection {
		case "scripts":
			if strings.Contains(line, "package.json") {
				result.Commands = append(result.Commands, line)
			}
		case "files":
			result.FilesWritten = append(result.FilesWritten, line)
		case "suspicious":
			if suspiciousCategory != "" && strings.HasPrefix(line, "node_modules/") {
				result.SuspiciousFiles[suspiciousCategory] = append(
					result.SuspiciousFiles[suspiciousCategory], line)
			}
		}
	}
}

// QuickCheck runs a lightweight check without full analysis
func (s *Sandbox) QuickCheck(packageName, version string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Quick check: just fetch package info and check for install scripts
	script := fmt.Sprintf(`
npm view %s@%s scripts --json 2>/dev/null || echo "{}"
`, packageName, version)

	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network=bridge",
		SandboxImage, "/bin/sh", "-c", script)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return false, "", err
	}

	output := stdout.String()
	hasRisk := strings.Contains(output, "preinstall") ||
		strings.Contains(output, "postinstall") ||
		strings.Contains(output, "install")

	return hasRisk, output, nil
}

// AnalyzePythonPackage runs a Python package in the sandbox and captures behavior
func (s *Sandbox) AnalyzePythonPackage(packageName, version string) (*ExecutionResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	start := time.Now()
	result := &ExecutionResult{}

	// Create container with the analysis script
	script := fmt.Sprintf(`
set -e
echo "=== VIGIL PYTHON ANALYSIS START ==="
echo "Package: %s@%s"
echo "Timestamp: $(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)"

# Create temp directory for installation
mkdir -p /tmp/python-test
cd /tmp/python-test

# Capture network calls using a simple DNS log
echo "=== INSTALL START ==="

# Install the package and capture output
pip install %s==%s 2>&1 | tee /tmp/install.log

echo "=== INSTALL END ==="

# Check for setup.py and pyproject.toml
echo "=== SETUP CHECK ==="
find . -name "setup.py" -o -name "pyproject.toml" 2>/dev/null || true

# List files created
echo "=== FILES CREATED ==="
find . -type f -name "*.py" | head -50

# Detect suspicious patterns by category
echo "=== SUSPICIOUS PATTERNS ==="

echo "--- SHELL_ACCESS ---"
grep -r 'subprocess\|os\.system\|os\.popen' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- DYNAMIC_CODE ---"
grep -r 'eval(\|exec(\|compile(' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- ENV_ACCESS ---"
grep -r 'os\.environ\|getenv' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- SENSITIVE_FILES ---"
grep -r '/etc/passwd\|/etc/shadow\|\.ssh/\|\.aws/\|\.pythonrc' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- NETWORK_ACCESS ---"
grep -r 'requests\|urllib\|socket\|http' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- VENV_MANIPULATION ---"
grep -r 'venv\|virtualenv\|site-packages\|sys.prefix\|sys.exec_prefix\|VIRTUAL_ENV' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- PATH_MANIPULATION ---"
grep -r 'sys.path\|PYTHONPATH\|site.addsitedir\|site.addpackage' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- DYNAMIC_IMPORT ---"
grep -r '__import__\|importlib\|imp.load_source\|imp.load_module\|pkgutil.iter_modules\|pkgutil.find_loader' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- IMPORT_HIJACKING ---"
grep -r 'sys.modules' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- PIP_INSTALLATION ---"
grep -r 'pip install\|python -m pip\|subprocess.*pip\|os.system.*pip' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- CONFIG_MODIFICATION ---"
grep -r 'pythonrc\|sitecustomize\|usercustomize\|pyvenv.cfg\|\.pth\|setup.cfg' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- CRYPTOGRAPHY_USAGE ---"
grep -r 'cryptography\|Crypto\|pycryptodome\|pycrypto\|hashlib\|secrets\|ssl\|OpenSSL' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- DEBUGGER_DETECTION ---"
grep -r 'sys.gettrace\|sys._getframe\|traceback\|pdb\|pydevd\|pycharm\|vscode\|docker\|vbox\|vmware\|virtualbox' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- WINDOWS_REGISTRY ---"
grep -r 'winreg\|win32api\|win32con\|win32service\|win32process\|HKEY_\|RegOpenKey\|RegSetValue' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- PROCESS_INJECTION ---"
grep -r 'ctypes.windll.kernel32\|ctypes.windll.kernelbase\|CreateProcess\|WriteProcessMemory\|ReadProcessMemory\|VirtualAllocEx\|VirtualFreeEx\|OpenProcess\|TerminateProcess' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- INPUT_CONTROL ---"
grep -r 'pynput\|pyautogui\|keyboard\|mouse\|win32api.keybd_event\|win32api.mouse_event\|SendInput' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- SYSTEM_INFO ---"
grep -r 'platform\|psutil\|socket.gethostname\|socket.gethostbyname\|uuid.getnode\|os.uname\|os.cpu_count\|shutil.disk_usage\|platform.machine\|platform.processor' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- FILE_ENCRYPTION ---"
grep -r 'encrypt\|decrypt\|AES\|RSA\|DES\|Blowfish\|ChaCha20\|Fernet\|Cipher\|encrypt_file\|decrypt_file' . --include="*.py" 2>/dev/null | head -10 || true

echo "--- MEMORY_OPERATIONS ---"
grep -r 'ctypes\|ctypes.c_\|ctypes.POINTER\|ctypes.byref\|ctypes.addressof\|ctypes.string_at\|ctypes.memmove\|ctypes.memset' . --include="*.py" 2>/dev/null | head -10 || true

echo "=== END SUSPICIOUS ==="

echo "=== VIGIL PYTHON ANALYSIS END ==="
`, packageName, version, packageName, version)

	// Run container
	args := []string{
		"run",
		"--rm",
		"--network=bridge", // Allow network for now (to capture calls)
		"--memory=512m",
		"--cpus=1.0",
		"--security-opt=no-new-privileges",
		SandboxPythonImage,
		"/bin/sh", "-c", script,
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result.Duration = time.Since(start)
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = fmt.Errorf("Python analysis timed out after %v", s.timeout)
		} else {
			result.Error = err
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
	}

	// Parse output for behavioral indicators
	s.parsePythonOutput(result)

	return result, nil
}

// parsePythonOutput extracts behavioral data from the Python analysis output
func (s *Sandbox) parsePythonOutput(result *ExecutionResult) {
	lines := strings.Split(result.Stdout, "\n")
	result.SuspiciousFiles = make(map[string][]string)

	inSection := ""
	suspiciousCategory := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Track sections
		switch line {
		case "=== SETUP CHECK ===":
			inSection = "setup"
			continue
		case "=== FILES CREATED ===":
			inSection = "files"
			continue
		case "=== SUSPICIOUS PATTERNS ===":
			inSection = "suspicious"
			continue
		case "=== END SUSPICIOUS ===":
			inSection = ""
			suspiciousCategory = ""
			continue
		case "=== INSTALL START ===", "=== INSTALL END ===", "=== VIGIL PYTHON ANALYSIS START ===", "=== VIGIL PYTHON ANALYSIS END ===":
			inSection = ""
			continue
		}

		// Track suspicious subcategories
		if inSection == "suspicious" {
			switch line {
			case "--- SHELL_ACCESS ---":
				suspiciousCategory = "shell_access"
				continue
			case "--- DYNAMIC_CODE ---":
				suspiciousCategory = "dynamic_code"
				continue
			case "--- ENV_ACCESS ---":
				suspiciousCategory = "env_access"
				continue
			case "--- SENSITIVE_FILES ---":
				suspiciousCategory = "sensitive_files"
				continue
			case "--- NETWORK_ACCESS ---":
				suspiciousCategory = "network_access"
				continue
			case "--- VENV_MANIPULATION ---":
				suspiciousCategory = "venv_manipulation"
				continue
			case "--- PATH_MANIPULATION ---":
				suspiciousCategory = "path_manipulation"
				continue
			case "--- DYNAMIC_IMPORT ---":
				suspiciousCategory = "dynamic_import"
				continue
			case "--- IMPORT_HIJACKING ---":
				suspiciousCategory = "import_hijacking"
				continue
			case "--- PIP_INSTALLATION ---":
				suspiciousCategory = "pip_installation"
				continue
			case "--- CONFIG_MODIFICATION ---":
				suspiciousCategory = "config_modification"
				continue
			case "--- CRYPTOGRAPHY_USAGE ---":
				suspiciousCategory = "cryptography_usage"
				continue
			case "--- DEBUGGER_DETECTION ---":
				suspiciousCategory = "debugger_detection"
				continue
			case "--- WINDOWS_REGISTRY ---":
				suspiciousCategory = "windows_registry"
				continue
			case "--- PROCESS_INJECTION ---":
				suspiciousCategory = "process_injection"
				continue
			case "--- INPUT_CONTROL ---":
				suspiciousCategory = "input_control"
				continue
			case "--- SYSTEM_INFO ---":
				suspiciousCategory = "system_info"
				continue
			case "--- FILE_ENCRYPTION ---":
				suspiciousCategory = "file_encryption"
				continue
			case "--- MEMORY_OPERATIONS ---":
				suspiciousCategory = "memory_operations"
				continue
			}
		}

		if line == "" {
			continue
		}

		switch inSection {
		case "setup":
			if strings.Contains(line, "setup.py") || strings.Contains(line, "pyproject.toml") {
				result.Commands = append(result.Commands, line)
			}
		case "files":
			result.FilesWritten = append(result.FilesWritten, line)
		case "suspicious":
			if suspiciousCategory != "" && strings.HasPrefix(line, ".") {
				result.SuspiciousFiles[suspiciousCategory] = append(
					result.SuspiciousFiles[suspiciousCategory], line)
			}
		}
	}
}

// QuickCheckPython runs a lightweight check for Python packages
func (s *Sandbox) QuickCheckPython(packageName, version string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Quick check: just fetch package info
	script := fmt.Sprintf(`
pip show %s 2>/dev/null || echo "Package not found"
`, packageName)

	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network=bridge",
		SandboxPythonImage, "/bin/sh", "-c", script)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return false, "", err
	}

	output := stdout.String()
	hasRisk := strings.Contains(output, "setup.py") ||
		strings.Contains(output, "pyproject.toml")

	return hasRisk, output, nil
}

// GoImageExists checks if the Go sandbox image exists
func GoImageExists() bool {
	cmd := exec.Command("docker", "image", "inspect", SandboxGoImage)
	return cmd.Run() == nil
}

// BuildGoImage builds the Go sandbox Docker image
func BuildGoImage(dockerfilePath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "docker", "build", "-t", SandboxGoImage, "-f", dockerfilePath, ".")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to build Go sandbox image: %w\n%s", err, stderr.String())
	}
	return nil
}

// BuildGoImageFromDefault builds the Go sandbox image using the embedded Dockerfile
func BuildGoImageFromDefault() error {
	tmpDir, err := os.MkdirTemp("", "vigil-go-build-*")
	if err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	if err := os.WriteFile(dockerfilePath, []byte(EmbeddedGoDockerfile), 0644); err != nil {
		return fmt.Errorf("failed to write Go Dockerfile: %w", err)
	}

	return BuildGoImage(dockerfilePath)
}

// AnalyzeGoPackage runs a Go package in the sandbox and captures behavior
func (s *Sandbox) AnalyzeGoPackage(modulePath, version string) (*ExecutionResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	start := time.Now()
	result := &ExecutionResult{}

	// Create container with the analysis script
	script := fmt.Sprintf(`
set -e
echo "=== VIGIL GO ANALYSIS START ==="
echo "Module: %s@%s"
echo "Timestamp: $(date -u +%%Y-%%m-%%dT%%H:%%M:%%SZ)"

# Create temp directory for analysis
mkdir -p /tmp/go-test
cd /tmp/go-test

# Initialize a minimal go.mod
echo 'module test' > go.mod
echo 'go 1.21' >> go.mod
echo '' >> go.mod
echo 'require %s %s' >> go.mod

# Capture network calls using a simple DNS log
echo "=== MODULE FETCH START ==="

# Fetch the module and capture output
go mod download %s@%s 2>&1 | tee /tmp/download.log

echo "=== MODULE FETCH END ==="

# Check for go.mod and go.sum
echo "=== MODULE FILES CHECK ==="
ls -la go.mod go.sum 2>/dev/null || true

# List files created
echo "=== FILES CREATED ==="
find . -type f -name "*.go" | head -50

# Detect suspicious patterns by category
echo "=== SUSPICIOUS PATTERNS ==="

echo "--- CGO_USAGE ---"
grep -r 'CGO_ENABLED\|#cgo\|_cgo_\|C\.CString\|C\.GoString\|C\.free\|C\.malloc\|C\.sizeof\|C\.ptr' . --include="*.go" 2>/dev/null | head -10 || true

echo "--- NATIVE_COMPILATION ---"
find . -name "*.a" -o -name "*.so" -o -name "*.dylib" -o -name "*.dll" -o -name "*.exe" 2>/dev/null | head -10 || true

echo "--- MODULE_PROXY_USAGE ---"
grep -r 'GOPROXY\|GONOPROXY\|GOSUMDB\|GONOSUMDB\|replace\|=>' . --include="*.go" --include="go.mod" 2>/dev/null | head -10 || true

echo "--- BUILD_TIME_EXECUTION ---"
grep -r 'go:build\|//go:build\|go:generate\|//go:generate\|os/exec\|exec\.Command\|os\.StartProcess\|syscall\|runtime' . --include="*.go" 2>/dev/null | head -10 || true

echo "--- UNSAFE_PACKAGE ---"
grep -r 'import "unsafe"\|unsafe\.Pointer\|unsafe\.Sizeof\|unsafe\.Offsetof\|unsafe\.Alignof' . --include="*.go" 2>/dev/null | head -10 || true

echo "--- REFLECTION_HEAVY ---"
grep -r 'reflect\.\|reflect\.Value\|reflect\.Type\|reflect\.StructOf\|reflect\.New\|reflect\.Call' . --include="*.go" 2>/dev/null | head -10 || true

echo "--- ASSEMBLY_CODE ---"
find . -name "*.s" -o -name "*.asm" 2>/dev/null | head -10 || true

echo "--- EXTERNAL_LINKER ---"
grep -r '-linkmode external\|-extld\|-extldflags\|CGO_LDFLAGS\|LDFLAGS' . --include="*.go" --include="go.mod" 2>/dev/null | head -10 || true

echo "--- VENDOR_DIRECTORY ---"
find . -name "vendor" -type d 2>/dev/null | head -10 || true

echo "--- FILE_EMBEDDING ---"
grep -r '//go:embed\|embed\.FS\|embed\.ReadFile\|embed\.ReadDir' . --include="*.go" 2>/dev/null | head -10 || true

echo "--- PLUGIN_LOADING ---"
grep -r 'plugin\.Open\|plugin\.Lookup' . --include="*.go" 2>/dev/null | head -10 || true

echo "--- SYSTEM_CALL_HEAVY ---"
grep -r 'syscall\.\|os/exec\|os\.StartProcess\|os\.Process\|os\.Kill\|os\.Signal' . --include="*.go" 2>/dev/null | head -10 || true

echo "--- NETWORK_ACTIVITY ---"
grep -r 'net\.\|http\.\|url\.\|dns' . --include="*.go" 2>/dev/null | head -10 || true

echo "--- FILE_SYSTEM_ACCESS ---"
grep -r 'os\.Open\|os\.Create\|os\.Remove\|os\.Rename\|/etc/passwd\|/etc/shadow\|\.ssh/\|\.aws/\|\.gitconfig\|id_rsa' . --include="*.go" 2>/dev/null | head -10 || true

echo "--- ENVIRONMENT_ACCESS ---"
grep -r 'os\.Getenv\|os\.Setenv\|os\.Environ\|GOPATH\|GOROOT\|GOOS\|GOARCH' . --include="*.go" 2>/dev/null | head -10 || true

echo "=== END SUSPICIOUS ==="

echo "=== VIGIL GO ANALYSIS END ==="
`, modulePath, version, modulePath, version, modulePath, version)

	// Run container
	args := []string{
		"run",
		"--rm",
		"--network=bridge", // Allow network for now (to capture calls)
		"--memory=512m",
		"--cpus=1.0",
		"--security-opt=no-new-privileges",
		SandboxGoImage,
		"/bin/sh", "-c", script,
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	result.Duration = time.Since(start)
	result.Stdout = stdout.String()
	result.Stderr = stderr.String()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			result.Error = fmt.Errorf("Go analysis timed out after %v", s.timeout)
		} else {
			result.Error = err
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
		}
	}

	// Parse output for behavioral indicators
	s.parseGoOutput(result)

	return result, nil
}

// parseGoOutput extracts behavioral data from the Go analysis output
func (s *Sandbox) parseGoOutput(result *ExecutionResult) {
	lines := strings.Split(result.Stdout, "\n")
	result.SuspiciousFiles = make(map[string][]string)

	inSection := ""
	suspiciousCategory := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Track sections
		switch line {
		case "=== MODULE FILES CHECK ===":
			inSection = "module_files"
			continue
		case "=== FILES CREATED ===":
			inSection = "files"
			continue
		case "=== SUSPICIOUS PATTERNS ===":
			inSection = "suspicious"
			continue
		case "=== END SUSPICIOUS ===":
			inSection = ""
			suspiciousCategory = ""
			continue
		case "=== MODULE FETCH START ===", "=== MODULE FETCH END ===", "=== VIGIL GO ANALYSIS START ===", "=== VIGIL GO ANALYSIS END ===":
			inSection = ""
			continue
		}

		// Track suspicious subcategories
		if inSection == "suspicious" {
			switch line {
			case "--- CGO_USAGE ---":
				suspiciousCategory = "cgo_usage"
				continue
			case "--- NATIVE_COMPILATION ---":
				suspiciousCategory = "native_compilation"
				continue
			case "--- MODULE_PROXY_USAGE ---":
				suspiciousCategory = "module_proxy_usage"
				continue
			case "--- BUILD_TIME_EXECUTION ---":
				suspiciousCategory = "build_time_execution"
				continue
			case "--- UNSAFE_PACKAGE ---":
				suspiciousCategory = "unsafe_package"
				continue
			case "--- REFLECTION_HEAVY ---":
				suspiciousCategory = "reflection_heavy"
				continue
			case "--- ASSEMBLY_CODE ---":
				suspiciousCategory = "assembly_code"
				continue
			case "--- EXTERNAL_LINKER ---":
				suspiciousCategory = "external_linker"
				continue
			case "--- VENDOR_DIRECTORY ---":
				suspiciousCategory = "vendor_directory"
				continue
			case "--- FILE_EMBEDDING ---":
				suspiciousCategory = "file_embedding"
				continue
			case "--- PLUGIN_LOADING ---":
				suspiciousCategory = "plugin_loading"
				continue
			case "--- SYSTEM_CALL_HEAVY ---":
				suspiciousCategory = "system_call_heavy"
				continue
			case "--- NETWORK_ACTIVITY ---":
				suspiciousCategory = "network_activity"
				continue
			case "--- FILE_SYSTEM_ACCESS ---":
				suspiciousCategory = "file_system_access"
				continue
			case "--- ENVIRONMENT_ACCESS ---":
				suspiciousCategory = "environment_access"
				continue
			}
		}

		if line == "" {
			continue
		}

		switch inSection {
		case "module_files":
			if strings.Contains(line, "go.mod") || strings.Contains(line, "go.sum") {
				result.Commands = append(result.Commands, line)
			}
		case "files":
			result.FilesWritten = append(result.FilesWritten, line)
		case "suspicious":
			if suspiciousCategory != "" && strings.HasPrefix(line, ".") {
				result.SuspiciousFiles[suspiciousCategory] = append(
					result.SuspiciousFiles[suspiciousCategory], line)
			}
		}
	}
}

// QuickCheckGo runs a lightweight check for Go packages
func (s *Sandbox) QuickCheckGo(modulePath, version string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Quick check: just fetch module info
	script := fmt.Sprintf(`
go list -m -json %s@%s 2>/dev/null || echo "Module not found"
`, modulePath, version)

	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "--network=bridge",
		SandboxGoImage, "/bin/sh", "-c", script)

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return false, "", err
	}

	output := stdout.String()
	hasRisk := strings.Contains(output, "go.mod") ||
		strings.Contains(output, "go.sum")

	return hasRisk, output, nil
}
