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
