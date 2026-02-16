package resolver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const goProxyURL = "https://proxy.golang.org"

// GoModClient handles communication with Go module proxy
type GoModClient struct {
	baseURL    string
	httpClient *http.Client
}

// GoModuleInfo represents module metadata from Go proxy
type GoModuleInfo struct {
	Path     string `json:"Path"`
	Version  string `json:"Version"`
	Time     string `json:"Time"`
	Origin   string `json:"Origin"`
	Files    []string `json:"Files"`
	Info     string `json:"Info"`
	Mod      string `json:"Mod"`
	Zip      string `json:"Zip"`
}

// GoModuleVersion represents a specific version of a module
type GoModuleVersion struct {
	Version string `json:"Version"`
	Time    string `json:"Time"`
}

// GoModuleVersions represents available versions for a module
type GoModuleVersions struct {
	Versions []string `json:"Versions"`
}

// NewGoModClient creates a new Go module proxy client
func NewGoModClient() *GoModClient {
	return &GoModClient{
		baseURL: goProxyURL,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// GetModuleInfo fetches module metadata from Go proxy
func (c *GoModClient) GetModuleInfo(modulePath, version string) (*GoModuleInfo, error) {
	// Go proxy API: /{module}@{version}.info
	reqURL := fmt.Sprintf("%s/%s@%s.info", c.baseURL, modulePath, version)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s@%s: %w", modulePath, version, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "VIGIL-Go-Client/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch module %s@%s: %w", modulePath, version, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("module %s@%s not found", modulePath, version)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Go proxy returned status %d for %s@%s", resp.StatusCode, modulePath, version)
	}

	var info GoModuleInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to parse Go proxy response for %s@%s: %w", modulePath, version, err)
	}

	return &info, nil
}

// GetLatestVersion returns the latest version from Go proxy
func (c *GoModClient) GetLatestVersion(modulePath string) (string, error) {
	// Go proxy API: /{module}@latest
	reqURL := fmt.Sprintf("%s/%s@latest.info", c.baseURL, modulePath)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request for %s@latest: %w", modulePath, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "VIGIL-Go-Client/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch latest version for %s: %w", modulePath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("module %s not found", modulePath)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Go proxy returned status %d for %s@latest", resp.StatusCode, modulePath)
	}

	var info GoModuleInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("failed to parse Go proxy response for %s@latest: %w", modulePath, err)
	}

	return info.Version, nil
}

// GetModuleModFile fetches the go.mod file content for a module version
func (c *GoModClient) GetModuleModFile(modulePath, version string) (string, error) {
	// Go proxy API: /{module}@{version}.mod
	reqURL := fmt.Sprintf("%s/%s@%s.mod", c.baseURL, modulePath, version)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request for %s@%s.mod: %w", modulePath, version, err)
	}
	req.Header.Set("User-Agent", "VIGIL-Go-Client/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch go.mod for %s@%s: %w", modulePath, version, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("go.mod not found for %s@%s", modulePath, version)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("Go proxy returned status %d for %s@%s.mod", resp.StatusCode, modulePath, version)
	}

	var modContent string
	if err := json.NewDecoder(resp.Body).Decode(&modContent); err != nil {
		// If JSON decoding fails, try reading as plain text
		resp.Body.Close()
		req, err = http.NewRequest("GET", reqURL, nil)
		if err != nil {
			return "", fmt.Errorf("failed to create request for %s@%s.mod: %w", modulePath, version, err)
		}
		req.Header.Set("Accept", "text/plain")
		req.Header.Set("User-Agent", "VIGIL-Go-Client/1.0")

		resp, err = c.httpClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("failed to fetch go.mod for %s@%s: %w", modulePath, version, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("Go proxy returned status %d for %s@%s.mod", resp.StatusCode, modulePath, version)
		}

		buf := make([]byte, 1024*1024) // 1MB buffer
		n, err := resp.Body.Read(buf)
		if err != nil {
			return "", fmt.Errorf("failed to read go.mod content for %s@%s: %w", modulePath, version, err)
		}
		modContent = string(buf[:n])
	}

	return modContent, nil
}

// GetModuleZipURL returns the download URL for module zip file
func (c *GoModClient) GetModuleZipURL(modulePath, version string) (string, error) {
	// Go proxy API: /{module}@{version}.zip
	return fmt.Sprintf("%s/%s@%s.zip", c.baseURL, modulePath, version), nil
}

// HasCGOUsage checks if a module uses CGO by examining its go.mod and source files
func (c *GoModClient) HasCGOUsage(modulePath, version string) (bool, error) {
	// For now, we'll assume modules might use CGO
	// In the future, we could download and inspect the module source
	return true, nil
}

// GoPackage represents a Go module with its dependencies
type GoPackage struct {
	Path         string
	Version      string
	Dependencies []string
	Indirect     []string
	Replace      map[string]string
	Exclude      []string
	Retract      []string
}

// ParseGoMod parses a go.mod file content and returns package information
func ParseGoMod(content string) (*GoPackage, error) {
	var pkg GoPackage
	pkg.Replace = make(map[string]string) // Initialize the map
	lines := strings.Split(content, "\n")
	inRequire := false
	inReplace := false
	inExclude := false
	inRetract := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		// Module directive
		if strings.HasPrefix(line, "module ") {
			pkg.Path = strings.TrimSpace(strings.TrimPrefix(line, "module"))
			continue
		}

		// Go version directive
		if strings.HasPrefix(line, "go ") {
			continue
		}

		// Toolchain directive
		if strings.HasPrefix(line, "toolchain ") {
			continue
		}

		// Require block
		if line == "require (" {
			inRequire = true
			continue
		}
		if line == ")" && inRequire {
			inRequire = false
			continue
		}
		if inRequire {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				dep := parts[0]
				// Check if it's indirect
				if len(parts) > 2 && parts[len(parts)-1] == "indirect" {
					pkg.Indirect = append(pkg.Indirect, dep)
				} else {
					pkg.Dependencies = append(pkg.Dependencies, dep)
				}
			}
			continue
		}

		// Replace block
		if line == "replace (" {
			inReplace = true
			continue
		}
		if line == ")" && inReplace {
			inReplace = false
			continue
		}
		if inReplace {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				old := parts[0]
				new := parts[2]
				// Join the rest of the parts for the new value
				if len(parts) > 3 {
					new = strings.Join(parts[2:], " ")
				}
				pkg.Replace[old] = new
			}
			continue
		}

		// Exclude block
		if line == "exclude (" {
			inExclude = true
			continue
		}
		if line == ")" && inExclude {
			inExclude = false
			continue
		}
		if inExclude {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				exclude := parts[0]
				// Join the rest of the parts for the version
				if len(parts) > 2 {
					exclude = strings.Join(parts[0:2], " ")
				}
				pkg.Exclude = append(pkg.Exclude, exclude)
			}
			continue
		}

		// Retract block
		if line == "retract (" {
			inRetract = true
			continue
		}
		if line == ")" && inRetract {
			inRetract = false
			continue
		}
		if inRetract {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pkg.Retract = append(pkg.Retract, parts[0])
			}
			continue
		}

		// Single-line require
		if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				dep := parts[1]
				pkg.Dependencies = append(pkg.Dependencies, dep)
			}
			continue
		}

		// Single-line replace
		if strings.HasPrefix(line, "replace ") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				old := parts[1]
				new := parts[3]
				pkg.Replace[old] = new
			}
			continue
		}

		// Single-line exclude
		if strings.HasPrefix(line, "exclude ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pkg.Exclude = append(pkg.Exclude, parts[1])
			}
			continue
		}

		// Single-line retract
		if strings.HasPrefix(line, "retract ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pkg.Retract = append(pkg.Retract, parts[1])
			}
			continue
		}
	}

	return &pkg, nil
}

// ParseGoSum parses a go.sum file content and returns checksum information
func ParseGoSum(content string) map[string]string {
	checksums := make(map[string]string)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			module := parts[0] + " " + parts[1]
			checksum := parts[2]
			checksums[module] = checksum
		}
	}

	return checksums
}

// GetGoDirectDependencies extracts direct dependencies from go.mod
func GetGoDirectDependencies(pkg *GoPackage) []string {
	var deps []string
	for _, dep := range pkg.Dependencies {
		// Skip if this dependency is replaced
		if _, replaced := pkg.Replace[dep]; !replaced {
			deps = append(deps, dep)
		}
	}
	return deps
}

// GetGoIndirectDependencies extracts indirect dependencies from go.mod
func GetGoIndirectDependencies(pkg *GoPackage) []string {
	var indirect []string
	for _, dep := range pkg.Indirect {
		// Skip if this dependency is replaced
		if _, replaced := pkg.Replace[dep]; !replaced {
			indirect = append(indirect, dep)
		}
	}
	return indirect
}
