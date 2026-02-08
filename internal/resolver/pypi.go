package resolver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const pypiRegistryURL = "https://pypi.org/pypi"

// PyPIClient handles communication with the PyPI registry
type PyPIClient struct {
	baseURL    string
	httpClient *http.Client
}

// PyPIPackageInfo represents package metadata from PyPI registry
type PyPIPackageInfo struct {
	Info    PyPIPackageInfoData `json:"info"`
	Releases map[string][]PyPIReleaseInfo `json:"releases"`
	URLs    []PyPIReleaseInfo   `json:"urls"`
}

// PyPIPackageInfoData contains the main package information
type PyPIPackageInfoData struct {
	Name        string            `json:"name"`
	Summary     string            `json:"summary"`
	Description string            `json:"description"`
	Author      string            `json:"author"`
	AuthorEmail string            `json:"author_email"`
	License     string            `json:"license"`
	HomePage    string            `json:"home_page"`
	ProjectURLs map[string]string `json:"project_urls"`
	RequiresPython string         `json:"requires_python"`
	RequiresDist []string         `json:"requires_dist"`
	Keywords    string            `json:"keywords"`
}

// PyPIReleaseInfo represents a specific version's metadata
type PyPIReleaseInfo struct {
	Filename    string `json:"filename"`
	URL         string `json:"url"`
	UploadTime  string `json:"upload_time_iso_8601"`
	MD5Digest   string `json:"md5_digest"`
	SHA256Digest string `json:"digests.sha256"`
	Packagetype string `json:"packagetype"`
	Size        int64  `json:"size"`
}

// NewPyPIClient creates a new PyPI registry client
func NewPyPIClient() *PyPIClient {
	return &PyPIClient{
		baseURL: pypiRegistryURL,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// GetPackageInfo fetches package metadata from PyPI
func (c *PyPIClient) GetPackageInfo(packageName string) (*PyPIPackageInfo, error) {
	// PyPI API endpoint: /pypi/{package}/json
	reqURL := fmt.Sprintf("%s/%s/json", c.baseURL, packageName)

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", packageName, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "VIGIL-Python-Client/1.0")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package %s: %w", packageName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %s not found", packageName)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("PyPI registry returned status %d for %s", resp.StatusCode, packageName)
	}

	var info PyPIPackageInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to parse PyPI response for %s: %w", packageName, err)
	}

	return &info, nil
}

// GetLatestVersion returns the latest version from PyPI
func (c *PyPIClient) GetLatestVersion(packageName string) (string, error) {
	info, err := c.GetPackageInfo(packageName)
	if err != nil {
		return "", fmt.Errorf("failed to get package info for %s: %w", packageName, err)
	}

	// PyPI returns versions in the releases map, latest is usually the highest
	var latest string
	for version := range info.Releases {
		if latest == "" || compareVersions(version, latest) > 0 {
			latest = version
		}
	}

	if latest == "" {
		return "", fmt.Errorf("no versions found for %s", packageName)
	}

	return latest, nil
}

// GetVersionInfo fetches metadata for a specific version
func (c *PyPIClient) GetVersionInfo(packageName, version string) (*PyPIReleaseInfo, error) {
	info, err := c.GetPackageInfo(packageName)
	if err != nil {
		return nil, fmt.Errorf("failed to get package info for %s: %w", packageName, err)
	}

	// Find the specific version in releases
	releases, ok := info.Releases[version]
	if !ok || len(releases) == 0 {
		return nil, fmt.Errorf("version %s not found for package %s", version, packageName)
	}

	// Return the first release info (usually the source distribution)
	return &releases[0], nil
}

// HasInstallHooks checks if a package has setup.py or pyproject.toml with build scripts
func (c *PyPIClient) HasInstallHooks(packageName, version string) (bool, error) {
	// For now, we'll assume most Python packages have some form of installation
	// In the future, we could download and inspect the package metadata
	return true, nil
}

// compareVersions compares two version strings
// Returns: 1 if v1 > v2, -1 if v1 < v2, 0 if equal
func compareVersions(v1, v2 string) int {
	// Simple version comparison for now
	// This is a basic implementation - real version comparison is more complex
	v1Parts := strings.Split(v1, ".")
	v2Parts := strings.Split(v2, ".")

	maxLen := len(v1Parts)
	if len(v2Parts) > maxLen {
		maxLen = len(v2Parts)
	}

	for i := 0; i < maxLen; i++ {
		part1 := "0"
		if i < len(v1Parts) {
			part1 = v1Parts[i]
		}

		part2 := "0"
		if i < len(v2Parts) {
			part2 = v2Parts[i]
		}

		// Remove any non-numeric suffixes for basic comparison
		num1 := strings.TrimRight(part1, "0123456789")
		num2 := strings.TrimRight(part2, "0123456789")

		if num1 > num2 {
			return 1
		} else if num1 < num2 {
			return -1
		}
	}

	return 0
}

// PythonPackage represents a Python package with its dependencies
type PythonPackage struct {
	Name         string
	Version      string
	Dependencies []string
	Author       string
	Summary      string
	HomePage     string
	Keywords     []string
}

// ParseRequirements parses a requirements.txt content and returns package names
func ParseRequirements(content string) []string {
	var packages []string
	scanner := strings.Split(content, "\n")

	for _, line := range scanner {
		line = strings.TrimSpace(line)
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Extract package name (before ==, >=, <=, etc.)
		pkg := strings.Split(line, "==")[0]
		pkg = strings.Split(pkg, ">=")[0]
		pkg = strings.Split(pkg, "<=")[0]
		pkg = strings.Split(pkg, ">")[0]
		pkg = strings.Split(pkg, "<")[0]
		pkg = strings.Split(pkg, "~=")[0]
		pkg = strings.TrimSpace(pkg)

		if pkg != "" {
			packages = append(packages, pkg)
		}
	}

	return packages
}

// ParsePyProject parses a pyproject.toml content and returns package names
func ParsePyProject(content string) []string {
	var packages []string
	lines := strings.Split(content, "\n")
	inDependencies := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for dependencies section
		if strings.Contains(line, "[tool.poetry.dependencies]") || 
		   strings.Contains(line, "[project.optional-dependencies]") ||
		   strings.Contains(line, "[project.dependencies]") {
			inDependencies = true
			continue
		}

		// End of dependencies section
		if strings.HasPrefix(line, "[") && inDependencies {
			inDependencies = false
			continue
		}

		if inDependencies && line != "" && !strings.HasPrefix(line, "#") {
			// Parse dependency line: package = "version" or package = {version = "..."}
			if idx := strings.Index(line, "="); idx > 0 {
				pkg := strings.TrimSpace(line[:idx])
				if pkg != "" && !strings.ContainsAny(pkg, "{}") {
					packages = append(packages, pkg)
				}
			}
		}
	}

	return packages
}