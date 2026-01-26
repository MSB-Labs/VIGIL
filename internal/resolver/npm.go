package resolver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const npmRegistryURL = "https://registry.npmjs.org"

// NPMClient handles communication with the npm registry
type NPMClient struct {
	baseURL    string
	httpClient *http.Client
}

// NPMPackageInfo represents package metadata from npm registry
type NPMPackageInfo struct {
	Name        string                        `json:"name"`
	Description string                        `json:"description"`
	DistTags    map[string]string             `json:"dist-tags"`
	Versions    map[string]NPMVersionInfo     `json:"versions"`
	Time        map[string]string             `json:"time"` // version -> publish timestamp
	Maintainers []NPMMaintainer               `json:"maintainers"`
}

// NPMVersionInfo represents a specific version's metadata
type NPMVersionInfo struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Description     string            `json:"description"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Scripts         map[string]string `json:"scripts"`
	Dist            NPMDist           `json:"dist"`
}

// NPMDist contains distribution information
type NPMDist struct {
	Tarball   string `json:"tarball"`
	Shasum    string `json:"shasum"`
	Integrity string `json:"integrity"`
}

// NPMMaintainer represents a package maintainer
type NPMMaintainer struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

// NewNPMClient creates a new npm registry client
func NewNPMClient() *NPMClient {
	return &NPMClient{
		baseURL: npmRegistryURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetPackageInfo fetches full package metadata from npm
func (c *NPMClient) GetPackageInfo(packageName string) (*NPMPackageInfo, error) {
	url := fmt.Sprintf("%s/%s", c.baseURL, packageName)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch package %s: %w", packageName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("package %s not found", packageName)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm registry returned status %d for %s", resp.StatusCode, packageName)
	}

	var info NPMPackageInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to parse npm response for %s: %w", packageName, err)
	}

	return &info, nil
}

// GetVersionInfo fetches metadata for a specific version
func (c *NPMClient) GetVersionInfo(packageName, version string) (*NPMVersionInfo, error) {
	url := fmt.Sprintf("%s/%s/%s", c.baseURL, packageName, version)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s@%s: %w", packageName, version, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("version %s@%s not found", packageName, version)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm registry returned status %d for %s@%s", resp.StatusCode, packageName, version)
	}

	var info NPMVersionInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to parse npm response for %s@%s: %w", packageName, version, err)
	}

	return &info, nil
}

// GetLatestVersion returns the latest version tag
func (c *NPMClient) GetLatestVersion(packageName string) (string, error) {
	info, err := c.GetPackageInfo(packageName)
	if err != nil {
		return "", err
	}

	latest, ok := info.DistTags["latest"]
	if !ok {
		return "", fmt.Errorf("no latest tag found for %s", packageName)
	}

	return latest, nil
}

// HasPostInstallScript checks if a version has install scripts (security risk indicator)
func (v *NPMVersionInfo) HasPostInstallScript() bool {
	riskyScripts := []string{"preinstall", "install", "postinstall", "preuninstall", "postuninstall"}
	for _, script := range riskyScripts {
		if _, exists := v.Scripts[script]; exists {
			return true
		}
	}
	return false
}
