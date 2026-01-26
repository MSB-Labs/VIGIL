// Package resolver handles fetching packages from registries
// and resolving dependency trees.
package resolver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// PackageJSON represents the structure of a package.json file
type PackageJSON struct {
	Name            string            `json:"name"`
	Version         string            `json:"version"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// Dependency represents a single package dependency
type Dependency struct {
	Name    string
	Version string // version constraint from package.json
	Parent  string // which package depends on this
}

// DependencyTree holds the full resolved dependency information
type DependencyTree struct {
	Root         PackageJSON
	Dependencies []Dependency
}

// ParsePackageJSON reads and parses a package.json file
func ParsePackageJSON(projectPath string) (*PackageJSON, error) {
	pkgPath := filepath.Join(projectPath, "package.json")

	data, err := os.ReadFile(pkgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}

	var pkg PackageJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	return &pkg, nil
}

// GetDirectDependencies extracts all direct dependencies from package.json
func GetDirectDependencies(pkg *PackageJSON, includeDevDeps bool) []Dependency {
	var deps []Dependency

	for name, version := range pkg.Dependencies {
		deps = append(deps, Dependency{
			Name:    name,
			Version: version,
			Parent:  pkg.Name,
		})
	}

	if includeDevDeps {
		for name, version := range pkg.DevDependencies {
			deps = append(deps, Dependency{
				Name:    name,
				Version: version,
				Parent:  pkg.Name + " (dev)",
			})
		}
	}

	return deps
}
