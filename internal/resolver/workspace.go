package resolver

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// WorkspacePackage represents a discovered workspace member
type WorkspacePackage struct {
	Path        string       // relative path to the workspace package directory
	PackageJSON *PackageJSON // parsed package.json of the workspace member
}

// WorkspaceInfo holds aggregated workspace information
type WorkspaceInfo struct {
	RootPackage   *PackageJSON
	Packages      []WorkspacePackage
	InternalNames map[string]bool // package names that are workspace-internal
}

// DetectWorkspaces checks if the project uses workspaces and discovers all members.
// Supports npm/yarn workspaces (package.json "workspaces" field) and
// pnpm workspaces (pnpm-workspace.yaml).
// Returns nil if the project is not a workspace.
func DetectWorkspaces(projectPath string) (*WorkspaceInfo, error) {
	rootPkg, err := ParsePackageJSON(projectPath)
	if err != nil {
		return nil, err
	}

	patterns := rootPkg.Workspaces.Patterns

	// If no workspaces in package.json, check for pnpm-workspace.yaml
	if len(patterns) == 0 {
		pnpmPatterns, pnpmErr := parsePnpmWorkspace(projectPath)
		if pnpmErr == nil && len(pnpmPatterns) > 0 {
			patterns = pnpmPatterns
		}
	}

	// Not a workspace project
	if len(patterns) == 0 {
		return nil, nil
	}

	info := &WorkspaceInfo{
		RootPackage:   rootPkg,
		InternalNames: make(map[string]bool),
	}

	// Add root package name as internal
	if rootPkg.Name != "" {
		info.InternalNames[rootPkg.Name] = true
	}

	// Glob each pattern to find workspace package directories
	for _, pattern := range patterns {
		globPattern := filepath.Join(projectPath, filepath.FromSlash(pattern))
		matches, err := filepath.Glob(globPattern)
		if err != nil {
			fmt.Printf("Warning: invalid workspace pattern %q: %v\n", pattern, err)
			continue
		}

		for _, match := range matches {
			pkgJsonPath := filepath.Join(match, "package.json")
			if _, statErr := os.Stat(pkgJsonPath); os.IsNotExist(statErr) {
				continue
			}

			wsPkg, parseErr := ParsePackageJSON(match)
			if parseErr != nil {
				fmt.Printf("Warning: failed to parse %s: %v\n", pkgJsonPath, parseErr)
				continue
			}

			relPath, _ := filepath.Rel(projectPath, match)
			info.Packages = append(info.Packages, WorkspacePackage{
				Path:        filepath.ToSlash(relPath),
				PackageJSON: wsPkg,
			})
			if wsPkg.Name != "" {
				info.InternalNames[wsPkg.Name] = true
			}
		}
	}

	return info, nil
}

// GetExternalDependencies aggregates dependencies from root and all workspace members,
// excluding references to other workspace packages (internal refs).
func (wi *WorkspaceInfo) GetExternalDependencies(includeDevDeps bool) []Dependency {
	seen := make(map[string]bool) // "name@version" dedup
	var deps []Dependency

	// Collect from root package
	for _, d := range GetDirectDependencies(wi.RootPackage, includeDevDeps) {
		if wi.InternalNames[d.Name] {
			continue
		}
		key := d.Name + "@" + d.Version
		if !seen[key] {
			seen[key] = true
			deps = append(deps, d)
		}
	}

	// Collect from each workspace member
	for _, wsPkg := range wi.Packages {
		for _, d := range GetDirectDependencies(wsPkg.PackageJSON, includeDevDeps) {
			if wi.InternalNames[d.Name] {
				continue
			}
			key := d.Name + "@" + d.Version
			if !seen[key] {
				seen[key] = true
				d.Parent = wsPkg.PackageJSON.Name
				deps = append(deps, d)
			}
		}
	}

	return deps
}

// pnpmWorkspaceConfig represents pnpm-workspace.yaml structure
type pnpmWorkspaceConfig struct {
	Packages []string `yaml:"packages"`
}

func parsePnpmWorkspace(projectPath string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(projectPath, "pnpm-workspace.yaml"))
	if err != nil {
		return nil, err
	}
	var config pnpmWorkspaceConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse pnpm-workspace.yaml: %w", err)
	}
	return config.Packages, nil
}
