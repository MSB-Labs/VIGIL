package resolver

import (
	"fmt"
	"strings"
	"sync"
)

// ResolvedPackage contains full info about a resolved dependency
type ResolvedPackage struct {
	Name            string
	Version         string
	ResolvedVersion string // actual version after constraint resolution
	Parent          string
	Depth           int
	HasInstallHooks bool
	Dependencies    map[string]string
}

// TreeResolver resolves the full dependency tree
type TreeResolver struct {
	client   *NPMClient
	resolved map[string]*ResolvedPackage // name@version -> package
	mu       sync.Mutex
	maxDepth int
}

// NewTreeResolver creates a new dependency tree resolver
func NewTreeResolver(maxDepth int) *TreeResolver {
	return &TreeResolver{
		client:   NewNPMClient(),
		resolved: make(map[string]*ResolvedPackage),
		maxDepth: maxDepth,
	}
}

// Resolve builds the complete dependency tree for a project
func (r *TreeResolver) Resolve(projectPath string, includeDevDeps bool) ([]*ResolvedPackage, error) {
	pkg, err := ParsePackageJSON(projectPath)
	if err != nil {
		return nil, err
	}

	directDeps := GetDirectDependencies(pkg, includeDevDeps)

	for _, dep := range directDeps {
		if err := r.resolveDependency(dep.Name, dep.Version, dep.Parent, 1); err != nil {
			// Log warning but continue - some deps might fail
			fmt.Printf("Warning: failed to resolve %s: %v\n", dep.Name, err)
		}
	}

	// Convert map to slice
	result := make([]*ResolvedPackage, 0, len(r.resolved))
	for _, pkg := range r.resolved {
		result = append(result, pkg)
	}

	return result, nil
}

// resolveDependency recursively resolves a single dependency
func (r *TreeResolver) resolveDependency(name, versionConstraint, parent string, depth int) error {
	if depth > r.maxDepth {
		return nil // stop at max depth
	}

	// Resolve version constraint to actual version
	resolvedVersion, err := r.resolveVersion(name, versionConstraint)
	if err != nil {
		return err
	}

	key := fmt.Sprintf("%s@%s", name, resolvedVersion)

	r.mu.Lock()
	if _, exists := r.resolved[key]; exists {
		r.mu.Unlock()
		return nil // already resolved
	}
	r.mu.Unlock()

	// Fetch package info
	versionInfo, err := r.client.GetVersionInfo(name, resolvedVersion)
	if err != nil {
		return err
	}

	pkg := &ResolvedPackage{
		Name:            name,
		Version:         versionConstraint,
		ResolvedVersion: resolvedVersion,
		Parent:          parent,
		Depth:           depth,
		HasInstallHooks: versionInfo.HasPostInstallScript(),
		Dependencies:    versionInfo.Dependencies,
	}

	r.mu.Lock()
	r.resolved[key] = pkg
	r.mu.Unlock()

	// Recursively resolve sub-dependencies
	for depName, depVersion := range versionInfo.Dependencies {
		if err := r.resolveDependency(depName, depVersion, name, depth+1); err != nil {
			fmt.Printf("Warning: failed to resolve %s -> %s: %v\n", name, depName, err)
		}
	}

	return nil
}

// resolveVersion converts a version constraint to an actual version
func (r *TreeResolver) resolveVersion(name, constraint string) (string, error) {
	// Handle exact versions
	if !strings.ContainsAny(constraint, "^~><=*x") {
		return constraint, nil
	}

	// Handle "latest" tag
	if constraint == "latest" || constraint == "*" {
		return r.client.GetLatestVersion(name)
	}

	// For semver ranges (^, ~, etc.), fetch the package and find matching version
	// For MVP, we'll just get the latest version that satisfies the constraint
	// A full implementation would use a semver library

	info, err := r.client.GetPackageInfo(name)
	if err != nil {
		return "", err
	}

	// Simple approach for MVP: use the latest dist-tag
	// In production, this should properly resolve semver ranges
	if latest, ok := info.DistTags["latest"]; ok {
		return latest, nil
	}

	return "", fmt.Errorf("could not resolve version %s for %s", constraint, name)
}

// GetResolved returns all resolved packages
func (r *TreeResolver) GetResolved() map[string]*ResolvedPackage {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Return a copy
	result := make(map[string]*ResolvedPackage, len(r.resolved))
	for k, v := range r.resolved {
		result[k] = v
	}
	return result
}

// Summary returns a summary of the resolved tree
type TreeSummary struct {
	TotalPackages    int
	DirectDeps       int
	TransitiveDeps   int
	WithInstallHooks int
	MaxDepth         int
}

// GetSummary returns statistics about the resolved tree
func (r *TreeResolver) GetSummary() TreeSummary {
	r.mu.Lock()
	defer r.mu.Unlock()

	summary := TreeSummary{}
	summary.TotalPackages = len(r.resolved)

	for _, pkg := range r.resolved {
		if pkg.Depth == 1 {
			summary.DirectDeps++
		} else {
			summary.TransitiveDeps++
		}

		if pkg.HasInstallHooks {
			summary.WithInstallHooks++
		}

		if pkg.Depth > summary.MaxDepth {
			summary.MaxDepth = pkg.Depth
		}
	}

	return summary
}
