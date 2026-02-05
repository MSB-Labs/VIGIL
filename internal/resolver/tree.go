package resolver

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	semver "github.com/Masterminds/semver/v3"
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

// SkippedDependency records a dependency that was skipped during resolution
type SkippedDependency struct {
	Name      string
	Specifier string
	Reason    string
	Parent    string
}

// TreeResolver resolves the full dependency tree
type TreeResolver struct {
	client   *NPMClient
	resolved map[string]*ResolvedPackage // name@version -> package
	skipped  []SkippedDependency
	mu       sync.Mutex
	maxDepth int
	lockfile *Lockfile // optional lockfile for exact version resolution
}

// NewTreeResolver creates a new dependency tree resolver
func NewTreeResolver(maxDepth int) *TreeResolver {
	return &TreeResolver{
		client:   NewNPMClient(),
		resolved: make(map[string]*ResolvedPackage),
		maxDepth: maxDepth,
	}
}

// SetLockfile sets the lockfile to use for exact version resolution
func (r *TreeResolver) SetLockfile(lockfile *Lockfile) {
	r.lockfile = lockfile
}

// HasLockfile returns true if a lockfile is set
func (r *TreeResolver) HasLockfile() bool {
	return r.lockfile != nil
}

// GetLockfileType returns the type of lockfile being used
func (r *TreeResolver) GetLockfileType() LockfileType {
	if r.lockfile == nil {
		return LockfileNone
	}
	return r.lockfile.Type
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

// ResolveFromDependencies resolves a dependency tree from a pre-built list of dependencies
func (r *TreeResolver) ResolveFromDependencies(deps []Dependency) ([]*ResolvedPackage, error) {
	for _, dep := range deps {
		if err := r.resolveDependency(dep.Name, dep.Version, dep.Parent, 1); err != nil {
			fmt.Printf("Warning: failed to resolve %s: %v\n", dep.Name, err)
		}
	}

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

	// Check for non-registry specifiers before attempting resolution
	if isNonRegistrySpecifier(versionConstraint) {
		r.mu.Lock()
		r.skipped = append(r.skipped, SkippedDependency{
			Name:      name,
			Specifier: versionConstraint,
			Reason:    "non-registry specifier",
			Parent:    parent,
		})
		r.mu.Unlock()
		return nil
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
	// Check lockfile first for exact version
	if r.lockfile != nil {
		if lockedVersion, found := r.lockfile.GetLockedVersion(name, constraint); found {
			return lockedVersion, nil
		}
	}

	// Handle "latest" tag or empty constraint
	if constraint == "latest" || constraint == "*" || constraint == "" {
		return r.client.GetLatestVersion(name)
	}

	// Only accept full X.Y.Z (2+ dots, no wildcards) as exact version.
	// Bare versions like "1", "0.3" are partial and must be treated as ranges.
	if strings.Count(constraint, ".") >= 2 && !strings.ContainsAny(constraint, "xX*") {
		if _, err := semver.NewVersion(constraint); err == nil {
			return constraint, nil
		}
	}

	// Check if this looks like a semver range
	trimmed := strings.TrimSpace(constraint)
	isRange := strings.ContainsAny(trimmed, "^~><=|") ||
		trimmed == "*" ||
		strings.Contains(trimmed, " ") ||
		strings.Contains(trimmed, ".x") ||
		strings.Contains(trimmed, ".X")

	// Bare/partial versions like "1", "0.3", "2" should be treated as ranges.
	// In npm, "1" means >=1.0.0 <2.0.0, "0.3" means >=0.3.0 <0.4.0.
	if !isRange && isPartialVersion(trimmed) {
		constraint = "~" + trimmed
		isRange = true
	}

	if !isRange {
		// Not a range — treat as dist-tag (e.g., "next", "beta", "canary")
		return constraint, nil
	}

	// Parse the semver constraint
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		// Constraint parsing failed — fall back to latest
		fmt.Printf("Warning: could not parse constraint %q for %s, using latest\n", constraint, name)
		return r.client.GetLatestVersion(name)
	}

	// Fetch all available versions from npm registry
	info, err := r.client.GetPackageInfo(name)
	if err != nil {
		return "", err
	}

	// Collect versions that satisfy the constraint
	var matching []*semver.Version
	for vStr := range info.Versions {
		v, err := semver.NewVersion(vStr)
		if err != nil {
			continue
		}
		// Skip prereleases unless the constraint explicitly mentions one
		if v.Prerelease() != "" && !strings.ContainsAny(constraint, "-") {
			continue
		}
		if c.Check(v) {
			matching = append(matching, v)
		}
	}

	if len(matching) == 0 {
		// No version satisfies — fall back to latest dist-tag
		if latest, ok := info.DistTags["latest"]; ok {
			return latest, nil
		}
		return "", fmt.Errorf("no version satisfies %s for %s", constraint, name)
	}

	// Sort descending, pick the highest matching version
	sort.Sort(sort.Reverse(semver.Collection(matching)))
	return matching[0].Original(), nil
}

// isNonRegistrySpecifier returns true for version specifiers that cannot
// be resolved against the npm registry.
func isNonRegistrySpecifier(constraint string) bool {
	prefixes := []string{
		"catalog:",
		"workspace:",
		"npm:",
		"git+",
		"git://",
		"github:",
		"file:",
		"link:",
		"http://",
		"https://",
	}
	lower := strings.ToLower(constraint)
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// isPartialVersion returns true for bare numeric versions like "1", "0.3", "2"
// that npm treats as ranges (e.g., "1" = >=1.0.0 <2.0.0) rather than exact versions.
func isPartialVersion(s string) bool {
	if strings.Count(s, ".") > 1 {
		return false // full X.Y.Z — not partial
	}
	for _, c := range s {
		if c != '.' && (c < '0' || c > '9') {
			return false
		}
	}
	return len(s) > 0
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

// GetSkipped returns all skipped dependencies
func (r *TreeResolver) GetSkipped() []SkippedDependency {
	r.mu.Lock()
	defer r.mu.Unlock()

	result := make([]SkippedDependency, len(r.skipped))
	copy(result, r.skipped)
	return result
}

// TreeSummary holds statistics about the resolved tree
type TreeSummary struct {
	TotalPackages    int
	DirectDeps       int
	TransitiveDeps   int
	WithInstallHooks int
	MaxDepth         int
	SkippedCount     int
}

// GetSummary returns statistics about the resolved tree
func (r *TreeResolver) GetSummary() TreeSummary {
	r.mu.Lock()
	defer r.mu.Unlock()

	summary := TreeSummary{}
	summary.TotalPackages = len(r.resolved)
	summary.SkippedCount = len(r.skipped)

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
