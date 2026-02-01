package resolver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestTreeResolver(handler http.HandlerFunc) (*TreeResolver, func()) {
	server := httptest.NewServer(handler)
	client := &NPMClient{
		baseURL:    server.URL,
		httpClient: server.Client(),
	}
	r := &TreeResolver{
		client:   client,
		resolved: make(map[string]*ResolvedPackage),
		maxDepth: 5,
	}
	return r, server.Close
}

// --- resolveVersion tests ---

func TestResolveVersion_ExactVersion(t *testing.T) {
	r, cleanup := newTestTreeResolver(func(w http.ResponseWriter, req *http.Request) {
		t.Fatal("should not call NPM for exact version")
	})
	defer cleanup()

	v, err := r.resolveVersion("lodash", "4.17.21")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "4.17.21" {
		t.Errorf("got %q, want %q", v, "4.17.21")
	}
}

func TestResolveVersion_LatestTag(t *testing.T) {
	r, cleanup := newTestTreeResolver(func(w http.ResponseWriter, req *http.Request) {
		// GetLatestVersion now calls GetVersionInfo(name, "latest")
		_ = json.NewEncoder(w).Encode(NPMVersionInfo{
			Name:    "lodash",
			Version: "4.17.21",
		})
	})
	defer cleanup()

	v, err := r.resolveVersion("lodash", "latest")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "4.17.21" {
		t.Errorf("got %q, want %q", v, "4.17.21")
	}
}

func TestResolveVersion_Star(t *testing.T) {
	r, cleanup := newTestTreeResolver(func(w http.ResponseWriter, req *http.Request) {
		// GetLatestVersion now calls GetVersionInfo(name, "latest")
		_ = json.NewEncoder(w).Encode(NPMVersionInfo{
			Name:    "lodash",
			Version: "4.17.21",
		})
	})
	defer cleanup()

	v, err := r.resolveVersion("lodash", "*")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "4.17.21" {
		t.Errorf("got %q, want %q", v, "4.17.21")
	}
}

func TestResolveVersion_CaretRange(t *testing.T) {
	r, cleanup := newTestTreeResolver(func(w http.ResponseWriter, req *http.Request) {
		_ = json.NewEncoder(w).Encode(NPMPackageInfo{
			Name:     "lodash",
			DistTags: map[string]string{"latest": "5.0.0"},
			Versions: map[string]NPMVersionInfo{
				"4.17.19": {Name: "lodash", Version: "4.17.19"},
				"4.17.20": {Name: "lodash", Version: "4.17.20"},
				"4.17.21": {Name: "lodash", Version: "4.17.21"},
				"5.0.0":   {Name: "lodash", Version: "5.0.0"},
			},
		})
	})
	defer cleanup()

	v, err := r.resolveVersion("lodash", "^4.17.19")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// ^4.17.19 should resolve to highest 4.x.x, which is 4.17.21 (not 5.0.0)
	if v != "4.17.21" {
		t.Errorf("got %q, want %q", v, "4.17.21")
	}
}

func TestResolveVersion_TildeRange(t *testing.T) {
	r, cleanup := newTestTreeResolver(func(w http.ResponseWriter, req *http.Request) {
		_ = json.NewEncoder(w).Encode(NPMPackageInfo{
			Name:     "debug",
			DistTags: map[string]string{"latest": "4.4.0"},
			Versions: map[string]NPMVersionInfo{
				"4.3.2": {Name: "debug", Version: "4.3.2"},
				"4.3.4": {Name: "debug", Version: "4.3.4"},
				"4.4.0": {Name: "debug", Version: "4.4.0"},
			},
		})
	})
	defer cleanup()

	v, err := r.resolveVersion("debug", "~4.3.2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// ~4.3.2 should resolve to highest 4.3.x, which is 4.3.4 (not 4.4.0)
	if v != "4.3.4" {
		t.Errorf("got %q, want %q", v, "4.3.4")
	}
}

func TestResolveVersion_GTERange(t *testing.T) {
	r, cleanup := newTestTreeResolver(func(w http.ResponseWriter, req *http.Request) {
		_ = json.NewEncoder(w).Encode(NPMPackageInfo{
			Name:     "express",
			DistTags: map[string]string{"latest": "4.18.2"},
			Versions: map[string]NPMVersionInfo{
				"3.21.2": {Name: "express", Version: "3.21.2"},
				"4.17.1": {Name: "express", Version: "4.17.1"},
				"4.18.2": {Name: "express", Version: "4.18.2"},
			},
		})
	})
	defer cleanup()

	v, err := r.resolveVersion("express", ">=4.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "4.18.2" {
		t.Errorf("got %q, want %q", v, "4.18.2")
	}
}

func TestResolveVersion_ORRange(t *testing.T) {
	r, cleanup := newTestTreeResolver(func(w http.ResponseWriter, req *http.Request) {
		_ = json.NewEncoder(w).Encode(NPMPackageInfo{
			Name:     "readable-stream",
			DistTags: map[string]string{"latest": "4.0.0"},
			Versions: map[string]NPMVersionInfo{
				"2.3.8": {Name: "readable-stream", Version: "2.3.8"},
				"3.6.0": {Name: "readable-stream", Version: "3.6.0"},
				"4.0.0": {Name: "readable-stream", Version: "4.0.0"},
			},
		})
	})
	defer cleanup()

	v, err := r.resolveVersion("readable-stream", "^2.0.0 || ^3.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should pick the highest matching: 3.6.0 (^3.0.0 matches 3.6.0, ^2 matches 2.3.8)
	if v != "3.6.0" {
		t.Errorf("got %q, want %q", v, "3.6.0")
	}
}

func TestResolveVersion_NoMatch_FallsBackToLatest(t *testing.T) {
	r, cleanup := newTestTreeResolver(func(w http.ResponseWriter, req *http.Request) {
		_ = json.NewEncoder(w).Encode(NPMPackageInfo{
			Name:     "pkg",
			DistTags: map[string]string{"latest": "1.0.0"},
			Versions: map[string]NPMVersionInfo{
				"1.0.0": {Name: "pkg", Version: "1.0.0"},
			},
		})
	})
	defer cleanup()

	v, err := r.resolveVersion("pkg", "^9.0.0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No version satisfies ^9.0.0, should fall back to latest
	if v != "1.0.0" {
		t.Errorf("got %q, want %q", v, "1.0.0")
	}
}

func TestResolveVersion_DistTag(t *testing.T) {
	r, cleanup := newTestTreeResolver(func(w http.ResponseWriter, req *http.Request) {
		t.Fatal("should not call NPM for dist tags")
	})
	defer cleanup()

	// "next" and "beta" are dist-tags, not semver constraints
	v, err := r.resolveVersion("pkg", "next")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != "next" {
		t.Errorf("got %q, want %q", v, "next")
	}
}

// --- isNonRegistrySpecifier tests ---

func TestIsNonRegistrySpecifier(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"catalog:", true},
		{"catalog:default", true},
		{"workspace:*", true},
		{"workspace:^", true},
		{"npm:lodash@^4.0.0", true},
		{"git+https://github.com/user/repo.git", true},
		{"git://github.com/user/repo.git", true},
		{"github:user/repo", true},
		{"file:../local-pkg", true},
		{"link:../local-pkg", true},
		{"http://example.com/pkg.tgz", true},
		{"https://example.com/pkg.tgz", true},
		{"^4.17.21", false},
		{"~1.2.3", false},
		{">=2.0.0", false},
		{"4.17.21", false},
		{"latest", false},
		{"*", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isNonRegistrySpecifier(tt.input)
			if got != tt.want {
				t.Errorf("isNonRegistrySpecifier(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// --- Skipped dependency tracking tests ---

func TestSkippedDependencyTracking(t *testing.T) {
	r, cleanup := newTestTreeResolver(func(w http.ResponseWriter, req *http.Request) {
		// Should not be called for non-registry specifiers
		t.Fatalf("unexpected NPM call: %s", req.URL.Path)
	})
	defer cleanup()

	// Resolve a workspace: specifier — should be skipped
	err := r.resolveDependency("internal-pkg", "workspace:*", "root", 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	skipped := r.GetSkipped()
	if len(skipped) != 1 {
		t.Fatalf("skipped count = %d, want 1", len(skipped))
	}
	if skipped[0].Name != "internal-pkg" {
		t.Errorf("skipped name = %q, want %q", skipped[0].Name, "internal-pkg")
	}
	if skipped[0].Specifier != "workspace:*" {
		t.Errorf("skipped specifier = %q, want %q", skipped[0].Specifier, "workspace:*")
	}

	// Verify summary includes skipped count
	summary := r.GetSummary()
	if summary.SkippedCount != 1 {
		t.Errorf("SkippedCount = %d, want 1", summary.SkippedCount)
	}
}

func TestGetSkipped_ReturnsCopy(t *testing.T) {
	r := &TreeResolver{
		resolved: make(map[string]*ResolvedPackage),
		skipped: []SkippedDependency{
			{Name: "pkg", Specifier: "workspace:*"},
		},
	}

	skippedCopy := r.GetSkipped()
	skippedCopy[0].Name = "modified"

	if r.skipped[0].Name != "pkg" {
		t.Error("GetSkipped did not return a copy")
	}
}

// --- Original tests ---

func TestTreeResolver_GetSummary_Empty(t *testing.T) {
	r := &TreeResolver{
		resolved: make(map[string]*ResolvedPackage),
	}

	s := r.GetSummary()
	if s.TotalPackages != 0 {
		t.Errorf("TotalPackages = %d, want 0", s.TotalPackages)
	}
	if s.DirectDeps != 0 {
		t.Errorf("DirectDeps = %d, want 0", s.DirectDeps)
	}
	if s.TransitiveDeps != 0 {
		t.Errorf("TransitiveDeps = %d, want 0", s.TransitiveDeps)
	}
	if s.WithInstallHooks != 0 {
		t.Errorf("WithInstallHooks = %d, want 0", s.WithInstallHooks)
	}
	if s.MaxDepth != 0 {
		t.Errorf("MaxDepth = %d, want 0", s.MaxDepth)
	}
}

func TestTreeResolver_GetSummary_WithPackages(t *testing.T) {
	r := &TreeResolver{
		resolved: map[string]*ResolvedPackage{
			"lodash@4.17.21": {
				Name: "lodash", Depth: 1,
				HasInstallHooks: false,
			},
			"express@4.18.2": {
				Name: "express", Depth: 1,
				HasInstallHooks: true,
			},
			"debug@4.3.4": {
				Name: "debug", Depth: 3,
				HasInstallHooks: false,
			},
		},
	}

	s := r.GetSummary()
	if s.TotalPackages != 3 {
		t.Errorf("TotalPackages = %d, want 3", s.TotalPackages)
	}
	if s.DirectDeps != 2 {
		t.Errorf("DirectDeps = %d, want 2", s.DirectDeps)
	}
	if s.TransitiveDeps != 1 {
		t.Errorf("TransitiveDeps = %d, want 1", s.TransitiveDeps)
	}
	if s.WithInstallHooks != 1 {
		t.Errorf("WithInstallHooks = %d, want 1", s.WithInstallHooks)
	}
	if s.MaxDepth != 3 {
		t.Errorf("MaxDepth = %d, want 3", s.MaxDepth)
	}
}

// --- Partial/bare version tests ---

func TestIsPartialVersion(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"1", true},
		{"0", true},
		{"2", true},
		{"0.3", true},
		{"1.1", true},
		{"4.17", true},
		{"1.2.3", false},   // full version — not partial
		{"next", false},    // dist-tag
		{"beta", false},    // dist-tag
		{"latest", false},  // dist-tag
		{"^1.0.0", false},  // range operator
		{"", false},        // empty
		{"1.x", false},     // contains non-digit
		{"1.2.x", false},   // contains non-digit
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isPartialVersion(tt.input)
			if got != tt.want {
				t.Errorf("isPartialVersion(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolveVersion_BareVersion(t *testing.T) {
	r, cleanup := newTestTreeResolver(func(w http.ResponseWriter, req *http.Request) {
		_ = json.NewEncoder(w).Encode(NPMPackageInfo{
			Name:     "wrappy",
			DistTags: map[string]string{"latest": "1.0.4"},
			Versions: map[string]NPMVersionInfo{
				"1.0.0": {Name: "wrappy", Version: "1.0.0"},
				"1.0.2": {Name: "wrappy", Version: "1.0.2"},
				"1.0.4": {Name: "wrappy", Version: "1.0.4"},
				"2.0.0": {Name: "wrappy", Version: "2.0.0"},
			},
		})
	})
	defer cleanup()

	v, err := r.resolveVersion("wrappy", "1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// "1" in npm means >=1.0.0 <2.0.0, should resolve to 1.0.4
	if v != "1.0.4" {
		t.Errorf("got %q, want %q", v, "1.0.4")
	}
}

func TestResolveVersion_PartialMinorVersion(t *testing.T) {
	r, cleanup := newTestTreeResolver(func(w http.ResponseWriter, req *http.Request) {
		_ = json.NewEncoder(w).Encode(NPMPackageInfo{
			Name:     "split",
			DistTags: map[string]string{"latest": "1.0.1"},
			Versions: map[string]NPMVersionInfo{
				"0.3.0": {Name: "split", Version: "0.3.0"},
				"0.3.3": {Name: "split", Version: "0.3.3"},
				"0.4.0": {Name: "split", Version: "0.4.0"},
				"1.0.1": {Name: "split", Version: "1.0.1"},
			},
		})
	})
	defer cleanup()

	v, err := r.resolveVersion("split", "0.3")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// "0.3" means >=0.3.0 <0.4.0, should resolve to 0.3.3
	if v != "0.3.3" {
		t.Errorf("got %q, want %q", v, "0.3.3")
	}
}

func TestResolveVersion_XRangeMinor(t *testing.T) {
	r, cleanup := newTestTreeResolver(func(w http.ResponseWriter, req *http.Request) {
		_ = json.NewEncoder(w).Encode(NPMPackageInfo{
			Name:     "readable-stream",
			DistTags: map[string]string{"latest": "4.0.0"},
			Versions: map[string]NPMVersionInfo{
				"1.1.0":  {Name: "readable-stream", Version: "1.1.0"},
				"1.1.14": {Name: "readable-stream", Version: "1.1.14"},
				"1.2.0":  {Name: "readable-stream", Version: "1.2.0"},
				"2.0.0":  {Name: "readable-stream", Version: "2.0.0"},
			},
		})
	})
	defer cleanup()

	v, err := r.resolveVersion("readable-stream", "1.1.x")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// "1.1.x" means >=1.1.0 <1.2.0, should resolve to 1.1.14
	if v != "1.1.14" {
		t.Errorf("got %q, want %q", v, "1.1.14")
	}
}

func TestTreeResolver_GetResolved_ReturnsCopy(t *testing.T) {
	r := &TreeResolver{
		resolved: map[string]*ResolvedPackage{
			"lodash@4.17.21": {Name: "lodash", Depth: 1},
		},
	}

	copy := r.GetResolved()
	copy["new-pkg@1.0.0"] = &ResolvedPackage{Name: "new-pkg"}

	if len(r.resolved) != 1 {
		t.Errorf("original map modified: len = %d, want 1", len(r.resolved))
	}
}
