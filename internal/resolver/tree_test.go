package resolver

import (
	"testing"
)

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
