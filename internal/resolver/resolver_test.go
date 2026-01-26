package resolver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParsePackageJSON_Valid(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]interface{}{
		"name":    "test-project",
		"version": "1.0.0",
		"dependencies": map[string]string{
			"lodash":  "^4.17.21",
			"express": "^4.18.0",
		},
		"devDependencies": map[string]string{
			"jest": "^29.0.0",
		},
	}
	data, _ := json.Marshal(pkg)
	os.WriteFile(filepath.Join(dir, "package.json"), data, 0644)

	result, err := ParsePackageJSON(dir)
	if err != nil {
		t.Fatalf("ParsePackageJSON returned error: %v", err)
	}
	if result.Name != "test-project" {
		t.Errorf("Name = %q, want %q", result.Name, "test-project")
	}
	if result.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", result.Version, "1.0.0")
	}
	if len(result.Dependencies) != 2 {
		t.Errorf("Dependencies count = %d, want 2", len(result.Dependencies))
	}
	if result.Dependencies["lodash"] != "^4.17.21" {
		t.Errorf("lodash version = %q, want %q", result.Dependencies["lodash"], "^4.17.21")
	}
	if len(result.DevDependencies) != 1 {
		t.Errorf("DevDependencies count = %d, want 1", len(result.DevDependencies))
	}
}

func TestParsePackageJSON_NotFound(t *testing.T) {
	dir := t.TempDir()
	_, err := ParsePackageJSON(dir)
	if err == nil {
		t.Error("expected error for missing package.json")
	}
}

func TestParsePackageJSON_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte("{invalid json}"), 0644)

	_, err := ParsePackageJSON(dir)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestParsePackageJSON_MinimalValid(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"minimal","version":"0.0.1"}`), 0644)

	result, err := ParsePackageJSON(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Name != "minimal" {
		t.Errorf("Name = %q, want %q", result.Name, "minimal")
	}
	if len(result.Dependencies) != 0 {
		t.Errorf("Dependencies count = %d, want 0", len(result.Dependencies))
	}
	if len(result.DevDependencies) != 0 {
		t.Errorf("DevDependencies count = %d, want 0", len(result.DevDependencies))
	}
}

func TestGetDirectDependencies_WithoutDevDeps(t *testing.T) {
	pkg := &PackageJSON{
		Name:    "my-app",
		Version: "1.0.0",
		Dependencies: map[string]string{
			"lodash":  "^4.17.21",
			"express": "^4.18.0",
		},
		DevDependencies: map[string]string{
			"jest": "^29.0.0",
		},
	}

	deps := GetDirectDependencies(pkg, false)
	if len(deps) != 2 {
		t.Fatalf("got %d deps, want 2", len(deps))
	}

	for _, d := range deps {
		if d.Parent != "my-app" {
			t.Errorf("dep %s: Parent = %q, want %q", d.Name, d.Parent, "my-app")
		}
		if d.Name == "jest" {
			t.Error("dev dependency jest should not be included")
		}
	}
}

func TestGetDirectDependencies_WithDevDeps(t *testing.T) {
	pkg := &PackageJSON{
		Name:    "my-app",
		Version: "1.0.0",
		Dependencies: map[string]string{
			"lodash": "^4.17.21",
		},
		DevDependencies: map[string]string{
			"jest": "^29.0.0",
		},
	}

	deps := GetDirectDependencies(pkg, true)
	if len(deps) != 2 {
		t.Fatalf("got %d deps, want 2", len(deps))
	}

	foundDev := false
	for _, d := range deps {
		if d.Name == "jest" {
			foundDev = true
			if d.Parent != "my-app (dev)" {
				t.Errorf("dev dep Parent = %q, want %q", d.Parent, "my-app (dev)")
			}
		}
	}
	if !foundDev {
		t.Error("dev dependency jest should be included")
	}
}

func TestGetDirectDependencies_EmptyDeps(t *testing.T) {
	pkg := &PackageJSON{
		Name:    "empty",
		Version: "0.0.1",
	}

	deps := GetDirectDependencies(pkg, false)
	if len(deps) != 0 {
		t.Errorf("got %d deps, want 0", len(deps))
	}

	deps = GetDirectDependencies(pkg, true)
	if len(deps) != 0 {
		t.Errorf("got %d deps with devDeps, want 0", len(deps))
	}
}
