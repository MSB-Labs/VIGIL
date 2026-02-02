package resolver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspacesConfig_UnmarshalJSON_Array(t *testing.T) {
	input := `["packages/*", "apps/*"]`
	var wc WorkspacesConfig
	if err := json.Unmarshal([]byte(input), &wc); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(wc.Patterns) != 2 {
		t.Fatalf("got %d patterns, want 2", len(wc.Patterns))
	}
	if wc.Patterns[0] != "packages/*" {
		t.Errorf("pattern[0] = %q, want %q", wc.Patterns[0], "packages/*")
	}
	if wc.Patterns[1] != "apps/*" {
		t.Errorf("pattern[1] = %q, want %q", wc.Patterns[1], "apps/*")
	}
}

func TestWorkspacesConfig_UnmarshalJSON_Object(t *testing.T) {
	input := `{"packages": ["packages/*"]}`
	var wc WorkspacesConfig
	if err := json.Unmarshal([]byte(input), &wc); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(wc.Patterns) != 1 {
		t.Fatalf("got %d patterns, want 1", len(wc.Patterns))
	}
	if wc.Patterns[0] != "packages/*" {
		t.Errorf("pattern[0] = %q, want %q", wc.Patterns[0], "packages/*")
	}
}

func TestWorkspacesConfig_UnmarshalJSON_Null(t *testing.T) {
	input := `null`
	var wc WorkspacesConfig
	if err := json.Unmarshal([]byte(input), &wc); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(wc.Patterns) != 0 {
		t.Errorf("got %d patterns, want 0", len(wc.Patterns))
	}
}

func TestParsePackageJSON_WithWorkspaces(t *testing.T) {
	dir := t.TempDir()
	pkgData := `{
		"name": "monorepo",
		"version": "1.0.0",
		"workspaces": ["packages/*"],
		"devDependencies": {"typescript": "^5.0.0"}
	}`
	_ = os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgData), 0644)

	pkg, err := ParsePackageJSON(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkg.Workspaces.Patterns) != 1 {
		t.Fatalf("workspace patterns = %d, want 1", len(pkg.Workspaces.Patterns))
	}
	if pkg.Workspaces.Patterns[0] != "packages/*" {
		t.Errorf("pattern = %q, want %q", pkg.Workspaces.Patterns[0], "packages/*")
	}
}

func TestDetectWorkspaces_NotAWorkspace(t *testing.T) {
	dir := t.TempDir()
	pkgData := `{"name": "simple-app", "version": "1.0.0", "dependencies": {"lodash": "^4.0.0"}}`
	_ = os.WriteFile(filepath.Join(dir, "package.json"), []byte(pkgData), 0644)

	wsInfo, err := DetectWorkspaces(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wsInfo != nil {
		t.Error("expected nil for non-workspace project")
	}
}

func TestDetectWorkspaces_WithNpmWorkspaces(t *testing.T) {
	dir := t.TempDir()

	// Root package.json with workspaces
	rootPkg := `{
		"name": "my-monorepo",
		"version": "1.0.0",
		"workspaces": ["packages/*"],
		"devDependencies": {"typescript": "^5.0.0"}
	}`
	_ = os.WriteFile(filepath.Join(dir, "package.json"), []byte(rootPkg), 0644)

	// Create workspace package: packages/core
	coreDir := filepath.Join(dir, "packages", "core")
	_ = os.MkdirAll(coreDir, 0755)
	corePkg := `{
		"name": "@myorg/core",
		"version": "1.0.0",
		"dependencies": {"lodash": "^4.17.21"}
	}`
	_ = os.WriteFile(filepath.Join(coreDir, "package.json"), []byte(corePkg), 0644)

	// Create workspace package: packages/cli
	cliDir := filepath.Join(dir, "packages", "cli")
	_ = os.MkdirAll(cliDir, 0755)
	cliPkg := `{
		"name": "@myorg/cli",
		"version": "1.0.0",
		"dependencies": {
			"@myorg/core": "workspace:*",
			"commander": "^11.0.0"
		}
	}`
	_ = os.WriteFile(filepath.Join(cliDir, "package.json"), []byte(cliPkg), 0644)

	wsInfo, err := DetectWorkspaces(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wsInfo == nil {
		t.Fatal("expected workspace info, got nil")
	}
	if len(wsInfo.Packages) != 2 {
		t.Fatalf("workspace packages = %d, want 2", len(wsInfo.Packages))
	}

	// Check internal names
	if !wsInfo.InternalNames["@myorg/core"] {
		t.Error("@myorg/core should be an internal name")
	}
	if !wsInfo.InternalNames["@myorg/cli"] {
		t.Error("@myorg/cli should be an internal name")
	}
	if !wsInfo.InternalNames["my-monorepo"] {
		t.Error("my-monorepo (root) should be an internal name")
	}
}

func TestDetectWorkspaces_PnpmWorkspaceYaml(t *testing.T) {
	dir := t.TempDir()

	// Root package.json WITHOUT workspaces field
	rootPkg := `{"name": "pnpm-monorepo", "version": "1.0.0"}`
	_ = os.WriteFile(filepath.Join(dir, "package.json"), []byte(rootPkg), 0644)

	// pnpm-workspace.yaml
	pnpmWs := "packages:\n  - 'packages/*'\n"
	_ = os.WriteFile(filepath.Join(dir, "pnpm-workspace.yaml"), []byte(pnpmWs), 0644)

	// Create a workspace package
	pkgDir := filepath.Join(dir, "packages", "utils")
	_ = os.MkdirAll(pkgDir, 0755)
	utilsPkg := `{"name": "@myorg/utils", "version": "1.0.0", "dependencies": {"zod": "^3.0.0"}}`
	_ = os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(utilsPkg), 0644)

	wsInfo, err := DetectWorkspaces(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if wsInfo == nil {
		t.Fatal("expected workspace info, got nil")
	}
	if len(wsInfo.Packages) != 1 {
		t.Fatalf("workspace packages = %d, want 1", len(wsInfo.Packages))
	}
	if wsInfo.Packages[0].PackageJSON.Name != "@myorg/utils" {
		t.Errorf("package name = %q, want %q", wsInfo.Packages[0].PackageJSON.Name, "@myorg/utils")
	}
}

func TestGetExternalDependencies_SkipsInternal(t *testing.T) {
	wsInfo := &WorkspaceInfo{
		RootPackage: &PackageJSON{
			Name:    "monorepo",
			Version: "1.0.0",
			DevDependencies: map[string]string{
				"typescript": "^5.0.0",
			},
		},
		Packages: []WorkspacePackage{
			{
				Path: "packages/core",
				PackageJSON: &PackageJSON{
					Name:    "@myorg/core",
					Version: "1.0.0",
					Dependencies: map[string]string{
						"lodash": "^4.17.21",
					},
				},
			},
			{
				Path: "packages/cli",
				PackageJSON: &PackageJSON{
					Name:    "@myorg/cli",
					Version: "1.0.0",
					Dependencies: map[string]string{
						"@myorg/core": "workspace:*", // internal — should be skipped
						"commander":   "^11.0.0",
					},
				},
			},
		},
		InternalNames: map[string]bool{
			"monorepo":    true,
			"@myorg/core": true,
			"@myorg/cli":  true,
		},
	}

	// Without dev deps
	deps := wsInfo.GetExternalDependencies(false)

	// Should include: lodash, commander (NOT @myorg/core)
	names := make(map[string]bool)
	for _, d := range deps {
		names[d.Name] = true
	}

	if !names["lodash"] {
		t.Error("lodash should be in external dependencies")
	}
	if !names["commander"] {
		t.Error("commander should be in external dependencies")
	}
	if names["@myorg/core"] {
		t.Error("@myorg/core is internal and should be excluded")
	}
	if names["typescript"] {
		t.Error("typescript is a devDep and should be excluded without --dev")
	}
	if len(deps) != 2 {
		t.Errorf("external deps count = %d, want 2", len(deps))
	}
}

func TestGetExternalDependencies_WithDevDeps(t *testing.T) {
	wsInfo := &WorkspaceInfo{
		RootPackage: &PackageJSON{
			Name:    "monorepo",
			Version: "1.0.0",
			DevDependencies: map[string]string{
				"typescript": "^5.0.0",
			},
		},
		Packages: []WorkspacePackage{
			{
				Path: "packages/core",
				PackageJSON: &PackageJSON{
					Name:    "@myorg/core",
					Version: "1.0.0",
					Dependencies: map[string]string{
						"lodash": "^4.17.21",
					},
				},
			},
		},
		InternalNames: map[string]bool{
			"monorepo":    true,
			"@myorg/core": true,
		},
	}

	deps := wsInfo.GetExternalDependencies(true)

	names := make(map[string]bool)
	for _, d := range deps {
		names[d.Name] = true
	}

	if !names["lodash"] {
		t.Error("lodash should be in external dependencies")
	}
	if !names["typescript"] {
		t.Error("typescript should be included with devDeps enabled")
	}
	if len(deps) != 2 {
		t.Errorf("external deps count = %d, want 2", len(deps))
	}
}

func TestGetExternalDependencies_Deduplicates(t *testing.T) {
	wsInfo := &WorkspaceInfo{
		RootPackage: &PackageJSON{
			Name:    "monorepo",
			Version: "1.0.0",
			Dependencies: map[string]string{
				"lodash": "^4.17.21",
			},
		},
		Packages: []WorkspacePackage{
			{
				Path: "packages/a",
				PackageJSON: &PackageJSON{
					Name:    "pkg-a",
					Version: "1.0.0",
					Dependencies: map[string]string{
						"lodash": "^4.17.21", // same as root
					},
				},
			},
		},
		InternalNames: map[string]bool{
			"monorepo": true,
			"pkg-a":    true,
		},
	}

	deps := wsInfo.GetExternalDependencies(false)
	if len(deps) != 1 {
		t.Errorf("expected dedup to 1 dep, got %d", len(deps))
	}
}
