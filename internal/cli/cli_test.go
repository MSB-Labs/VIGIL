package cli

import (
	"testing"
)

func TestParsePackageArg_RegularPackage(t *testing.T) {
	name, version := parsePackageArg("lodash")
	if name != "lodash" {
		t.Errorf("name = %q, want %q", name, "lodash")
	}
	if version != "latest" {
		t.Errorf("version = %q, want %q", version, "latest")
	}
}

func TestParsePackageArg_WithVersion(t *testing.T) {
	name, version := parsePackageArg("lodash@4.17.21")
	if name != "lodash" {
		t.Errorf("name = %q, want %q", name, "lodash")
	}
	if version != "4.17.21" {
		t.Errorf("version = %q, want %q", version, "4.17.21")
	}
}

func TestParsePackageArg_ScopedPackage(t *testing.T) {
	name, version := parsePackageArg("@types/node")
	if name != "@types/node" {
		t.Errorf("name = %q, want %q", name, "@types/node")
	}
	if version != "latest" {
		t.Errorf("version = %q, want %q", version, "latest")
	}
}

func TestParsePackageArg_ScopedWithVersion(t *testing.T) {
	name, version := parsePackageArg("@types/node@18.0.0")
	if name != "@types/node" {
		t.Errorf("name = %q, want %q", name, "@types/node")
	}
	if version != "18.0.0" {
		t.Errorf("version = %q, want %q", version, "18.0.0")
	}
}

func TestParsePackageArg_EmptyString(t *testing.T) {
	name, version := parsePackageArg("")
	if name != "" {
		t.Errorf("name = %q, want %q", name, "")
	}
	if version != "latest" {
		t.Errorf("version = %q, want %q", version, "latest")
	}
}

func TestParsePackageArg_VersionRange(t *testing.T) {
	name, version := parsePackageArg("express@^4.0.0")
	if name != "express" {
		t.Errorf("name = %q, want %q", name, "express")
	}
	if version != "^4.0.0" {
		t.Errorf("version = %q, want %q", version, "^4.0.0")
	}
}

func TestParallelFlag_DefaultValue(t *testing.T) {
	f := scanCmd.Flags().Lookup("parallel")
	if f == nil {
		t.Fatal("--parallel flag not registered on scan command")
	}
	if f.DefValue != "4" {
		t.Errorf("default = %q, want %q", f.DefValue, "4")
	}
}

func TestParallelFlag_ParsesValue(t *testing.T) {
	f := scanCmd.Flags().Lookup("parallel")
	if f == nil {
		t.Fatal("--parallel flag not registered on scan command")
	}
	if err := f.Value.Set("8"); err != nil {
		t.Fatalf("failed to set --parallel to 8: %v", err)
	}
	if f.Value.String() != "8" {
		t.Errorf("value = %q, want %q", f.Value.String(), "8")
	}
	// Reset to default for other tests
	_ = f.Value.Set("4")
}

func TestClampWorkers_ZeroClampsToOne(t *testing.T) {
	if got := clampWorkers(0, 10); got != 1 {
		t.Errorf("clampWorkers(0, 10) = %d, want 1", got)
	}
}

func TestClampWorkers_NegativeClampsToOne(t *testing.T) {
	if got := clampWorkers(-1, 10); got != 1 {
		t.Errorf("clampWorkers(-1, 10) = %d, want 1", got)
	}
}

func TestClampWorkers_ExceedsJobsClampsToJobs(t *testing.T) {
	if got := clampWorkers(999, 5); got != 5 {
		t.Errorf("clampWorkers(999, 5) = %d, want 5", got)
	}
}

func TestClampWorkers_ValidValueUnchanged(t *testing.T) {
	if got := clampWorkers(4, 10); got != 4 {
		t.Errorf("clampWorkers(4, 10) = %d, want 4", got)
	}
}

func TestNoColorFlag_Registered(t *testing.T) {
	// Verify the --no-color flag exists on rootCmd and defaults to false.
	// rootCmd uses PersistentFlags so it applies to all subcommands.
	f := rootCmd.PersistentFlags().Lookup("no-color")
	if f == nil {
		t.Fatal("--no-color flag not registered on root command")
	}
	if f.DefValue != "false" {
		t.Errorf("--no-color default = %q, want %q", f.DefValue, "false")
	}
}

