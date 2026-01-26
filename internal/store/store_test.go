package store

import (
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("failed to create test store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func sampleFingerprint(name, version string, riskScore int) *BehaviorFingerprint {
	return &BehaviorFingerprint{
		PackageName:     name,
		Version:         version,
		Ecosystem:       "npm",
		AnalyzedAt:      time.Now(),
		NetworkCalls:    []string{"example.com"},
		FileReads:       []string{"/etc/passwd"},
		FileWrites:      []string{"/tmp/out"},
		EnvVarsRead:     []string{"HOME"},
		ShellCommands:   []string{"echo hi"},
		HasInstallHooks: true,
		DynamicCodeExec: false,
		RiskScore:       riskScore,
		Checksum:        "abc123",
	}
}

func TestNew_CreatesDatabase(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	s, err := New(dbPath)
	if err != nil {
		t.Fatalf("New returned error: %v", err)
	}
	defer s.Close()

	// DB should be usable
	_, err = s.GetStats()
	if err != nil {
		t.Errorf("GetStats on new DB returned error: %v", err)
	}
}

func TestNew_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "sub", "dir", "test.db")

	s, err := New(dbPath)
	if err != nil {
		t.Fatalf("New with nested dir returned error: %v", err)
	}
	s.Close()
}

func TestSaveFingerprint_AndRetrieve(t *testing.T) {
	s := newTestStore(t)
	fp := sampleFingerprint("lodash", "4.17.21", 0)

	err := s.SaveFingerprint(fp)
	if err != nil {
		t.Fatalf("SaveFingerprint returned error: %v", err)
	}
	if fp.ID == 0 {
		t.Error("ID should be set after save")
	}

	// Retrieve
	got, err := s.GetFingerprint("lodash", "4.17.21", "npm")
	if err != nil {
		t.Fatalf("GetFingerprint returned error: %v", err)
	}
	if got == nil {
		t.Fatal("GetFingerprint returned nil")
	}

	if got.PackageName != "lodash" {
		t.Errorf("PackageName = %q, want %q", got.PackageName, "lodash")
	}
	if got.Version != "4.17.21" {
		t.Errorf("Version = %q, want %q", got.Version, "4.17.21")
	}
	if got.Ecosystem != "npm" {
		t.Errorf("Ecosystem = %q, want %q", got.Ecosystem, "npm")
	}
	if got.RiskScore != 0 {
		t.Errorf("RiskScore = %d, want 0", got.RiskScore)
	}
	if !got.HasInstallHooks {
		t.Error("HasInstallHooks should be true")
	}
	if got.Checksum != "abc123" {
		t.Errorf("Checksum = %q, want %q", got.Checksum, "abc123")
	}

	// Check JSON round-trip of slices
	if len(got.NetworkCalls) != 1 || got.NetworkCalls[0] != "example.com" {
		t.Errorf("NetworkCalls = %v, want [example.com]", got.NetworkCalls)
	}
	if len(got.FileReads) != 1 || got.FileReads[0] != "/etc/passwd" {
		t.Errorf("FileReads = %v, want [/etc/passwd]", got.FileReads)
	}
	if len(got.ShellCommands) != 1 || got.ShellCommands[0] != "echo hi" {
		t.Errorf("ShellCommands = %v, want [echo hi]", got.ShellCommands)
	}
}

func TestSaveFingerprint_Upsert(t *testing.T) {
	s := newTestStore(t)

	fp := sampleFingerprint("lodash", "4.17.21", 10)
	err := s.SaveFingerprint(fp)
	if err != nil {
		t.Fatalf("first save error: %v", err)
	}

	// Update risk score
	fp.RiskScore = 80
	err = s.SaveFingerprint(fp)
	if err != nil {
		t.Fatalf("second save (upsert) error: %v", err)
	}

	got, err := s.GetFingerprint("lodash", "4.17.21", "npm")
	if err != nil {
		t.Fatalf("GetFingerprint error: %v", err)
	}
	if got.RiskScore != 80 {
		t.Errorf("RiskScore after upsert = %d, want 80", got.RiskScore)
	}
}

func TestGetFingerprint_NotFound(t *testing.T) {
	s := newTestStore(t)

	got, err := s.GetFingerprint("nonexistent", "1.0.0", "npm")
	if err != nil {
		t.Fatalf("GetFingerprint returned error: %v", err)
	}
	if got != nil {
		t.Error("expected nil for non-existent fingerprint")
	}
}

func TestHasFingerprint_Exists(t *testing.T) {
	s := newTestStore(t)
	s.SaveFingerprint(sampleFingerprint("lodash", "4.17.21", 0))

	has, err := s.HasFingerprint("lodash", "4.17.21", "npm")
	if err != nil {
		t.Fatalf("HasFingerprint error: %v", err)
	}
	if !has {
		t.Error("HasFingerprint should return true")
	}
}

func TestHasFingerprint_NotExists(t *testing.T) {
	s := newTestStore(t)

	has, err := s.HasFingerprint("nonexistent", "1.0.0", "npm")
	if err != nil {
		t.Fatalf("HasFingerprint error: %v", err)
	}
	if has {
		t.Error("HasFingerprint should return false")
	}
}

func TestGetHighRiskPackages(t *testing.T) {
	s := newTestStore(t)
	s.SaveFingerprint(sampleFingerprint("high-risk", "1.0.0", 80))
	s.SaveFingerprint(sampleFingerprint("medium-risk", "1.0.0", 50))
	s.SaveFingerprint(sampleFingerprint("low-risk", "1.0.0", 30))

	// Threshold 75
	results, err := s.GetHighRiskPackages(75)
	if err != nil {
		t.Fatalf("GetHighRiskPackages error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("threshold 75: got %d results, want 1", len(results))
	}
	if results[0].PackageName != "high-risk" {
		t.Errorf("first result = %q, want %q", results[0].PackageName, "high-risk")
	}

	// Threshold 50
	results, err = s.GetHighRiskPackages(50)
	if err != nil {
		t.Fatalf("GetHighRiskPackages error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("threshold 50: got %d results, want 2", len(results))
	}
	// Should be ordered descending
	if results[0].RiskScore < results[1].RiskScore {
		t.Error("results should be ordered by risk score descending")
	}
}

func TestGetHighRiskPackages_Empty(t *testing.T) {
	s := newTestStore(t)

	results, err := s.GetHighRiskPackages(50)
	if err != nil {
		t.Fatalf("GetHighRiskPackages error: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("empty DB: got %d results, want 0", len(results))
	}
}

func TestGetStats(t *testing.T) {
	s := newTestStore(t)
	s.SaveFingerprint(sampleFingerprint("lodash", "4.17.21", 0))
	s.SaveFingerprint(sampleFingerprint("lodash", "4.17.20", 10))
	s.SaveFingerprint(sampleFingerprint("express", "4.18.2", 80))

	stats, err := s.GetStats()
	if err != nil {
		t.Fatalf("GetStats error: %v", err)
	}
	if stats.TotalPackages != 2 {
		t.Errorf("TotalPackages = %d, want 2", stats.TotalPackages)
	}
	if stats.TotalVersions != 3 {
		t.Errorf("TotalVersions = %d, want 3", stats.TotalVersions)
	}
	if stats.HighRiskCount != 1 {
		t.Errorf("HighRiskCount = %d, want 1", stats.HighRiskCount)
	}
	if stats.WithInstallHooks != 3 {
		t.Errorf("WithInstallHooks = %d, want 3", stats.WithInstallHooks)
	}
}

func TestGetStats_EmptyDatabase(t *testing.T) {
	s := newTestStore(t)

	stats, err := s.GetStats()
	if err != nil {
		t.Fatalf("GetStats error: %v", err)
	}
	if stats.TotalPackages != 0 {
		t.Errorf("TotalPackages = %d, want 0", stats.TotalPackages)
	}
	if stats.TotalVersions != 0 {
		t.Errorf("TotalVersions = %d, want 0", stats.TotalVersions)
	}
	if stats.HighRiskCount != 0 {
		t.Errorf("HighRiskCount = %d, want 0", stats.HighRiskCount)
	}
}
