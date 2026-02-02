package colorutil

import (
	"strings"
	"testing"

	"github.com/fatih/color"
)

// TestApplyNoColor checks that calling ApplyNoColor sets the
// global color.NoColor flag to true, which disables all ANSI
// color codes from the fatih/color library.
func TestApplyNoColor(t *testing.T) {
	// Save the original value so we can restore it after the test.
	// This prevents side effects on other tests.
	original := color.NoColor
	defer func() { color.NoColor = original }()

	color.NoColor = false // start with color enabled
	ApplyNoColor()

	if !color.NoColor {
		t.Error("expected color.NoColor to be true after ApplyNoColor()")
	}
}

// TestColorizeSeverity_Known tests that each known severity string
// (critical, high, medium, low) returns a non-empty result that
// still contains the original severity text.
func TestColorizeSeverity_Known(t *testing.T) {
	// We force NoColor so Sprint returns plain text without ANSI codes.
	// This makes string comparison reliable in tests.
	color.NoColor = true
	defer func() { color.NoColor = false }()

	cases := []string{"critical", "high", "medium", "low"}
	for _, severity := range cases {
		result := ColorizeSeverity(severity)
		if result == "" {
			t.Errorf("ColorizeSeverity(%q) returned empty string", severity)
		}
		if !strings.Contains(result, severity) {
			t.Errorf("ColorizeSeverity(%q) = %q, does not contain %q", severity, result, severity)
		}
	}
}

// TestColorizeSeverity_Unknown tests that an unrecognized severity
// string is returned as-is without modification.
func TestColorizeSeverity_Unknown(t *testing.T) {
	result := ColorizeSeverity("unknown")
	if result != "unknown" {
		t.Errorf("ColorizeSeverity(\"unknown\") = %q, want %q", result, "unknown")
	}
}

// TestColorizeRiskLevel_Known tests that each known risk level
// (CRITICAL, HIGH, MEDIUM, LOW) returns output containing the
// original level string.
func TestColorizeRiskLevel_Known(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	cases := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW"}
	for _, level := range cases {
		result := ColorizeRiskLevel(level)
		if result == "" {
			t.Errorf("ColorizeRiskLevel(%q) returned empty string", level)
		}
		if !strings.Contains(result, level) {
			t.Errorf("ColorizeRiskLevel(%q) = %q, does not contain %q", level, result, level)
		}
	}
}

// TestColorizeRiskLevel_Unknown tests that an unrecognized level
// falls through to the default case and returns the input unchanged.
func TestColorizeRiskLevel_Unknown(t *testing.T) {
	result := ColorizeRiskLevel("UNKNOWN")
	if result != "UNKNOWN" {
		t.Errorf("ColorizeRiskLevel(\"UNKNOWN\") = %q, want %q", result, "UNKNOWN")
	}
}

// TestPrintRiskLevel_DoesNotPanic verifies that calling PrintRiskLevel
// with each known label doesn't crash. We can't easily capture stdout
// in a unit test without extra plumbing, so we just verify no panic.
func TestPrintRiskLevel_DoesNotPanic(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	labels := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
	for _, label := range labels {
		// If this panics, the test fails automatically
		PrintRiskLevel(label, 5)
	}
}

// TestColorizePackageRisk_ScoreThresholds tests that the function
// returns non-empty output for each risk score bracket:
//   - >= 75: CRITICAL (red)
//   - >= 50: HIGH (yellow bold)
//   - >= 25: MEDIUM (yellow)
//   - < 25:  LOW (green)
func TestColorizePackageRisk_ScoreThresholds(t *testing.T) {
	color.NoColor = true
	defer func() { color.NoColor = false }()

	cases := []struct {
		name  string
		score int
	}{
		{"critical score", 100},
		{"high score", 60},
		{"medium score", 30},
		{"low score", 10},
	}

	for _, tc := range cases {
		result := ColorizePackageRisk("lodash@4.17.21", tc.score)
		if result == "" {
			t.Errorf("ColorizePackageRisk(%q, %d) returned empty string", "lodash@4.17.21", tc.score)
		}
		if !strings.Contains(result, "lodash@4.17.21") {
			t.Errorf("ColorizePackageRisk(%q, %d) = %q, does not contain package name", "lodash@4.17.21", tc.score, result)
		}
	}
}
