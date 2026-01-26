package analyzer

import (
	"strings"
	"testing"

	"github.com/MSB-Labs/vigil/internal/sandbox"
)

func TestNew(t *testing.T) {
	a := New()
	if a == nil {
		t.Fatal("New() returned nil")
	}
	if a.rules == nil {
		t.Fatal("New() analyzer has nil rules")
	}
	if len(a.rules.Rules) == 0 {
		t.Fatal("New() analyzer has 0 rules")
	}
}

func TestNewWithRules(t *testing.T) {
	customRule := makeRule("custom-1", SeverityHigh, "network", "exists", "")
	rs := &RuleSet{Rules: []*Rule{customRule}}
	a := NewWithRules(rs)

	if a == nil {
		t.Fatal("NewWithRules returned nil")
	}

	report := a.Analyze(&BehaviorData{NetworkCalls: []string{"test.com"}})
	if len(report.Matches) != 1 {
		t.Errorf("custom rule: got %d matches, want 1", len(report.Matches))
	}
	if report.Matches[0].Rule.ID != "custom-1" {
		t.Errorf("matched rule ID = %q, want %q", report.Matches[0].Rule.ID, "custom-1")
	}
}

func TestAnalyze_CleanPackage(t *testing.T) {
	a := New()
	report := a.Analyze(&BehaviorData{
		PackageName: "clean-pkg",
		Version:     "1.0.0",
	})

	if report.RiskScore != 0 {
		t.Errorf("clean package: RiskScore = %d, want 0", report.RiskScore)
	}
	if report.RiskLevel != "LOW" {
		t.Errorf("clean package: RiskLevel = %q, want %q", report.RiskLevel, "LOW")
	}
	if len(report.Matches) != 0 {
		t.Errorf("clean package: got %d matches, want 0", len(report.Matches))
	}
	if report.Summary.HasInstallScripts {
		t.Error("clean package: HasInstallScripts should be false")
	}
	if report.Summary.HasNetworkActivity {
		t.Error("clean package: HasNetworkActivity should be false")
	}
	if report.Summary.HasSuspiciousCode {
		t.Error("clean package: HasSuspiciousCode should be false")
	}
	if report.Summary.HasFileOperations {
		t.Error("clean package: HasFileOperations should be false")
	}
	if report.Summary.HasEnvAccess {
		t.Error("clean package: HasEnvAccess should be false")
	}
}

func TestAnalyze_CriticalPackage(t *testing.T) {
	a := New()
	report := a.Analyze(&BehaviorData{
		PackageName: "evil-pkg",
		Version:     "1.0.0",
		EnvVarsRead: []string{"AWS_SECRET_ACCESS_KEY"},
		NetworkCalls: []string{
			"http://192.168.1.1/exfil",
		},
	})

	if report.RiskScore < 75 {
		t.Errorf("critical package: RiskScore = %d, want >= 75", report.RiskScore)
	}
	if report.RiskLevel != "CRITICAL" {
		t.Errorf("critical package: RiskLevel = %q, want %q", report.RiskLevel, "CRITICAL")
	}
	if !report.HasCritical() {
		t.Error("critical package: HasCritical() should be true")
	}
}

func TestAnalyze_RiskLevelThresholds(t *testing.T) {
	tests := []struct {
		name     string
		data     *BehaviorData
		minScore int
		maxScore int
		level    string
	}{
		{
			name:     "LOW - clean package",
			data:     &BehaviorData{PackageName: "clean", Version: "1.0.0"},
			minScore: 0, maxScore: 24,
			level: "LOW",
		},
		{
			name: "MEDIUM - single low match",
			data: &BehaviorData{
				PackageName: "low-risk", Version: "1.0.0",
				FileWrites: []string{"file.node"},
			},
			minScore: 25, maxScore: 49,
			level: "MEDIUM",
		},
		{
			name: "HIGH - network activity",
			data: &BehaviorData{
				PackageName: "med-risk", Version: "1.0.0",
				NetworkCalls: []string{"https://example.com"},
			},
			minScore: 50, maxScore: 74,
			level: "HIGH",
		},
	}

	a := New()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := a.Analyze(tt.data)
			if report.RiskLevel != tt.level {
				t.Errorf("RiskLevel = %q, want %q (score=%d)", report.RiskLevel, tt.level, report.RiskScore)
			}
		})
	}
}

func TestAnalyze_MatchesSortedBySeverity(t *testing.T) {
	rules := []*Rule{
		makeRule("low-rule", SeverityLow, "file_write", "exists", ""),
		makeRule("crit-rule", SeverityCritical, "network", "exists", ""),
		makeRule("med-rule", SeverityMedium, "env", "exists", ""),
	}
	a := NewWithRules(&RuleSet{Rules: rules})

	report := a.Analyze(&BehaviorData{
		FileWrites:   []string{"/tmp/x"},
		NetworkCalls: []string{"evil.com"},
		EnvVarsRead:  []string{"HOME"},
	})

	if len(report.Matches) < 3 {
		t.Fatalf("got %d matches, want >= 3", len(report.Matches))
	}

	// Should be sorted descending by severity
	for i := 1; i < len(report.Matches); i++ {
		prev := SeverityScore(report.Matches[i-1].Rule.Severity)
		curr := SeverityScore(report.Matches[i].Rule.Severity)
		if prev < curr {
			t.Errorf("matches not sorted: [%d]=%d < [%d]=%d", i-1, prev, i, curr)
		}
	}
}

func TestAnalyze_BehaviorSummary(t *testing.T) {
	a := New()
	report := a.Analyze(&BehaviorData{
		PackageName:     "pkg",
		Version:         "1.0.0",
		HasInstallHooks: true,
		NetworkCalls:    []string{"example.com"},
		SuspiciousFiles: []string{"evil.js"},
		FileWrites:      []string{"a.txt", "b.txt"},
		EnvVarsRead:     []string{"HOME"},
	})

	s := report.Summary
	if !s.HasInstallScripts {
		t.Error("HasInstallScripts should be true")
	}
	if !s.HasNetworkActivity {
		t.Error("HasNetworkActivity should be true")
	}
	if !s.HasSuspiciousCode {
		t.Error("HasSuspiciousCode should be true")
	}
	if !s.HasFileOperations {
		t.Error("HasFileOperations should be true")
	}
	if !s.HasEnvAccess {
		t.Error("HasEnvAccess should be true")
	}
	if s.TotalFilesInstalled != 2 {
		t.Errorf("TotalFilesInstalled = %d, want 2", s.TotalFilesInstalled)
	}
}

func TestAnalyze_FingerprintCreated(t *testing.T) {
	a := New()
	report := a.Analyze(&BehaviorData{
		PackageName:  "fingerprint-pkg",
		Version:      "2.0.0",
		NetworkCalls: []string{"example.com"},
		FileWrites:   []string{"/tmp/file"},
		EnvVarsRead:  []string{"HOME"},
		ShellCommands: []string{"echo hello"},
		HasInstallHooks: true,
	})

	fp := report.Fingerprint
	if fp == nil {
		t.Fatal("Fingerprint is nil")
	}
	if fp.PackageName != "fingerprint-pkg" {
		t.Errorf("Fingerprint.PackageName = %q, want %q", fp.PackageName, "fingerprint-pkg")
	}
	if fp.Version != "2.0.0" {
		t.Errorf("Fingerprint.Version = %q, want %q", fp.Version, "2.0.0")
	}
	if fp.Ecosystem != "npm" {
		t.Errorf("Fingerprint.Ecosystem = %q, want %q", fp.Ecosystem, "npm")
	}
	if fp.RiskScore != report.RiskScore {
		t.Errorf("Fingerprint.RiskScore = %d, want %d", fp.RiskScore, report.RiskScore)
	}
	if !fp.HasInstallHooks {
		t.Error("Fingerprint.HasInstallHooks should be true")
	}
}

func TestAnalyzeResult_ConvertsExecutionResult(t *testing.T) {
	a := New()
	result := &sandbox.ExecutionResult{
		NetworkCalls: []string{"example.com"},
		FilesWritten: []string{"/tmp/out"},
		Commands:     []string{"npm install"},
		SuspiciousFiles: map[string][]string{
			"env_access":   {"process.env.SECRET"},
			"shell_access": {"child_process"},
		},
	}

	report := a.AnalyzeResult(result, "test-pkg", "1.0.0")

	if report.PackageName != "test-pkg" {
		t.Errorf("PackageName = %q, want %q", report.PackageName, "test-pkg")
	}
	if report.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", report.Version, "1.0.0")
	}
	// HasInstallHooks should be true because Commands is non-empty
	if !report.Summary.HasInstallScripts {
		t.Error("HasInstallScripts should be true (Commands non-empty)")
	}
}

func TestAnalyzeResult_EmptyExecutionResult(t *testing.T) {
	a := New()
	result := &sandbox.ExecutionResult{
		SuspiciousFiles: map[string][]string{},
	}

	report := a.AnalyzeResult(result, "empty", "0.0.0")
	if report == nil {
		t.Fatal("AnalyzeResult returned nil for empty result")
	}
	if report.RiskScore != 0 {
		t.Errorf("empty result: RiskScore = %d, want 0", report.RiskScore)
	}
}

// --- FormatReport tests ---

func TestFormatReport_NoMatches(t *testing.T) {
	report := &AnalysisReport{
		PackageName: "clean",
		Version:     "1.0.0",
		RiskScore:   0,
		RiskLevel:   "LOW",
		Matches:     nil,
		Summary:     &BehaviorSummary{},
	}

	output := report.FormatReport()
	if !strings.Contains(output, "clean@1.0.0") {
		t.Error("report should contain package@version")
	}
	if !strings.Contains(output, "No rules triggered") {
		t.Error("report should contain 'No rules triggered'")
	}
	if !strings.Contains(output, "0/100 [LOW]") {
		t.Error("report should contain '0/100 [LOW]'")
	}
}

func TestFormatReport_WithMatches(t *testing.T) {
	report := &AnalysisReport{
		PackageName: "evil",
		Version:     "6.6.6",
		RiskScore:   100,
		RiskLevel:   "CRITICAL",
		Matches: []*RuleMatch{
			{
				Rule:        &Rule{Name: "Credential Theft", Severity: SeverityCritical, Description: "Steals creds"},
				MatchedData: []string{"AWS_SECRET_KEY", "GITHUB_TOKEN"},
			},
			{
				Rule:        &Rule{Name: "Minor Issue", Severity: SeverityLow, Description: "Not serious"},
				MatchedData: []string{"something"},
			},
		},
		Summary: &BehaviorSummary{HasEnvAccess: true},
	}

	output := report.FormatReport()
	if !strings.Contains(output, "[!]") {
		t.Error("report should contain severity icon [!]")
	}
	if !strings.Contains(output, "[-]") {
		t.Error("report should contain severity icon [-]")
	}
	if !strings.Contains(output, "Credential Theft") {
		t.Error("report should contain rule name")
	}
	if !strings.Contains(output, "Steals creds") {
		t.Error("report should contain rule description")
	}
	if !strings.Contains(output, "AWS_SECRET_KEY") {
		t.Error("report should contain matched data")
	}
}

func TestFormatReport_ManyMatchedDataTruncated(t *testing.T) {
	report := &AnalysisReport{
		PackageName: "pkg",
		Version:     "1.0.0",
		RiskScore:   50,
		RiskLevel:   "HIGH",
		Matches: []*RuleMatch{
			{
				Rule:        &Rule{Name: "Many Matches", Severity: SeverityMedium, Description: "desc"},
				MatchedData: []string{"a", "b", "c", "d", "e", "f", "g"},
			},
		},
		Summary: &BehaviorSummary{},
	}

	output := report.FormatReport()
	if !strings.Contains(output, "(7 items matched)") {
		t.Error("report should contain '(7 items matched)' for >5 items")
	}
}

// --- GetMatchesBySeverity tests ---

func TestGetMatchesBySeverity(t *testing.T) {
	report := &AnalysisReport{
		Matches: []*RuleMatch{
			{Rule: &Rule{Severity: SeverityCritical}},
			{Rule: &Rule{Severity: SeverityHigh}},
			{Rule: &Rule{Severity: SeverityMedium}},
			{Rule: &Rule{Severity: SeverityLow}},
		},
	}

	high := report.GetMatchesBySeverity(SeverityHigh)
	if len(high) != 2 {
		t.Errorf("GetMatchesBySeverity(high) = %d matches, want 2", len(high))
	}

	all := report.GetMatchesBySeverity(SeverityInfo)
	if len(all) != 4 {
		t.Errorf("GetMatchesBySeverity(info) = %d matches, want 4", len(all))
	}

	crit := report.GetMatchesBySeverity(SeverityCritical)
	if len(crit) != 1 {
		t.Errorf("GetMatchesBySeverity(critical) = %d matches, want 1", len(crit))
	}
}

// --- HasCritical / HasHigh tests ---

func TestHasCritical(t *testing.T) {
	withCrit := &AnalysisReport{Matches: []*RuleMatch{{Rule: &Rule{Severity: SeverityCritical}}}}
	if !withCrit.HasCritical() {
		t.Error("HasCritical() should be true with critical match")
	}

	withHigh := &AnalysisReport{Matches: []*RuleMatch{{Rule: &Rule{Severity: SeverityHigh}}}}
	if withHigh.HasCritical() {
		t.Error("HasCritical() should be false with only high match")
	}

	empty := &AnalysisReport{}
	if empty.HasCritical() {
		t.Error("HasCritical() should be false with no matches")
	}
}

func TestHasHigh(t *testing.T) {
	withHigh := &AnalysisReport{Matches: []*RuleMatch{{Rule: &Rule{Severity: SeverityHigh}}}}
	if !withHigh.HasHigh() {
		t.Error("HasHigh() should be true with high match")
	}

	withCrit := &AnalysisReport{Matches: []*RuleMatch{{Rule: &Rule{Severity: SeverityCritical}}}}
	if !withCrit.HasHigh() {
		t.Error("HasHigh() should be true with critical match")
	}

	withMed := &AnalysisReport{Matches: []*RuleMatch{{Rule: &Rule{Severity: SeverityMedium}}}}
	if withMed.HasHigh() {
		t.Error("HasHigh() should be false with only medium match")
	}
}

// --- truncate helper test ---

func TestTruncate(t *testing.T) {
	if got := truncate("short", 60); got != "short" {
		t.Errorf("truncate short string: got %q, want %q", got, "short")
	}

	long := strings.Repeat("x", 100)
	got := truncate(long, 60)
	if len(got) != 60 {
		t.Errorf("truncate long string: len = %d, want 60", len(got))
	}
	if !strings.HasSuffix(got, "...") {
		t.Error("truncated string should end with '...'")
	}
}
