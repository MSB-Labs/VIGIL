package analyzer

import (
	"testing"
)

// Helper to create a minimal rule for testing
func makeRule(id string, severity Severity, condType, operator, value string) *Rule {
	return &Rule{
		ID:          id,
		Name:        "Test Rule " + id,
		Description: "Test rule for " + id,
		Severity:    severity,
		Category:    "test",
		Enabled:     true,
		Conditions: []Condition{{
			Type:     condType,
			Operator: operator,
			Value:    value,
		}},
	}
}

func makeRuleWithValues(id string, severity Severity, condType, operator string, values []string) *Rule {
	return &Rule{
		ID:          id,
		Name:        "Test Rule " + id,
		Description: "Test rule for " + id,
		Severity:    severity,
		Category:    "test",
		Enabled:     true,
		Conditions: []Condition{{
			Type:     condType,
			Operator: operator,
			Values:   values,
		}},
	}
}

// --- ParseRules tests ---

func TestParseRules_ValidYAML(t *testing.T) {
	yaml := []byte(`
version: "2.0"
rules:
  - id: test-rule-1
    name: "Test Rule 1"
    description: "First test rule"
    severity: critical
    category: test
    enabled: true
    conditions:
      - type: network
        operator: exists
  - id: test-rule-2
    name: "Test Rule 2"
    description: "Second test rule"
    severity: low
    category: test
    enabled: true
    conditions:
      - type: env
        operator: contains
        value: "SECRET"
`)
	rs, err := ParseRules(yaml)
	if err != nil {
		t.Fatalf("ParseRules returned error: %v", err)
	}
	if rs == nil {
		t.Fatal("ParseRules returned nil RuleSet")
	}
	if rs.Version != "2.0" {
		t.Errorf("Version = %q, want %q", rs.Version, "2.0")
	}
	if len(rs.Rules) != 2 {
		t.Fatalf("len(Rules) = %d, want 2", len(rs.Rules))
	}
	if rs.Rules[0].ID != "test-rule-1" {
		t.Errorf("Rules[0].ID = %q, want %q", rs.Rules[0].ID, "test-rule-1")
	}
	if rs.Rules[0].Severity != SeverityCritical {
		t.Errorf("Rules[0].Severity = %q, want %q", rs.Rules[0].Severity, SeverityCritical)
	}
	if rs.Rules[1].Severity != SeverityLow {
		t.Errorf("Rules[1].Severity = %q, want %q", rs.Rules[1].Severity, SeverityLow)
	}
	if len(rs.Rules[0].Conditions) != 1 {
		t.Errorf("Rules[0] conditions count = %d, want 1", len(rs.Rules[0].Conditions))
	}
	if rs.Rules[0].Conditions[0].Type != "network" {
		t.Errorf("Rules[0].Conditions[0].Type = %q, want %q", rs.Rules[0].Conditions[0].Type, "network")
	}
}

func TestParseRules_InvalidYAML(t *testing.T) {
	_, err := ParseRules([]byte("not: [valid: yaml: {{"))
	if err == nil {
		t.Error("ParseRules should return error for invalid YAML")
	}
}

func TestParseRules_EmptyInput(t *testing.T) {
	rs, err := ParseRules([]byte(""))
	if err != nil {
		t.Fatalf("ParseRules returned error for empty input: %v", err)
	}
	if rs == nil {
		t.Fatal("ParseRules returned nil for empty input")
	}
	if len(rs.Rules) != 0 {
		t.Errorf("len(Rules) = %d, want 0", len(rs.Rules))
	}
}

func TestParseRules_DefaultSeverity(t *testing.T) {
	yaml := []byte(`
version: "1.0"
rules:
  - id: no-severity
    name: "No Severity Rule"
    description: "Test"
    category: test
    enabled: true
    conditions:
      - type: network
        operator: exists
`)
	rs, err := ParseRules(yaml)
	if err != nil {
		t.Fatalf("ParseRules returned error: %v", err)
	}
	if rs.Rules[0].Severity != SeverityMedium {
		t.Errorf("default severity = %q, want %q", rs.Rules[0].Severity, SeverityMedium)
	}
}

func TestLoadDefaultRules(t *testing.T) {
	rs := LoadDefaultRules()
	if rs == nil {
		t.Fatal("LoadDefaultRules returned nil")
	}
	if rs.Version != "1.0" {
		t.Errorf("Version = %q, want %q", rs.Version, "1.0")
	}
	if len(rs.Rules) == 0 {
		t.Fatal("LoadDefaultRules returned 0 rules")
	}
	// Count by severity
	counts := map[Severity]int{}
	for _, r := range rs.Rules {
		counts[r.Severity]++
		if r.ID == "" {
			t.Error("found rule with empty ID")
		}
		if r.Name == "" {
			t.Error("found rule with empty Name")
		}
		if len(r.Conditions) == 0 {
			t.Errorf("rule %s has no conditions", r.ID)
		}
	}
	if counts[SeverityCritical] < 3 {
		t.Errorf("critical rules = %d, want >= 3", counts[SeverityCritical])
	}
	if counts[SeverityHigh] < 5 {
		t.Errorf("high rules = %d, want >= 5", counts[SeverityHigh])
	}
}

// --- SeverityScore tests ---

func TestSeverityScore(t *testing.T) {
	tests := []struct {
		severity Severity
		want     int
	}{
		{SeverityCritical, 100},
		{SeverityHigh, 75},
		{SeverityMedium, 50},
		{SeverityLow, 25},
		{SeverityInfo, 10},
		{Severity("unknown"), 0},
		{Severity(""), 0},
	}

	for _, tt := range tests {
		got := SeverityScore(tt.severity)
		if got != tt.want {
			t.Errorf("SeverityScore(%q) = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

// --- CalculateRiskScore tests ---

func TestCalculateRiskScore_Empty(t *testing.T) {
	score := CalculateRiskScore(nil)
	if score != 0 {
		t.Errorf("CalculateRiskScore(nil) = %d, want 0", score)
	}
	score = CalculateRiskScore([]*RuleMatch{})
	if score != 0 {
		t.Errorf("CalculateRiskScore([]) = %d, want 0", score)
	}
}

func TestCalculateRiskScore_SingleMatch(t *testing.T) {
	tests := []struct {
		severity Severity
		want     int
	}{
		{SeverityCritical, 100},
		{SeverityHigh, 75},
		{SeverityMedium, 50},
		{SeverityLow, 25},
	}

	for _, tt := range tests {
		match := &RuleMatch{Rule: &Rule{Severity: tt.severity}}
		got := CalculateRiskScore([]*RuleMatch{match})
		if got != tt.want {
			t.Errorf("single %s match: score = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

func TestCalculateRiskScore_CapsAt100(t *testing.T) {
	matches := []*RuleMatch{
		{Rule: &Rule{Severity: SeverityHigh}},
		{Rule: &Rule{Severity: SeverityHigh}},
		{Rule: &Rule{Severity: SeverityHigh}},
	}
	got := CalculateRiskScore(matches)
	if got != 100 {
		t.Errorf("3 high matches: score = %d, want 100 (capped)", got)
	}
}

func TestCalculateRiskScore_Accumulates(t *testing.T) {
	matches := []*RuleMatch{
		{Rule: &Rule{Severity: SeverityLow}},
		{Rule: &Rule{Severity: SeverityMedium}},
	}
	got := CalculateRiskScore(matches)
	if got != 75 {
		t.Errorf("low+medium: score = %d, want 75", got)
	}
}

// --- evaluateCondition tests (via RuleSet.Analyze) ---

func TestEvaluateCondition_ExistsOperator(t *testing.T) {
	rs := &RuleSet{Rules: []*Rule{makeRule("exists-net", SeverityMedium, "network", "exists", "")}}

	// Has network calls -> triggers
	matches := rs.Analyze(&BehaviorData{NetworkCalls: []string{"example.com"}})
	if len(matches) != 1 {
		t.Errorf("exists with data: got %d matches, want 1", len(matches))
	}

	// No network calls -> no trigger
	matches = rs.Analyze(&BehaviorData{})
	if len(matches) != 0 {
		t.Errorf("exists without data: got %d matches, want 0", len(matches))
	}
}

func TestEvaluateCondition_ContainsOperator(t *testing.T) {
	rs := &RuleSet{Rules: []*Rule{makeRule("contains-env", SeverityHigh, "env", "contains", "AWS_SECRET")}}

	// Contains substring -> triggers
	matches := rs.Analyze(&BehaviorData{EnvVarsRead: []string{"reading AWS_SECRET_KEY"}})
	if len(matches) != 1 {
		t.Errorf("contains match: got %d matches, want 1", len(matches))
	}

	// No match
	matches = rs.Analyze(&BehaviorData{EnvVarsRead: []string{"PATH"}})
	if len(matches) != 0 {
		t.Errorf("contains no match: got %d matches, want 0", len(matches))
	}

	// Empty data
	matches = rs.Analyze(&BehaviorData{})
	if len(matches) != 0 {
		t.Errorf("contains empty data: got %d matches, want 0", len(matches))
	}
}

func TestEvaluateCondition_ContainsCaseInsensitive(t *testing.T) {
	rs := &RuleSet{Rules: []*Rule{makeRule("case-test", SeverityMedium, "env", "contains", "aws_secret")}}

	matches := rs.Analyze(&BehaviorData{EnvVarsRead: []string{"AWS_SECRET_ACCESS_KEY"}})
	if len(matches) != 1 {
		t.Errorf("case-insensitive contains: got %d matches, want 1", len(matches))
	}
}

func TestEvaluateCondition_MatchesOperator(t *testing.T) {
	rs := &RuleSet{Rules: []*Rule{makeRule("ip-match", SeverityCritical, "network", "matches", `\d+\.\d+\.\d+\.\d+`)}}

	// IP address -> matches
	matches := rs.Analyze(&BehaviorData{NetworkCalls: []string{"http://192.168.1.1/data"}})
	if len(matches) != 1 {
		t.Errorf("regex IP match: got %d matches, want 1", len(matches))
	}

	// No IP -> no match
	matches = rs.Analyze(&BehaviorData{NetworkCalls: []string{"https://example.com"}})
	if len(matches) != 0 {
		t.Errorf("regex no IP: got %d matches, want 0", len(matches))
	}
}

func TestEvaluateCondition_MatchesInvalidRegex(t *testing.T) {
	rs := &RuleSet{Rules: []*Rule{makeRule("bad-regex", SeverityMedium, "network", "matches", "[invalid")}}

	// Should not panic
	matches := rs.Analyze(&BehaviorData{NetworkCalls: []string{"anything"}})
	if len(matches) != 0 {
		t.Errorf("invalid regex: got %d matches, want 0", len(matches))
	}
}

func TestEvaluateCondition_CountGtOperator(t *testing.T) {
	rs := &RuleSet{Rules: []*Rule{makeRule("count-files", SeverityLow, "file_write", "count_gt", "5")}}

	// 6 writes -> triggers
	writes := []string{"a", "b", "c", "d", "e", "f"}
	matches := rs.Analyze(&BehaviorData{FileWrites: writes})
	if len(matches) != 1 {
		t.Errorf("count_gt 6>5: got %d matches, want 1", len(matches))
	}

	// Exactly 5 -> does not trigger
	matches = rs.Analyze(&BehaviorData{FileWrites: writes[:5]})
	if len(matches) != 0 {
		t.Errorf("count_gt 5>5: got %d matches, want 0", len(matches))
	}

	// 0 -> does not trigger
	matches = rs.Analyze(&BehaviorData{})
	if len(matches) != 0 {
		t.Errorf("count_gt 0>5: got %d matches, want 0", len(matches))
	}
}

func TestEvaluateCondition_AllConditionTypes(t *testing.T) {
	tests := []struct {
		condType string
		data     *BehaviorData
	}{
		{"network", &BehaviorData{NetworkCalls: []string{"example.com"}}},
		{"file_read", &BehaviorData{FileReads: []string{"/etc/passwd"}}},
		{"file_write", &BehaviorData{FileWrites: []string{"/tmp/malware"}}},
		{"env", &BehaviorData{EnvVarsRead: []string{"SECRET_KEY"}}},
		{"script", &BehaviorData{InstallScripts: []string{"postinstall.sh"}}},
		{"shell", &BehaviorData{ShellCommands: []string{"rm -rf /"}}},
		{"suspicious", &BehaviorData{SuspiciousFiles: []string{"eval(code)"}}},
	}

	for _, tt := range tests {
		rs := &RuleSet{Rules: []*Rule{makeRule("type-"+tt.condType, SeverityMedium, tt.condType, "exists", "")}}
		matches := rs.Analyze(tt.data)
		if len(matches) != 1 {
			t.Errorf("type %q with matching data: got %d matches, want 1", tt.condType, len(matches))
		}
	}

	// install_hooks type
	rs := &RuleSet{Rules: []*Rule{makeRule("hooks", SeverityHigh, "install_hooks", "exists", "")}}
	matches := rs.Analyze(&BehaviorData{HasInstallHooks: true})
	if len(matches) != 1 {
		t.Errorf("install_hooks=true: got %d matches, want 1", len(matches))
	}
	matches = rs.Analyze(&BehaviorData{HasInstallHooks: false})
	if len(matches) != 0 {
		t.Errorf("install_hooks=false: got %d matches, want 0", len(matches))
	}
}

func TestEvaluateCondition_UnknownType(t *testing.T) {
	rs := &RuleSet{Rules: []*Rule{makeRule("unknown", SeverityMedium, "nonexistent", "exists", "")}}
	matches := rs.Analyze(&BehaviorData{NetworkCalls: []string{"data"}})
	if len(matches) != 0 {
		t.Errorf("unknown type: got %d matches, want 0", len(matches))
	}
}

func TestEvaluateCondition_MultipleValues(t *testing.T) {
	rs := &RuleSet{Rules: []*Rule{
		makeRuleWithValues("multi-val", SeverityHigh, "env", "contains", []string{"AWS_SECRET", "GITHUB_TOKEN", "NPM_TOKEN"}),
	}}

	matches := rs.Analyze(&BehaviorData{EnvVarsRead: []string{"my GITHUB_TOKEN here"}})
	if len(matches) != 1 {
		t.Errorf("multiple values, one matches: got %d matches, want 1", len(matches))
	}
}

func TestEvaluateCondition_ValueAndValuesBothSet(t *testing.T) {
	rule := &Rule{
		ID: "both", Name: "Both", Description: "test", Severity: SeverityMedium,
		Category: "test", Enabled: true,
		Conditions: []Condition{{
			Type: "env", Operator: "contains",
			Value: "ALPHA", Values: []string{"BETA", "GAMMA"},
		}},
	}
	rs := &RuleSet{Rules: []*Rule{rule}}

	// Match on Value
	matches := rs.Analyze(&BehaviorData{EnvVarsRead: []string{"ALPHA_KEY"}})
	if len(matches) != 1 {
		t.Errorf("match on Value: got %d matches, want 1", len(matches))
	}

	// Match on Values
	matches = rs.Analyze(&BehaviorData{EnvVarsRead: []string{"BETA_KEY"}})
	if len(matches) != 1 {
		t.Errorf("match on Values: got %d matches, want 1", len(matches))
	}
}

// --- RuleSet.Analyze logic tests ---

func TestRuleSetAnalyze_MultipleConditionsAND(t *testing.T) {
	rule := &Rule{
		ID: "and-rule", Name: "AND Rule", Description: "test", Severity: SeverityCritical,
		Category: "test", Enabled: true,
		Conditions: []Condition{
			{Type: "network", Operator: "exists"},
			{Type: "env", Operator: "contains", Value: "SECRET"},
		},
	}
	rs := &RuleSet{Rules: []*Rule{rule}}

	// Both met -> triggers
	matches := rs.Analyze(&BehaviorData{
		NetworkCalls: []string{"evil.com"},
		EnvVarsRead:  []string{"SECRET_KEY"},
	})
	if len(matches) != 1 {
		t.Errorf("both conditions met: got %d matches, want 1", len(matches))
	}

	// Only first met -> no trigger
	matches = rs.Analyze(&BehaviorData{
		NetworkCalls: []string{"evil.com"},
	})
	if len(matches) != 0 {
		t.Errorf("only first condition met: got %d matches, want 0", len(matches))
	}

	// Only second met -> no trigger
	matches = rs.Analyze(&BehaviorData{
		EnvVarsRead: []string{"SECRET_KEY"},
	})
	if len(matches) != 0 {
		t.Errorf("only second condition met: got %d matches, want 0", len(matches))
	}
}

func TestRuleSetAnalyze_DisabledRuleSkipped(t *testing.T) {
	rule := makeRule("disabled", SeverityCritical, "network", "exists", "")
	rule.Enabled = false
	rs := &RuleSet{Rules: []*Rule{rule}}

	matches := rs.Analyze(&BehaviorData{NetworkCalls: []string{"evil.com"}})
	if len(matches) != 0 {
		t.Errorf("disabled rule: got %d matches, want 0", len(matches))
	}
}

// --- GetRulesByCategory tests ---

func TestGetRulesByCategory(t *testing.T) {
	rs := LoadDefaultRules()

	network := rs.GetRulesByCategory("network")
	if len(network) == 0 {
		t.Error("GetRulesByCategory(\"network\") returned 0 rules")
	}
	for _, r := range network {
		if r.Category != "network" {
			t.Errorf("expected category network, got %q for rule %s", r.Category, r.ID)
		}
	}

	empty := rs.GetRulesByCategory("nonexistent")
	if len(empty) != 0 {
		t.Errorf("GetRulesByCategory(\"nonexistent\") returned %d rules, want 0", len(empty))
	}
}

// --- GetRulesBySeverity tests ---

func TestGetRulesBySeverity(t *testing.T) {
	rs := LoadDefaultRules()

	critical := rs.GetRulesBySeverity(SeverityCritical)
	for _, r := range critical {
		if r.Severity != SeverityCritical {
			t.Errorf("GetRulesBySeverity(critical) included %s rule %s", r.Severity, r.ID)
		}
	}

	all := rs.GetRulesBySeverity(SeverityInfo)
	if len(all) != len(rs.Rules) {
		t.Errorf("GetRulesBySeverity(info) = %d rules, want %d (all)", len(all), len(rs.Rules))
	}

	high := rs.GetRulesBySeverity(SeverityHigh)
	for _, r := range high {
		if r.Severity != SeverityHigh && r.Severity != SeverityCritical {
			t.Errorf("GetRulesBySeverity(high) included %s rule %s", r.Severity, r.ID)
		}
	}
}
