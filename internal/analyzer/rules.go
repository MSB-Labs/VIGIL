package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Severity levels for rules
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Rule defines a detection rule
type Rule struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Severity    Severity `yaml:"severity"`
	Category    string   `yaml:"category"`
	Enabled     bool     `yaml:"enabled"`
	Conditions  []Condition `yaml:"conditions"`
	Tags        []string `yaml:"tags"`
}

// Condition defines what triggers a rule
type Condition struct {
	Type     string   `yaml:"type"`     // "network", "file", "env", "script", "pattern"
	Operator string   `yaml:"operator"` // "contains", "matches", "exists", "count_gt"
	Value    string   `yaml:"value"`    // Pattern or threshold
	Values   []string `yaml:"values"`   // Multiple patterns (OR logic)
}

// RuleSet holds all loaded rules
type RuleSet struct {
	Rules   []*Rule
	Version string
}

// RuleMatch represents a triggered rule
type RuleMatch struct {
	Rule        *Rule
	Details     string
	MatchedData []string
}

// BehaviorData represents the behavioral data to analyze
type BehaviorData struct {
	PackageName     string
	Version         string
	NetworkCalls    []string
	FileReads       []string
	FileWrites      []string
	EnvVarsRead     []string
	ShellCommands   []string
	SuspiciousFiles []string
	HasInstallHooks bool
	InstallScripts  []string
}

// LoadRulesFromFile loads rules from a YAML file
func LoadRulesFromFile(path string) (*RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules file: %w", err)
	}

	return ParseRules(data)
}

// ParseRules parses YAML rule definitions
func ParseRules(data []byte) (*RuleSet, error) {
	var config struct {
		Version string  `yaml:"version"`
		Rules   []*Rule `yaml:"rules"`
	}

	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse rules: %w", err)
	}

	// Set defaults
	for _, rule := range config.Rules {
		if rule.Severity == "" {
			rule.Severity = SeverityMedium
		}
		// Enable by default if not specified
		if !rule.Enabled {
			rule.Enabled = true
		}
	}

	return &RuleSet{
		Rules:   config.Rules,
		Version: config.Version,
	}, nil
}

// LoadDefaultRules returns the built-in detection rules
func LoadDefaultRules() *RuleSet {
	rules, _ := ParseRules([]byte(DefaultRulesYAML))
	return rules
}

// Analyze checks behavioral data against all rules
func (rs *RuleSet) Analyze(data *BehaviorData) []*RuleMatch {
	var matches []*RuleMatch

	for _, rule := range rs.Rules {
		if !rule.Enabled {
			continue
		}

		if match := rs.checkRule(rule, data); match != nil {
			matches = append(matches, match)
		}
	}

	return matches
}

// checkRule evaluates a single rule against behavior data
func (rs *RuleSet) checkRule(rule *Rule, data *BehaviorData) *RuleMatch {
	var matchedDetails []string
	allConditionsMet := true

	for _, cond := range rule.Conditions {
		met, details := rs.evaluateCondition(cond, data)
		if !met {
			allConditionsMet = false
			break
		}
		matchedDetails = append(matchedDetails, details...)
	}

	if !allConditionsMet || len(matchedDetails) == 0 {
		return nil
	}

	return &RuleMatch{
		Rule:        rule,
		Details:     rule.Description,
		MatchedData: matchedDetails,
	}
}

// evaluateCondition checks a single condition
func (rs *RuleSet) evaluateCondition(cond Condition, data *BehaviorData) (bool, []string) {
	var targetData []string
	var matched []string

	// Select data based on condition type
	switch cond.Type {
	case "network":
		targetData = data.NetworkCalls
	case "file_read":
		targetData = data.FileReads
	case "file_write":
		targetData = data.FileWrites
	case "env":
		targetData = data.EnvVarsRead
	case "script":
		targetData = data.InstallScripts
	case "shell":
		targetData = data.ShellCommands
	case "suspicious":
		targetData = data.SuspiciousFiles
	case "install_hooks":
		if data.HasInstallHooks {
			return true, []string{"has install hooks"}
		}
		return false, nil
	default:
		return false, nil
	}

	// Get patterns to match
	patterns := cond.Values
	if cond.Value != "" {
		patterns = append(patterns, cond.Value)
	}

	// Evaluate based on operator
	switch cond.Operator {
	case "exists":
		if len(targetData) > 0 {
			return true, targetData
		}
		return false, nil

	case "contains":
		for _, item := range targetData {
			for _, pattern := range patterns {
				if strings.Contains(strings.ToLower(item), strings.ToLower(pattern)) {
					matched = append(matched, item)
				}
			}
		}

	case "matches":
		for _, item := range targetData {
			for _, pattern := range patterns {
				if re, err := regexp.Compile(pattern); err == nil {
					if re.MatchString(item) {
						matched = append(matched, item)
					}
				}
			}
		}

	case "count_gt":
		// Value should be a number string
		var threshold int
		fmt.Sscanf(cond.Value, "%d", &threshold)
		if len(targetData) > threshold {
			return true, targetData
		}
		return false, nil
	}

	return len(matched) > 0, matched
}

// GetRulesByCategory returns rules filtered by category
func (rs *RuleSet) GetRulesByCategory(category string) []*Rule {
	var filtered []*Rule
	for _, rule := range rs.Rules {
		if rule.Category == category {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

// GetRulesBySeverity returns rules at or above a severity level
func (rs *RuleSet) GetRulesBySeverity(minSeverity Severity) []*Rule {
	severityOrder := map[Severity]int{
		SeverityCritical: 4,
		SeverityHigh:     3,
		SeverityMedium:   2,
		SeverityLow:      1,
		SeverityInfo:     0,
	}

	minLevel := severityOrder[minSeverity]
	var filtered []*Rule

	for _, rule := range rs.Rules {
		if severityOrder[rule.Severity] >= minLevel {
			filtered = append(filtered, rule)
		}
	}
	return filtered
}

// SeverityScore returns numeric score for severity
func SeverityScore(s Severity) int {
	switch s {
	case SeverityCritical:
		return 100
	case SeverityHigh:
		return 75
	case SeverityMedium:
		return 50
	case SeverityLow:
		return 25
	case SeverityInfo:
		return 10
	default:
		return 0
	}
}

// CalculateRiskScore computes overall risk from matches
func CalculateRiskScore(matches []*RuleMatch) int {
	if len(matches) == 0 {
		return 0
	}

	score := 0
	for _, match := range matches {
		score += SeverityScore(match.Rule.Severity)
	}

	// Cap at 100
	if score > 100 {
		score = 100
	}

	return score
}

// DefaultRulesDir returns the default directory for custom rules
func DefaultRulesDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".vigil", "rules")
}
