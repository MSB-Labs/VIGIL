package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/MSB-Labs/vigil/internal/analyzer"
)

// AnalyzeJSON is the JSON output for the analyze command
type AnalyzeJSON struct {
	Package   string                   `json:"package"`
	Version   string                   `json:"version"`
	RiskScore int                      `json:"risk_score"`
	RiskLevel string                   `json:"risk_level"`
	Summary   *analyzer.BehaviorSummary `json:"summary"`
	Matches   []RuleMatchJSON          `json:"matches"`
	Duration  string                   `json:"duration"`
}

// RuleMatchJSON is a JSON-friendly rule match
type RuleMatchJSON struct {
	RuleID      string   `json:"rule_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	MatchedData []string `json:"matched_data,omitempty"`
}

// ScanJSON is the JSON output for the scan command
type ScanJSON struct {
	Project       string            `json:"project"`
	TotalPackages int               `json:"total_packages"`
	Analyzed      int               `json:"analyzed"`
	NeedsAnalysis int               `json:"needs_analysis"`
	RiskBreakdown RiskBreakdownJSON `json:"risk_breakdown"`
	HighRisk      []PackageRiskJSON `json:"high_risk,omitempty"`
	InstallHooks  []string          `json:"install_hooks,omitempty"`
}

// RiskBreakdownJSON shows the risk distribution
type RiskBreakdownJSON struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// PackageRiskJSON represents a package with its risk data
type PackageRiskJSON struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	RiskScore int    `json:"risk_score"`
	RiskLevel string `json:"risk_level"`
}

func outputJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
}
