package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/MSB-Labs/vigil/internal/analyzer"
)

// AnalyzeJSON is the JSON output for the analyze command
type AnalyzeJSON struct {
	Package   string                    `json:"package"`
	Version   string                    `json:"version"`
	RiskScore int                       `json:"risk_score"`
	RiskLevel string                    `json:"risk_level"`
	Summary   *analyzer.BehaviorSummary `json:"summary"`
	Matches   []RuleMatchJSON           `json:"matches"`
	Duration  string                    `json:"duration"`
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
	Project           string            `json:"project"`
	IsWorkspace       bool              `json:"is_workspace,omitempty"`
	WorkspacePackages []string          `json:"workspace_packages,omitempty"`
	AutoIncludedDev   bool              `json:"auto_included_dev,omitempty"`
	TotalPackages     int               `json:"total_packages"`
	Analyzed          int               `json:"analyzed"`
	NeedsAnalysis     int               `json:"needs_analysis"`
	RiskBreakdown     RiskBreakdownJSON `json:"risk_breakdown"`
	HighRisk          []PackageRiskJSON `json:"high_risk,omitempty"`
	InstallHooks      []string          `json:"install_hooks,omitempty"`
	Skipped           []SkippedJSON     `json:"skipped,omitempty"`
}

// SkippedJSON represents a skipped dependency in JSON output
type SkippedJSON struct {
	Name      string `json:"name"`
	Specifier string `json:"specifier"`
	Reason    string `json:"reason"`
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
