// Package analyzer processes collected behavioral data,
// compares against baselines, and generates risk reports.
package analyzer

import (
	"fmt"
	"sort"
	"strings"

	"github.com/MSB-Labs/vigil/internal/colorutil"
	"github.com/MSB-Labs/vigil/internal/sandbox"
	"github.com/MSB-Labs/vigil/internal/store"
)

// Analyzer processes behavioral data and detects anomalies
type Analyzer struct {
	rules *RuleSet
}

// AnalysisReport contains the full analysis results
type AnalysisReport struct {
	PackageName string
	Version     string
	RiskScore   int
	RiskLevel   string
	Matches     []*RuleMatch
	Summary     *BehaviorSummary
	Fingerprint *store.BehaviorFingerprint
}

// BehaviorSummary provides a quick overview of behaviors
type BehaviorSummary struct {
	HasInstallScripts   bool
	HasNetworkActivity  bool
	HasSuspiciousCode   bool
	HasFileOperations   bool
	HasEnvAccess        bool
	TotalFilesInstalled int
}

// New creates a new analyzer with default rules
func New() *Analyzer {
	return &Analyzer{
		rules: LoadDefaultRules(),
	}
}

// NewWithRules creates an analyzer with custom rules
func NewWithRules(rules *RuleSet) *Analyzer {
	return &Analyzer{
		rules: rules,
	}
}

// AnalyzeResult processes sandbox execution results
func (a *Analyzer) AnalyzeResult(result *sandbox.ExecutionResult, packageName, version string) *AnalysisReport {
	return a.AnalyzeResultWithEcosystem(result, packageName, version, "npm")
}

// AnalyzeResultWithEcosystem processes sandbox execution results with ecosystem info
func (a *Analyzer) AnalyzeResultWithEcosystem(result *sandbox.ExecutionResult, packageName, version, ecosystem string) *AnalysisReport {
	// Flatten SuspiciousFiles map into a single slice for rule matching
	var suspiciousFiles []string
	for _, files := range result.SuspiciousFiles {
		suspiciousFiles = append(suspiciousFiles, files...)
	}

	// Collect env-access files from categorized findings
	var envVars []string
	if files, ok := result.SuspiciousFiles["env_access"]; ok {
		envVars = files
	}

	// Convert sandbox result to behavior data
	data := &BehaviorData{
		PackageName:     packageName,
		Version:         version,
		Ecosystem:       ecosystem,
		NetworkCalls:    result.NetworkCalls,
		FileWrites:      result.FilesWritten,
		EnvVarsRead:     envVars,
		ShellCommands:   result.Commands,
		SuspiciousFiles: suspiciousFiles,
		HasInstallHooks: len(result.Commands) > 0,
		InstallScripts:  result.Commands,
	}

	return a.Analyze(data)
}

// Analyze processes behavior data against rules
func (a *Analyzer) Analyze(data *BehaviorData) *AnalysisReport {
	// Run rule matching
	matches := a.rules.Analyze(data)

	// Sort matches by severity
	sort.Slice(matches, func(i, j int) bool {
		return SeverityScore(matches[i].Rule.Severity) > SeverityScore(matches[j].Rule.Severity)
	})

	// Calculate risk score
	riskScore := CalculateRiskScore(matches)

	// Determine risk level
	riskLevel := "LOW"
	if riskScore >= 75 {
		riskLevel = "CRITICAL"
	} else if riskScore >= 50 {
		riskLevel = "HIGH"
	} else if riskScore >= 25 {
		riskLevel = "MEDIUM"
	}

	// Build summary
	summary := &BehaviorSummary{
		HasInstallScripts:   data.HasInstallHooks,
		HasNetworkActivity:  len(data.NetworkCalls) > 0,
		HasSuspiciousCode:   len(data.SuspiciousFiles) > 0,
		HasFileOperations:   len(data.FileWrites) > 0,
		HasEnvAccess:        len(data.EnvVarsRead) > 0,
		TotalFilesInstalled: len(data.FileWrites),
	}

	// Create fingerprint for storage
	fingerprint := &store.BehaviorFingerprint{
		PackageName:     data.PackageName,
		Version:         data.Version,
		Ecosystem:       data.Ecosystem,
		NetworkCalls:    data.NetworkCalls,
		FileWrites:      data.FileWrites,
		EnvVarsRead:     data.EnvVarsRead,
		ShellCommands:   data.ShellCommands,
		HasInstallHooks: data.HasInstallHooks,
		DynamicCodeExec: len(data.SuspiciousFiles) > 0,
		RiskScore:       riskScore,
	}

	return &AnalysisReport{
		PackageName: data.PackageName,
		Version:     data.Version,
		RiskScore:   riskScore,
		RiskLevel:   riskLevel,
		Matches:     matches,
		Summary:     summary,
		Fingerprint: fingerprint,
	}
}

// FormatReport returns a human-readable report
func (r *AnalysisReport) FormatReport() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Package: %s@%s\n", r.PackageName, r.Version))
	sb.WriteString(fmt.Sprintf("Risk Score: %d/100 [%s]\n\n", r.RiskScore,
		colorutil.ColorizeRiskLevel(r.RiskLevel)))

	// Summary
	sb.WriteString("Behavior Summary:\n")
	sb.WriteString(fmt.Sprintf("  Install Scripts:    %s\n", boolToCheck(r.Summary.HasInstallScripts)))
	sb.WriteString(fmt.Sprintf("  Network Activity:   %s\n", boolToCheck(r.Summary.HasNetworkActivity)))
	sb.WriteString(fmt.Sprintf("  Suspicious Code:    %s\n", boolToCheck(r.Summary.HasSuspiciousCode)))
	sb.WriteString(fmt.Sprintf("  File Operations:    %s\n", boolToCheck(r.Summary.HasFileOperations)))
	sb.WriteString(fmt.Sprintf("  Environment Access: %s\n", boolToCheck(r.Summary.HasEnvAccess)))
	sb.WriteString(fmt.Sprintf("  Files Installed:    %d\n\n", r.Summary.TotalFilesInstalled))

	// Matched rules
	if len(r.Matches) > 0 {
		sb.WriteString("Triggered Rules:\n")
		for _, match := range r.Matches {
			icon := severityIcon(match.Rule.Severity)
			sb.WriteString(fmt.Sprintf("  %s [%s] %s\n", icon,
				colorutil.ColorizeSeverity(string(match.Rule.Severity)), match.Rule.Name))
			sb.WriteString(fmt.Sprintf("     %s\n", match.Rule.Description))
			if len(match.MatchedData) > 0 && len(match.MatchedData) <= 5 {
				for _, data := range match.MatchedData {
					sb.WriteString(fmt.Sprintf("     - %s\n", truncate(data, 60)))
				}
			} else if len(match.MatchedData) > 5 {
				sb.WriteString(fmt.Sprintf("     (%d items matched)\n", len(match.MatchedData)))
			}
		}
	} else {
		sb.WriteString("No rules triggered.\n")
	}

	return sb.String()
}

// GetMatchesBySeverity returns matches filtered by minimum severity
func (r *AnalysisReport) GetMatchesBySeverity(minSeverity Severity) []*RuleMatch {
	minScore := SeverityScore(minSeverity)
	var filtered []*RuleMatch
	for _, match := range r.Matches {
		if SeverityScore(match.Rule.Severity) >= minScore {
			filtered = append(filtered, match)
		}
	}
	return filtered
}

// HasCritical returns true if any critical rules were triggered
func (r *AnalysisReport) HasCritical() bool {
	for _, match := range r.Matches {
		if match.Rule.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

// HasHigh returns true if any high severity rules were triggered
func (r *AnalysisReport) HasHigh() bool {
	for _, match := range r.Matches {
		if match.Rule.Severity == SeverityHigh || match.Rule.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

func boolToCheck(b bool) string {
	if b {
		return "YES"
	}
	return "no"
}

func severityIcon(s Severity) string {
	switch s {
	case SeverityCritical:
		return "[!]"
	case SeverityHigh:
		return "[!]"
	case SeverityMedium:
		return "[*]"
	case SeverityLow:
		return "[-]"
	default:
		return "[i]"
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
