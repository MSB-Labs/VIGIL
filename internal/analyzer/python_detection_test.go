package analyzer

import (
	"testing"
)

func TestPythonSpecificRules(t *testing.T) {
	// Test that our Python-specific rules are properly loaded
	rules := LoadDefaultRules()
	
	// Check that we have the expected number of Python rules
	pythonRules := rules.GetRulesByCategory("python")
	if len(pythonRules) == 0 {
		t.Error("Expected to find Python-specific rules, but none were found")
	}
	
	// Verify specific Python rules exist
	expectedRules := []string{
		"python-venv-manipulation",
		"python-path-manipulation", 
		"python-dynamic-import",
		"python-package-install-outside-site-packages",
		"python-import-hijacking",
		"python-pip-install-external",
		"python-config-file-modification",
		"python-cryptography-usage",
		"python-debugger-detection",
		"python-registry-access-windows",
		"python-process-injection",
		"python-keyboard-mouse-control",
		"python-system-info-gathering",
		"python-file-encryption",
		"python-memory-operations",
	}
	
	for _, expectedRule := range expectedRules {
		found := false
		for _, rule := range pythonRules {
			if rule.ID == expectedRule {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected Python rule %s not found", expectedRule)
		}
	}
}

func TestPythonBehavioralDetection(t *testing.T) {
	// Test behavioral detection with Python-specific patterns
	rules := LoadDefaultRules()
	
	// Create test data with Python-specific suspicious patterns
	testData := &BehaviorData{
		PackageName: "test-package",
		Version:     "1.0.0",
		Ecosystem:   "pypi",
		SuspiciousFiles: []string{
			"setup.py: sys.path.append('/tmp/malicious')",
			"module.py: __import__('os').system('whoami')",
			"install.py: subprocess.run(['pip', 'install', 'malware'])",
			"config.py: sys.modules['builtins'] = malicious_builtins",
			"utils.py: ctypes.windll.kernel32.CreateProcessA()",
		},
		ShellCommands: []string{
			"pip install requests",
			"python -m pip install --upgrade pip",
		},
		FileWrites: []string{
			"/tmp/malicious_file.py",
			"/home/user/.pythonrc",
		},
	}
	
	// Analyze the test data
	matches := rules.Analyze(testData)
	
	// We should have matches for our suspicious patterns
	if len(matches) == 0 {
		t.Error("Expected behavioral matches for suspicious Python patterns, but found none")
	}
	
	// Check for specific rule matches
	ruleIDs := make(map[string]bool)
	for _, match := range matches {
		ruleIDs[match.Rule.ID] = true
	}
	
	// Verify we caught key suspicious behaviors
	expectedMatches := []string{
		"python-path-manipulation",
		"python-dynamic-import", 
		"python-pip-install-external",
		"python-import-hijacking",
		"python-process-injection",
		"python-package-install-outside-site-packages",
	}
	
	for _, expectedMatch := range expectedMatches {
		if !ruleIDs[expectedMatch] {
			t.Errorf("Expected to match rule %s, but it was not triggered", expectedMatch)
		}
	}
}

func TestPythonRiskScoring(t *testing.T) {
	// Test that Python-specific rules contribute appropriately to risk scoring
	rules := LoadDefaultRules()
	
	// Test data with high-severity Python patterns
	testData := &BehaviorData{
		PackageName: "malicious-package",
		Version:     "1.0.0",
		Ecosystem:   "pypi",
		SuspiciousFiles: []string{
			"injector.py: sys.modules['os'] = malicious_os_module",
			"process.py: ctypes.windll.kernel32.WriteProcessMemory()",
		},
	}
	
	// Analyze and calculate risk score
	matches := rules.Analyze(testData)
	riskScore := CalculateRiskScore(matches)
	
	// Should have a high risk score due to critical/high severity rules
	if riskScore < 75 {
		t.Errorf("Expected high risk score (>=75) for critical Python behaviors, got %d", riskScore)
	}
}

func TestPythonRuleSeverityLevels(t *testing.T) {
	// Test that Python rules have appropriate severity levels
	rules := LoadDefaultRules()
	
	// Check that critical rules exist
	criticalRules := rules.GetRulesBySeverity(SeverityCritical)
	criticalFound := false
	for _, rule := range criticalRules {
		if rule.Category == "python" {
			criticalFound = true
			break
		}
	}
	
	if !criticalFound {
		t.Error("Expected to find critical-severity Python rules")
	}
	
	// Check that high-severity rules exist
	highRules := rules.GetRulesBySeverity(SeverityHigh)
	highFound := false
	for _, rule := range highRules {
		if rule.Category == "python" {
			highFound = true
			break
		}
	}
	
	if !highFound {
		t.Error("Expected to find high-severity Python rules")
	}
}
