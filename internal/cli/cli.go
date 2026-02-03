package cli

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/MSB-Labs/vigil/internal/analyzer"
	"github.com/MSB-Labs/vigil/internal/colorutil"
	"github.com/MSB-Labs/vigil/internal/resolver"
	"github.com/MSB-Labs/vigil/internal/sandbox"
	"github.com/MSB-Labs/vigil/internal/store"
	"github.com/spf13/cobra"
)

const version = "0.1.0"

var (
	includeDevDeps  bool
	maxDepth        int
	dbPath          string
	timeout         int
	analyzeAll      bool
	jsonOutput      bool
	noColor         bool
	parallelWorkers int
	failAbove       int
)

var rootCmd = &cobra.Command{
	Use:   "vigil",
	Short: "VIGIL - Verified Integrity Guard for Imported Libraries",
	Long: `VIGIL - Verified Integrity Guard for Imported Libraries

A dynamic analysis tool that maps dependency behavior through sandboxed
execution, flagging behavioral anomalies in the software supply chain.

VIGIL doesn't just list your dependencies—it runs them in a sandbox to
observe what they actually do: network calls, file access, environment
variable reads, shell commands, and more.

Quick Start:
  vigil build-image              Build the sandbox Docker image (first time)
  vigil scan /path/to/project    Scan a project's dependencies
  vigil analyze lodash           Deep analysis of a single package

Documentation: https://github.com/MSB-Labs/vigil`,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Print the version number of VIGIL.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("VIGIL v%s\n", version)
		fmt.Println("Verified Integrity Guard for Imported Libraries")
		fmt.Println("https://github.com/MSB-Labs/vigil")
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan [path]",
	Short: "Scan a project's dependencies for behavioral anomalies",
	Long: `Scan a project's package.json to resolve all dependencies and check
their behavioral fingerprints against the local database.

This command will:
  - Parse package.json and resolve the full dependency tree
  - Check which packages have already been analyzed
  - Show risk overview for analyzed packages
  - Flag packages with install scripts (postinstall, preinstall)

Use --analyze to automatically analyze all unanalyzed packages.
Use --parallel N to run N analyses concurrently (default 4).

Examples:
  vigil scan                           Scan current directory
  vigil scan /path/to/project          Scan specific project
  vigil scan . --dev                   Include dev dependencies
  vigil scan . --analyze               Scan and analyze all packages
  vigil scan . --analyze --parallel 8  Analyze with 8 concurrent workers
  vigil scan . --json                  Output as JSON`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		path := "."
		if len(args) > 0 {
			path = args[0]
		}
		runScan(path)
	},
}

var statsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show fingerprint database statistics",
	Long: `Display statistics about the local fingerprint database.

Shows:
  - Total packages and versions analyzed
  - Number of high-risk packages detected
  - Packages with install hooks
  - Last analysis timestamp`,
	Run: func(cmd *cobra.Command, args []string) {
		runStats()
	},
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze <package>[@version]",
	Short: "Analyze a single package in the sandbox",
	Long: `Run deep behavioral analysis on a single npm package.

The package will be installed and executed in an isolated Docker container.
VIGIL captures behavior and matches against 14 detection rules covering:
  - Credential exfiltration attempts
  - Suspicious network calls
  - Shell command execution
  - Dynamic code evaluation (eval, Function constructor)
  - Sensitive file access
  - Install hook abuse

The analysis results are saved to the local fingerprint database.

Examples:
  vigil analyze lodash           Analyze latest version
  vigil analyze lodash@4.17.21   Analyze specific version
  vigil analyze @types/node      Analyze scoped package
  vigil analyze express -t 120   Set 120 second timeout
  vigil analyze lodash --json    Output as JSON`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		runAnalyze(args[0])
	},
}

var buildImageCmd = &cobra.Command{
	Use:   "build-image",
	Short: "Build the sandbox Docker image",
	Long: `Build the Docker image used for sandboxed package analysis.

This command must be run before using 'vigil analyze'. The image is based
on Node.js Alpine and includes tools for behavioral analysis.

Requirements:
  - Docker must be installed and running
  - Internet connection (to pull base image)

The image will be tagged as 'vigil-sandbox:latest'.`,
	Run: func(cmd *cobra.Command, args []string) {
		runBuildImage()
	},
}

func runScan(projectPath string) {
	scanStart := time.Now()

	if noColor {
		colorutil.ApplyNoColor()
	}

	if !jsonOutput {
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println("  VIGIL - Verified Integrity Guard for Imported Libraries")
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println()
	}

	// Initialize store
	db, err := store.New(dbPath)
	if err != nil {
		if !jsonOutput {
			fmt.Fprintf(os.Stderr, "Warning: Could not open database: %v\n", err)
			fmt.Fprintf(os.Stderr, "Continuing without cache...\n\n")
		}
		db = nil
	} else {
		defer db.Close()
	}

	// Parse package.json
	if !jsonOutput {
		fmt.Printf("Scanning: %s\n\n", projectPath)
	}

	pkg, err := resolver.ParsePackageJSON(projectPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Auto-include devDeps when no direct dependencies exist
	autoIncludedDevDeps := false
	if len(pkg.Dependencies) == 0 && len(pkg.DevDependencies) > 0 && !includeDevDeps {
		includeDevDeps = true
		autoIncludedDevDeps = true
	}

	// Detect workspaces
	wsInfo, _ := resolver.DetectWorkspaces(projectPath)
	isWorkspace := wsInfo != nil

	if !jsonOutput {
		fmt.Printf("Project: %s\n", pkg.Name)
		fmt.Printf("Version: %s\n", pkg.Version)
		fmt.Printf("Direct dependencies: %d\n", len(pkg.Dependencies))
		fmt.Printf("Dev dependencies: %d\n", len(pkg.DevDependencies))
		if autoIncludedDevDeps {
			fmt.Printf("\n  [i] No direct dependencies found. Auto-including %d dev dependencies.\n", len(pkg.DevDependencies))
		}
		if isWorkspace {
			fmt.Printf("\n  Workspace detected: %d packages\n", len(wsInfo.Packages))
			for _, ws := range wsInfo.Packages {
				name := ws.PackageJSON.Name
				if name == "" {
					name = ws.Path
				}
				fmt.Printf("    - %s (%s)\n", name, ws.Path)
			}
		}
		fmt.Println()
	}

	// Resolve dependency tree
	if !jsonOutput {
		fmt.Println("Resolving dependency tree...")
	}

	treeResolver := resolver.NewTreeResolver(maxDepth)
	var packages []*resolver.ResolvedPackage

	if isWorkspace {
		externalDeps := wsInfo.GetExternalDependencies(includeDevDeps)
		packages, err = treeResolver.ResolveFromDependencies(externalDeps)
	} else {
		packages, err = treeResolver.Resolve(projectPath, includeDevDeps)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving dependencies: %v\n", err)
		os.Exit(1)
	}

	// Check cache status and collect risk data
	type cachedResult struct {
		name      string
		version   string
		riskScore int
	}

	var cached, needsAnalysis int
	var cachedResults []cachedResult

	if db != nil {
		for _, p := range packages {
			exists, _ := db.HasFingerprint(p.Name, p.ResolvedVersion, "npm")
			if exists {
				cached++
				fp, fpErr := db.GetFingerprint(p.Name, p.ResolvedVersion, "npm")
				if fpErr == nil && fp != nil {
					cachedResults = append(cachedResults, cachedResult{
						name:      p.Name,
						version:   p.ResolvedVersion,
						riskScore: fp.RiskScore,
					})
				}
			} else {
				needsAnalysis++
			}
		}
	} else {
		needsAnalysis = len(packages)
	}

	// JSON output path
	if jsonOutput {
		scanJSON := ScanJSON{
			Project:         pkg.Name,
			TotalPackages:   len(packages),
			Analyzed:        cached,
			NeedsAnalysis:   needsAnalysis,
			AutoIncludedDev: autoIncludedDevDeps,
			IsWorkspace:     isWorkspace,
		}

		if isWorkspace {
			for _, ws := range wsInfo.Packages {
				name := ws.PackageJSON.Name
				if name == "" {
					name = ws.Path
				}
				scanJSON.WorkspacePackages = append(scanJSON.WorkspacePackages, name)
			}
		}

		jsonSkipped := treeResolver.GetSkipped()
		for _, s := range jsonSkipped {
			scanJSON.Skipped = append(scanJSON.Skipped, SkippedJSON{
				Name:      s.Name,
				Specifier: s.Specifier,
				Reason:    s.Reason,
			})
		}

		// Risk breakdown from cached results
		for _, cr := range cachedResults {
			switch {
			case cr.riskScore >= 75:
				scanJSON.RiskBreakdown.Critical++
				scanJSON.HighRisk = append(scanJSON.HighRisk, PackageRiskJSON{
					Name: cr.name, Version: cr.version,
					RiskScore: cr.riskScore, RiskLevel: "CRITICAL",
				})
			case cr.riskScore >= 50:
				scanJSON.RiskBreakdown.High++
				scanJSON.HighRisk = append(scanJSON.HighRisk, PackageRiskJSON{
					Name: cr.name, Version: cr.version,
					RiskScore: cr.riskScore, RiskLevel: "HIGH",
				})
			case cr.riskScore >= 25:
				scanJSON.RiskBreakdown.Medium++
			default:
				scanJSON.RiskBreakdown.Low++
			}
		}

		for _, p := range packages {
			if p.HasInstallHooks {
				scanJSON.InstallHooks = append(scanJSON.InstallHooks,
					fmt.Sprintf("%s@%s", p.Name, p.ResolvedVersion))
			}
		}

		outputJSON(scanJSON)
		return
	}

	// Print summary
	treeSummary := treeResolver.GetSummary()
	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Println("  Dependency Summary")
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Printf("  Total packages:      %d\n", treeSummary.TotalPackages)
	fmt.Printf("  Direct dependencies: %d\n", treeSummary.DirectDeps)
	fmt.Printf("  Transitive deps:     %d\n", treeSummary.TransitiveDeps)
	fmt.Printf("  Max depth:           %d\n", treeSummary.MaxDepth)
	fmt.Println()

	// Cache status
	if db != nil {
		fmt.Println("───────────────────────────────────────────────────────────")
		fmt.Println("  Cache Status")
		fmt.Println("───────────────────────────────────────────────────────────")
		fmt.Printf("  Already analyzed:    %d\n", cached)
		fmt.Printf("  Needs analysis:      %d\n", needsAnalysis)
		fmt.Println()
	}

	// Risk overview for already-analyzed packages
	if len(cachedResults) > 0 {
		var cCritical, cHigh, cMedium, cLow int
		var criticalPkgs, highPkgs []string

		for _, cr := range cachedResults {
			switch {
			case cr.riskScore >= 75:
				cCritical++
				criticalPkgs = append(criticalPkgs,
					fmt.Sprintf("%s@%s (score: %d)", cr.name, cr.version, cr.riskScore))
			case cr.riskScore >= 50:
				cHigh++
				highPkgs = append(highPkgs,
					fmt.Sprintf("%s@%s (score: %d)", cr.name, cr.version, cr.riskScore))
			case cr.riskScore >= 25:
				cMedium++
			default:
				cLow++
			}
		}

		fmt.Println("───────────────────────────────────────────────────────────")
		fmt.Println("  Risk Overview (analyzed packages)")
		fmt.Println("───────────────────────────────────────────────────────────")
		colorutil.PrintRiskLevel("CRITICAL", cCritical)
		colorutil.PrintRiskLevel("HIGH", cHigh)
		colorutil.PrintRiskLevel("MEDIUM", cMedium)
		colorutil.PrintRiskLevel("LOW", cLow)

		if len(criticalPkgs) > 0 {
			fmt.Println()
			fmt.Printf("  [!] %s packages:\n", colorutil.ColorizeRiskLevel("CRITICAL"))
			for _, p := range criticalPkgs {
				fmt.Printf("      %s\n", colorutil.ColorizePackageRisk(p, 75))
			}
		}
		if len(highPkgs) > 0 {
			fmt.Println()
			fmt.Printf("  [!] %s risk packages:\n", colorutil.ColorizeRiskLevel("HIGH"))
			for _, p := range highPkgs {
				fmt.Printf("      %s\n", colorutil.ColorizePackageRisk(p, 50))
			}
		}
		fmt.Println()
	}

	// Flag packages with install hooks
	if treeSummary.WithInstallHooks > 0 {
		fmt.Println("───────────────────────────────────────────────────────────")
		fmt.Printf("  ⚠ Packages with install scripts: %d\n", treeSummary.WithInstallHooks)
		fmt.Println("───────────────────────────────────────────────────────────")
		for _, p := range packages {
			if p.HasInstallHooks {
				fmt.Printf("  • %s@%s\n", p.Name, p.ResolvedVersion)
			}
		}
		fmt.Println()
	}

	// Show skipped packages (non-registry specifiers)
	skipped := treeResolver.GetSkipped()
	if len(skipped) > 0 {
		fmt.Println("───────────────────────────────────────────────────────────")
		fmt.Printf("  Skipped (non-registry specifiers): %d\n", len(skipped))
		fmt.Println("───────────────────────────────────────────────────────────")
		for _, s := range skipped {
			fmt.Printf("  - %s: %s\n", s.Name, s.Specifier)
		}
		fmt.Println()
	}

	// Track max risk score from cached results
	maxRisk := 0
	for _, cr := range cachedResults {
		if cr.riskScore > maxRisk {
			maxRisk = cr.riskScore
		}
	}

	// Auto-analyze if requested
	if analyzeAll && needsAnalysis > 0 && db != nil {
		batchMaxRisk := runBatchAnalyze(db, packages, parallelWorkers)
		if batchMaxRisk > maxRisk {
			maxRisk = batchMaxRisk
		}
	}

	elapsed := time.Since(scanStart)
	fmt.Println("═══════════════════════════════════════════════════════════")
	if len(packages) == 0 {
		fmt.Println("  Scan complete. No packages found to analyze.")
	} else if analyzeAll && needsAnalysis > 0 {
		fmt.Printf("  Scan complete. %d packages resolved.\n", len(packages))
	} else if needsAnalysis > 0 {
		fmt.Printf("  Scan complete. %d packages resolved, %d need analysis.\n", len(packages), needsAnalysis)
		fmt.Println("  Run 'vigil scan --analyze' for full analysis.")
	} else {
		fmt.Printf("  Scan complete. All %d packages analyzed.\n", len(packages))
	}
	fmt.Printf("  Duration: %v\n", elapsed.Round(time.Second))
	fmt.Println("═══════════════════════════════════════════════════════════")

	// Check fail-above threshold
	if failAbove >= 0 && maxRisk > failAbove {
		fmt.Printf("\n  [!] FAILED: Max risk score %d exceeds threshold %d\n", maxRisk, failAbove)
		os.Exit(1)
	}
}

// clampWorkers ensures parallel is between 1 and totalJobs.
func clampWorkers(parallel, totalJobs int) int {
	if parallel < 1 {
		parallel = 1
	}
	if parallel > totalJobs {
		parallel = totalJobs
	}
	return parallel
}

func runBatchAnalyze(db *store.Store, packages []*resolver.ResolvedPackage, parallel int) int {
	// Pre-flight checks
	if err := sandbox.CheckDocker(); err != nil {
		fmt.Fprintf(os.Stderr, "\nError: Docker not available for analysis: %v\n", err)
		return 0
	}
	if !sandbox.ImageExists() {
		fmt.Fprintf(os.Stderr, "\nError: Sandbox image not found. Run 'vigil build-image' first.\n")
		return 0
	}

	// Filter to unanalyzed packages
	var toAnalyze []*resolver.ResolvedPackage
	for _, p := range packages {
		exists, _ := db.HasFingerprint(p.Name, p.ResolvedVersion, "npm")
		if !exists {
			toAnalyze = append(toAnalyze, p)
		}
	}

	if len(toAnalyze) == 0 {
		fmt.Println("\n  All packages already analyzed.")
		return 0
	}

	parallel = clampWorkers(parallel, len(toAnalyze))

	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Printf("  Analyzing %d packages (%d workers)...\n", len(toAnalyze), parallel)
	fmt.Println("───────────────────────────────────────────────────────────")

	type analyzeJob struct {
		index int
		pkg   *resolver.ResolvedPackage
	}

	type analyzeResult struct {
		pkg    *resolver.ResolvedPackage
		report *analyzer.AnalysisReport
		err    error
	}

	jobs := make(chan analyzeJob, len(toAnalyze))
	resultsCh := make(chan analyzeResult, len(toAnalyze))

	cfg := &sandbox.Config{
		Timeout: time.Duration(timeout) * time.Second,
	}

	// Spawn worker goroutines
	var wg sync.WaitGroup
	for w := 0; w < parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := analyzer.New()
			sb := sandbox.New(cfg)
			for job := range jobs {
				result, err := sb.AnalyzePackage(job.pkg.Name, job.pkg.ResolvedVersion)
				if err != nil {
					resultsCh <- analyzeResult{pkg: job.pkg, err: err}
					continue
				}
				report := a.AnalyzeResult(result, job.pkg.Name, job.pkg.ResolvedVersion)
				report.Fingerprint.AnalyzedAt = time.Now()
				resultsCh <- analyzeResult{pkg: job.pkg, report: report}
			}
		}()
	}

	// Send all jobs
	for i, pkg := range toAnalyze {
		jobs <- analyzeJob{index: i, pkg: pkg}
	}
	close(jobs)

	// Close results channel once all workers finish
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect results from the main goroutine (serialized DB writes + progress output)
	var allResults []*analyzer.AnalysisReport
	var failed []string
	completed := 0
	total := len(toAnalyze)
	startTime := time.Now()
	maxRisk := 0

	for r := range resultsCh {
		completed++
		elapsed := time.Since(startTime)

		if r.err != nil {
			fmt.Printf("\n  [%d/%d] %s@%s FAILED: %v",
				completed, total, r.pkg.Name, r.pkg.ResolvedVersion, r.err)
			failed = append(failed, fmt.Sprintf("%s@%s", r.pkg.Name, r.pkg.ResolvedVersion))
			continue
		}

		if err := db.SaveFingerprint(r.report.Fingerprint); err != nil {
			fmt.Fprintf(os.Stderr, "\n  (save failed for %s@%s: %v)", r.pkg.Name, r.pkg.ResolvedVersion, err)
		}

		allResults = append(allResults, r.report)

		// Track max risk score
		if r.report.RiskScore > maxRisk {
			maxRisk = r.report.RiskScore
		}

		avgPerPkg := elapsed / time.Duration(completed)
		remaining := avgPerPkg * time.Duration(total-completed)
		fmt.Printf("\n  [%d/%d] %s@%s Risk: %d/100 [%s] (ETA: %v)",
			completed, total, r.pkg.Name, r.pkg.ResolvedVersion,
			r.report.RiskScore, colorutil.ColorizeRiskLevel(r.report.RiskLevel),
			remaining.Round(time.Second))
	}

	totalElapsed := time.Since(startTime)
	printRiskSummary(allResults, failed, totalElapsed)
	return maxRisk
}

func printRiskSummary(results []*analyzer.AnalysisReport, failed []string, elapsed time.Duration) {
	fmt.Println()
	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Println("  Risk Summary")
	fmt.Println("───────────────────────────────────────────────────────────")

	var critical, high, medium, low int
	var criticalPkgs, highPkgs []string

	for _, r := range results {
		switch r.RiskLevel {
		case "CRITICAL":
			critical++
			criticalPkgs = append(criticalPkgs,
				fmt.Sprintf("%s@%s (score: %d)", r.PackageName, r.Version, r.RiskScore))
		case "HIGH":
			high++
			highPkgs = append(highPkgs,
				fmt.Sprintf("%s@%s (score: %d)", r.PackageName, r.Version, r.RiskScore))
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
	}

	fmt.Printf("  Analyzed:  %d\n", len(results))
	colorutil.PrintRiskLevel("CRITICAL", critical)
	colorutil.PrintRiskLevel("HIGH", high)
	colorutil.PrintRiskLevel("MEDIUM", medium)
	colorutil.PrintRiskLevel("LOW", low)
	fmt.Printf("  Failed:    %d\n", len(failed))
	fmt.Printf("  Duration:  %v\n", elapsed.Round(time.Second))

	if len(criticalPkgs) > 0 {
		fmt.Println()
		fmt.Printf("  [!] %s packages:\n", colorutil.ColorizeRiskLevel("CRITICAL"))
		for _, p := range criticalPkgs {
			fmt.Printf("      %s\n", colorutil.ColorizePackageRisk(p, 75))
		}
	}

	if len(highPkgs) > 0 {
		fmt.Println()
		fmt.Printf("  [!] %s risk packages:\n", colorutil.ColorizeRiskLevel("HIGH"))
		for _, p := range highPkgs {
			fmt.Printf("      %s\n", colorutil.ColorizePackageRisk(p, 50))
		}
	}

	if len(failed) > 0 {
		fmt.Println()
		fmt.Println("  [*] Failed to analyze:")
		for _, p := range failed {
			fmt.Printf("      %s\n", p)
		}
	}

	fmt.Println()
}

func runStats() {
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("  VIGIL - Fingerprint Database Statistics")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()

	db, err := store.New(dbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Could not open database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	stats, err := db.GetStats()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Could not get stats: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("  Database path:       %s\n", dbPath)
	fmt.Printf("  Total packages:      %d\n", stats.TotalPackages)
	fmt.Printf("  Total versions:      %d\n", stats.TotalVersions)
	fmt.Printf("  High risk (>=75):    %d\n", stats.HighRiskCount)
	fmt.Printf("  With install hooks:  %d\n", stats.WithInstallHooks)
	if !stats.LastAnalyzed.IsZero() {
		fmt.Printf("  Last analyzed:       %s\n", stats.LastAnalyzed.Format("2006-01-02 15:04:05"))
	}
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
}

func runAnalyze(packageArg string) {
	// Parse package@version
	packageName, packageVersion := parsePackageArg(packageArg)

	// Apply no-color flag
	if noColor {
		colorutil.ApplyNoColor()
	}

	if !jsonOutput {
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println("  VIGIL - Package Behavioral Analysis")
		fmt.Println("═══════════════════════════════════════════════════════════")
		fmt.Println()
		fmt.Printf("Package:  %s\n", packageName)
		fmt.Printf("Version:  %s\n", packageVersion)
		fmt.Println()
	}

	// Check Docker
	if err := sandbox.CheckDocker(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Please ensure Docker is installed and running.\n")
		os.Exit(1)
	}

	// Check sandbox image
	if !sandbox.ImageExists() {
		fmt.Fprintf(os.Stderr, "Error: Sandbox image not found.\n")
		fmt.Fprintf(os.Stderr, "Run 'vigil build-image' first to build the sandbox.\n")
		os.Exit(1)
	}

	// Initialize store
	db, err := store.New(dbPath)
	if err != nil {
		if !jsonOutput {
			fmt.Fprintf(os.Stderr, "Warning: Could not open database: %v\n", err)
		}
		db = nil
	} else {
		defer db.Close()
	}

	// Check cache
	if db != nil && !jsonOutput {
		exists, _ := db.HasFingerprint(packageName, packageVersion, "npm")
		if exists {
			fmt.Println("Note: Package already analyzed. Re-analyzing...")
		}
	}

	// Run sandbox
	if !jsonOutput {
		fmt.Println("───────────────────────────────────────────────────────────")
		fmt.Println("  Starting sandbox analysis...")
		fmt.Println("───────────────────────────────────────────────────────────")
	}

	cfg := &sandbox.Config{
		Timeout: time.Duration(timeout) * time.Second,
	}
	sb := sandbox.New(cfg)

	result, err := sb.AnalyzePackage(packageName, packageVersion)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during analysis: %v\n", err)
		os.Exit(1)
	}

	// Run through analyzer engine (rule matching + risk scoring)
	a := analyzer.New()
	report := a.AnalyzeResult(result, packageName, packageVersion)

	// JSON output path
	if jsonOutput {
		out := AnalyzeJSON{
			Package:   packageName,
			Version:   packageVersion,
			RiskScore: report.RiskScore,
			RiskLevel: report.RiskLevel,
			Summary:   report.Summary,
			Duration:  result.Duration.Round(time.Millisecond).String(),
		}
		for _, m := range report.Matches {
			out.Matches = append(out.Matches, RuleMatchJSON{
				RuleID:      m.Rule.ID,
				Name:        m.Rule.Name,
				Severity:    string(m.Rule.Severity),
				Category:    m.Rule.Category,
				Description: m.Rule.Description,
				MatchedData: m.MatchedData,
			})
		}
		outputJSON(out)

		// Still save to DB
		if db != nil {
			report.Fingerprint.AnalyzedAt = time.Now()
			db.SaveFingerprint(report.Fingerprint)
		}
		return
	}

	// Display formatted results
	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Println("  Analysis Results")
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Printf("  Duration:            %v\n", result.Duration.Round(time.Millisecond))
	fmt.Printf("  Exit code:           %d\n", result.ExitCode)
	if result.Error != nil {
		fmt.Printf("  Error:               %v\n", result.Error)
	}
	fmt.Println()

	// Display analyzer report
	fmt.Println("───────────────────────────────────────────────────────────")
	fmt.Print(report.FormatReport())
	fmt.Println("───────────────────────────────────────────────────────────")

	// Save fingerprint from analyzer
	if db != nil {
		report.Fingerprint.AnalyzedAt = time.Now()
		if err := db.SaveFingerprint(report.Fingerprint); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not save fingerprint: %v\n", err)
		} else {
			fmt.Println("  Fingerprint saved to database.")
		}
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
}

func runBuildImage() {
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("  VIGIL - Building Sandbox Image")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println()

	// Check Docker
	if err := sandbox.CheckDocker(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		fmt.Fprintf(os.Stderr, "Please ensure Docker is installed and running.\n")
		os.Exit(1)
	}

	fmt.Println("Building sandbox image...")
	fmt.Println()

	if err := sandbox.BuildImageFromDefault(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("Sandbox image built successfully!")
	fmt.Println("  Image: vigil-sandbox:latest")
	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════")
}

func parsePackageArg(arg string) (name, version string) {
	// Handle scoped packages like @types/node@1.0.0
	if strings.HasPrefix(arg, "@") {
		// Scoped package
		parts := strings.SplitN(arg[1:], "@", 2)
		if len(parts) == 2 {
			return "@" + parts[0], parts[1]
		}
		return arg, "latest"
	}

	// Regular package
	parts := strings.SplitN(arg, "@", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return arg, "latest"
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVar(&dbPath, "db", store.DefaultDBPath(), "Path to fingerprint database")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")

	// Scan flags
	scanCmd.Flags().BoolVar(&includeDevDeps, "dev", false, "Include dev dependencies")
	scanCmd.Flags().IntVar(&maxDepth, "depth", 5, "Maximum dependency tree depth")
	scanCmd.Flags().BoolVar(&analyzeAll, "analyze", false, "Analyze all unanalyzed packages")
	scanCmd.Flags().IntVar(&timeout, "timeout", 60, "Analysis timeout per package in seconds")
	scanCmd.Flags().IntVar(&parallelWorkers, "parallel", 4, "Number of packages to analyze concurrently (high values need more Docker resources)")
	scanCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	scanCmd.Flags().IntVar(&failAbove, "fail-above", -1, "Exit with code 1 if any package exceeds this risk score (disabled by default)")

	// Analyze flags
	analyzeCmd.Flags().IntVarP(&timeout, "timeout", "t", 60, "Analysis timeout in seconds")
	analyzeCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")

	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(statsCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(buildImageCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
