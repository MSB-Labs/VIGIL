package resolver

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/pelletier/go-toml"
	"gopkg.in/yaml.v3"
)

// LockfileType represents the type of lockfile detected
type LockfileType int

const (
	LockfileNone LockfileType = iota
	LockfileYarn
	LockfilePnpm
	LockfileNPM
	LockfilePip
	LockfilePipenv
	LockfilePoetry
	LockfileConda
)

// LockedPackage represents a package with its exact resolved version from a lockfile
type LockedPackage struct {
	Name     string
	Version  string // exact resolved version
	Resolved string // resolved URL (optional)
	Integrity string // integrity hash (optional)
}

// Lockfile holds parsed lockfile data
type Lockfile struct {
	Type     LockfileType
	Packages map[string]LockedPackage // name@constraint -> LockedPackage
}

// DetectLockfile checks for lockfiles in the project directory
// Priority: yarn.lock > pnpm-lock.yaml > package-lock.json > poetry.lock > Pipfile.lock > requirements.txt
func DetectLockfile(projectPath string) (LockfileType, string) {
	// JavaScript/Node.js lockfiles
	yarnLock := filepath.Join(projectPath, "yarn.lock")
	if _, err := os.Stat(yarnLock); err == nil {
		return LockfileYarn, yarnLock
	}

	pnpmLock := filepath.Join(projectPath, "pnpm-lock.yaml")
	if _, err := os.Stat(pnpmLock); err == nil {
		return LockfilePnpm, pnpmLock
	}

	npmLock := filepath.Join(projectPath, "package-lock.json")
	if _, err := os.Stat(npmLock); err == nil {
		return LockfileNPM, npmLock
	}

	// Python lockfiles
	poetryLock := filepath.Join(projectPath, "poetry.lock")
	if _, err := os.Stat(poetryLock); err == nil {
		return LockfilePoetry, poetryLock
	}

	pipenvLock := filepath.Join(projectPath, "Pipfile.lock")
	if _, err := os.Stat(pipenvLock); err == nil {
		return LockfilePipenv, pipenvLock
	}

	// Python requirements files (not technically lockfiles but provide version info)
	requirementsTxt := filepath.Join(projectPath, "requirements.txt")
	if _, err := os.Stat(requirementsTxt); err == nil {
		return LockfilePip, requirementsTxt
	}

	return LockfileNone, ""
}

// ParseLockfile parses the lockfile at the given path
func ParseLockfile(lockfilePath string, lockType LockfileType) (*Lockfile, error) {
	switch lockType {
	case LockfileYarn:
		return parseYarnLock(lockfilePath)
	case LockfilePnpm:
		return parsePnpmLock(lockfilePath)
	case LockfileNPM:
		return parseNPMLock(lockfilePath)
	case LockfilePoetry:
		return parsePoetryLock(lockfilePath)
	case LockfilePipenv:
		return parsePipenvLock(lockfilePath)
	case LockfilePip:
		return parseRequirementsTxt(lockfilePath)
	default:
		return nil, fmt.Errorf("unknown lockfile type")
	}
}

// parseYarnLock parses yarn.lock (supports both v1 and berry/v2+ formats)
func parseYarnLock(lockfilePath string) (*Lockfile, error) {
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read yarn.lock: %w", err)
	}

	content := string(data)
	lockfile := &Lockfile{
		Type:     LockfileYarn,
		Packages: make(map[string]LockedPackage),
	}

	// Check if it's yarn berry (v2+) format (YAML-like with __metadata)
	if strings.Contains(content, "__metadata:") {
		return parseYarnBerryLock(content, lockfile)
	}

	// Parse yarn v1 format
	return parseYarnV1Lock(content, lockfile)
}

// parseYarnV1Lock parses yarn.lock v1 format
func parseYarnV1Lock(content string, lockfile *Lockfile) (*Lockfile, error) {
	// Yarn v1 format:
	// "package@^1.0.0", "package@~1.0.0":
	//   version "1.0.5"
	//   resolved "https://..."
	//   integrity sha512-...

	scanner := bufio.NewScanner(strings.NewReader(content))

	// Regex patterns
	headerRegex := regexp.MustCompile(`^"?([^"]+)"?(?:,\s*"?([^"]+)"?)*:\s*$`)
	versionRegex := regexp.MustCompile(`^\s+version\s+"([^"]+)"`)
	resolvedRegex := regexp.MustCompile(`^\s+resolved\s+"([^"]+)"`)
	integrityRegex := regexp.MustCompile(`^\s+integrity\s+(\S+)`)

	var currentKeys []string
	var currentVersion, currentResolved, currentIntegrity string

	flushEntry := func() {
		if len(currentKeys) > 0 && currentVersion != "" {
			for _, key := range currentKeys {
				name := extractPackageName(key)
				lockfile.Packages[key] = LockedPackage{
					Name:      name,
					Version:   currentVersion,
					Resolved:  currentResolved,
					Integrity: currentIntegrity,
				}
			}
		}
		currentKeys = nil
		currentVersion = ""
		currentResolved = ""
		currentIntegrity = ""
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		// Check for package header
		if matches := headerRegex.FindStringSubmatch(line); matches != nil {
			flushEntry()
			// Parse all package specifiers from the header
			currentKeys = parseYarnV1Header(line)
			continue
		}

		// Parse version
		if matches := versionRegex.FindStringSubmatch(line); matches != nil {
			currentVersion = matches[1]
			continue
		}

		// Parse resolved URL
		if matches := resolvedRegex.FindStringSubmatch(line); matches != nil {
			currentResolved = matches[1]
			continue
		}

		// Parse integrity
		if matches := integrityRegex.FindStringSubmatch(line); matches != nil {
			currentIntegrity = matches[1]
			continue
		}
	}

	// Don't forget the last entry
	flushEntry()

	return lockfile, scanner.Err()
}

// parseYarnV1Header parses the header line of a yarn.lock v1 entry
func parseYarnV1Header(line string) []string {
	// Remove trailing colon
	line = strings.TrimSuffix(line, ":")
	line = strings.TrimSpace(line)

	var keys []string
	// Split by ", " but handle quoted strings
	parts := strings.Split(line, ", ")
	for _, part := range parts {
		part = strings.Trim(part, "\"")
		if part != "" {
			keys = append(keys, part)
		}
	}
	return keys
}

// parseYarnBerryLock parses yarn berry (v2+) format
func parseYarnBerryLock(content string, lockfile *Lockfile) (*Lockfile, error) {
	// Yarn berry format is YAML-like
	// "package@npm:^1.0.0":
	//   version: 1.0.5
	//   resolution: "package@npm:1.0.5"
	//   checksum: ...

	var data map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &data); err != nil {
		return nil, fmt.Errorf("failed to parse yarn.lock (berry): %w", err)
	}

	for key, value := range data {
		// Skip metadata
		if key == "__metadata" {
			continue
		}

		entry, ok := value.(map[string]interface{})
		if !ok {
			continue
		}

		version, _ := entry["version"].(string)
		resolution, _ := entry["resolution"].(string)
		checksum, _ := entry["checksum"].(string)

		if version != "" {
			name := extractPackageName(key)
			lockfile.Packages[key] = LockedPackage{
				Name:      name,
				Version:   version,
				Resolved:  resolution,
				Integrity: checksum,
			}
		}
	}

	return lockfile, nil
}

// parsePnpmLock parses pnpm-lock.yaml
func parsePnpmLock(lockfilePath string) (*Lockfile, error) {
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pnpm-lock.yaml: %w", err)
	}

	lockfile := &Lockfile{
		Type:     LockfilePnpm,
		Packages: make(map[string]LockedPackage),
	}

	var pnpmData map[string]interface{}
	if err := yaml.Unmarshal(data, &pnpmData); err != nil {
		return nil, fmt.Errorf("failed to parse pnpm-lock.yaml: %w", err)
	}

	// pnpm v6+ uses "packages" key
	// pnpm v9+ uses "snapshots" for dependency info and "packages" for metadata
	packages, ok := pnpmData["packages"].(map[string]interface{})
	if !ok {
		// Try older format or empty lockfile
		return lockfile, nil
	}

	for pkgPath, value := range packages {
		entry, ok := value.(map[string]interface{})
		if !ok {
			continue
		}

		// pkgPath format: /package@version or /@scope/package@version
		name, version := parsePnpmPackagePath(pkgPath)
		if name == "" || version == "" {
			continue
		}

		resolution, _ := entry["resolution"].(map[string]interface{})
		integrity := ""
		if resolution != nil {
			integrity, _ = resolution["integrity"].(string)
		}

		// Create entry for name@version lookup
		key := fmt.Sprintf("%s@%s", name, version)
		lockfile.Packages[key] = LockedPackage{
			Name:      name,
			Version:   version,
			Integrity: integrity,
		}
	}

	return lockfile, nil
}

// parsePnpmPackagePath extracts package name and version from pnpm path
// Format: /package@version or /@scope/package@version
func parsePnpmPackagePath(path string) (name, version string) {
	// Remove leading slash
	path = strings.TrimPrefix(path, "/")

	// Handle scoped packages: @scope/package@version
	if strings.HasPrefix(path, "@") {
		// Find the second @ which separates name from version
		idx := strings.LastIndex(path, "@")
		if idx > 0 {
			name = path[:idx]
			version = path[idx+1:]
			// Remove any trailing parenthetical info like (react@18.0.0)
			if parenIdx := strings.Index(version, "("); parenIdx > 0 {
				version = version[:parenIdx]
			}
			return name, version
		}
	} else {
		// Regular package: package@version
		parts := strings.SplitN(path, "@", 2)
		if len(parts) == 2 {
			name = parts[0]
			version = parts[1]
			// Remove any trailing parenthetical info
			if parenIdx := strings.Index(version, "("); parenIdx > 0 {
				version = version[:parenIdx]
			}
			return name, version
		}
	}

	return "", ""
}

// parseNPMLock parses package-lock.json
func parseNPMLock(lockfilePath string) (*Lockfile, error) {
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read package-lock.json: %w", err)
	}

	lockfile := &Lockfile{
		Type:     LockfileNPM,
		Packages: make(map[string]LockedPackage),
	}

	var npmData map[string]interface{}
	if err := json.Unmarshal(data, &npmData); err != nil {
		return nil, fmt.Errorf("failed to parse package-lock.json: %w", err)
	}

	// npm v7+ uses "packages" key with "" as root
	if packages, ok := npmData["packages"].(map[string]interface{}); ok {
		for pkgPath, value := range packages {
			if pkgPath == "" {
				continue // Skip root package
			}

			entry, ok := value.(map[string]interface{})
			if !ok {
				continue
			}

			// pkgPath format: node_modules/package or node_modules/@scope/package
			name := extractNPMPackageName(pkgPath)
			version, _ := entry["version"].(string)
			resolved, _ := entry["resolved"].(string)
			integrity, _ := entry["integrity"].(string)

			if name != "" && version != "" {
				key := fmt.Sprintf("%s@%s", name, version)
				lockfile.Packages[key] = LockedPackage{
					Name:      name,
					Version:   version,
					Resolved:  resolved,
					Integrity: integrity,
				}
			}
		}
	}

	// npm v6 and below uses "dependencies" key
	if deps, ok := npmData["dependencies"].(map[string]interface{}); ok {
		parseNPMDependencies(deps, "", lockfile)
	}

	return lockfile, nil
}

// parseNPMDependencies recursively parses npm v6 dependencies
func parseNPMDependencies(deps map[string]interface{}, prefix string, lockfile *Lockfile) {
	for name, value := range deps {
		entry, ok := value.(map[string]interface{})
		if !ok {
			continue
		}

		version, _ := entry["version"].(string)
		resolved, _ := entry["resolved"].(string)
		integrity, _ := entry["integrity"].(string)

		if version != "" {
			key := fmt.Sprintf("%s@%s", name, version)
			lockfile.Packages[key] = LockedPackage{
				Name:      name,
				Version:   version,
				Resolved:  resolved,
				Integrity: integrity,
			}
		}

		// Recursively parse nested dependencies
		if nested, ok := entry["dependencies"].(map[string]interface{}); ok {
			parseNPMDependencies(nested, name+"/", lockfile)
		}
	}
}

// extractNPMPackageName extracts package name from node_modules path
func extractNPMPackageName(path string) string {
	// Remove node_modules/ prefix (may be nested)
	for strings.Contains(path, "node_modules/") {
		idx := strings.LastIndex(path, "node_modules/")
		path = path[idx+len("node_modules/"):]
	}
	return path
}

// extractPackageName extracts the package name from a version specifier
// e.g., "lodash@^4.17.0" -> "lodash", "@types/node@^14.0.0" -> "@types/node"
func extractPackageName(specifier string) string {
	// Remove npm: prefix if present (yarn berry)
	specifier = strings.TrimPrefix(specifier, "npm:")

	// Handle scoped packages
	if strings.HasPrefix(specifier, "@") {
		// Find the second @ which separates name from version
		rest := specifier[1:]
		idx := strings.Index(rest, "@")
		if idx > 0 {
			return specifier[:idx+1]
		}
		return specifier
	}

	// Regular package
	idx := strings.Index(specifier, "@")
	if idx > 0 {
		return specifier[:idx]
	}
	return specifier
}

// GetLockedVersion returns the locked version for a package, if available
func (l *Lockfile) GetLockedVersion(name, constraint string) (string, bool) {
	if l == nil {
		return "", false
	}

	// Try exact match first
	key := fmt.Sprintf("%s@%s", name, constraint)
	if pkg, ok := l.Packages[key]; ok {
		return pkg.Version, true
	}

	// For yarn berry, try with npm: prefix
	key = fmt.Sprintf("%s@npm:%s", name, constraint)
	if pkg, ok := l.Packages[key]; ok {
		return pkg.Version, true
	}

	// Fallback: search by name only and return first match
	// This handles cases where the constraint format differs
	for k, pkg := range l.Packages {
		if pkg.Name == name {
			return pkg.Version, true
		}
		// Also check the key prefix
		if strings.HasPrefix(k, name+"@") {
			return pkg.Version, true
		}
	}

	return "", false
}

// LockfileTypeName returns a human-readable name for the lockfile type
func LockfileTypeName(t LockfileType) string {
	switch t {
	case LockfileYarn:
		return "yarn.lock"
	case LockfilePnpm:
		return "pnpm-lock.yaml"
	case LockfileNPM:
		return "package-lock.json"
	case LockfilePoetry:
		return "poetry.lock"
	case LockfilePipenv:
		return "Pipfile.lock"
	case LockfilePip:
		return "requirements.txt"
	default:
		return "none"
	}
}

// parsePoetryLock parses poetry.lock
func parsePoetryLock(lockfilePath string) (*Lockfile, error) {
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read poetry.lock: %w", err)
	}

	lockfile := &Lockfile{
		Type:     LockfilePoetry,
		Packages: make(map[string]LockedPackage),
	}

	var poetryData map[string]interface{}
	if err := toml.Unmarshal(data, &poetryData); err != nil {
		return nil, fmt.Errorf("failed to parse poetry.lock: %w", err)
	}

	// Poetry lock format has a "package" array
	if packages, ok := poetryData["package"].([]interface{}); ok {
		for _, pkg := range packages {
			entry, ok := pkg.(map[string]interface{})
			if !ok {
				continue
			}

			name, _ := entry["name"].(string)
			version, _ := entry["version"].(string)
			if name != "" && version != "" {
				key := fmt.Sprintf("%s@%s", name, version)
				lockfile.Packages[key] = LockedPackage{
					Name:    name,
					Version: version,
				}
			}
		}
	}

	return lockfile, nil
}

// parsePipenvLock parses Pipfile.lock
func parsePipenvLock(lockfilePath string) (*Lockfile, error) {
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Pipfile.lock: %w", err)
	}

	lockfile := &Lockfile{
		Type:     LockfilePipenv,
		Packages: make(map[string]LockedPackage),
	}

	var pipenvData map[string]interface{}
	if err := json.Unmarshal(data, &pipenvData); err != nil {
		return nil, fmt.Errorf("failed to parse Pipfile.lock: %w", err)
	}

	// Pipfile.lock has "default" and "develop" sections
	for _, section := range []string{"default", "develop"} {
		if deps, ok := pipenvData[section].(map[string]interface{}); ok {
			for name, value := range deps {
				entry, ok := value.(map[string]interface{})
				if !ok {
					continue
				}

				version, _ := entry["version"].(string)
				if version != "" {
					// Remove the leading == from version
					version = strings.TrimPrefix(version, "==")
					key := fmt.Sprintf("%s@%s", name, version)
					lockfile.Packages[key] = LockedPackage{
						Name:    name,
						Version: version,
					}
				}
			}
		}
	}

	return lockfile, nil
}

// parseRequirementsTxt parses requirements.txt
func parseRequirementsTxt(lockfilePath string) (*Lockfile, error) {
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read requirements.txt: %w", err)
	}

	lockfile := &Lockfile{
		Type:     LockfilePip,
		Packages: make(map[string]LockedPackage),
	}

	content := string(data)
	lines := strings.Split(content, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse package name and version
		parts := strings.Split(line, "==")
		if len(parts) >= 2 {
			name := strings.TrimSpace(parts[0])
			version := strings.TrimSpace(parts[1])
			key := fmt.Sprintf("%s@%s", name, version)
			lockfile.Packages[key] = LockedPackage{
				Name:    name,
				Version: version,
			}
		} else {
			// Package without pinned version
			name := strings.TrimSpace(line)
			key := fmt.Sprintf("%s@latest", name)
			lockfile.Packages[key] = LockedPackage{
				Name:    name,
				Version: "latest",
			}
		}
	}

	return lockfile, nil
}
