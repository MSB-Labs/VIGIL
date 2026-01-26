// Package store handles persistence of behavioral fingerprints
// and package metadata using SQLite.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// Store manages the SQLite database for package fingerprints
type Store struct {
	db     *sql.DB
	dbPath string
}

// BehaviorFingerprint represents the behavioral profile of a package version
type BehaviorFingerprint struct {
	ID              int64     `json:"id"`
	PackageName     string    `json:"package_name"`
	Version         string    `json:"version"`
	Ecosystem       string    `json:"ecosystem"` // npm, pypi, etc.
	AnalyzedAt      time.Time `json:"analyzed_at"`
	NetworkCalls    []string  `json:"network_calls"`    // hosts contacted
	FileReads       []string  `json:"file_reads"`       // paths read
	FileWrites      []string  `json:"file_writes"`      // paths written
	EnvVarsRead     []string  `json:"env_vars_read"`    // env vars accessed
	ShellCommands   []string  `json:"shell_commands"`   // commands executed
	HasInstallHooks bool      `json:"has_install_hooks"`
	DynamicCodeExec bool      `json:"dynamic_code_exec"` // eval, new Function, etc.
	RiskScore       int       `json:"risk_score"`        // 0-100
	Checksum        string    `json:"checksum"`          // for quick diff
}

// New creates a new store, initializing the database if needed
func New(dbPath string) (*Store, error) {
	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	store := &Store{
		db:     db,
		dbPath: dbPath,
	}

	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return store, nil
}

// migrate creates the database schema
func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS fingerprints (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		package_name TEXT NOT NULL,
		version TEXT NOT NULL,
		ecosystem TEXT NOT NULL DEFAULT 'npm',
		analyzed_at DATETIME NOT NULL,
		network_calls TEXT,
		file_reads TEXT,
		file_writes TEXT,
		env_vars_read TEXT,
		shell_commands TEXT,
		has_install_hooks BOOLEAN DEFAULT FALSE,
		dynamic_code_exec BOOLEAN DEFAULT FALSE,
		risk_score INTEGER DEFAULT 0,
		checksum TEXT,
		UNIQUE(package_name, version, ecosystem)
	);

	CREATE INDEX IF NOT EXISTS idx_fingerprints_package
		ON fingerprints(package_name, ecosystem);

	CREATE INDEX IF NOT EXISTS idx_fingerprints_risk
		ON fingerprints(risk_score DESC);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Close closes the database connection
func (s *Store) Close() error {
	return s.db.Close()
}

// SaveFingerprint stores a behavioral fingerprint
func (s *Store) SaveFingerprint(fp *BehaviorFingerprint) error {
	networkCalls, _ := json.Marshal(fp.NetworkCalls)
	fileReads, _ := json.Marshal(fp.FileReads)
	fileWrites, _ := json.Marshal(fp.FileWrites)
	envVarsRead, _ := json.Marshal(fp.EnvVarsRead)
	shellCommands, _ := json.Marshal(fp.ShellCommands)

	query := `
	INSERT INTO fingerprints (
		package_name, version, ecosystem, analyzed_at,
		network_calls, file_reads, file_writes, env_vars_read,
		shell_commands, has_install_hooks, dynamic_code_exec,
		risk_score, checksum
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(package_name, version, ecosystem) DO UPDATE SET
		analyzed_at = excluded.analyzed_at,
		network_calls = excluded.network_calls,
		file_reads = excluded.file_reads,
		file_writes = excluded.file_writes,
		env_vars_read = excluded.env_vars_read,
		shell_commands = excluded.shell_commands,
		has_install_hooks = excluded.has_install_hooks,
		dynamic_code_exec = excluded.dynamic_code_exec,
		risk_score = excluded.risk_score,
		checksum = excluded.checksum
	`

	result, err := s.db.Exec(query,
		fp.PackageName, fp.Version, fp.Ecosystem, fp.AnalyzedAt,
		string(networkCalls), string(fileReads), string(fileWrites),
		string(envVarsRead), string(shellCommands),
		fp.HasInstallHooks, fp.DynamicCodeExec,
		fp.RiskScore, fp.Checksum,
	)
	if err != nil {
		return fmt.Errorf("failed to save fingerprint: %w", err)
	}

	id, _ := result.LastInsertId()
	fp.ID = id
	return nil
}

// GetFingerprint retrieves a fingerprint by package name and version
func (s *Store) GetFingerprint(packageName, version, ecosystem string) (*BehaviorFingerprint, error) {
	query := `
	SELECT id, package_name, version, ecosystem, analyzed_at,
		network_calls, file_reads, file_writes, env_vars_read,
		shell_commands, has_install_hooks, dynamic_code_exec,
		risk_score, checksum
	FROM fingerprints
	WHERE package_name = ? AND version = ? AND ecosystem = ?
	`

	var fp BehaviorFingerprint
	var networkCalls, fileReads, fileWrites, envVarsRead, shellCommands string

	err := s.db.QueryRow(query, packageName, version, ecosystem).Scan(
		&fp.ID, &fp.PackageName, &fp.Version, &fp.Ecosystem, &fp.AnalyzedAt,
		&networkCalls, &fileReads, &fileWrites, &envVarsRead,
		&shellCommands, &fp.HasInstallHooks, &fp.DynamicCodeExec,
		&fp.RiskScore, &fp.Checksum,
	)

	if err == sql.ErrNoRows {
		return nil, nil // not found
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get fingerprint: %w", err)
	}

	// Unmarshal JSON arrays
	json.Unmarshal([]byte(networkCalls), &fp.NetworkCalls)
	json.Unmarshal([]byte(fileReads), &fp.FileReads)
	json.Unmarshal([]byte(fileWrites), &fp.FileWrites)
	json.Unmarshal([]byte(envVarsRead), &fp.EnvVarsRead)
	json.Unmarshal([]byte(shellCommands), &fp.ShellCommands)

	return &fp, nil
}

// HasFingerprint checks if a fingerprint exists for a package version
func (s *Store) HasFingerprint(packageName, version, ecosystem string) (bool, error) {
	query := `SELECT 1 FROM fingerprints WHERE package_name = ? AND version = ? AND ecosystem = ? LIMIT 1`
	var exists int
	err := s.db.QueryRow(query, packageName, version, ecosystem).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetHighRiskPackages returns packages above a risk threshold
func (s *Store) GetHighRiskPackages(minRiskScore int) ([]*BehaviorFingerprint, error) {
	query := `
	SELECT id, package_name, version, ecosystem, analyzed_at,
		network_calls, file_reads, file_writes, env_vars_read,
		shell_commands, has_install_hooks, dynamic_code_exec,
		risk_score, checksum
	FROM fingerprints
	WHERE risk_score >= ?
	ORDER BY risk_score DESC
	`

	rows, err := s.db.Query(query, minRiskScore)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*BehaviorFingerprint
	for rows.Next() {
		var fp BehaviorFingerprint
		var networkCalls, fileReads, fileWrites, envVarsRead, shellCommands string

		err := rows.Scan(
			&fp.ID, &fp.PackageName, &fp.Version, &fp.Ecosystem, &fp.AnalyzedAt,
			&networkCalls, &fileReads, &fileWrites, &envVarsRead,
			&shellCommands, &fp.HasInstallHooks, &fp.DynamicCodeExec,
			&fp.RiskScore, &fp.Checksum,
		)
		if err != nil {
			return nil, err
		}

		json.Unmarshal([]byte(networkCalls), &fp.NetworkCalls)
		json.Unmarshal([]byte(fileReads), &fp.FileReads)
		json.Unmarshal([]byte(fileWrites), &fp.FileWrites)
		json.Unmarshal([]byte(envVarsRead), &fp.EnvVarsRead)
		json.Unmarshal([]byte(shellCommands), &fp.ShellCommands)

		results = append(results, &fp)
	}

	return results, rows.Err()
}

// Stats returns database statistics
type Stats struct {
	TotalPackages   int
	TotalVersions   int
	HighRiskCount   int
	WithInstallHooks int
	LastAnalyzed    time.Time
}

// GetStats returns statistics about the fingerprint database
func (s *Store) GetStats() (*Stats, error) {
	var stats Stats

	// Total unique packages
	s.db.QueryRow(`SELECT COUNT(DISTINCT package_name) FROM fingerprints`).Scan(&stats.TotalPackages)

	// Total versions
	s.db.QueryRow(`SELECT COUNT(*) FROM fingerprints`).Scan(&stats.TotalVersions)

	// High risk (score >= 75)
	s.db.QueryRow(`SELECT COUNT(*) FROM fingerprints WHERE risk_score >= 75`).Scan(&stats.HighRiskCount)

	// With install hooks
	s.db.QueryRow(`SELECT COUNT(*) FROM fingerprints WHERE has_install_hooks = TRUE`).Scan(&stats.WithInstallHooks)

	// Last analyzed
	s.db.QueryRow(`SELECT MAX(analyzed_at) FROM fingerprints`).Scan(&stats.LastAnalyzed)

	return &stats, nil
}

// DefaultDBPath returns the default database path
func DefaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".vigil", "fingerprints.db")
}
