# VIGIL

**Verified Integrity Guard for Imported Libraries**

A dynamic analysis tool that maps dependency behavior through sandboxed execution, flagging behavioral anomalies in the software supply chain.

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/MSB-Labs/vigil/actions/workflows/ci.yml/badge.svg)](https://github.com/MSB-Labs/vigil/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/MSB-Labs/vigil?include_prereleases)](https://github.com/MSB-Labs/vigil/releases)

## The Problem

The software supply chain is vulnerable. Attacks like Log4Shell have shown that developers don't know the actual risk of their deep dependencies. Current SCA (Software Composition Analysis) tools are static list-checkers that only match known CVEs.

**What's missing?** Behavioral trust for open-source packages.

## The Solution

VIGIL doesn't just list your dependencies—it **runs them in a sandbox** to observe what they actually do:

- Network calls (DNS lookups, HTTP requests)
- File system access (reads, writes, sensitive paths)
- Environment variable access (credentials, secrets)
- Shell command execution
- Dynamic code evaluation (eval, Function constructor)

If a "string formatting" library suddenly tries to read your AWS credentials, VIGIL flags it.

## Features

- **Dependency Resolution** - Parse `package.json` and resolve full dependency trees
- **Sandboxed Execution** - Docker-based isolation for safe package analysis
- **Behavioral Fingerprinting** - Capture and store behavioral profiles
- **Rule-Based Detection** - YAML-configurable detection rules with severity levels
- **Risk Scoring** - Quantified risk assessment (0-100)
- **Local Database** - SQLite storage for analyzed packages (no cloud dependency)

## Installation

### Prerequisites

- Docker (required for sandbox analysis)

### Option 1: Download Binary (Recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/MSB-Labs/vigil/releases).

**Linux/macOS:**
```bash
# Download (replace VERSION and PLATFORM)
curl -LO https://github.com/MSB-Labs/vigil/releases/latest/download/vigil-linux-amd64

# Make executable
chmod +x vigil-linux-amd64

# Move to PATH
sudo mv vigil-linux-amd64 /usr/local/bin/vigil

# Verify
vigil version
```

**Windows:**
1. Download `vigil-windows-amd64.exe` from [Releases](https://github.com/MSB-Labs/vigil/releases)
2. Rename to `vigil.exe`
3. Add to your PATH or run directly

### Option 2: Go Install

If you have Go 1.21+ installed:

```bash
go install github.com/MSB-Labs/vigil/cmd/vigil@latest
```

### Option 3: Build from Source

```bash
git clone https://github.com/MSB-Labs/vigil.git
cd vigil
go mod tidy
go build -o vigil ./cmd/vigil
```

### Setup: Build the Sandbox Image

After installing, build the Docker sandbox image (required once):

```bash
vigil build-image
```

This creates a secure Docker container for package analysis.

## Quick Start

### 1. Scan a Project

Resolve and analyze a project's dependencies:

```bash
vigil scan /path/to/your/project
```

Output:
```
═══════════════════════════════════════════════════════════
  VIGIL - Verified Integrity Guard for Imported Libraries
═══════════════════════════════════════════════════════════

Scanning: /path/to/your/project

Project: my-app
Version: 1.0.0
Direct dependencies: 15
Dev dependencies: 23

Resolving dependency tree...

───────────────────────────────────────────────────────────
  Dependency Summary
───────────────────────────────────────────────────────────
  Total packages:      247
  Direct dependencies: 15
  Transitive deps:     232
  Max depth:           5

───────────────────────────────────────────────────────────
  Cache Status
───────────────────────────────────────────────────────────
  Already analyzed:    180
  Needs analysis:      67
```

### 2. Analyze a Single Package

Deep behavioral analysis of a specific package:

```bash
vigil analyze lodash@4.17.21
```

Output:
```
═══════════════════════════════════════════════════════════
  VIGIL - Package Behavioral Analysis
═══════════════════════════════════════════════════════════

Package:  lodash
Version:  4.17.21

───────────────────────────────────────────────────────────
  Analysis Results
───────────────────────────────────────────────────────────
  Duration:            12.3s
  Exit code:           0

───────────────────────────────────────────────────────────
  Behavioral Indicators
───────────────────────────────────────────────────────────
  ✓ No install scripts detected
  ✓ No suspicious patterns detected
  Files installed:     1054

───────────────────────────────────────────────────────────
  Risk Score: 0/100 [LOW]
───────────────────────────────────────────────────────────
  Fingerprint saved to database.
```

### 3. View Database Statistics

```bash
vigil stats
```

## CLI Reference

```
VIGIL - Verified Integrity Guard for Imported Libraries

Usage:
  vigil [command]

Available Commands:
  scan         Scan a project's dependencies for behavioral anomalies
  analyze      Analyze a single package in the sandbox
  stats        Show fingerprint database statistics
  build-image  Build the sandbox Docker image
  version      Print the version number
  help         Help about any command

Flags:
  --db string   Path to fingerprint database (default "~/.vigil/fingerprints.db")
  -h, --help    help for vigil

Use "vigil [command] --help" for more information about a command.
```

### Scan Options

```bash
vigil scan [path] [flags]

Flags:
  --dev          Include dev dependencies
  --depth int    Maximum dependency tree depth (default 5)
```

### Analyze Options

```bash
vigil analyze <package>[@version] [flags]

Flags:
  --timeout int   Analysis timeout in seconds (default 60)

Examples:
  vigil analyze lodash
  vigil analyze lodash@4.17.21
  vigil analyze @types/node
  vigil analyze express --timeout 120
```

## Detection Rules

VIGIL uses YAML-based detection rules. Default rules cover:

| Severity | Examples |
|----------|----------|
| **Critical** | Credential exfiltration, suspicious domains, reverse shells |
| **High** | Install scripts, shell execution, eval(), child_process |
| **Medium** | Network activity, sensitive file reads, obfuscated code |
| **Low** | Native addons, large dependency trees |

### Custom Rules

Create custom rules in `~/.vigil/rules/` or specify with `--rules`:

```yaml
version: "1.0"
rules:
  - id: my-custom-rule
    name: "Custom Detection"
    description: "Detects specific behavior"
    severity: high
    category: custom
    enabled: true
    conditions:
      - type: env
        operator: contains
        values:
          - "MY_SECRET"
    tags: [custom]
```

### Condition Types

| Type | Description |
|------|-------------|
| `network` | Network calls made by the package |
| `file_read` | Files read during execution |
| `file_write` | Files written during execution |
| `env` | Environment variables accessed |
| `shell` | Shell commands executed |
| `suspicious` | Files with suspicious patterns |
| `install_hooks` | Presence of install scripts |

### Operators

| Operator | Description |
|----------|-------------|
| `contains` | Case-insensitive substring match |
| `matches` | Regular expression match |
| `exists` | Data exists (non-empty) |
| `count_gt` | Count greater than value |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLI / API Gateway                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Package Resolver                                  │
│  • Parse package.json • Fetch from npm registry • Resolve dependency tree   │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Sandbox Manager                                   │
│  • Docker container isolation • Resource limits • Behavior capture          │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Analysis Engine                                   │
│  • Rule matching • Risk scoring • Report generation                         │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Fingerprint Store (SQLite)                          │
│  • Behavioral profiles • Version history • Risk scores                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
vigil/
├── cmd/
│   └── vigil/
│       └── main.go           # Entry point
├── internal/
│   ├── cli/
│   │   └── cli.go            # CLI commands
│   ├── resolver/
│   │   ├── resolver.go       # Package.json parser
│   │   ├── npm.go            # npm registry client
│   │   └── tree.go           # Dependency tree resolver
│   ├── sandbox/
│   │   └── sandbox.go        # Docker sandbox manager
│   ├── analyzer/
│   │   ├── analyzer.go       # Analysis engine
│   │   ├── rules.go          # Rule parser and matcher
│   │   └── default_rules.go  # Built-in rules
│   ├── store/
│   │   └── store.go          # SQLite fingerprint store
│   └── collector/
│       └── collector.go      # (Future: advanced collection)
├── docker/
│   └── Dockerfile            # Sandbox image
├── rules/
│   └── default.yaml          # Default detection rules
├── go.mod
├── go.sum
└── README.md
```

## Roadmap

### Phase 2 - Hardening
- [ ] gVisor migration for stronger isolation
- [ ] eBPF tracing for syscall-level events
- [ ] API fuzzing of exported functions
- [ ] Pre-built fingerprint database for top packages

### Phase 3 - Expansion
- [ ] PyPI ecosystem support
- [ ] CI/CD integration (GitHub Action)
- [ ] Hosted service option
- [ ] ML-based anomaly detection

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Prior Art

- [Socket.dev](https://socket.dev/) - Commercial behavioral analysis
- [Sandworm](https://github.com/nicolo-ribaudo/sandworm) - JS permissions tracking
- [Packj](https://github.com/ossillate-inc/packj) - Static + dynamic analysis

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**VIGIL** - Because `npm install` shouldn't be a leap of faith.
