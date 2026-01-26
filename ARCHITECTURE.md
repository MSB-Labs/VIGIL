# VIGIL - Architecture

**Verified Integrity Guard for Imported Libraries**

> A dynamic analysis tool that maps dependency behavior through sandboxed execution, flagging behavioral anomalies in the software supply chain.

## Problem Statement

The software supply chain is vulnerable (see Log4Shell). Developers don't know the actual risk of their deep dependencies, beyond just version CVEs. Current SCA (Software Composition Analysis) tools are static list-checkers. Behavioral trust for open-source packages is a missing layer.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLI / API Gateway                               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            Orchestrator Service                              │
│  • Queue management • Job scheduling • Result aggregation                   │
└─────────────────────────────────────────────────────────────────────────────┘
          │                           │                           │
          ▼                           ▼                           ▼
┌──────────────────┐    ┌──────────────────────┐    ┌──────────────────────┐
│  Package Resolver │    │   Sandbox Manager     │    │  Analysis Engine     │
│  ────────────────│    │  ────────────────────│    │  ──────────────────  │
│  • Fetch from     │    │  • Container lifecycle│    │  • Behavioral diff   │
│    registry       │───▶│  • Resource limits    │───▶│  • Anomaly detection │
│  • Resolve deps   │    │  • Network isolation  │    │  • Risk scoring      │
│  • Version diff   │    │  • Syscall tracing    │    │  • Report generation │
└──────────────────┘    └──────────────────────┘    └──────────────────────┘
                                      │                           │
                                      ▼                           ▼
                        ┌──────────────────────┐    ┌──────────────────────┐
                        │  Behavior Collector   │    │  Fingerprint Store   │
                        │  ────────────────────│    │  ──────────────────  │
                        │  • Syscall events     │    │  • Package baselines │
                        │  • Network traffic    │───▶│  • Version history   │
                        │  • File operations    │    │  • Category norms    │
                        │  • Runtime hooks      │    │  • Known-bad patterns│
                        └──────────────────────┘    └──────────────────────┘
```

---

## Component Breakdown

### 1. Package Resolver

**Purpose:** Fetch and prepare packages for analysis

**Inputs:**
- Package name + version (e.g., `lodash@4.17.21`)
- Or: `package.json` / `requirements.txt` / `go.mod`

**Outputs:**
- Package tarball
- Resolved dependency tree
- Metadata (maintainers, publish date, download count)
- Diff against previous version (file-level)

**Tech:**
- npm registry API / PyPI JSON API / crates.io API
- Package-specific parsers for lockfiles

---

### 2. Sandbox Manager

**Purpose:** Isolated execution environment with full observability

```
┌─────────────────────────────────────────┐
│            Host System                   │
│  ┌─────────────────────────────────────┐│
│  │  gVisor / Firecracker microVM       ││
│  │  ┌───────────────────────────────┐  ││
│  │  │  Minimal OS + Language Runtime │  ││
│  │  │  • Node.js / Python / etc      │  ││
│  │  │  • Instrumentation hooks       │  ││
│  │  │  • eBPF probes attached        │  ││
│  │  └───────────────────────────────┘  ││
│  │         │                            ││
│  │         ▼                            ││
│  │  ┌─────────────┐  ┌─────────────┐   ││
│  │  │ Fake Network│  │Fake Filesys │   ││
│  │  │ (honeypot)  │  │(copy-on-wr) │   ││
│  │  └─────────────┘  └─────────────┘   ││
│  └─────────────────────────────────────┘│
│              │ Event Stream              │
│              ▼                           │
│  ┌─────────────────────────────────────┐│
│  │       Behavior Collector             ││
│  └─────────────────────────────────────┘│
└─────────────────────────────────────────┘
```

**Isolation Layers:**
- **Network:** No real internet, DNS honeypot captures lookups
- **Filesystem:** Copy-on-write overlay, monitors all writes
- **Resources:** CPU/memory/time limits (kill after 60s)
- **Syscalls:** Restricted via seccomp + traced via eBPF

---

### 3. Behavior Collector

**Purpose:** Capture everything the package does at runtime

**Event Categories:**

| Category    | Events Captured                                          |
|-------------|----------------------------------------------------------|
| Network     | DNS queries, connection attempts, HTTP requests (method, host, path) |
| Filesystem  | Reads (which paths), writes, sensitive file access (`/etc/passwd`) |
| Process     | Subprocess spawning, shell commands, `exec()` calls with arguments |
| Environment | Env var reads (`AWS_SECRET`, etc), stdin access, tty detection |
| Code Loading| Dynamic requires, `eval()`, `new Function()`, wasm instantiation |

**Execution Phases:**
1. **Install-time** - postinstall scripts (high risk)
2. **Import-time** - top-level code execution
3. **API-time** - call exported functions with fuzzy inputs

---

### 4. Analysis Engine

**Purpose:** Turn raw events into actionable risk assessment

**Pipeline:**

```
Raw Events
    │
    ▼
┌──────────────────┐
│ Event Normalizer │  Dedupe, group by category
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Baseline Compare │  This version vs previous version
└────────┬─────────┘  This package vs category norm
         │
         ▼
┌──────────────────┐
│ Rule Engine      │  Declarative risk rules
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Risk Scorer      │  Weighted aggregation
└────────┬─────────┘
         │
         ▼
Risk Report + Alerts
```

**Example Rules (YAML):**

```yaml
- id: network-in-utility
  description: "Utility package makes network calls"
  condition: |
    category in ['string', 'math', 'date', 'validation']
    AND events.network.count > 0
  severity: high

- id: env-credential-access
  description: "Reads cloud credential env vars"
  condition: |
    events.env_read intersects ['AWS_SECRET*', 'GITHUB_TOKEN', 'NPM_TOKEN']
  severity: critical

- id: postinstall-shell
  description: "Runs shell commands during install"
  condition: |
    phase == 'install' AND events.process.shell_commands.count > 0
  severity: high
```

---

### 5. Fingerprint Store

**Purpose:** Historical behavioral data for comparison

**Schema (simplified):**

```
packages
  ├── id
  ├── ecosystem (npm, pypi, cargo)
  ├── name
  ├── category (inferred or manual)
  └── baseline_behavior_id

versions
  ├── id
  ├── package_id
  ├── version
  ├── published_at
  ├── analyzed_at
  └── behavior_fingerprint_id

behavior_fingerprints
  ├── id
  ├── network_calls      JSON [{host, port, protocol}]
  ├── file_reads         JSON [paths]
  ├── file_writes        JSON [paths]
  ├── env_reads          JSON [var_names]
  ├── shell_commands     JSON [commands]
  ├── dynamic_code_exec  BOOLEAN
  └── checksum           (for quick diff)
```

**Key Queries:**
- "What did `lodash@4.17.20` do vs `4.17.21`?"
- "What's normal for packages tagged 'string-utils'?"
- "Has any version of this package ever made network calls?"

---

## Data Flow Example

```
User runs: sentinel scan package.json

1. [Resolver] Parse package.json → 847 transitive dependencies
2. [Resolver] Filter to: unanalyzed + outdated fingerprints → 23 packages
3. [Orchestrator] Queue 23 analysis jobs

For each package:
4. [Sandbox] Spin up gVisor container with Node.js 20
5. [Sandbox] npm install <package> with instrumented npm
6. [Collector] Capture: 3 DNS lookups, 12 file reads, 0 shell commands
7. [Sandbox] require('<package>') in test harness
8. [Collector] Capture: 2 env var reads, 1 file write to /tmp
9. [Sandbox] Call exported functions with fuzz inputs
10. [Collector] Capture: eval() called with user-controlled string
11. [Sandbox] Terminate, destroy container
12. [Analysis] Compare against previous version fingerprint
13. [Analysis] Flag: +eval() usage (new), +ENV read of HOME (new)
14. [Store] Save fingerprint, update version record

15. [Orchestrator] Aggregate all 23 results
16. [CLI] Output:
    ┌─────────────────────────────────────────────────────┐
    │ Dependency Sentinel Report                          │
    ├─────────────────────────────────────────────────────┤
    │ Scanned: 847 dependencies                           │
    │ Analyzed: 23 (824 cached)                           │
    │                                                     │
    │ 🔴 CRITICAL (1)                                     │
    │   fake-lodash@1.0.3                                 │
    │   - Exfiltrates ENV to http://evil.com (!)          │
    │                                                     │
    │ 🟠 HIGH (3)                                         │
    │   some-lib@2.1.0                                    │
    │   - New: postinstall runs curl command              │
    │   - Changed: now reads AWS_ACCESS_KEY_ID            │
    │   ...                                               │
    │                                                     │
    │ 🟡 MEDIUM (7)                                       │
    │   ...                                               │
    └─────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Component         | Recommendation                        | Rationale                                    |
|-------------------|---------------------------------------|----------------------------------------------|
| Orchestrator      | Go                                    | Concurrency, container ecosystem tooling     |
| Sandbox           | gVisor (runsc)                        | Stronger isolation than Docker, still fast   |
| Syscall Tracing   | eBPF (via cilium/ebpf)                | Low overhead, kernel-level visibility        |
| Language Hooks    | Per-ecosystem (JS: require hooks, Python: import hooks) | Catches language-level behavior |
| Fingerprint Store | SQLite (local) / PostgreSQL (service) | Simple, good enough for MVP                  |
| Rule Engine       | Expr or CEL                           | Declarative, user-extensible                 |
| CLI               | Go (cobra)                            | Single binary distribution                   |

---

## Implementation Roadmap

### Phase 1 - MVP (npm only, local CLI)

- [ ] Package resolver for npm
- [ ] Docker-based sandbox (simpler than gVisor for MVP)
- [ ] Basic behavior collection (network, fs, process)
- [ ] Install-time + import-time analysis
- [ ] Version diff comparison
- [ ] SQLite fingerprint storage
- [ ] CLI with scan command
- [ ] 10 core detection rules

### Phase 2 - Hardening

- [ ] gVisor migration for better isolation
- [ ] eBPF tracing for syscall-level events
- [ ] API fuzzing of exported functions
- [ ] Community rule contributions
- [ ] Pre-built fingerprint database (top 1000 npm packages)

### Phase 3 - Expansion

- [ ] PyPI ecosystem support
- [ ] CI/CD integration (GitHub Action)
- [ ] Hosted service option
- [ ] ML-based anomaly detection

---

## Prior Art & References

- **Socket.dev** - Commercial behavioral analysis for npm
- **Sandworm** - Open source JS permissions tracking
- **Packj** - Static + some dynamic analysis
- **Falco/Sysdig** - Runtime behavioral monitoring (different domain but relevant tech)
