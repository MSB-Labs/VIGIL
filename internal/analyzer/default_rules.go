package analyzer

// DefaultRulesYAML contains the built-in detection rules
const DefaultRulesYAML = `
version: "1.0"
rules:
  # ============================================
  # CRITICAL - Immediate threats
  # ============================================

  - id: exfiltration-env-credentials
    name: "Credential Exfiltration Attempt"
    description: "Package attempts to read sensitive credential environment variables"
    severity: critical
    category: exfiltration
    enabled: true
    conditions:
      - type: env
        operator: contains
        values:
          - "AWS_SECRET"
          - "AWS_ACCESS_KEY"
          - "GITHUB_TOKEN"
          - "NPM_TOKEN"
          - "DOCKER_PASSWORD"
          - "API_KEY"
          - "PRIVATE_KEY"
          - "SECRET_KEY"
    tags: [credentials, exfiltration]

  - id: network-suspicious-domain
    name: "Suspicious Network Call"
    description: "Package makes network calls to suspicious or obfuscated domains"
    severity: critical
    category: network
    enabled: true
    conditions:
      - type: network
        operator: matches
        values:
          - "\\d+\\.\\d+\\.\\d+\\.\\d+"  # Raw IP address
          - "pastebin\\.com"
          - "ngrok\\.io"
          - "requestbin"
          - "webhook\\.site"
          - "\\.onion$"
          - "bit\\.ly"
          - "tinyurl"
    tags: [network, c2]

  - id: shell-reverse-shell
    name: "Reverse Shell Attempt"
    description: "Package attempts to spawn a reverse shell"
    severity: critical
    category: shell
    enabled: true
    conditions:
      - type: shell
        operator: matches
        values:
          - "nc\\s.*-e"
          - "bash\\s+-i"
          - "/dev/tcp/"
          - "mkfifo"
          - "telnet.*\\|.*bash"
    tags: [shell, reverse-shell]

  # ============================================
  # HIGH - Serious concerns
  # ============================================

  - id: postinstall-script
    name: "Post-Install Script Present"
    description: "Package runs code during npm install via postinstall hook"
    severity: high
    category: install
    enabled: true
    conditions:
      - type: install_hooks
        operator: exists
    tags: [install, scripts]

  - id: shell-command-execution
    name: "Shell Command Execution"
    description: "Package executes shell commands during install"
    severity: high
    category: shell
    enabled: true
    conditions:
      - type: shell
        operator: exists
    tags: [shell, exec]

  - id: dynamic-code-eval
    name: "Dynamic Code Execution"
    description: "Package uses eval() or similar dynamic code execution"
    severity: high
    category: code
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "eval("
          - "new Function("
          - "vm.runInContext"
          - "vm.runInNewContext"
    tags: [eval, dynamic]

  - id: child-process-spawn
    name: "Child Process Spawning"
    description: "Package spawns child processes which could execute arbitrary code"
    severity: high
    category: process
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "child_process"
          - "exec("
          - "execSync"
          - "spawn("
          - "spawnSync"
    tags: [process, exec]

  - id: env-home-access
    name: "Home Directory Access"
    description: "Package accesses user home directory environment"
    severity: high
    category: filesystem
    enabled: true
    conditions:
      - type: env
        operator: contains
        values:
          - "HOME"
          - "USERPROFILE"
          - "HOMEPATH"
    tags: [filesystem, privacy]

  # ============================================
  # MEDIUM - Notable behaviors
  # ============================================

  - id: network-any-call
    name: "Network Activity"
    description: "Package makes network calls during install or import"
    severity: medium
    category: network
    enabled: true
    conditions:
      - type: network
        operator: exists
    tags: [network]

  - id: file-sensitive-read
    name: "Sensitive File Read"
    description: "Package reads potentially sensitive files"
    severity: medium
    category: filesystem
    enabled: true
    conditions:
      - type: file_read
        operator: contains
        values:
          - "/etc/passwd"
          - "/etc/shadow"
          - ".ssh/"
          - ".aws/"
          - ".npmrc"
          - ".gitconfig"
          - ".bash_history"
          - "id_rsa"
    tags: [filesystem, sensitive]

  - id: file-write-outside-node-modules
    name: "File Write Outside node_modules"
    description: "Package writes files outside its expected directory"
    severity: medium
    category: filesystem
    enabled: true
    conditions:
      - type: file_write
        operator: matches
        values:
          - "^/tmp/"
          - "^/var/"
          - "^~/"
          - "^/home/"
    tags: [filesystem, write]

  - id: obfuscated-code
    name: "Potentially Obfuscated Code"
    description: "Package may contain obfuscated or minified malicious code"
    severity: medium
    category: code
    enabled: true
    conditions:
      - type: suspicious
        operator: matches
        values:
          - "\\\\x[0-9a-f]{2}"  # Hex escapes
          - "\\\\u[0-9a-f]{4}"  # Unicode escapes
          - "atob\\("           # Base64 decode
          - "Buffer\\.from\\(.*base64"
    tags: [obfuscation]

  # ============================================
  # LOW - Informational
  # ============================================

  - id: native-addon
    name: "Native Addon"
    description: "Package includes native compiled code"
    severity: low
    category: code
    enabled: true
    conditions:
      - type: file_write
        operator: contains
        values:
          - ".node"
          - ".dylib"
          - ".so"
          - ".dll"
    tags: [native]

  - id: many-dependencies
    name: "Large Dependency Tree"
    description: "Package has many transitive dependencies increasing attack surface"
    severity: low
    category: supply-chain
    enabled: true
    conditions:
      - type: file_write
        operator: count_gt
        value: "100"
    tags: [dependencies]

  # ============================================
  # INFO - Awareness only
  # ============================================

  - id: uses-https
    name: "HTTPS Network Calls"
    description: "Package makes HTTPS network calls (informational)"
    severity: info
    category: network
    enabled: true
    conditions:
      - type: network
        operator: contains
        values:
          - "https://"
    tags: [network, https]
`
