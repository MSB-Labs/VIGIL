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

  # ============================================
  # PYTHON-SPECIFIC RULES
  # ============================================

  - id: python-setup-py-exec
    name: "setup.py Code Execution"
    description: "Python package executes code in setup.py during installation"
    severity: high
    category: install
    enabled: true
    conditions:
      - type: script
        operator: contains
        values:
          - "setup.py"
          - "pyproject.toml"
    tags: [python, setup]

  - id: python-subprocess-exec
    name: "Python Subprocess Execution"
    description: "Python package uses subprocess to execute shell commands"
    severity: high
    category: shell
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "subprocess."
          - "os.system("
          - "os.popen("
          - "exec("
          - "eval("
    tags: [python, subprocess]

  - id: python-requests-network
    name: "Python Network Requests"
    description: "Python package makes network requests during installation"
    severity: medium
    category: network
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "requests."
          - "urllib."
          - "urllib2."
          - "http.client"
          - "socket."
    tags: [python, network]

  - id: python-env-access
    name: "Python Environment Access"
    description: "Python package accesses environment variables"
    severity: medium
    category: env
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "os.environ"
          - "os.getenv"
          - "getenv"
    tags: [python, env]

  - id: python-file-access
    name: "Python File System Access"
    description: "Python package accesses sensitive files during installation"
    severity: medium
    category: filesystem
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "/etc/passwd"
          - "/etc/shadow"
          - ".ssh/"
          - ".aws/"
          - ".pythonrc"
          - ".piprc"
    tags: [python, filesystem]

  # ============================================
  # PYTHON-SPECIFIC ADVANCED RULES
  # ============================================

  - id: python-venv-manipulation
    name: "Virtual Environment Manipulation"
    description: "Python package attempts to create, modify, or detect virtual environments"
    severity: high
    category: python
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "venv"
          - "virtualenv"
          - "site-packages"
          - "sys.prefix"
          - "sys.exec_prefix"
          - "os.environ['VIRTUAL_ENV']"
          - "VIRTUAL_ENV"
          - "activate"
          - "deactivate"
    tags: [python, venv, environment]

  - id: python-path-manipulation
    name: "Python Path Manipulation"
    description: "Python package modifies sys.path or PYTHONPATH during installation"
    severity: high
    category: python
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "sys.path.append"
          - "sys.path.insert"
          - "sys.path.extend"
          - "PYTHONPATH"
          - "os.environ['PYTHONPATH']"
          - "site.addsitedir"
          - "site.addpackage"
    tags: [python, path, syspath]

  - id: python-dynamic-import
    name: "Dynamic Module Loading"
    description: "Python package uses dynamic import mechanisms that could load malicious code"
    severity: high
    category: python
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "__import__"
          - "importlib.import_module"
          - "importlib.util.spec_from_file_location"
          - "importlib.util.module_from_spec"
          - "imp.load_source"
          - "imp.load_module"
          - "pkgutil.iter_modules"
          - "pkgutil.find_loader"
    tags: [python, dynamic, import]

  - id: python-package-install-outside-site-packages
    name: "Package Installation Outside site-packages"
    description: "Python package attempts to install files outside normal Python directories"
    severity: high
    category: python
    enabled: true
    conditions:
      - type: file_write
        operator: matches
        values:
          - "^/tmp/"
          - "^/var/"
          - "^~/"
          - "^/home/"
          - "^/usr/local/bin/"
          - "^/opt/"
          - "^/etc/"
          - "^[A-Za-z]:\\\\"  # Windows paths
    tags: [python, installation, filesystem]

  - id: python-import-hijacking
    name: "Import Hijacking Attempt"
    description: "Python package attempts to hijack imports by modifying sys.modules"
    severity: critical
    category: python
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "sys.modules"
          - "sys.modules['"
          - "sys.modules.update"
          - "sys.modules.__setitem__"
          - "import sys; sys.modules"
    tags: [python, hijacking, sysmodules]

  - id: python-pip-install-external
    name: "External Package Installation"
    description: "Python package attempts to install additional packages via pip"
    severity: high
    category: python
    enabled: true
    conditions:
      - type: shell
        operator: contains
        values:
          - "pip install"
          - "python -m pip install"
          - "pip3 install"
          - "subprocess.*pip"
          - "os.system.*pip"
    tags: [python, pip, installation]

  - id: python-config-file-modification
    name: "Python Configuration File Modification"
    description: "Python package modifies Python configuration files"
    severity: medium
    category: python
    enabled: true
    conditions:
      - type: file_write
        operator: contains
        values:
          - "pythonrc"
          - "sitecustomize.py"
          - "usercustomize.py"
          - "pyvenv.cfg"
          - ".pth"
          - "setup.cfg"
          - "pyproject.toml"
    tags: [python, configuration, files]

  - id: python-cryptography-usage
    name: "Cryptography Module Usage"
    description: "Python package uses cryptography modules which could be used for malicious purposes"
    severity: medium
    category: python
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "cryptography."
          - "Crypto."
          - "pycryptodome"
          - "pycrypto"
          - "hashlib."
          - "secrets."
          - "ssl."
          - "OpenSSL"
    tags: [python, cryptography, security]

  - id: python-debugger-detection
    name: "Debugger/Sandbox Detection"
    description: "Python package attempts to detect debuggers or sandbox environments"
    severity: high
    category: python
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "sys.gettrace"
          - "sys._getframe"
          - "traceback"
          - "pdb"
          - "pydevd"
          - "pycharm"
          - "vscode"
          - "docker"
          - "vbox"
          - "vmware"
          - "virtualbox"
    tags: [python, detection, sandbox]

  - id: python-registry-access-windows
    name: "Windows Registry Access"
    description: "Python package accesses Windows Registry (Windows-specific)"
    severity: high
    category: python
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "winreg"
          - "win32api"
          - "win32con"
          - "win32service"
          - "win32process"
          - "HKEY_"
          - "RegOpenKey"
          - "RegSetValue"
    tags: [python, windows, registry]

  - id: python-process-injection
    name: "Process Injection/Manipulation"
    description: "Python package attempts to manipulate or inject into other processes"
    severity: critical
    category: python
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "ctypes.windll.kernel32"
          - "ctypes.windll.kernelbase"
          - "CreateProcess"
          - "WriteProcessMemory"
          - "ReadProcessMemory"
          - "VirtualAllocEx"
          - "VirtualFreeEx"
          - "OpenProcess"
          - "TerminateProcess"
    tags: [python, process, injection, windows]

  - id: python-keyboard-mouse-control
    name: "Input Device Control"
    description: "Python package attempts to control keyboard or mouse input"
    severity: medium
    category: python
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "pynput"
          - "pyautogui"
          - "keyboard"
          - "mouse"
          - "win32api.keybd_event"
          - "win32api.mouse_event"
          - "SendInput"
    tags: [python, input, control]

  - id: python-system-info-gathering
    name: "System Information Gathering"
    description: "Python package gathers detailed system information"
    severity: medium
    category: python
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "platform."
          - "psutil."
          - "socket.gethostname"
          - "socket.gethostbyname"
          - "uuid.getnode"
          - "os.uname"
          - "os.cpu_count"
          - "shutil.disk_usage"
          - "platform.machine"
          - "platform.processor"
    tags: [python, info, gathering]

  - id: python-file-encryption
    name: "File Encryption/Decryption"
    description: "Python package performs file encryption or decryption operations"
    severity: medium
    category: python
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "encrypt"
          - "decrypt"
          - "AES"
          - "RSA"
          - "DES"
          - "Blowfish"
          - "ChaCha20"
          - "Fernet"
          - "Cipher"
          - "encrypt_file"
          - "decrypt_file"
    tags: [python, encryption, crypto]

  - id: python-memory-operations
    name: "Low-level Memory Operations"
    description: "Python package performs low-level memory operations using ctypes"
    severity: high
    category: python
    enabled: true
    conditions:
      - type: suspicious
        operator: contains
        values:
          - "ctypes."
          - "ctypes.c_"
          - "ctypes.POINTER"
          - "ctypes.byref"
          - "ctypes.addressof"
          - "ctypes.string_at"
          - "ctypes.memmove"
          - "ctypes.memset"
    tags: [python, memory, ctypes]
`
