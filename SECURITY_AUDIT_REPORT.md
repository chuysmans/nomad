# Security Audit Report: HashiCorp Nomad v0.9.2

## Injection Vulnerability Analysis

**Audit Date:** 2026-08-03
**Scope:** Injection vulnerabilities across command execution, path traversal, SSRF, state store, template, and header injection vectors.

---

### Finding 1: Command Execution via consul-template `plugin` Function

| Field | Detail |
|---|---|
| **Severity** | **CRITICAL** |
| **Location** | `vendor/github.com/hashicorp/consul-template/template/funcs.go:798-840` |
| **Title** | Arbitrary command execution through consul-template `plugin` function in job templates |

**Description:**
The consul-template library, used by Nomad's template rendering engine, exposes a `plugin` template function that executes arbitrary commands via `exec.Command`. Any user who can submit a job spec with an embedded template can execute arbitrary commands on the Nomad client node.

**Impact:**
Full remote code execution on any Nomad client node. An attacker with job submission privileges can execute arbitrary commands as the Nomad agent user (often root).

**Attack Path:**
1. Attacker submits a job with a template block containing `{{ plugin "malicious_command" "arg1" "arg2" }}`
2. The template is processed by `client/allocrunner/taskrunner/template/template.go` which creates a consul-template runner
3. The runner calls `funcMap()` which registers the `plugin` function at `template/template.go:245`
4. When the template renders, `plugin()` in `funcs.go:798` calls `exec.Command(name, jsons...)` with attacker-controlled `name` and `args`
5. The command executes on the client node with the Nomad agent's privileges

**Evidence:**
```go
// vendor/github.com/hashicorp/consul-template/template/funcs.go:798
func plugin(name string, args ...string) (string, error) {
    // ...
    cmd := exec.Command(name, jsons...)  // line 814 - attacker controls name and args
    cmd.Stdout = stdout
    cmd.Stderr = stderr
    if err := cmd.Start(); err != nil {
```

The template function map at `template/template.go:245` unconditionally registers `"plugin": plugin` with no allowlist or sandbox restriction.

**Remediation:**
- Remove or disable the `plugin` template function in Nomad's consul-template configuration
- Implement an allowlist of permitted template functions
- Add a `disable_plugin_function` configuration option (defaulting to disabled)

---

### Finding 2: Raw Exec Driver - Unsandboxed Command Execution

| Field | Detail |
|---|---|
| **Severity** | **HIGH** |
| **Location** | `drivers/rawexec/driver.go:305-381` |
| **Title** | raw_exec driver executes user-supplied commands without filesystem isolation |

**Description:**
The `raw_exec` driver directly executes user-supplied commands from job specs with `FSIsolation: drivers.FSIsolationNone` (line 97). While disabled by default (`enabled: false` at line 76), when enabled, it provides no filesystem isolation, no chroot, and optional-only cgroup constraints.

**Impact:**
When `raw_exec` is enabled, any user who can submit jobs can execute arbitrary commands with no filesystem sandboxing, potentially as root, with access to the full host filesystem.

**Attack Path:**
1. Operator enables `raw_exec` driver in client configuration
2. Attacker submits job: `driver = "raw_exec"` with `config { command = "/bin/sh" args = ["-c", "malicious payload"] }`
3. `StartTask()` at line 305 decodes `driverConfig.Command` and `driverConfig.Args` directly from the job spec
4. Command is passed to `executor.Launch()` via `ExecCommand{Cmd: driverConfig.Command, Args: driverConfig.Args}` (lines 336-345)
5. Executor runs it without any path restriction or chroot

**Evidence:**
```go
// drivers/rawexec/driver.go:97
capabilities = &drivers.Capabilities{
    SendSignals: true,
    Exec:        true,
    FSIsolation: drivers.FSIsolationNone,  // No filesystem isolation
}
```

**Remediation:**
- Ensure `raw_exec` remains disabled by default (already the case)
- Add command allowlisting/denylisting capability to `raw_exec`
- Log all `raw_exec` invocations at WARN level with the full command
- Consider requiring explicit ACL permission beyond standard `submit-job`

---

### Finding 3: Deprecated `filepath.HasPrefix` Used for Secret Directory Protection

| Field | Detail |
|---|---|
| **Severity** | **HIGH** |
| **Location** | `client/allocdir/alloc_dir.go:417` |
| **Title** | Secret directory access control bypass via deprecated `filepath.HasPrefix` |

**Description:**
The `ReadAt` function uses `filepath.HasPrefix(p, dir.SecretsDir)` to prevent reading secret files. However, `filepath.HasPrefix` has been deprecated in Go since Go 1.8 because it does not correctly handle all path cases. The Go documentation explicitly states: "HasPrefix exists for historical compatibility and should not be used." It can be bypassed with path manipulation.

**Impact:**
An attacker with `ReadFS` ACL permission could potentially read Vault tokens and other secrets stored in task secret directories by crafting paths that bypass the `filepath.HasPrefix` check.

**Attack Path:**
1. Attacker has `ReadFS` namespace capability (required to use the filesystem API)
2. The `PathEscapesAllocDir` check at line 406 validates the path stays within the alloc dir
3. However, the secrets directory check at line 417 uses `filepath.HasPrefix`
4. On certain OS/path combinations, `filepath.HasPrefix("/alloc/task/secrets", "/alloc/task/secret")` could return incorrect results due to the prefix-based (not path-component-based) matching
5. Path constructions like volume-relative paths or case-sensitivity issues (on case-insensitive filesystems) could bypass the check

**Evidence:**
```go
// client/allocdir/alloc_dir.go:414-421
d.mu.RLock()
for _, dir := range d.TaskDirs {
    if filepath.HasPrefix(p, dir.SecretsDir) {  // DEPRECATED - unreliable
        d.mu.RUnlock()
        return nil, fmt.Errorf("Reading secret file prohibited: %s", path)
    }
}
d.mu.RUnlock()
```

**Remediation:**
- Replace `filepath.HasPrefix` with a proper path containment check using `filepath.Rel` and checking for `..` prefix (similar to `PathEscapesAllocDir`)
- Use `strings.HasPrefix(filepath.Clean(p)+"/", filepath.Clean(dir.SecretsDir)+"/")` or equivalent

---

### Finding 4: Path Traversal via Symlinks in Allocation Directory

| Field | Detail |
|---|---|
| **Severity** | **MEDIUM** |
| **Location** | `client/allocdir/alloc_dir.go:356-432` |
| **Title** | Symlink-following in filesystem operations can escape allocation directory |

**Description:**
The `PathEscapesAllocDir` check validates the *logical* path doesn't escape the alloc directory using `filepath.Abs` and `filepath.Rel`. However, the actual file operations (`os.Stat`, `ioutil.ReadDir`, `os.Open`) follow symlinks. If a task creates a symlink pointing outside the alloc directory, subsequent filesystem API calls can read arbitrary files on the host.

**Impact:**
A malicious task (or a task with a vulnerability) could create a symlink pointing to `/etc/shadow`, `/etc/nomad.d/`, or other sensitive paths. The filesystem API would then serve those files to anyone with `ReadFS` permission, since the logical path passes `PathEscapesAllocDir` but the symlink target escapes the directory.

**Attack Path:**
1. Malicious job runs a task that creates `ln -s /etc/passwd /alloc/data/link`
2. API request: `GET /v1/client/fs/cat/<allocID>?path=alloc/data/link`
3. `PathEscapesAllocDir("", "alloc/data/link")` returns `false` (path looks contained)
4. `os.Open(filepath.Join(allocDir, "alloc/data/link"))` follows the symlink to `/etc/passwd`
5. File contents are returned to the attacker

**Evidence:**
```go
// client/allocdir/alloc_dir.go:405-412
func (d *AllocDir) ReadAt(path string, offset int64) (io.ReadCloser, error) {
    if escapes, err := structs.PathEscapesAllocDir("", path); err != nil {
        return nil, ...
    } else if escapes {
        return nil, ...
    }
    p := filepath.Join(d.AllocDir, path)
    // No symlink resolution check - os.Open follows symlinks
    f, err := os.Open(p)
```

**Remediation:**
- After constructing the full path, resolve symlinks with `filepath.EvalSymlinks` and verify the resolved path is still within the allocation directory
- Apply the same fix to `List`, `Stat`, `BlockUntilExists`, and `ChangeEvents`

---

### Finding 5: SSRF via Artifact Fetching (go-getter)

| Field | Detail |
|---|---|
| **Severity** | **MEDIUM** |
| **Location** | `client/allocrunner/taskrunner/getter/getter.go:59-115` |
| **Title** | SSRF through artifact source URLs in job specifications |

**Description:**
The artifact fetching system uses `go-getter` with user-controlled URLs from job specs. While the getter restricts protocols to `http`, `https`, `s3`, `hg`, `git` (line 21), it does not restrict target hosts. An attacker can point artifact URLs to internal services, cloud metadata endpoints, or other internal infrastructure.

**Impact:**
An attacker with job submission privileges can probe internal network services, access cloud metadata services (e.g., `http://169.254.169.254/`), and potentially steal IAM credentials or other sensitive data available via HTTP on internal networks.

**Attack Path:**
1. Attacker submits job with artifact: `source = "http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"`
2. `getGetterUrl()` at line 59 interpolates environment variables into the source but performs no host validation
3. `GetArtifact()` at line 92 passes the URL to `getClient(url, mode, dest).Get()`
4. go-getter fetches the URL from the Nomad client's network perspective
5. Response is written to the task directory where the attacker can read it

**Evidence:**
```go
// client/allocrunner/taskrunner/getter/getter.go:21
supported = []string{"http", "https", "s3", "hg", "git"}  // No host restriction

// getter.go:92-112
func GetArtifact(taskEnv EnvReplacer, artifact *structs.TaskArtifact, taskDir string) error {
    url, err := getGetterUrl(taskEnv, artifact)
    // No validation of target host/IP
    dest := filepath.Join(taskDir, artifact.RelativeDest)
    if err := getClient(url, mode, dest).Get(); err != nil {
```

**Remediation:**
- Add a configurable allowlist/denylist for artifact source hosts
- Block RFC 1918 addresses and link-local addresses (169.254.0.0/16) by default
- Block cloud metadata endpoints explicitly
- Add a `artifact.deny_internal_networks` client configuration option

---

### Finding 6: RKT Driver Command Injection via Unsanitized Configuration

| Field | Detail |
|---|---|
| **Severity** | **MEDIUM** |
| **Location** | `drivers/rkt/driver.go:443-655` |
| **Title** | Injection into rkt command arguments via unsanitized job spec fields |

**Description:**
The RKT driver constructs command-line arguments for `rkt prepare` and `rkt run-prepared` by directly interpolating user-supplied configuration values. Fields like `trustPrefix`, `dnsServers`, `dnsSearchDomains`, `net`, `volumes`, `command`, `group`, and `args` are inserted into command arguments via `fmt.Sprintf` without sanitization.

**Impact:**
An attacker could inject additional rkt flags or manipulate the container configuration through specially crafted values in DNS servers, search domains, volume paths, network names, or trust prefixes. This could lead to container escapes or privilege escalation.

**Attack Path:**
1. Attacker submits job using rkt driver with `dns_search_domains = ["evil.com --net=host"]`
2. At line 580: `runArgs = append(runArgs, fmt.Sprintf("--dns-search=%s", domain))`
3. The resulting argument `--dns-search=evil.com --net=host` could be parsed by rkt as two separate flags depending on shell parsing behavior
4. Note: Since args are passed as array elements to `exec.Command`, direct shell injection is not possible, but `rkt`'s own argument parsing of the formatted strings could still be exploitable

**Evidence:**
```go
// drivers/rkt/driver.go:447
cmd := exec.Command(rktCmd, "trust", "--skip-fingerprint-review=true",
    fmt.Sprintf("--prefix=%s", trustPrefix),  // trustPrefix from job spec
    fmt.Sprintf("--debug=%t", debug))

// drivers/rkt/driver.go:574
runArgs = append(runArgs, fmt.Sprintf("--dns=%s", ip))  // ip from job spec

// drivers/rkt/driver.go:580
runArgs = append(runArgs, fmt.Sprintf("--dns-search=%s", domain))  // domain from job spec
```

**Remediation:**
- Validate and sanitize all user-supplied configuration values before interpolation
- Validate DNS servers are valid IP addresses (the existing check at line 569 has inverted logic - `net.ParseIP` returns nil on error, not the other way around)
- Validate DNS search domains match a hostname pattern
- Validate volume paths don't contain flag-like prefixes

---

### Finding 7: Template Destination Path Traversal via Environment Variable Interpolation

| Field | Detail |
|---|---|
| **Severity** | **MEDIUM** |
| **Location** | `client/allocrunner/taskrunner/template/template.go:548-549` |
| **Title** | Template destination path escape via environment variable expansion |

**Description:**
Template destinations undergo environment variable interpolation *after* the `PathEscapesAllocDir` validation happens on the raw template spec. The `parseTemplateConfigs` function applies `taskEnv.ReplaceEnv()` to both `SourcePath` and `DestPath` after the validation in `Template.Validate()` has already passed.

**Impact:**
If an attacker can control environment variables (e.g., via a dispatch payload, parameterized job, or Consul KV), they could set a variable that, when interpolated into the template destination path, causes it to escape the allocation directory.

**Attack Path:**
1. Job defines template with `destination = "local/${MY_VAR}"` - passes `PathEscapesAllocDir` validation
2. Attacker sets env var `MY_VAR=../../etc/cron.d/backdoor` via dispatch payload or meta
3. At `template.go:549`: `dest = filepath.Join(config.TaskDir, taskEnv.ReplaceEnv(tmpl.DestPath))` expands to a path outside the task directory
4. consul-template writes the rendered template to the escaped path

**Evidence:**
```go
// Validation happens on the raw path at nomad/structs/structs.go:5779
escaped, err := PathEscapesAllocDir("task", t.DestPath)  // Validates "local/${MY_VAR}"

// But interpolation happens later at template.go:548-549
src = filepath.Join(config.TaskDir, taskEnv.ReplaceEnv(tmpl.SourcePath))
dest = filepath.Join(config.TaskDir, taskEnv.ReplaceEnv(tmpl.DestPath))
// dest could now escape the task directory
```

**Remediation:**
- Apply `PathEscapesAllocDir` validation *after* environment variable interpolation
- Add a path escape check in `parseTemplateConfigs` after `ReplaceEnv` is applied

---

### Finding 8: Header Injection via `http_api_response_headers` Configuration

| Field | Detail |
|---|---|
| **Severity** | **LOW** |
| **Location** | `command/agent/http.go:278, 375-379` |
| **Title** | Operator-controlled custom HTTP headers set without validation |

**Description:**
The `HTTPAPIResponseHeaders` configuration allows operators to set arbitrary HTTP response headers on all API responses. The `setHeaders` function directly calls `resp.Header().Set()` with the configured key/value pairs without any validation or restriction on header names.

**Impact:**
A misconfigured or malicious operator configuration could set security-sensitive headers (e.g., overriding `Content-Security-Policy`, setting `Access-Control-Allow-Origin: *`, or injecting CRLF in header values). This is operator-level configuration, so the risk requires a compromised or malicious config file.

**Attack Path:**
1. Attacker modifies Nomad agent configuration (requires file-level access)
2. Sets `http_api_response_headers { "X-Frame-Options" = "" }` to remove security headers
3. Or sets headers that could weaken the security posture of the API

**Evidence:**
```go
// command/agent/http.go:375-379
func setHeaders(resp http.ResponseWriter, headers map[string]string) {
    for field, value := range headers {
        resp.Header().Set(http.CanonicalHeaderKey(field), value)  // No validation
    }
}
```

**Remediation:**
- Implement a denylist of security-sensitive headers that cannot be overridden (e.g., `Content-Security-Policy`, `Strict-Transport-Security`)
- Document security implications of this configuration option
- This is low severity since it requires operator-level access to the configuration file

---

### Finding 9: No SQL Injection Risk - MemDB is Safe

| Field | Detail |
|---|---|
| **Severity** | **INFO** |
| **Location** | `nomad/state/state_store.go` |
| **Title** | State store uses MemDB with parameterized queries - no SQL injection risk |

**Description:**
The state store uses HashiCorp's `go-memdb`, an in-memory database that uses Go struct-based schema definitions and type-safe query functions. There is no raw query building or string interpolation in queries. All data access goes through `memdb.Txn` methods like `First()`, `Get()`, and iterators with typed index names and values.

**Evidence:**
```go
// nomad/state/state_store.go:68-70
func NewStateStore(config *StateStoreConfig) (*StateStore, error) {
    db, err := memdb.NewMemDB(stateStoreSchema())
    // All queries use type-safe MemDB API, no string concatenation
```

**Remediation:** None needed.

---

### Finding 10: Vault URL Configuration is Server-Side Only

| Field | Detail |
|---|---|
| **Severity** | **INFO** |
| **Location** | `nomad/vault.go:238-380` |
| **Title** | Vault address is operator-configured, not job-spec controlled - no SSRF via Vault |

**Description:**
The Vault integration uses server-side configuration for the Vault address. Job specs can specify Vault policies but cannot control the Vault server URL. The `vaultClient.buildClient()` reads the address from `v.config.Addr` which comes from the server's `VaultConfig`, not from job specifications. The consul-template runner's Vault configuration at `template.go:644-646` also reads from `cc.VaultConfig.Addr` (client config), not from job specs.

**Evidence:**
```go
// nomad/vault.go:377-379
func (v *vaultClient) buildClient() error {
    if v.config.Token == "" {
        return errors.New("Vault token must be set")
    } else if v.config.Addr == "" {
        return errors.New("Vault address must be set")
    }
```

**Remediation:** None needed. The Vault address is appropriately restricted to operator configuration.

---

## Summary

| # | Severity | Title | Category |
|---|---|---|---|
| 1 | **CRITICAL** | consul-template `plugin` function allows arbitrary command execution | Command Injection |
| 2 | **HIGH** | raw_exec driver executes unsandboxed commands | Command Injection |
| 3 | **HIGH** | Deprecated `filepath.HasPrefix` for secret directory protection | Path Traversal |
| 4 | **MEDIUM** | Symlink-following escapes allocation directory | Path Traversal |
| 5 | **MEDIUM** | SSRF through artifact fetching to internal networks | SSRF |
| 6 | **MEDIUM** | RKT driver unsanitized configuration injection | Command Injection |
| 7 | **MEDIUM** | Template destination path escape via env var interpolation | Path Traversal |
| 8 | **LOW** | Custom HTTP headers set without validation | Header Injection |
| 9 | **INFO** | MemDB state store is safe from SQL injection | SQL Injection |
| 10 | **INFO** | Vault URL is server-configured, not job-controlled | SSRF |

### Critical Recommendations

1. **Immediately** disable the `plugin` template function or implement an allowlist for template functions
2. **Urgently** replace `filepath.HasPrefix` with a proper path containment check
3. Add symlink resolution and re-validation in all filesystem API operations
4. Add host/IP allowlisting for artifact downloads
5. Apply `PathEscapesAllocDir` after environment variable interpolation, not before
