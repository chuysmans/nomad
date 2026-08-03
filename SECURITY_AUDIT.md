# Security Audit Report: HashiCorp Nomad v0.9.2

**Audit Date:** 2026-08-03
**Scope:** Cryptography, secrets handling, infrastructure/configuration vulnerabilities
**Codebase:** HashiCorp Nomad v0.9.2 (commit 68cf7506a)

---

## Summary

This audit identified **13 findings** across the Nomad v0.9.2 codebase, ranging from Critical to Informational severity. The most severe issues involve insecure defaults that leave deployments vulnerable out-of-the-box, TLS hostname verification bypass, and race conditions in security-critical token operations.

| Severity | Count |
|----------|-------|
| Critical | 3     |
| High     | 4     |
| Medium   | 4     |
| Low      | 2     |

---

## Findings

### FINDING-01: TLS Hostname Verification Disabled by Default (InsecureSkipVerify=true)

- **Severity:** Critical
- **Location:** `helper/tlsutil/config.go`, lines 236-244
- **Title:** Outgoing TLS connections set InsecureSkipVerify=true unless VerifyServerHostname is explicitly enabled
- **Description:** In `OutgoingTLSConfig()`, the TLS configuration is created with `InsecureSkipVerify: true` on line 238. This is only set to `false` if `VerifyServerHostname` is explicitly enabled (line 243-245). When `VerifyOutgoing` is true but `VerifyServerHostname` is false (which is the default), all outgoing TLS connections will accept any certificate regardless of hostname, enabling man-in-the-middle attacks.
- **Impact:** An attacker who can intercept network traffic between Nomad servers or between client and server can present any valid CA-signed certificate (even one for a completely different domain) and successfully impersonate a Nomad server. This enables full man-in-the-middle attacks: reading/modifying all RPC traffic including job submissions, secret material, and ACL tokens.
- **Attack Path:**
  1. Attacker positions themselves on the network between Nomad agents (ARP spoofing, BGP hijack, compromised switch, cloud VPC misconfiguration)
  2. Attacker obtains any certificate signed by the same CA (e.g., a certificate for a web server in the same PKI)
  3. Attacker presents this certificate during TLS handshake
  4. Nomad accepts the certificate because `InsecureSkipVerify=true` — no hostname check
  5. Attacker intercepts all RPC traffic: job submissions, Vault tokens, ACL tokens
- **Evidence:**
  ```go
  // helper/tlsutil/config.go:236-244
  tlsConfig := &tls.Config{
      RootCAs:                  x509.NewCertPool(),
      InsecureSkipVerify:       true,   // <-- Always true initially
      CipherSuites:             c.CipherSuites,
      MinVersion:               c.MinVersion,
      PreferServerCipherSuites: c.PreferServerCipherSuites,
  }
  if c.VerifyServerHostname {
      tlsConfig.InsecureSkipVerify = false  // Only fixed if this is explicitly set
  }
  ```
- **Remediation:** Default `InsecureSkipVerify` to `false`. When `VerifyOutgoing` is true, hostname verification should also be enabled by default. The custom verification in `WrapTLSClient` (lines 311-351) only checks CA signature but not hostname, which is insufficient.

---

### FINDING-02: ACL System Disabled by Default — Unauthenticated Full Cluster Access

- **Severity:** Critical
- **Location:** `nomad/config.go`, line 259; `command/agent/config.go`, line 626
- **Title:** ACL enforcement is disabled by default, allowing any network-reachable client full cluster control
- **Description:** The `ACLEnabled` field defaults to `false` in `DefaultConfig()` (nomad/config.go). No ACL configuration is set in the agent's `DefaultConfig()` either. This means fresh Nomad deployments have zero authentication or authorization. Any client that can reach the HTTP API or RPC port can submit jobs (including privileged ones), read all data, drain nodes, and modify cluster state.
- **Impact:** Complete cluster compromise. Any user or service on the network can submit arbitrary workloads, access secrets, drain nodes, and read all job/allocation data.
- **Attack Path:**
  1. Attacker discovers Nomad HTTP API on port 4646 (bound to 0.0.0.0 by default — see FINDING-04)
  2. No ACL token required for any operation
  3. Attacker submits a privileged job with `raw_exec` driver
  4. Job executes arbitrary code on Nomad client nodes
  5. Full cluster and potentially host compromise
- **Evidence:**
  ```go
  // nomad/config.go:258-259
  // ACLEnabled controls if ACL enforcement and management is enabled.
  ACLEnabled bool  // defaults to false (zero value)
  ```
  ```go
  // client/client.go:848
  if !c.config.ACLEnabled {
      // No ACL enforcement
  ```
- **Remediation:** Enable ACL by default or require explicit opt-out. At minimum, emit a prominent warning at startup when ACLs are disabled. Consider requiring an explicit `acl { enabled = false }` to disable rather than using the zero value.

---

### FINDING-03: Vault Token Unauthenticated Access Enabled by Default

- **Severity:** Critical
- **Location:** `nomad/structs/config/vault.go`, lines 85-93
- **Title:** `allow_unauthenticated` defaults to `true`, letting any user submit jobs that request Vault tokens without proving Vault access
- **Description:** The `DefaultVaultConfig()` sets `AllowUnauthenticated` to `true`. When this is enabled, users can submit jobs requesting Vault policies without providing a Vault token proving they have access to those policies. The Nomad server will then use its own privileged Vault token to create child tokens with the requested policies.
- **Impact:** Privilege escalation via Vault. Any user who can submit a Nomad job (which is anyone if ACLs are also disabled) can request Vault tokens with arbitrary policies, potentially gaining access to all secrets stored in Vault.
- **Attack Path:**
  1. Attacker submits a Nomad job with a `vault` stanza requesting sensitive policies (e.g., `secret/production/*`)
  2. Because `allow_unauthenticated=true`, no Vault token is required from the submitter
  3. Nomad server creates a child token from its own privileged token with the requested policies
  4. Attacker's task receives a Vault token with access to sensitive secrets
  5. Attacker exfiltrates secrets from the running task
- **Evidence:**
  ```go
  // nomad/structs/config/vault.go:85-93
  func DefaultVaultConfig() *VaultConfig {
      return &VaultConfig{
          Addr:                "https://vault.service.consul:8200",
          ConnectionRetryIntv: DefaultVaultConnectRetryIntv,
          AllowUnauthenticated: func(b bool) *bool {
              return &b
          }(true),  // <-- defaults to true
      }
  }
  ```
  ```go
  // nomad/job_endpoint.go:142
  if !vconf.AllowsUnauthenticated() {
      // Only checked when AllowUnauthenticated is false
  ```
- **Remediation:** Default `AllowUnauthenticated` to `false`. Require job submitters to provide a valid Vault token proving they have access to the requested policies.

---

### FINDING-04: Default Bind Address 0.0.0.0 Exposes All Interfaces

- **Severity:** High
- **Location:** `command/agent/config.go`, line 626
- **Title:** Nomad binds to all network interfaces by default, exposing HTTP API, RPC, and Serf to all networks
- **Description:** `DefaultConfig()` sets `BindAddr` to `"0.0.0.0"`, causing all Nomad services (HTTP API on 4646, RPC on 4647, Serf on 4648) to listen on every network interface. Combined with disabled ACLs and no default TLS, this exposes the full Nomad API to any reachable network.
- **Impact:** Remote unauthenticated access to the cluster management API, RPC, and gossip protocol from any network the host is connected to, including potentially the public internet.
- **Attack Path:**
  1. Nomad deployed with default config on a host with a public IP
  2. Port scan reveals ports 4646/4647/4648 open on the public interface
  3. Attacker accesses HTTP API without authentication
  4. Full cluster control via unauthenticated API
- **Evidence:**
  ```go
  // command/agent/config.go:626
  BindAddr:   "0.0.0.0",
  ```
- **Remediation:** Default `BindAddr` to `127.0.0.1`. Require explicit configuration to bind to other interfaces.

---

### FINDING-05: CORS Wildcard Origin on Client Endpoints

- **Severity:** High
- **Location:** `command/agent/http.go`, lines 42-46, 165-168
- **Title:** `Access-Control-Allow-Origin: *` with `AllowedHeaders: *` is set on sensitive client endpoints
- **Description:** The CORS configuration uses wildcard origin (`*`) and wildcard headers (`*`) and is applied to filesystem, stats, and allocation endpoints. This allows any website to make cross-origin requests to these Nomad endpoints from a user's browser.
- **Impact:** If an operator has browser access to the Nomad API (common in internal networks), a malicious website can make cross-origin requests to the Nomad API using the operator's network position. This enables reading filesystem contents of allocations, viewing stats, and accessing allocation data.
- **Attack Path:**
  1. Operator browses to attacker-controlled website while on the internal network
  2. Malicious JavaScript makes fetch/XHR requests to `http://nomad-server:4646/v1/client/fs/...`
  3. CORS allows the request due to `Access-Control-Allow-Origin: *`
  4. Attacker's JavaScript reads allocation filesystem contents, including logs and potentially secrets
  5. Data is exfiltrated to the attacker's server
- **Evidence:**
  ```go
  // command/agent/http.go:42-46
  allowCORS = cors.New(cors.Options{
      AllowedOrigins: []string{"*"},
      AllowedMethods: []string{"HEAD", "GET"},
      AllowedHeaders: []string{"*"},
  })
  ```
  Applied to sensitive endpoints:
  ```go
  // command/agent/http.go:165-168
  s.mux.Handle("/v1/client/fs/", wrapCORS(s.wrap(s.FsRequest)))
  s.mux.Handle("/v1/client/stats", wrapCORS(s.wrap(s.ClientStatsRequest)))
  s.mux.Handle("/v1/client/allocation/", wrapCORS(s.wrap(s.ClientAllocRequest)))
  ```
- **Remediation:** Remove wildcard CORS origins. If cross-origin access is needed, configure specific allowed origins. At minimum, do not allow wildcard headers and consider restricting to the UI origin only.

---

### FINDING-06: TLS 1.0 and 1.1 Supported

- **Severity:** High
- **Location:** `helper/tlsutil/config.go`, lines 18-22
- **Title:** TLS 1.0 and TLS 1.1 are supported and configurable, enabling downgrade attacks
- **Description:** While the default minimum TLS version is 1.2 (line 468), TLS 1.0 and 1.1 are listed as supported versions and can be explicitly configured. Both versions have known vulnerabilities (BEAST, POODLE, Lucky13) and are deprecated by RFC 8996.
- **Impact:** If an operator configures `tls_min_version = "tls10"` or `"tls11"`, the cluster becomes vulnerable to known TLS attacks. An active network attacker could potentially downgrade connections.
- **Attack Path:**
  1. Operator sets `tls_min_version = "tls10"` in configuration
  2. Attacker performs active MITM and forces TLS 1.0 negotiation
  3. Attacker exploits BEAST/POODLE/Lucky13 to decrypt traffic
  4. Sensitive data (tokens, job specs, secrets) exposed
- **Evidence:**
  ```go
  // helper/tlsutil/config.go:18-22
  var supportedTLSVersions = map[string]uint16{
      "tls10": tls.VersionTLS10,
      "tls11": tls.VersionTLS11,
      "tls12": tls.VersionTLS12,
  }
  ```
- **Remediation:** Remove TLS 1.0 and 1.1 from the supported versions map. Only allow TLS 1.2+. If backward compatibility is required, log a strong warning when deprecated versions are configured.

---

### FINDING-07: CBC Mode Cipher Suites Supported (Vulnerable to Padding Oracle Attacks)

- **Severity:** High
- **Location:** `helper/tlsutil/config.go`, lines 32-37
- **Title:** Multiple CBC-mode cipher suites are in the supported list, vulnerable to padding oracle attacks
- **Description:** The supported cipher suites include six CBC-mode ciphers (e.g., `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256`, `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`). While these are not in the default list, they can be configured. CBC-mode ciphers in TLS are vulnerable to padding oracle attacks (Lucky13, POODLE variants).
- **Impact:** If an operator explicitly configures CBC cipher suites, traffic may be vulnerable to padding oracle attacks that can recover plaintext.
- **Evidence:**
  ```go
  // helper/tlsutil/config.go:32-37 (subset)
  "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
  "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
  "TLS_RSA_WITH_AES_128_CBC_SHA256":         tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
  "TLS_RSA_WITH_AES_128_CBC_SHA":            tls.TLS_RSA_WITH_AES_128_CBC_SHA,
  "TLS_RSA_WITH_AES_256_CBC_SHA":            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
  ```
  Additionally, non-ECDHE RSA key exchange suites (`TLS_RSA_WITH_*`) lack forward secrecy.
- **Remediation:** Remove CBC-mode and static RSA key exchange cipher suites from the supported list. Only allow AEAD ciphers (GCM, CHACHA20_POLY1305) with ephemeral key exchange (ECDHE).

---

### FINDING-08: Agent Self Endpoint Partial Config Leak

- **Severity:** Medium
- **Location:** `command/agent/agent_endpoint.go`, lines 76-91
- **Title:** `/v1/agent/self` returns full agent configuration with only Vault token redacted
- **Description:** The `AgentSelfRequest` handler returns a deep copy of the entire agent configuration. Only the Vault token is redacted (line 87). Other sensitive configuration fields are exposed, including: Consul tokens, TLS certificate paths, ACL replication tokens, bind addresses, internal network topology, and enabled features.
- **Impact:** Information disclosure that aids further attacks. An attacker with agent:read permission (or no permission if ACLs are disabled) can learn the full internal configuration of the cluster including network topology, enabled features, and the location of TLS key material on disk.
- **Attack Path:**
  1. Query `GET /v1/agent/self` (no auth needed if ACLs disabled)
  2. Extract Consul token, TLS cert/key file paths, bind addresses, datacenter layout
  3. Use gathered information to plan lateral movement or targeted attacks
- **Evidence:**
  ```go
  // command/agent/agent_endpoint.go:86-88
  if self.Config != nil && self.Config.Vault != nil && self.Config.Vault.Token != "" {
      self.Config.Vault.Token = "<redacted>"
  }
  // Only Vault token is redacted; all other config fields returned as-is
  ```
- **Remediation:** Redact all sensitive fields before returning the config: Consul tokens, ACL replication tokens, TLS key file paths, encrypt keys, and any other credential material. Consider returning only a sanitized subset of configuration.

---

### FINDING-09: Race Condition in DeriveVaultToken — Concurrent Map Write

- **Severity:** Medium
- **Location:** `nomad/node_endpoint.go`, lines 1435-1456
- **Title:** Concurrent goroutines write to unsynchronized `results` map in DeriveVaultToken
- **Description:** In `DeriveVaultToken`, multiple goroutines spawned via `errgroup` write to the shared `results` map (`results[task] = secret` on line 1450) without any synchronization (no mutex, no sync.Map). Go maps are not safe for concurrent writes, and this can cause a runtime panic ("concurrent map writes") or silent data corruption.
- **Impact:** Under concurrent token derivation for multiple tasks, this can cause the Nomad server to panic (crash), leading to denial of service. In rare cases, data corruption could cause a task to receive another task's Vault token, violating task isolation.
- **Attack Path:**
  1. Submit a job with many tasks requiring Vault tokens (>1 task)
  2. DeriveVaultToken is called, spawning multiple goroutines
  3. Goroutines race on writing to the shared `results` map
  4. Server panics with "concurrent map writes" or silently corrupts token assignments
  5. Potential: Task A receives Task B's Vault token, gaining access to policies it should not have
- **Evidence:**
  ```go
  // nomad/node_endpoint.go:1435-1455
  results := make(map[string]*vapi.Secret, len(args.Tasks))
  for i := 0; i < handlers; i++ {
      g.Go(func() error {
          for {
              select {
              case task, ok := <-input:
                  // ...
                  results[task] = secret  // RACE: concurrent write to shared map
              }
          }
      })
  }
  ```
- **Remediation:** Protect the `results` map with a `sync.Mutex`, or use a `sync.Map`, or collect results through a channel instead of writing to a shared map.

---

### FINDING-10: SHA-1 Used for Service and Check Identifiers

- **Severity:** Medium
- **Location:** `nomad/structs/structs.go`, lines 5026 and 5196
- **Title:** SHA-1 hash used for generating service and health check identifiers
- **Description:** Service identifiers and health check identifiers are generated using SHA-1 hashing. SHA-1 is cryptographically broken — practical collision attacks exist (SHAttered, 2017). While these hashes are used for identifiers rather than security decisions, collisions could cause identifier conflicts leading to service registration issues.
- **Impact:** An attacker who can craft job definitions with specific parameters could create SHA-1 collisions, causing two different services or checks to have the same identifier. This could lead to service hijacking in Consul, where a malicious service replaces a legitimate one.
- **Attack Path:**
  1. Attacker studies the hash input structure for Service.Hash()
  2. Crafts two services with different parameters but same SHA-1 hash (collision)
  3. Malicious service overwrites legitimate service registration in Consul
  4. Traffic intended for the legitimate service routes to the attacker's service
- **Evidence:**
  ```go
  // nomad/structs/structs.go:5026
  h := sha1.New()  // Used in ServiceCheck.Hash()

  // nomad/structs/structs.go:5196
  h := sha1.New()  // Used in Service.Hash()
  ```
- **Remediation:** Replace SHA-1 with SHA-256 for identifier generation.

---

### FINDING-11: MD5 and SHA-1 Accepted for Artifact Checksum Verification

- **Severity:** Medium
- **Location:** `nomad/structs/structs.go`, lines 6503-6506
- **Title:** Artifact downloads accept MD5 and SHA-1 checksums, which are vulnerable to collision attacks
- **Description:** The artifact checksum validation code accepts `md5` and `sha1` as valid checksum types. Both algorithms have known collision attacks. An attacker who compromises an artifact download source could substitute a malicious artifact with a matching MD5 or SHA-1 hash.
- **Impact:** An attacker could provide a malicious artifact (binary, script, config) with a matching weak checksum, and Nomad would accept it as valid. This leads to arbitrary code execution on client nodes.
- **Attack Path:**
  1. Attacker compromises or MITM's an artifact download URL
  2. Attacker crafts a malicious artifact with the same MD5/SHA-1 checksum as the legitimate one
  3. Nomad downloads and validates the artifact against the weak checksum
  4. Malicious artifact passes validation and is executed/used by the task
- **Evidence:**
  ```go
  // nomad/structs/structs.go:6502-6506
  switch checksumType {
  case "md5":
      expectedLength = md5.Size
  case "sha1":
      expectedLength = sha1.Size
  ```
- **Remediation:** Deprecate and eventually remove MD5 and SHA-1 checksum support. Require SHA-256 or SHA-512 for artifact verification. Log warnings when weak checksums are used.

---

### FINDING-12: Debug/pprof Endpoints Enabled in Dev Mode Without Authentication

- **Severity:** Low
- **Location:** `command/agent/http.go`, lines 208-214; `command/agent/config.go`, line 597
- **Title:** pprof debug endpoints are enabled via `enable_debug` without requiring authentication
- **Description:** When `EnableDebug` is true (always true in dev mode, configurable in production), the pprof endpoints are registered without any authentication check. These endpoints expose goroutine dumps, heap profiles, CPU profiles, and execution traces, which can reveal internal state, memory contents, and aid in exploitation.
- **Impact:** Information disclosure of server internals. Heap dumps may contain sensitive data (tokens, keys). CPU profiling can cause performance degradation (denial of service).
- **Attack Path:**
  1. Access `/debug/pprof/heap` to dump server memory
  2. Search heap dump for token strings, encryption keys, or secrets
  3. Use `/debug/pprof/profile` to consume CPU and degrade performance
- **Evidence:**
  ```go
  // command/agent/http.go:208-214
  if enableDebug {
      s.mux.HandleFunc("/debug/pprof/", pprof.Index)
      s.mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
      s.mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
      s.mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
      s.mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
  }
  ```
- **Remediation:** Require ACL authentication (agent:write) for pprof endpoints. Never enable debug endpoints by default in production.

---

### FINDING-13: Hardcoded Test Credentials in Vendor Dependencies

- **Severity:** Low
- **Location:** `vendor/github.com/circonus-labs/circonus-gometrics/checkmgr/check.go`, line 300
- **Title:** Hardcoded secret value in vendored dependency
- **Description:** A hardcoded secret string `"myS3cr3t"` exists in vendored code. While this is in a vendor dependency and not Nomad's own code, it could indicate a pattern where test credentials leak into production builds.
- **Impact:** Minimal direct impact as this is in vendored test/example code. However, if this pattern exists in dependencies, it could be exploited if those code paths are reachable.
- **Evidence:**
  ```go
  // vendor/github.com/circonus-labs/circonus-gometrics/checkmgr/check.go:300
  secret = "myS3cr3t"
  ```
- **Remediation:** Audit vendored dependencies for hardcoded credentials. Consider using tools like `trufflehog` or `gitleaks` in CI to catch credential patterns.

---

## Risk Summary and Prioritized Remediation

### Immediate Action Required (Critical)
1. **FINDING-01:** Fix TLS hostname verification — set `InsecureSkipVerify=false` by default
2. **FINDING-02:** Enable ACL by default or add strong startup warnings
3. **FINDING-03:** Set `allow_unauthenticated=false` as the Vault default

### Short-term (High)
4. **FINDING-04:** Change default bind address to `127.0.0.1`
5. **FINDING-05:** Remove wildcard CORS origins
6. **FINDING-06:** Remove TLS 1.0/1.1 from supported versions
7. **FINDING-07:** Remove CBC cipher suites from supported list

### Medium-term (Medium)
8. **FINDING-08:** Redact all sensitive config fields in `/v1/agent/self`
9. **FINDING-09:** Fix concurrent map write race in DeriveVaultToken
10. **FINDING-10:** Replace SHA-1 with SHA-256 for identifiers
11. **FINDING-11:** Deprecate MD5/SHA-1 artifact checksums

### Maintenance (Low)
12. **FINDING-12:** Require ACL auth for debug endpoints
13. **FINDING-13:** Audit vendored dependencies for credentials
