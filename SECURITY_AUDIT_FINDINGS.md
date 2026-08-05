# Security Audit: Nomad v0.9.2 — Authentication & Authorization Vulnerabilities

**Audit Date:** 2026-08-03
**Scope:** ACL bypass, token handling, unauthenticated endpoints, IDOR/privilege escalation, client ACL cache

---

## Finding 1: Conditional ACL Checks Bypass When ACLs Are Disabled

**Severity:** CRITICAL

**Location:** `nomad/acl.go`, `command/agent/agent_endpoint.go`, and all RPC endpoints

**Title:** All ACL enforcement is conditional on `ACLEnabled` — returning `nil` ACL object silently grants full access

**Description:**
`Server.ResolveToken()` in `nomad/acl.go:15-36` returns `(nil, nil)` when `ACLEnabled` is `false`. Every single RPC endpoint that consumes this result uses the pattern `if aclObj != nil && !aclObj.Allow...()` — meaning a `nil` ACL object silently passes all authorization checks. This is the designed behavior for "ACLs disabled" mode, but it creates a systemic risk: any misconfiguration that leaves `ACLEnabled = false` (the default) exposes the entire cluster without authentication. There is no defense-in-depth or fail-closed behavior.

**Impact:**
Complete unauthenticated access to all Nomad operations including job submission, node management, secret viewing, and cluster administration when ACLs are not explicitly enabled.

**Attack Path:**
1. Connect to any Nomad HTTP API endpoint without providing an `X-Nomad-Token` header
2. All operations succeed because `ResolveToken("")` returns `(nil, nil)`
3. The `aclObj != nil` guard evaluates to `false`, skipping authorization entirely

**Evidence:**
- `nomad/acl.go:17-19`: `if !s.config.ACLEnabled { return nil, nil }`
- `nomad/job_endpoint.go:88`: `} else if aclObj != nil {` (skip if nil)
- `nomad/system_endpoint.go:27`: `} else if acl != nil && !acl.IsManagement() {`
- `nomad/operator_endpoint.go:30`: `} else if aclObj != nil && !aclObj.IsManagement() {`
- Pattern repeated across 50+ RPC methods in `nomad/*.go`

**Remediation:**
Consider a fail-closed design where `ResolveToken` returns a deny-all ACL object instead of nil when ACLs are disabled, or add explicit documentation/warnings on startup that ACLs are not enabled. At minimum, add a startup warning log when `ACLEnabled = false`.

---

## Finding 2: Agent Join Endpoint Has No ACL Check

**Severity:** CRITICAL

**Location:** `command/agent/agent_endpoint.go`

**Title:** `/v1/agent/join` allows unauthenticated cluster membership manipulation

**Description:**
The `AgentJoinRequest` handler at `command/agent/agent_endpoint.go:93-116` does not perform any ACL check. It does not call `parseToken`, `ResolveToken`, or any authorization method. Any caller can instruct the agent to join arbitrary server addresses.

**Impact:**
An unauthenticated attacker can cause a Nomad server to join a rogue cluster or inject malicious server addresses, enabling man-in-the-middle attacks, cluster disruption, or data exfiltration by redirecting Raft traffic.

**Attack Path:**
1. `PUT /v1/agent/join?address=attacker-controlled-server:4648`
2. No token required — handler accepts the request directly
3. Nomad server attempts to join the attacker's cluster
4. Attacker can intercept Raft replication, inject jobs, or disrupt consensus

**Evidence:**
- `command/agent/agent_endpoint.go:93-116`: Full handler — no `parseToken`, no `ResolveToken`, no ACL check of any kind
- Compare to `AgentForceLeaveRequest` at line 136-164 which properly calls `parseToken` and checks `AllowAgentWrite()`

**Remediation:**
Add `parseToken` and `ResolveToken` with `AllowAgentWrite()` check, matching the pattern used by `AgentForceLeaveRequest`.

---

## Finding 3: Metrics Endpoint Fully Unauthenticated

**Severity:** HIGH

**Location:** `command/agent/metrics_endpoint.go`

**Title:** `/v1/metrics` exposes operational telemetry without authentication

**Description:**
The `MetricsRequest` handler at `command/agent/metrics_endpoint.go:19-30` performs no ACL check whatsoever. It does not call `parseToken` or `ResolveToken`. The handler exposes all Nomad operational metrics in JSON or Prometheus format.

**Impact:**
Unauthenticated information disclosure of cluster operational data including: job counts, allocation statistics, RPC timings, Raft metrics, memory/CPU usage, and custom application metrics. This data enables reconnaissance for targeted attacks.

**Attack Path:**
1. `GET /v1/metrics` or `GET /v1/metrics?format=prometheus`
2. No token required
3. Full metric data returned including internal cluster state

**Evidence:**
- `command/agent/metrics_endpoint.go:19-30`: No token parsing or ACL check
- `command/agent/http.go:178`: Registered without any wrapper beyond `s.wrap()`

**Remediation:**
Add `parseToken` and `ResolveToken` with `AllowAgentRead()` check.

---

## Finding 4: Status Leader/Peers Endpoints Unauthenticated

**Severity:** MEDIUM

**Location:** `command/agent/status_endpoint.go`, `nomad/status_endpoint.go`

**Title:** `/v1/status/leader` and `/v1/status/peers` expose cluster topology without authentication

**Description:**
Both `StatusLeaderRequest` and `StatusPeersRequest` at `command/agent/status_endpoint.go:9-44` pass tokens via `s.parse()` but the backing RPC methods `Status.Leader` and `Status.Peers` at `nomad/status_endpoint.go:43-78` perform no ACL checks. The `Status.Members` method at line 82 does check ACLs, showing these two were intentionally or accidentally left open.

**Impact:**
Information disclosure of Raft leader address, all peer addresses, and cluster topology. Enables targeted network attacks against specific cluster members.

**Attack Path:**
1. `GET /v1/status/leader` — returns leader IP:port
2. `GET /v1/status/peers` — returns all peer IP:port addresses
3. No authentication required at the RPC layer

**Evidence:**
- `nomad/status_endpoint.go:43-58`: `Status.Leader` — no `ResolveToken` call
- `nomad/status_endpoint.go:61-78`: `Status.Peers` — no `ResolveToken` call
- `nomad/status_endpoint.go:82-86`: `Status.Members` — properly checks ACL (shows inconsistency)

**Remediation:**
Add `ResolveToken` checks to `Status.Leader` and `Status.Peers` requiring at minimum node:read or operator:read permission.

---

## Finding 5: Debug/pprof Endpoints Expose Runtime Internals Without ACL

**Severity:** HIGH

**Location:** `command/agent/http.go`

**Title:** `/debug/pprof/*` endpoints bypass ACL system entirely when debug mode is enabled

**Description:**
When `enableDebug` is true, pprof handlers are registered at `command/agent/http.go:208-214` using raw `pprof.Index`, `pprof.Profile`, etc. These handlers are registered directly with `s.mux.HandleFunc` and NOT wrapped with `s.wrap()`, meaning they completely bypass the Nomad HTTP middleware including any future ACL checks that might be added to `wrap()`.

**Impact:**
Full Go runtime profiling data including: goroutine stacks (may contain secrets in memory), heap profiles (may contain tokens, passwords), CPU profiles, and execution traces. This can leak sensitive data from server memory including ACL tokens and Vault tokens.

**Attack Path:**
1. Enable `enable_debug = true` in Nomad config (common in pre-production)
2. `GET /debug/pprof/heap` — heap memory dump containing secrets
3. `GET /debug/pprof/goroutine?debug=1` — goroutine stacks with request contexts
4. No authentication of any kind

**Evidence:**
- `command/agent/http.go:208-214`: pprof handlers registered without `s.wrap()`
- `command/agent/http.go:276`: `wrap()` is the standard handler wrapper, not used for pprof

**Remediation:**
Wrap pprof handlers with `s.wrap()` and add ACL checks requiring management token, or add a separate authentication check in a custom pprof wrapper.

---

## Finding 6: ACL Bootstrap Race Condition (TOCTOU)

**Severity:** HIGH

**Location:** `nomad/acl_endpoint.go`

**Title:** Bootstrap endpoint has a time-of-check-time-of-use race between snapshot check and Raft apply

**Description:**
The `ACL.Bootstrap` method at `nomad/acl_endpoint.go:342-414` performs an early check via `state.CanBootstrapACLToken()` at line 365, then proceeds to generate a new management token and apply it via Raft at line 394. Between the snapshot check and the Raft apply, there is a window where multiple concurrent bootstrap requests could pass the check. Although the state store's `BootstrapACLTokens` method at `nomad/state/state_store.go:3984` re-checks within the transaction, the Raft serialization means only one will succeed — but the race window exists and the loser gets an opaque error rather than a clean rejection.

Additionally, the bootstrap reset mechanism reads from a file at `<data-dir>/acl-bootstrap-reset` (line 371, `fileBootstrapResetIndex()`). If an attacker gains filesystem access to the data directory, they can write the reset index value and re-bootstrap the cluster to obtain a new management token, fully taking over ACL.

**Impact:**
An attacker with filesystem access to the data directory can reset the bootstrap, generate a new management token, and gain full cluster control. The TOCTOU race is lower risk since Raft serialization provides a backstop.

**Attack Path (filesystem):**
1. Read the reset index from the error message: `"ACL bootstrap already done (reset index: 42)"`
2. Write `42` to `<data-dir>/acl-bootstrap-reset`
3. `PUT /v1/acl/bootstrap` — generates new management token
4. Old management token remains valid; attacker has parallel admin access

**Evidence:**
- `nomad/acl_endpoint.go:365-380`: Early check then file-based reset
- `nomad/acl_endpoint.go:371-379`: `fileBootstrapResetIndex()` reads reset from predictable file path
- `nomad/acl_endpoint.go:417-440`: Reset file parsing in `fileBootstrapResetIndex()`
- The reset index is leaked in the error message at line 373

**Remediation:**
Do not leak the reset index in the error message. Consider requiring an existing management token to perform bootstrap reset. Ensure the data directory has restrictive filesystem permissions.

---

## Finding 7: Client ACL Token Cache Extends Revoked Tokens on Server Unreachability

**Severity:** HIGH

**Location:** `client/acl.go`

**Title:** Client-side ACL cache uses stale tokens when servers are unreachable, allowing revoked tokens to remain valid

**Description:**
The `resolveTokenValue` method at `client/acl.go:110-150` caches ACL tokens for `ACLTokenTTL` (default 30 seconds). When the cache expires and the server cannot be reached, the client falls back to the expired cached value at line 136-139: `"failed to resolve token, using expired cached value"`. This means a revoked or deleted token continues to grant access on the client for as long as the server is unreachable.

The same pattern exists for policy resolution at `client/acl.go:156-219` — expired policies are used when server communication fails (line 200-204).

**Impact:**
A token that has been revoked on the server continues to authorize operations on Nomad clients indefinitely during network partitions or server outages. An attacker who obtains a token can use it even after revocation by inducing or waiting for a network partition.

**Attack Path:**
1. Obtain a valid ACL token (even temporarily)
2. Token gets cached on a Nomad client
3. Token is revoked on the server
4. Attacker causes network partition between client and server (or waits for one)
5. Client falls back to cached (now revoked) token — access continues indefinitely

**Evidence:**
- `client/acl.go:117-123`: Token cached with TTL
- `client/acl.go:134-141`: On RPC error, expired cached value is used with a warning log only
- `client/acl.go:199-204`: Same pattern for policy cache

**Remediation:**
Implement a maximum staleness limit beyond which cached tokens are rejected even if the server is unreachable. Consider a hard upper bound (e.g., 5 minutes) after which the client should deny requests rather than use stale tokens.

---

## Finding 8: Jobs Parse Endpoint Has No Authentication

**Severity:** MEDIUM

**Location:** `command/agent/job_endpoint.go`

**Title:** `/v1/jobs/parse` parses HCL job specs without any ACL check

**Description:**
The `JobsParseRequest` handler at `command/agent/job_endpoint.go:566-589` does not call `parseWriteRequest`, `parseToken`, or any authentication method. It accepts arbitrary HCL input and parses it using `jobspec.Parse`. While this is a "read-only" operation, it can be used to probe for parser vulnerabilities and consumes server resources.

**Impact:**
Unauthenticated resource consumption and potential for parser exploitation. An attacker can send maliciously crafted HCL to probe for parser bugs or cause resource exhaustion.

**Attack Path:**
1. `PUT /v1/jobs/parse` with body `{"JobHCL": "<crafted input>"}`
2. No authentication required
3. Server parses arbitrary input

**Evidence:**
- `command/agent/job_endpoint.go:566-589`: No token parsing or ACL check
- `command/agent/http.go:142`: Registered at `/v1/jobs/parse`

**Remediation:**
Add `parseWriteRequest` and RPC-level ACL check requiring at least namespace:read-job capability.

---

## Finding 9: Validate Job Endpoint Has No Authentication

**Severity:** MEDIUM

**Location:** `command/agent/job_endpoint.go`

**Title:** `/v1/validate/job` validates job specs without ACL check at the HTTP layer

**Description:**
The `ValidateJobRequest` handler at `command/agent/job_endpoint.go:163-193` calls `parseWriteRequest` (which does parse the token), but the RPC method `Job.Validate` does not perform an ACL check. The token is parsed but never verified.

**Impact:**
Unauthenticated job validation leaks information about cluster configuration (Sentinel policies, constraint validation) and consumes server resources.

**Attack Path:**
1. `PUT /v1/validate/job` with an arbitrary job spec
2. Token is parsed but not checked server-side
3. Validation response reveals cluster configuration details

**Evidence:**
- `command/agent/job_endpoint.go:163-193`: Calls `parseWriteRequest` but RPC doesn't verify
- No corresponding `ResolveToken` in `Job.Validate` RPC method

**Remediation:**
Add ACL check in the `Job.Validate` RPC method.

---

## Finding 10: ACL ResolveToken RPC Has No Authorization Check

**Severity:** HIGH

**Location:** `nomad/acl_endpoint.go`

**Title:** `ACL.ResolveToken` RPC returns full token details including SecretID without authorization

**Description:**
The `ACL.ResolveToken` RPC method at `nomad/acl_endpoint.go:798-835` accepts a `SecretID` and returns the full ACL token object including the `SecretID` itself. It performs no authorization check — any caller who knows a SecretID can confirm it is valid and retrieve the associated token metadata (policies, type, name). This is used by clients for token resolution, but it is also exposed via `/v1/acl/token/self` which makes it accessible over HTTP.

**Impact:**
Token validation oracle — an attacker can confirm whether a guessed or leaked SecretID is valid without needing any existing authentication. Combined with UUID prediction or brute force, this could enumerate valid tokens.

**Attack Path:**
1. `GET /v1/acl/token/self` with `X-Nomad-Token: <guessed-secret-id>`
2. RPC calls `ACL.ResolveToken` with the secret
3. If valid: returns 200 with full token details
4. If invalid: returns 404
5. Binary response allows brute-force token enumeration

**Evidence:**
- `nomad/acl_endpoint.go:798-835`: No `ResolveToken`/ACL check on the RPC itself
- `command/agent/acl_endpoint.go:212-233`: `aclTokenSelf` passes the auth token as SecretID

**Remediation:**
This is partially by design (self-lookup), but consider rate-limiting the endpoint and adding monitoring for enumeration attempts.

---

## Finding 11: Health Endpoint Unauthenticated

**Severity:** MEDIUM

**Location:** `command/agent/agent_endpoint.go`

**Title:** `/v1/agent/health` exposes cluster health status without authentication

**Description:**
The `HealthRequest` handler at `command/agent/agent_endpoint.go:304-381` does not perform any ACL check. While it calls `s.parse()` which parses the token, the health check logic itself does not use the token for authorization. It reveals whether the server has a leader, whether the client has known servers, and the overall health state.

**Impact:**
Information disclosure of cluster health status useful for reconnaissance. Attackers can determine when the cluster is in a degraded state (no leader, no known servers) which is the optimal time to attack.

**Attack Path:**
1. `GET /v1/agent/health`
2. Response reveals cluster health, leader status, client connectivity
3. No authentication required

**Evidence:**
- `command/agent/agent_endpoint.go:304-381`: No `ResolveToken` or ACL check after parsing

**Remediation:**
Add ACL check requiring at minimum `agent:read` permission.

---

## Finding 12: Region List Endpoint Unauthenticated at RPC Level

**Severity:** LOW

**Location:** `command/agent/region_endpoint.go`, `nomad/region_endpoint.go`

**Title:** `/v1/regions` exposes federated region list without authentication

**Description:**
The `RegionListRequest` handler at `command/agent/region_endpoint.go:9-24` forwards to the `Region.List` RPC which does not perform ACL checks. This reveals the names and existence of all federated Nomad regions.

**Impact:**
Minor information disclosure of cluster federation topology.

**Evidence:**
- `command/agent/region_endpoint.go:9-24`: No ACL check at HTTP layer
- The `Region.List` RPC does not check tokens

**Remediation:**
Consider adding a basic ACL check, though this is commonly left open for service discovery purposes.

---

## Summary Table

| # | Severity | Location | Title |
|---|----------|----------|-------|
| 1 | CRITICAL | `nomad/acl.go` | Conditional ACL checks bypass when ACLs disabled |
| 2 | CRITICAL | `command/agent/agent_endpoint.go` | Agent Join endpoint unauthenticated |
| 3 | HIGH | `command/agent/metrics_endpoint.go` | Metrics endpoint unauthenticated |
| 4 | MEDIUM | `nomad/status_endpoint.go` | Status Leader/Peers unauthenticated |
| 5 | HIGH | `command/agent/http.go` | pprof endpoints bypass ACL entirely |
| 6 | HIGH | `nomad/acl_endpoint.go` | Bootstrap race condition + reset index leak |
| 7 | HIGH | `client/acl.go` | Stale token cache extends revoked tokens |
| 8 | MEDIUM | `command/agent/job_endpoint.go` | Jobs Parse endpoint unauthenticated |
| 9 | MEDIUM | `command/agent/job_endpoint.go` | Validate Job endpoint no server-side ACL |
| 10 | HIGH | `nomad/acl_endpoint.go` | ResolveToken RPC has no authorization |
| 11 | MEDIUM | `command/agent/agent_endpoint.go` | Health endpoint unauthenticated |
| 12 | LOW | `command/agent/region_endpoint.go` | Region List unauthenticated |
