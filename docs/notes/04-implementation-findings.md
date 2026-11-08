# 04: Implementation findings

A running log of what was learned while building and testing: surprises, SDK quirks, failed approaches and measured results. Newest entries go at the bottom, dated, with the milestone tag.

---

- 2026-11-08 [Step 0] Environment: Docker 28.3.2, Compose v2.38.2, Python 3.14.6, uv 0.13.0 on macOS arm64. `claude` CLI available; `codex` not installed.
- 2026-11-09 [M1] The MCP Python SDK is at **2.3.0** (v2 API). Big changes from v1 tutorials:
  - The low-level `Server` takes handlers as constructor args (`on_list_tools=`, `on_call_tool=`) with shape `async (ctx, params) -> result`.
  - **v2 no longer validates tool arguments against the input schema.** It is advertised but never applied, so validation is entirely our job. That confirms the Pydantic layer is needed.
  - `ctx.request` exposes the HTTP request, so the gateway can read the session token from headers.
  - The client is a single `mcp.Client(url | StdioServerParameters | server)`. HTTP headers go on an `httpx2.AsyncClient` passed to `streamable_http_client`.
  - An unexpected exception in a handler becomes a sanitized `-32603`. To deny with a readable reason, return `CallToolResult(is_error=True)`.
- 2026-11-09 [M2] Audit-core design details:
  - **Integer `ts_ms`** instead of float seconds, so canonical number formatting can never be a source of MAC mismatches.
  - The chain **resumes** after a restart (continues seq and prev_mac) instead of starting a new chain, so a restart can't be used to hide a deletion. A `proxy_start` entry marks it.
  - **The anchor is the only defence against clean truncation.** Test `test_truncation_only_caught_by_anchor` shows that a log cut at an entry boundary verifies fine without it.
  - **HMAC limitation:** verifying needs the same secret key as writing, so third parties can't verify without being able to forge. Ed25519 signatures would fix this (afr does that); noted as a later upgrade.
  - Writes use `O_APPEND` and `fsync` per entry. Any OS error raises `AuditWriteError` so the proxy fails closed.
- 2026-11-09 [M3] Policy, validation and identity:
  - **Schemas are hand-written Pydantic models per tool, with `extra="forbid", strict=True`.** "strict" matters: without it Pydantic would coerce `1234` to `"1234"`. A tool with no registered schema is denied, so adding a tool upstream doesn't silently widen the attack surface. Trade-off: every tool needs a model. Generating models from the upstream JSON schema would be more generic, but then a rug-pulled schema would be trusted. Pinning covers part of that.
  - The policy uses `fnmatchcase` patterns (`crm.*`). A test makes sure `crmX.lookup` doesn't match `crm.*`.
  - The session registry stores **SHA-256 of tokens**, never plain tokens, so reading the gateway config doesn't hand out credentials.
  - Impersonation fields (`role`, `as_user`, …) are rejected by the strict schema *and* named separately, so the log can record the attempt as `impersonation_attempt` rather than as a generic validation error. That matters for the scorecard (A7: "blocked + logged").
  - Pinning quarantines both changed definitions and **new, unpinned tools** that appear after start.
- 2026-11-09 [M4] Reference gateway, end to end:
  - **Pipeline order** is authenticate → reject identity fields → pin check → policy → validate → log `call_request` → forward → log `call_result`. Cheap, identity-related checks run first, so a forged token never touches upstream.
  - **Every denial is logged before it is returned.** If logging a denial fails, the call is still denied, because nothing executed. If logging a `call_request` fails, the call is **not forwarded** (fail closed). If the result can't be logged, the result is withheld. The tool has already run in that case, which is an inherent limit: you can't un-execute a side effect.
  - **Ground-truth ledger:** the demo tool server writes every *executed* call to a ledger in the tool zone. The integration test asserts `#ledger entries == #call_request entries`. This is the completeness check the scorecard will use: a call in the ledger but not in the audit log means an undetected bypass.
  - **Rug pull** is simulated with `DEMO_RUG_PULL_AFTER=N`. The gateway re-lists upstream tools on every call (cheap here; in production it would be cached or triggered by `tools/list_changed`) and refuses the changed tool.
  - The audit log stores a hash of the raw arguments plus the *validated* arguments, and the full result plus its hash. In a real deployment, storing full arguments and results raises privacy and PII questions (see Stage 5); mcp-auth-gateway logs no arguments for this reason. Here, full detail helps forensics.
  - SDK detail: the low-level `Server.streamable_http_app()` returns a Starlette app with its own lifespan (the session manager). We **wrap** that lifespan so the upstream stdio client, the `proxy_start` entry and the heartbeat task live exactly as long as the HTTP server.
  - Gotcha: the repo path contains spaces, so the upstream command is parsed with `shlex`; build it with `shlex.join`.
  - Gotcha: the first heartbeat check failed because the whole scenario ran in under one heartbeat interval. Heartbeats are periodic, so tests must wait at least one interval.
  - Still open for M5: `streamable_http_app(host=...)` drives DNS-rebinding protection (Host-header checks). Inside Docker the Host header will be `gateway:8000`, which needs checking when the lab comes up.
- 2026-11-09 [M5] Lab infrastructure (Docker Compose):
  - **Tool zone is a separate container over Streamable HTTP**, not a stdio child of the gateway. With stdio inside the gateway container there'd be no tool endpoint at all, so A6 ("call the tool server directly") would be trivially unreachable and say nothing about real deployments, where tool servers are usually network services. Now `tools` sits on an `internal: true` network the agent isn't attached to, and it also requires a gateway-only bearer token (defence in depth: if the network were misconfigured, the agent still lacks the token).
  - **Separate UIDs per zone** (gateway 10001, tools 10002, agent 10003). The audit log, anchor and key exist only in the gateway container; the ledger only in tools. Named volumes take their ownership from the image directories.
  - **The agent's MCP config (`/home/agent/mcp.json`) is a writable bind mount**, like a real host's config. It holds the gateway URL and the agent's user token. A4 edits it.
  - **Secrets per run:** `lab/setup.py` rotates the HMAC key, tokens and upstream token into `lab/.run/` (git-ignored). Only token hashes reach the gateway. The admin token and key copy go to `operator/`, which is never mounted into the agent.
  - **DNS-rebinding protection:** the SDK auto-enables Host-header checks only when bound to localhost. In Docker the Host is `gateway:8000`, so the gateway takes `--allowed-host gateway:*` and enables the check explicitly instead of turning it off.
  - **Observer** runs on the host. It copies the log and anchor out with `docker compose cp` (which works even after the gateway is killed), reads the tool ledger, and pulls `docker events` for kill, stop and restart actions.
  - **First real catch:** rebuilding the image recreated the gateway container. The log resumed on its volume, and the verifier flagged the 11 s silence as `time_gap` at the exact seq. This is the A5 detection path, working on the live lab.
  - Gotchas: Docker Desktop wasn't running (`open -a Docker`, ~15 s to come up). Three services that each declared `build:` with the same image tag raced and failed ("image already exists"), so the image is now built once (`make lab-image`) with `pull_policy: never`. A failed connection from the SDK client surfaces as an `ExceptionGroup`, not a plain `ConnectError`, so the harness must not rely on the exception type and should use the ledger as ground truth.
