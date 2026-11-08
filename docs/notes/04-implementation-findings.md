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
