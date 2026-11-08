# Decision log

Format per entry: **ID · date · status**, then Context / Options / Decision / Rationale.

---

### D-001 · 2026-11-06 · accepted
**Context:** A weekend-sized AI-security portfolio project that also supports the Apart sprint.
**Options:** the 12-stage list (prompt injection, RAG poisoning, PII proxy, PyRIT CI, and others).
**Decision:** combine Stage 3 (MCP tool security) and Stage 11 (audit and governance) into one MCP security gateway with a hash-chained audit log.
**Rationale:** one end-to-end story (attack, defence, proof); feeds the sprint's Track 4.2; fits a weekend. Stage 2 risks provider terms of service; Stages 9, 10 and 12 take weeks; Stage 8 is a later follow-up aimed at this gateway.

### D-002 · 2026-11-06 · accepted
**Decision:** repo name `mcp-security-gateway-hashchain-audit`; Python `src/` layout, with one package `mcp_gateway` split into `validation/`, `policy/`, `audit/` and `proxy/`.
**Rationale:** the name states the three technical pieces; each subpackage maps to one stage of the pipeline, so each can be tested on its own.

### D-003 · 2026-11-06 · superseded by D-004 (see notes/03 for why)
**Context:** MCP gateways and hash-chained agent loggers both already exist (see notes/02).
**Decision:** position the project as *agent-proof logging*: the recorder sits outside the agent's trust boundary, with an external anchor and a standalone verifier. Ship four deliverables: drop-in stdio proxy, open log format + verifier, attack test suite mapped to OWASP ASI, and threat model write-up. The weekend MVP is the proxy, a basic verifier and a few attack cases.
**Rationale:** it differentiates from in-process audit SDKs; it is directly useful to the Apart Track 4.2 forensics work; the format and test suite are things others can build on.

### D-004 · 2026-11-08 · accepted
**Context:** Independent validation (notes/03) found 15+ gateways with hash-chained logs, existing external anchoring and non-bypass designs, and outside-attacker suites (MCPSEC). There was no benchmark with the agent as the attacker.
**Decision:** the project becomes an **agent-as-attacker test lab**: reference gateway, adapters for existing gateways, scripted attack harness (A1–A11), observer and scorecard. Keep the repo name (owner's choice).
**Rationale:** the only clearly open gap; cites the Tübingen/Snyk trace-tampering result; still teaches Stages 3 and 11 through the reference gateway, and adds Stage 8.

### D-005 · 2026-11-08 · accepted
**Decision:** transport is MCP **Streamable HTTP** from agent to gateway; **stdio** from gateway to tool servers.
**Rationale:** a stdio wrapper launched by the agent's own config runs as the agent's user, so the agent can remove, bypass or kill it. HTTP across separate containers is a real boundary with one interceptable ingress. stdio behind the gateway is out of the agent's reach.

### D-006 · 2026-11-08 · accepted
**Decision:** the gateway issues an opaque session token bound to a role from server-side config. Any identity or role field in a request is ignored and logged as an impersonation attempt. No token passthrough.
**Rationale:** never trust identity the agent can write; the MCP spec names token passthrough as a confused-deputy cause.

### D-007 · 2026-11-08 · accepted
**Decision:** the audit log is JSONL with **RFC 8785** canonical JSON. Each entry has `seq`, `prev_mac` and an **HMAC-SHA256** `mac` (key held only by the gateway user). Heartbeat entries are written periodically, and a `proxy_start` entry records the policy and tool-definition hashes. The head is anchored to a store in the tool zone. The gateway fails closed if logging fails. Sigstore Rekor anchoring is a stretch goal.
**Rationale:** canonicalization avoids silent hash mismatches; the HMAC stops chain recomputation without the key; the anchor catches truncation; heartbeats catch kills; fail-closed preserves completeness.

### D-008 · 2026-11-08 · accepted
**Decision:** the platform is Docker Compose: agent, gateway and tool containers on two networks (`agent_net` and internal `tool_net`), non-root UIDs, plus an observer outside the zones. Attackers are scripted first; a real-LLM driver (owner's Claude API key) comes after M6.
**Rationale:** runs on a laptop, no cloud; network isolation makes "no route around the gateway" real and testable; scripted baselines are deterministic and free.

### D-009 · 2026-11-08 · accepted
**Decision:** during implementation, commit and push gradually as each step passes, as `faheemgurkani`, with no AI attribution. No force-push or history rewrite without asking.
