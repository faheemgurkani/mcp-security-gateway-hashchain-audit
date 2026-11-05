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

### D-003 · 2026-11-06 · proposed (awaiting owner approval)
**Context:** MCP gateways and hash-chained agent loggers both already exist (see notes/02).
**Decision:** position the project as *agent-proof logging*: the recorder sits outside the agent's trust boundary, with an external anchor and a standalone verifier. Ship four deliverables: drop-in stdio proxy, open log format + verifier, attack test suite mapped to OWASP ASI, and threat model write-up. The weekend MVP is the proxy, a basic verifier and a few attack cases.
**Rationale:** it differentiates from in-process audit SDKs; it is directly useful to the Apart Track 4.2 forensics work; the format and test suite are things others can build on.
