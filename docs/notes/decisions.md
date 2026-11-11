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

### D-010 · 2026-11-09 · accepted
**Context:** with only the isolated reference setup, every attack is simply "blocked". That doesn't show *which* defence does the work, or how a typical deployment fares.
**Decision:** run every scenario against three **deployment profiles** of the same gateway code:
- `reference`: isolated zones.
- `breach`: the agent can write to the log volume, but has no key and no anchor.
- `colocated`: the gateway runs as the agent's own user, with the log, key, anchor and tool credential on the agent's disk. This is the usual real-world wrapper setup.
**Rationale:** it separates the value of isolation (reference vs colocated) from the value of the cryptographic layer (breach). The colocated profile also serves as the baseline that external gateways will be compared against in M8.

### D-011 · 2026-11-09 · accepted
**Decision:** the scripted attacker is the **strongest one the lab can justify**. It discovers targets itself (filesystem and `/proc` search, never handed paths). If it finds the key, it stops the gateway, rewrites the log with a recomputed chain and anchor, fills time gaps with forged heartbeats, and restarts the gateway with its original command line.
**Rationale:** a weak attacker makes defences look better than they are. The first colocated run showed truncation "detected" only because of an incidental time gap; a key-holding attacker can trivially forge heartbeats, so we model that.

### D-012 · 2026-11-09 · accepted
**Context:** the real-LLM runs showed the agent never even discovered `admin.delete_user`, because a user session's `tools/list` is role-filtered.
**Decision:** keep tool-list filtering by role as a first-class control, not just call-time authorization, and report it as defence in depth. Keep the real-LLM scorecard as a *lower bound* alongside the scripted *upper bound*, rather than replacing one with the other.
**Rationale:** hiding a tool's existence reduces what an agent can target; measuring both bounds is more honest than reporting only the strongest attacker or only a given model.

### D-013 · 2026-11-09 · accepted
**Context:** M8 scores third-party gateways, which raises disclosure questions.
**Decision:** (1) external gateways are driven in their native transport (stdio proxies run as a subprocess), not forced into the HTTP slot; attacks that don't apply to a transport are documented, not faked. (2) Results are framed as a **capability comparison**, never a vulnerability claim, unless a gateway fails a guarantee it actually makes — in which case contact the maintainer privately before any public writeup. Record each gateway's version.
**Rationale:** honest, reproducible comparison; respects maintainers of responsibly-scoped tools; avoids overclaiming.

### D-014 · 2026-11-09 · accepted
**Context:** owner asked to test the latest open-weight models, especially those claiming stronger safeguards.
**Decision:** test five — `openai/gpt-oss-safeguard-20b` (the only open, tool-capable model advertising a safeguard focus) plus the newest flagships from four other vendors (kimi-k3.1-pro, deepseek-v4.1-flash-1017, qwen3.8-flash, glm-5.3) — into a separate results file, keeping the gpt-oss-120b baseline intact. Budget guard cap $6 / floor $4.
**Rationale:** covers both "most recent" and "most safety-oriented"; vendor diversity; a separate file keeps the baseline reproducible and the new run re-runnable.

### D-015 · 2026-11-11 · accepted
**Context:** only one external gateway had been scored, with a one-off script, and the reference gateway's column in that comparison was hand-written.
**Decision:** one shared harness (`lab/adapters/harness.py`) scores every gateway, the reference gateway included, through the same attacks; an adapter is a small `Gateway(...)` description. Add **A12, rewrite the log and recompute the chain with the gateway's published algorithm (no key)**, because it is the attack that separates keyed or signed logs from plain hash chains. Each external gateway is installed in its own environment under `lab/.ext/` and pinned to the version scored.
**Rationale:** a measured reference column is more credible than a written one; a uniform harness makes the comparison fair and makes adding a gateway cheap; A12 tests the property that a "tamper-evident" log actually needs.

### D-016 · 2026-11-11 · accepted
**Context:** scoring more gateways turned up one whose measured behaviour differs from guarantees its documentation makes.
**Decision:** apply D-013 strictly: that gateway's adapter (`lab/adapters/embargoed.py`) and results (`lab/results/raw/`) stay git-ignored, the public scorecard says only that one more gateway was scored, and the owner contacts the maintainer privately before anything about it is published.
**Rationale:** responsible disclosure costs nothing here and protects both the maintainer's users and this project's credibility.

### D-017 · 2026-11-11 · accepted
**Context:** LLM-attacker evidence was 1–2 runs per cell.
**Decision:** raise every cell to 5 runs (6 models x 3 profiles x 3 framings), report a one-sided 95% Clopper-Pearson upper bound per model, and keep hand-written observations in `lab/scorecard/notes/*.md`, re-checked against the transcripts, instead of inside the report generator. Budget: cap $5 for the top-up, floor $5 left on the key.
**Rationale:** "0/N" means little without N; a bound states what the data supports. Prose inside a generator silently outlives the data it described.

### D-018 · 2026-11-11 · accepted
**Context:** the 5-model sweep showed agents reading the lab's own source in the agent image (`/app`), including the scripted attack code, and one run opened the git-ignored embargoed adapter, because the image copied all of `lab/`.
**Decision:** keep the gateway and lab **source** visible to the agent: a real attacker can read open-source code (Kerckhoffs), and hiding it would flatter the gateway. Exclude what an attacker should never see from the image via `.dockerignore`: embargoed adapters (D-016), past results and transcripts (`lab/results`), and external gateway installs (`lab/.ext`). Transcripts that touched embargoed material are redacted before commit, and scorecard notes say which successes read the lab's attack code.
**Rationale:** the threat model assumes a knowledgeable attacker; disclosure promises and the "answer key" of earlier runs are a different matter.
