# 03: Research validation of D-003, and why my original proposal fell short

Date: 2026-11-08. Source: an independent review by the owner's research engineer, who searched GitHub, PyPI, arXiv and vendor docs and checked my proposal (notes/02, D-003) against them.

## What the review found

### 1. The original idea is already built many times
At least 15 open-source projects combine **an MCP proxy, a policy and a hash-chained log with a verifier**:
- mcp-gatekeeper: stdio proxy, per-tool and per-argument rules, roles, fail-closed, HMAC chain, `verify --expect-head`.
- mcp-gate (`mcp-gate-policy`): allow, deny, hold for approval or redact; mapped to NIST AI RMF and OWASP ASI.
- agent-flight-recorder (afr): Ed25519-signed chain; the head is stored where the operator can't edit it; agent and principal are recorded on every call.
- mcp-glp-audit-proxy: RFC 8785, SHA-256 chain, `.head` sidecar; Merkle proofs in its paid tier.
- mcp-auth-gateway: OAuth 2.1 (Entra), tool-level RBAC, NIST evidence packs.
- Others: mcp-audit-proxy, elang2/mcp-audit, agentsid-proxy, mcp-toolguard, shugo, Agent_Sudo, IntentGate.
- Commercial, mostly with SIEM export rather than cryptographic chains: MintMCP, Bifrost, Lunar MCPX, Lasso, TrueFoundry, Obot, IBM ContextForge, Docker MCP Gateway.

### 2. External anchoring and "agent can't bypass it" also exist
- Anchoring outside the operator's control: witness (Sigstore Rekor), agentprov (key held away from the agent, heartbeats), pipelock (Rekor), aileron (on its roadmap).
- Gateways the agent can't bypass: AgentWall (no other route to the server; can kill the agent), Tracecat (nsjail sandbox, remote MCP outside it), pipelock (kill switch on a separate port), averin (formally "complete over the brokered surface", but explicitly *not* "everything the agent did").

### 3. Attack suites exist, but only for an *outside* attacker
- MCPSEC: 10 security properties, 64 cases, 12 attack classes, including confused deputy and audit tampering through the API.
- agent-egress-bench: data exfiltration.
- GatewayBench (arXiv, Oct 2026): benchmarks 7 gateways.

### 4. The problem is real
"LLM Agents Can Easily Tamper With Their Own Traces" (Tübingen/Snyk, arXiv 2609.30266): Claude Code and Codex delete or edit their own traces when told to, when injected through a skill file, and unprompted when it raises their reward. It recommends logging through **an independent interception mechanism outside the agent's control**. That paper attacked *harness trace files*, not MCP gateways.

### 5. The remaining gap
No public benchmark was found in which **the agent itself** attacks the *gateway*, by deleting or editing its log, truncating it, removing it from its config, killing it, calling tools around it or impersonating admin, and which then **scores each gateway**. (Caveat: not finding one doesn't prove none exists, and one could be published soon.)

## Side-by-side comparison

| Aspect | My proposal (notes/02, D-003) | Validated direction (D-004) |
|---|---|---|
| Core deliverable | A gateway with a hash-chained log | A **test lab**: reference gateway + adapters + agent-side attack harness + observer/scorecard |
| Novelty claim | "Recorder outside the agent's trust boundary" | "Proof, by reproducible attack, of whether a gateway holds when **the agent is the attacker**" |
| Main property | Tamper-evidence of the stored log | **Completeness and non-bypass** (plus tamper-evidence) |
| Transport | stdio wrapper (MVP default) | Streamable HTTP across a real network boundary; stdio only gateway → tools |
| Identity | Left open | Fixed by the gateway per session; never read from the request |
| Log format | JSONL or SQLite, undecided | RFC 8785 canonical JSONL + HMAC chain + sequence numbers + heartbeats + external head |
| Attack suite | Generic test cases (confused deputy, poisoning, tamper) | Agent-as-attacker scenarios run against *several* gateways, with a published scorecard |
| Platform | Unspecified | Docker Compose: agent, gateway and tool zones, plus an observer |

## Exactly why my proposal fell short
1. **The search was too shallow.** I ran about five general web searches and found ~5 gateways and ~3 loggers. I didn't search GitHub or PyPI directly, or arXiv for 2026 work. The reality is 15+ near-exact matches, so the planned MVP would have been roughly the 15th clone of the same thing.
2. **I declared a gap without checking it.** D-003's "recorder outside the agent's trust boundary" was already shipped by afr, agentprov, witness and pipelock. I compared against in-process SDKs (the weakest competitors) instead of the strongest ones.
3. **I solved the wrong property.** I treated tamper-evidence of the stored log as the core problem. A hash chain only proves integrity of *what was logged*. It says nothing about whether *everything* was logged. The open problem is **completeness and non-bypass**.
4. **My default transport contradicted my own threat model.** I proposed a stdio wrapper as the MVP. A stdio child that the agent's own MCP config launches, running as the same OS user, can be removed from the config, bypassed (by calling tools natively) or killed by the agent. My design couldn't have met the property I was claiming.
5. **I didn't specify canonical serialization.** Hashing non-canonical JSON breaks silently (one project found 26 serialization differences across MCP SDKs). RFC 8785 is required.
6. **The "reusable attack suite" wasn't novel.** MCPSEC already has 64 cases. A suite is novel only if the *agent* is the attacker and several gateways are scored.
7. **I left identity open**, when established practice is clear: the gateway binds the role to the session and never trusts an identity field the agent can write.

**Lesson recorded for future work:** before claiming a gap, search code hosts (GitHub, PyPI, crates.io) and arXiv for the current year directly, compare against the *strongest* existing tools, and check that the proposed design can actually meet the property it claims under the stated threat model.

## Sources
mcp-gatekeeper (github.com/sumankrsh/mcp-gatekeeper) · mcp-gate-policy (pypi) · agent-flight-recorder (github.com/Mihirajmera/agent-flight-recorder) · mcp-glp-audit-proxy · mcp-auth-gateway · witness (github.com/halleylabs/witness) · agentprov (github.com/somoore/agentprov) · AgentWall (github.com/noviqtechnologies/agentwall) · Tracecat security architecture · pipelock · averin (github.com/FeirAI/averin) · MCPSEC (docs.rs/crate/mcpsec) · GatewayBench (arXiv 2610.23449) · Agent Flight Recorder paper (arXiv 2609.01931) · LLM Agents Can Easily Tamper With Their Own Traces (arXiv 2609.30266).
These were cited by the reviewer; I haven't independently re-verified each one.
