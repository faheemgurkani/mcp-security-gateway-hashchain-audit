# Architecture

Two things live in this repo: a **reference MCP security gateway**, and a
**test lab** that attacks it (and other gateways) with the agent as the
adversary.

## Reference gateway (`src/mcp_gateway/`)

A Streamable HTTP MCP server that proxies to stdio or HTTP tool servers. Each
`tools/call` runs one pipeline:

```
authenticate → reject identity fields → pin check → policy → validate
   → log call_request (fail closed) → forward upstream → log call_result
```

| Module | Role |
|--------|------|
| `identity/session.py` | Bearer token → principal + role, from server-side config. Token hashes only. Identity fields in arguments are flagged, never honoured. |
| `policy/engine.py` + `policy.yaml` | Default-deny, role → allowed tool globs. Policy hash logged at start. |
| `policy/pinning.py` | Fingerprints tool definitions at start; quarantines changed or newly-appearing tools (rug-pull defence). |
| `validation/schemas.py` | Strict Pydantic models per tool (`extra="forbid"`, no coercion). Unknown tool → deny. |
| `audit/canonical.py` | RFC 8785 canonical JSON, so hashing is deterministic. |
| `audit/chain.py` | Append-only JSONL; each entry `{seq, ts_ms, type, session, payload, prev_mac, mac}`, `mac = HMAC-SHA256(key, JCS(entry\mac))`. fsync per write; `AuditWriteError` → fail closed. |
| `audit/anchor.py` | Atomic external store of the latest `(seq, mac)`; catches truncation. |
| `audit/heartbeat.py` | Periodic entries; a gap means the gateway was down. |
| `audit/verify.py` | Standalone verifier: `mac_mismatch`, `seq_gap`, `broken_link`, `truncated`, `time_gap`. |
| `proxy/gateway.py` | Wires the pipeline; wraps the SDK's HTTP app lifespan around the upstream client, `proxy_start` entry and heartbeat task. |
| `cli.py` | `keygen`, `issue-token`, `serve`, `verify`. |

Design decisions and rationale: `docs/notes/decisions.md` (D-005…D-012).

## Test lab (`lab/`)

```
agent zone (untrusted) ─HTTP─► gateway zone (trusted) ─internal net─► tool zone
   attacker (scripted/LLM)        gateway under test                 demo tools + ledger
            observer (host, outside every zone) ─► scorecards
```

| Piece | Role |
|-------|------|
| `compose/` | One image, three services, distinct UIDs, two networks (`agent_net`; internal `tool_net`). Overlays `colocated.yml`, `breach.yml` define the other profiles. |
| `setup.py` | Rotates per-run secrets into `lab/.run/` (git-ignored). Only token hashes reach the gateway; the admin token and key copy go to `operator/`, never mounted into the agent. |
| `agent/` | The agent's editable MCP config + client; `llm_agent.py` is an autonomous open-weight LLM agent. |
| `attacks/` | `actions.py` (agent-side attacker that discovers its own targets), `scenarios.py` (catalogue + judging rules). |
| `observer/` | Ground truth from outside the zones: tool ledger, log + anchor copies, Docker events. |
| `scorecard/` | `run.py` (scripted), `run_llm.py` (LLM, with a budget guard), `report*.py`. |
| `adapters/` | External gateways in the same slot; `mcpgate/` scores `mcp-gate-policy`. |

### Deployment profiles (D-010)
- **reference**: isolated zones — gateway in its own container/UID; log, key, anchor out of agent reach; tools only via the gateway.
- **breach**: agent can write the log volume, but has no key and no anchor.
- **colocated**: gateway runs as the agent's own user, with log, key, anchor and tool credential on the agent's disk (how most stdio wrappers deploy).

### How outcomes are decided
Never from the gateway's own claims. **Execution**: compare the tool zone's
execution ledger with logged `call_request` entries. **Tampering**: compare
before/after copies of the log and run the verifier. Each result is
`blocked` / `detected` / `undetected`. Rules are unit-tested without Docker
(`tests/harness/test_judge.py`).

## Results
- `docs/results/scorecard.md` — scripted attacker across three profiles (upper bound on what the gateway must withstand).
- `docs/results/scorecard-llm.md` — real open-weight LLM agent (lower bound on what a modest agent does).
- `docs/results/scorecard-external.md` — reference gateway vs. `mcp-gate-policy`.
