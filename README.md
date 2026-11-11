# mcp-security-gateway-hashchain-audit

A **reference MCP security gateway** plus a **test lab that attacks it with the
AI agent as the adversary** — and scores other gateways the same way.

Existing MCP gateways with tamper-evident logs are plentiful. What was missing
is a reproducible benchmark that asks: *when the agent itself tries to delete
its log, truncate it, remove the gateway from its config, kill it, call tools
around it, or impersonate an admin — does the gateway hold, and can you prove
it?* This project is that benchmark, built around a hardened reference gateway.

> Side project, developed independently of (and labelled separately from) an
> Apart Research sprint. The audit log *supports* EU AI Act Art. 12 / NIST AI
> RMF record-keeping; it is tamper-**evident**, not tamper-**proof**, and this
> is not a compliance claim.

## The gateway

A Streamable HTTP MCP proxy. Every tool call is:

1. **validated** — strict per-tool Pydantic schemas (`extra="forbid"`, no coercion);
2. **authorized** — default-deny, role → allowed tools; identity is bound to the
   session and never read from the request;
3. **logged** — RFC 8785 canonical JSONL with an HMAC-SHA256 hash chain,
   sequence numbers, heartbeats, and the head anchored outside the agent's
   reach; writes fail closed.

Tool definitions are pinned at startup to catch rug pulls.

```bash
uv sync
uv run mcp-gateway keygen --out audit.key
uv run mcp-gateway issue-token --sessions sessions.yaml --principal alice --role user
uv run mcp-gateway serve --upstream "python -m tools.demo_server.server" \
    --sessions sessions.yaml --key-file audit.key \
    --log audit.jsonl --anchor head.json
uv run mcp-gateway verify audit.jsonl --key-file audit.key --anchor head.json
```

### Two-minute demo (no Docker)

```bash
./scripts/run_demo.sh
```

Starts the gateway, makes allowed and forbidden calls (confused deputy,
impersonation, smuggled fields, forged token), verifies the log, then tampers
with copies of it (`scripts/tamper_log.py`: edit, delete, truncate, spoof) and
shows each one caught, and finally shows a key-holding attacker forging a log
that still verifies.

## The lab

Three Docker zones (agent / gateway / tools) with the agent isolated from the
tool zone, plus a host-side observer that records ground truth from outside
every zone. The same scenarios run against three deployment profiles.

```bash
make lab-up                                             # needs Docker
uv run python -m lab.scorecard.run --profile reference  # also: breach, colocated
uv run python -m lab.scorecard.report                   # -> docs/results/scorecard.md
```

### Headline result (scripted attacker)

| profile | log tampering (A1–A3, A11) | bypass (A4–A6) | RBAC/validation (A7–A10) |
|---|---|---|---|
| **reference** (isolated) | 🛡️ blocked | 🛡️ blocked | 🛡️ blocked |
| **breach** (log writable, no key) | 🔎 detected | 🛡️ blocked | 🛡️ blocked |
| **colocated** (gateway as agent's user) | ❌ undetected | ❌ undetected | 🛡️ blocked |

**The cryptographic log is only as strong as the separation between the agent
and the key.** In the colocated shape — how most stdio wrappers deploy — a
misbehaving agent rewrites history and the verifier still says OK. Isolation is
what stops attacks; signatures are what detect them when isolation partly fails.

Full results, including a real open-weight LLM attacker and a comparison with
the external gateway `mcp-gate-policy`, are in [`docs/results/`](docs/results/).

## Documentation
- [Architecture](docs/ARCHITECTURE.md)
- [Threat model](docs/threat-model/THREAT_MODEL.md)
- [Design notes & decisions](docs/notes/) · [implementation plan](docs/PLAN.md)

## License
MIT.
