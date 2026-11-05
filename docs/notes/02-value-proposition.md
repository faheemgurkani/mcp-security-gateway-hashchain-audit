# 02: What value this project delivers (beyond "another repo")

## The honest landscape (Nov 2026)
Both halves of this idea already exist separately:
- **MCP gateways/proxies:** hoophq/mcpproxy (Go), Enkrypt MCP Gateway, agentsec-gateway, SentinelGate, MCP Guardian, Docker MCP Gateway.
- **Hash-chained agent audit logs:** AgentLedger, AgentTrail, asqav, and others, mostly **SDKs that run inside the agent's own process**.

So "a gateway" or "a hash-chained log" on its own is not new. We need a sharper angle.

## The gap we fill: *logging that survives a misbehaving agent*
Most audit SDKs assume the agent is the honest party recording its own actions. But the case that matters (and the Apart sprint's Track 4.2 incident) is when **the agent itself is the adversary**: it deletes evidence or spoofs transcripts. A log the agent writes in its own process, to disk it can access, protects nothing in that case.

Our design puts the recorder **outside the agent's trust boundary**:
1. The gateway is a separate process the agent can't bypass, because the agent only sees tools through it.
2. The gateway itself writes the log, not the agent.
3. The latest hash is **anchored** somewhere the agent can't write (printed checkpoint, then later a signed C2SP-style checkpoint or witness).
4. The **verifier is a standalone tool** anyone can run on a log file without trusting us.

Simple version: *a flight recorder for AI agents that the pilot can't tamper with, and that also refuses unsafe commands.*

## What people can actually use (the deliverables)
1. **A drop-in tool** (`pip install`; wrap any MCP server's command in your Claude, Cursor or other MCP config). No code changes, so it adds security to tools you already use.
2. **An open, documented log format + standalone verifier.** Other projects (sprint forensic tools, auditors, other gateways) can produce or check the same format. This is the piece others can **build on**.
3. **A reusable attack test suite**: confused-deputy, tool-poisoning, malformed-parameter and log-tampering cases, mapped to OWASP ASI IDs. Anyone can run it against *their* gateway or server. It is the seed for Stage 8 (PyRIT/CI) later.
4. **A written threat model + teardown** (docs/threat-model): a teaching resource for beginners like us, which also reads well in a portfolio.

## Why this is good for you specifically
- It demonstrates the two most in-demand skills (agent/MCP security, plus audit and compliance) in one coherent story: *attack → block → prove*.
- It's framed in the AI-safety "control" language (untrusted agent), which fits Apart and alignment-adjacent roles, not just AppSec.
- Each deliverable is small; the weekend MVP is #1 + #2 (basic) + a few cases of #3.

## What we deliberately won't claim
- Not "tamper-proof", only tamper-**evident**, and only up to the last anchored checkpoint.
- Not "EU AI Act compliant"; it *supports* Article 12 record-keeping.
- Not a prompt-injection detector; we enforce policy at the tool boundary (CaMeL-style thinking), which works even when detection fails.
