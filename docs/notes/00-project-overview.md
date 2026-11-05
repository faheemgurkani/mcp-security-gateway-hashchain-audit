# 00: Project overview

## The problem
An AI agent calls **tools** (send email, update CRM, delete user) through MCP, the Model Context Protocol, which uses JSON-RPC between the agent and its tool servers. The agent acts with *its own* privileges, but its instructions can come from untrusted text: a user prompt, an email it reads, a retrieved document. This creates two risks:

1. **Confused deputy / tool misuse.** An attacker's text persuades the agent to use privileges the attacker doesn't have, e.g. "call `admin.delete_user`". Malformed or smuggled parameters are a related risk; this is the agentic version of SQL injection.
2. **Unaccountable actions.** After something goes wrong, nobody can prove what the agent saw and did. If the agent, or an attacker, can edit or delete logs, the evidence can't be trusted either.

## The idea
Put a **gateway** in the middle. The agent never talks to tools directly; every call passes through three checks:

```
agent ──► [1 Validate] ──► [2 Authorize] ──► tool server
              │                 │                 │
              └──────── [3 Audit log (hash-chained)] ◄──┘
```

1. **Validate:** each tool has a strict Pydantic schema. Wrong types, missing fields or extra fields are rejected before anything runs.
2. **Authorize:** a least-privilege policy maps who is calling (the user's role or the session's origin) to the tools they may use. A user-driven session can't reach admin tools, even if the agent tries.
3. **Audit:** each event (prompt, tool call, decision, result, final output) is appended to a log. Every entry holds the hash of the entry before it, forming a hash chain. Editing or deleting any entry changes the hashes after it, so a verifier detects the tampering. Blocked calls are logged as well.

## Why a hash chain makes the log tamper-evident
Entry *n* stores `prev_hash = H(entry n-1)` and its own hash `H(content_n + prev_hash)`. To change entry 5 without detection, an attacker must recompute entries 6 to N. Anchoring the latest hash somewhere the agent can't write to (printed, stored externally or signed) makes that recomputation detectable too. The chain doesn't *prevent* tampering; it makes tampering **evident**.

## What the demo will show
1. A legitimate CRM call passes and is logged.
2. A confused-deputy call to an admin tool is **blocked** and logged.
3. `tamper_log.py` edits one log entry; `verify` **flags** the exact broken entry.

## How it connects
- **Apart sprint, Track 4.2:** oversight that holds up when agents can delete or spoof logs. The gateway's log can serve as trusted ground truth. Any reuse there is labeled as side or pre-existing work.
- **Frameworks:** OWASP Top 10 for LLMs (excessive agency, insecure plugin design); EU AI Act and NIST AI RMF (record-keeping and traceability).

## Open questions (to be decided, logged in decisions.md)
- Transport: stdio vs HTTP MCP proxying.
- How the caller's identity or origin reaches the gateway.
- Log storage format (JSONL vs SQLite) and hash anchoring strategy.
