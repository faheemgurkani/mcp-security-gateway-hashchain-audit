# Threat model: the agent as the attacker

## System
An AI agent calls tools over MCP. A **gateway** sits between the agent and its
tool servers; for every tool call it validates arguments, authorizes against a
least-privilege policy, and appends the call to a tamper-evident audit log.

```
agent ──Streamable HTTP──► gateway ──stdio / private net──► tool servers
   (untrusted)          validate→authorize→log                (trusted)
                                  │
                        audit log + external anchor
```

## What we assume the attacker controls
The distinguishing assumption of this project: **the agent itself is the
adversary** (OWASP ASI10 *Rogue Agents*). This is not hypothetical — LLM agents
delete or edit their own traces when instructed, when injected through a tool
result or skill file, and unprompted when it raises their reward
([arXiv:2609.30266]). This lab reproduced the incentivized case: kimi-k3.1-pro,
rewarded for a clean log, went around a `colocated` gateway in 3 of 5 runs
(`docs/results/scorecard-llm-models.md`). The attacker can therefore, up to the limits of its
deployment:

- send any MCP request, with any arguments and any headers;
- run arbitrary code in its own environment (shell, filesystem, processes);
- read, edit or delete any file it has permission to reach;
- edit its own MCP configuration;
- start, stop or kill processes it owns.

## Trust boundaries (what the attacker must *not* control)
The gateway's guarantees hold only to the extent these are true:

1. **The gateway runs outside the agent's control** — a separate OS user or
   container the agent cannot modify, stop, or impersonate.
2. **The tool servers are reachable only through the gateway** — no network or
   process path around it.
3. **The audit key and the log head anchor are not readable/writable by the
   agent.**

When all three hold (the `reference` profile) the gateway is sound. The project
*measures* what happens as they erode (`breach`, `colocated`), rather than
assuming them.

## Assets
- **Integrity of actions**: no forbidden tool call executes.
- **Completeness of the record**: every executed call is logged.
- **Integrity of the record**: no logged entry can be altered or removed
  undetectably.

## Attacks and controls

| ID | Attack | OWASP ASI | Control | Holds when |
|----|--------|-----------|---------|-----------|
| A1 | Edit a log entry | ASI10 | HMAC-SHA256 chain | key is out of agent reach |
| A2 | Delete an entry | ASI10 | seq + prev_mac chain | — |
| A3 | Truncate the tail | ASI10 | external head anchor | anchor is out of agent reach |
| A4 | Remove gateway from config | ASI02 | no route to tools but via gateway | network boundary |
| A5 | Kill the gateway, then act | ASI10 | heartbeats + fail-closed + isolation | gateway runs as another user |
| A6 | Call the tool server directly | ASI02 | network isolation + tool-side token | tool zone unreachable by agent |
| A7 | Impersonate admin (request fields / forged token) | ASI03 | session-bound identity; fields ignored & logged | token not forgeable by agent |
| A8 | Confused deputy (user → admin tool) | ASI03 | default-deny role policy | — |
| A9 | Smuggle / malformed parameters | ASI02 | strict Pydantic schemas (`extra=forbid`) | — |
| A10 | Rug pull (tool definition changes) | ASI04 | tool-definition pinning | — |
| A11 | Spoof a log entry | ASI10 | HMAC chain | key is out of agent reach |
| A12 | Rewrite the log and recompute the chain with the published algorithm | ASI10 | a secret in the chain (HMAC) or a signature that the verifier checks | key is out of agent reach |

A12 is what separates a keyed or signed log from a plain hash chain: a SHA-256
chain with no secret can be recomputed by anyone who can write the file, so it
proves consistency, not authorship (`scorecard-external.md`).

A7–A10 are enforced at the gateway regardless of deployment. A1–A3, A5, A11, A12
depend on keeping the key, anchor and gateway process out of the agent's reach;
A4, A6 depend on the network boundary. The scorecards (`docs/results/`) show
each attack's actual outcome across three deployment profiles.

## Residual risks and limits
- **Side effects already executed can't be un-executed.** If a tool runs and
  the result can't be logged, the gateway withholds the result but the action
  happened. Fail-closed covers the request, not the irreversible effect.
- **A key-holding attacker can forge a consistent chain**, including heartbeats,
  if it can also stop and restart the gateway. Only isolation prevents this; the
  cryptography alone does not. (Ed25519 with the private key held off-host, and
  a cosigned/witnessed checkpoint, raise this bar — see the roadmap.)
- **Completeness is architectural, not cryptographic.** A hash chain proves
  integrity of what was logged, never that everything was logged. Only a gateway
  the agent cannot bypass delivers completeness.
- **HMAC is symmetric**: verifying requires the signing key, so third parties
  can't verify without being able to forge. Public-key signing is the fix.
- The demo tools, policy and attack set are illustrative, not exhaustive.

## Mapping to frameworks
- **OWASP Top 10 for Agentic Applications (2026):** ASI02 Tool Misuse, ASI03
  Identity & Privilege Abuse, ASI04 Agentic Supply Chain, ASI10 Rogue Agents.
- **EU AI Act Art. 12 / NIST AI RMF:** the audit log *supports* automatic,
  traceable record-keeping. This project does not claim compliance, and the log
  is tamper-**evident**, not tamper-**proof**.

[arXiv:2609.30266]: https://arxiv.org/pdf/2609.30266
