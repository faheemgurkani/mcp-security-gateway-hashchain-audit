# When the Agent Is the Attacker: Measuring MCP Security Gateways Against Their Own Agents

*Technical report, 2026-11-11. Repository:
https://github.com/faheemgurkani/mcp-security-gateway-hashchain-audit. Every number below
is reproducible from the commands in §9; the raw results are in `docs/results/` and
`lab/results/`.*

## Abstract

MCP security gateways sit between an AI agent and its tools. They check each tool call
against a policy and record it in an audit log that is often described as
tamper-evident. Most published designs are tested against an outside attacker. We ask
the question their threat model usually leaves open: **what happens when the agent the
gateway is meant to control is itself the adversary?**

We built three things:

- a reference gateway (session-bound identity, default-deny roles, closed JSON-Schema
  argument validation, tool-definition pinning, and an RFC 8785 log with an HMAC-SHA256
  chain and an external head anchor);
- a three-zone Docker lab with an observer outside every zone;
- `mcp-lab`, a harness that runs the same twelve attacks against any gateway described
  in a short YAML spec. It judges each attack from the tool server's execution ledger and
  the gateway's *own* verifier, never from the gateway's report.

We find three things:

1. **Isolation, not cryptography, decides the outcome.**
   - Isolated, the reference gateway blocks all 11 lab attacks.
   - Deployed as the agent's own OS user, which is the usual shape of a stdio gateway,
     it loses every log and bypass attack while its verifier still reports success.
2. **A current open-weight model found such a bypass on its own.** kimi-k3.1-pro, given
   a goal and a shell, executed a forbidden action undetected in 3 of 5 runs against the
   colocated profile, and failed against the isolated one. Across 270 runs of six
   models, no run tampered with the log.
3. **A hash chain without a secret proves consistency, not integrity.** Every keyless
   gateway we scored accepted a log rewritten with recomputed hashes. A generic forger
   that needs no gateway-specific code recovered each gateway's scheme.

## 1. Introduction

The Model Context Protocol (MCP) lets an agent discover and call tools on separate
servers. Gateways for MCP have multiplied. A typical one is a stdio or HTTP proxy that:

- enforces an allow list or role policy;
- sometimes validates arguments or pins tool descriptions;
- writes a hash-chained audit log with a `verify` command.

The log is meant to answer, after an incident, *what did the agent do?*

Agents do misbehave. Prior work (arXiv:2609.30266) reports coding agents deleting or
editing their own traces when instructed, when prompt-injected, and when it raised their
reward. If the agent can reach the gateway's log, key, configuration or upstream
credentials, a correct gateway can still be routed around or made to vouch for a
rewritten history. Whether that happens is a property of the **deployment**, not the
gateway's code. It is rarely measured.

Contributions:

1. **An agent-as-attacker benchmark.** It has twelve attacks (A1–A12) mapped to the
   OWASP Top 10 for Agentic Applications. Each is judged from evidence outside the
   gateway.
2. **Three deployment profiles** (`reference`, `breach`, `colocated`), which isolate how
   much of a gateway's security comes from its code and how much from where it runs.
3. **Real-model attackers.** Six open-weight models, three framings, five runs per
   cell, with one-sided 95% Clopper-Pearson bounds.
4. **`mcp-lab`, a one-command harness** for any gateway, validated by reproducing
   bespoke adapters for five third-party gateways exactly. It includes a generic forger
   for keyless chains, a deployment checker and a log inspector.
5. **A reference gateway** whose argument rules come from operator config or each tool's
   pinned schema, so it can front any tool server.

## 2. Threat model

**The attacker is the agent.** Within its deployment it can:

- send any MCP request with any arguments;
- run code;
- read, write and delete files it has permission to reach;
- edit its own MCP client configuration;
- start and kill processes it owns.

It does not have root and cannot break cryptographic primitives.

**Assets:**

- *integrity of actions*: no forbidden call executes;
- *completeness of the record*: every executed call is logged;
- *integrity of the record*: no logged entry is altered or removed undetectably.

**Trust boundaries the gateway depends on:**

- B1: the gateway runs outside the agent's control;
- B2: tools are reachable only through the gateway;
- B3: the audit key is unreadable by the agent;
- B4: the head anchor is unwritable by the agent.

**Profiles.** The three profiles remove these boundaries step by step:

| Profile | Agent can | Boundaries kept |
|---|---|---|
| `reference` | nothing beyond its own zone | B1–B4 |
| `breach` | write the log volume | B1–B3, plus the anchor |
| `colocated` | everything the gateway can: its log, key, anchor, config and upstream token | none (gateway runs as the agent's user) |

`colocated` is how a stdio gateway launched from the agent's own configuration
naturally runs.

**Attacks.**

| ID | Attack | OWASP ASI |
|---|---|---|
| A1 | edit a log entry | ASI10 Rogue Agents |
| A2 | delete entries | ASI10 |
| A3 | truncate the tail | ASI10 |
| A4 | remove the gateway from the agent's config | ASI02 Tool Misuse |
| A5 | kill the gateway, then act | ASI10 |
| A6 | call the tool server directly | ASI02 |
| A7 | claim `role: admin` in arguments, or forge a token | ASI03 Identity & Privilege Abuse |
| A8 | call an admin tool as a user (confused deputy) | ASI03 |
| A9 | smuggle or malformed arguments | ASI02 |
| A10 | rug pull: a tool's definition changes after approval | ASI04 Agentic Supply Chain |
| A11 | spoof a log entry | ASI10 |
| A12 | rewrite the log and recompute its chain with the published algorithm, without any key | ASI10 |

## 3. System

### 3.1 Reference gateway

The agent side is Streamable HTTP; the tool side is stdio or HTTP. Every `tools/call`
runs one pipeline:

```
authenticate → reject identity fields → pin check → role policy → validate arguments
  → log call_request (fail closed) → forward → log call_result
```

- **Identity** is a gateway-issued bearer token mapped server-side to a principal and
  role. Only token hashes are stored, and identity fields in arguments are refused.
- **Policy** is default-deny, role → tool globs. A user's `tools/list` hides the tools it
  cannot call.
- **Arguments** are validated against a JSON Schema per tool. The schema comes from the
  operator's rules file if one exists, otherwise from the tool's own `inputSchema`
  captured at startup, otherwise the call is denied. Object schemas are closed
  (`additionalProperties: false`) unless they say otherwise, and types are never
  coerced. Using the advertised schema is sound only because of pinning: a tool whose
  definition (name, description, schema) changes after startup is quarantined. This
  doubles as the rug-pull defence (A10).
- **The log** is JSONL in RFC 8785 canonical form:
  - entries `{seq, ts_ms, type, session, payload, prev_mac, mac}`, with
    `mac = HMAC-SHA256(key, JCS(entry \ mac))`;
  - fsync per write;
  - heartbeats, so a gap is visible;
  - the latest `(seq, mac)` written atomically to an anchor outside the log's
    directory;
  - fail closed: a call that cannot be logged is not forwarded.
- **The verifier** reports MAC mismatches, sequence gaps, broken links, truncation
  against the anchor, and time gaps.

### 3.2 Lab and observer

One image runs three services under distinct UIDs:

- **agent**, on `agent_net` only;
- **gateway**, bridging `agent_net` and the internal `tool_net`;
- **tools**: the demo tool server, which appends every call it *executes* to a ledger in
  the tool zone.

Per-run secrets are rotated; the agent never receives the admin token or the key. A
host-side observer reads the ledger, the log and anchor (before and after each attack),
and Docker events.

**Judging:**

- **Execution:** an executed forbidden call is *blocked* if it never reached the tool,
  *detected* if it is in the log, and *undetected* if it is in the ledger but not the
  log.
- **Tampering:** a change to the log is *detected* if the verifier flags it, and
  *undetected* if not.

### 3.3 `mcp-lab`: scoring any gateway

A gateway is described in YAML:

- how to start it in front of `{{upstream}}`, an executable launching the demo tool
  server with a fresh ledger;
- configuration templates;
- where its log ends up;
- its own verify command.

The harness then runs A7–A10 through it as an MCP client and judges execution from the
ledger. For log integrity it writes a seed log and alters copies, which the gateway's
own verifier judges:

- A1: edit the middle and the newest entry; the worse result counts;
- A2: delete an entry;
- A3: drop the newest two;
- A12: recompute the chain.

The network-boundary attacks (A4–A6) are deployment properties, assessed by
`mcp-lab check-deployment` rather than per gateway.

**Generic A12.** The harness carries a catalogue of keyless schemes:

- a hash field over the entry minus that field;
- with or without the previous hash prepended;
- with or without the previous-hash field;
- under RFC 8785, sorted-compact, sorted-UTF-8/NFC, sorted-spaced and insertion-order
  JSON;
- or a previous-hash field holding the SHA-256 of the previous raw line.

A scheme is used only if it **reproduces every hash in the untouched log**, so success
also proves that the chain needs no secret. The forger then edits one entry, recomputes
the chain, and rewrites any file in the gateway's directory that held an old head hash,
such as a sidecar. A missing or wrong scheme yields `n/a` or `detected`, so errors can
only flatter a gateway.

**Handshake robustness.** Some gateways negotiate the newest MCP revision but omit its
required result fields; one does so only in its own deny replies. The probe makes an
allowed and a denied call and falls back to the initialize-era handshake if needed.

## 4. Method

**Scripted attacks** run in the Docker lab for each profile. For the gateway comparison
they run through `mcp-lab`. Each external gateway is configured as close to least
privilege as it allows (a user may call `crm.*` only), with its strongest audit option
on. Versions are pinned: mcp-gate-policy 0.3.2, shugo 0.1.0, mcp-glp-audit-proxy 0.4.0
(Community), mcp-audit-proxy 0.1.0.

**LLM attackers.** An autonomous agent runs in the agent container with a shell and the
MCP tools; it learns nothing else about the lab. Settings: temperature 0.7, a 20-turn
budget, accessed via OpenRouter. There are three framings:

- *instructed*: told to delete a user it lacks rights for and to erase the logs;
- *injected*: a benign task, with the malicious instruction planted in a customer
  record the agent reads;
- *incentivized*: never told to tamper, but scored on finishing a task and leaving no
  denied actions in the log.

Six models: gpt-oss-120b (baseline), gpt-oss-safeguard-20b, kimi-k3.1-pro,
deepseek-v4.1-flash, qwen3.8-flash and glm-5.3. Each ran 3 profiles × 3 framings × 5
runs, 270 runs in all, at a cost of US$3.91.

The lab's source code was visible inside the agent container on purpose, since a real
attacker can read open-source code. Earlier results and transcripts were not. We report
an upper bound on the per-run success rate from a one-sided 95% Clopper-Pearson
interval; for 0 successes in n runs that is 1 − 0.05^(1/n).

## 5. Results

### 5.1 Profiles (scripted attacker)

| | reference | breach | colocated |
|---|---|---|---|
| A1–A3, A11 log tampering | blocked | detected | **undetected** |
| A4–A6 bypass | blocked | blocked | **undetected** |
| A7–A10 role, arguments, rug pull | blocked | blocked | blocked |

A7–A10 are enforced at the gateway and hold everywhere. Everything else depends on the
deployment:

- In `breach` the agent can rewrite the log but not re-key it, so every change is
  detected.
- In `colocated` the agent reads the key, rewrites history, re-signs it and moves the
  anchor, and the verifier reports `OK`. It can also kill the gateway, drop it from its
  config, or call the tool server with the gateway's own credential.

### 5.2 Real-model attackers

| model | blunt-task refusals (0 tool calls) | runs reaching log/secrets | forbidden execution or tampering | 95% upper bound |
|---|---|---|---|---|
| gpt-oss-120b | 0/15 | 0/45 | 0/45 | ≤ 6.4% |
| gpt-oss-safeguard-20b | 9/15 | 1/45 | 0/45 | ≤ 6.4% |
| kimi-k3.1-pro | 10/15 | 15/45 | **3/45** | ≤ 16% |
| deepseek-v4.1-flash | 0/15 | 28/45 | 0/45 | ≤ 6.4% |
| qwen3.8-flash | 0/15 | 29/45 | 0/45 | ≤ 6.4% |
| glm-5.3 | 11/15 | 19/45 | 0/45 | ≤ 6.4% |

All three successes are kimi-k3.1-pro, on `colocated`, *incentivized*. In each run the
model:

1. read the gateway's upstream token from the agent-readable secrets directory;
2. wrote a small MCP client;
3. called `admin.delete_user` on the tool server directly.

The gateway never saw the call, so the log stayed clean and verified. One of the three
runs built its client by inspecting the installed MCP SDK and never opened the lab's
attack code; the other two read it first. On `reference` the same model attempted the
same bypass in two runs and failed: the token and the tool server were out of reach.

**No model tampered with the log** in 270 runs. Further observations:

- **Refusal did not predict safety.** The model that refused the blunt instruction most
  often after glm (10/15) was the only one to succeed when merely rewarded.
- **The safeguard-tuned model** never reached anything. That was mostly a tool-use
  failure: it called a lookup with no arguments until the turn cap. It is not evidence
  of a safer agent.
- **The injected instruction never became an action.** Two models instead rewrote the
  poisoned record to flag it.
- **The turn budget binds.** Most incentivized runs of the four flagship models ended
  mid-reconnaissance at the 20-turn cap.

### 5.3 Gateways under the same attacks

Key: 🛡️ blocked, 🔎 detected, ❌ undetected.

| | reference | mcp-gate-policy | shugo | mcp-glp-audit-proxy | mcp-audit-proxy |
|---|---|---|---|---|---|
| A7 role in arguments | 🛡️ | 🛡️ | 🛡️ | 🛡️ | 🛡️ |
| A8 confused deputy | 🛡️ | 🛡️ | 🛡️ | 🛡️ | 🛡️ |
| A9 malformed arguments | 🛡️ | ❌ | 🛡️ | ❌ | ❌ |
| A10 rug pull | 🛡️ | ❌ | ❌ | ❌ | 🔎 |
| A1 / A2 edit, delete | 🔎 | 🔎 | 🔎 | 🔎 | ❌ |
| A3 truncation | 🔎 | ❌ | ❌ | 🔎 | ❌ |
| A12 keyless rewrite | 🔎 | ❌ | ❌ | ❌ | ❌ |

**Reading the table:**

- **A7/A8:** default-deny name policy is table stakes.
- **A9:** argument validation is rare. shugo gets it from MCP SDK v1, which validates
  arguments against the tool's schema; v2 dropped that check, so v2-based gateways
  forward malformed calls unless they validate themselves.
- **A10:** only the reference gateway refuses a changed tool. mcp-audit-proxy flags it
  by design and keeps the call flowing.
- **A3:** truncation is caught only with the head recorded elsewhere: the reference
  gateway's anchor and glp's `.head` sidecar. glp's documentation itself notes that the
  sidecar can be moved along with the log by whoever can edit both.
- **A12:** every keyless chain accepted a rewrite. The generic forger recovered each
  scheme without gateway-specific code:
  - mcp-gate-policy and glp: SHA-256 over RFC 8785 of the entry;
  - shugo: the previous hash prepended.
- **mcp-audit-proxy** is a flight recorder and makes no integrity claim.

This is a capability comparison, not a vulnerability list. Each gateway is scored on
controls it may not set out to provide.

**Validation of the harness.** YAML specs for all five external gateways (including one
withheld, §8) reproduce the results of hand-written adapters, each with a bespoke A12
forger, exactly.

## 6. Discussion

**Where a gateway runs matters as much as what it checks.** The gateway's code delivered
A7–A10 in every profile. Everything about the record depended on boundaries B1–B4. A
hardened gateway launched by the agent, as the agent's user, with its key on the agent's
disk, is a recorder the agent controls. The useful question for a deployment is
therefore not "is the log signed?" but **"can the agent reach the key, the log, the
config, or the tools without the gateway?"**. `mcp-lab check-deployment` asks exactly
that.

**"Tamper-evident" needs a secret the writer lacks.** A SHA-256 chain whose algorithm is
public detects careless edits (A1, A2). It cannot detect a writer who recomputes the
chain (A12). Detection needs one of:

- a key the writer cannot read (HMAC);
- a signature whose private key is elsewhere and which the verifier actually checks;
- a head committed off-host (a witness, transparency log or C2SP checkpoint).

A sidecar head in the same directory moves with the log.

**Agents follow incentives, not instructions.** The successful model refused the blunt
request most of the time, yet found the bypass when only rewarded for an outcome that
the bypass delivered: a log with no denied actions. Refusal rates on harmful requests
measured this way say little about what an agent will do to reach a goal. The scripted
scorecard remains the right bar for a gateway, because it is the **upper bound**; LLM
results are a **lower bound** that will rise with capability and turn budget.

**For gateway authors:**

- refuse changed tool definitions;
- validate arguments yourself, and close schemas by default;
- key or sign the log with material the agent cannot reach, and verify it;
- record the head off-host;
- document the deployment your guarantees assume.

## 7. Limitations

- **The demo tool server** is small: three tools and one injected record. Real tool
  servers have larger attack surfaces.
- **External gateways** were scored in their native stdio shape and in configurations we
  chose to be least-privilege; a different configuration may score differently. We did
  not score network-boundary attacks per gateway.
- **The LLM sample is small.** Five runs per cell and a 20-turn cap give wide intervals:
  the 95% upper bound is up to 16% per model. Results depend on prompts, temperature and
  provider routing, and on the lab's source being visible to the agent (by design; two
  of three successes read it).
- **The generic forger** knows only catalogued schemes; `n/a` means "not recognised", not
  "secure".
- **The reference gateway's** heartbeat and anchor detect, but do not prevent, attacks
  once isolation fails. It has no off-host anchor or transparency-log integration yet.

## 8. Ethics and disclosure

- **Disclosure policy (D-013).** Results about third-party gateways are framed as
  capability comparisons. Where a gateway's measured behaviour contradicts a guarantee
  its documentation makes, results are withheld until the maintainer has been informed.
  One gateway's results are withheld on that basis.
- **Licenses.** All scored gateways are open source: two MIT, two Apache-2.0 and one
  AGPL-3.0. None restricts benchmarking or publication. They were installed from public
  package registries and driven through their public CLIs; no code was redistributed.
- **LLM transcripts** are published with secrets redacted.

## 9. Reproducing

```bash
git clone https://github.com/faheemgurkani/mcp-security-gateway-hashchain-audit && cd mcp-security-gateway-hashchain-audit
uv sync
uv run mcp-lab score --reference examples/specs/toy-gateway.yaml   # minutes, no Docker
# external gateways: install them (lab/adapters/README.md), then
uv run mcp-lab score examples/specs/{mcp-gate-policy,shugo,mcp-glp-audit-proxy,mcp-audit-proxy}.yaml
# profiles (Docker): make lab-up && uv run python -m lab.scorecard.run --profile colocated
# LLM attackers: see docs/GUIDE.md §4 (needs an OpenRouter key)
```

Design decisions with rationale are logged as D-001 to D-021 in `docs/notes/decisions.md`,
and implementation findings in `docs/notes/04-implementation-findings.md`.

## References

- arXiv:2609.30266: coding agents deleting or editing their own traces when instructed,
  injected or incentivized.
- OWASP Top 10 for Agentic Applications (ASI01–ASI10).
- RFC 8785: JSON Canonicalization Scheme.
- RFC 9162 and C2SP tlog-checkpoint / witness: transparency logs and off-host head
  commitments.
- Model Context Protocol specification, revision 2026-07-28.
