# 00: Project overview

> Updated 2026-11-08 after the research validation (notes/03). The project is now an **agent-as-attacker test lab for MCP security gateways**. The repo name stays the same.

## The problem, in plain terms
An AI agent uses **tools** (look up a customer, update the CRM, delete a user) through **MCP**, the Model Context Protocol, which sends JSON-RPC messages between agent and tool servers. The agent's instructions can come from untrusted text, so two things go wrong:

1. **Misuse of privileges (confused deputy):** text persuades the agent to use a tool the *person* behind it isn't allowed to use.
2. **Unaccountable actions:** after an incident, nobody can prove what the agent did. If the agent can edit or delete the logs, the evidence is worthless. Research (arXiv 2609.30266) shows real coding agents *do* delete their own traces when told to, when tricked, or when it raises their reward.

## What already exists
Many **gateways** sit between agent and tools, check every call, and write a hash-chained log (notes/03 lists 15+). Some claim the agent can't get around them. **Nobody has built a standard test of that claim with the agent itself as the attacker.**

## What we're building: a lock-testing kit
Lots of people have built locks. We're building the kit that tests whether a lock holds when the *burglar is the agent*.

```
┌──── agent zone (untrusted) ────┐
│ attacker agent (scripted, later │
│ a real LLM)                     │
└──────────────┬──────────────────┘
               │ Streamable HTTP: the only route out
┌──────────────▼── gateway zone ──┐
│ gateway under test: ours or an  │
│ existing one via an adapter     │
│ validate → authorize → log      │
└──────────────┬──────────────────┘
               │ private network
┌──────────────▼── tool zone ─────┐
│ demo MCP tools + log-head anchor│
└─────────────────────────────────┘
observer (outside every zone): records what *really* happened → scorecard
```

The four parts:
1. **Reference gateway** (what we learn Stages 3 and 11 from): strict Pydantic validation, a default-deny role policy, identity fixed by the gateway, an HMAC hash-chained log with sequence numbers and heartbeats, its head anchored where the agent can't write, and fail-closed behaviour if the log can't be written.
2. **Adapters:** thin wrappers that put existing gateways (mcp-gatekeeper, mcp-gate, …) into the same slot.
3. **Attack harness:** scenarios A1–A11 in which the agent edits, deletes or truncates the log, removes the gateway from its config, kills it, calls tools directly, impersonates admin, smuggles parameters or swaps tool definitions.
4. **Observer and scorecard:** for each gateway and attack, was it **blocked**, **detected**, or did it get through **undetected**?

## Key concepts, briefly
- **Hash chain / HMAC chain:** each log entry contains a fingerprint of the previous one. Change or delete one entry and every later fingerprint stops matching. With an HMAC the fingerprint also needs a secret key, so an attacker without the key can't recompute the chain.
- **Anchor:** a copy of the latest fingerprint kept somewhere the agent can't write. It catches *truncation*, where the attacker cuts entries off the end and the chain still looks valid.
- **Heartbeats:** the gateway logs "I'm alive" every few seconds. A gap means the gateway was stopped, which catches *kill* attacks.
- **Completeness vs integrity:** a chain proves that what was logged wasn't altered (integrity). Only an architecture the agent can't route around proves that everything was logged (completeness). Testing completeness is our novel part.
- **Fail closed:** if the gateway can't log a call, it refuses the call instead of letting it through unrecorded.

## How it maps to the learning stages
| Stage | Where |
|---|---|
| 3: MCP / agent security | the reference gateway's validation, policy, identity and rug-pull defence |
| 11: Audit and compliance | the HMAC chain, verifier, anchor and heartbeats; EU AI Act Art. 12 / NIST AI RMF mapping |
| 8: Automated red teaming (bonus) | the attack harness and scorecard |

## What we never claim
"Tamper-proof" (only tamper-*evident*), "EU AI Act compliant" (only *supports* Art. 12), or that our scorecard is exhaustive.

The detailed build plan is in [../PLAN.md](../PLAN.md).
