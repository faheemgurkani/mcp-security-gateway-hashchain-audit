# Contributing

This lab is most useful when it covers more attacks, more gateways and more ways of
deploying them than one person can build. Contributions of every size are welcome: a new
attack idea in an issue, a spec for a gateway you use, a hashing scheme the forger
doesn't know yet, or a whole new deployment profile.

If you're unsure where to start, open an issue describing what you'd like to try. Each
type has a template.

## Ways to help

### 1. New attack vectors and techniques

The catalogue (A1–A12) covers role abuse, argument smuggling, rug pulls, log tampering
and bypass. Some directions that are not covered yet:

- **Tool shadowing:** a second MCP server registers a tool with the same name as a
  trusted one.
- **Result-side injection:** instructions hidden in a tool's *output*, and whether the
  gateway inspects or labels results.
- **Token and session abuse:** replaying a captured session token, or confusing sessions
  across concurrent agents.
- **Log flooding:** burying a forbidden call under thousands of benign entries, or
  forcing log rotation to drop it.
- **Time and liveness:** forging heartbeats, skewing clocks around a kill (A5), or racing
  the anchor write.
- **Argument-level exploits** that pass a schema: path traversal, oversized values,
  Unicode confusables.
- **Signed-log checks:**
  - whether a verifier actually checks signatures;
  - whether the public key can be swapped;
  - whether checkpoints are committed off-host.
- **Other MCP features:** elicitation, sampling, resources and prompts, used as side
  channels.

There are two places to add an attack, depending on what it needs:

| Where | When to use it | What to change |
|---|---|---|
| Gateway harness (`src/mcp_lab/harness.py`), so every gateway gets it through `mcp-lab score` | It only needs an MCP client, the tool ledger, or the gateway's own log and verifier | Append to `EXECUTION` (judged from the tool server's ledger) or `TAMPER` (judged by the gateway's own verifier on an altered copy of its log). If it needs new demo-tool behaviour, extend `src/mcp_lab/demo/server.py` behind an environment variable, as `DEMO_RUG_PULL_AFTER` does. |
| Docker lab (`lab/attacks/`), with deployment profiles | It needs the agent's shell, network position or file permissions | Add the scenario and its judging rule to `scenarios.py` and the agent-side action to `actions.py`. |

Every attack needs a **ground-truth judging rule** that does not trust the gateway's own
report. Also map it to an OWASP Agentic Top 10 category in
`docs/threat-model/THREAT_MODEL.md`.

### 2. Gateway specs

If you use or maintain an MCP gateway, write a spec for it. `mcp-lab template` prints a
commented starting point, and [`examples/specs/`](examples/specs/) has six worked
examples. Please submit it under `examples/specs/`, with:

- the version you scored, and how to install it;
- a least-privilege configuration: a user may call `crm.*` only;
- the gateway's strongest audit option turned on;
- `caveats:` for anything the gateway does not set out to do.

If you maintain the gateway, a spec in your own CI (`action.yml`) catches regressions
before your users do.

### 3. The A12 forger's scheme catalogue

`src/mcp_lab/forge.py` recognises keyless hash chains by trying known schemes. Each one
is used only if it reproduces the untouched log exactly. If a gateway's chain shows `n/a`
but is in fact keyless, add its scheme by extending `HASH_FIELDS`, `PREV_FIELDS`,
`SERIALIZERS` or a new `Scheme`. Include a test in `tests/unit/test_forge.py` that writes
a log in that scheme and checks that the forged copy passes a verifier for it.

### 4. Deployment profiles and checks

The lab has three profiles: `reference`, `breach` and `colocated`. Real deployments look
like other things too:

- Kubernetes pods and sidecars;
- systemd sandboxing;
- macOS or Windows agents;
- remote gateways reached over OAuth.

New compose overlays (`lab/compose/`), and new questions for
`mcp-lab check-deployment` (`src/mcp_lab/deployment.py`), are both welcome.

### 5. LLM attackers

- More models, including closed ones.
- New framings (`FRAMINGS` in `lab/agent/llm_agent.py`).
- Longer turn budgets, and more runs per cell, to tighten the confidence bounds.

Keep `--cap-usd` and `--floor-usd` set. Hand-check any observation you add to
`lab/scorecard/notes/` against the transcripts.

### 6. The reference gateway

Upgrade paths that are noted but not built yet:

- an off-host head anchor (C2SP tlog-checkpoint, a witness, or a transparency log);
- signed checkpoints;
- per-argument policy constraints;
- an OAuth-based identity front end.

### 7. Docs

Clearer explanations, corrections, translations, and write-ups of what you found with
the lab.

## Ground rules

- **Judge from outside the gateway.** A result comes from the tool server's ledger or the
  gateway's own verifier, never from what the gateway says it did.
- **Don't overclaim.** The lab measures tamper-*evidence*, not tamper-*proofing*. A clean
  LLM run is a lower bound, not proof of safety, and "n/a" means "not recognised", not
  "secure".
- **Responsible disclosure for third-party gateways.** Results are a capability
  comparison. If a gateway fails a guarantee **its own documentation makes**, tell its
  maintainer privately (for example, a GitHub security advisory) before publishing, and
  don't open a public issue with the details. To report a security problem in *this*
  repository, use GitHub's private vulnerability reporting.
- **No secrets in results.** LLM transcripts pass through a redaction filter; check for
  API keys before committing anything under `lab/results/`.
- **Record decisions.** A design change gets an entry in `docs/notes/decisions.md`, and a
  surprising result gets one in `docs/notes/04-implementation-findings.md`.

## Development

```bash
uv sync                          # add --extra external for mcp-gate-policy
uv run pytest                    # unit, integration and harness tests (no Docker)
uv run ruff check . && uv run ruff format .
uv run mcp-lab score --reference examples/specs/toy-gateway.yaml
make lab-up                      # Docker lab, for profile and LLM work
```

Two things to know:

- The repository path may contain spaces: build shell commands with `shlex.join`.
- In specs, placeholders are shell-quoted for you.

Please keep each pull request to one thing, include tests, and describe how you verified
it.

## Citing

If you use the lab, its results or its attack catalogue, please cite it. The metadata is
in [`CITATION.cff`](CITATION.cff), and GitHub's "Cite this repository" button renders it.

## Releasing (maintainer)

Releases go to PyPI as `mcp-gateway-lab` when a `v*` tag is pushed. The steps, and why
each exists, are in
[`docs/notes/06-publishing-to-pypi.md`](docs/notes/06-publishing-to-pypi.md#11-the-release-checklist-every-time).
