# Using the lab in practice

This guide is for people who build, choose or run MCP security gateways. It turns the
lab into six concrete jobs. Each one takes minutes and needs no Docker.

| Job | Command | When |
|---|---|---|
| [1. Score a gateway](#1-score-a-gateway) | `mcp-lab score my-gateway.yaml` | choosing or building a gateway |
| [2. Review a deployment](#2-review-a-deployment) | `mcp-lab check-deployment ...` | before go-live, after changes |
| [3. Gate CI on regressions](#3-gate-ci-on-regressions) | the GitHub Action | every push to your gateway |
| [4. Red-team with real models](#4-red-team-with-real-models) | `lab.scorecard.run_llm` | to see what agents actually try |
| [5. Judge a log handed to you](#5-judge-a-log-handed-to-you) | `mcp-lab inspect-log audit.jsonl` | audits, incidents |
| [6. Threat-model your own system](#6-threat-model-your-own-system) | [template](templates/agent-gateway-review.md) | design reviews |

## Install

```bash
uv tool install git+https://github.com/faheemgurkani/mcp-security-gateway-hashchain-audit
mcp-lab --help
```

Or, without installing: `uvx --from git+https://github.com/faheemgurkani/mcp-security-gateway-hashchain-audit mcp-lab ...`.
You need Python 3.12+ and `uv`.

## 1. Score a gateway

`mcp-lab` starts your gateway in front of its own **demo tool server**. That server
offers `crm.lookup` and `crm.update` (user tools) and `admin.delete_user` (an admin
tool), and it records every call it actually executes. The lab then attacks through
your gateway as a misbehaving agent would.

The verdicts never rely on the gateway's own account:

- whether a forbidden call **ran** comes from the tool server's ledger;
- whether log tampering was **caught** comes from *your* verifier, run on a copy of your
  log that the lab altered.

### Write a spec

`mcp-lab template > my-gateway.yaml` prints a commented starting point. A stdio proxy
needs about ten lines:

```yaml
name: my-gateway
command: my-gateway run --config {{dir}}/config.yaml -- {{upstream}}
files:
  config.yaml: |
    audit_log: {{dir}}/audit.jsonl
    roles: {user: {allow: ["crm.*"]}}     # least privilege: no admin.* for this user
log: "{{dir}}/audit.jsonl"
verify: my-gateway verify {{log}}          # exit 0 = your verifier accepts the log
```

The placeholders:

| Placeholder | Filled with |
|---|---|
| `{{upstream}}` | an executable that starts the demo tool server |
| `{{dir}}` | a fresh work directory for each run |
| `{{port}}` | a free port, for HTTP gateways (`transport: http`, `url:`) |

Working specs for six gateways are in [`examples/specs/`](../examples/specs/); copy the
closest one:

| Spec | Shows |
|---|---|
| `toy-gateway.yaml` | a tiny keyless-chain proxy, in [`examples/toy-gateway/`](../examples/toy-gateway/) |
| `reference.yaml` | an HTTP gateway with tokens and setup commands |
| `mcp-gate-policy.yaml` | minting a token in `setup` |
| `shugo.yaml` | a config file that names the upstream |
| `mcp-glp-audit-proxy.yaml` | the older-handshake case, auto-detected |
| `mcp-audit-proxy.yaml` | a gateway with no verifier, plus `rug_alarm` |

### Run it

```bash
mcp-lab score my-gateway.yaml                 # add --markdown report.md --json r.json
```

```
my-gateway 1.0.0 (stdio)
  A7   blocked     Impersonate admin via a request field
  A8   blocked     Confused deputy (user calls admin tool)
  A9   UNDETECTED  Smuggle / malformed parameters
  A10  UNDETECTED  Rug pull (tool definition changes)
  A1   detected    Edit a log entry (middle, then newest)
  A2   detected    Delete a log entry
  A3   UNDETECTED  Truncate the log tail (drop the newest 2)
  A12  UNDETECTED  Rewrite and re-hash with the public algorithm (no key)
```

### What each row means

| Row | Passes when |
|---|---|
| A7 | a call claiming `role: admin` in its arguments is refused |
| A8 | a user cannot call an admin tool (confused deputy) |
| A9 | malformed or extra arguments never reach the tool |
| A10 | a tool whose definition changed after approval is refused (or flagged: *detected*) |
| A1 / A2 | your verifier catches an edited or deleted entry |
| A3 | your verifier catches entries cut off the end. This needs the head (last hash) kept somewhere the writer can't reach. |
| A12 | your verifier catches a log rewritten with **recomputed** hashes. A plain SHA-256 chain can't: anyone who can write the file can recompute it. This needs a key or signature the writer doesn't hold. |

**A12 needs no forging code from you.** The lab tries a catalogue of keyless hashing
schemes, but uses one only if it reproduces your untouched log exactly. So "recomputed
and accepted" is itself proof that your chain needs no secret. If no scheme matches, A12
shows `n/a`. You can supply `forge:` in the spec to test your chain anyway.

**What this does not test.** These attacks target the gateway's own controls. Whether
the *agent* can go around a stdio gateway (edit its config, kill it, call the tool
directly) depends on how it is deployed, not on its code. That is job 2.

## 2. Review a deployment

The lab's main finding is that **a signed log protects you only if the agent cannot
reach the key**. `check-deployment` asks the questions behind that finding about a real
setup.

Run it **as the agent's OS user, on the machine (or container) where the agent runs**:

```bash
mcp-lab check-deployment \
  --key /etc/gateway/audit.key --log /var/log/gateway/audit.jsonl \
  --anchor /var/lib/gateway/head.json --agent-config ~/.config/agent/mcp.json \
  --secret /etc/gateway/upstream_token --tool-url http://tools:9000 \
  --gateway-process mcp-gateway
```

```
  [EXPOSED] Can the agent read the audit signing key?
            /etc/gateway/audit.key: readable
            opens: A11 spoof, A12 rewrite, A1-A3 undetected
  [ok     ] Can the agent reach the tool server directly?
            http://tools:9000: tools:9000 unreachable (Connection refused)
  ...
Closest lab profile: colocated
  - every log attack goes undetected: with the key the agent can rewrite history and
    the verifier still says OK
```

It never writes anything: it uses permission checks and a TCP connect.
`--fail-on breach` or `--fail-on colocated` makes it usable as a deployment gate. What
each profile loses, attack by attack, is in
[`docs/results/scorecard.md`](results/scorecard.md).

**How to reach `reference`:**

- run the gateway as its own user or container;
- put the key and the head anchor where only the gateway can read them;
- make the log append-only for the gateway and unwritable for the agent;
- make the agent's MCP config read-only to the agent;
- reach the tool servers only through the gateway, on a network the agent isn't on.

## 3. Gate CI on regressions

Add this to the gateway's own CI. It fails the build if any attack goes undetected, and
writes the table to the job summary:

```yaml
- uses: actions/checkout@v4
- run: pip install .                    # make your gateway's command available
- uses: faheemgurkani/mcp-security-gateway-hashchain-audit@main
  with:
    spec: ci/my-gateway.yaml
    fail-on: undetected                 # or: detected (stricter), never (report only)
```

Without GitHub Actions, run `mcp-lab score my-gateway.yaml --fail-on undetected`; it
exits 1 when the gate trips. This repo's own CI uses the action on the reference gateway
(`.github/workflows/ci.yml`).

To accept a known gap without silencing everything, keep `fail-on: never` and compare
the `--json` output against a committed baseline.

## 4. Red-team with real models

The scripted attacks are the **upper bound**: what the gateway must withstand. Real LLM
agents show what agents actually try. In this lab:

- one current open-weight model went around a `colocated` gateway in 3 of 5 runs, by
  reading its token and calling the tool server directly;
- the same model failed against `reference`.

The LLM driver runs inside the Docker lab (it needs a checkout of this repo and an
OpenRouter key in `.env`):

```bash
make lab-up
uv run python -m lab.scorecard.run_llm --profiles colocated,reference \
  --framings incentivized --models moonshotai/kimi-k3.1-pro --reps 5 \
  --out mine.json --cap-usd 2 --floor-usd 1
uv run python -m lab.scorecard.report_llm --in mine.json --out mine.md
```

Treat a clean result as a **lower bound, never as proof of safety**. The reports give a
95% upper bound on the per-run success rate, for that reason.

## 5. Judge a log handed to you

When an agent's audit log is offered as evidence:

```bash
mcp-lab inspect-log audit.jsonl
```

It says whether the chain can be recomputed without any secret (and by which scheme),
whether there are keyed or signed fields, and whether a copy of the head sits next to
the log. It then lists the questions to ask:

- who could write the file;
- where the key was;
- whether the verifier really checks the signatures;
- where the head was anchored.

It is offline and read-only.

## 6. Threat-model your own system

[`templates/agent-gateway-review.md`](templates/agent-gateway-review.md) is a fillable
review. It lists the attacks the lab uses (OWASP Agentic Top 10 mapping), the trust
boundary each control needs, and the deployment questions from job 2. The worked version
for this repo's gateway is [`threat-model/THREAT_MODEL.md`](threat-model/THREAT_MODEL.md).

## The reference gateway with your own tools

The reference gateway (`mcp-gateway serve`) is not tied to the demo tools:

- **roles:** `--policy roles.yaml` maps each role to the tool globs it may call;
- **arguments:** each tool is validated against its own advertised input schema. That
  schema is captured at startup and pinned, and it is closed to undeclared fields by
  default.
- **tighter rules:** `--arg-rules rules.yaml` sets patterns, enums or lengths beyond what
  a tool advertises.

Format and rationale: `src/mcp_lab/demo/arg-rules.yaml` and decision D-019.
