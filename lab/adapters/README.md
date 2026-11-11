# Adapters: scoring MCP gateways with one harness

`harness.py` runs the same attacks against every gateway; `gateways.py` describes each
gateway; `score.py` runs them and writes `lab/results/external.json`, which
`lab/scorecard/report_external.py` renders into `docs/results/scorecard-external.md`.

```bash
uv run python -m lab.adapters.score                       # every installed gateway
uv run python -m lab.adapters.score --only reference,shugo
uv run python -m lab.scorecard.report_external
```

## The contract

A gateway is scorable if it can **mediate tool calls** between an MCP client and an MCP
tool server under a policy, and (for the log attacks) **write an audit log that some
verifier can check**. An adapter is one `Gateway(...)` in `gateways.py`:

| field | what it supplies |
|---|---|
| `connect(dir, upstream_env)` | an MCP client session *through* the gateway, which wraps the demo tool server (`harness.UPSTREAM`) started with `upstream_env`; write the gateway's config into `dir` |
| `log(dir)` | where its audit log ends up |
| `verify(dir)` | its **own** integrity check → `(ok, message)`; `None` if it has none |
| `forge(dir)` | A12: edit an entry and recompute the chain with its *published* algorithm, without any secret; `None` if there is no chain |
| `dump(entry)` | how it serializes a log line, so edits look native |
| `rug_flagged(dir)` | optional: did it raise a rug-pull alarm? (turns A10 into *detected*) |
| `prefix` | how it renames upstream tools (e.g. `demo__`) |
| `caveats` | what the gateway does not set out to do, shown under the table |

Configure each gateway as close to least privilege as it allows: a user may call `crm.*`
only, admin tools are denied, and its strongest audit option is on.

## How outcomes are decided

Never from the gateway's own claims about a call:

- **Execution** (A7–A10): the demo tool server appends every call it *executes* to a
  ledger. A forbidden call in the ledger is `undetected` (or `detected` for A10 if the
  gateway raised an alarm); none is `blocked`.
- **Tampering** (A1–A3, A12): the harness alters a copy of a real log the gateway wrote,
  then runs the gateway's own verifier. Rejected is `detected`, accepted is `undetected`.
  A1 is tried on a middle entry and on the newest one, and the worse result counts.

A forger that gets a gateway's algorithm wrong produces a log its verifier rejects, so a
mistake can only flatter the gateway, never wrong it.

## Transport reality

Most published gateways are **stdio proxies**: the agent launches them as a subprocess,
which is structurally the `colocated` profile. The agent can edit their config, read
their files and run the tool server itself, so network-boundary attacks (A4–A6) are not
repeated per gateway. Only a gateway with a real boundary (the reference gateway's HTTP
slot, or any gateway run as a separate user/container) reaches `reference`/`breach`.

## Installing the external gateways

Each one goes into its own environment under `lab/.ext/` (git-ignored), never into the
project's, and is pinned to the version that was scored:

```bash
uv sync --extra external                                   # mcp-gate-policy (PyPI)
for spec in shugo==0.1.0 mcp-glp-audit-proxy==0.4.0; do    # PyPI, isolated venvs
  n=${spec%%==*}; uv venv -p 3.12 "lab/.ext/$n"
  uv pip install -p "lab/.ext/$n/bin/python" --only-binary :all: "$spec"
done
mkdir -p lab/.ext/mcp-audit-proxy && (cd lab/.ext/mcp-audit-proxy && npm init -y >/dev/null \
  && npm install --ignore-scripts mcp-audit-proxy@0.1.0)   # Go binary via npm
chmod +x lab/.ext/mcp-audit-proxy/node_modules/mcp-audit-proxy-*/bin/mcp-audit
```

`--ignore-scripts` is safe here (the package ships the binary, no postinstall download) but
leaves it non-executable, hence the `chmod`.

## Gateways scored

| gateway | version | what it is | notes |
|---|---|---|---|
| reference | this repo | HTTP gateway: session identity, role policy, strict schemas, pinning, HMAC chain + anchor | |
| [mcp-gate-policy](https://pypi.org/project/mcp-gate-policy/) | 0.3.2 | stdio proxy: roles via HMAC token, SHA-256 chain, `verify` | |
| [shugo](https://github.com/aritraghosh01/shugo) | 0.1.0 | stdio proxy: policy-as-code, approvals, SHA-256 chain | no per-principal identity in v0.1 |
| [mcp-glp-audit-proxy](https://github.com/antonio-castellon/mcp-glp-audit-proxy) | 0.4.0 | stdio/HTTPS proxy for GxP audit trails: roles, RFC 8785 + SHA-256 chain, `.head` sidecar | Community edition; needs the legacy handshake |
| [mcp-audit-proxy](https://github.com/firatmio/mcp-audit-proxy) | 0.1.0 | Go flight recorder: per-client rules, rug-pull and poisoning detectors | no integrity claim |

Checked and **not** scored, because they are not a proxy in front of an arbitrary MCP
server: `mcp-gatekeeper` on PyPI (a CI quality gate; the npm package of that name is a
coding-agent hook), `agent-flight-recorder` (agent debugging telemetry), `agent-sudo-mcp`
(an MCP server exposing its own tools, not a proxy), `mcp-toolguard` (CI contracts),
`intentgate` (SDK for a hosted service), `agentprov` (research framework). One more proxy
was scored; its results are held back pending private disclosure (D-013).
