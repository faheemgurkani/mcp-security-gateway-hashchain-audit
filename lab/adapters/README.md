# Adapters: scoring external MCP gateways

The lab scores any gateway that can sit in the same slot as the reference
gateway. The **adapter contract** is small:

A gateway is scorable if it can:

1. **Mediate tool calls** between an MCP client (the agent) and an MCP tool
   server, enforcing a policy (default-deny, role → allowed tools).
2. **Bind identity to the session**, not read it from the request body.
3. **Write an append-only audit log** the harness can read and check — either
   with the gateway's own verifier, or with ours if the format matches.

An adapter supplies three things:

- **placement**: how the gateway is started and where it sits relative to the
  agent and the tool server (a Docker service in the HTTP slot, or a stdio
  subprocess for stdio-only gateways);
- **config**: policy, identity/token and key material in the gateway's format;
- **judging hooks**: where its audit log is, and how to verify it (a command
  or a format adapter), so outcomes are decided the same way for every
  gateway — execution from the tool-zone ledger (ground truth), tampering from
  the gateway's own integrity check.

## Transport reality

Most published gateways (mcp-gate-policy, shugo, agent-sudo-mcp) are **stdio
proxies**: the agent launches them as a subprocess and they wrap a stdio tool
server. That is structurally the **colocated** profile — the gateway runs as
the agent's own user, so the agent can edit its config, read its key, or kill
it. Only a gateway with a real network/privilege boundary (the reference
gateway's HTTP slot, or a gateway run as a separate user/container) can reach
the `reference`/`breach` profiles. This is itself a finding: the common
deployment shape of existing gateways is the weak one.

## Current adapters

- [`mcpgate/`](mcpgate/) — `mcp-gate-policy` (PyPI), run as a stdio proxy.
  A peer design: hash-chained audit, default-deny roles, its own `verify`.

Install the extra first: `uv sync --extra external`.
