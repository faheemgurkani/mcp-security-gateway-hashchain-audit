# Security

## Reporting a problem in this repository

Please report vulnerabilities in the reference gateway, `mcp-lab` or the lab privately,
through GitHub's private vulnerability reporting: **Security → Report a vulnerability**
on this repository. Don't open a public issue. Please include steps to reproduce, and
the commit you tested.

## Findings about other gateways

If `mcp-lab` shows that a third-party gateway fails a guarantee its own documentation
makes, report it to **that project's maintainer** privately first, not here. Results
that only show a gateway lacks a control it never claimed are a capability comparison,
and can be shared openly (see `CONTRIBUTING.md`).

## Scope

The reference gateway's audit log is tamper-**evident**, not tamper-proof. Its
guarantees assume the deployment boundaries in `docs/threat-model/THREAT_MODEL.md`:
- the gateway runs outside the agent's control;
- the tools are reachable only through it;
- the key and the head anchor are out of the agent's reach.

Breaking a guarantee by removing one of those boundaries is the lab's documented result
(the `breach` and `colocated` profiles), not a vulnerability.
