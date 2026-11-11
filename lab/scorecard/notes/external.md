## Reading it

This is a **capability comparison**, not a list of vulnerabilities (D-013): each gateway is
scored on controls it may or may not set out to provide, and the caveats above say which.

- **Role and tool-name policy is table stakes.** Every gateway blocks the confused deputy
  (A8) and the admin call carrying a `role: admin` field (A7) with a default-deny allow list.
- **Argument validation (A9) is rare.** Only the reference gateway (a strict JSON Schema per
  tool, closed to undeclared fields) and shugo reject `field=password` and a smuggled `role` field. shugo
  gets this from MCP SDK **v1**, whose server validates arguments against the tool server's
  own advertised schema; SDK **v2** dropped that check (notes/04, M1), so gateways built on
  v2 forward malformed calls unless they validate themselves. shugo's SDK-level rejections
  happen before its policy hook, so they never reach its audit log.
- **Rug pulls (A10).** Only the reference gateway refuses a tool whose definition changed
  (pinning). mcp-audit-proxy raises an alarm and keeps the call flowing, by design
  ("detectors flag; only rules block"), and a person approves the change with
  `mcp-audit lock`.
- **Log integrity is where the designs really differ.**
  - A hash chain *without a secret* catches naive edits and deletions (A1, A2), but proves
    consistency, not authorship: anyone who can write the file can recompute the chain with
    the published algorithm (A12), and every keyless verifier accepts the result.
  - Truncation (A3) needs the head recorded somewhere else. mcp-glp-audit-proxy's `.head`
    sidecar catches a plain cut; mcp-gate-policy and shugo don't record the head. glp's own
    README notes that someone who can edit both files can move them together and points to
    an off-host copy of the head (and signed checkpoints in its Pro edition).
  - The reference gateway's HMAC key and anchor catch all four, **provided the key and
    anchor are out of the agent's reach**. `scorecard.md` shows the `colocated` deployment,
    where they are not, losing every log attack. Keys only move the problem to isolation.
  - mcp-audit-proxy is a flight recorder and makes no integrity claim.
- **Interop note.** mcp-glp-audit-proxy 0.4.0 negotiates MCP spec 2026-07-28 but omits that
  revision's required `resultType` on tool results, so an SDK 2.3 client rejects them. The
  harness connects to it with the initialize-era handshake (`mode="legacy"`), which works.
- **Not shown:** one more gateway was scored with the same harness. Its results are held back
  until its maintainer has been told privately, because they differ from what its
  documentation promises (D-013).
