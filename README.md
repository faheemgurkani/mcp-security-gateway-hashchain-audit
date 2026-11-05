# mcp-security-gateway-hashchain-audit

A security gateway that sits between an AI agent and its MCP tools:

1. **Validates** every tool call's parameters strictly (Pydantic).
2. **Blocks** unauthorized calls, e.g. confused-deputy attempts to reach admin tools (least-privilege policy).
3. **Logs** prompt, tool call, result and final output to an **append-only, hash-chained audit log**, so any edited or deleted entry is detectable.

> Side project, built independently of (and labeled separately from) Apart Research sprint work.

## Status
Scaffold only — work in progress.
