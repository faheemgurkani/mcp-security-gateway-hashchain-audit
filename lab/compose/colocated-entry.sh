#!/bin/sh
# Start the gateway as a background process of the agent's own user.
mkdir -p "$HOME/.gateway"
S="$HOME/.gateway-secrets"
mcp-gateway serve \
  --upstream=http://tools:9000/mcp \
  --upstream-token-file="$S/upstream_token" \
  --arg-rules=/app/src/mcp_lab/demo/arg-rules.yaml \
  --sessions="$S/sessions.yaml" \
  --key-file="$S/audit.key" \
  --log="$HOME/.gateway/audit.jsonl" \
  --anchor="$HOME/.gateway/head.json" \
  --host=127.0.0.1 --port=8000 \
  --heartbeat="${HEARTBEAT_S:-2}" &
exec sleep infinity
