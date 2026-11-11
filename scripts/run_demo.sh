#!/usr/bin/env bash
# Two-minute local demo, no Docker: start the gateway, make allowed and forbidden
# calls, verify the audit log, then tamper with copies of it and verify again.
#
#   ./scripts/run_demo.sh
set -euo pipefail

cd "$(dirname "$0")/.."
WORK="$(mktemp -d)"
PORT="${PORT:-8765}"
GW=(uv run --quiet mcp-gateway)
trap 'kill "${GW_PID:-}" 2>/dev/null || true; rm -rf "$WORK"' EXIT

echo "== setup (in $WORK)"
"${GW[@]}" keygen --out "$WORK/key" >/dev/null
USER_TOKEN="$("${GW[@]}" issue-token --sessions "$WORK/sessions.yaml" --principal alice --role user)"
ADMIN_TOKEN="$("${GW[@]}" issue-token --sessions "$WORK/sessions.yaml" --principal root --role admin)"
echo "  key, a user token and an admin token issued (only token hashes are stored)"

echo "== start the gateway on :$PORT (demo tool server as upstream)"
"${GW[@]}" serve --upstream "$(uv run --quiet python -c 'import shlex,sys; print(shlex.join([sys.executable, "-m", "tools.demo_server.server"]))')" \
  --sessions "$WORK/sessions.yaml" --key-file "$WORK/key" \
  --arg-rules src/mcp_lab/demo/arg-rules.yaml \
  --log "$WORK/audit.jsonl" --anchor "$WORK/head.json" \
  --port "$PORT" --heartbeat 1 &
GW_PID=$!
for _ in $(seq 50); do
  (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null && break
  sleep 0.2
done

echo "== calls through the gateway"
uv run --quiet python scripts/demo_calls.py "http://127.0.0.1:$PORT/mcp" "$USER_TOKEN" "$ADMIN_TOKEN"
sleep 1.5
kill "$GW_PID"; wait "$GW_PID" 2>/dev/null || true

verify() { "${GW[@]}" verify "$1" --key-file "$WORK/key" --anchor "$2" | head -3 | sed 's/^/    /' || true; }

echo "== verify the untouched log"
verify "$WORK/audit.jsonl" "$WORK/head.json"

for mode in edit delete truncate spoof; do
  cp "$WORK/audit.jsonl" "$WORK/t.jsonl"
  uv run --quiet python scripts/tamper_log.py "$mode" "$WORK/t.jsonl" --seq 2 >/dev/null
  echo "== attacker without the key: $mode"
  verify "$WORK/t.jsonl" "$WORK/head.json"
done

cp "$WORK/audit.jsonl" "$WORK/t.jsonl"; cp "$WORK/head.json" "$WORK/t-head.json"
uv run --quiet python scripts/tamper_log.py forge "$WORK/t.jsonl" --seq 2 \
  --key-file "$WORK/key" --anchor "$WORK/t-head.json" >/dev/null
echo "== attacker WITH the key: forge (rewrite the chain and the anchor)"
verify "$WORK/t.jsonl" "$WORK/t-head.json"
echo "   ^ passes: the log is only as strong as keeping the key away from the agent."
echo "   The Docker lab measures exactly that: see docs/results/scorecard.md"
