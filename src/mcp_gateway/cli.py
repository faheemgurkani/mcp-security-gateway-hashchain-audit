"""mcp-gateway: serve | verify | keygen | issue-token."""

import json
import os
import secrets
from pathlib import Path

import typer
import yaml

from mcp_gateway.audit import AuditChain, FileAnchor, verify_log
from mcp_gateway.identity import SessionRegistry, hash_token
from mcp_gateway.identity.session import new_token
from mcp_gateway.policy import Policy

app = typer.Typer(no_args_is_help=True, add_completion=False)

DEFAULT_POLICY = Path(__file__).parent / "policy" / "policy.yaml"


def read_key(path: Path) -> bytes:
    return bytes.fromhex(path.read_text().strip())


@app.command()
def keygen(out: Path = typer.Option(..., help="Where to write the hex HMAC key (mode 0600).")):
    """Generate a 256-bit HMAC key for the audit chain."""
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secrets.token_hex(32) + "\n")
    typer.echo(f"wrote {out}")


@app.command("issue-token")
def issue_token(
    sessions: Path = typer.Option(..., help="Gateway sessions file (YAML) to append to."),
    principal: str = typer.Option(...),
    role: str = typer.Option(...),
):
    """Create a session token; only its SHA-256 is stored. Prints the token once."""
    data = yaml.safe_load(sessions.read_text()) if sessions.exists() else None
    data = data or {"sessions": []}
    token = new_token()
    data["sessions"].append(
        {"principal": principal, "role": role, "token_sha256": hash_token(token)}
    )
    sessions.write_text(yaml.safe_dump(data, sort_keys=False))
    typer.echo(token)


@app.command()
def serve(
    upstream: str = typer.Option(..., help="Command that starts the stdio MCP tool server."),
    sessions: Path = typer.Option(...),
    key_file: Path = typer.Option(...),
    log: Path = typer.Option(Path("audit.jsonl")),
    anchor: Path | None = typer.Option(None, help="Log-head anchor file (outside agent reach)."),
    policy: Path = typer.Option(DEFAULT_POLICY),
    host: str = "127.0.0.1",
    port: int = 8000,
    heartbeat: float = 5.0,
    upstream_env: list[str] = typer.Option([], help="KEY=VALUE passed to the tool server."),
    upstream_token_file: Path | None = typer.Option(
        None, help="Bearer token the gateway presents to an HTTP tool server."
    ),
    allowed_host: list[str] = typer.Option([], help="Accepted Host headers, e.g. gateway:*"),
):
    """Run the reference gateway (Streamable HTTP at /mcp)."""
    import uvicorn

    from mcp_gateway.proxy import GatewayConfig, build_app

    cfg = GatewayConfig(
        upstream_command=upstream,
        policy=Policy.from_yaml(policy),
        sessions=SessionRegistry.from_yaml(sessions),
        chain=AuditChain(log, read_key(key_file), FileAnchor(anchor) if anchor else None),
        heartbeat_s=heartbeat,
        upstream_env=dict(kv.split("=", 1) for kv in upstream_env) or None,
        upstream_token=upstream_token_file.read_text().strip() if upstream_token_file else None,
        allowed_hosts=allowed_host or None,
    )
    uvicorn.run(build_app(cfg), host=host, port=port, log_level="warning")


@app.command()
def verify(
    log: Path,
    key_file: Path = typer.Option(...),
    anchor: Path | None = typer.Option(None),
    max_gap_ms: int | None = typer.Option(None, help="Flag silences longer than this."),
    as_json: bool = typer.Option(False, "--json"),
):
    """Verify a log; exit code 1 on any issue."""
    head = FileAnchor(anchor).read() if anchor else None
    report = verify_log(log, read_key(key_file), head, max_gap_ms)
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "ok": report.ok,
                    "entries": report.entries,
                    "issues": [i.__dict__ for i in report.issues],
                }
            )
        )
    else:
        typer.echo(f"{'OK' if report.ok else 'FAIL'}: {report.entries} entries")
        for i in report.issues:
            typer.echo(f"  line {i.line} seq {i.seq}: {i.kind}: {i.detail}")
    raise typer.Exit(0 if report.ok else 1)
