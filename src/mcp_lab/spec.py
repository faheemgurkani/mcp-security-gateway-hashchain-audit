"""Describe any MCP gateway in a small YAML spec, and score it with no Python.

A spec says how to start the gateway in front of the lab's demo tool server, where
its audit log ends up, and how to verify that log. Example (a stdio proxy)::

    name: my-gateway
    command: my-gateway run --config {{dir}}/config.yaml -- {{upstream}}
    files:
      config.yaml: |
        audit_log: {{dir}}/audit.jsonl
        allow: [crm.*]          # a user may call crm.* only
    log: "{{dir}}/audit.jsonl"
    verify: my-gateway verify {{log}}

Placeholders (``{{name}}``), filled in for every run:

=================  ==========================================================
``{{dir}}``        a fresh work directory for this run (the command's cwd)
``{{upstream}}``   executable that starts the demo tool server over stdio
``{{python}}``     the Python running mcp-lab
``{{port}}``       a free TCP port (HTTP gateways)
``{{log}}``        the rendered ``log`` path (in ``verify``/``forge``/``rug_alarm``)
``{{spec_dir}}``   the directory holding the spec file
=================  ==========================================================

Keys: ``name``, ``version``, ``transport`` (``stdio`` | ``http``), ``command``,
``url`` and ``headers`` (http), ``setup`` (shell commands run in the work dir
first), ``files`` (templates written into it), ``env``, ``log``, ``verify``
(exit 0 = the gateway accepts the log), ``forge`` (optional bespoke A12 rewrite;
otherwise every catalogued keyless scheme is tried), ``rug_alarm`` (optional;
exit 0 = the gateway raised a rug-pull alarm), ``legacy`` (``auto`` | true | false:
use the initialize-era MCP handshake), ``caveats``.

Commands run through ``/bin/sh -c`` in the work directory. In commands, placeholder
values are shell-quoted for you (paths may contain spaces): write ``{{log}}``, not
``"{{log}}"``. In ``files`` they are inserted as-is.
"""

import contextlib
import os
import shlex
import socket
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import anyio
import httpx2
import yaml
from mcp import Client, MCPError, StdioServerParameters
from mcp.client.streamable_http import streamable_http_client

from mcp_lab.harness import UPSTREAM, Gateway, upstream_env


class SpecError(ValueError):
    pass


@dataclass
class Spec:
    name: str
    command: str
    transport: str = "stdio"
    version: str = "?"
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    setup: list[str] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    log: str | None = None
    verify: str | None = None
    forge: str | None = None
    rug_alarm: str | None = None
    legacy: Any = "auto"
    caveats: list[str] = field(default_factory=list)
    spec_dir: Path = Path(".")
    ready_timeout: float = 20.0

    @classmethod
    def load(cls, path: Path) -> "Spec":
        data = yaml.safe_load(path.read_text()) or {}
        unknown = set(data) - {f for f in cls.__dataclass_fields__ if f != "spec_dir"}
        if unknown:
            raise SpecError(f"{path}: unknown keys {sorted(unknown)}")
        for key in ("name", "command"):
            if not data.get(key):
                raise SpecError(f"{path}: '{key}' is required")
        if data.get("transport", "stdio") not in ("stdio", "http"):
            raise SpecError(f"{path}: transport must be stdio or http")
        if data.get("transport") == "http" and not data.get("url"):
            raise SpecError(f"{path}: an http gateway needs 'url'")
        if data.get("verify") and not data.get("log"):
            raise SpecError(f"{path}: 'verify' needs 'log'")
        data["version"] = str(data.get("version", "?"))
        if isinstance(data.get("caveats"), str):
            data["caveats"] = [data["caveats"]]
        return cls(**data, spec_dir=path.resolve().parent)


# ---- rendering ------------------------------------------------------------------------
def _upstream_wrapper(d: Path, env: dict[str, str]) -> Path:
    """A tiny executable that starts the demo tool server with this run's ledger, so the
    gateway needs no way to pass environment variables through."""
    p = d / "upstream.sh"
    exports = "".join(f"export {k}='{v}'\n" for k, v in env.items())
    argv = " ".join(f"'{a}'" for a in UPSTREAM)
    p.write_text(f'#!/bin/sh\n{exports}exec {argv} "$@"\n')
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return p


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Run:
    """The rendered spec for one work directory."""

    def __init__(self, spec: Spec, d: Path, env: dict[str, str]):
        self.spec, self.d = spec, d
        self.vars = {
            "dir": str(d),
            "upstream": str(_upstream_wrapper(d, env)),
            "python": sys.executable,
            "port": str(_free_port()),
            "spec_dir": str(spec.spec_dir),
        }
        if spec.log:
            self.vars["log"] = self.render(spec.log)

    def render(self, text: str, quote: bool = False) -> str:
        """Fill placeholders; in shell commands (``quote``) each value is shell-quoted, so
        paths with spaces work and spec authors never quote placeholders themselves."""
        for k, v in self.vars.items():
            text = text.replace("{{" + k + "}}", shlex.quote(v) if quote else v)
        if "{{" in text:
            raise SpecError(f"unknown placeholder in: {text.strip()[:80]}")
        return text

    def sh(self, cmd: str, timeout: float = 120) -> tuple[bool, str]:
        argv = ["/bin/sh", "-c", self.render(cmd, quote=True)]
        r = subprocess.run(argv, cwd=self.d, env=self.env(), capture_output=True, text=True,
                           timeout=timeout)  # fmt: skip
        return r.returncode == 0, (r.stdout + r.stderr).strip()

    def env(self) -> dict[str, str]:
        return {**os.environ, **{k: self.render(str(v)) for k, v in self.spec.env.items()}}

    def write_files(self) -> None:
        for name, body in self.spec.files.items():
            target = self.d / self.render(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(self.render(body))

    def prepare(self) -> None:
        self.write_files()
        for cmd in self.spec.setup:
            ok, out = self.sh(cmd)
            if not ok:
                raise SpecError(f"setup command failed: {cmd.strip()[:80]}\n{out[-800:]}")


# ---- the Gateway built from a spec ----------------------------------------------------------
def build(spec: Spec, prefix: str = "", legacy: bool = False) -> Gateway:
    runs: dict[str, Run] = {}

    def run_for(d: Path, env: dict[str, str] | None = None) -> Run:
        key = str(d)
        if key not in runs:
            runs[key] = Run(spec, d, env or upstream_env(d))
            if env is None:
                # a copy of another run's directory (tamper cases): re-render the config
                # files so their paths point here, not at the original (absolute paths in a
                # copied config once made every tampered log look accepted)
                runs[key].write_files()
        return runs[key]

    @contextlib.asynccontextmanager
    async def connect(d: Path, env: dict[str, str]) -> AsyncIterator[Client]:
        r = run_for(d, env)
        r.prepare()
        mode = "legacy" if legacy else "auto"
        cmd = r.render(spec.command, quote=True)
        if spec.transport == "stdio":
            params = StdioServerParameters(command="/bin/sh", args=["-c", cmd], env=r.env(), cwd=d)
            async with Client(params, mode=mode) as c:
                yield c
            return
        url = r.render(spec.url or "")
        log = open(d / "gateway.out", "w")  # noqa: SIM115 - closed below
        proc = subprocess.Popen(["/bin/sh", "-c", cmd], cwd=d, env=r.env(), stdout=log,
                                stderr=subprocess.STDOUT, start_new_session=True)  # fmt: skip
        try:
            await _wait_http(url, proc, spec.ready_timeout, d / "gateway.out")
            headers = {k: r.render(str(v)) for k, v in spec.headers.items()}
            http = httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30, read=120))
            async with Client(streamable_http_client(url, http_client=http), mode=mode) as c:
                yield c
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, 15)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=10)
            log.close()

    def log_path(d: Path) -> Path:
        return Path(run_for(d).vars["log"])

    def verify(d: Path) -> tuple[bool, str]:
        return run_for(d).sh(spec.verify or "")

    def forge(d: Path) -> None:
        ok, out = run_for(d).sh(spec.forge or "")
        if not ok:
            raise SpecError(f"forge command failed: {out[-400:]}")

    def rug(d: Path) -> bool:
        return run_for(d).sh(spec.rug_alarm or "")[0]

    return Gateway(
        name=spec.name,
        version=spec.version,
        transport=spec.transport,
        connect=connect,
        log=log_path if spec.log else (lambda d: d / "no-log"),
        verify=verify if spec.verify else None,
        forge=forge if spec.forge else None,
        generic_forge=not spec.forge,
        rug_flagged=rug if spec.rug_alarm else None,
        prefix=prefix,
        caveats=spec.caveats,
    )


async def _wait_http(url: str, proc: subprocess.Popen, timeout: float, out: Path) -> None:
    host_port = url.split("://", 1)[-1].split("/", 1)[0]
    host, _, port = host_port.partition(":")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise SpecError(f"gateway exited with {proc.returncode}:\n{out.read_text()[-800:]}")
        with contextlib.suppress(OSError):
            socket.create_connection((host or "127.0.0.1", int(port or 80)), timeout=0.3).close()
            return
        await anyio.sleep(0.2)
    raise SpecError(f"gateway did not open {host_port} within {timeout:.0f}s")


# ---- probe: does the spec work, which tool prefix, which handshake -------------------------
async def _probe_once(gw: Gateway, d: Path) -> str:
    async with gw.connect(d, upstream_env(d)) as c:
        names = [t.name for t in (await c.list_tools()).tools]
        hit = [n for n in names if n.endswith("crm.lookup")]
        if not hit:
            raise SpecError(
                "the gateway does not list the demo tool crm.lookup; check that its config "
                f"wraps {{{{upstream}}}} and lets a user call crm.* (it listed: {names[:8]})"
            )
        prefix = hit[0][: -len("crm.lookup")]
        await c.call_tool(prefix + "crm.lookup", {"customer_id": "C1001"})
        # a call that should be denied too: some gateways shape only their own deny replies
        # for the older handshake (the probe's ledger is thrown away)
        with contextlib.suppress(MCPError):
            await c.call_tool(prefix + "admin.delete_user", {"user_id": "U2002"})
        return prefix


def probe(spec: Spec) -> Gateway:
    """Start the gateway once and return a Gateway with the right prefix and handshake.

    Some gateways negotiate the newest MCP spec but omit its required fields, which a
    current client rejects; with ``legacy: auto`` the probe retries with the
    initialize-era handshake.
    """
    modes = [spec.legacy] if isinstance(spec.legacy, bool) else [False, True]
    last: Exception | None = None
    for legacy in modes:
        gw = build(spec, legacy=legacy)
        d = Path(tempfile.mkdtemp(prefix=f"{spec.name}-probe-"))
        try:
            prefix = anyio.run(_probe_once, gw, d)
            return build(spec, prefix=prefix, legacy=legacy)
        except SpecError:
            raise
        except Exception as e:  # noqa: BLE001 - reported with the gateway's output below
            last = e
    detail = "".join(f"\n--- {p.name} ---\n{p.read_text()[-600:]}" for p in d.glob("gateway.out"))
    raise SpecError(f"could not talk MCP to the gateway: {_root(last)}{detail}")


def _root(e: BaseException | None) -> str:
    while isinstance(e, BaseExceptionGroup) and e.exceptions:
        e = e.exceptions[0]
    return f"{type(e).__name__}: {e}" if e else "unknown error"
