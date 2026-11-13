"""Argument rules for any tool, from config or from the tool's own pinned schema.

The MCP Python SDK v2 advertises a tool's input schema but does not enforce it,
so the gateway validates every call itself. Each tool's rule is a JSON Schema,
taken from (first match wins):

1. the operator's rules file (``--arg-rules``), which can tighten a tool beyond
   what its server advertises (patterns, enums, lengths);
2. the tool's own ``inputSchema``, captured when the gateway starts. Pinning
   (``policy/pinning.py``) quarantines a tool whose definition later changes,
   so this schema cannot be swapped under the gateway;
3. nothing: the call is rejected (default deny).

Schemas are **closed by default**: any object schema that does not say
otherwise gets ``additionalProperties: false``, so smuggled fields are rejected.
JSON Schema never coerces types, so ``"1"`` is not accepted for an integer.
"""

import copy
import hashlib
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from mcp_lab.gateway.audit.canonical import canonical


class ArgumentError(ValueError):
    pass


def close_schema(schema: Any) -> Any:
    """Copy of ``schema`` where every object schema rejects undeclared fields."""
    s = copy.deepcopy(schema)

    def walk(node: Any) -> None:
        if isinstance(node, list):
            for x in node:
                walk(x)
            return
        if not isinstance(node, dict):
            return
        is_object = node.get("type") == "object" or "properties" in node
        if is_object and "additionalProperties" not in node:
            node["additionalProperties"] = False
        for key in ("properties", "$defs", "definitions", "patternProperties"):
            for sub in (node.get(key) or {}).values():
                walk(sub)
        for key in ("items", "additionalProperties", "not", "if", "then", "else"):
            walk(node.get(key))
        for key in ("allOf", "anyOf", "oneOf", "prefixItems"):
            walk(node.get(key))

    walk(s)
    return s


def load_rules_file(path: Path) -> dict[str, dict]:
    """Read ``{tools: {name: <JSON Schema>}}`` from YAML or JSON."""
    data = yaml.safe_load(path.read_text()) or {}
    tools = data.get("tools")
    if not isinstance(tools, dict):
        raise ValueError(f"{path}: expected a top-level 'tools' mapping")
    return tools


class ArgumentRules:
    def __init__(self, schemas: dict[str, dict], sources: dict[str, str]):
        self.sources = sources  # tool -> "config" | "upstream"
        self.schemas = {name: close_schema(s) for name, s in schemas.items()}
        self._validators = {}
        for name, s in self.schemas.items():
            try:
                Draft202012Validator.check_schema(s)
            except SchemaError as e:
                raise ValueError(f"invalid schema for tool {name!r}: {e.message}") from e
            self._validators[name] = Draft202012Validator(s, format_checker=FormatChecker())

    @classmethod
    def build(
        cls, configured: dict[str, dict] | None, upstream: dict[str, dict] | None
    ) -> "ArgumentRules":
        schemas: dict[str, dict] = {}
        sources: dict[str, str] = {}
        for name, s in (upstream or {}).items():
            if isinstance(s, dict) and s:
                schemas[name], sources[name] = s, "upstream"
        for name, s in (configured or {}).items():
            schemas[name], sources[name] = s, "config"
        return cls(schemas, sources)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(canonical(self.schemas)).hexdigest()

    def validate(self, tool: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
        validator = self._validators.get(tool)
        if validator is None:
            raise ArgumentError(f"no argument rule for tool {tool!r}")
        args = {} if arguments is None else arguments
        errors = sorted(validator.iter_errors(args), key=lambda e: list(e.absolute_path))
        if errors:
            raise ArgumentError(
                "; ".join(
                    f"{'.'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
                    for e in errors
                )
            )
        return copy.deepcopy(args)
