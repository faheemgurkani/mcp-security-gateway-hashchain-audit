"""Strict per-tool argument schemas.

The MCP Python SDK v2 advertises a tool's input schema but does not enforce
it, so the gateway validates every call itself. Models forbid extra fields
(no smuggled parameters) and use strict types (no "1" -> 1 coercion). A
tool without a registered schema is rejected: default deny.
"""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError

CustomerId = Annotated[str, StringConstraints(pattern=r"^C\d{4,8}$")]
UserId = Annotated[str, StringConstraints(pattern=r"^U\d{4,8}$")]


class StrictArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CrmLookup(StrictArgs):
    customer_id: CustomerId


class CrmUpdate(StrictArgs):
    customer_id: CustomerId
    field: Literal["email", "phone", "notes"]
    value: Annotated[str, StringConstraints(max_length=500)]


class AdminDeleteUser(StrictArgs):
    user_id: UserId


SCHEMAS: dict[str, type[StrictArgs]] = {
    "crm.lookup": CrmLookup,
    "crm.update": CrmUpdate,
    "admin.delete_user": AdminDeleteUser,
}


class ArgumentError(ValueError):
    pass


def validate_arguments(tool: str, arguments: dict[str, Any] | None) -> dict[str, Any]:
    model = SCHEMAS.get(tool)
    if model is None:
        raise ArgumentError(f"no schema registered for tool {tool!r}")
    try:
        return model.model_validate(arguments or {}).model_dump()
    except ValidationError as e:
        problems = "; ".join(
            f"{'.'.join(map(str, err['loc'])) or '<root>'}: {err['msg']}" for err in e.errors()
        )
        raise ArgumentError(problems) from e
