"""Pydantic models for the broker's wire surface and rule grammar."""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

Outcome = Literal["allow", "deny", "require_approval"]


class PermissionRequest(BaseModel):
    """An invocation supplied by a host. The broker does not authenticate its caller."""

    model_config = ConfigDict(extra="forbid")

    caller_id: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Caller identifier asserted by the embedding application.",
    )
    tool_name: str = Field(
        ...,
        min_length=1,
        max_length=256,
        description="Tool identifier asserted by the embedding application.",
    )
    tool_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Opaque tool arguments. Not inspected by default.",
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form context for rules (tenant_id, environment, etc.).",
    )


class TrustedCardContext(BaseModel):
    """Runtime facts asserted by the embedding host, never by the MCP request.

    Construct this only after the host authenticates the caller, resolves the
    buyer and vendor resource, and checks each condition. This model validates
    shape, but cannot establish the host's authority by itself.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    buyer_id: str = Field(..., min_length=1, max_length=256)
    vendor_id: str = Field(..., min_length=1, max_length=512)
    action: Literal["use"]
    conditions_satisfied: dict[str, StrictBool] = Field(default_factory=dict)


class _Because(BaseModel):
    """Operator-supplied reference metadata; neither the card nor URL is verified."""

    model_config = ConfigDict(extra="ignore")

    decision_card: str | None = Field(
        default=None, description="Decision Card URL whose condition this rule enforces."
    )
    condition_id: str | None = Field(
        default=None, description="The condition.id from the Decision Card."
    )


class PolicyRule(BaseModel):
    """Local rule matched by regex and a restricted context condition grammar.

    A condition cannot run Python code. Rule patterns use the ``regex`` package
    with a 20 ms timeout per match; load only reviewed patterns.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    priority: int = 0
    effect: Outcome
    tool_name: str = Field(
        default=".*",
        min_length=1,
        max_length=256,
        description="Regex matched against request.tool_name.",
    )
    caller_id: str = Field(
        default=".*",
        min_length=1,
        max_length=256,
        description="Regex matched against request.caller_id.",
    )
    when: dict[str, str] | None = Field(
        default=None,
        description="Optional {'expr': <restricted condition over `context`>}.",
    )
    because: _Because | None = None


class PolicyBundle(BaseModel):
    """A local rules[] bundle, incompatible with policy-as-code-engine policies[]."""

    model_config = ConfigDict(extra="forbid")

    bundle_id: str
    decision_card_url: str | None = None
    rules: list[PolicyRule] = Field(default_factory=list)


class PermissionDecision(BaseModel):
    """The broker's verdict on a PermissionRequest."""

    model_config = ConfigDict(extra="forbid")

    outcome: Outcome
    matched_rules: list[str] = Field(default_factory=list)
    decision_card_refs: list[str] = Field(default_factory=list)
    correlation_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    rationale: str = ""
