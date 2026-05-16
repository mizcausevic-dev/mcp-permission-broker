"""Pydantic models for the broker's wire surface and rule grammar."""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Outcome = Literal["allow", "deny", "require_approval"]


class PermissionRequest(BaseModel):
    """An MCP tool invocation, presented to the broker for a decision."""

    model_config = ConfigDict(extra="forbid")

    caller_id: str = Field(
        ..., description="Identity of the agent / tool client (e.g. agent_card.system_id)."
    )
    tool_name: str = Field(
        ..., description="The MCP tool being invoked (e.g. 'github.search_repositories')."
    )
    tool_args: dict[str, Any] = Field(
        default_factory=dict,
        description="Opaque tool arguments. Not inspected by default.",
    )
    context: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form context for rules (tenant_id, environment, etc.).",
    )


class _Because(BaseModel):
    """Provenance for why a rule exists — typically traces back to a Decision Card."""

    model_config = ConfigDict(extra="ignore")

    decision_card: str | None = Field(
        default=None, description="Decision Card URL whose condition this rule enforces."
    )
    condition_id: str | None = Field(
        default=None, description="The condition.id from the Decision Card."
    )


class PolicyRule(BaseModel):
    """A single rule. Matched against PermissionRequest via regex on tool_name + caller_id.

    Optional `when.expr` is a Python expression evaluated against a single
    bound name `context` (the request's context dict). The expression is
    evaluated with no builtins to limit blast radius.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    priority: int = 0
    effect: Outcome
    tool_name: str = Field(default=".*", description="Regex matched against request.tool_name.")
    caller_id: str = Field(default=".*", description="Regex matched against request.caller_id.")
    when: dict[str, str] | None = Field(
        default=None,
        description="Optional {'expr': <python expression over `context`>}.",
    )
    because: _Because | None = None


class PolicyBundle(BaseModel):
    """A named collection of rules. Typically produced by policy-as-code-engine
    from a single AI Procurement Decision Card."""

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
