from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from mcp_permission_broker import (
    Broker,
    PermissionRequest,
    PolicyBundle,
    PolicyRule,
)

EXAMPLES = Path(__file__).parent.parent / "examples"


def _request(**overrides: object) -> PermissionRequest:
    defaults: dict[str, object] = {
        "caller_id": "acme-tutor-v2.1",
        "tool_name": "filesystem.read_file",
        "context": {"environment": "production"},
    }
    defaults.update(overrides)
    return PermissionRequest(**defaults)  # type: ignore[arg-type]


def test_default_outcome_is_deny_when_no_bundles() -> None:
    broker = Broker()
    decision = broker.check(_request())
    assert decision.outcome == "deny"
    assert decision.matched_rules == []
    assert "default" in decision.rationale


def test_explicit_default_allow_overrides() -> None:
    broker = Broker(default_outcome="allow")
    decision = broker.check(_request())
    assert decision.outcome == "allow"


def test_allow_rule_matches_read_only_baseline() -> None:
    broker = Broker.from_yaml_dir(EXAMPLES)
    decision = broker.check(_request(tool_name="filesystem.read_file"))
    assert decision.outcome == "allow"
    assert decision.matched_rules == ["allow-read-only-baseline"]
    assert decision.decision_card_refs == [
        "https://district.example/.well-known/decisions/SPRINGFIELD-DEC-2026-001.json"
    ]


def test_deny_trumps_allow_for_destructive_in_prod() -> None:
    broker = Broker.from_yaml_dir(EXAMPLES)
    decision = broker.check(
        _request(tool_name="filesystem.delete_file", context={"environment": "production"})
    )
    assert decision.outcome == "deny"
    assert decision.matched_rules == ["deny-destructive-prod-actions"]


def test_when_expr_gates_deny_to_production_only() -> None:
    """Same destructive tool in staging should NOT match the deny rule."""
    broker = Broker.from_yaml_dir(EXAMPLES)
    decision = broker.check(
        _request(tool_name="filesystem.delete_file", context={"environment": "staging"})
    )
    # staging → deny rule's when.expr is false → falls through. No allow rule matches deletes.
    # → default deny.
    assert decision.outcome == "deny"
    assert decision.matched_rules == []  # no matches; defaulted


def test_require_approval_for_pii_tools() -> None:
    broker = Broker.from_yaml_dir(EXAMPLES)
    decision = broker.check(_request(tool_name="pii.lookup_student"))
    assert decision.outcome == "require_approval"
    assert decision.matched_rules == ["require-approval-pii-tools"]


def test_correlation_id_is_uuid4() -> None:
    broker = Broker(default_outcome="allow")
    a = broker.check(_request()).correlation_id
    b = broker.check(_request()).correlation_id
    assert a != b
    assert len(a) == 36 and a.count("-") == 4


def test_when_expr_eval_failure_is_safe() -> None:
    """A malformed expression should NOT match (fail closed)."""
    broker = Broker(default_outcome="allow")
    broker.add_bundle(
        PolicyBundle(
            bundle_id="b",
            rules=[
                PolicyRule(
                    id="bad-expr",
                    effect="deny",
                    when={"expr": "this is not valid python syntax !!!"},
                )
            ],
        )
    )
    decision = broker.check(_request())
    assert decision.outcome == "allow"  # rule didn't match, default applied


def test_when_expr_cannot_use_builtins() -> None:
    """Restricted eval — `open` and `__import__` should be unavailable."""
    broker = Broker(default_outcome="allow")
    broker.add_bundle(
        PolicyBundle(
            bundle_id="b",
            rules=[
                PolicyRule(
                    id="builtin-leak",
                    effect="deny",
                    when={"expr": "open('/etc/passwd')"},
                )
            ],
        )
    )
    decision = broker.check(_request())
    # If builtins were available this would deny; the eval fails, rule skipped.
    assert decision.outcome == "allow"


def test_invalid_bundle_yaml_raises() -> None:
    broker = Broker()
    with pytest.raises(ValidationError):
        broker.add_bundle(PolicyBundle.model_validate({"bundle_id": "x", "rules": "not a list"}))
