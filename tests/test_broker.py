from __future__ import annotations

from pathlib import Path

import httpx
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


@pytest.mark.parametrize("field", ["caller_id", "tool_name"])
def test_request_rejects_empty_or_oversized_identity_fields(field: str) -> None:
    for value in ("", "x" * 257):
        with pytest.raises(ValidationError):
            PermissionRequest.model_validate(
                {"caller_id": "agent", "tool_name": "filesystem.read_file", field: value}
            )


def test_rule_rejects_oversized_regex() -> None:
    with pytest.raises(ValidationError):
        PolicyRule(id="oversized", effect="allow", caller_id="a" * 257)


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
    """A malformed expression must deny even if permissive mode was selected."""
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
    assert decision.outcome == "deny"
    assert decision.matched_rules == ["bad-expr"]


def test_when_expr_cannot_use_builtins() -> None:
    """The restricted grammar rejects calls to `open` and `__import__`."""
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
    assert decision.outcome == "deny"
    assert decision.matched_rules == ["builtin-leak"]


def test_false_condition_does_not_block_an_allow_rule() -> None:
    broker = Broker()
    broker.add_bundle(
        PolicyBundle(
            bundle_id="b",
            rules=[
                PolicyRule(
                    id="deny-prod",
                    effect="deny",
                    when={"expr": "context.get('environment') == 'production'"},
                ),
                PolicyRule(id="allow-staging", effect="allow"),
            ],
        )
    )
    decision = broker.check(_request(context={"environment": "staging"}))
    assert decision.outcome == "allow"
    assert decision.matched_rules == ["allow-staging"]


def test_invalid_when_shape_cannot_become_unconditional_allow() -> None:
    broker = Broker()
    broker.add_bundle(
        PolicyBundle(
            bundle_id="b",
            rules=[PolicyRule(id="bad-when", effect="allow", when={"not_expr": "yes"})],
        )
    )
    decision = broker.check(_request())
    assert decision.outcome == "deny"
    assert decision.matched_rules == ["bad-when"]


def test_empty_when_cannot_become_unconditional_allow() -> None:
    broker = Broker()
    broker.add_bundle(
        PolicyBundle(
            bundle_id="b",
            rules=[PolicyRule(id="empty-when", effect="allow", when={})],
        )
    )
    decision = broker.check(_request())
    assert decision.outcome == "deny"
    assert decision.matched_rules == ["empty-when"]


def test_invalid_regex_denies_instead_of_crashing() -> None:
    broker = Broker()
    broker.add_bundle(
        PolicyBundle(
            bundle_id="b",
            rules=[PolicyRule(id="bad-regex", effect="allow", tool_name="(")],
        )
    )
    decision = broker.check(_request())
    assert decision.outcome == "deny"
    assert decision.matched_rules == ["bad-regex"]


def test_non_2xx_audit_response_is_logged_without_leaking_url(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    events: list[dict[str, object]] = []

    def failed_post(url: str, *, json: dict[str, object], timeout: float) -> httpx.Response:
        events.append(json)
        return httpx.Response(503, request=httpx.Request("POST", url))

    monkeypatch.setattr("mcp_permission_broker.broker.httpx.post", failed_post)
    broker = Broker(audit_stream_url="https://audit.example/secret-in-url")
    decision = broker.check(_request(tool_args={"sensitive": "never-log"}))
    assert decision.outcome == "deny"
    assert events[0]["kind"] == "tool_invocation_denied"
    assert events[0]["source"] == "mcp-permission-broker"
    assert isinstance(events[0]["payload"], dict)
    assert events[0]["payload"]["correlation_id"] == decision.correlation_id
    assert "tool_args" not in events[0]
    assert "context" not in events[0]
    assert "HTTPStatusError" in caplog.text
    assert "secret-in-url" not in caplog.text


def test_failed_deny_condition_cannot_fall_through_to_allow() -> None:
    broker = Broker()
    broker.add_bundle(
        PolicyBundle(
            bundle_id="b",
            rules=[
                PolicyRule(
                    id="deny-prod",
                    effect="deny",
                    when={"expr": "context['environment'] == 'production'"},
                ),
                PolicyRule(id="allow-all", effect="allow"),
            ],
        )
    )
    decision = broker.check(_request(context={}))
    assert decision.outcome == "deny"
    assert decision.matched_rules == ["deny-prod"]


def test_python_object_traversal_is_not_executed_as_a_condition() -> None:
    broker = Broker()
    broker.add_bundle(
        PolicyBundle(
            bundle_id="b",
            rules=[
                PolicyRule(
                    id="unsafe",
                    effect="allow",
                    when={"expr": "().__class__.__mro__[1].__subclasses__()"},
                )
            ],
        )
    )
    decision = broker.check(_request())
    assert decision.outcome == "deny"
    assert decision.matched_rules == ["unsafe"]


def test_invalid_bundle_yaml_raises() -> None:
    broker = Broker()
    with pytest.raises(ValidationError):
        broker.add_bundle(PolicyBundle.model_validate({"bundle_id": "x", "rules": "not a list"}))
