from __future__ import annotations

import base64
import hashlib
from pathlib import Path
from threading import Event, Thread
from typing import Any

import httpx
import pytest
import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from policy_as_code_engine.card_attestation import CardAttestation
from pydantic import ValidationError

from mcp_permission_broker import (
    Broker,
    PermissionRequest,
    PolicyBundle,
    PolicyRule,
    TrustedCardContext,
)

EXAMPLES = Path(__file__).parent.parent / "examples"
TEST_AUDIT_TOKEN = "T" * 32


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


def test_local_regex_timeout_denies(monkeypatch: pytest.MonkeyPatch) -> None:
    def timed_out(pattern: str, value: str, *, timeout: float) -> None:
        assert timeout == 0.02
        raise TimeoutError

    monkeypatch.setattr("mcp_permission_broker.broker.regex.fullmatch", timed_out)
    broker = Broker(default_outcome="allow")
    broker.add_bundle(
        PolicyBundle(
            bundle_id="local",
            rules=[PolicyRule(id="slow", effect="allow", tool_name=r"(a|aa)+$")],
        )
    )
    decision = broker.check(_request(tool_name="a" * 255 + "!"))
    assert decision.outcome == "deny"
    assert decision.matched_rules == ["slow"]


@pytest.mark.parametrize("status", [302, 401, 503])
def test_non_2xx_audit_response_is_logged_without_leaking_url(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, status: int
) -> None:
    events: list[dict[str, object]] = []
    urls: list[str] = []
    monkeypatch.setenv("AUDIT_STREAM_TOKEN", TEST_AUDIT_TOKEN)

    def failed_post(
        url: str,
        *,
        json: dict[str, object],
        headers: dict[str, str],
        timeout: float,
        follow_redirects: bool,
    ) -> httpx.Response:
        events.append(json)
        urls.append(url)
        assert headers == {"Authorization": f"Bearer {TEST_AUDIT_TOKEN}"}
        assert follow_redirects is False
        return httpx.Response(status, request=httpx.Request("POST", url))

    monkeypatch.setattr("mcp_permission_broker.broker.httpx.post", failed_post)
    broker = Broker(audit_stream_url="https://audit.example/secret-in-url")
    decision = broker.check(_request(tool_args={"sensitive": "never-log"}))
    assert decision.outcome == "deny"
    assert events[0]["kind"] == "tool_invocation_denied"
    assert urls == ["https://audit.example/secret-in-url/events"]
    assert events[0]["source"] == "mcp-permission-broker"
    assert isinstance(events[0]["payload"], dict)
    assert events[0]["payload"]["correlation_id"] == decision.correlation_id
    assert "tool_args" not in events[0]
    assert "context" not in events[0]
    assert "HTTPStatusError" in caplog.text
    assert "secret-in-url" not in caplog.text
    assert TEST_AUDIT_TOKEN not in caplog.text


def test_audit_legacy_events_endpoint_is_not_duplicated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    urls: list[str] = []
    monkeypatch.setenv("AUDIT_STREAM_TOKEN", TEST_AUDIT_TOKEN)

    def accepted_post(
        url: str,
        *,
        json: dict[str, object],
        headers: dict[str, str],
        timeout: float,
        follow_redirects: bool,
    ) -> httpx.Response:
        urls.append(url)
        assert headers == {"Authorization": f"Bearer {TEST_AUDIT_TOKEN}"}
        assert follow_redirects is False
        return httpx.Response(201, request=httpx.Request("POST", url))

    monkeypatch.setattr("mcp_permission_broker.broker.httpx.post", accepted_post)
    Broker(audit_stream_url="https://audit.example/events").check(_request())
    assert urls == ["https://audit.example/events"]


def test_audit_missing_token_skips_post(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.delenv("AUDIT_STREAM_TOKEN", raising=False)

    def unexpected_post(*args: object, **kwargs: object) -> None:
        pytest.fail("anonymous audit POST must not be attempted")

    monkeypatch.setattr("mcp_permission_broker.broker.httpx.post", unexpected_post)
    Broker(audit_stream_url="https://audit.example").check(_request())
    assert "AUDIT_STREAM_TOKEN is missing or invalid" in caplog.text


@pytest.mark.parametrize("token", ["short", "T" * 31 + " ", "é" * 32])
def test_audit_invalid_token_skips_post(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, token: str
) -> None:
    monkeypatch.setenv("AUDIT_STREAM_TOKEN", token)

    def unexpected_post(*args: object, **kwargs: object) -> None:
        pytest.fail("invalid audit token must not be sent")

    monkeypatch.setattr("mcp_permission_broker.broker.httpx.post", unexpected_post)
    Broker(audit_stream_url="https://audit.example").check(_request())
    assert "AUDIT_STREAM_TOKEN is missing or invalid" in caplog.text
    assert token not in caplog.text


@pytest.mark.parametrize(
    "url",
    [
        "http://audit.example",
        "http://localhost:8093",
        "https://user:password@audit.example",
        "https://audit.example?token=secret",
        "file:///tmp/audit.sock",
    ],
)
def test_audit_rejects_insecure_or_credentialed_url(url: str) -> None:
    with pytest.raises(ValueError, match="audit stream URL"):
        Broker(audit_stream_url=url)


@pytest.mark.parametrize("url", ["http://127.0.0.1:8093", "http://[::1]:8093"])
def test_audit_accepts_numeric_loopback_http(url: str) -> None:
    Broker(audit_stream_url=url)


def _signed_card(
    *,
    status: str = "approved",
    conditions: list[dict[str, str]] | None = None,
    effective_until: str = "2999-01-01T00:00:00Z",
) -> tuple[dict[str, Any], CardAttestation, bytes]:
    card: dict[str, Any] = {
        "decision_card_version": "0.1",
        "decision_id": "TEST-001",
        "issued_at": "2026-05-14T19:00:00Z",
        "buyer": {"id": "buyer-1", "name": "Buyer One", "type": "school-district"},
        "decision": {"status": status, "effective_until": effective_until},
        "subject": {"vendor_name": "Vendor One", "vendor_id": "vendor-1"},
        "rationale": "Synthetic test fixture.",
    }
    if conditions is not None:
        card["conditions"] = conditions
    key = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
    fields = {
        "algorithm": "ed25519",
        "hash_profile": "jcs-rfc8785-v1",
        "signed_hash": "sha256:" + hashlib.sha256(rfc8785.dumps(card)).hexdigest(),
        "key_url": "https://buyer.example/keys/card",
        "signed_at": "2026-10-07T12:00:00Z",
    }
    signature = key.sign(b"hash-attestation/v2\x00" + rfc8785.dumps(fields))
    attestation = CardAttestation(**fields, signature=base64.b64encode(signature).decode("ascii"))
    return card, attestation, key.public_key().public_bytes_raw()


def _load_card(
    broker: Broker, card: dict[str, Any], attestation: CardAttestation, key: bytes
) -> None:
    broker.add_signed_decision_card(
        card,
        attestation=attestation,
        expected_buyer_id="buyer-1",
        trusted_key_url="https://buyer.example/keys/card",
        trusted_public_key=key,
    )


def _trusted_context(**overrides: object) -> TrustedCardContext:
    values: dict[str, object] = {
        "buyer_id": "buyer-1",
        "vendor_id": "vendor-1",
        "action": "use",
        "conditions_satisfied": {},
    }
    values.update(overrides)
    return TrustedCardContext.model_validate(values)


def test_signed_card_gate_allows_only_attested_scoped_card() -> None:
    card, attestation, key = _signed_card()
    broker = Broker(require_signed_card=True)
    assert broker.check(_request(), trusted_card_context=_trusted_context()).outcome == "deny"
    _load_card(broker, card, attestation, key)
    assert broker.check(_request(), trusted_card_context=_trusted_context()).outcome == "allow"
    assert broker.check(_request()).outcome == "deny"
    assert (
        broker.check(_request(), trusted_card_context=_trusted_context(buyer_id="other")).outcome
        == "deny"
    )
    assert (
        broker.check(_request(), trusted_card_context=_trusted_context(vendor_id="other")).outcome
        == "deny"
    )


def test_untrusted_request_context_cannot_satisfy_signed_card_conditions() -> None:
    card, attestation, key = _signed_card(
        status="approved-with-conditions",
        conditions=[{"id": "dpa-signed", "description": "DPA on file"}],
    )
    broker = Broker(require_signed_card=True)
    _load_card(broker, card, attestation, key)
    spoofed = _request(
        context={
            "buyer_id": "buyer-1",
            "vendor_id": "vendor-1",
            "conditions_satisfied": {"dpa-signed": True},
        }
    )
    assert broker.check(spoofed).outcome == "deny"
    assert broker.check(spoofed, trusted_card_context=_trusted_context()).outcome == "deny"
    assert (
        broker.check(
            _request(),
            trusted_card_context=_trusted_context(conditions_satisfied={"dpa-signed": True}),
        ).outcome
        == "allow"
    )
    with pytest.raises(ValidationError):
        _trusted_context(conditions_satisfied={"dpa-signed": 1})


def test_signed_card_and_local_rules_must_both_allow() -> None:
    card, attestation, key = _signed_card()
    broker = Broker(require_signed_card=True, default_outcome="allow")
    _load_card(broker, card, attestation, key)
    broker.add_bundle(
        PolicyBundle(
            bundle_id="local",
            rules=[
                PolicyRule(id="read-only", effect="allow", tool_name=r"^filesystem\.read_file$")
            ],
        )
    )
    assert broker.check(_request(), trusted_card_context=_trusted_context()).outcome == "allow"
    assert (
        broker.check(
            _request(tool_name="filesystem.delete_file"),
            trusted_card_context=_trusted_context(),
        ).outcome
        == "deny"
    )


def test_signed_card_rejects_tamper_and_failed_reload_invalidates_prior_allow() -> None:
    card, attestation, key = _signed_card()
    broker = Broker(require_signed_card=True)
    _load_card(broker, card, attestation, key)
    assert broker.check(_request(), trusted_card_context=_trusted_context()).outcome == "allow"
    tampered = {**card, "rationale": "changed after signature"}
    with pytest.raises(ValueError):
        _load_card(broker, tampered, attestation, key)
    assert broker.check(_request(), trusted_card_context=_trusted_context()).outcome == "deny"
    with pytest.raises(ValueError, match="buyer"):
        broker.add_signed_decision_card(
            card,
            attestation=attestation,
            expected_buyer_id="wrong-buyer",
            trusted_key_url="https://buyer.example/keys/card",
            trusted_public_key=key,
        )
    assert broker.check(_request(), trusted_card_context=_trusted_context()).outcome == "deny"


def test_superseded_card_reload_cannot_restore_old_approval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved, attestation, key = _signed_card()
    withdrawn, withdrawn_attestation, _ = _signed_card(status="withdrawn")
    broker = Broker(require_signed_card=True)
    from mcp_permission_broker import broker as broker_module

    real_converter = broker_module.policy_bundle_from_decision_card
    entered = Event()
    resume = Event()
    errors: list[Exception] = []

    def delayed_converter(card: dict[str, Any], **kwargs: Any) -> Any:
        if card["decision"]["status"] == "approved":
            entered.set()
            assert resume.wait(5)
        return real_converter(card, **kwargs)

    def load_approved() -> None:
        try:
            _load_card(broker, approved, attestation, key)
        except Exception as exc:
            errors.append(exc)

    monkeypatch.setattr(broker_module, "policy_bundle_from_decision_card", delayed_converter)
    thread = Thread(target=load_approved)
    thread.start()
    try:
        assert entered.wait(5)
        assert broker.check(_request(), trusted_card_context=_trusted_context()).outcome == "deny"
        _load_card(broker, withdrawn, withdrawn_attestation, key)
    finally:
        resume.set()
        thread.join(5)
    assert not thread.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], RuntimeError)
    assert broker.check(_request(), trusted_card_context=_trusted_context()).outcome == "deny"


def test_card_reload_waits_for_local_rule_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    approved, attestation, key = _signed_card()
    withdrawn, withdrawn_attestation, _ = _signed_card(status="withdrawn")
    broker = Broker(require_signed_card=True, audit_stream_url="")
    _load_card(broker, approved, attestation, key)
    broker.add_bundle(
        PolicyBundle(
            bundle_id="local",
            rules=[PolicyRule(id="local-allow", effect="allow", when={"expr": "True"})],
        )
    )
    from mcp_permission_broker import broker as broker_module

    entered = Event()
    resume = Event()
    reload_started = Event()
    reload_done = Event()
    outcomes: list[str] = []

    def blocked_condition(expr: str, context: dict[str, Any]) -> bool:
        entered.set()
        assert resume.wait(5)
        return True

    def check_in_thread() -> None:
        outcomes.append(broker.check(_request(), trusted_card_context=_trusted_context()).outcome)

    def reload_in_thread() -> None:
        reload_started.set()
        _load_card(broker, withdrawn, withdrawn_attestation, key)
        reload_done.set()

    monkeypatch.setattr(broker_module, "_evaluate_condition", blocked_condition)
    check_thread = Thread(target=check_in_thread)
    reload_thread = Thread(target=reload_in_thread)
    check_thread.start()
    try:
        assert entered.wait(5)
        reload_thread.start()
        assert reload_started.wait(5)
        assert not reload_done.wait(0.1)
    finally:
        resume.set()
        check_thread.join(5)
        if reload_thread.ident is not None:
            reload_thread.join(5)
    assert not check_thread.is_alive() and not reload_thread.is_alive()
    assert outcomes == ["allow"]
    assert broker.check(_request(), trusted_card_context=_trusted_context()).outcome == "deny"


@pytest.mark.parametrize("status", ["withdrawn", "expired"])
def test_terminal_card_status_denies(status: str) -> None:
    card, attestation, key = _signed_card(status=status)
    broker = Broker(require_signed_card=True)
    _load_card(broker, card, attestation, key)
    assert broker.check(_request(), trusted_card_context=_trusted_context()).outcome == "deny"


def test_expired_effective_window_denies() -> None:
    card, attestation, key = _signed_card(effective_until="2026-10-07T23:00:00Z")
    broker = Broker(require_signed_card=True)
    _load_card(broker, card, attestation, key)
    assert broker.check(_request(), trusted_card_context=_trusted_context()).outcome == "deny"


def test_serialized_unsigned_engine_bundle_is_not_accepted() -> None:
    broker = Broker(require_signed_card=True)
    with pytest.raises(TypeError):
        broker.add_bundle({"bundle_id": "fake", "policies": []})  # type: ignore[arg-type]
    assert broker.check(_request(), trusted_card_context=_trusted_context()).outcome == "deny"


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
