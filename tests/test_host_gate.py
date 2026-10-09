"""Synthetic tests for the opt-in MCP tools/call reference gate."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from mcp_permission_broker import Broker, PolicyBundle, PolicyRule
from mcp_permission_broker.host_gate import (
    AcceptedAuditReceipt,
    AuthenticatedToolGate,
    GateDenied,
    PrincipalBinding,
    ToolBinding,
)
from tests.test_broker import _signed_card


def _make_gate(
    *,
    card_status: str = "approved",
    card_conditions: list[dict[str, str]] | None = None,
    card_effective_until: str = "2999-01-01T00:00:00Z",
    condition_check: Callable[[PrincipalBinding, ToolBinding], bool] | None = None,
    audit_mode: str = "accepted",
    buyer_id: str = "buyer-1",
    tenant_id: str = "tenant-1",
    vendor_id: str = "vendor-1",
    validate_arguments: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    handler: Callable[[dict[str, Any]], Any] | None = None,
    on_audit: Callable[[], None] | None = None,
    load_card: bool = True,
    broker_audit_url: str = "",
) -> tuple[AuthenticatedToolGate, Ed25519PrivateKey, list[dict[str, Any]]]:
    calls: list[dict[str, Any]] = []

    def observed_handler(arguments: dict[str, Any]) -> object:
        calls.append(arguments)
        return handler(arguments) if handler else {"ok": True}

    def validate_demo(arguments: dict[str, Any]) -> dict[str, Any]:
        if set(arguments) != {"query"} or type(arguments["query"]) is not str:
            raise ValueError("demo.read requires one string query")
        return {"query": arguments["query"]}

    def audit(decision: Any, principal: Any, tool: Any, name: str) -> AcceptedAuditReceipt:
        assert principal.caller_id == "caller-one"
        assert tool.vendor_id == vendor_id
        assert name == "demo.read"
        if on_audit is not None:
            on_audit()
        if audit_mode == "error":
            raise TimeoutError("synthetic audit outage")
        if audit_mode == "wrong-id":
            return AcceptedAuditReceipt(
                correlation_id="other", accepted=True, event_id=1, hash="0" * 64
            )
        if audit_mode == "bool":
            return True  # type: ignore[return-value]
        return AcceptedAuditReceipt(
            correlation_id=decision.correlation_id,
            accepted=audit_mode == "accepted",
            event_id=0 if audit_mode == "missing-event" else 1,
            hash="bad" if audit_mode == "bad-hash" else "0" * 64,
        )

    broker = Broker(audit_stream_url=broker_audit_url)
    broker.add_bundle(
        PolicyBundle(
            bundle_id="tenant-rule",
            rules=[
                PolicyRule(
                    id="allow-demo-tenant-one",
                    effect="allow",
                    tool_name=r"^demo\.read$",
                    caller_id=r"^caller-one$",
                    when={"expr": "context['tenant_id'] == 'tenant-1'"},
                )
            ],
        )
    )
    auth_key = Ed25519PrivateKey.generate()
    public_pem = auth_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    gate = AuthenticatedToolGate(
        broker=broker,
        issuer="https://issuer.example/",
        audience="https://host.example/mcp",
        public_key_pem=public_pem,
        principals={
            "issuer-subject": PrincipalBinding(
                caller_id="caller-one",
                client_id="client-one",
                buyer_id=buyer_id,
                tenant_id=tenant_id,
            )
        },
        tools={
            "demo.read": ToolBinding(
                vendor_id=vendor_id,
                allowed_tenants=frozenset({"tenant-1"}),
                validate_arguments=validate_arguments or validate_demo,
                handler=observed_handler,
            )
        },
        conditions={"dpa-signed": condition_check} if condition_check else {},
        accepted_audit=audit,
    )
    if load_card:
        card, attestation, card_key = _signed_card(
            status=card_status,
            conditions=card_conditions,
            effective_until=card_effective_until,
        )
        gate.load_signed_decision_card(
            card,
            attestation=attestation,
            expected_buyer_id="buyer-1",
            trusted_key_url="https://buyer.example/keys/card",
            trusted_public_key=card_key,
        )
    return gate, auth_key, calls


def _token(key: Ed25519PrivateKey, **changes: object) -> str:
    now = int(time.time())
    claims: dict[str, object] = {
        "iss": "https://issuer.example/",
        "sub": "issuer-subject",
        "aud": "https://host.example/mcp",
        "client_id": "client-one",
        "scope": "mcp:tools.call",
        "jti": "jti-one",
        "iat": now - 1,
        "nbf": now - 1,
        "exp": now + 120,
    }
    claims.update(changes)
    return "Bearer " + jwt.encode(claims, key, algorithm="EdDSA")


def _call() -> dict[str, object]:
    return {"name": "demo.read", "arguments": {"query": "synthetic"}}


def test_selected_call_requires_card_token_scope_audit_and_rule() -> None:
    gate, key, calls = _make_gate()
    result = gate.dispatch(_token(key), _call())
    assert result.value == {"ok": True}
    assert len(result.correlation_id) == 36
    assert calls == [{"query": "synthetic"}]


def test_missing_card_denies_before_handler() -> None:
    gate, key, calls = _make_gate(load_card=False)
    with pytest.raises(GateDenied, match="policy_denied"):
        gate.dispatch(_token(key), _call())
    assert calls == []


def test_gate_rejects_duplicate_best_effort_broker_audit() -> None:
    with pytest.raises(ValueError, match="best-effort audit"):
        _make_gate(broker_audit_url="https://audit.example")


@pytest.mark.parametrize(
    "changes",
    [
        {"iss": "https://other.example/"},
        {"aud": "https://other.example/mcp"},
        {"client_id": "other-client"},
        {"scope": "mcp:tools.list"},
        {"scope": "mcp:tools.call admin"},
        {"exp": 1},
        {"iat": 1, "nbf": 1, "exp": 999_999_999_999},
        {"iat": 999_999_999_999, "nbf": 999_999_999_999, "exp": 1_000_000_000_000},
        {"buyer_id": "buyer-1"},
        {"tenant_id": "tenant-1"},
        {"vendor_id": "vendor-1"},
        {"conditions_satisfied": {"dpa-signed": True}},
        {"buyerId": "buyer-1"},
        {"custom": {"Tenant-ID": "tenant-1"}},
        {"aud": ["https://host.example/mcp"]},
        {"jti": "line\nbreak"},
        {"sub": " leading-space"},
    ],
)
def test_bad_token_claims_deny_before_handler(changes: dict[str, object]) -> None:
    gate, key, calls = _make_gate()
    with pytest.raises(GateDenied):
        gate.dispatch(_token(key, **changes), _call())
    assert calls == []


@pytest.mark.parametrize(
    "missing", ["iss", "sub", "aud", "iat", "nbf", "exp", "jti", "client_id", "scope"]
)
def test_missing_token_claim_denies(missing: str) -> None:
    gate, key, calls = _make_gate()
    now = int(time.time())
    claims: dict[str, object] = {
        "iss": "https://issuer.example/",
        "sub": "issuer-subject",
        "aud": "https://host.example/mcp",
        "client_id": "client-one",
        "scope": "mcp:tools.call",
        "jti": "jti-one",
        "iat": now - 1,
        "nbf": now - 1,
        "exp": now + 120,
    }
    claims.pop(missing)
    with pytest.raises(GateDenied, match="authentication_required"):
        gate.dispatch("Bearer " + jwt.encode(claims, key, algorithm="EdDSA"), _call())
    assert calls == []


def test_wrong_key_and_missing_bearer_deny() -> None:
    gate, key, calls = _make_gate()
    unsigned = "Bearer " + jwt.encode({"sub": "issuer-subject"}, key="", algorithm="none")
    wrong_alg = "Bearer " + jwt.encode({"sub": "issuer-subject"}, "S" * 32, algorithm="HS256")
    for authorization in (
        None,
        "Basic xyz",
        _token(Ed25519PrivateKey.generate()),
        unsigned,
        wrong_alg,
    ):
        with pytest.raises(GateDenied, match="authentication_required"):
            gate.dispatch(authorization, _call())
    assert calls == []
    assert gate.dispatch(_token(key), _call()).value == {"ok": True}


@pytest.mark.parametrize(
    "params",
    [
        {"name": "demo.read", "arguments": {}, "context": {"buyer_id": "buyer-1"}},
        {"name": "demo.read", "arguments": {"buyerId": "buyer-1"}},
        {"name": "demo.read", "arguments": {"outer": [{"Tenant-ID": "tenant-1"}]}},
        {"name": "demo.read", "arguments": {"document": '{"conditionsSatisfied":{"x":true}}'}},
        {"name": "demo.read", "arguments": {"document": '"{\\"vendorId\\":\\"x\\"}"'}},
        {"name": "demo.read", "arguments": {"query": float("nan")}},
        {"name": "demo.read", "arguments": {"query": "x" * 20_000}},
        {"name": "demo.read", "arguments": {"query": [[[[[[[[[[[[[[[[["x"]]]]]]]]]]]]]]]]]}},
        {"name": "demo.read", "arguments": {"query": 1}},
        {"name": "demo.read", "arguments": {"query": "ok", "extra": "not allowed"}},
    ],
)
def test_client_authority_or_invalid_arguments_deny_before_handler(
    params: dict[str, object],
) -> None:
    gate, key, calls = _make_gate()
    with pytest.raises(GateDenied, match="invalid_call"):
        gate.dispatch(_token(key), params)
    assert calls == []


def test_unknown_tool_tenant_buyer_vendor_and_condition_denials() -> None:
    for changes in (
        {"tenant_id": "tenant-2"},
        {"buyer_id": "buyer-2"},
        {"vendor_id": "vendor-2"},
        {
            "card_status": "approved-with-conditions",
            "card_conditions": [{"id": "dpa-signed", "description": "Synthetic DPA"}],
            "condition_check": lambda _principal, _tool: False,
        },
    ):
        gate, key, calls = _make_gate(**changes)  # type: ignore[arg-type]
        with pytest.raises(GateDenied):
            gate.dispatch(_token(key), _call())
        assert calls == []
    gate, key, calls = _make_gate()
    with pytest.raises(GateDenied, match="resource_denied"):
        gate.dispatch(_token(key), {"name": "demo.unknown", "arguments": {}})
    assert calls == []


def test_denied_decision_neither_invokes_handler_nor_acceptance_callback() -> None:
    def must_not_accept() -> None:
        pytest.fail("denied decisions must not request an allow receipt")

    gate, key, calls = _make_gate(buyer_id="wrong-buyer", on_audit=must_not_accept)
    with pytest.raises(GateDenied, match="policy_denied"):
        gate.dispatch(_token(key), _call())
    assert calls == []


def test_validator_output_is_checked_again_before_policy_and_handler() -> None:
    gate, key, calls = _make_gate(
        validate_arguments=lambda _arguments: {"query": "ok", "buyerId": "spoofed"}
    )
    with pytest.raises(GateDenied, match="invalid_call"):
        gate.dispatch(_token(key), _call())
    assert calls == []


def test_trusted_condition_allows_and_condition_error_denies() -> None:
    card_conditions = [{"id": "dpa-signed", "description": "Synthetic DPA"}]
    gate, key, calls = _make_gate(
        card_status="approved-with-conditions",
        card_conditions=card_conditions,
        condition_check=lambda _principal, _tool: True,
    )
    assert gate.dispatch(_token(key), _call()).value == {"ok": True}
    assert len(calls) == 1

    def unavailable(_principal: PrincipalBinding, _tool: ToolBinding) -> bool:
        raise TimeoutError("synthetic condition outage")

    gate, key, calls = _make_gate(
        card_status="approved-with-conditions",
        card_conditions=card_conditions,
        condition_check=unavailable,
    )
    with pytest.raises(GateDenied, match="condition_unavailable"):
        gate.dispatch(_token(key), _call())
    assert calls == []

    gate, key, calls = _make_gate(
        card_status="approved-with-conditions",
        card_conditions=card_conditions,
        condition_check=lambda _principal, _tool: 1,  # type: ignore[return-value]
    )
    with pytest.raises(GateDenied, match="condition_unavailable"):
        gate.dispatch(_token(key), _call())
    assert calls == []


@pytest.mark.parametrize(
    "mode", ["error", "wrong-id", "rejected", "bool", "missing-event", "bad-hash"]
)
def test_missing_or_wrong_audit_receipt_prevents_handler(mode: str) -> None:
    gate, key, calls = _make_gate(audit_mode=mode)
    with pytest.raises(GateDenied, match="audit_unavailable"):
        gate.dispatch(_token(key), _call())
    assert calls == []


@pytest.mark.parametrize(
    "method,value",
    [
        ("revoke_jti", "jti-one"),
        ("revoke_caller", "caller-one"),
        ("revoke_buyer", "buyer-1"),
        ("revoke_card", None),
    ],
)
def test_revocation_before_dispatch_denies(method: str, value: str | None) -> None:
    gate, key, calls = _make_gate()
    if value is None:
        getattr(gate, method)()
    else:
        getattr(gate, method)(value)
    with pytest.raises(GateDenied):
        gate.dispatch(_token(key), _call())
    assert calls == []


def test_revocation_waits_for_running_handler_then_blocks_next_call() -> None:
    entered = Event()
    release = Event()
    revoke_started = Event()
    revoke_done = Event()
    results: list[object] = []

    def blocked_handler(_arguments: dict[str, Any]) -> object:
        entered.set()
        assert release.wait(5)
        return "completed"

    gate, key, calls = _make_gate(handler=blocked_handler)
    authorization = _token(key)

    def invoke() -> None:
        results.append(gate.dispatch(authorization, _call()).value)

    def revoke() -> None:
        revoke_started.set()
        gate.revoke_jti("jti-one")
        revoke_done.set()

    call_thread = Thread(target=invoke)
    revoke_thread = Thread(target=revoke)
    call_thread.start()
    try:
        assert entered.wait(5)
        revoke_thread.start()
        assert revoke_started.wait(5)
        assert not revoke_done.wait(0.1)
    finally:
        release.set()
        call_thread.join(5)
        if revoke_thread.ident is not None:
            revoke_thread.join(5)
    assert not call_thread.is_alive() and not revoke_thread.is_alive()
    assert results == ["completed"]
    assert revoke_done.is_set()
    with pytest.raises(GateDenied, match="identity_denied"):
        gate.dispatch(authorization, _call())
    assert len(calls) == 1


def test_handler_cannot_reenter_dispatch() -> None:
    holder: dict[str, object] = {}

    def recursive_handler(_arguments: dict[str, Any]) -> object:
        gate = holder["gate"]
        assert isinstance(gate, AuthenticatedToolGate)
        with pytest.raises(GateDenied, match="recursive_call_denied"):
            gate.dispatch(holder["authorization"], _call())  # type: ignore[arg-type]
        return "outer-only"

    gate, key, calls = _make_gate(handler=recursive_handler)
    holder["gate"] = gate
    holder["authorization"] = _token(key)
    assert gate.dispatch(holder["authorization"], _call()).value == "outer-only"  # type: ignore[arg-type]
    assert len(calls) == 1


def test_caller_mutation_after_validation_cannot_change_handler_arguments() -> None:
    audit_entered = Event()
    caller_mutated = Event()
    params = _call()

    def wait_for_mutation() -> None:
        audit_entered.set()
        assert caller_mutated.wait(5)

    gate, key, calls = _make_gate(on_audit=wait_for_mutation)

    def mutate() -> None:
        assert audit_entered.wait(5)
        arguments = params["arguments"]
        assert isinstance(arguments, dict)
        arguments["query"] = "changed"
        arguments["buyerId"] = "spoofed"
        caller_mutated.set()

    mutation_thread = Thread(target=mutate)
    mutation_thread.start()
    try:
        assert gate.dispatch(_token(key), params).value == {"ok": True}
    finally:
        mutation_thread.join(5)
    assert not mutation_thread.is_alive()
    assert calls == [{"query": "synthetic"}]


def test_condition_change_after_receipt_denies_before_handler() -> None:
    state = {"allowed": True}

    def withdraw_condition() -> None:
        state["allowed"] = False

    gate, key, calls = _make_gate(
        card_status="approved-with-conditions",
        card_conditions=[{"id": "dpa-signed", "description": "Synthetic DPA"}],
        condition_check=lambda _principal, _tool: state["allowed"],
        on_audit=withdraw_condition,
    )
    with pytest.raises(GateDenied, match="policy_denied"):
        gate.dispatch(_token(key), _call())
    assert calls == []


def test_jti_revocation_during_receipt_denies_before_handler() -> None:
    holder: dict[str, AuthenticatedToolGate] = {}

    def revoke_during_audit() -> None:
        holder["gate"].revoke_jti("jti-one")

    gate, key, calls = _make_gate(on_audit=revoke_during_audit)
    holder["gate"] = gate
    with pytest.raises(GateDenied, match="identity_denied"):
        gate.dispatch(_token(key), _call())
    assert calls == []


def test_token_expiry_during_receipt_denies_before_handler() -> None:
    gate, key, calls = _make_gate(on_audit=lambda: time.sleep(2.1))
    with pytest.raises(GateDenied, match="authentication_required"):
        gate.dispatch(_token(key, exp=int(time.time()) + 2), _call())
    assert calls == []


def test_card_expiry_during_receipt_denies_before_handler() -> None:
    effective_until = (datetime.now(UTC) + timedelta(seconds=2)).isoformat().replace("+00:00", "Z")
    gate, key, calls = _make_gate(
        card_effective_until=effective_until,
        on_audit=lambda: time.sleep(2.1),
    )
    with pytest.raises(GateDenied, match="policy_denied"):
        gate.dispatch(_token(key), _call())
    assert calls == []
