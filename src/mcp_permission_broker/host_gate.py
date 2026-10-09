"""Opt-in reference gate for a host-owned MCP ``tools/call`` dispatcher.

The embedding host must expose only this dispatcher for its selected tools.
This module does not secure another process, the published TypeScript MCP
server, or a direct route to a registered handler.
"""

from __future__ import annotations

import inspect
import json
import re
import time
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from threading import RLock, local
from typing import Any, cast

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwt import InvalidTokenError
from policy_as_code_engine.card_attestation import CardAttestation

from mcp_permission_broker.broker import Broker
from mcp_permission_broker.models import PermissionDecision, PermissionRequest, TrustedCardContext

_AUTHORITY_KEYS = frozenset(
    {
        "accesskey",
        "accesstoken",
        "apikey",
        "auth",
        "authenticatedcaller",
        "authorization",
        "bearer",
        "bearertoken",
        "buyer",
        "buyerid",
        "caller",
        "callerid",
        "conditions",
        "conditionfacts",
        "conditionssatisfied",
        "context",
        "identity",
        "jwt",
        "meta",
        "principal",
        "tenant",
        "tenantid",
        "toolname",
        "trustedcardcontext",
        "upstreamtoken",
        "vendor",
        "vendorid",
    }
)
_MAX_ARGS_BYTES = 16_384
_MAX_ARGS_DEPTH = 16
_MAX_ARGS_NODES = 512
_MAX_TOKEN_BYTES = 4096


class GateDenied(PermissionError):
    """A generic denial code with no token, request body, or policy details."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class PrincipalBinding:
    """Identity and tenancy resolved by the host from a verified token subject."""

    caller_id: str
    client_id: str
    buyer_id: str
    tenant_id: str


@dataclass(frozen=True)
class ToolBinding:
    """A host-registered handler and independently configured resource scope."""

    vendor_id: str
    allowed_tenants: frozenset[str]
    validate_arguments: Callable[[dict[str, Any]], dict[str, Any]]
    handler: Callable[[dict[str, Any]], Any]


@dataclass(frozen=True)
class AcceptedAuditReceipt:
    """Result from a host-owned, independently verified pre-dispatch audit sink."""

    correlation_id: str
    accepted: bool
    event_id: int
    hash: str


@dataclass(frozen=True)
class InvocationResult:
    """The handler result and the accepted decision-audit correlation."""

    value: Any
    correlation_id: str


ConditionCheck = Callable[[PrincipalBinding, ToolBinding], bool]
AuditAccept = Callable[
    [PermissionDecision, PrincipalBinding, ToolBinding, str], AcceptedAuditReceipt
]


class AuthenticatedToolGate:
    """Serialize authentication, authorization, audit acceptance, and invocation.

    All mappings and callbacks are installed by the host, not taken from MCP
    call parameters. Revocation holds the same process-local lock as dispatch,
    so a revocation that completes first prevents a later handler entry. A
    running handler cannot be interrupted; revocation waits for it to return.
    """

    def __init__(
        self,
        *,
        broker: Broker,
        issuer: str,
        audience: str,
        public_key_pem: bytes,
        principals: Mapping[str, PrincipalBinding],
        tools: Mapping[str, ToolBinding],
        conditions: Mapping[str, ConditionCheck],
        accepted_audit: AuditAccept,
        max_token_lifetime_seconds: int = 300,
    ) -> None:
        if not issuer or not audience or not 1 <= max_token_lifetime_seconds <= 300:
            raise ValueError(
                "issuer, audience, and a token lifetime of 1..300 seconds are required"
            )
        if not callable(accepted_audit):
            raise ValueError("an accepted-audit callback is required")
        if broker.best_effort_audit_enabled:
            raise ValueError("reference gate requires Broker best-effort audit to be disabled")
        try:
            key = serialization.load_pem_public_key(public_key_pem)
        except (TypeError, ValueError) as exc:
            raise ValueError("a pinned Ed25519 public key is required") from exc
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("a pinned Ed25519 public key is required")
        if not principals or not tools:
            raise ValueError("host-owned principal and tool mappings are required")
        for subject, principal in principals.items():
            if not _valid_id(subject) or not isinstance(principal, PrincipalBinding):
                raise ValueError("invalid host-owned principal mapping")
            if not all(
                _valid_id(value)
                for value in (
                    principal.caller_id,
                    principal.client_id,
                    principal.buyer_id,
                    principal.tenant_id,
                )
            ):
                raise ValueError("invalid host-owned principal mapping")
        for name, tool in tools.items():
            if (
                not _valid_id(name)
                or not isinstance(tool, ToolBinding)
                or not _valid_id(tool.vendor_id)
                or not isinstance(tool.allowed_tenants, frozenset)
                or not tool.allowed_tenants
                or not all(_valid_id(tenant) for tenant in tool.allowed_tenants)
                or not callable(tool.validate_arguments)
                or inspect.iscoroutinefunction(tool.validate_arguments)
                or not callable(tool.handler)
                or inspect.iscoroutinefunction(tool.handler)
            ):
                raise ValueError("invalid host-owned tool mapping")
        if any(not _valid_id(name) or not callable(check) for name, check in conditions.items()):
            raise ValueError("invalid host-owned condition mapping")

        self._broker = broker
        self._broker.require_signed_card()
        self._issuer = issuer
        self._audience = audience
        self._public_key = key
        self._principals = dict(principals)
        self._tools = dict(tools)
        self._conditions = dict(conditions)
        self._accepted_audit = accepted_audit
        self._max_token_lifetime = max_token_lifetime_seconds
        self._revoked_jtis: set[str] = set()
        self._revoked_callers: set[str] = set()
        self._revoked_buyers: set[str] = set()
        self._lock = RLock()
        self._thread_state = local()

    def dispatch(
        self, authorization_header: str | None, call_params: Mapping[str, object]
    ) -> InvocationResult:
        """Handle one selected MCP ``tools/call`` payload before its handler runs.

        The embedding host supplies the HTTP Authorization header value as a
        separate argument; this class does not inspect an HTTP transport. The
        MCP payload can name a tool and pass bounded JSON arguments;
        it cannot assert caller, buyer, tenant, vendor, or condition facts.
        """
        if getattr(self._thread_state, "active", False):
            raise GateDenied("recursive_call_denied")
        self._thread_state.active = True
        try:
            return self._dispatch(authorization_header, call_params)
        finally:
            self._thread_state.active = False

    def _dispatch(
        self, authorization_header: str | None, call_params: Mapping[str, object]
    ) -> InvocationResult:
        name, arguments = _parse_call_params(call_params)
        with self._lock:
            claims = self._verify_token(authorization_header)
            subject = claims["sub"]
            jti = claims["jti"]
            principal = self._principals.get(subject)
            if (
                principal is None
                or principal.client_id != claims["client_id"]
                or jti in self._revoked_jtis
                or principal.caller_id in self._revoked_callers
                or principal.buyer_id in self._revoked_buyers
            ):
                raise GateDenied("identity_denied")
            tool = self._tools.get(name)
            if tool is None or principal.tenant_id not in tool.allowed_tenants:
                raise GateDenied("resource_denied")
            try:
                arguments = _detached_json_args(tool.validate_arguments(arguments))
            except Exception:
                raise GateDenied("invalid_call") from None

            decision = self._check_policy(principal, tool, name, arguments)
            if decision.outcome != "allow":
                raise GateDenied("policy_denied")
            try:
                receipt = self._accepted_audit(decision, principal, tool, name)
            except Exception:
                raise GateDenied("audit_unavailable") from None
            if (
                not isinstance(receipt, AcceptedAuditReceipt)
                or receipt.accepted is not True
                or receipt.correlation_id != decision.correlation_id
                or type(receipt.event_id) is not int
                or receipt.event_id < 1
                or not isinstance(receipt.hash, str)
                or re.fullmatch(r"[0-9a-f]{64}", receipt.hash) is None
            ):
                raise GateDenied("audit_unavailable")
            fresh_claims = self._verify_token(authorization_header)
            if (
                fresh_claims["sub"] != subject
                or fresh_claims["jti"] != jti
                or fresh_claims["client_id"] != principal.client_id
                or jti in self._revoked_jtis
                or principal.caller_id in self._revoked_callers
                or principal.buyer_id in self._revoked_buyers
            ):
                raise GateDenied("identity_denied")
            fresh_decision = self._check_policy(principal, tool, name, arguments)
            if fresh_decision.outcome != "allow":
                raise GateDenied("policy_denied")
            if time.time() >= fresh_claims["exp"]:
                raise GateDenied("authentication_required")
            result = tool.handler(arguments)
            if inspect.isawaitable(result):
                raise TypeError("host tool handlers must be synchronous")
            return InvocationResult(value=result, correlation_id=decision.correlation_id)

    def _check_policy(
        self,
        principal: PrincipalBinding,
        tool: ToolBinding,
        name: str,
        arguments: dict[str, Any],
    ) -> PermissionDecision:
        try:
            checked_conditions = {
                condition_id: check(principal, tool)
                for condition_id, check in self._conditions.items()
            }
            if any(type(value) is not bool for value in checked_conditions.values()):
                raise ValueError("condition checks must return bool")
        except Exception:
            raise GateDenied("condition_unavailable") from None
        try:
            return self._broker.check(
                PermissionRequest(
                    caller_id=principal.caller_id,
                    tool_name=name,
                    tool_args=arguments,
                    context={
                        "client_id": principal.client_id,
                        "buyer_id": principal.buyer_id,
                        "tenant_id": principal.tenant_id,
                        "vendor_id": tool.vendor_id,
                    },
                ),
                trusted_card_context=TrustedCardContext(
                    buyer_id=principal.buyer_id,
                    vendor_id=tool.vendor_id,
                    action="use",
                    conditions_satisfied=checked_conditions,
                ),
            )
        except Exception:
            raise GateDenied("policy_unavailable") from None

    def revoke_jti(self, jti: str) -> None:
        if not _valid_id(jti):
            raise ValueError("invalid token ID")
        with self._lock:
            self._revoked_jtis.add(jti)

    def revoke_caller(self, caller_id: str) -> None:
        if not _valid_id(caller_id):
            raise ValueError("invalid caller ID")
        with self._lock:
            self._revoked_callers.add(caller_id)

    def revoke_buyer(self, buyer_id: str) -> None:
        if not _valid_id(buyer_id):
            raise ValueError("invalid buyer ID")
        with self._lock:
            self._revoked_buyers.add(buyer_id)

    def revoke_card(self) -> None:
        with self._lock:
            self._broker.revoke_signed_decision_card()

    def load_signed_decision_card(
        self,
        card: dict[str, Any],
        *,
        attestation: CardAttestation,
        expected_buyer_id: str,
        trusted_key_url: str,
        trusted_public_key: bytes,
    ) -> None:
        """Load or replace the card under the same lock as handler execution."""
        with self._lock:
            self._broker.add_signed_decision_card(
                card,
                attestation=attestation,
                expected_buyer_id=expected_buyer_id,
                trusted_key_url=trusted_key_url,
                trusted_public_key=trusted_public_key,
            )

    def _verify_token(self, authorization_header: str | None) -> dict[str, Any]:
        if (
            not isinstance(authorization_header, str)
            or len(authorization_header) > _MAX_TOKEN_BYTES + 32
        ):
            raise GateDenied("authentication_required")
        parts = authorization_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer" or len(parts[1]) > _MAX_TOKEN_BYTES:
            raise GateDenied("authentication_required")
        try:
            claims = jwt.decode(
                parts[1],
                self._public_key,
                algorithms=["EdDSA"],
                issuer=self._issuer,
                audience=self._audience,
                options={
                    "require": [
                        "iss",
                        "sub",
                        "aud",
                        "exp",
                        "nbf",
                        "iat",
                        "jti",
                        "client_id",
                        "scope",
                    ],
                    "strict_aud": True,
                },
                leeway=0,
            )
        except InvalidTokenError:
            raise GateDenied("authentication_required") from None
        try:
            _reject_authority_fields(claims)
        except GateDenied:
            raise GateDenied("authentication_required") from None
        if (
            not _valid_id(claims.get("sub"))
            or not _valid_id(claims.get("jti"))
            or not _valid_id(claims.get("client_id"))
            or any(type(claims.get(field)) is not int for field in ("iat", "nbf", "exp"))
            or claims["nbf"] < claims["iat"]
            or claims["exp"] <= claims["nbf"]
            or claims["exp"] - claims["iat"] > self._max_token_lifetime
            or claims["iat"] > time.time()
            or not isinstance(claims.get("scope"), str)
            or claims["scope"].split() != ["mcp:tools.call"]
        ):
            raise GateDenied("authentication_required")
        return claims


def _valid_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value) <= 256
        and value == value.strip()
        and all(
            not char.isspace() and not unicodedata.category(char).startswith("C") for char in value
        )
    )


def _parse_call_params(params: Mapping[str, object]) -> tuple[str, dict[str, Any]]:
    if type(params) is not dict or set(params) not in ({"name"}, {"name", "arguments"}):
        raise GateDenied("invalid_call")
    name = params["name"]
    arguments = params.get("arguments", {})
    if not _valid_id(name):
        raise GateDenied("invalid_call")
    return name, _detached_json_args(arguments)


def _detached_json_args(arguments: object) -> dict[str, Any]:
    if type(arguments) is not dict:
        raise GateDenied("invalid_call")
    try:
        _reject_authority_fields(arguments)
        encoded = json.dumps(arguments, ensure_ascii=False, allow_nan=False)
        if len(encoded.encode("utf-8")) > _MAX_ARGS_BYTES:
            raise GateDenied("invalid_call")
        detached = json.loads(encoded)
        if type(detached) is not dict:
            raise GateDenied("invalid_call")
        _reject_authority_fields(detached)
    except (TypeError, ValueError, RuntimeError, RecursionError, OverflowError):
        raise GateDenied("invalid_call") from None
    return cast(dict[str, Any], detached)


def _reject_authority_fields(value: object) -> None:
    seen = 0

    def scan(node: object, depth: int) -> None:
        nonlocal seen
        seen += 1
        if depth > _MAX_ARGS_DEPTH or seen > _MAX_ARGS_NODES:
            raise GateDenied("invalid_call")
        if type(node) is dict:
            for key, child in node.items():
                if not isinstance(key, str):
                    raise GateDenied("invalid_call")
                if len(key) > _MAX_ARGS_BYTES or len(key.encode("utf-8")) > _MAX_ARGS_BYTES:
                    raise GateDenied("invalid_call")
                normalized = re.sub(r"[^a-z0-9]", "", unicodedata.normalize("NFKC", key).lower())
                if normalized in _AUTHORITY_KEYS:
                    raise GateDenied("invalid_call")
                scan(child, depth + 1)
        elif type(node) is list:
            for child in node:
                scan(child, depth + 1)
        elif type(node) is str:
            if len(node) > _MAX_ARGS_BYTES or len(node.encode("utf-8")) > _MAX_ARGS_BYTES:
                raise GateDenied("invalid_call")
            if not node.lstrip().startswith(("{", "[", '"')):
                return
            try:
                embedded = json.loads(node)
            except (ValueError, RecursionError):
                return
            if type(embedded) in (dict, list, str) and embedded != node:
                scan(embedded, depth + 1)
        elif type(node) not in (str, int, float, bool, type(None)):
            raise GateDenied("invalid_call")

    scan(value, 0)
