"""One-request private stdio bridge from a trusted MCP host to signed-card Broker.

The parent authenticates the MCP caller. This child independently resolves the
buyer, tenant, vendor, card, conditions, and revocation from an operator-owned
snapshot. It has no network listener and never receives the upstream bearer or
tool arguments. A nonzero exit is a denial at the embedding host.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from policy_as_code_engine.card_attestation import CardAttestation
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt

from mcp_permission_broker.broker import Broker
from mcp_permission_broker.models import PermissionRequest, TrustedCardContext

PILOT_TOOL = "suite_doc_detect_spec"
MAX_CONFIG_BYTES = 98_304
MAX_REQUEST_BYTES = 4_096
MAX_SNAPSHOT_LIFETIME_SECONDS = 300
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$")


class _PrincipalBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    client_id: str = Field(min_length=1, max_length=128)
    buyer_id: str = Field(min_length=1, max_length=128)
    tenant_id: str = Field(min_length=1, max_length=128)
    conditions_satisfied: dict[str, StrictBool]


class _ToolBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    vendor_id: str = Field(min_length=1, max_length=128)
    allowed_tenants: list[str] = Field(max_length=100)


class _Snapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal[1]
    valid_until: StrictInt
    expected_buyer_id: str = Field(min_length=1, max_length=128)
    trusted_key_url: str = Field(min_length=1, max_length=2048)
    trusted_public_key_b64: str = Field(min_length=1, max_length=128)
    card: dict[str, Any]
    attestation: dict[str, Any]
    principal_bindings: dict[str, _PrincipalBinding] = Field(max_length=100)
    tool_bindings: dict[str, _ToolBinding] = Field(max_length=1)
    revoked_jtis: list[str] = Field(max_length=1000)
    revoked_subjects: list[str] = Field(max_length=100)
    revoked_buyer_ids: list[str] = Field(max_length=100)
    revoked_decision_ids: list[str] = Field(max_length=100)


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    version: Literal[1]
    request_id: str = Field(min_length=36, max_length=36)
    client_id: str = Field(min_length=1, max_length=128)
    subject: str = Field(min_length=1, max_length=128)
    jti: str = Field(min_length=1, max_length=128)
    expires_at: StrictInt
    tool_name: str = Field(min_length=1, max_length=128)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_nonfinite(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _parse_json(raw: bytes) -> Any:
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_reject_duplicate_keys,
        parse_constant=_reject_nonfinite,
    )


def _read_snapshot(path: Path) -> tuple[_Snapshot, str]:
    if not path.is_absolute():
        raise ValueError("bridge config path must be absolute")
    # Validate and read through the same descriptor. An operator may atomically
    # replace the path, but this check never combines metadata and other bytes.
    with path.open("rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("bridge config must be a regular file")
        raw = stream.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("bridge config too large")
    snapshot = _Snapshot.model_validate(_parse_json(raw))
    now = int(time.time())
    if not now < snapshot.valid_until <= now + MAX_SNAPSHOT_LIFETIME_SECONDS:
        raise ValueError("bridge config outside validity window")
    if set(snapshot.tool_bindings) != {PILOT_TOOL}:
        raise ValueError("unsupported tool bindings")
    for value in [snapshot.expected_buyer_id, *snapshot.principal_bindings.keys()]:
        if not IDENTIFIER.fullmatch(value):
            raise ValueError("invalid binding identifier")
    parsed_url = urlsplit(snapshot.trusted_key_url)
    if (
        parsed_url.scheme != "https"
        or not parsed_url.hostname
        or parsed_url.username
        or parsed_url.password
        or parsed_url.query
        or parsed_url.fragment
    ):
        raise ValueError("invalid pinned key URL")
    return snapshot, hashlib.sha256(raw).hexdigest()


def _request_from_stdin() -> _Request:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        raise ValueError("bridge request too large")
    request = _Request.model_validate(_parse_json(raw))
    parsed_id = uuid.UUID(request.request_id)
    if (
        parsed_id.version != 4
        or str(parsed_id) != request.request_id
        or request.tool_name != PILOT_TOOL
        or any(
            not IDENTIFIER.fullmatch(value)
            for value in (request.client_id, request.subject, request.jti)
        )
        or request.expires_at <= int(time.time())
        or request.expires_at > int(time.time()) + MAX_SNAPSHOT_LIFETIME_SECONDS
    ):
        raise ValueError("invalid bridge request")
    return request


def _evaluate(
    request: _Request, snapshot: _Snapshot
) -> tuple[Literal["allow", "deny"], str, str | None]:
    principal = snapshot.principal_bindings.get(request.subject)
    tool = snapshot.tool_bindings[PILOT_TOOL]
    card_id = snapshot.card.get("decision_id")
    if (
        principal is None
        or principal.client_id != request.client_id
        or principal.buyer_id != snapshot.expected_buyer_id
        or principal.tenant_id not in tool.allowed_tenants
        or request.jti in snapshot.revoked_jtis
        or request.subject in snapshot.revoked_subjects
        or principal.buyer_id in snapshot.revoked_buyer_ids
        or not isinstance(card_id, str)
        or card_id in snapshot.revoked_decision_ids
    ):
        return "deny", str(uuid.uuid4()), None
    public_key = base64.b64decode(snapshot.trusted_public_key_b64, validate=True)
    if len(public_key) != 32:
        raise ValueError("pinned public key must be Ed25519 raw 32 bytes")
    broker = Broker(require_signed_card=True, audit_stream_url="")
    broker.add_signed_decision_card(
        snapshot.card,
        attestation=CardAttestation.model_validate(snapshot.attestation),
        expected_buyer_id=snapshot.expected_buyer_id,
        trusted_key_url=snapshot.trusted_key_url,
        trusted_public_key=public_key,
    )
    decision = broker.check(
        PermissionRequest(caller_id=request.subject, tool_name=request.tool_name),
        trusted_card_context=TrustedCardContext(
            buyer_id=principal.buyer_id,
            vendor_id=tool.vendor_id,
            action="use",
            conditions_satisfied=principal.conditions_satisfied,
        ),
    )
    if decision.outcome != "allow":
        return "deny", decision.correlation_id, None
    if not IDENTIFIER.fullmatch(card_id):
        raise ValueError("invalid signed card decision ID")
    return "allow", decision.correlation_id, card_id


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1:
        return 2
    try:
        request = _request_from_stdin()
        snapshot, state_sha256 = _read_snapshot(Path(arguments[0]))
        outcome, broker_correlation_id, signed_card_decision_id = _evaluate(request, snapshot)
        response = {
            "version": 1,
            "request_id": request.request_id,
            "outcome": outcome,
            "broker_correlation_id": broker_correlation_id,
            "signed_card_decision_id": signed_card_decision_id,
            "state_sha256": state_sha256,
        }
        sys.stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
        return 0
    except Exception:
        # The parent must fail closed. Do not expose card, identity, or key data.
        sys.stderr.write("broker runtime bridge unavailable\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
