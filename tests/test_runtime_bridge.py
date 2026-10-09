"""Real child-process signed-card decisions for the selected MCP pilot tool."""

from __future__ import annotations

import json
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import pytest

from tests.create_runtime_bridge_fixture import create_fixture


@pytest.fixture
def snapshot_path(tmp_path: Path) -> Path:
    path = tmp_path / "broker-snapshot.json"
    create_fixture(path)
    return path


def _request(**changes: Any) -> dict[str, Any]:
    request: dict[str, Any] = {
        "version": 1,
        "request_id": str(uuid.uuid4()),
        "client_id": "synthetic-client-a",
        "subject": "synthetic-subject-a",
        "jti": "synthetic-jti-a",
        "expires_at": int(time.time()) + 60,
        "tool_name": "suite_doc_detect_spec",
    }
    request.update(changes)
    return request


def _run(path: Path, request: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-I", "-m", "mcp_permission_broker.runtime_bridge", str(path)],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        timeout=8,
        check=False,
    )


def _change(path: Path, callback: Any) -> None:
    value = json.loads(path.read_text(encoding="utf-8"))
    callback(value)
    replacement = path.with_suffix(".replacement")
    replacement.write_text(json.dumps(value, separators=(",", ":")), encoding="utf-8")
    replacement.replace(path)


def test_actual_signed_card_allows_only_bound_call(snapshot_path: Path) -> None:
    request = _request()
    result = _run(snapshot_path, request)
    assert result.returncode == 0, result.stderr
    response = json.loads(result.stdout)
    assert response["version"] == 1
    assert response["request_id"] == request["request_id"]
    assert response["outcome"] == "allow"
    assert len(response["state_sha256"]) == 64
    uuid.UUID(response["broker_correlation_id"])
    assert response["signed_card_decision_id"] == "SYNTHETIC-BRIDGE-001"
    assert result.stderr == ""


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value["principal_bindings"]["synthetic-subject-a"][
            "conditions_satisfied"
        ].clear(),
        lambda value: value["principal_bindings"]["synthetic-subject-a"].update(
            {"conditions_satisfied": {"dpa-signed": False}}
        ),
        lambda value: value["revoked_jtis"].append("synthetic-jti-a"),
        lambda value: value["revoked_subjects"].append("synthetic-subject-a"),
        lambda value: value["revoked_buyer_ids"].append("synthetic-buyer-a"),
        lambda value: value["revoked_decision_ids"].append("SYNTHETIC-BRIDGE-001"),
        lambda value: value["tool_bindings"]["suite_doc_detect_spec"].update(
            {"vendor_id": "wrong-vendor"}
        ),
        lambda value: value["tool_bindings"]["suite_doc_detect_spec"].update(
            {"allowed_tenants": ["other-tenant"]}
        ),
    ],
)
def test_missing_fact_or_persisted_revocation_denies(snapshot_path: Path, change: Any) -> None:
    _change(snapshot_path, change)
    result = _run(snapshot_path, _request())
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["outcome"] == "deny"
    assert json.loads(result.stdout)["signed_card_decision_id"] is None


@pytest.mark.parametrize(
    "changes",
    [
        {"client_id": "other-client"},
        {"subject": "other-subject"},
        {"jti": "bad space"},
        {"expires_at": 1},
        {"tool_name": "audit_event_emit"},
        {"buyer_id": "synthetic-buyer-a"},
        {"conditions_satisfied": {"dpa-signed": True}},
    ],
)
def test_unbound_or_caller_supplied_authority_cannot_allow(
    snapshot_path: Path, changes: dict[str, Any]
) -> None:
    result = _run(snapshot_path, _request(**changes))
    if "buyer_id" in changes or "conditions_satisfied" in changes:
        assert result.returncode != 0
        assert result.stdout == ""
    else:
        assert result.returncode != 0 or json.loads(result.stdout)["outcome"] == "deny"


def test_tampered_card_and_expired_snapshot_fail_closed(snapshot_path: Path) -> None:
    _change(snapshot_path, lambda value: value["card"].update({"rationale": "tampered"}))
    tampered = _run(snapshot_path, _request())
    assert tampered.returncode != 0
    assert tampered.stdout == ""
    assert "tampered" not in tampered.stderr
    create_fixture(snapshot_path)
    _change(snapshot_path, lambda value: value.update({"valid_until": 1}))
    expired = _run(snapshot_path, _request())
    assert expired.returncode != 0
    assert expired.stdout == ""


@pytest.mark.parametrize("status", ["rejected", "withdrawn"])
def test_authentically_signed_nonallow_card_fails_closed(snapshot_path: Path, status: str) -> None:
    create_fixture(snapshot_path, status=status)
    result = _run(snapshot_path, _request())
    assert result.returncode != 0 or json.loads(result.stdout)["outcome"] == "deny"


def test_oversized_snapshot_and_duplicate_request_key_fail_closed(snapshot_path: Path) -> None:
    snapshot_path.write_bytes(b" " * 98_305)
    too_large = _run(snapshot_path, _request())
    assert too_large.returncode != 0
    assert too_large.stdout == ""
    create_fixture(snapshot_path)
    request = _request()
    duplicated = json.dumps(request)[:-1] + ',"client_id":"other-client"}'
    result = subprocess.run(
        [sys.executable, "-I", "-m", "mcp_permission_broker.runtime_bridge", str(snapshot_path)],
        input=duplicated,
        text=True,
        capture_output=True,
        timeout=8,
        check=False,
    )
    assert result.returncode != 0
    assert result.stdout == ""


def test_snapshot_digest_changes_after_operator_update(snapshot_path: Path) -> None:
    before = json.loads(_run(snapshot_path, _request()).stdout)
    _change(snapshot_path, lambda value: value["revoked_jtis"].append("synthetic-jti-a"))
    after = json.loads(_run(snapshot_path, _request()).stdout)
    assert before["outcome"] == "allow"
    assert after["outcome"] == "deny"
    assert before["state_sha256"] != after["state_sha256"]
