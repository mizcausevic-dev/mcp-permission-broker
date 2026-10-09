"""Create a short-lived synthetic signed-card snapshot for cross-repo tests.

The Ed25519 private key stays in this process. Only a public key and synthetic
fixture values are written to the requested file. Never use this as a buyer
identity source or production card issuer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def create_fixture(path: Path, *, status: str = "approved-with-conditions") -> dict[str, Any]:
    if status not in {"approved-with-conditions", "rejected", "withdrawn"}:
        raise ValueError("unsupported synthetic card status")
    now = datetime.now(UTC)
    timestamp = now.isoformat(timespec="seconds").replace("+00:00", "Z")
    expires = (now + timedelta(days=1)).isoformat(timespec="seconds").replace("+00:00", "Z")
    card: dict[str, Any] = {
        "decision_card_version": "0.1",
        "decision_id": "SYNTHETIC-BRIDGE-001",
        "issued_at": timestamp,
        "buyer": {"id": "synthetic-buyer-a", "name": "Synthetic Buyer", "type": "school-district"},
        "decision": {"status": status, "effective_until": expires},
        "subject": {"vendor_name": "Synthetic Vendor", "vendor_id": "synthetic-vendor-a"},
        "conditions": [{"id": "dpa-signed", "description": "Synthetic fixture condition"}],
        "rationale": "Synthetic bridge test fixture.",
    }
    key = Ed25519PrivateKey.generate()
    fields = {
        "algorithm": "ed25519",
        "hash_profile": "jcs-rfc8785-v1",
        "signed_hash": "sha256:" + hashlib.sha256(rfc8785.dumps(card)).hexdigest(),
        "key_url": "https://synthetic-buyer.invalid/keys/bridge-test",
        "signed_at": timestamp,
    }
    signature = key.sign(b"hash-attestation/v2\x00" + rfc8785.dumps(fields))
    snapshot: dict[str, Any] = {
        "version": 1,
        "valid_until": int(time.time()) + 120,
        "expected_buyer_id": "synthetic-buyer-a",
        "trusted_key_url": fields["key_url"],
        "trusted_public_key_b64": base64.b64encode(key.public_key().public_bytes_raw()).decode(
            "ascii"
        ),
        "card": card,
        "attestation": {**fields, "signature": base64.b64encode(signature).decode("ascii")},
        "principal_bindings": {
            "synthetic-subject-a": {
                "client_id": "synthetic-client-a",
                "buyer_id": "synthetic-buyer-a",
                "tenant_id": "synthetic-tenant-a",
                "conditions_satisfied": {"dpa-signed": True},
            }
        },
        "tool_bindings": {
            "suite_doc_detect_spec": {
                "vendor_id": "synthetic-vendor-a",
                "allowed_tenants": ["synthetic-tenant-a"],
            }
        },
        "revoked_jtis": [],
        "revoked_subjects": [],
        "revoked_buyer_ids": [],
        "revoked_decision_ids": [],
    }
    path.write_text(json.dumps(snapshot, separators=(",", ":")), encoding="utf-8")
    return snapshot


if __name__ == "__main__":
    if len(sys.argv) not in {2, 3}:
        raise SystemExit(2)
    create_fixture(
        Path(sys.argv[1]).resolve(),
        status=sys.argv[2] if len(sys.argv) == 3 else "approved-with-conditions",
    )
