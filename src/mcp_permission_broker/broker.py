"""The Broker — load PolicyBundles, evaluate a PermissionRequest, emit audit events."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

import httpx
import yaml

from mcp_permission_broker.models import (
    Outcome,
    PermissionDecision,
    PermissionRequest,
    PolicyBundle,
    PolicyRule,
)

logger = logging.getLogger(__name__)

_AUDIT_EVENT_KIND: dict[Outcome, str] = {
    "allow": "tool_invocation_allowed",
    "deny": "tool_invocation_denied",
    "require_approval": "tool_invocation_required_approval",
}


class Broker:
    """In-memory registry of PolicyBundles + a deny-trumps-allow evaluator.

    Parameters
    ----------
    default_outcome:
        What to return when no rule matches. Defaults to ``"deny"`` (governed
        posture); pass ``"allow"`` for permissive deployments.
    audit_stream_url:
        If provided, every decision is best-effort POSTed to this URL. If
        None, falls back to the ``AUDIT_STREAM_URL`` environment variable.
        Set to empty string to disable explicitly.
    """

    def __init__(
        self,
        *,
        default_outcome: Outcome = "deny",
        audit_stream_url: str | None = None,
    ) -> None:
        self._bundles: dict[str, PolicyBundle] = {}
        self._default_outcome: Outcome = default_outcome
        if audit_stream_url is None:
            audit_stream_url = os.environ.get("AUDIT_STREAM_URL", "")
        self._audit_stream_url = audit_stream_url

    # ------------------------------------------------------------------ load

    def add_bundle(self, bundle: PolicyBundle) -> None:
        """Register a PolicyBundle in memory, replacing any prior bundle with the same id."""
        self._bundles[bundle.bundle_id] = bundle

    def remove_bundle(self, bundle_id: str) -> None:
        self._bundles.pop(bundle_id, None)

    @property
    def bundle_ids(self) -> list[str]:
        return sorted(self._bundles.keys())

    @classmethod
    def from_yaml_dir(cls, directory: str | Path, **kwargs: Any) -> Broker:
        """Construct a Broker preloaded with every ``*.yaml`` / ``*.yml`` file in ``directory``."""
        broker = cls(**kwargs)
        path = Path(directory)
        if not path.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")
        for yaml_file in sorted([*path.glob("*.yaml"), *path.glob("*.yml")]):
            data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            broker.add_bundle(PolicyBundle.model_validate(data))
        return broker

    # ------------------------------------------------------------------ check

    def check(self, request: PermissionRequest) -> PermissionDecision:
        """Evaluate the request. Returns a PermissionDecision and emits an audit event."""
        matches: list[tuple[PolicyRule, PolicyBundle]] = []
        for bundle in self._bundles.values():
            for rule in bundle.rules:
                if self._rule_matches(rule, request):
                    matches.append((rule, bundle))

        # Sort by priority descending so the first deny we encounter is the highest-priority one.
        matches.sort(key=lambda pair: pair[0].priority, reverse=True)

        decision = self._resolve(matches, request)
        self._emit_audit(decision, request)
        return decision

    # -------------------------------------------------------------- internals

    def _rule_matches(self, rule: PolicyRule, request: PermissionRequest) -> bool:
        if not re.fullmatch(rule.tool_name, request.tool_name):
            return False
        if not re.fullmatch(rule.caller_id, request.caller_id):
            return False
        if rule.when:
            expr = rule.when.get("expr", "")
            if not expr:
                return True
            try:
                # Restricted eval: no builtins, single binding.
                return bool(eval(expr, {"__builtins__": {}}, {"context": request.context}))
            except Exception as exc:
                logger.warning("when.expr evaluation failed for rule %s: %s", rule.id, exc)
                return False
        return True

    def _resolve(
        self,
        matches: list[tuple[PolicyRule, PolicyBundle]],
        request: PermissionRequest,
    ) -> PermissionDecision:
        # 1) Deny trumps allow — first deny wins.
        for rule, bundle in matches:
            if rule.effect == "deny":
                return PermissionDecision(
                    outcome="deny",
                    matched_rules=[rule.id],
                    decision_card_refs=_card_refs(bundle),
                    rationale=f"Denied by rule {rule.id}",
                )

        # 2) require_approval if any present, highest priority.
        for rule, bundle in matches:
            if rule.effect == "require_approval":
                return PermissionDecision(
                    outcome="require_approval",
                    matched_rules=[rule.id],
                    decision_card_refs=_card_refs(bundle),
                    rationale=f"Approval required by rule {rule.id}",
                )

        # 3) First allow wins.
        for rule, bundle in matches:
            if rule.effect == "allow":
                return PermissionDecision(
                    outcome="allow",
                    matched_rules=[rule.id],
                    decision_card_refs=_card_refs(bundle),
                    rationale=f"Allowed by rule {rule.id}",
                )

        # 4) Default.
        return PermissionDecision(
            outcome=self._default_outcome,
            rationale=f"No rule matched — default {self._default_outcome}",
        )

    def _emit_audit(self, decision: PermissionDecision, request: PermissionRequest) -> None:
        if not self._audit_stream_url:
            return
        event = {
            "kind": _AUDIT_EVENT_KIND[decision.outcome],
            "correlation_id": decision.correlation_id,
            "caller_id": request.caller_id,
            "tool_name": request.tool_name,
            "matched_rules": decision.matched_rules,
            "decision_card_refs": decision.decision_card_refs,
            "rationale": decision.rationale,
        }
        # Best-effort. Never raised.
        try:
            httpx.post(self._audit_stream_url, json=event, timeout=2.0)
        except Exception as exc:
            logger.warning("audit-stream POST failed (best-effort): %s", exc)


def _card_refs(bundle: PolicyBundle) -> list[str]:
    return [bundle.decision_card_url] if bundle.decision_card_url else []
