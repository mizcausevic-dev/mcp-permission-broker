"""The Broker — load PolicyBundles, evaluate a PermissionRequest, emit audit events."""

from __future__ import annotations

import ast
import logging
import os
from pathlib import Path
from threading import RLock
from typing import Any

import httpx
import regex
import yaml
from policy_as_code_engine import EvaluationContext, PolicyEvaluator
from policy_as_code_engine.card_attestation import CardAttestation
from policy_as_code_engine.from_decision_card import policy_bundle_from_decision_card
from policy_as_code_engine.models import PolicyBundle as CardPolicyBundle

from mcp_permission_broker.models import (
    Outcome,
    PermissionDecision,
    PermissionRequest,
    PolicyBundle,
    PolicyRule,
    TrustedCardContext,
)

logger = logging.getLogger(__name__)

_AUDIT_EVENT_KIND: dict[Outcome, str] = {
    "allow": "tool_invocation_allowed",
    "deny": "tool_invocation_denied",
    "require_approval": "tool_invocation_required_approval",
}
_LOCAL_REGEX_TIMEOUT_SECONDS = 0.02


class Broker:
    """In-memory registry of PolicyBundles + a deny-trumps-allow evaluator.

    Parameters
    ----------
    default_outcome:
        What to return when no rule matches. Defaults to ``"deny"`` (governed
        posture); pass ``"allow"`` for permissive deployments.
    audit_stream_url:
        If provided, every decision is best-effort POSTed to its /events endpoint. If
        None, falls back to the ``AUDIT_STREAM_URL`` environment variable.
        Set to empty string to disable explicitly.
    require_signed_card:
        Require a Decision Card converted locally from a buyer-attested card.
        Until one is loaded, every request is denied. When local rules are also
        loaded, both gates must allow the request.
    """

    def __init__(
        self,
        *,
        default_outcome: Outcome = "deny",
        audit_stream_url: str | None = None,
        require_signed_card: bool = False,
    ) -> None:
        self._bundles: dict[str, PolicyBundle] = {}
        self._default_outcome: Outcome = default_outcome
        self._card_lock = RLock()
        self._card_generation = 0
        self._signed_card_required = require_signed_card
        self._card_bundle: CardPolicyBundle | None = None
        self._expected_buyer_id: str | None = None
        self._card_evaluator = PolicyEvaluator()
        if audit_stream_url is None:
            audit_stream_url = os.environ.get("AUDIT_STREAM_URL", "")
        self._audit_stream_url = _audit_events_url(audit_stream_url)
        self._audit_stream_token = os.environ.get("AUDIT_STREAM_TOKEN", "")

    # ------------------------------------------------------------------ load

    def add_bundle(self, bundle: PolicyBundle) -> None:
        """Register a PolicyBundle in memory, replacing any prior bundle with the same id."""
        if not isinstance(bundle, PolicyBundle):
            raise TypeError("add_bundle accepts only local rules[] PolicyBundle instances")
        with self._card_lock:
            self._bundles[bundle.bundle_id] = bundle

    def remove_bundle(self, bundle_id: str) -> None:
        with self._card_lock:
            self._bundles.pop(bundle_id, None)

    def add_signed_decision_card(
        self,
        card: dict[str, Any],
        *,
        attestation: CardAttestation,
        expected_buyer_id: str,
        trusted_key_url: str,
        trusted_public_key: bytes,
    ) -> None:
        """Convert a raw buyer-attested card with independently pinned trust.

        A serialized ``policies[]`` bundle is deliberately not accepted: it has
        no proof of its Decision Card origin. A failed reload invalidates the
        previous card, so a rejected or tampered replacement cannot leave an
        older approval active.
        """
        with self._card_lock:
            self._card_generation += 1
            generation = self._card_generation
            self._signed_card_required = True
            self._card_bundle = None
            self._expected_buyer_id = None
        buyer = card.get("buyer") if isinstance(card, dict) else None
        if (
            not expected_buyer_id
            or not isinstance(buyer, dict)
            or buyer.get("id") != expected_buyer_id
        ):
            raise ValueError("Decision Card buyer does not match pinned buyer ID")
        if not trusted_key_url or len(trusted_public_key) != 32:
            raise ValueError("Decision Card buyer key is not pinned")
        bundle = policy_bundle_from_decision_card(
            card,
            allowed_actions=["use"],
            attestation=attestation,
            trusted_key_url=trusted_key_url,
            trusted_public_key=trusted_public_key,
        )
        with self._card_lock:
            if generation != self._card_generation:
                raise RuntimeError("Decision Card reload was superseded")
            self._expected_buyer_id = expected_buyer_id
            self._card_bundle = bundle

    @property
    def bundle_ids(self) -> list[str]:
        with self._card_lock:
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

    def check(
        self,
        request: PermissionRequest,
        *,
        trusted_card_context: TrustedCardContext | None = None,
    ) -> PermissionDecision:
        """Evaluate the request. Returns a PermissionDecision and emits an audit event."""
        # Card reload and local rule evaluation share a linearization point.
        # Audit is outside the lock so a slow sink cannot delay revocation.
        with self._card_lock:
            card_decision = self._check_signed_card_locked(trusted_card_context)
            if card_decision is not None and card_decision.outcome != "allow":
                decision = card_decision
            elif self._bundles:
                decision = self._check_local_rules(request)
                if card_decision is not None and decision.outcome == "allow":
                    decision.matched_rules = card_decision.matched_rules + decision.matched_rules
                    decision.rationale = "Signed Decision Card and local rules allowed"
            elif card_decision is not None:
                decision = card_decision
            else:
                decision = PermissionDecision(
                    outcome=self._default_outcome,
                    rationale=f"No rule matched — default {self._default_outcome}",
                )
        self._emit_audit(decision, request)
        return decision

    def _check_signed_card_locked(
        self, context: TrustedCardContext | None
    ) -> PermissionDecision | None:
        if not self._signed_card_required:
            if context is not None:
                return PermissionDecision(
                    outcome="deny", rationale="No signed Decision Card gate configured"
                )
            return None
        if self._card_bundle is None or self._expected_buyer_id is None:
            return PermissionDecision(outcome="deny", rationale="Signed Decision Card missing")
        if context is None or not isinstance(context, TrustedCardContext):
            return PermissionDecision(outcome="deny", rationale="Trusted card context missing")
        if context.buyer_id != self._expected_buyer_id:
            return PermissionDecision(outcome="deny", rationale="Buyer scope mismatch")
        try:
            result = self._card_evaluator.evaluate(
                self._card_bundle,
                EvaluationContext(
                    data={"conditions_satisfied": dict(context.conditions_satisfied)},
                    action=context.action,
                    resource={"vendor_id": context.vendor_id},
                ),
            )
        except Exception as exc:
            logger.warning("signed card evaluation failed: %s", type(exc).__name__)
            return PermissionDecision(outcome="deny", rationale="Signed card evaluation failed")
        matched = result.decision.matched_rule_id or result.decision.matched_policy_id
        return PermissionDecision(
            outcome="allow" if result.decision.kind == "allow" else "deny",
            matched_rules=[f"card:{matched}"] if matched else [],
            rationale=(
                "Signed Decision Card allowed"
                if result.decision.kind == "allow"
                else "Signed Decision Card denied"
            ),
        )

    def _check_local_rules(self, request: PermissionRequest) -> PermissionDecision:
        matches: list[tuple[PolicyRule, PolicyBundle]] = []
        for bundle in self._bundles.values():
            for rule in bundle.rules:
                try:
                    if self._rule_matches(rule, request):
                        matches.append((rule, bundle))
                except Exception as exc:
                    # A broken condition or pattern must never remove a deny
                    # from consideration and let another allow rule win.
                    logger.warning(
                        "policy rule %s failed to evaluate: %s", rule.id, type(exc).__name__
                    )
                    decision = PermissionDecision(
                        outcome="deny",
                        matched_rules=[rule.id],
                        decision_card_refs=_card_refs(bundle),
                        rationale=f"Policy rule {rule.id} failed to evaluate",
                    )
                    return decision

        # Sort by priority descending so the first deny we encounter is the highest-priority one.
        matches.sort(key=lambda pair: pair[0].priority, reverse=True)

        return self._resolve(matches, request)

    # -------------------------------------------------------------- internals

    def _rule_matches(self, rule: PolicyRule, request: PermissionRequest) -> bool:
        if not regex.fullmatch(
            rule.tool_name, request.tool_name, timeout=_LOCAL_REGEX_TIMEOUT_SECONDS
        ):
            return False
        if not regex.fullmatch(
            rule.caller_id, request.caller_id, timeout=_LOCAL_REGEX_TIMEOUT_SECONDS
        ):
            return False
        if rule.when is not None:
            if set(rule.when) != {"expr"} or not rule.when["expr"].strip():
                raise ValueError("when must contain one nonempty expr")
            return _evaluate_condition(rule.when["expr"], request.context)
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
        default_outcome: Outcome = "deny" if self._signed_card_required else self._default_outcome
        return PermissionDecision(
            outcome=default_outcome,
            rationale=f"No rule matched — default {default_outcome}",
        )

    def _emit_audit(self, decision: PermissionDecision, request: PermissionRequest) -> None:
        if not self._audit_stream_url:
            return
        event = {
            "kind": _AUDIT_EVENT_KIND[decision.outcome],
            "source": "mcp-permission-broker",
            "payload": {
                "correlation_id": decision.correlation_id,
                "caller_id": request.caller_id,
                "tool_name": request.tool_name,
                "matched_rules": decision.matched_rules,
                "decision_card_refs": decision.decision_card_refs,
                "rationale": decision.rationale,
            },
        }
        # Best-effort. Never raised. A missing token cannot be sent as anonymous
        # audit evidence to a sink that requires authenticated producers.
        if len(self._audit_stream_token) < 32 or any(
            not 33 <= ord(char) <= 126 for char in self._audit_stream_token
        ):
            logger.warning("audit-stream POST skipped: AUDIT_STREAM_TOKEN is missing or invalid")
            return
        try:
            response = httpx.post(
                self._audit_stream_url,
                json=event,
                headers={"Authorization": f"Bearer {self._audit_stream_token}"},
                timeout=2.0,
                follow_redirects=False,
            )
            response.raise_for_status()
        except Exception as exc:
            logger.warning("audit-stream POST failed (best-effort): %s", type(exc).__name__)


def _audit_events_url(raw_url: str) -> str:
    """Accept the documented sink base URL and the legacy exact endpoint URL."""
    if not raw_url:
        return ""
    try:
        url = httpx.URL(raw_url)
    except httpx.InvalidURL:
        raise ValueError("invalid audit stream URL") from None
    if (
        url.scheme not in {"http", "https"}
        or not url.host
        or url.userinfo
        or url.query
        or url.fragment
        or (url.scheme == "http" and url.host not in {"127.0.0.1", "::1"})
    ):
        raise ValueError("audit stream URL must be HTTPS or loopback HTTP without credentials")
    path = url.path.rstrip("/")
    if not path.endswith("/events"):
        path += "/events"
    return str(url.copy_with(path=path))


def _card_refs(bundle: PolicyBundle) -> list[str]:
    return [bundle.decision_card_url] if bundle.decision_card_url else []


def _evaluate_condition(expr: str, context: dict[str, Any]) -> bool:
    """Evaluate a deliberately small boolean grammar, never Python code."""
    if len(expr) > 512:
        raise ValueError("condition is too long")
    tree = ast.parse(expr, mode="eval")

    def visit(node: ast.AST, depth: int = 0) -> Any:
        if depth > 16:
            raise ValueError("condition is too deep")
        if isinstance(node, ast.Constant):
            if type(node.value) in (str, int, float, bool, type(None)):
                return node.value
        elif isinstance(node, (ast.List, ast.Tuple)):
            if len(node.elts) <= 32:
                return [visit(item, depth + 1) for item in node.elts]
        elif isinstance(node, ast.Call):
            target = node.func
            if (
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "context"
                and target.attr == "get"
                and not node.keywords
                and 1 <= len(node.args) <= 2
            ):
                key = visit(node.args[0], depth + 1)
                if not isinstance(key, str):
                    raise ValueError("context key must be a string")
                default = visit(node.args[1], depth + 1) if len(node.args) == 2 else None
                return context.get(key, default)
        elif isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name) and node.value.id == "context":
                key = visit(node.slice, depth + 1)
                if isinstance(key, str):
                    return context[key]
        elif isinstance(node, ast.BoolOp):
            values = [bool(visit(item, depth + 1)) for item in node.values]
            if isinstance(node.op, ast.And):
                return all(values)
            if isinstance(node.op, ast.Or):
                return any(values)
        elif isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not bool(visit(node.operand, depth + 1))
        elif isinstance(node, ast.Compare) and len(node.ops) == 1:
            left = visit(node.left, depth + 1)
            right = visit(node.comparators[0], depth + 1)
            op = node.ops[0]
            if isinstance(op, ast.Eq):
                return left == right
            if isinstance(op, ast.NotEq):
                return left != right
            if isinstance(op, ast.In):
                return left in right
            if isinstance(op, ast.NotIn):
                return left not in right
        raise ValueError("unsupported condition syntax")

    return bool(visit(tree.body))
