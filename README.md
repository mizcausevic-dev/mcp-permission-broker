# mcp-permission-broker

> An embeddable rule evaluator for MCP tool calls, with an opt-in reference host gate for selected calls.

`mcp-permission-broker` evaluates locally loaded `PolicyBundle.rules[]` against a `PermissionRequest`. A separate signed-card gate converts a raw Decision Card with `policy-as-code-engine==0.2.1` and evaluates its scoped `policies[]` with that engine. `Broker.check()` alone does not intercept MCP traffic or authenticate callers. The optional `AuthenticatedToolGate` wraps a host-owned `tools/call` dispatcher for a selected set of registered handlers. It is a reference integration, not an HTTP MCP server or a guard on the separately published TypeScript server.

The two bundle formats remain distinct. A serialized `policies[]` bundle has no signature or proof that it came from a verified card; the broker does not accept one as signed. The signed-card gate calls the engine's converter on the raw card with an independently pinned buyer ID and Ed25519 public key, then keeps the resulting typed bundle in memory. This is an in-process prototype, not a hosted MCP authorization boundary.

## Why this exists

The library supplies a local allow/deny/approval decision and checks a positive card's signature, buyer pin, vendor/action scope, conditions, and effective window in its optional signed-card path. The reference gate adds pinned-token verification, server-owned caller/buyer/tenant/vendor/condition mappings, process-local revocation, and a required pre-dispatch audit receipt callback. A production boundary still needs a real authenticated MCP transport, exclusive routing through the gate, durable revocation and audit, trusted condition sources, and hosted failure/rollback proof.

```
[operator loads a local rules[] YAML bundle]
            │
            ▼
[MCP server authenticates caller and supplies trusted context]
            │
            ▼
[MCP server calls Broker.check() before each tool execution]
            │
            ▼
[allow / deny / require_approval; optional best-effort audit POST]
```

## Design

### Inputs

A `PermissionRequest` carries everything the broker needs:

| Field | Meaning |
|---|---|
| `caller_id` | Caller identifier asserted by the embedding application. The broker does not authenticate it. |
| `tool_name` | Tool identifier supplied by the embedding application (e.g. `github.search_repositories`). The broker matches its rules against this string; it does not inspect a Tool Card. |
| `tool_args` | The opaque arguments. The broker does NOT inspect these by default. |
| `context` | Free-form dict supplied by the embedding application. Do not copy untrusted request claims into it as authoritative facts. |

### Outputs

A `PermissionDecision` carries the verdict:

| Field | Meaning |
|---|---|
| `outcome` | `allow` / `deny` / `require_approval` (terminal, with deny-trumps-allow precedence). |
| `matched_rules` | List of rule IDs that contributed to this decision. |
| `decision_card_refs` | URL copied from the locally loaded bundle, if present. The broker does not verify the card or URL. |
| `correlation_id` | UUIDv4 also included in attempted audit POSTs. It does not prove that a sink accepted the event. |

### Rule semantics

A `PolicyRule` is:

```yaml
id: deny-deletions-without-approval
priority: 100
effect: deny                       # allow | deny | require_approval
tool_name: "^github\\..*delete.*"   # regex on tool_name
caller_id: ".*"                    # regex on caller_id
when:                              # optional restricted condition over context
  expr: "context.get('environment') == 'production'"
because:
  decision_card: "https://district.example/.well-known/decisions/DEC-2026-001.json" # unverified metadata
  condition_id: "no-destructive-prod-actions"
```

Evaluation order:

1. Every rule in every loaded `PolicyBundle` is checked against the request.
2. Rules are sorted by `priority` (descending).
3. **Deny trumps allow.** First `deny` match short-circuits to `deny`.
4. Otherwise the highest-priority `require_approval` match wins.
5. Otherwise the first `allow` match wins.
6. If nothing matches: configurable default. The default is `deny`; explicit `allow` is only suitable for non-enforcing experiments.
7. If a matching rule's regex or condition cannot be evaluated, the request is denied, even when another allow rule matches.

`when.expr` supports comparisons (`==`, `!=`, `in`, `not in`), `and`, `or`, `not`, constants, literal lists, `context['key']`, and `context.get('key', default)`. It is parsed as a restricted expression tree; Python attribute traversal and arbitrary calls are rejected. This is a local rule format, not the `policy-as-code-engine` matcher DSL.

`caller_id`, `tool_name`, and each regex pattern are capped at 256 characters. Local rule matching uses the `regex` package with a 20 ms timeout per match; a timeout denies. A large number of reviewed rules can still multiply evaluation time, so constrain policy counts at the embedding host. Do not load unreviewed local rules.

### Signed Decision Card gate

Create `Broker(require_signed_card=True)` when a buyer decision is required. Until a valid signed card is loaded, `check()` denies every request. `add_signed_decision_card()` takes a raw card, its v2 `CardAttestation`, and an operator-pinned buyer ID, key URL, and 32-byte Ed25519 public key. It verifies a positive card through the policy engine's converter and clears the previous card before a failed reload. A loaded card marked withdrawn or expired, a tampered reload, or a card outside its effective window cannot allow. The only permitted card action is `use`.

```python
from mcp_permission_broker import Broker, PermissionRequest, TrustedCardContext

# Load card and attestation from an operator-approved source. Independently pin
# buyer_id, key URL, and public key outside the card or request payload.
broker = Broker(require_signed_card=True)
broker.add_signed_decision_card(
    card,
    attestation=attestation,
    expected_buyer_id=buyer_id,
    trusted_key_url=buyer_key_url,
    trusted_public_key=buyer_public_key,
)
decision = broker.check(
    PermissionRequest(caller_id=authenticated_caller, tool_name=tool_name),
    trusted_card_context=TrustedCardContext(
        buyer_id=authenticated_buyer,
        vendor_id=resolved_vendor,
        action="use",
        conditions_satisfied=server_checked_conditions,
    ),
)
if decision.outcome != "allow":
    raise PermissionError("Tool invocation denied")
```

`TrustedCardContext` is a separate keyword argument so `PermissionRequest.context`, `tool_args`, and other caller-controlled input cannot supply card authority. The embedding host must authenticate `authenticated_caller` and `authenticated_buyer`, resolve `resolved_vendor`, and compute every condition assertion from trusted checks. The model validates values but cannot prove the host did that work. Missing context, a mismatched buyer or vendor, a false/missing condition, or an evaluator error denies. If local `rules[]` bundles are also loaded, the card and local rules must both allow. In that mode a local rule miss denies even if `default_outcome="allow"` was selected. Card reload and rule evaluation share a lock, but the host must coordinate the time between this decision and actual tool invocation; the broker cannot guarantee revocation at that later boundary.

Card signature verification happens when the card is loaded. The broker does not fetch updates or detect a later withdrawal until the host reloads the card. Do not use a stale in-memory approval as proof of current buyer consent. The `policy-as-code-engine` `policies[]` bundle is never accepted directly as a signed artifact.

### Opt-in reference host gate

Install the reviewed source with `pip install -e ".[host]"` to use `mcp_permission_broker.host_gate.AuthenticatedToolGate`. The host must pass the HTTP `Authorization` header separately from MCP `tools/call` parameters and make `dispatch()` its only path to the selected registered handlers. `dispatch()` accepts exactly `{name, arguments}`. It rejects added authority fields, including nested and normalized aliases, and bounds JSON arguments to 16 KiB, 16 levels, and 512 nodes. Every `ToolBinding` must provide a server-owned `validate_arguments` callback that returns a validated dict or raises; the gate rechecks and detaches its output before policy and handler receive the same copy. An unexpected field or type must fail that callback. The embedding transport must cap wire bytes **before** parsing a request into a Python dict.

The gate accepts only Ed25519 JWTs verified against a host-pinned public key, issuer, and single audience. It requires `sub`, `client_id`, `scope` equal to `mcp:tools.call`, `jti`, `iat`, `nbf`, and `exp`; lifetime is capped at five minutes. The signed `sub` resolves to a server-owned `PrincipalBinding`, and the signed `client_id` must match that binding. Buyer and tenant are resolved from the binding, vendor and allowed tenants from the host's `ToolBinding`, and condition facts from host-owned callbacks that never receive tool arguments. No upstream bearer is forwarded to a handler. Missing or false facts, unknown tools, mismatched scopes, revoked IDs, or any non-allow broker decision deny before invocation.

For every allowed decision, a host-owned `accepted_audit` callback must return an `AcceptedAuditReceipt` with `accepted is True`, the exact decision correlation ID, a positive `event_id`, and a lowercase 64-hex `hash`, matching the audit sink's accepted event shape. Missing, rejected, mismatched, or malformed receipts block the handler. Before entering the handler, the gate rechecks the JWT, trusted conditions, and Broker decision under the same lock; a token or card that expires during audit, or a condition that changes, blocks execution. A successful result retains the first receipt's correlation ID. This interface does not implement an audit sink or prove that the callback returned a committed event; the embedding host must verify the response and durability independently. Receipt acceptance is required **only for an allowed pre-dispatch decision**. Authentication failures, condition failures, denied decisions, a post-receipt denial, and execution outcomes are not guaranteed durable audit events here. Complete call history remains a production blocker. The broker's separate audit POST remains best effort and does not satisfy this gate; the adapter rejects a Broker with it enabled. Construct the reference broker with `audit_stream_url=""` so it cannot emit a misleading duplicate allow event before receipt acceptance.

`revoke_jti()`, `revoke_caller()`, `revoke_buyer()`, `revoke_card()`, and `load_signed_decision_card()` use the same process-local lock as decision, accepted audit, and synchronous handler execution. This serializes all selected calls. Once revocation completes, a later dispatch cannot start its handler. An already running handler is not aborted; revocation waits for it to finish. A process restart loses these revocation sets and card generation, so a production host needs an independently controlled durable withdrawal source before it can trust a fresh process. Limit this reference path to bounded read-only handlers. A stuck condition, audit, or handler callback can delay revocation; hosted use requires timeouts and isolated execution. Recursive dispatch is denied.

This adapter does not provide an MCP HTTP transport, token issuer, OAuth discovery, rate limiter, durable audit implementation, persistent revocation feed, or exclusive network routing. Tool argument validators must be pure and handlers must enforce resource-level tenant scope; a static tenant allowlist alone cannot prove data isolation. Code with a direct reference to a registered handler can bypass the gate. Direct mutation of the underlying `Broker` outside the adapter can also race invocation; use only the adapter's card-load/revocation methods for this reference path. The published `mcp-kinetic-gain` TypeScript stdio server still invokes its own handlers directly. Do not describe this reference adapter's tests as proof that that server or any hosted provider is protected.

### Private stdio signed-card bridge source pilot

`python -I -m mcp_permission_broker.runtime_bridge <absolute-snapshot.json>`
evaluates one request from a trusted parent over inherited stdin/stdout pipes. It
has no network listener. The parent must first verify the MCP bearer token and
pass only `{version, request_id, client_id, subject, jti, expires_at,
tool_name}`. Do not pass the bearer, tool arguments, buyer, tenant, vendor, or
condition claims. The child permits only `suite_doc_detect_spec`; it resolves
buyer, tenant, vendor, conditions, signed raw Decision Card, pinned buyer key,
and revocations from the operator-owned snapshot, then calls
`Broker(require_signed_card=True, audit_stream_url="").check()`. Its response is
only `{version, request_id, outcome, broker_correlation_id,
signed_card_decision_id, state_sha256}`. The signed card ID is present only for
an allowed, verified card; it is `null` on denial. The Broker correlation ID
is a per-check UUID, not the buyer's card ID. Invalid
configuration or evaluation exits nonzero with no decision JSON; the parent
must deny execution.

The snapshot must be an absolute-path regular JSON file of at most 96 KiB. It
contains `version: 1`, `valid_until` no more than 300 seconds ahead,
`expected_buyer_id`, `trusted_key_url`, standard-base64
`trusted_public_key_b64`, raw `card`, v2 `attestation`,
`principal_bindings` keyed by signed subject, `tool_bindings`, and
`revoked_jtis`, `revoked_subjects`, `revoked_buyer_ids`, and
`revoked_decision_ids` lists. Each principal binding contains `client_id`,
`buyer_id`, `tenant_id`, and boolean `conditions_satisfied`; the selected tool
binding contains `vendor_id` and `allowed_tenants`. Unknown keys and duplicate
JSON keys fail closed. The child reads one bounded snapshot through one file
descriptor and hashes those exact bytes. The parent must require two `allow`
decisions with the same state digest, one before an accepted audit receipt and
one immediately afterward. The [fixture generator](tests/create_runtime_bridge_fixture.py)
creates a synthetic signed snapshot for tests; it does not issue real buyer
approval.

Snapshot files survive process restarts, unlike the in-memory reference gate,
but an operator-owned file is not an authoritative revocation feed or a trusted
condition source by itself. Protect the file and executable with operating
system ACLs and atomic updates. An older still-valid snapshot can be replayed
after a revocation, so an independently controlled monotonic revocation source
is required for production. A card or revocation update after the second check
can still race handler entry. The bridge has no token issuer, real buyer
approval source, private hosted route, audit custodian, or hosted rollback
proof. Do not publish it as a production authorization service.

### Audit-stream integration

If `AUDIT_STREAM_URL` and `AUDIT_STREAM_TOKEN` are set in the environment, the broker attempts to POST each decision to the sink's `/events` endpoint as one of:

- `tool_invocation_allowed`
- `tool_invocation_denied`
- `tool_invocation_required_approval`

POSTs are best effort. Set `AUDIT_STREAM_URL` to the trusted sink base URL; a legacy URL already ending in `/events` is accepted. The URL must use HTTPS or numeric loopback HTTP (`127.0.0.1` or `::1`), with no embedded credentials, query, or fragment. `AUDIT_STREAM_TOKEN` must contain at least 32 visible ASCII characters with no whitespace, matching the sink's requirement; it is sent only in the Bearer header and is never logged. Redirects are disabled so the token is never forwarded to a redirect target. If the token is missing or invalid, no POST is attempted. The body follows the sink's `{kind, source, payload}` envelope; `payload` contains the asserted caller ID, tool name, rule IDs, and reference URLs, but excludes `tool_args`, request `context`, and trusted card condition signals. Connection failures and non-2xx responses are logged without the endpoint URL or token and do not change the decision. The broker does not prove delivery or make its events tamper-evident; verify acceptance and retention at the sink independently.

Without `AUDIT_STREAM_URL` the broker emits decisions only to its return value — no HTTP traffic, no side effects, no crashes.

## Quickstart

```python
from mcp_permission_broker import Broker, PermissionRequest, PolicyBundle, PolicyRule

broker = Broker()
broker.add_bundle(PolicyBundle(
    bundle_id="local-example",
    rules=[PolicyRule(
        id="allow-read-for-tutor",
        effect="allow",
        tool_name=r"^filesystem\.read_file$",
        caller_id=r"^acme-tutor-v2\.1$",
    )],
))
decision = broker.check(PermissionRequest(
    caller_id="acme-tutor-v2.1",
    tool_name="filesystem.read_file",
    context={"environment": "production", "tenant_id": "springfield-isd"},
))

if decision.outcome != "allow":
    raise PermissionError(f"{decision.outcome}: matched {decision.matched_rules}")
```

Wire it into your MCP server's request handler. Only `allow` may proceed. Deny or require-approval must block tool execution until a separate, authenticated approval flow exists. This example alone is not a production authorization boundary.

## Status

**Unreleased review branch, source version 0.1.0** — in-memory rule registry, signed-card gate backed by `policy-as-code-engine==0.2.1`, optional best-effort authenticated audit POST, and an opt-in reference host dispatcher with pinned-token checks. There is no MCP server, HTTP API, hosted deployment, durable revocation source, or verified exclusive host boundary.

## Place in the Kinetic Gain portfolio

| Concern | Repo |
|---|---|
| Spec the buyer publishes | [`ai-procurement-decision-spec`](https://github.com/mizcausevic-dev/ai-procurement-decision-spec) |
| Drafting Decision Cards | [`procurement-decision-api`](https://github.com/mizcausevic-dev/procurement-decision-api) |
| Building runtime bundles | [`policy-as-code-engine`](https://github.com/mizcausevic-dev/policy-as-code-engine) |
| **Reference MCP call-time decision gate** | **`mcp-permission-broker` (this repo)** |
| Walking the graph after an incident | [`incident-correlation-rs`](https://github.com/mizcausevic-dev/incident-correlation-rs) |
| Tamper-evident audit spine | [`audit-stream-py`](https://github.com/mizcausevic-dev/audit-stream-py) |

## License

MIT.
