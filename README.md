# mcp-permission-broker

> An embeddable rule evaluator for MCP tool calls. Integration and authority checks are the caller's responsibility.

`mcp-permission-broker` evaluates locally loaded `PolicyBundle.rules[]` against a `PermissionRequest`. A separate signed-card gate converts a raw Decision Card with `policy-as-code-engine==0.2.0` and evaluates its scoped `policies[]` with that engine. An MCP server must call `Broker.check()` before executing each tool and block every outcome other than `allow`. This package does not intercept MCP traffic or authenticate callers.

The two bundle formats remain distinct. A serialized `policies[]` bundle has no signature or proof that it came from a verified card; the broker does not accept one as signed. The signed-card gate calls the engine's converter on the raw card with an independently pinned buyer ID and Ed25519 public key, then keeps the resulting typed bundle in memory. This is an in-process prototype, not a hosted MCP authorization boundary.

## Why this exists

The library supplies a local allow/deny/approval decision and checks a positive card's signature, buyer pin, vendor/action scope, conditions, and effective window in its optional signed-card path. A production authorization boundary still needs an authenticated MCP host, trusted caller-to-buyer mapping, independently checked condition signals, card refresh/revocation handling, durable accepted audit receipts, and a tested failure and rollback path. Those host and deployment controls are not implemented here.

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

### Audit-stream integration

If `AUDIT_STREAM_URL` and `AUDIT_STREAM_TOKEN` are set in the environment, the broker attempts to POST each decision to the sink's `/events` endpoint as one of:

- `tool_invocation_allowed`
- `tool_invocation_denied`
- `tool_invocation_required_approval`

POSTs are best effort. Set `AUDIT_STREAM_URL` to the trusted sink base URL; a legacy URL already ending in `/events` is accepted. The URL must use HTTPS or loopback HTTP, with no embedded credentials, query, or fragment. `AUDIT_STREAM_TOKEN` must contain at least 32 visible ASCII characters with no whitespace, matching the sink's requirement; it is sent only in the Bearer header and is never logged. If the token is missing or invalid, no POST is attempted. The body follows the sink's `{kind, source, payload}` envelope; `payload` contains the asserted caller ID, tool name, rule IDs, and reference URLs, but excludes `tool_args`, request `context`, and trusted card condition signals. Connection failures and non-2xx responses are logged without the endpoint URL or token and do not change the decision. The broker does not prove delivery or make its events tamper-evident; verify acceptance and retention at the sink independently.

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

**Unreleased review branch, source version 0.1.0** — pure library with an in-memory local rule registry, a separate signed-card gate backed by `policy-as-code-engine==0.2.0`, and optional best-effort authenticated audit POST. There is no MCP server, HTTP API, hosted deployment, or verified host identity boundary.

## Place in the Kinetic Gain portfolio

| Concern | Repo |
|---|---|
| Spec the buyer publishes | [`ai-procurement-decision-spec`](https://github.com/mizcausevic-dev/ai-procurement-decision-spec) |
| Drafting Decision Cards | [`procurement-decision-api`](https://github.com/mizcausevic-dev/procurement-decision-api) |
| Building runtime bundles | [`policy-as-code-engine`](https://github.com/mizcausevic-dev/policy-as-code-engine) |
| **Enforcing at MCP call time** | **`mcp-permission-broker` (this repo)** |
| Walking the graph after an incident | [`incident-correlation-rs`](https://github.com/mizcausevic-dev/incident-correlation-rs) |
| Tamper-evident audit spine | [`audit-stream-py`](https://github.com/mizcausevic-dev/audit-stream-py) |

## License

MIT.
