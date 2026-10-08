# mcp-permission-broker

> An embeddable rule evaluator for MCP tool calls. Integration and authority checks are the caller's responsibility.

`mcp-permission-broker` evaluates locally loaded `PolicyBundle.rules[]` against a `PermissionRequest`. An MCP server must call `Broker.check()` before executing each tool and block every outcome other than `allow`. This package does not intercept MCP traffic, authenticate callers, fetch or verify Decision Cards, or convert them into its rule format.

The current [`policy-as-code-engine`](https://github.com/mizcausevic-dev/policy-as-code-engine) converter emits a different `PolicyBundle.policies[]` contract with scope, effective dates, and buyer-attestation checks. Its output cannot be loaded into this broker's `PolicyBundle.rules[]` model. No bridge between those contracts is shipped here.

## Why this exists

The library supplies a local allow/deny/approval decision. It can be useful inside an MCP server, but a production authorization boundary also needs authenticated caller and buyer identities, trusted policy loading, tenant and vendor scope, verified Decision Card attestation, effective-window checks, and a tested failure and rollback path. Those controls are not implemented here.

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

`caller_id`, `tool_name`, and each regex pattern are capped at 256 characters. Python `re` has no match timeout here; a crafted pattern with backtracking can still stall evaluation even at that size. Load only reviewed policy files. **Regex denial of service remains a release blocker for untrusted policies or caller/tool identifiers.**

### Audit-stream integration

If `AUDIT_STREAM_URL` is set in the environment, the broker attempts to POST each decision to that endpoint as one of:

- `tool_invocation_allowed`
- `tool_invocation_denied`
- `tool_invocation_required_approval`

POSTs are best effort. Set the URL to the trusted audit sink's `/events` endpoint. The body follows its `{kind, source, payload}` envelope; `payload` contains the asserted caller ID, tool name, rule IDs, and reference URLs, but excludes `tool_args` and `context`. Connection failures and non-2xx responses are logged without the endpoint URL and do not change the decision. The broker does not prove delivery or make its events tamper-evident; verify acceptance and retention at the sink independently.

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

## Bundle from a Decision Card

No Decision Card loader or converter is implemented. The current `policy-as-code-engine` bundle has `policies[]`, `card_scope`, and effective dates, while this library accepts `rules[]`; Pydantic rejects the engine's output. Until a verified adapter or shared evaluator exists, do not treat a Decision Card approval as an allow rule in this broker.

## Status

**v0.1.0** — pure library with an in-memory rule registry, YAML loading, deny-trumps-allow evaluator, and optional best-effort audit POST. There is no MCP server, HTTP API, hosted deployment, or verified Decision Card adapter.

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
