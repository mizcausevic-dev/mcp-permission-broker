# mcp-permission-broker

> The runtime gate that turns *"buyer signed off"* into *"this MCP tool call is allowed."*

`mcp-permission-broker` is a Python library that decides, at the moment an MCP client tries to invoke a tool, whether the call is permitted. It composes a buyer's published **AI Procurement Decision Cards** (Kinetic Gain Protocol Suite spec #11) into runtime PolicyBundles, applies them against an incoming `PermissionRequest`, and emits the decision — plus an optional `audit-stream-py` event — to the caller.

Where [`policy-as-code-engine`](https://github.com/mizcausevic-dev/policy-as-code-engine) is the *general* policy evaluator, this library is the *MCP-shaped* enforcement point: the missing link between a Decision Card's `conditions[]` and an actual `tool_invocation_allowed` / `tool_invocation_denied` event in your governance log.

## Why this exists

The Kinetic Gain Protocol Suite already has the static side covered. Vendors publish Agent Cards, Tool Cards, AEO declarations, Clinical/Tutor/Incident Cards. Buyers publish Decision Cards that approve, condition, or reject a vendor's posture. Everything is verifiable, hash-bound, machine-readable.

What's been missing is the **runtime side** for MCP specifically. When an MCP client calls a tool, *what enforces the buyer's decision?* Today: nothing. The Decision Card says "approved-with-conditions"; the MCP server happily serves every request. The broker closes that gap.

```
[buyer publishes a Decision Card]
            │
            ▼
[policy-as-code-engine builds a PolicyBundle from its conditions[]]
            │
            ▼
[mcp-permission-broker holds the PolicyBundles; an MCP server consults it before tool execution]
            │
            ▼
[allow / deny / require_approval — every decision a tamper-evident audit-stream event]
```

## Design

### Inputs

A `PermissionRequest` carries everything the broker needs:

| Field | Meaning |
|---|---|
| `caller_id` | The identity of the agent / tool client making the call. Matches against `agent_card.system_id`. |
| `tool_name` | The MCP tool being invoked (e.g. `github.search_repositories`). Matches against `tool_card.tool_name`. |
| `tool_args` | The opaque arguments. The broker does NOT inspect these by default. |
| `context` | Free-form dict. Use for tenant ID, environment, time-of-day, anything a rule may need. |

### Outputs

A `PermissionDecision` carries the verdict:

| Field | Meaning |
|---|---|
| `outcome` | `allow` / `deny` / `require_approval` (terminal, with deny-trumps-allow precedence). |
| `matched_rules` | List of rule IDs that contributed to this decision. |
| `decision_card_refs` | List of Decision Card URLs whose conditions this enforced. |
| `correlation_id` | UUIDv4. Same value goes to audit-stream so an auditor can replay the chain. |

### Rule semantics

A `PolicyRule` is:

```yaml
id: deny-deletions-without-approval
priority: 100
effect: deny                       # allow | deny | require_approval
tool_name: "^github\\..*delete.*"   # regex on tool_name
caller_id: ".*"                    # regex on caller_id
when:                              # optional Python expression over context
  expr: "context.get('environment') == 'production'"
because:
  decision_card: "https://district.example/.well-known/decisions/DEC-2026-001.json"
  condition_id: "no-destructive-prod-actions"
```

Evaluation order:

1. Every rule in every loaded `PolicyBundle` is checked against the request.
2. Rules are sorted by `priority` (descending).
3. **Deny trumps allow.** First `deny` match short-circuits to `deny`.
4. Otherwise the highest-priority `require_approval` match wins.
5. Otherwise the first `allow` match wins.
6. If nothing matches: configurable default (`allow` for permissive deployments, `deny` for governed ones — default is `deny`).

### Audit-stream integration

If `AUDIT_STREAM_URL` is set in the environment, every decision is POSTed to that endpoint as one of:

- `tool_invocation_allowed`
- `tool_invocation_denied`
- `tool_invocation_required_approval`

The producer follows the [`audit-stream-py`](https://github.com/mizcausevic-dev/audit-stream-py) contract: best-effort POST, never raised back to the caller, structured envelope with `correlation_id` so you can join broker decisions to downstream events.

Without `AUDIT_STREAM_URL` the broker emits decisions only to its return value — no HTTP traffic, no side effects, no crashes.

## Quickstart

```python
from mcp_permission_broker import Broker, PermissionRequest

broker = Broker.from_yaml_dir("./policies")
decision = broker.check(PermissionRequest(
    caller_id="acme-tutor-v2.1",
    tool_name="filesystem.write_file",
    context={"environment": "production", "tenant_id": "springfield-isd"},
))

if decision.outcome != "allow":
    raise PermissionError(f"{decision.outcome}: matched {decision.matched_rules}")
```

Wire it into your MCP server's request handler. Allow ⇒ proceed. Deny ⇒ return an MCP error. Require approval ⇒ park the request, ping the human-in-loop.

## Optional FastAPI service

Install with `pip install mcp-permission-broker[api]` for the HTTP wrapper. Single endpoint, deterministic, audit-stream-integrated. See [`docs/api.md`](docs/api.md) for the OpenAPI surface (added in v0.2).

## Bundle from a Decision Card

`policy-as-code-engine` already does the heavy lifting of turning a Decision Card's `conditions[]` array into a portable PolicyBundle. The broker treats those bundles as a first-class load source:

```python
from mcp_permission_broker import Broker

broker = Broker()
broker.load_bundle_from_decision_card("https://district.example/.well-known/decisions/DEC-2026-001.json")
```

This makes the broker a thin enforcement layer on top of decisions that were already published, signed, and reviewable — exactly the design the Suite is built around.

## Status

**v0.1.0** — pure library. Core models, in-memory bundle registry, YAML loading, deny-trumps-allow evaluator, audit-stream emitter, full test coverage. No HTTP server (slated for v0.2).

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
