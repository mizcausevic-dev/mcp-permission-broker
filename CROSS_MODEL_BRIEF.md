# Cross-Model Brief — mcp-permission-broker

> **If you (Claude / Codex / Gemini / any LLM) are about to scaffold a sibling implementation of this repo, read the [canonical Cross-Model Brief in kinetic-gain-protocol-suite](https://github.com/mizcausevic-dev/kinetic-gain-protocol-suite/blob/main/CROSS_MODEL_BRIEF.md) FIRST.** That file is the contract for the whole ecosystem. This file is the broker-specific addendum.

---

## Repo-specific addendum

### What this repo IS

`mcp-permission-broker` is the **runtime enforcement point** between an AI Procurement Decision Card (a buyer's published review document) and an actual MCP tool invocation. It is a Python library — pydantic v2 models, in-memory `PolicyBundle` registry, deny-trumps-allow evaluator, audit-stream-py emitter.

### What this repo is NOT

| It's not | Because that's already covered by |
| --- | --- |
| A Decision Card editor or generator | [`procurement-decision-api`](https://github.com/mizcausevic-dev/procurement-decision-api) drafts Decision Cards |
| A general policy evaluator | [`policy-as-code-engine`](https://github.com/mizcausevic-dev/policy-as-code-engine) is the general-purpose rule engine; this library is the MCP-shaped enforcement *application* of it |
| An MCP server | This is a library you embed in *your* MCP server's request handler — not a server itself |
| An audit log | Decisions are POSTed to `audit-stream-py` via `AUDIT_STREAM_URL`. Do not maintain a parallel log. |
| A web UI | The dashboard / visual control plane lives in `mcp-permission-broker-dashboard` (separate repo, in flight). The library is headless and embeddable. |

### Vocabulary — important

This is the term most consistently mis-modeled by other LLMs when they see this repo:

- A **PolicyRule** is one row in a PolicyBundle's `rules[]` array. It has `id`, `priority`, `effect`, `tool_name` (regex), `caller_id` (regex), optional `when.expr`, and a `because` pointer to the Decision Card condition that produced it.
- A **Decision Card** is the buyer's whole published document at `/.well-known/decisions/<id>.json`. It contains `conditions[]` that — when compiled by `policy-as-code-engine` — produce a `PolicyBundle` full of `PolicyRule`s.

These are NOT the same thing. A `DecisionCard` class that wraps `name + pattern + decision + rationale` (as one sibling implementation has) is conflating a `PolicyRule` with a Decision Card. Use the canonical names.

### What's authoritative in this repo

- The Python API surface (`Broker`, `PermissionRequest`, `PermissionDecision`, `PolicyBundle`, `PolicyRule`, `Outcome`) — these are the names every sibling implementation should mirror.
- Deny-trumps-allow → require_approval → first allow → default — this evaluation order is the contract. Don't reorder it.
- Regex match grammar for `tool_name` and `caller_id` — the engine internal. Buyer-facing UIs may surface wildcards (`fs.*delete*`), but they MUST compile to regex before evaluation so behavior stays consistent.
- Best-effort, never-raised `AUDIT_STREAM_URL` POSTs — match `audit-stream-py`'s producer contract exactly.

### What's open to reinterpret

- **HTTP wrapper**: v0.1 is library-only. A FastAPI service (under the `[api]` optional extra) is planned for v0.2 — if you're building one, mirror the shape of `procurement-decision-api`'s OpenAPI surface.
- **Natural-language card generation**: not in v0.1. Sibling implementations have added this via Gemini Flash; we'll add it via the Anthropic SDK in v0.2. Same prompt shape, different model.
- **Wildcard → regex helper**: not yet shipped. If you're building a UI for buyers, write `wildcard_to_regex()` and contribute it back here.
- **Per-tool policy editor UI**: dashboard concern, not library concern. See `mcp-permission-broker-dashboard` when it lands.

### Sibling implementations known to exist

- **TypeScript / Express full-stack dashboard** built by Google AI Studio (Gemini Flash). Reimplements the broker logic in TS for demo purposes; uses Bento Grid UI. **The Python lib is the source of truth — the TS version should eventually hit this lib via FastAPI rather than maintaining its own broker.** ([`docs/sibling-implementations.md`](docs/sibling-implementations.md) tracks the full list.)

### What event kinds this repo emits to audit-stream-py

| Event kind | When emitted |
| --- | --- |
| `tool_invocation_allowed` | `Broker.check()` returns an allow decision |
| `tool_invocation_denied` | `Broker.check()` returns a deny decision |
| `tool_invocation_required_approval` | `Broker.check()` returns require_approval |

These are added to [audit-stream-py's `EventKind` Literal](https://github.com/mizcausevic-dev/audit-stream-py/pull/1). Do not invent your own.

---

For everything else, the [canonical Cross-Model Brief](https://github.com/mizcausevic-dev/kinetic-gain-protocol-suite/blob/main/CROSS_MODEL_BRIEF.md) is the source.
