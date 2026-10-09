# Cross-Model Brief — mcp-permission-broker

> **If you (Claude / Codex / Gemini / any LLM) are about to scaffold a sibling implementation of this repo, read the [canonical Cross-Model Brief in kinetic-gain-protocol-suite](https://github.com/mizcausevic-dev/kinetic-gain-protocol-suite/blob/main/CROSS_MODEL_BRIEF.md) FIRST.** That file is the contract for the whole ecosystem. This file is the broker-specific addendum.

---

## Repo-specific addendum

### What this repo IS

`mcp-permission-broker` is an embeddable Python rule evaluator. It has pydantic v2 models, an in-memory `PolicyBundle.rules[]` registry, a separate raw signed-card gate backed by `policy-as-code-engine==0.2.1`, deny-trumps-allow evaluation, and optional best-effort audit POSTs. Its opt-in reference `AuthenticatedToolGate` verifies a pinned Ed25519 JWT and server-owned bindings before invoking selected synchronous handlers, requiring an accepted pre-dispatch audit callback. It is not an MCP transport or a guard on the published TypeScript server. A real host must route every selected call exclusively through it.

### What this repo is NOT

| It's not | Because that's already covered by |
| --- | --- |
| A Decision Card editor or generator | [`procurement-decision-api`](https://github.com/mizcausevic-dev/procurement-decision-api) drafts Decision Cards |
| A serialized `policies[]` importer | Engine bundles have no signature proof. The broker converts a raw attested card with pinned buyer authority, then evaluates the typed bundle privately. |
| An MCP server | This is a library you embed in *your* MCP server's request handler — not a server itself |
| An audit log | Optional best-effort POSTs go to `AUDIT_STREAM_URL`; this library does not guarantee delivery or retention. |
| A web UI | The dashboard / visual control plane lives in `mcp-permission-broker-dashboard` (separate repo, in flight). The library is headless and embeddable. |

### Vocabulary — important

This is the term most consistently mis-modeled by other LLMs when they see this repo:

- A **PolicyRule** is one row in this library's PolicyBundle `rules[]` array. It has `id`, `priority`, `effect`, `tool_name` (regex), `caller_id` (regex), optional `when.expr`, and optional unverified `because` metadata.
- A **Decision Card** is the buyer's whole published document at `/.well-known/decisions/<id>.json`. The `policy-as-code-engine` converter produces a distinct bundle with `policies[]`, not this library's `PolicyRule`s. The broker verifies the card through that converter only when the host pins buyer authority and enables the signed-card gate.

These are NOT the same thing. A `DecisionCard` class that wraps `name + pattern + decision + rationale` (as one sibling implementation has) is conflating a `PolicyRule` with a Decision Card. Use the canonical names.

### What's authoritative in this repo

- The Python API surface (`Broker`, `PermissionRequest`, `TrustedCardContext`, `PermissionDecision`, `PolicyBundle`, `PolicyRule`, `Outcome`) for this library. Do not infer contract compatibility from similar class names.
- Deny-trumps-allow → require_approval → first allow → default — this evaluation order is the contract. Don't reorder it.
- Regex match grammar for `tool_name` and `caller_id` — the engine internal. Buyer-facing UIs may surface wildcards (`fs.*delete*`), but they MUST compile to regex before evaluation so behavior stays consistent.
- Local rule regex matching uses a 20 ms per-match timeout and 256-character caps on patterns and identity/tool strings. Policy count can still multiply latency; load only reviewed policies and bound their count at the embedding host.
- Best-effort, never-raised authenticated POSTs to `AUDIT_STREAM_URL` `/events` using `AUDIT_STREAM_TOKEN`. A successful broker decision is not proof that an audit event reached or was accepted by a sink.

### What's open to reinterpret

- **HTTP wrapper**: none is shipped. Any future service requires its own authentication, authorization, and abuse review.
- **Natural-language card generation**: none is shipped.
- **Wildcard → regex helper**: not yet shipped. If you're building a UI for buyers, write `wildcard_to_regex()` and contribute it back here.
- **Per-tool policy editor UI**: dashboard concern, not library concern. See `mcp-permission-broker-dashboard` when it lands.

### Sibling implementations known to exist

- A separate TypeScript / Express dashboard has been described, but its integration and parity have not been verified in this repo.

### What event kinds this repo emits to audit-stream-py

| Event kind | When emitted |
| --- | --- |
| `tool_invocation_allowed` | `Broker.check()` returns an allow decision |
| `tool_invocation_denied` | `Broker.check()` returns a deny decision |
| `tool_invocation_required_approval` | `Broker.check()` returns require_approval |

The broker constructs these event names, but this repo does not test acceptance by a live `audit-stream-py` instance.

---

For everything else, the [canonical Cross-Model Brief](https://github.com/mizcausevic-dev/kinetic-gain-protocol-suite/blob/main/CROSS_MODEL_BRIEF.md) is the source.
