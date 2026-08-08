# Runtime instrumentation contract

**Status:** Gate 3 implementation complete
**Version:** `0.1.0-dev`
**Decision record:** [ADR-0004](adr/0004-runtime-capture-and-action-preflight.md)

The runtime SDK captures a small normalized event stream. Decorators, direct MCP
middleware, and framework callbacks must produce the same action and evidence
attributes so the provenance compiler does not depend on a framework-specific trace
shape.

## Event model

The core emits five lifecycle concepts:

| Event | Purpose |
| --- | --- |
| `glassbox.run.started` | Opens an agent or workflow run and fixes its correlation context. |
| `glassbox.evidence.observed` | Records a typed evidence claim and an optional representation digest. |
| `glassbox.action.attempted` | Preflights a tool action before application code executes it. |
| `glassbox.action.finished` | Records a successful, failed, or blocked terminal action state. |
| `glassbox.run.finished` | Closes a run with success, failure, abstention, or cancellation. |

Every event declares runtime event spec `0.1.0` and contains a monotonically
increasing process-local sequence, UTC timestamp, trace ID, span ID, parent span ID,
run ID, parent run ID, agent identity, workflow identity, and normalized attributes.
Child runs inherit the trace ID and retain explicit parent identifiers.

The event sequence is evidence, not a global ordering protocol. Multi-process
collectors must order by trace relationships and timestamps while preserving each
producer's sequence.

## Privacy boundary

Raw evidence representations, arguments, results, authorization headers, and
exception messages are not event fields.

- Tool inputs and outputs become domain-separated SHA-256 commitments.
- Evidence representations become commitments when supplied.
- Sensitive metadata keys and configured dotted paths render as `[REDACTED]`.
- Exception capture stores only the qualified event context and exception type.
- Unknown Python objects are represented by qualified type; their `repr` is never
  called.
- Bytes are normalized to a SHA-256 value before the outer commitment.
- Cycles, non-finite floats, large integers, decimals, dates, UUIDs, sets, and
  dataclasses have deterministic JSON-safe normalization rules.

Display redaction does not alter commitment material. For example, two inputs with
different passwords create different digests while both sanitized metadata values
display as `[REDACTED]`.

Digests of low-entropy values can be guessed. They prevent unnoticed substitution;
they are not encryption. Do not publish receipts containing predictable sensitive
value digests without an appropriate deployment-level keyed commitment policy.

## Run APIs

Decorator mode supports synchronous and asynchronous functions:

```python
runtime = GlassBox()

@runtime.consequential(agent_id="pricing-agent", workflow_id="recommend-price")
async def recommend(customer_id: str) -> dict[str, int]:
    return {"recommended_price": 42}
```

The explicit context manager supports nesting and status control:

```python
with runtime.run(agent_id="orchestrator", workflow_id="pricing") as parent:
    with runtime.run(agent_id="specialist", workflow_id="analysis") as child:
        child.record_output({"recommendation": 42})
    parent.abstain()
```

Exceptions mark the active run `FAILED` and are reraised unchanged. The exception
message is not retained.

## Evidence requirements

- `OBSERVED` requires a runtime representation and receives its digest plus a source
  span.
- `INFERRED` requires both a non-empty rule ID and confidence in `[0, 1]`.
- `DECLARED` is an owner or configuration claim and must not be promoted to observed
  by a compiler.
- `UNKNOWN` preserves missing provenance explicitly.

An evidence item also records its role: input, reference, constraint, policy,
memory, or output target.

## Action controls

| Effect | Idempotency key | Approval | Default sink behavior |
| --- | --- | --- | --- |
| `READ_ONLY` | Optional | Optional | Fail open |
| `REVERSIBLE` | Required | Optional | Fail open unless configured otherwise |
| `IRREVERSIBLE` | Required | Required | Fail closed |
| `UNKNOWN_EFFECT` | Optional | Optional | Fail closed |

Blocked policy checks emit a terminal `BLOCKED` observation before raising. For
fail-closed effects, the attempt event must reach the sink before the tool function
is invoked. The runtime cannot atomically coordinate an arbitrary external mutation
and its terminal event; an accepted attempt with no terminal event is an explicit
uncertain outcome for the compiler and operator.

## Direct MCP middleware

`MCPToolMiddleware` wraps an async `call_next(name, arguments)` function without a
dependency on one MCP client implementation. The normalized tool identifier is
`<server>.<tool>` when a server name is available. Arguments and results remain on
the call stack and only their commitments reach the event sink.

## Framework callback bridge

`CallbackActionAdapter` connects framework-owned start, end, and error callbacks by
an opaque call ID. Its pending state stores only an `ActionToken`: correlation
context, effect classification, input digest, approval/idempotency identifiers, and
sanitized metadata. It never holds the original tool input.

Callbacks may complete out of order. Duplicate pending IDs and terminal callbacks
without a matching start are rejected because silently merging them would corrupt
provenance.

### LangChain and LangGraph

`LangChainToolCallbackAdapter` implements the current `langchain-core` tool callback
shape (`on_tool_start`, `on_tool_end`, and `on_tool_error`). LangGraph uses this same
callback protocol. `create_langchain_callback` returns an actual
`BaseCallbackHandler` when the `langchain` extra is installed.

Structured `inputs` take precedence over the fallback input string. The tool name
must be present in the serialized callback object, and the framework `run_id` is the
opaque correlation key. Exception messages are never retained.

### Google ADK

`GoogleADKToolAdapter` implements Google ADK 2.x plugin callbacks:
`before_tool_callback`, `after_tool_callback`, and `on_tool_error_callback`.
`create_google_adk_plugin` returns an actual ADK `BasePlugin` when the `google-adk`
extra is installed. The adapter uses the public
`tool_context.function_call_id`; it refuses to invent correlation when that value or
`tool.name` is absent.

Both named adapters require an explicit `ToolPolicyResolver`. The mapping resolver
uses exact tool IDs and defaults unconfigured tools to `UNKNOWN_EFFECT`; framework
metadata can never silently classify a mutation as read-only.

## OpenTelemetry GenAI mapping

`OpenTelemetrySpanSink` reduces normalized lifecycle events to exporter-neutral
completed spans using the pinned GenAI semantic-convention schema
`https://opentelemetry.io/schemas/gen-ai/1.42.0`:

- agent runs become `invoke_agent {agent}` internal spans;
- tool calls become `execute_tool {tool}` internal spans;
- evidence claims become `glassbox.evidence.observed` events on their active run;
- evidence events retain their originating runtime span ID for DBOM attribution;
- failed runs plus failed or blocked tools receive error span status;
- DataHub entity and schema-field URNs use the GlassBox extension namespace;
- tool arguments and results are never placed in the standard sensitive
  `gen_ai.tool.call.arguments` or `gen_ai.tool.call.result` attributes.

The reducer rejects orphan evidence, duplicate starts, and run terminals without a
start instead of manufacturing a plausible trace. Gate 4 now provides a strict
OTLP/HTTP protobuf-JSON parser and completed-span normalizer; see the
[provenance compiler contract](provenance-compiler.md).

## Current limits

- The in-memory sink is for tests and embedded demos. Gate 4 provides a checksummed
  append-only development log; production still requires a durable collector/store.
- The span mapper emits exporter-neutral records; the compiler accepts those records
  and OTLP/HTTP JSON, while network transport remains a deployment concern.
- Named framework factories require their optional dependency extras.
- Receipt compilation and DataHub emission remain outside the runtime package and
  are implemented by the Gate 4 compiler and DataHub adapter boundaries.
