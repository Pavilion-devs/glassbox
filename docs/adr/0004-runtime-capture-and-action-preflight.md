# ADR-0004: Normalize runtime events and preflight governed actions

- **Status:** Accepted
- **Date:** 2026-08-06
- **Owners:** GlassBox maintainers

## Context

GlassBox must capture the same provenance across decorators, framework callbacks,
and direct MCP clients. Instrumentation must not retain prompts, tool arguments,
results, credentials, or exception messages by default. It must also avoid letting
an irreversible action execute when its required provenance sink is already known
to be unavailable.

## Decision

- Normalize every instrumentation mode into immutable `RuntimeEvent` records.
- Correlate nested agent runs with task-local context variables. Child runs inherit
  their parent's trace ID and retain explicit parent run and span IDs.
- Preserve raw tool arguments and results only on the application call stack. Emit
  domain-separated SHA-256 commitments, never those plaintext values.
- Redact sensitive metadata keys and configured dotted paths before an event reaches
  a sink. Exception capture records the exception type, never its message.
- Keep display redaction separate from digest normalization: two different secret
  values remain different cryptographic commitments even though both render as
  `[REDACTED]`.
- Require idempotency keys for reversible and irreversible actions, and require an
  approval ID for irreversible actions.
- Emit an `ACTION_ATTEMPTED` preflight before invoking a tool. Sink failure is
  fail-open for read-only execution and fail-closed for irreversible or
  unknown-effect execution by default.
- Join framework start/end callbacks with privacy-safe action tokens that retain the
  input digest and correlation context but not the input.
- Map normalized events to the OpenTelemetry GenAI `invoke_agent` and `execute_tool`
  conventions while keeping sensitive arguments and results absent.
- Treat evidence claims as point-in-time span events and preserve GlassBox evidence,
  DataHub URN, action-effect, and approval attributes in a versioned extension
  namespace.

## Alternatives considered

- Retaining complete arguments and results in spans: rejected because observability
  stores are broad data-exfiltration surfaces.
- Redacting before hashing: rejected because distinct sensitive inputs would become
  the same commitment.
- Treating every telemetry failure as fail-open: rejected for governed mutations.
- Treating every telemetry failure as fail-closed: rejected because a tracing outage
  should not stop ordinary read-only analysis.
- Using a process-global run stack: rejected because concurrent async tasks would
  corrupt parent/child correlation.

## Consequences

- A runtime digest commits the normalized input but may still be vulnerable to
  guessing when the input has very low entropy; deployments can add protected raw
  trace storage or keyed commitments in a future profile.
- Unknown Python objects normalize to their qualified type rather than calling
  `repr`, which could leak data or execute user code. Adapters should supply
  structured values when exact object state matters.
- Preflight proves the sink accepted an attempt before a guarded effect begins. No
  client-side library can make the external mutation and terminal telemetry export
  atomic; a missing terminal event is therefore an explicit uncertain outcome.
- Framework adapters share one normalization kernel instead of inventing separate
  provenance formats.
- OpenTelemetry mapping is exporter-neutral so a framework SDK upgrade cannot change
  the normative GlassBox runtime-event contract.

## Reversal conditions

This decision may be superseded by a standardized OpenTelemetry GenAI action
transaction contract or by a durable outbox that can atomically coordinate specific
external systems. The privacy-safe normalized model remains the compatibility
boundary.
