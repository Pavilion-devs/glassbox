# GlassBox normalized runtime event 0.1.0

This directory is the normative serialization contract for events emitted by the
Python runtime. Every instrumentation adapter produces this shared shape before
OpenTelemetry or another sink-specific mapping.

The schema controls the envelope and correlation identifiers. Event-specific
attribute constraints remain in Python until the OpenTelemetry semantic mapping is
finished; they will be promoted into conditional schema branches before the runtime
event format is declared stable.

Version `0.1.0` is append-only. Breaking envelope or meaning changes require a new
schema directory.
