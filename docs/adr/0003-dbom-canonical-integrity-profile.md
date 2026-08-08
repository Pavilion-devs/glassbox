# ADR-0003: Use RFC 8785, SHA-256, Merkle commitments, and Ed25519

- **Status:** Accepted
- **Date:** 2026-08-06
- **Owners:** GlassBox maintainers

## Context

A DBOM must be verifiable without DataHub or a GlassBox service. Ordinary JSON does
not define object-key order or a universal number representation, and signing a
receipt that includes its own digest creates a circular definition.

## Decision

- Canonicalize payloads with RFC 8785 JSON Canonicalization Scheme.
- Remove `receipt_id` and the complete `integrity` object from payload-digest
  material.
- Compute SHA-256 and derive `gbx:receipt:sha256:<digest>` from that material.
- Commit evidence, actions, evaluations, and output through a domain-separated
  binary Merkle tree.
- Support optional Ed25519 signatures over a domain separator plus the payload
  digest bytes.
- Encode raw public keys and signatures with unpadded base64url.
- Reject non-finite numbers and other values RFC 8785 cannot represent.
- Treat array ordering as material and causal.

The normative byte-level rules live beside the JSON Schema under
`schemas/dbom/0.1.0/`.

## Alternatives considered

- Pretty-printed or sorted-key JSON: rejected because it leaves number and escaping
  behavior underspecified.
- JSON Web Signature as the only container: deferred because DBOM requires a simple
  portable JSON form and explicit multiple-signature semantics.
- SHA-512: acceptable cryptographically, but rejected for 0.1 to align with common
  content-addressing and DataHub property constraints.
- ECDSA: rejected for the initial profile because Ed25519 has a smaller,
  deterministic signature surface.

## Consequences

- Every implementation must use compatible RFC 8785 semantics.
- Integrity proves bytes and signer identity, never factual truth.
- Changing any payload field or array order changes the receipt ID.
- Signature additions do not change the payload digest.

## Reversal conditions

A future DBOM version may add an algorithm registry or envelope format. Version 0.1
verification rules remain immutable.
