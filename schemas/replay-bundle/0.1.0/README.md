# Replay Bundle 0.1.0 canonical integrity profile

`schema.json` is the normative machine-readable contract. A replay bundle is a
derived artifact; it never modifies its source DBOM.

## Payload digest and bundle ID

1. Deep-copy the replay bundle.
2. Remove the complete top-level `integrity` member.
3. Remove the complete top-level `bundle_id` member.
4. Serialize the remaining object with RFC 8785 JSON Canonicalization Scheme.
5. Compute:

```text
SHA256("glassbox.replay.bundle.v1\0" || RFC8785(material))
```

6. Set `bundle_id` to `gbx:replay-bundle:sha256:<hex digest>`.
7. Store the same digest as `integrity.payload_digest`.

The payload commits the source receipt ID and payload digest, replay mode, complete
recipe pins, action digests, execution supplement, active context representations,
and original output digest. Signatures are excluded to avoid a circular digest.

## Action digests

Each replay action commits both the exact action and its pinned tool:

```text
SHA256("glassbox.replay.action.v1\0" ||
       RFC8785({"action": action-without-action-digest, "tool": pinned-tool}))
```

Changing an input, effect, idempotency key, tool version, source digest, or tool
schema digest changes the action digest.

For corrected `INPUT` evidence, the action additionally commits
`original_input_digest`, the active `input_digest`, `input_origin`, the exact
`input_evidence_ids`, and `input_verification_authority`. The builder requires every
replaced input-evidence item to propagate into an action replacement, requires the
context and action authorities to match, and rejects a replacement that reuses the
source digest. The executor then hashes the resolved transient value before calling
the capability.

## Signatures

Ed25519 signatures sign:

```text
"glassbox.replay.bundle.signature.v1\0" || payload-digest-bytes
```

Public keys and signatures use unpadded base64url. A signature establishes artifact
integrity and possession of a private key. It does not establish factual truth or
that the embedded key ID belongs to a trusted operator.

## Closed replay modes

- `PINNED` uses only original receipt context.
- `CORRECTED` requires at least one explicitly identified context replacement and,
  for replaced `INPUT` evidence, an explicit affected action-input replacement.
- `COUNTERFACTUAL` requires exactly one replacement.
- `DRY` can be reconstructed and inspected but can never authorize execution.

There is no best-effort mode. Missing pins or verification authorities remain
visible and force a non-executing policy result.
