# State Transfer 0.1.0 canonical integrity profile

`schema.json` is the normative portable contract for transferring verified GlassBox
receipt state. It is not a database dump and its operational archive is never live
on import.

## Payload digest and bundle ID

1. Deep-copy the complete bundle.
2. Remove the top-level `integrity` member.
3. Remove the top-level `bundle_id` member.
4. Serialize the remaining object with RFC 8785 JSON Canonicalization Scheme.
5. Compute:

```text
SHA256("glassbox.state-transfer.payload.v1\0" || RFC8785(material))
```

6. Set `bundle_id` to `gbx:state-transfer:sha256:<hex digest>`.
7. Store the same digest as `integrity.payload_digest`.

The payload commits the source engine and schema version, verified source counts,
every signed receipt, field-lineage proof, supersession pointer, and the inactive
operational archive.

## Signatures and authority

Each Ed25519 signature signs:

```text
"glassbox.state-transfer.signature.v1\0" || payload-digest-bytes
```

Public keys and signatures use unpadded base64url. An embedded signature proves
mathematical integrity only. Production verification also requires the key ID and
public-key fingerprint to meet the active state-transfer authority policy and its
signature threshold.

Transfer authority and receipt authority are separate. Every embedded DBOM is
verified again under the destination's current receipt-signer `ADMISSION` policy.
A trusted transfer signature cannot authorize an unknown, retired, revoked,
out-of-window, or otherwise invalid receipt signature.

## Import semantics

`source.import_scope` is fixed to `RECEIPTS_ONLY` and
`operational_archive.activated_on_import` is fixed to `false`.

One target transaction activates:

- the exact signed receipt;
- its field-lineage proof;
- its supersession pointer; and
- one fresh `READY` publication obligation when newly inserted.

It never activates archived campaign tasks, publication status, leases, retries,
audit rows, routing tasks, or remote-side-effect evidence. Exact duplicate receipts
are idempotent; conflicting dependency metadata rejects and rolls back the complete
batch.

See [ADR-0018](../../../docs/adr/0018-signed-state-transfer-and-safe-reactivation.md)
and the [operator runbook](../../../docs/operations/state-transfer.md).
