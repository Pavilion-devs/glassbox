# DBOM 0.1.0 canonical integrity profile

`schema.json` is the normative machine-readable contract.

## Payload digest and receipt ID

1. Deep-copy the receipt.
2. Remove the complete top-level `integrity` member.
3. Remove the complete top-level `receipt_id` member.
4. Serialize the remaining object using RFC 8785 JSON Canonicalization Scheme.
5. Compute SHA-256 over those bytes.
6. Set `receipt_id` to `gbx:receipt:sha256:<hex digest>`.
7. Store the same digest as `integrity.payload_digest`.

Removing both computed members prevents a circular digest definition. All other
fields—including timestamps and extension values—are digest material.

## Merkle root

The leaves are the items in `evidence`, `actions`, and `evaluations`, followed by
the single `output` object. Empty arrays contribute no leaves.

Each leaf is:

```text
SHA256("glassbox.dbom.leaf.v1\0" || section || "\0" || decimal-index || "\0" || RFC8785(item))
```

Parent nodes are:

```text
SHA256("glassbox.dbom.node.v1\0" || left-bytes || right-bytes)
```

Duplicate the final node at an odd-width tree level. A receipt with no possible
leaves uses `SHA256("glassbox.dbom.empty.v1")`, though DBOM 0.1 always has an output
and therefore normally has at least one leaf.

## Signatures

Ed25519 signatures sign:

```text
"glassbox.dbom.signature.v1\0" || payload-digest-bytes
```

Public keys and signatures use unpadded base64url. A valid signature proves the
receipt bytes were signed by the holder of that key. It does not prove that the
receipt's claims are factually correct.

## Ordering

RFC 8785 orders object keys, but array order remains meaningful. Producers must
emit evidence, actions, approvals, and evaluations in causal order. Reordering an
array changes the receipt digest by design.
