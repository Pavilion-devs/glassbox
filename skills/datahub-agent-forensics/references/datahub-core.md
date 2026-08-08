# DataHub Core projection reference

GlassBox uses stable DataHub Core 1.6.0 Documents as compatibility projections.
Search may locate them; direct reads establish the persisted aspects and managed
properties.

## Receipt Document

Deterministic URN:

```text
urn:li:document:glassbox.receipt.<receipt-sha256>
```

Useful properties include receipt/payload/Merkle/output digests, run and agent IDs,
replay eligibility, counts, and referenced URNs. This is a privacy-safe summary. It
is not the full signed DBOM and cannot independently prove the Merkle tree or
signature.

## Supersession Document

Deterministic URN:

```text
urn:li:document:glassbox.replay.supersession.<supersession-sha256>
```

It links both receipt IDs/Document URNs plus bundle, plan, execution, diff, exact
semantic result, change count, policy, and time. It is separate so neither receipt
Document needs rewriting.

## Retrieval discipline

1. Search for candidate URNs.
2. Directly fetch the selected entity/aspects.
3. Preserve unknown or missing aspects.
4. For integrity questions, fetch and verify the authoritative signed DBOM.
5. For writes, use deterministic IDs, repeat the write, and directly read back exact
   managed properties. Do not call transport acceptance human acknowledgement.

Generic DataHub lineage is valuable context but not proof that an agent consumed an
asset. Require DBOM influence evidence for that claim.
