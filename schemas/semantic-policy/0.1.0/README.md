# GlassBox Semantic Policy 0.1.0

This schema defines content-addressed declarative rule packs for deterministic
replay-output comparison. Policy documents contain no executable code and no output
values. A policy is authoritative only when its exact `policy_id` is present in an
operator-configured trusted registry.

Version 0.1.0 supports two closed primitives:

- `NUMERIC_TOLERANCE`: accepts an exact JSON Pointer and at least one non-negative
  decimal absolute or relative bound;
- `UNORDERED_COLLECTION`: proves two arrays contain the same canonical multiset and
  differ only in order.

Every structural change must be covered by a passing rule before the result can be
`EQUIVALENT`. Missing paths, wrong types, exceeded tolerances, and unmatched changes
produce `CHANGED`. Arbitrary ignore rules and model judgments are not part of this
contract.
