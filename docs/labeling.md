# Labeling rules

Used for every evaluation set. Write the rule down before labeling, and never relabel a frozen set.

## Categories
Each item gets the single category that best names the **root cause the error text states**.
`SAN_MISSING`, `KEY_TOO_WEAK`, `KEY_TYPE_NOT_ALLOWED`, `EKU_NOT_ALLOWED`, `VALIDITY_TOO_LONG`, `SIG_ALG_REJECTED`, `CHAIN_UNTRUSTED`, `CERT_EXPIRED`, `VALIDATION_PENDING`, `REVOKED`, `AUTH_FAILED`, `POLICY_REJECTED`.

## The `UNKNOWN` rule
Label `UNKNOWN` when **any** of these holds:
1. The text is not about certificate issuance or validation (unrelated tickets).
2. The text names a condition that is **not one of the categories above** (for example CRL expiry, path-length or name-constraint violations, malformed fields, rate limits, server errors, account problems), even if a nearby category looks plausible.
3. The text does not contain enough information to pick a category.

A classifier that places such an item in the nearest category is counted as wrong. This is deliberately strict: the tool should not guess a root cause the text does not state.

## Ambiguous items
Mark `"ambiguous": true` when the mapping to a category is a judgement call (for example `hostname mismatch` -> `SAN_MISSING`). Reports show accuracy with and without ambiguous items.

## Provenance
Each item records `source_url` and the `labeler`. Items labeled by the tool's author or an AI assistant must say so; independent review is needed before quoting results as more than indicative.
