## I0.13. Current support, conformance and product status

Architecture defines meaning; Implementation defines the current target contract; exact code, runtime, and data evidence demonstrates support.

Every load-bearing contract has independent `ImplementationSupport`:

```text
CURRENT_VERIFIED;
CURRENT_UNVERIFIED;
PARTIAL;
BLOCKED;
TARGET;
EXPERIMENTAL;
DEFERRED;
DEGRADED;
STALE;
NOT_APPLICABLE.
```

A prose type, CLI example, schema, report, or generated catalogue row is `TARGET` by default unless exact source handles, Product Identity, executed evidence, verifier, and invalidation set exist.

Current product status:

```text
Architecture direction: accepted for continued design;
Implementation document: target contract;
local current source: UNKNOWN until CurrentSystemEvidenceSnapshot;
installed runtime: UNKNOWN;
live store/data revision: UNKNOWN;
product: NOT_ACCEPTED / UNVERIFIED.
```

No audit package, manifest, or test count can elevate this status without Product Proof.

