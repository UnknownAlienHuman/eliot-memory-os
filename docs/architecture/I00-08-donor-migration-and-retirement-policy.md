## I0.8. Donor migration and retirement policy

Until the old three books are retired, every useful donor decision has one disposition in the current content-addressed donor-retirement ledger:

```text
RETAIN      — transferred without semantic change;
MERGE       — preserved inside a broader current contract;
SUPERSEDE   — intentionally replaced by Architecture/Implementation;
DEFER       — valuable but belongs to a later capability layer;
REJECT      — obsolete, contradictory or overengineered;
UNKNOWN     — cannot be decided before code/data audit or experiment.
```

Rules:

```text
Architecture wins every semantic conflict;
Implementation wins concrete conflicts after its corresponding contract is accepted;
old text never remains normative merely because it is more detailed;
RETAIN/MERGE require a live owning I-section or a current ContractCatalogueEntry; a cold inventory may only point to that owner;
SUPERSEDE/REJECT require a reason;
UNKNOWN blocks deletion of the donor section, not unrelated development;
no donor file is deleted until the donor migration audit has zero unresolved load-bearing items and the I19 retirement proof passes.
```

Useful exact semantics are preserved in an owning I-section and, when a concrete schema is needed, in the contract catalogue/IDL. Historical manual inventories remain cold evidence and never become an active schema source. Historical work packages, giant test matrices, obsolete phase gates and addendum precedence are not imported as current requirements.

Retirement has five independent proof classes:

```text
P1 syntactic inventory
   every supplied heading, named object and explicit rule has a disposition;

P2 semantic preservation
   each load-bearing item names current owner, behavior, failure behavior and proof,
   or an explicit supersession/rejection/defer rationale;

P3 active-reference migration
   repository source, tests, schemas, Skills, prompts, configs, CI and generated artifacts
   no longer use donor prose as active authority;

P4 runtime/data migration
   persisted records, live integrations, installed agents and reports no longer depend on
   donor paths or obsolete semantics;

P5 recovery and owner cutover
   exact archive restores, new pair is installed and discoverable, active authority contract
   points to it, and System/Architecture Owner approves retirement.
```

`P1/P2 PASS` does not imply `P3–P5 PASS`. Broad chapter mapping or identifier occurrence is navigation evidence, not proof of semantic preservation.

Audit status is always qualified by class:

```text
INVENTORY_COMPLETE       — supplied source units were enumerated;
SEMANTIC_REVIEWED        — independent ideas received owner/rationale/falsifier review;
DOCUMENT_CONFORMANT      — current Architecture/Implementation bytes have no known document contradiction in the stated scope;
SOURCE_VERIFIED          — exact code/schema/config identity implements the claim;
RUNTIME_VERIFIED         — the exact installed generation produced executed evidence;
PRODUCT_VERIFIED         — the declared user/product property passed its evaluation plan.
```

Unqualified `PASS`, heading counts, keyword coverage, generated manifests or auditor confidence cannot be promoted across these classes. Every audit claim names exact bytes, scope, blind spots and invalidation conditions.

