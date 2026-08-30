## I19.13. Donor contract extraction

The authoritative non-normative donor-retirement ledger is content-addressed and bound to exact Architecture, Implementation and donor digests.

A donor item is not considered preserved because its name appears in the new book or because a whole old chapter points to `I0–I20`. For each load-bearing item the retirement ledger records:

```text
source heading/object and exact donor digest;
semantic obligation;
current owner;
current contract/mechanism;
failure behavior;
observable proof;
disposition and rationale;
active-reference/runtime migration status.
```

Before deleting old documentation:

```text
1. Freeze exact source bytes and digests.
2. Inventory every heading, named object, principle, state machine, profile, scenario and unique identifier.
3. Give every load-bearing item exactly one disposition: RETAIN, MERGE, SUPERSEDE, DEFER, REJECT or UNKNOWN.
4. RETAIN/MERGE require an active target with owner, behavior, failure behavior and proof; a chapter-level pointer is insufficient.
5. SUPERSEDE/REJECT record the current conflicting decision and rationale.
6. DEFER preserves the complete unique obligation in an owned Research Gate/backlog artifact; the donor file may not remain its only specification.
7. Verify every Architecture anchor against Implementation owner, mechanism, failure behavior and observable proof.
8. Perform active-reference scans over repository source, tests, schemas, Skills, prompts, configs, CI, generated files and installation manifests.
9. Inspect live schema/data/tasks/integrations for donor paths, obsolete statuses and old authority semantics.
10. Migrate active references; historical citations use an immutable archived URI and digest.
11. Build and restore the archive; compare every source digest.
12. Record explicit System/Architecture Owner cutover approval.
```

The evidence levels are reported separately:

```text
DOCUMENT_INVENTORY_READY;
DOCUMENT_SEMANTICS_READY;
REPOSITORY_REFERENCE_READY;
RUNTIME_DATA_READY;
RECOVERY_ARCHIVE_READY;
AUTHORITY_CUTOVER_READY;
PHYSICAL_DELETION_READY.
```

No lower level implies a higher one.

