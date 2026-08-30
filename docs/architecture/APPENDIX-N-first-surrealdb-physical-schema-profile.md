# Appendix N. First SurrealDB physical schema profile

> **Projection lifecycle label (artifact-local):** `BOOTSTRAP_RETAINED_PHYSICAL_PROFILE`. **Projected I0.5 support/evidence:** `TARGET` / `NOT_EXECUTED`. **Runtime load policy:** `DOCUMENTATION_ONLY`; the companion `store/schema.generated.sql` policy is `MUST_NOT_APPLY`. The detailed active documentation profile is `docs/generated/surrealdb-physical-schema-profile.md`, including post-integration logical-to-physical ownership mapping. `store/schema.generated.sql` is an intentional rejection sentinel until a real migration/catalogue generator emits executable schema with checksums and proof.

Owners: I5.4–I5.7, I5.17 and the migration role. Manifest: `docs/generated/PROJECTION_MANIFEST.json`. Exact historical source: `_REVIEW/baseline_sections/Appendix_N.md`.

Rules that remain normative here:

```text
only the migration role changes physical schema and only the store bridge holds credentials;
stable fields use generated constraints; flexible payloads require versioned codecs and round-trip/property proof;
large bodies remain in Blob Store and projections/indexes remain explicitly rebuildable;
runtime access uses named parameterized operations produced from PreparedTransition;
no agent-visible operation names a table or field;
additive migration precedes backfill and destructive retirement;
backfill is a checkpointed Durable Job with shadow compatibility and rollback evidence;
old representation retires only after no active or rollback generation requires it;
ECXF export and canonical record identity remain independent of table layout;
the sentinel file must never be applied as DDL.
```

---

