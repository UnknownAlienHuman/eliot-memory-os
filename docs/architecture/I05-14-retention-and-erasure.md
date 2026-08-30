## I5.14. Retention and erasure

Privacy erase operation enumerates:

```text
canonical payload;
derived projections/indexes;
blob store;
ORS pending copies;
backup catalog and future restore path;
Route Continuation State;
provider-side data when API supports deletion.
```

Evidence handles expose one closed availability axis, orthogonal to epistemic status, execution/evaluation and source admissibility:

```text
EvidenceHandleAvailability:
  LIVE | STALE | COLD_RESTORABLE | REDACTED | RETENTION_BLOCKED | BROKEN_INTEGRITY
```

These are not all terminal states. `STALE` may be revalidated, `COLD_RESTORABLE` may be restored through a qualified path, and the retention-blocked state records a hold/policy reference plus next review or expiry while ordinary use remains unavailable where policy permits. `REDACTED` returns no deleted content—only a non-revealing tombstone/purge reference. It is not `BROKEN_INTEGRITY` and cannot be silently substituted by a summary, cached excerpt or other derivative. `BROKEN_INTEGRITY` means required bytes/digest lineage cannot be proven and never masquerades as privacy erasure.

Erasure produces purge receipt and non-revealing tombstone/digest when policy permits. Restore refuses to resurrect purged payload.

---

