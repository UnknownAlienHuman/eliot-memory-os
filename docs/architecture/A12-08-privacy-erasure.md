## A12.8. Privacy Erasure

Privacy erasure is a separate governed process. Within technical and legal limits, it propagates to canonical payload, projections, indexes, Operational Recovery State, Route Continuation State, provider-side copies, backups, and the restore path.

The purge ledger preserves a non-revealing record and deletion scope without reconstructing the content. Restore applies the purge ledger before cutover.

**ARCH-PRIV-01 — Erasure removes future availability without rewriting unrelated history.** Deletion cannot be replaced by suppression, and erased content cannot be resurrected from backup.

---
