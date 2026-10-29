# Store source ownership

The Store package owns executable schema, migration wrapper and fixed query bytes.
[Implementation §4–7](../IMPLEMENTATION.md#4-migration-0001-and-schema-authority) owns
the contract; [the existing D4 findings](../ANALYSIS-REGISTRY.md#store-reconciliation)
own unresolved work. This directory is navigation, not a second executable SQL pack.

## Source candidate, not a working Store

The current review target is
[PR #5327](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/5327), owned by
[issue #5326](https://github.com/UnknownAlienHuman/eliot-memory-os/issues/5326):

- [Schema package at c5154b0](https://github.com/UnknownAlienHuman/eliot-memory-os/tree/c5154b0ea352980279cd0d46ca3353148d4c8027/crates/storage/eliot-v3-store-schema)
  owns DDL, one wrapper, source catalog metadata and their digests.
- [Fixed queries](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c5154b0ea352980279cd0d46ca3353148d4c8027/crates/storage/eliot-v3-store-schema/src/queries.rs)
  are source fragments, not complete capture/revision/job operations or a connected client.

That PR is separate and unmerged at this review. Naming its package as the sole asset
owner does not approve its current bytes. Imports, unsupported FOR UPDATE targets,
byte budgets, representations, claim-time freeze, catalog evidence and full transaction/
readback remain recorded defects. Correct them in the owning source task; do not copy
its files into the documentation branch or create a third schema/query catalogue.

## Retired design inputs

The former [migration](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c2b7402c3fedc51ccb3fb881173e028ffcbdac44/docs/v3/store/0001-base.surql)
and [query pack](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/c2b7402c3fedc51ccb3fb881173e028ffcbdac44/docs/v3/store/queries-base.surql)
remain available at that exact historical revision. They were never qualified runtime
assets. Their enum/history/wrapper differences are dispositions to reconcile, not two
equally current formats. Do not restore or dynamically load them as a fallback.

## Next source increment

Follow [Implementation §11](../IMPLEMENTATION.md#11-implementation-sequence), not the old
all-in-one Slice 0 checklist. First connect the actual Store admission and one complete
capture/open path with finite input/result bounds, exact identity and unknown readback.
Select only statements used by that path; keep unimplemented operations unavailable.

Rust compile/Clippy checks source; exact-engine execution checks the selected DDL/query
and DTO boundary; restart/readback checks the connected behavior. One does not imply
the others. Add broader rollback/concurrency/platform/load coverage after the connected
product in the owner's development order. No successful local compiler, SurrealDB or
Windows run is claimed by this documentation change.
