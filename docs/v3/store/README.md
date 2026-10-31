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

Use the contracts on current `main`. The root first reconciles that baseline into
the existing open source PR; the package has one writer, not a new competing branch.
Pinned links above identify the inspected original assets, not a frozen implementation
base. Inspect the live head and preserve changes made since that observation.

The immediate #5326 assignment is **asset-package repair**, not all of Slice 0:

1. Correct the missing constant imports in `src/queries.rs`, format the package and
   run its [package-local checks](../DEVELOPMENT.md#rust-source). Report actual failures;
   a compile fix does not close the remaining schema/semantic findings.
2. Align DDL, fixed statements/projections, validators, catalog and digests with
   [R-174 and R-182–R-188](../ANALYSIS-REGISTRY.md#store-reconciliation). The selected
   representations are in Implementation §4.7; do not invent aliases. Choose concrete
   per-operation byte caps with the encoder/decoder, not a blanket larger limit.
3. Publish the corrected asset increment with exact-engine/catalog gaps still named.
   `inspect` validates embedded assets; it does not establish a working Store.

The **next connected runtime assignment** follows
[Implementation §11](../IMPLEMENTATION.md#11-implementation-sequence): actual Store
admission, one bounded client and a complete capture/open path with unknown-outcome
readback. Select only the statements used by that path. It does not wait for inference
or the full backup campaign, and absent operations remain unavailable rather than stubs.

Rust compile/Clippy checks source; exact-engine execution checks the selected DDL/query
and DTO boundary; restart/readback checks the connected behavior. One does not imply
the others. Add broader rollback/concurrency/platform/load coverage after the connected
product in the owner's development order. No successful local compiler, SurrealDB or
Windows run is claimed by this documentation change.
