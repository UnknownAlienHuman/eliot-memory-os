# Assignment reservation

Owning issue: #800
Implementation PR: #801
Branch: `work/800-reactive-context-host-state`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope:
- `crates/kernel/eliot-host-state/**`
- this temporary marker

Required predecessor: B-RCTX-C0 #796 / PR #797.
Required consumer: B-RCTX-H1 #798 / PR #799.

Implement the single Host-local durable reactive-Context queue inside the existing HostState journal. Own queue bytes, per-attempt stream/sequence state, expected-revision compare-and-transition, idempotency, immutable receipts, bounded snapshots, replay, recovery and compaction. Reuse #796 typed event/ack identities and expose the lower-level `ReactiveContextQueuePort` consumed by Host service.

Forbidden: a second journal/database/sidecar/in-memory production queue, endpoint resolution, transport send/retry, active Context mutation, visibility/use/outcome inference, authority/effect/finish, protocol/Host-service/bin/platform changes, root workspace/lockfile, workflows or docs.

Issue #800 is the complete execution contract. Remove this marker before ready.
