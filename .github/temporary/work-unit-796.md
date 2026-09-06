# Assignment reservation

Owning issue: #796
Implementation PR: #797
Branch: `work/796-reactive-context-protocol`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope:
- `crates/foundation/eliot-protocol/src/reactive_context.rs`
- minimal module/re-export lines in `crates/foundation/eliot-protocol/src/lib.rs`
- `crates/foundation/eliot-protocol/tests/reactive_context.rs`
- this temporary marker

Define one closed typed outbound reactive-Context payload and acknowledgement-binding specialization over the existing generic `EventEnvelope`, `EventAckReceipt` and `AckPhase`. Bind exact planner/view/admission/assembly/measurement/task/attempt/session/generation/scope/fence/payload/sequence/deadline identities without importing Smart crates.

Keep planned, enqueued, attempted, unknown, delivered, acknowledged, visible, selected, used, outcome and benefit structurally distinct. Forbidden: a second generic event/ack protocol, durable queue, transport, retry, Context planning/admission/assembly, active-view mutation, authority/effect/use/outcome/finish state, root workspace/lockfile, workflows or docs.

Issue #796 is the complete execution contract. Remove this marker before ready.
