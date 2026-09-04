# Assignment reservation

Owning issue: #798
Implementation PR: #799
Branch: `work/798-reactive-context-host-delivery`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope:
- `crates/kernel/eliot-host-service/src/reactive_context_delivery.rs`
- minimal module/re-export lines in `crates/kernel/eliot-host-service/src/lib.rs`
- `crates/kernel/eliot-host-service/tests/reactive_context_delivery.rs`
- package manifest only for direct existing dependencies on #796/#800 owners
- this temporary marker

Required predecessors:
- B-RCTX-C0 #796 / PR #797
- B-RCTX-S1 #800 / PR #801

Implement Host-owned delivery orchestration over the injected #800 queue port and one narrow transport port. Require committed enqueue and send-requested receipts before transport, preserve not-attempted versus possible delivery, reconcile unknown outcomes under the same operation identity, validate exact #796 acknowledgements, and rehydrate/drain from durable queue state.

This package does not own queue bytes, concrete OS/agent transport, active Context, visibility/use/outcome evidence or later Learning assessment. Delivered, acknowledged, visible, selected, used, outcome and benefit remain distinct. The concrete Host composition/transport adapter is a separate unresolved integration owner and must not be absorbed here without a new exclusive work unit.

Issue #798 is the complete execution contract. Remove this marker before ready.
