# Assignment reservation

Owning issue: #769
Implementation PR: #770
Branch: `work/769-dreamer-kernel-wire`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: `crates/foundation/eliot-protocol/src/dreamer_job.rs`, minimal protocol exports, focused protocol tests, and this temporary marker. Define owner-neutral requester/controller and Dreamer-worker control over the exact I14.20 DurableJob lifecycle:

`NOT_STARTED → QUEUED → LEASED → RUNNING ↔ CHECKPOINTED → VERIFYING → COMPLETED | PARTIAL | FAILED | CANCELLED | UNKNOWN_OUTCOME`.

A-03 semantics remain opaque. Store mutation unknown commit remains separate from semantic job outcome. No Kernel/Store/Dreamer implementation, process/model launch, candidate application, authority/effect or task finish. Issue #769 is the complete corrected contract. Remove this marker before ready.
