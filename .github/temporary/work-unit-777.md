# Assignment reservation

Owning issue: #777
Implementation PR: #778
Branch: `work/777-dreamer-store-wire`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: exact Dreamer-ledger dispatch arms in `bins/eliot-store-surreal/src/request_dispatch.rs`, minimal Store composition delegation, focused package tests/manifest wiring, and this temporary marker. Expose every corrected #773 typed operation exactly once after #775, preserve record/event/receipt and Store unknown-commit semantics, and advertise only implemented least-privilege capabilities.

No string/generic JSON route, local queue/state machine/retry, semantic inspection, Store API/adapter mutation, Kernel/Dreamer, authority/effect or task finish. Issue #777 and its corrected Store-wire comment are normative. Remove this marker before ready.
