# Assignment reservation

Owning issue: #773
Implementation PR: #774
Branch: `work/773-dreamer-store-ledger-contract`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: the Store-neutral Dreamer ledger contract/module, exact Store wire/client variants, focused Store API tests, minimal exports, and this temporary marker. Reuse corrected #769 and the canonical I14.20 lifecycle. Store owns durable bytes, CAS/revision/event/idempotency/receipt/recovery; A-03 semantic input/result remains opaque.

No adapter/process/Kernel/Dreamer implementation, private `Claimed`/`CandidateReady`/`ReconciliationRequired` states, generic patch/query/write, candidate application, authority/effect or task finish. Issue #773 is the complete corrected contract. Remove this marker before ready.
