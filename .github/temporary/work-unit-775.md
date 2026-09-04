# Assignment reservation

Owning issue: #775
Implementation PR: #776
Branch: `work/775-dreamer-surreal-ledger`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: the Dreamer ledger implementation/tests in `eliot-store-surreal-adapter`, minimal adapter exports/error projection, conditional existing-ledger schema/readiness migration when proven necessary, and this temporary marker. Implement every corrected #773 submit/lease/renew/transition/cancel-request/status/list/reconcile operation with one Surreal transaction for record + event + idempotency + receipt.

No second ledger/table/state machine, Smart semantic inspection, Store process/Kernel/Dreamer, scheduler/retry, candidate application or task finish. Issue #775 and its canonical-lifecycle correction comment are normative. Remove this marker before ready.
