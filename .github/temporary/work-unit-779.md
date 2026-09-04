# Assignment reservation

Owning issue: #779
Implementation PR: #780
Branch: `work/779-kernel-dreamer-store-client`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: Dreamer ledger methods in `eliot-kernel-service` Store client/gateway, exact correlated response support, minimal exports, focused tests, and this temporary marker. Implement every corrected #773 operation with fresh per-call RequestIdentity, exact capability/fence/state/revision/lease/checkpoint correlation, one EBP call, truthful receipt validation and original-operation reconciliation.

No local job map/state machine/scheduler/retry, Store ownership, Kernel front door, Dreamer semantics, candidate application or task finish. Issue #779 and its corrected Kernel→Store comment are normative. Remove this marker before ready.
