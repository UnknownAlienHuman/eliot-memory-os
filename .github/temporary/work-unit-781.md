# Assignment reservation

Owning issue: #781
Implementation PR: #782
Branch: `work/781-kernel-dreamer-front-door`
Base revision: `182a335beba34fc93bd910479de388717ed45ad9`

Exclusive scope: typed Dreamer requester/worker dispatch in `bins/eliot-kernel`, exact classifier/action/main composition lines, package manifest/tests, and this temporary marker. Expose structurally separate requester Submit/Status/RequestCancel/Reconcile and current-worker Lease/Renew/Start/Checkpoint/Resume/BeginVerification/PublishOutcome/Status/Reconcile capabilities over corrected #769/#779.

No local ledger/queue/state machine/scheduler/retry, process/model launch, Store client duplication, A-03 semantic interpretation, candidate application, authority/effect or task finish. Successful Submit proves queued work only; demand-start remains an external owner/handoff. Issue #781 and its role-separated correction are normative. Remove this marker before ready.
