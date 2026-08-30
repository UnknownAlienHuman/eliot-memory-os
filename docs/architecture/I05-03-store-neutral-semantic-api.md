## I5.3. Store-neutral semantic API

### Semantic command families (summary; activation rules are in I5.17)

```text
capture/source observation;
task/WorkScope/plan state;
epistemic revision, conflict and attention;
canonical transition and receipt;
instrument, verification and finish;
authority, lease, capability and external effect;
session, attempt, coordination and integration;
module/config/lifecycle and recovery;
audit/telemetry evidence.
```

Exact executable variants exist only in an admitted contract catalogue bound to the current normative-pair receipt. Bootstrap retained projections under `docs/generated/` preserve design coverage but remain `ImplementationSupport = TARGET` with `EvidenceExecutionStatus = NOT_EXECUTED`; they cannot create a command, handler or public surface.

### Named reads (summary; physical/query profile is defined by I5.20 and Appendix N)

```text
GetRevisionHeads
GetScopeRevisionView
GetTaskState
GetCurrentEpistemicPosition
GetEvidencePack
GetUnderstandingProjectionInputs
GetAttentionAndProblems
GetModuleCatalogState
GetCapabilityEvidenceState
GetConformanceState
GetMailbox
GetAuditRange
ResolveWriteReceipt
```

No command contains a raw query string.

`GetGenerationRegistryView`, active Session/User Broker bindings, ORS operation state and live process health are Kernel/control reads, not canonical-store named reads. `CapabilityRegistryView` is composed by Governor from canonical manifests/evidence plus Kernel Generation Registry, current health, policy and Watchdog supervision; the store supplies only `GetCapabilityEvidenceState`. A store implementation therefore cannot become the owner of active process state or current capability admission.

