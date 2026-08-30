### I10.8.1. Purpose and ownership

Instrument Plane is the deterministic grounding fabric for development and verification:

```text
Human/Main Agent judgment
→ ELIOT task, authority and context
→ InstrumentProfileResolver
→ InstrumentRunner (control/aggregation)
→ TestExecutionPlane
→ isolated `eliot-testd`
→ one Windows ProcessExecutor semantics
→ exact tools / simulator / component builder
→ EvidenceEnvelope + VerificationReceipt
→ verifier, CodeCortex, Diagnostic Brief and Active View.
```

Canonical ownership:

| Concern | Owner | Forbidden alternative |
|---|---|---|
| tasks, acceptance, leases and finish | Governor | instrument-local task DB or tool self-certification |
| process-launch semantics | `eliot-process-windows` contract/reference implementation; each Kernel/testd/UserBroker supervisor owns its operations/tree | module-specific `Command::new` semantics or a global executor that steals lifecycle ownership |
| instrument definitions/profiles | Instrument Registry | duplicated command maps in PatchRunner/Justfile/CI |
| raw evidence | Blob Store + canonical handles | source-repository log files as authority |
| package graph | Cargo metadata instrument | guessed package relations |
| Rust symbol semantics | admitted rust-analyzer/SCIP backend | regex as primary semantic engine |
| heuristic architecture graph | quarantined/admitted graph adapter | source-of-truth or write authority |
| evidence fusion | CodeCortex compositor | model-written summary as authority |

Instrument Plane has no LLM, memory owner, scheduler or architecture authority. It may invoke deterministic tools only through typed profiles admitted by Governor.

