## I10.17. Adapter subsystem

Adapter classes:

```text
truth adapter;
verifier adapter;
code/dependency adapter;
artifact/professional-tool adapter;
provider-memory feed;
external-agent adapter;
research acquisition adapter;
notification/surface adapter.
```

Common contract:

```yaml
AdapterManifest:
  adapter_id_and_version:
  capabilities:
  input_output_schemas:
  truth_or_effect_semantics:
  required_permissions_and_data_classes:
  timeout_cancellation_idempotency:
  health_readiness_freshness:
  failure_translation:
  evidence_and_receipt_rules:
  compatibility_and_removal:
```

`AdapterSupervisor` owns the adapter reconciliation loop: it reads desired state from the Module Catalog, interprets health observations, applies circuit/restart policy and proposes lifecycle actions. It does not own a second desired-state store or the Capability Registry. Kernel owns physical process lifecycle, Job Objects, the Generation Registry, generation routing and fencing; Governor owns Module Catalog transitions and Capability Registry evidence. AdapterSupervisor does not decide semantic truth.


Each adapter has an independent runtime state:

```text
per-adapter semaphore and queue;
health/readiness/freshness;
circuit and restart budget;
current generation and in-flight requests;
resource and output limits.
```

A separate system-wide semaphore/ResourceArbiter limits aggregate load. The global limit never increases an adapter's own declared concurrency. Short service adapters use `AdapterManifest`; long-running compiler/test/index/runtime instruments use `InstrumentSpec` and InstrumentRunner rather than stretching one generic timeout/output contract.

Selection order prefers:

```text
exact/direct competent source;
registered local deterministic adapter;
existing warm supervised process;
bounded external route;
model synthesis only when interpretation is actually required.
```

### Baseline adapter capability registry

The first implementation preserves the useful exact routes from the former Governor without requiring their old class names:

| Legacy capability/name | Current adapter/module capability | Default lifecycle | Fallback |
|---|---|---|---|
| `GitStateAdapter` | `workspace.git_state` | built-in/platform or warm bridge | filesystem generation; mark Git facts unavailable |
| `FilesystemMetadataAdapter` | `workspace.fs_metadata` | built-in platform facade | direct bounded stat/read |
| `Process/ServiceHealthAdapter` | `runtime.process_health`, `runtime.service_health` | Watchdog/platform sensor | visible unknown/degraded; no invented health |
| `RipgrepAdapter` | `code.exact_text_search` | lazy process/module | bounded native search alternative |
| `AstGrepAdapter` | `code.structural_search` | lazy module | exact text/LSP; structural claim remains unavailable |
| `CodeGraphAdapter` | `code.graph_query` | shared warm process module | exact file/symbol/LSP route |
| `LspAdapter` | `code.definition_reference_diagnostic` | shared/lazy project module | code graph/exact source reads |
| `DiagnosticsAdapter` | `diagnostic.collect_normalize` | project/tool module | verifier/tool output capture |
| `DomainApiAdapter` | `domain.api_truth` | WorkScope-selected optional module | docs/direct probe/unknown |
| `DocumentationAdapter` | `source.document_exact` | Researcher or bounded source bridge | source unavailable/unknown |
| `VerifierMapAdapter` | `verification.registry_query` | Governor projection over Capability Registry | explicit missing verifier |
| `ArtifactVerifierAdapter` | `artifact.evaluate` | scoped professional/verifier module | deterministic partial checks or degraded proof |
| `ExternalAgentAdapter` | `agent.external_job` | transient supervised bridge | alternate route/defer |
| `ProviderMemoryAdapter` | `memory.provider_feed` | lazy read-only feed | ELIOT canonical memory remains authoritative owner |

Execution rules for every process/CLI adapter:

```text
construct executable and argv separately; never interpolate a shell command by default;
set explicit cwd and environment allowlist;
bind process to a Job Object/resource profile;
stream bounded stdout/stderr overflow to Blob Store;
kill the owned process tree on deadline/cancellation;
record exact version, input hash, duration, exit/protocol status and raw-output handle;
preserve path/symbol/range identity where the capability provides it;
never expose secrets in argv, logs or returned prose;
never write canonical state directly;
never invoke a model implicitly from a deterministic adapter contract.
```

Transport failure, semantic `no results`, stale index and unsupported capability are distinct outcomes; only transport/integrity failures count toward the circuit breaker.

