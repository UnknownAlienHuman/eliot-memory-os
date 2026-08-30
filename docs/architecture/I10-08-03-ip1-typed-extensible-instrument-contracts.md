### I10.8.3. IP1 — typed, extensible instrument contracts

Executable authority comes from an admitted `InstrumentSpec`, never from model-authored command text. The stable core distinguishes a small semantic class from a replaceable concrete kind:

```rust
pub enum InstrumentClass {
    SourceIdentity,
    Compiler,
    Test,
    SemanticIndex,
    HeuristicAnalysis,
    RuntimeDiagnostic,
    SecurityDependency,
    Concurrency,
    UnsafeFfi,
    Performance,
}

pub struct InstrumentSpec {
    pub kind_id: InstrumentKindId,          // opaque, versioned identifier
    pub class: InstrumentClass,
    pub executable: ExecutableRef,
    pub invocation_schema_ref: SchemaRef,
    pub fixed_or_validated_arguments: Vec<OsString>,
    pub environment_profile: EnvironmentProfileId,
    pub parser_id: ParserId,
    pub timeout_policy: TimeoutPolicy,
    pub resource_limits: ResourceLimits,
    pub authority_class: EvidenceAuthorityClass,
    pub negative_result_contract: NegativeResultContract,
    pub network_policy: NetworkPolicy,
    pub credential_policy: CredentialPolicy,
}
```

Built-in kinds are registered initially:

```text
cargo-metadata; cargo-clippy; rustfmt-check;
nextest-list; nextest-run; rust-analyzer-scip; ripgrep-json;
codebase-memory-index; codebase-memory-query;
cargo-llvm-cov; cargo-mutants; cargo-deny; cargo-hack; cargo-shear;
loom-test; shuttle-test; turmoil-sim; madsim-sim; eliot-sim-replay;
miri-test; cargo-careful; cargo-fuzz;
component-build-wasip2; component-inspect; component-conformance; component-shadow-compare;
criterion-bench; hyperfine-bench;
windows-etw-capture; windows-procdump; windows-process-scenario.
```

A new kind does not require changing Kernel or the semantic class enum. It is admitted through a versioned Module/Instrument manifest with:

```text
exact executable identity and supply-chain receipt;
argument schema and fixed command template;
parser generation;
environment/resource/credential policy;
evidence authority, freshness and coverage semantics;
negative-result contract;
golden and process-fault suite;
removal and replacement boundary.
```

Unregistered kind IDs, arbitrary shell text and agent-supplied executable/argv combinations fail before launch. Dynamic extensibility therefore does not become arbitrary command execution. Parser and profile generations can be replaced independently through normal Module/daemon cutover; no Rust DLL ABI is introduced.

Generic short adapters and long-running instruments remain different contracts. Each adapter/instrument has its own semaphore and circuit state; a system-wide resource pool never overrides the module's declared maximum concurrency.

