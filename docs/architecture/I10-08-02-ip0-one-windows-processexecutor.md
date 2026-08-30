### I10.8.2. IP0 — one Windows ProcessExecutor

All governed external processes use one public facade and one audited Windows semantic implementation. This means one contract/reference code path, **not** one global executor process, thread or mutable operation owner. Kernel owns daemon/module generations, `eliot-testd` owns its build/test descendants, User Broker owns interactive-user descendants, and an admitted module supervisor may own its isolated workers; each uses the same `eliot-process-windows` implementation and evidence format. This section owns the normative behavior. `docs/generated/rust-boundary-interfaces.md` §P.12 preserves one bootstrap **candidate Rust mapping** and is not a second contract owner or proof of source support. The semantic operations are `start`, `inspect`, `cancel` and `reconcile`; `start` receives a governed evidence sink. Only a future interface generated from the admitted catalogue and matched to exact source/API evidence may become an implementation-admission input.

The production Windows implementation is backed by the audited `eliot-windows-ipc` process guardian and provides:

```text
CreateProcessW with explicit executable/argv/env/cwd;
suspended launch and Job Object assignment before resume;
process, image and signer/hash identity;
parent/child/grandchild observation;
concurrent streaming stdout/stderr drain;
wall, idle, memory, CPU and process-count limits;
cancellation with explicit cleanup result;
completion-port lifecycle events;
raw stream storage and bounded previews;
no-orphan outcome or explicit cleanup failure.
```

Every governed launch carries a Kernel-issued `DispatchPermit` inside `ProcessRequest`:

```yaml
DispatchPermit:
  operation_id:
  action_lease_ref:
  state_fence:
  authority_and_generation_epoch:
  expected_revision_heads:
  executable_environment_and_effect_digest:
  expires_at:
  one_shot_nonce:
```

The Windows executor creates the process suspended, assigns the Job Object, resolves the actual image identity, and then asks Kernel to validate the permit against the current fence/epochs/revision heads **before `ResumeThread`**. `ProcessStartReceipt` binds the permit digest, validation revision, actual process/image/Job identity and resume time. Missing/expired/mismatched permits return `DISPATCH_PERMIT_REQUIRED`, `STALE_STATE_FENCE` or `STALE_AUTHORITY_EPOCH`; a child is never resumed on a stale pre-launch check.

The Kernel round trip applies at the authority/process-tree boundary, not to every descendant spawned by Cargo, a browser or another already admitted tool. Descendants remain inside the admitted Job Object/resource/effect envelope and are observed as lineage; an unexpected escape or effect is a failure.

For a deterministic multi-stage `TestdJob` or equivalent profile, Kernel activates one immutable `ProcessExecutionGrant` covering the exact profile DAG, executable allowlist, environment, resource envelope, State Fence and expiry. The owning testd/module supervisor may derive one-shot stage nonces under that grant without contacting Kernel for every compiler/test command; it cannot change executable class, effects, roots or budget. Revocation/epoch change invalidates unused stage nonces and stops new stages. Thus control remains explicit without turning Kernel into a per-process scheduling bottleneck.


Direct `std::process::Command`, `tokio::process::Command` or shell launch is forbidden outside:

```text
minimal bootstrapping needed to start Host/Kernel;
ProcessExecutor implementation;
test-only fixtures explicitly marked as such.
```

`clippy.toml` / workspace lint uses `disallowed-methods` for direct process-spawn APIs outside the allowlist, supplemented by source audit for aliases/wrappers. Process failure never becomes a product/test verdict until an instrument parser interprets the exact outcome.

