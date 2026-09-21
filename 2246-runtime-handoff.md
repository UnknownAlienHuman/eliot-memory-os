# 2246 runtime handoff — process-origin production join (for root integration)

Owner: leaf worker for `bins/eliotd/src/process_origin.rs` (PR #2246, issue #1960).
Not edited here: `bins/eliotd/src/lib.rs` (GOVERNOR worker34752),
`bins/eliotd/src/daemon_runtime.rs`, Kernel/src, Host/worker files.

## 1. Verified production-caller state (actual source, 2026-09-21)

Repo-wide search for `gate_process_control|prepare_kernel_forward|GovernedKernelAuthority`
outside `bins/eliotd/src/process_origin.rs` and the `lib.rs` re-export returns
zero hits. `bins/eliotd/src/daemon_runtime.rs` contains zero
`process_origin|ProcessOrigin|gate_process|OwnershipChallenge|OperationDisposition|KernelAuthorization`
references. The prepared PR exports the API but wires no production caller:
a public helper with only test callers is not runtime integration.

## 2. Exact public contract to join (read from `bins/eliotd/src/process_origin.rs`)

```rust
pub fn gate_process_control(
    evidence: &ProcessOriginEvidence,
    operation: ProcessControlOperation,
) -> OperationDisposition;

pub fn prepare_kernel_forward(
    evidence: &ProcessOriginEvidence,
    operation: ProcessControlOperation,
    challenge: Option<&OwnershipChallengeReceipt>,
) -> Result<KernelForwardRequest, ProcessOriginError>;

impl GovernedKernelAuthority {
    pub fn bootstrap(issuer_id: String, key: &KernelChallengeKey)
        -> Result<Self, ProcessOriginError>;
    pub fn issue_challenge(
        &mut self,
        evidence: &ProcessOriginEvidence,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<OwnershipChallengeReceipt, ProcessOriginError>;
    pub fn revoke_challenge(&mut self, challenge_id: &str)
        -> Result<(), ProcessOriginError>;
    pub fn decide_forward(
        &self,
        request: &KernelForwardRequest,
        now_unix_ms: u64,
    ) -> Result<KernelAuthorization, ProcessOriginError>;
    pub fn authorize_shutdown(
        &self,
        evidence: &ProcessOriginEvidence,
        challenge: &OwnershipChallengeReceipt,
        now_unix_ms: u64,
    ) -> Result<KernelAuthorization, ProcessOriginError>;
}
```

Re-exported unchanged from `bins/eliotd/src/lib.rs` (prepared 8-line delta,
all 18 public items covered — no additional export hunk needed):

```rust
pub use process_origin::{
    CapabilityEvidenceSource, CapabilityEvidenceStatus, GovernedKernelAuthority,
    KernelAuthorization, KernelChallengeKey, KernelForwardRequest, OperationDisposition,
    OwnershipChallengeIssuer, OwnershipChallengeReceipt, PROCESS_ORIGIN_CAPABILITY,
    ProcessCapabilityEvidence, ProcessControlOperation, ProcessOriginError, ProcessOriginEvidence,
    ProcessStatusReceipt, canonical_origin_digest, gate_process_control, prepare_kernel_forward,
};
```

Key provisioning constraint (exact, not guessed): `KernelChallengeKey::from_secret`
is `pub(crate)` and `OwnershipChallengeIssuer::kernel_minted` is `pub(crate)`;
only crate-internal `eliotd` wiring holding the provisioned secret can mint a
key/issuer. The public path is `GovernedKernelAuthority::bootstrap` with that
key. `KernelAuthorization` has private fields, no public constructor, no
`Deserialize` — only `decide_forward`/`authorize_shutdown` can mint it.

## 3. Proposed callsite hunk (root/Governor to place — NOT applied here)

Suggested join point, following the existing `note_owner_session_binding` /
`context_read_client` precedent (caller holding both the concrete
`DaemonKernelClient` and `DaemonComposition` threads clients per call, composition
retains no client/thread): in `bins/eliotd/src/daemon_runtime.rs` at the single
place where the concrete client and composition meet, after authenticated
connect+start:

```rust
// Proposed (root-owned files only): bootstrap once from the Kernel-provisioned
// secret held by crate-internal eliotd wiring; retain the authority alongside
// the composition (same retention pattern as `owner_session: Option<…>`).
// Per control request against an observed origin:
//   1. gate_process_control(&evidence, op)
//      → Observed: answer from evidence, never forward.
//      → NeedsKernelDecision { .. }: continue.
//      → Denied { .. }: fail closed.
//   2. prepare_kernel_forward(&evidence, op, Some(&challenge))?  // completeness only
//   3. authority.decide_forward(&request, now)?                  // exclusive authority
//      → KernelAuthorization proof token attached to the neutral authenticated
//        Kernel port call. Observe-only ops (ReadStatus/ProbeObserve) are never
//        forwarded (ObserveOnly); ProcessStatusReceipt has no overload and can
//        never substitute for OwnershipChallengeReceipt.
```

Open decisions for root/Governor/Kernel owners: (a) where the Kernel-held 32-byte
secret is provisioned into crate-internal `eliotd` wiring (required before
`bootstrap` is callable in production); (b) which daemon operation first needs
process control (today no `std::process`/kill/adopt callsite exists in
`daemon_runtime.rs`); (c) whether the Kernel front-door grant route (T6/#15)
carries the `KernelAuthorization` token or a separate opcode.

## 4. Bounded-owner completion

`bins/eliotd/src/process_origin.rs` unchanged from prepared work (reworks
`b4e73def`/`076ae935`/`461106aa` + clean merge `460ef7b7`): 8/8 focused tests
pass, `cargo fmt -p eliotd --check` clean, no `process_origin` clippy warnings.
States kept distinct: `Observed` vs `NeedsKernelDecision` vs `Denied`;
`ProcessOriginEvidence` vs `ProcessStatusReceipt` vs `OwnershipChallengeReceipt`
vs `KernelAuthorization`. No production semantics added to the composition
surface from this lane.
