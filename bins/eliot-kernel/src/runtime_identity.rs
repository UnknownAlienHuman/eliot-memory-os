//! Kernel runtime identity derivation.
//!
//! Immutable runtime and launch identity derivation only. Owns exactly
//! `observed_session_principal_binding`, `eliotd_launch_attempt_identity`,
//! `eliotd_operation_id`, `fresh_eliotd_launch_descriptor`, and
//! `stable_owner_principal_digest`.
//!
//! Architecture: A12.2 Principal, Session и visibility; A12.3 Один governed write path; A13.2 Kernel и failure domains; ARCH-AUTH-01 Kernel identity and session binding; ARCH-SEC-02 Authentication and principal binding; ARCH-RES-01 Resource governance
//! Implementation: I1.2 Обязательные процессы первого полного runtime; I1.8 Exact ownership and call paths; I14.15 Kernel launch and recovery identity; I15.2 Principal and Session binding; I2.23 Capability-family topology and crate extraction decisions — ordinary single-file extraction (<10k LOC) owning only runtime identity derivation
//! Forbidden authority: must not mint authority, must not own process lifecycle, must not make semantic decisions.
//! Ownership: immutable runtime and launch identity derivation only.

use crate::KernelBuildError;
#[cfg(windows)]
use crate::sha256_hex;
#[cfg(windows)]
use crate::unix_ms;
use eliot_contracts::EpochId;
#[cfg(windows)]
use eliot_kernel_service::EliotdLaunchDescriptor;
#[cfg(windows)]
use eliot_platform::PlatformHandle;
use eliot_process::Generation;
#[cfg(windows)]
use serde::Serialize;
use sha2::{Digest, Sha256};

#[cfg(windows)]
use eliot_platform_windows::current_process_named_pipe_expectation;

/// F-LOG-KERNEL-4 (#903 slice B): runtime-identity derivation observations.
///
/// Observation only, via #895's facade: fixed `kernel.identity.*` event names
/// plus a bounded stable outcome. Never carries SIDs, session identifiers,
/// nonces, image paths, digests, epochs, generations, or owner error strings
/// (I15.4, I15.2, I07.20): only the fact that a derivation boundary was
/// reached and its stable outcome are recorded. Terminal ownership stays with
/// the calling authorities — the composition build, the eliotd launch
/// wrapper, and the daemon lifecycle owners map `KernelBuildError` into their
/// typed terminal codes — so derivation helpers emit no terminal here and one
/// failed operation keeps exactly one terminal record.
fn observe_identity(event: &'static str, outcome: &'static str) {
    use crate::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "runtime identity observation"
    );
}

#[cfg(windows)]
pub(crate) fn observed_session_principal_binding() -> Result<String, KernelBuildError> {
    let expectation = match current_process_named_pipe_expectation() {
        Ok(expectation) => expectation,
        Err(error) => {
            observe_identity("kernel.identity.session_binding_failed", "fenced");
            return Err(KernelBuildError::Principal(error.to_string()));
        }
    };
    observe_identity("kernel.identity.session_binding_observed", "success");
    Ok(format!(
        "sid={};session={}",
        expectation.expected_sid(),
        expectation.expected_session_id()
    ))
}

#[cfg(windows)]
pub(crate) fn eliotd_launch_attempt_identity(
    launch: &EliotdLaunchDescriptor,
    kernel_process_id: u32,
    kernel_start_time_100ns: u64,
    kernel_image_path: &str,
) -> Result<String, KernelBuildError> {
    #[derive(Serialize)]
    struct AttemptBinding<'a> {
        authority_epoch: EpochId,
        generation: u64,
        launch_nonce: &'a str,
        kernel_process_id: u32,
        kernel_start_time_100ns: u64,
        kernel_image_path: &'a str,
    }

    let bytes = match serde_json::to_vec(&AttemptBinding {
        // INTENDED EpochId shape (Split A/B cutover): clone the lineage-aware
        // authority. Integrator resolves order B→A→C.
        authority_epoch: launch.authority_epoch.clone(),
        generation: launch.generation.value(),
        launch_nonce: launch.launch_nonce.as_str(),
        kernel_process_id,
        kernel_start_time_100ns,
        kernel_image_path,
    }) {
        Ok(bytes) => bytes,
        Err(error) => {
            observe_identity("kernel.identity.launch_attempt_failed", "rejected");
            return Err(KernelBuildError::Service(error.to_string()));
        }
    };
    observe_identity("kernel.identity.launch_attempt_derived", "success");
    Ok(sha256_hex(&bytes))
}

#[cfg(windows)]
pub(crate) fn eliotd_operation_id(
    generation: Generation,
    launch_attempt_identity: &str,
) -> Result<eliot_process::OperationId, KernelBuildError> {
    let Some(short) = launch_attempt_identity.get(..16) else {
        observe_identity("kernel.identity.operation_rejected", "rejected");
        return Err(KernelBuildError::Service(
            "eliotd launch attempt identity is malformed".to_owned(),
        ));
    };
    match eliot_process::OperationId::new(format!("eliotd-launch-{}-{short}", generation.get())) {
        Ok(operation_id) => {
            observe_identity("kernel.identity.operation_derived", "success");
            Ok(operation_id)
        }
        Err(error) => {
            observe_identity("kernel.identity.operation_rejected", "rejected");
            Err(KernelBuildError::Service(error.to_string()))
        }
    }
}

#[cfg(windows)]
pub(crate) fn fresh_eliotd_launch_descriptor(
    previous: &EliotdLaunchDescriptor,
    recovery_attempt: u64,
) -> Result<EliotdLaunchDescriptor, KernelBuildError> {
    observe_identity("kernel.identity.launch_refresh_requested", "attempt");
    let outcome = fresh_eliotd_launch_descriptor_inner(previous, recovery_attempt);
    if outcome.is_ok() {
        observe_identity("kernel.identity.launch_descriptor_refreshed", "success");
    } else {
        observe_identity("kernel.identity.launch_refresh_failed", "rejected");
    }
    outcome
}

#[cfg(windows)]
fn fresh_eliotd_launch_descriptor_inner(
    previous: &EliotdLaunchDescriptor,
    recovery_attempt: u64,
) -> Result<EliotdLaunchDescriptor, KernelBuildError> {
    previous
        .validate()
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    let nonce_material = format!(
        "{}:{}:{}:{}",
        previous.descriptor_sha256,
        previous.launch_nonce.as_str(),
        recovery_attempt,
        unix_ms(),
    );
    let launch_nonce =
        PlatformHandle::new(format!("eliotd:{}", sha256_hex(nonce_material.as_bytes())))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
    let mut next = previous.clone();
    next.launch_nonce = launch_nonce.clone();
    if next.arguments.len() != 8 {
        return Err(KernelBuildError::Service(
            "eliotd launch descriptor has a non-canonical argv contour".to_owned(),
        ));
    }
    next.arguments[5] = launch_nonce;
    next.with_computed_digest()
        .map_err(|error| KernelBuildError::Service(error.to_string()))
}

pub(crate) fn stable_owner_principal_digest(
    stable_sid: &str,
    module_id: &str,
    authority_epoch: &EpochId,
    generation: Generation,
) -> String {
    let mut principal = Sha256::new();
    principal.update(stable_sid.as_bytes());
    principal.update(module_id.as_bytes());
    // Lineage+sequence digest input (T6-E3): canonical lineage spelling plus
    // sequence bytes. No bare-u64 to_le_bytes, no .sequence.get() adapter for
    // comparison, no From<u64>.
    principal.update(authority_epoch.lineage_id.as_str().as_bytes());
    principal.update(authority_epoch.sequence.get().to_le_bytes());
    principal.update(generation.get().to_le_bytes());
    observe_identity("kernel.identity.owner_digest_derived", "success");
    format!("{:x}", Sha256::digest(principal.finalize()))
}

#[cfg(test)]
mod runtime_identity_diagnostics_tests {
    //! F-LOG-KERNEL-4 (#903 slice B) focused diagnostics proof: the owner
    //! digest derivation keeps its exact stable output while recording only
    //! a fixed, secret-free observation name.

    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture(run: impl FnOnce()) -> String {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer_sink.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, run);
        }
        String::from_utf8_lossy(&sink.bytes.lock().expect("capture lock")).into_owned()
    }

    fn test_epoch() -> eliot_contracts::EpochId {
        eliot_contracts::EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("lineage"),
            std::num::NonZeroU64::new(3).expect("sequence"),
        )
        .expect("epoch")
    }

    #[test]
    fn identity_digest_derivation_is_stable_and_secret_free() {
        // The real derivation runs through the existing caller path: same
        // inputs keep the exact 64-hex digest, distinct principals diverge,
        // and only the fixed event name reaches the sink.
        let generation = Generation::new(1).expect("generation");
        let first = stable_owner_principal_digest(
            "S-1-5-18-sid-canary",
            "testd",
            &test_epoch(),
            generation,
        );
        let second = stable_owner_principal_digest(
            "S-1-5-18-sid-canary",
            "testd",
            &test_epoch(),
            generation,
        );
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(
            first.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')),
            "owner digest must stay lowercase hex"
        );
        let other =
            stable_owner_principal_digest("S-1-5-19-other", "testd", &test_epoch(), generation);
        assert_ne!(first, other);

        let text = capture(|| {
            let _ = stable_owner_principal_digest(
                "S-1-5-18-sid-canary",
                "testd",
                &test_epoch(),
                generation,
            );
        });
        assert!(
            text.contains("kernel.identity.owner_digest_derived"),
            "missing diagnostics marker kernel.identity.owner_digest_derived"
        );
        assert!(
            !text.contains("sid-canary"),
            "identity material leaked into diagnostics"
        );
    }

    // ---------------------------------------------------------------------
    // #903 cases 2 / 3 / 28 over the private identity seams of this owner.
    // Every premise below compares two values the OWNER computes (the
    // platform port at crates/kernel/eliot-platform-windows/src/
    // named_pipe_process_admission.rs:577, `eliot_process::OperationId::new`
    // -> `validate_opaque_id` at crates/kernel/eliot-process/src/lib.rs:2901,
    // and `stable_owner_principal_digest` itself). No premise compares two
    // objects this test module built.
    // ---------------------------------------------------------------------

    // Fixed, non-secret principal identities used as derivation input. These
    // are ordinary test inputs only: they are never evidence about a real
    // principal and they must never reach the diagnostics surface.
    const OWNER_SID: &str = "S-1-5-21-903903903-903903903-903903903-1001";
    const OTHER_OWNER_SID: &str = "S-1-5-21-903903903-903903903-903903903-1002";

    // The `key=` field names actually present in a captured record. This is a
    // structural sweep of the WHOLE surface, not a hand-listed value set: a
    // mutation that adds any further field (a path, a payload, an error
    // string) shows up here even when no canary string matches it.
    fn record_field_keys(record: &str) -> Vec<String> {
        let bytes = record.as_bytes();
        let mut keys = Vec::new();
        let mut index = 0usize;
        while index < bytes.len() {
            if bytes[index] == b'=' && index > 0 {
                let mut start = index;
                while start > 0
                    && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_')
                {
                    start -= 1;
                }
                if start < index {
                    keys.push(record[start..index].to_owned());
                }
            }
            index += 1;
        }
        keys
    }

    // One derivation boundary reaches exactly one fixed observation record.
    // Quoting/spacing independent: only the `key=value` assignments are read.
    fn assert_single_observation(record: &str, event: &str, outcome: &str) {
        let event_key = record.find("event=").expect("captured event field");
        let outcome_key = record.find("outcome=").expect("captured outcome field");
        assert!(
            event_key < outcome_key,
            "the fixed pair must be event then outcome: {record}"
        );
        let event_slice = &record[event_key..outcome_key];
        let outcome_slice = &record[outcome_key..];
        assert!(
            event_slice.contains(event),
            "the record must name this exact derivation boundary ({event}): {record}"
        );
        assert!(
            !event_slice.contains(&format!("outcome={outcome}")),
            "the stable outcome must not be attached to the event field: {record}"
        );
        assert!(
            outcome_slice.contains(&format!("outcome={outcome}")),
            "the record must carry this exact stable outcome ({outcome}): {record}"
        );
        assert!(
            !outcome_slice.contains("event="),
            "the stable outcome must not be attached to a later field: {record}"
        );
        assert_eq!(
            record.matches(event).count(),
            1,
            "one derivation boundary must yield one observation: {record}"
        );
        let keys = record_field_keys(record);
        assert_eq!(
            keys.len(),
            2,
            "an identity observation carries only the two fixed fields: {record}"
        );
        assert!(
            keys[0] == "event" && keys[1] == "outcome",
            "an identity observation carries only event and outcome, in order: {record}"
        );
        assert!(
            !record.contains("kernel.terminal_error"),
            "derivation helpers emit no terminal here; the calling authority owns it: {record}"
        );
    }

    // Case 2 - candidate identity versus validated identity.
    //
    // GATE DISCLOSURE, and the shared one for all three #[cfg(windows)] tests
    // in this module: no `reason = "..."` clause may be attached to these
    // gates. On this repository's pinned toolchain (rust-toolchain.toml,
    // channel 1.97.1) a `key = "value"` pair inside `cfg` is a feature
    // predicate, so `#[cfg(all(windows, reason = "..."))]` compiles and then
    // configures the test out EVEN ON WINDOWS ("the item is gated behind the
    // `...` feature"), and the unwrapped `#[cfg(windows, reason = "...")]`
    // is rejected outright as a malformed `cfg` attribute. Both forms were
    // measured against `x86_64-pc-windows-msvc`. So a comment is the only
    // available disclosure, and each gate below carries one.
    //
    // THIS GATE hides: off Windows `current_process_named_pipe_expectation()`
    // is `Unavailable` (named_pipe_process_admission.rs:584-588), so there is
    // no inert candidate to interrogate and no counter-example to keep out of
    // the observed verdict.
    #[test]
    #[cfg(windows)]
    // The allow below rides on this FUNCTION, never on the `eprintln!`
    // statement: in statement position an attribute lands on the macro
    // invocation and is discarded, so `-D unused-attributes` then reports the
    // allow AND the `eprintln!` while suppressing nothing; an attribute on an
    // `fn` item is always applied. It is hoisted here because this body's only
    // output statement is that one `eprintln!` (the `panic!` further down is
    // `clippy::panic`, not an output lint), and the audited rationale is
    // verbatim in `reason`: it announces an absent proof, never a proof.
    #[allow(
        clippy::print_stderr,
        reason = "this test-only announcement is the disclosure that a green run on a host whose platform port refuses the owner's own process token is NOT proof of the candidate-versus-validated distinction; print_stderr and print_stdout are both warn-level workspace-wide (Cargo.toml:408-409) and assertion text cannot carry it because a passing assert prints nothing, so the skip is reported through stderr rather than silently absorbed"
    )]
    fn session_binding_offers_the_inert_candidate_and_never_an_admission_verdict() {
        // I1.8 "Session attach": "Kernel authenticates local process/profile
        // and transport generation". THIS step (runtime_identity.rs:56) only
        // OBSERVES the platform's inert named-pipe expectation, whose own
        // contract (crates/kernel/eliot-platform-windows/src/
        // named_pipe_process_admission.rs:571) states: "This does not
        // authenticate any pipe or issue a peer result." I14.20 "Blueprint
        // instance": "PROPOSED -> VALIDATING -> BINDING -> CONFORMANCE ->
        // STAGED -> ACTIVE" - a candidate is offered, only an owner-confirmed
        // binding is validated, and I14.14 step 3 is "start candidate with no
        // effect authority". So a candidate the owner never confirmed must
        // never be recorded as the observed/validated verdict, and the record
        // must name which of the two it is.
        let port = current_process_named_pipe_expectation();
        let mut derived: Option<Result<String, KernelBuildError>> = None;
        let record = capture(|| {
            derived = Some(observed_session_principal_binding());
        });
        let derived = derived.expect("observed_session_principal_binding result");

        // Owner confirmation is structurally absent from the candidate: the
        // owner constructs this expectation with no approved process and no
        // approved job binding (named_pipe_process_admission.rs:171-188), so a
        // mutation that silently turned an offered candidate into a validated
        // identity reddens in the Ok arm below.
        //
        // SCOPE OF THAT PROOF, NOT UNCONDITIONAL COVERAGE. It executes only
        // where the platform port handed back an expectation at all. Exactly two
        // host conditions skip it, and neither is silent any more:
        //   1. OFF WINDOWS: this whole test is #[cfg(windows)], so no arm of
        //      the match below runs anywhere but on Windows.
        //   2. WINDOWS, PORT Err: the owner could not observe its own process
        //      token (named_pipe_process_admission.rs:577-582), so it never
        //      produced a candidate. That arm still proves the typed refusal,
        //      and it announces the absent proof on stderr; it proves nothing
        //      whatsoever about candidate-versus-validated identity.
        match (&port, &derived) {
            (Ok(expectation), Ok(binding)) => {
                // The candidate-versus-validated proof, on the only host shape
                // that can produce the candidate at all.
                assert!(
                    expectation.approved_process_binding().is_none(),
                    "the offered expectation carries no owner-confirmed process identity"
                );
                assert!(
                    expectation.approved_process_job_binding().is_none(),
                    "the offered expectation carries no owner-confirmed job identity"
                );
                // Production comparison against the owner's own port output:
                // the returned identity IS the offered candidate, verbatim.
                assert_eq!(
                    binding,
                    &format!(
                        "sid={};session={}",
                        expectation.expected_sid(),
                        expectation.expected_session_id()
                    ),
                    "runtime_identity.rs:64 must render the owner's own inert expectation unchanged"
                );
                assert_single_observation(
                    &record,
                    "kernel.identity.session_binding_observed",
                    "success",
                );
                assert!(
                    !record.contains("kernel.identity.session_binding_failed"),
                    "the refusal verdict (runtime_identity.rs:59) is a distinct record and must not stand in for the observed one"
                );
            }
            (Err(_), Err(error)) => {
                // SKIPPED ON THIS HOST: the two no-approved-binding assertions
                // above did not run, because the port refused the owner's own
                // token and produced no candidate to interrogate. Announce it,
                // so a green result here is never read as
                // candidate-versus-validated proof. This arm proves the typed
                // refusal and nothing else.
                eprintln!(
                    "SKIPPED PROOF session_binding_offers_the_inert_candidate_and_never_an_admission_verdict: current_process_named_pipe_expectation() returned Err on this host, so the offered expectation's absent approved process and approved job binding were NOT proved here; only the typed refusal below is proved"
                );
                assert!(
                    matches!(error, KernelBuildError::Principal(_)),
                    "runtime_identity.rs:60 types an unconfirmable candidate as KernelBuildError::Principal"
                );
                assert_single_observation(
                    &record,
                    "kernel.identity.session_binding_failed",
                    "fenced",
                );
                assert!(
                    !record.contains("kernel.identity.session_binding_observed"),
                    "an identity the owner never confirmed must not be recorded as observed"
                );
            }
            (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
                panic!(
                    "the production binding (runtime_identity.rs:55) must reach the same verdict as the platform port"
                );
            }
        }
    }

    // Case 3 - invalid and foreign identity stay typed.
    //
    // THIS GATE hides: every premise below derives through
    // `eliotd_operation_id` (runtime_identity.rs:108), which does not exist
    // off Windows, so neither the refusals nor the two separations it closes
    // with are executed anywhere else. Attribute disclosure is impossible here
    //; see the shared note above the first gate in this module.
    #[test]
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the invalid, foreign and admitted candidates are one measured narrative: each leg derives its own candidate then judges the refusal or disposition that candidate produced, and the admitted identity is the reference the closing generation and owner separations compare against"
    )]
    fn operation_identity_refusals_stay_typed_for_invalid_and_foreign_candidates() {
        // I1.8: "Kernel verifies identity, authority, State Fence, idempotency,
        // ordering and runtime generation". The owner admits an operation
        // identity only from a launch-attempt identity whose 16-byte prefix it
        // can bind (runtime_identity.rs:113, :119); I14.14 "Request pinning":
        // "retry -> follows operation identity/receipt and its disposition,
        // never merely the newest generation". An invalid candidate and a
        // foreign candidate must each keep their own typed refusal instead of
        // collapsing into one generic failure, and neither may reach the
        // derived verdict.
        let generation = Generation::new(1).expect("generation");
        let other_generation = Generation::new(2).expect("other generation");
        let epoch = test_epoch();
        let owner_identity = stable_owner_principal_digest(OWNER_SID, "testd", &epoch, generation);
        let other_identity =
            stable_owner_principal_digest(OTHER_OWNER_SID, "testd", &epoch, generation);
        assert!(
            owner_identity.len() >= 16,
            "the owner derivation must yield a full 16-byte prefix source"
        );

        // INVALID candidate: shorter than the owner's 16-byte prefix contract,
        // so `get(..16)` is None (runtime_identity.rs:113).
        let mut invalid: Option<Result<eliot_process::OperationId, KernelBuildError>> = None;
        let invalid_record = capture(|| {
            invalid = Some(eliotd_operation_id(generation, "short"));
        });
        let invalid = invalid.expect("invalid candidate produced a result");
        let Err(KernelBuildError::Service(invalid_reason)) = invalid else {
            panic!(
                "runtime_identity.rs:115 refuses an invalid candidate as KernelBuildError::Service; this candidate came back under any other outcome, so it was not refused and reached the derived verdict"
            );
        };
        assert_eq!(
            invalid_reason, "eliotd launch attempt identity is malformed",
            "runtime_identity.rs:116 fixes the invalid-candidate refusal text"
        );
        assert_single_observation(
            &invalid_record,
            "kernel.identity.operation_rejected",
            "rejected",
        );
        assert!(
            !invalid_record.contains("kernel.identity.operation_derived"),
            "an invalid candidate must not reach the derived verdict"
        );

        // FOREIGN candidate: exactly 16 ASCII bytes, but the owner's own Sha256
        // derivation over sid/module_id/lineage/sequence/generation can never
        // produce a control character, so this identity is not one of ours.
        let foreign_candidate = "\u{7}eadbeefcafef00d";
        assert_eq!(
            foreign_candidate.len(),
            16,
            "the foreign candidate must clear the prefix contract so the OWNER's validator, not this test, refuses it"
        );
        let mut foreign: Option<Result<eliot_process::OperationId, KernelBuildError>> = None;
        let foreign_record = capture(|| {
            foreign = Some(eliotd_operation_id(generation, foreign_candidate));
        });
        let foreign = foreign.expect("foreign candidate produced a result");
        let Err(KernelBuildError::Service(foreign_reason)) = foreign else {
            panic!(
                "runtime_identity.rs:126 refuses a foreign candidate as KernelBuildError::Service; this candidate came back under any other outcome, so the OWNER's validator did not refuse it and it reached the derived verdict"
            );
        };
        assert_eq!(
            foreign_reason, "invalid opaque value in operation_id",
            "the owner's own validator (eliot-process/src/lib.rs:2901) names the refused field"
        );
        assert_ne!(
            foreign_reason, invalid_reason,
            "invalid and foreign candidates must not collapse into one generic refusal"
        );
        assert_single_observation(
            &foreign_record,
            "kernel.identity.operation_rejected",
            "rejected",
        );
        assert!(
            !foreign_record.contains("kernel.identity.operation_derived"),
            "a foreign candidate must not reach the derived verdict"
        );

        // The admitted leg: the owner's own derived identity, re-admitted by
        // the owner's own validator.
        let mut accepted: Option<Result<eliot_process::OperationId, KernelBuildError>> = None;
        let accepted_record = capture(|| {
            accepted = Some(eliotd_operation_id(generation, &owner_identity));
        });
        let accepted = accepted
            .expect("owner-derived candidate produced a result")
            .expect("the owner's own derived launch-attempt identity must be admitted");
        assert!(
            eliot_process::OperationId::new(accepted.as_str().to_owned()).is_ok(),
            "the returned identity must satisfy the owner's own opaque-id validator"
        );
        assert!(
            accepted.as_str().ends_with(&owner_identity[..16]),
            "runtime_identity.rs:119 binds the operation identity to the owner-derived 16-byte prefix"
        );
        assert_single_observation(
            &accepted_record,
            "kernel.identity.operation_derived",
            "success",
        );
        assert!(
            !accepted_record.contains("kernel.identity.operation_rejected"),
            "an admitted candidate must not also record a refusal"
        );

        // Neither a newer generation nor a different owner-derived identity is
        // the same operation identity.
        //
        // CONTRACT REQUIREMENT, NOT PROVED HERE. I14.14 "Request pinning" is
        // quoted verbatim in this test's header above, and its clause "retry ->
        // follows operation identity/receipt and its disposition, never merely
        // the newest generation" splits into two halves. The identity half -
        // two generations never share one operation identity - is what the two
        // asserts below prove, because runtime_identity.rs:119 interpolates the
        // generation into the operation id and nothing else differs between the
        // two candidates. The routing half - that a retry carrying operation id
        // X is dispatched by the DISPOSITION X was given, and not by generation
        // recency - is NOT proved by this test, and no assertion below claims
        // it: there is no retry, no receipt, no router lookup and no owner
        // lookup anywhere in this function. Proving the routing half needs a
        // dispatch path this owner does not contain: replay one derived
        // operation id against the owner and assert the disposition it returns
        // is the disposition already recorded for that id, unchanged by the
        // newer generation. That path belongs to the routing/disposition
        // owner, so adding it here would mean inventing a seam, not proving
        // this one.
        let mut by_generation = None;
        capture(|| {
            by_generation = Some(eliotd_operation_id(other_generation, &owner_identity));
        });
        let by_generation = by_generation.expect("result").expect("admitted");
        assert_ne!(
            accepted.as_str(),
            by_generation.as_str(),
            "runtime_identity.rs:119 binds the generation into the operation identity, so two generations never share one operation identity"
        );
        let mut by_identity = None;
        capture(|| {
            by_identity = Some(eliotd_operation_id(generation, &other_identity));
        });
        let by_identity = by_identity.expect("result").expect("admitted");
        assert_ne!(
            accepted.as_str(),
            by_identity.as_str(),
            "a different owner-derived identity is a different operation identity"
        );
    }

    // Case 28 - environment/config/path/credential/source/payload canaries.
    #[test]
    fn identity_observation_surface_excludes_forbidden_input_material() {
        // I13.11 "Diagnostic Brief": "Agent receives problem model, not raw log
        // dump." I16.17: "Operational logs never become verifier evidence by
        // themselves." runtime_identity.rs:33-37: "Never carries SIDs, session
        // identifiers, nonces, image paths, digests, epochs, generations, or
        // owner error strings (I15.4, I15.2, I07.20): only the fact that a
        // derivation boundary was reached and its stable outcome are recorded."
        // The live derivation below is FED every forbidden class as real input,
        // and the absence is asserted over the whole captured surface plus the
        // structural fact that no field beyond the fixed `event`/`outcome` pair
        // exists - so a digest that is merely stable proves nothing here.
        const SID_INPUT: &str = "S-1-5-21-903903903-903903903-903903903-4242";
        const PATH_INPUT: &str = r"C:\ProgramData\Eliot\secretinput\eliot.conf";
        const ENV_INPUT: &str = "ELIOT_SECRET_INPUT=S-1-5-21-4242424242";
        const CREDENTIAL_INPUT: &str = "Bearer secretinput.token.material-aaaaaaaaaaaaaaaa";
        const SIGNED_INPUT: &str =
            "-----BEGIN ELIOT SIGNATURE-----secretinputblob-----END ELIOT SIGNATURE-----";
        const SOURCE_INPUT: &str =
            "fn secretinput_symbol() -> &'static str { \"secretinput-literal\" }";
        const PAYLOAD_INPUT: &str = r#"{"prompt":"secretinput-body","token":"secretinput-token"}"#;

        let forbidden_inputs = [
            PATH_INPUT,
            ENV_INPUT,
            CREDENTIAL_INPUT,
            SIGNED_INPUT,
            SOURCE_INPUT,
            PAYLOAD_INPUT,
        ];
        let module_id = format!("testd/{}", forbidden_inputs.join("|"));
        let generation = Generation::new(903).expect("generation");
        let epoch = test_epoch();

        // The owner-derived digest itself is computed outside the capture so
        // the record can be checked against it: a digest, epoch or generation
        // appearing in the record breaks runtime_identity.rs:33-37.
        let owner_digest = stable_owner_principal_digest(SID_INPUT, &module_id, &epoch, generation);
        let record = capture(|| {
            let _second = stable_owner_principal_digest(SID_INPUT, &module_id, &epoch, generation);
        });
        assert_single_observation(&record, "kernel.identity.owner_digest_derived", "success");

        for forbidden in std::iter::once(SID_INPUT).chain(forbidden_inputs.iter().copied()) {
            assert!(
                !record.contains(forbidden),
                "a forbidden input class reached the diagnostics surface: {forbidden}"
            );
        }
        assert!(
            !record.contains(owner_digest.as_str()),
            "the owner-derived digest reached the diagnostics surface (runtime_identity.rs:191-192)"
        );
        for (name, value) in std::env::vars_os() {
            let name = name.to_string_lossy().into_owned();
            let value = value.to_string_lossy().into_owned();
            if value.len() >= 16
                && value
                    .chars()
                    .any(|character| !character.is_ascii_alphanumeric())
            {
                assert!(
                    !record.contains(value.as_str()),
                    "an environment value ({name}) reached the diagnostics surface"
                );
            }
        }
        for candidate in [std::env::current_exe(), std::env::current_dir()] {
            let Ok(path) = candidate else { continue };
            let raw_path = path.to_string_lossy().into_owned();
            assert!(
                !record.contains(raw_path.as_str()),
                "a raw path reached the diagnostics surface"
            );
        }
        let image = std::env::current_exe().expect("current executable path");
        let image_name = image
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert!(
            !record.contains(image_name.as_str()),
            "an image path reached the diagnostics surface (runtime_identity.rs:35)"
        );
    }

    // Cases 2/28 - the digest keeps every declared identity input distinct, so a
    // staged/superseded epoch position can never share an identity with the
    // current one, and no extra byte class is drawn in.
    #[test]
    fn owner_principal_digest_binds_every_identity_input_and_separates_epoch_positions() {
        // I1.8: "Kernel verifies identity, authority, State Fence, idempotency,
        // ordering and runtime generation". I14.14: "Rollback is never a
        // backward state transition. It is a new cutover with a newer Authority
        // Epoch" and "an old epoch is never reactivated". I14.20 "Authority
        // activation and token projection": "Only AuthorityActivationReceipt
        // enters ACTIVE", so a merely staged epoch position must not resolve to
        // the same principal identity as the activated one.
        let generation = Generation::new(1).expect("generation");
        let other_generation = Generation::new(2).expect("other generation");
        let epoch = test_epoch();
        let newer_epoch = eliot_contracts::EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("lineage"),
            std::num::NonZeroU64::new(4).expect("sequence"),
        )
        .expect("epoch");
        let other_lineage_epoch = eliot_contracts::EpochId::new(
            eliot_contracts::EpochLineageId::new("6ba7b810-9dad-41d1-80b4-00c04fd430c8")
                .expect("lineage"),
            std::num::NonZeroU64::new(3).expect("sequence"),
        )
        .expect("epoch");

        let activated = stable_owner_principal_digest(OWNER_SID, "testd", &epoch, generation);
        assert_eq!(
            activated,
            stable_owner_principal_digest(OWNER_SID, "testd", &epoch, generation),
            "the same identity inputs must keep the same principal identity"
        );
        assert_ne!(
            activated,
            stable_owner_principal_digest(OTHER_OWNER_SID, "testd", &epoch, generation),
            "runtime_identity.rs:183 binds the stable SID"
        );
        assert_ne!(
            activated,
            stable_owner_principal_digest(OWNER_SID, "otherd", &epoch, generation),
            "runtime_identity.rs:184 binds the module identity"
        );
        assert_ne!(
            activated,
            stable_owner_principal_digest(OWNER_SID, "testd", &other_lineage_epoch, generation),
            "runtime_identity.rs:188 binds the epoch lineage"
        );
        assert_ne!(
            activated,
            stable_owner_principal_digest(OWNER_SID, "testd", &newer_epoch, generation),
            "runtime_identity.rs:189 binds the epoch sequence, so a staged epoch position is a different identity"
        );
        assert_ne!(
            activated,
            stable_owner_principal_digest(OWNER_SID, "testd", &epoch, other_generation),
            "runtime_identity.rs:190 binds the runtime generation"
        );

        let record = capture(|| {
            let _one = stable_owner_principal_digest(OWNER_SID, "testd", &epoch, generation);
        });
        assert_single_observation(&record, "kernel.identity.owner_digest_derived", "success");
    }

    // Case 28/one-terminal - exactly one observation per derivation boundary,
    // and no terminal claim from an owner that does not own terminals.
    //
    // THIS GATE hides: the operation-identity boundaries counted below are
    // reached through `eliotd_operation_id` (runtime_identity.rs:108), which
    // does not exist off Windows, so the one-observation-per-boundary and
    // no-terminal-record counts run nowhere else. Attribute disclosure is
    // impossible here; see the shared note above the first gate in this module.
    #[test]
    #[cfg(windows)]
    fn each_identity_boundary_emits_one_observation_and_no_terminal_claim() {
        // runtime_identity.rs:37-41: "Terminal ownership stays with the calling
        // authorities ... so derivation helpers emit no terminal here and one
        // failed operation keeps exactly one terminal record." I14.24
        // "eliotd crash | Kernel revokes daemon epoch | external effects stop;
        // recovery/control remain": the caller, not this owner, terminalises.
        // So every boundary here adds exactly one observation and never a
        // second claim about an already-refused operation.
        let generation = Generation::new(1).expect("generation");
        let epoch = test_epoch();
        let owner_identity = stable_owner_principal_digest(OWNER_SID, "testd", &epoch, generation);

        let single_success = capture(|| {
            let _one = stable_owner_principal_digest(OWNER_SID, "testd", &epoch, generation);
        });
        assert_single_observation(
            &single_success,
            "kernel.identity.owner_digest_derived",
            "success",
        );

        let mut refused = None;
        let single_refusal = capture(|| {
            refused = Some(eliotd_operation_id(generation, "short"));
        });
        assert!(refused.expect("result").is_err(), "expected a refusal");
        assert_single_observation(
            &single_refusal,
            "kernel.identity.operation_rejected",
            "rejected",
        );

        // Two independent failed operations: one observation each, never a
        // re-emission and never a terminal claim.
        let two_refusals = capture(|| {
            let _first = eliotd_operation_id(generation, "short");
            let _second = eliotd_operation_id(generation, "also-short");
        });
        assert_eq!(
            two_refusals
                .matches("kernel.identity.operation_rejected")
                .count(),
            2,
            "one observation per failed operation boundary: {two_refusals}"
        );
        let refusal_keys = record_field_keys(&two_refusals);
        assert_eq!(
            refusal_keys.len(),
            4,
            "two failed operations carry only the fixed pair each: {two_refusals}"
        );
        assert!(
            refusal_keys
                .iter()
                .all(|key| key == "event" || key == "outcome"),
            "two failed operations carry only event and outcome fields: {two_refusals}"
        );
        assert!(
            !two_refusals.contains("kernel.terminal_error"),
            "this owner emits no terminal record: {two_refusals}"
        );

        let two_successes = capture(|| {
            let _first = eliotd_operation_id(generation, &owner_identity);
            let _second = eliotd_operation_id(generation, &owner_identity);
        });
        assert_eq!(
            two_successes
                .matches("kernel.identity.operation_derived")
                .count(),
            2,
            "one observation per derived operation identity: {two_successes}"
        );
        assert!(
            !two_successes.contains("kernel.terminal_error"),
            "this owner emits no terminal record: {two_successes}"
        );
    }

    // ---------------------------------------------------------------------
    // The second clause of the #903 W6 checklist row - bound values before
    // formatting, and exercise nested and oversized canaries - over the only
    // production seam in this file that reaches the bound declared at
    // bins/eliot-kernel/src/kernel_diagnostics.rs:59. PARAPHRASED, NOT QUOTED:
    // this worktree carries no `v2/issues/903/CHECKLIST.json` (untracked here,
    // and absent from `origin/main`), so the clause's exact wording is not
    // citable from the record available here, and is not offered as a quotation.
    //
    // The seam, established by reading rather than assumed. `observe_identity`
    // (runtime_identity.rs:42) takes `&'static str` and is the only caller of
    // `bound_field` in this file (runtime_identity.rs:44-45); every production
    // call site supplies a short literal (runtime_identity.rs:59, :63, :100,
    // :104, :114, :121, :125, :136, :139, :141, :191), so no production path feeds it
    // an oversized or a nested value. The legs below drive `observe_identity`
    // itself, so the bound is exercised where production applies it and is never
    // restated inside a test helper.
    //
    // What is new here, and it is not the canary. `origin/main` already drives
    // `bound_field` with an oversized canary at
    // tests/kernel_process_supervision_diagnostics.rs:3148-3313 (WORK_UNIT_CASE
    // 901/27) and covers `bound_detail` at
    // tests/kernel_diagnostics_contract.rs:132-183, but that canary is 320
    // CHARACTERS and that exact-bound case is 256 bytes, so both are screened
    // or admitted and neither reaches `truncate_to` (kernel_diagnostics.rs:276).
    // The TRUNCATING BRANCH is what the delivery leaves unaddressed.
    const OVERSIZED_HEAD: &str = "oversized-canary-head";
    const OVERSIZED_TAIL: &str = "oversized-canary-tail";
    const NESTED_OUTER: &str = "kernel.identity.nested-outer";
    const NESTED_INNER: &str = "{event=inner.event,outcome=inner.outcome}";

    // `observe_identity` takes `&'static str`, so the canary is handed over as a
    // leaked `String`. Only the lifetime is arranged here; the screen, the bound
    // and the truncation all stay in production code.
    fn bounded_canary(head: &str, tail: &str) -> &'static str {
        use crate::kernel_diagnostics::MAX_DIAGNOSTIC_FIELD_BYTES;
        let filler = "\u{3a9}".repeat((MAX_DIAGNOSTIC_FIELD_BYTES * 2) / 3);
        String::leak(format!("{head}{filler}{tail}"))
    }

    #[test]
    fn identity_observation_bounds_oversized_and_nested_field_values() {
        // 1. OVERSIZED. 212 chars / 382 bytes (21 + 170 two-byte U+03A9 + 21):
        //    inside the 256-char screen, tail marker at byte 361, past the bound.
        let oversized = bounded_canary(OVERSIZED_HEAD, OVERSIZED_TAIL);
        let record = capture(|| observe_identity(oversized, "oversized_probe"));
        assert!(
            record.contains(OVERSIZED_HEAD),
            "the bounded prefix of an oversized field must be retained: {record}"
        );
        assert!(
            !record.contains(OVERSIZED_TAIL),
            "the oversized tail must not reach the emitted record: {record}"
        );
        assert_single_observation(&record, OVERSIZED_HEAD, "oversized_probe");

        // 2. NESTED. 239 characters, and the inner envelope starts at byte
        //    28 + 2*170 = 368: inside the screen, far outside the bound.
        let nested = bounded_canary(NESTED_OUTER, NESTED_INNER);
        let record = capture(|| observe_identity(nested, "nested_probe"));
        assert!(
            record.contains(NESTED_OUTER),
            "the bounded prefix of a nested field must be retained: {record}"
        );
        assert!(
            !record.contains(NESTED_INNER),
            "a nested envelope must not be inlined verbatim into the outer field: {record}"
        );
        assert!(
            !record.contains("event=inner") && !record.contains("outcome=inner"),
            "a nested envelope must not escape into a sibling field: {record}"
        );
        assert_single_observation(&record, NESTED_OUTER, "nested_probe");

        // 3. ATTRIBUTION, and the honest limit of clause 2. `bound_field` is a
        //    byte bound and not a structural parser: inside the retained prefix a
        //    nested envelope IS inlined verbatim and its `key=` fragments read as
        //    sibling keys at text level. So this control asserts that inlining
        //    rather than suppressing it, which is what shows the two absences
        //    above are the byte bound's doing and not any filtering of nested
        //    material - and it sweeps four keys, not the two-key contour.
        let control: &'static str = String::leak(format!("{NESTED_OUTER}{NESTED_INNER}"));
        let record = capture(|| observe_identity(control, "nested_control"));
        assert!(
            record.contains(NESTED_INNER),
            "a nested envelope inside the bound is inlined verbatim: {record}"
        );
        assert_eq!(
            record_field_keys(&record).len(),
            4,
            "in-bound nested material contributes its own key= fragments: {record}"
        );
    }

    // ---------------------------------------------------------------------
    // Appended legs, closing the residual defects an adversarial read found in
    // `identity_observation_bounds_oversized_and_nested_field_values` above.
    // They are APPENDED rather than woven into that function, so any future
    // insertion ABOVE this point shifts every citation below it without shifting
    // these lines. The property that matters is therefore stated as a check on
    // citations rather than on line numbers: every `runtime_identity.rs:NNN`
    // target in this file names a line at or below 191, i.e. production code
    // above the test module, and none lands among these appended legs. That was
    // verified by reading, not asserted here.
    //
    // Why the filler above is two-byte, and what the bound actually guarantees.
    // `bounded_value` (kernel_diagnostics.rs:453) screens at :455 and only
    // reaches `truncate_to` at :493 when that screen does not trip.
    // `requires_evidence_handle`
    // (crates/instrument/eliot-observability/src/field_policy.rs:299-300) trips
    // on `chars().count() > MAX_LABEL_VALUE_CHARS`, 256 CHARACTERS
    // (field_policy.rs:29), and a tripped screen keeps NO prefix of the input
    // (kernel_diagnostics.rs:486-491). So only a value of at most 256
    // characters whose UTF-8 length passes 256 bytes can be truncated at all:
    // exactly the window both canaries above are built in, and sized from
    // `MAX_DIAGNOSTIC_FIELD_BYTES` itself.
    //
    // THE SCREEN/BOUND ORDER IS PROVED BELOW, NOT ASSUMED. The three legs above
    // cannot distinguish "screen then bound" from "bound then screen": both
    // canaries are at most 256 CHARACTERS, so the screen does not trip and
    // either order emits the same retained prefix. Until this block the order
    // rested on a reading of kernel_diagnostics.rs:455 and :493 alone, and no
    // other case in the delivery pins it - tests/kernel_diagnostics_contract.rs
    // :147-166 and tests/kernel_process_supervision_diagnostics.rs:3252-3271
    // both submit canaries exceeding 256 CHARACTERS, which the screen catches in
    // either order. The handle leg below is the only assertion anywhere in this
    // delivery that separates the two orderings.
    //
    // WHY THE DIRECT ACCESSORS ARE NOT REACHED. `BoundedField::truncated()` and
    // `BoundedField::original_bytes()` (kernel_diagnostics.rs:314-322) are the
    // direct evidence of a truncation and are unreachable from here:
    // `observe_identity` binds its two `BoundedField`s at runtime_identity.rs:44
    // and :45, emits only `.text()`, and is production code this slice may not
    // change. Everything below therefore pins the bound through the RENDERED
    // RECORD, reading the production constant rather than naming it, which is
    // the strongest evidence this seam can carry.
    // ---------------------------------------------------------------------

    // Two UTF-8 bytes each, and nothing else these legs emit is non-ASCII, so
    // the count of these characters on a captured surface IS the length of the
    // retained prefix, in filler characters.
    const FILLER: char = '\u{3a9}';

    // The retained prefix production keeps for `canary`, modelled from the
    // production constant and from the input itself - neither the bound nor the
    // truncation is restated here. Reading the bound instead of naming it is
    // what makes every count below bite from BELOW as well as from above.
    fn retained_filler_chars(canary: &str) -> usize {
        use crate::kernel_diagnostics::MAX_DIAGNOSTIC_FIELD_BYTES;
        let mut end = MAX_DIAGNOSTIC_FIELD_BYTES.min(canary.len());
        while !canary.is_char_boundary(end) {
            end -= 1;
        }
        canary[..end]
            .chars()
            .filter(|character| *character == FILLER)
            .count()
    }

    // The handle production must mint for a screened value, derived from the
    // public mint rather than read back out of a `BoundedField`: comparing two
    // accessors of one bound value cannot fail unless the implementation
    // defines text == handle, so it would prove nothing. The family and the key
    // are the ones the facade declares (kernel_diagnostics.rs:68 and :73).
    fn content_handle_for(value: &str) -> String {
        eliot_observability::field_policy::mint_handle(
            eliot_observability::field_policy::TelemetryFieldFamily::OperationalLog,
            "code",
            value,
            eliot_observability::field_policy::RedactionReason::Content,
        )
        .handle
    }

    // The bound, pinned from BOTH sides, and the outcome slot, which was never
    // exercised. Measured limits of the three legs above: they admit any
    // `MAX_DIAGNOSTIC_FIELD_BYTES` in [69, 281] - legs 1-2 need 28 bytes for the
    // nested head, leg 3 needs 69 for its control. The UPPER edge is leg 2's
    // 256-CHARACTER screen (field_policy.rs:29): that value measures 69 +
    // floor(2*MAX/3) CHARACTERS, admitted only while it is <= 256, so MAX <= 281.
    // Leg 1 sets no upper edge - its tail marker sits at byte 21 +
    // 2*floor(2*MAX/3), above MAX for every MAX > 0, so it never survives - so
    // 256 -> 128 reddened nothing; `retained_filler_chars` walks the constant.
    #[test]
    fn identity_observation_retains_exactly_the_production_bound_on_a_char_boundary() {
        // A lossy truncation - `String::from_utf8_lossy(&value.as_bytes()[..max])`
        // - keeps the same number of filler characters and still satisfies both
        // absences above, so the U+FFFD absence below is the assertion that
        // reddens it: a prefix cut mid-character emits U+FFFD, a prefix cut on
        // a boundary never can.
        let oversized = bounded_canary(OVERSIZED_HEAD, OVERSIZED_TAIL);
        let record = capture(|| observe_identity(oversized, "exact_bound_probe"));
        assert_eq!(
            record.matches(FILLER).count(),
            retained_filler_chars(oversized),
            "the retained prefix must be exactly the production bound applied to \
             this input: {record}"
        );
        assert!(
            !record.contains('\u{fffd}'),
            "the retained prefix must end on a char boundary, never on a lossy \
             replacement character: {record}"
        );
        assert!(
            !record.contains(OVERSIZED_TAIL),
            "the oversized tail must not reach the emitted record: {record}"
        );
        assert_single_observation(&record, OVERSIZED_HEAD, "exact_bound_probe");

        let nested = bounded_canary(NESTED_OUTER, NESTED_INNER);
        let record = capture(|| observe_identity(nested, "nested_bound_probe"));
        assert_eq!(
            record.matches(FILLER).count(),
            retained_filler_chars(nested),
            "the same production bound reaches the nested envelope: {record}"
        );
        assert!(
            !record.contains('\u{fffd}'),
            "the nested prefix must end on a char boundary too: {record}"
        );
        assert!(
            !record.contains(NESTED_INNER),
            "the inner envelope lies past the bound and must not survive: {record}"
        );

        // The OUTCOME slot - the second `bound_field` call at
        // runtime_identity.rs:45 - which no leg above drove with an oversized
        // value, so deleting that bound used to leave all three green.
        let record = capture(|| observe_identity("oversized_outcome_probe", oversized));
        assert_eq!(
            record.matches(FILLER).count(),
            retained_filler_chars(oversized),
            "the outcome slot is bounded by the same production bound: {record}"
        );
        assert!(
            record.contains(OVERSIZED_HEAD),
            "the bounded prefix of an oversized outcome must be retained: {record}"
        );
        assert!(
            !record.contains(OVERSIZED_TAIL),
            "the oversized tail must not reach the emitted record: {record}"
        );
        assert!(
            !record.contains('\u{fffd}'),
            "the outcome prefix must end on a char boundary too: {record}"
        );
    }

    // Screen-before-bound, proved rather than asserted in prose. This canary is
    // 342 CHARACTERS, so the screen trips. If screening really runs first, the
    // whole value is replaced by an immutable content handle and not one byte of
    // it survives; under the opposite order the 256-byte bound would run first,
    // the retained prefix would be 138 CHARACTERS and therefore under the
    // character screen, and this value would be emitted as a PREFIX. Those two
    // outcomes are distinguishable, which is the whole point of the leg.
    #[test]
    fn identity_observation_screens_a_long_value_whole_before_the_byte_bound() {
        let screened: &'static str = String::leak(format!(
            "{OVERSIZED_HEAD}{}{OVERSIZED_TAIL}",
            "\u{3a9}".repeat(300)
        ));
        let expected_handle = content_handle_for(screened);
        let record = capture(|| observe_identity(screened, "screened_probe"));
        assert!(
            record.contains(expected_handle.as_str()),
            "a value the screen must catch is replaced whole by the immutable \
             content handle minted for it: {record}"
        );
        assert!(
            !record.contains(OVERSIZED_HEAD) && !record.contains(OVERSIZED_TAIL),
            "no prefix of a screened value survives, so the screen ran BEFORE \
             the byte bound: {record}"
        );
        assert!(
            !record.contains(FILLER),
            "no fragment of a screened value survives: {record}"
        );
        assert_single_observation(&record, expected_handle.as_str(), "screened_probe");

        // The same screened value through the outcome slot.
        let record = capture(|| observe_identity("screened_outcome_probe", screened));
        assert!(
            record.contains(expected_handle.as_str()),
            "the outcome slot screens the same way: {record}"
        );
        assert!(
            !record.contains(FILLER),
            "the outcome slot keeps no fragment of a screened value: {record}"
        );
    }
}
