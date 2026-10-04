//! Watchdog-owned Host responsiveness/recovery attempt and pre-authorized
//! containment request records (I8.3, I8.9).
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-WDG-01.
//! Implementation: I8.1, I8.3, I8.9, I2.23.
//!
//! I8.3 puts two record categories in this Watchdog's own physically separate
//! spool, beside the intents in [`super::intent`]:
//!
//! - "Every attempt is recorded in the Watchdog spool and Windows Event Log for
//!   later reconciliation." [`HostAttemptRecord`] is that durable record: the
//!   bounded outcome of one bounded `HostResponsivenessChallenge` taken over
//!   two real observations, carrying the closed attempt/uncertainty/verdict
//!   codes and the observation digests the classification was made from.
//! - "emit a signed pre-authorized containment request to the owning
//!   Host/Kernel boundary." [`ContainmentRequestRecord`] is that request as the
//!   Watchdog's own retained copy, written only after the boundary fence
//!   admitted it.
//!
//! Why these carry no semantics. Both types are observation/request material,
//! not decisions: an attempt records what was and was not established, and a
//! containment request records what this Watchdog asked the owning boundary to
//! consider. Neither can express a canonical Problem or Incident transition, a
//! Current Epistemic Position update, a task decision, an Architecture change, a
//! completion decision, or a model/swarm budget decision, and neither writes
//! one. The canonical Problem/Incident transition belongs to the Governor; the
//! effect itself belongs to the owning Host/Kernel boundary, which revalidates
//! target, evidence, recipe class, current epoch, and allowed effect before
//! anything runs.
//!
//! Uncertainty is recorded, never resolved away. `produce_challenge_attempt` has
//! no production producer on the Host owner contour yet, so most passes classify
//! [`ChallengeUncertainty::InadequateCoverage`]. That is a real, named fact
//! about this Watchdog's own coverage and it is journalled as exactly that; the
//! record type never substitutes a fabricated timeout or a forged answer for a
//! missing producer, and it never turns `InadequateCoverage` into a verdict.
//!
//! Retention: both records are forensically linked evidence, so
//! [`is_forensically_linked_payload`] keeps them out of the compaction prefix at
//! every sequence, exactly like the spool-local intents. Retention-pressure
//! eviction remains the only thing that may drop them.

use eliot_contracts::sha256_hex;

use super::codec::WatchdogSpoolPayload;
use crate::host_identity_observation::{
    ChallengeAttemptOutcome, ChallengeUncertainty, HostResponsiveness,
};
use crate::host_recovery::{AdmittedRecoveryIntent, RecoveryTarget};
use crate::{SERVICE_NAME, SpoolError};

/// Maximum number of evidence references carried by one attempt or request
/// record.
///
/// The same ceiling the intent records use, so one record stays far below
/// `SPOOL_MAX_RECORD_BYTES` and the two categories cannot drift apart in how
/// much they may bind.
pub(crate) const MAX_ATTEMPT_EVIDENCE_REFS: usize = 16;

const _: () = assert!(MAX_ATTEMPT_EVIDENCE_REFS == 16);

/// Maximum accepted length of the `service` field these records carry.
const MAX_ATTEMPT_SERVICE_LEN: usize = 256;

/// Maximum accepted length of the stable operation identity a containment
/// request binds.
const MAX_ATTEMPT_OPERATION_ID_LEN: usize = 1024;

/// Maximum accepted length of one bound coordination handle a containment
/// request names.
const MAX_ATTEMPT_HANDLE_LEN: usize = 1024;

/// Length of one lowercase or uppercase hex SHA-256 digest.
const SHA256_HEX_LEN: usize = 64;

/// True for an opaque caller-supplied digest with exact SHA-256 hex shape.
fn is_sha256_hex_shape(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// True for a bounded, non-blank, control-character-free coordination handle.
///
/// The target bounds a containment request names are the admitted
/// [`RecoveryTarget`]'s own coordination handles, so they are checked as the
/// bounded text they are and not re-shaped into a digest this Watchdog did not
/// compute. The Watchdog-computed material — evidence references and the observed
/// target-identity digest — is checked as a sha256 digest instead, because those
/// two are computed here.
fn is_bounded_handle_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ATTEMPT_HANDLE_LEN
        && !value.chars().any(char::is_control)
}

/// True for the spool payloads this Watchdog must retain for forensic linkage.
///
/// An intent, a Host attempt, and a containment request are all evidence some
/// later canonical reconciliation has to be readable against, so none of them is
/// ever a compaction candidate at any sequence.
pub(crate) fn is_forensically_linked_payload(payload: &WatchdogSpoolPayload) -> bool {
    super::intent::is_intent_payload(payload)
        || matches!(
            payload,
            WatchdogSpoolPayload::HostAttempt { .. }
                | WatchdogSpoolPayload::ContainmentRequest { .. }
        )
}

fn validate_evidence_refs(evidence_refs: &[String]) -> Result<(), SpoolError> {
    if evidence_refs.is_empty() || evidence_refs.len() > MAX_ATTEMPT_EVIDENCE_REFS {
        return Err(SpoolError::Corrupt(
            "watchdog attempt record must carry a bounded non-empty evidence reference list"
                .to_owned(),
        ));
    }
    if evidence_refs
        .iter()
        .any(|value| !is_sha256_hex_shape(value))
    {
        return Err(SpoolError::Corrupt(
            "watchdog attempt record evidence reference is not a sha256 digest".to_owned(),
        ));
    }
    Ok(())
}

fn validate_service(service: &str) -> Result<(), SpoolError> {
    if service.is_empty() || service.len() > MAX_ATTEMPT_SERVICE_LEN {
        return Err(SpoolError::Corrupt(
            "watchdog attempt record service identity is unusable".to_owned(),
        ));
    }
    Ok(())
}

/// Closed wire code of one bounded challenge attempt outcome.
fn attempt_code(attempt: ChallengeAttemptOutcome) -> &'static str {
    match attempt {
        ChallengeAttemptOutcome::CompetentTimeout => "COMPETENT_TIMEOUT",
        ChallengeAttemptOutcome::Uncertain(_) => "UNCERTAIN",
    }
}

/// Closed wire code of one named challenge uncertainty.
const fn uncertainty_code(uncertainty: ChallengeUncertainty) -> &'static str {
    match uncertainty {
        ChallengeUncertainty::Unauthenticated => "UNAUTHENTICATED",
        ChallengeUncertainty::ConnectionDenied => "CONNECTION_DENIED",
        ChallengeUncertainty::TargetChanged => "TARGET_CHANGED",
        ChallengeUncertainty::InadequateCoverage => "INADEQUATE_COVERAGE",
        ChallengeUncertainty::TargetNotLive => "TARGET_NOT_LIVE",
    }
}

/// Closed wire code of one responsiveness verdict.
const fn verdict_code(verdict: HostResponsiveness) -> &'static str {
    match verdict {
        HostResponsiveness::Responsive => "RESPONSIVE",
        HostResponsiveness::AliveUnresponsive => "ALIVE_UNRESPONSIVE",
        HostResponsiveness::Uncertain(_) => "UNCERTAIN",
    }
}

/// Digest over one observed target identity, or `None` when none was observed.
///
/// This Watchdog never names a target it did not observe: an absent identity
/// stays an absent leg, so a record can state "the observation carried no
/// identity" instead of substituting a placeholder that a reader could mistake
/// for one.
#[must_use]
pub(crate) fn target_identity_digest(
    observation: &crate::host_identity_observation::HostObservation,
) -> Option<String> {
    observation
        .identity
        .as_ref()
        .and_then(|identity| crate::host_recovery::identity_digest(identity).ok())
        .map(|handle| handle.as_str().to_owned())
}

/// Watchdog-owned Host responsiveness/recovery attempt record.
///
/// One record is one bounded challenge attempt over the two observations the
/// production pass actually took. It states the attempt's own outcome, the
/// uncertainty that kept it from a verdict when it stayed unresolved, the
/// verdict when one was reached, the granted bounded interval, and the digests
/// of the observations it was classified from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HostAttemptRecord {
    service: String,
    attempt: String,
    uncertainty: Option<String>,
    verdict: String,
    bounded_wait_secs: u64,
    target_identity_digest: Option<String>,
    evidence_refs: Vec<String>,
}

impl HostAttemptRecord {
    /// Binds one attempt record from the closed outcome and verdict codes.
    ///
    /// `evidence_refs` are the owner-computed observation digests the
    /// classification was made from; they are required and bounded, because a
    /// stored attempt with no evidence reference could not be reconciled against
    /// anything later.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the service identity is unusable,
    /// the bounded interval is zero or over the contour ceiling, an evidence
    /// list is empty, oversized, or not made of sha256 digests, or a named
    /// digest is not a sha256 digest.
    pub(crate) fn new(
        service: String,
        attempt: ChallengeAttemptOutcome,
        verdict: HostResponsiveness,
        bounded_wait_secs: u64,
        target_identity_digest: Option<String>,
        evidence_refs: Vec<String>,
    ) -> Result<Self, SpoolError> {
        validate_service(&service)?;
        if bounded_wait_secs == 0
            || bounded_wait_secs > crate::host_identity_observation::MAX_CHALLENGE_WAIT_SECS
        {
            return Err(SpoolError::Corrupt(
                "watchdog attempt record bounded interval is outside the challenge ceiling"
                    .to_owned(),
            ));
        }
        validate_evidence_refs(&evidence_refs)?;
        if target_identity_digest
            .as_ref()
            .is_some_and(|digest| !is_sha256_hex_shape(digest))
        {
            return Err(SpoolError::Corrupt(
                "watchdog attempt record target identity digest is not a sha256 digest".to_owned(),
            ));
        }
        let uncertainty = match attempt {
            ChallengeAttemptOutcome::CompetentTimeout => None,
            ChallengeAttemptOutcome::Uncertain(reason) => Some(uncertainty_code(reason).to_owned()),
        };
        if let HostResponsiveness::Uncertain(reason) = verdict {
            if uncertainty.is_none() {
                return Err(SpoolError::Corrupt(
                    "watchdog attempt record cannot report an uncertainty no attempt observed"
                        .to_owned(),
                ));
            }
            if uncertainty.as_deref() != Some(uncertainty_code(reason)) {
                return Err(SpoolError::Corrupt(
                    "watchdog attempt record verdict and attempt name different uncertainties"
                        .to_owned(),
                ));
            }
        }
        Ok(Self {
            service,
            attempt: attempt_code(attempt).to_owned(),
            uncertainty,
            verdict: verdict_code(verdict).to_owned(),
            bounded_wait_secs,
            target_identity_digest,
            evidence_refs,
        })
    }

    /// Returns the closed verdict code this attempt reached.
    ///
    /// The production pass reads it to name the durable coverage/uncertainty
    /// diagnostic it emits beside the journalled record, so the trace and the
    /// retained record cannot state two different verdicts.
    #[must_use]
    pub(crate) fn verdict_code(&self) -> &str {
        &self.verdict
    }

    /// Projects the record onto its spool payload.
    #[must_use]
    pub(crate) fn to_payload(&self) -> WatchdogSpoolPayload {
        WatchdogSpoolPayload::HostAttempt {
            service: self.service.clone(),
            attempt: self.attempt.clone(),
            uncertainty: self.uncertainty.clone(),
            verdict: self.verdict.clone(),
            bounded_wait_secs: self.bounded_wait_secs,
            target_identity_digest: self.target_identity_digest.clone(),
            evidence_refs: self.evidence_refs.clone(),
        }
    }
}

/// Watchdog-owned pre-authorized containment request record.
///
/// Written only after [`crate::host_recovery::fence_recovery`] admitted one
/// fenced request, so the record can only name a request this Watchdog was
/// actually authorized to emit. It carries the request, never an effect: the
/// owning Host/Kernel boundary revalidates target, evidence, recipe class,
/// current epoch, and allowed effect before any containment runs, and this
/// Watchdog performs none.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ContainmentRequestRecord {
    service: String,
    operation_id: String,
    recipe_digest: String,
    owner_epoch_digest: String,
    registration_digest: String,
    target_identity_digest: String,
    evidence_refs: Vec<String>,
}

impl ContainmentRequestRecord {
    /// Binds the retained request copy of one admitted containment intent.
    ///
    /// Every digest is the target's own recorded bound, taken from the admitted
    /// [`RecoveryTarget`], so the record names what the boundary revalidates
    /// rather than a value restated by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the service or operation identity is
    /// unusable, any bound digest is not a sha256 digest, or the evidence list is
    /// empty, oversized, or not made of sha256 digests.
    pub(crate) fn new(
        service: String,
        intent: &AdmittedRecoveryIntent,
        evidence_refs: Vec<String>,
    ) -> Result<Self, SpoolError> {
        let operation_id = intent.operation_id.as_str().to_owned();
        if operation_id.is_empty() || operation_id.len() > MAX_ATTEMPT_OPERATION_ID_LEN {
            return Err(SpoolError::Corrupt(
                "watchdog containment request operation identity is unusable".to_owned(),
            ));
        }
        Self::from_target(service, operation_id, &intent.target, evidence_refs)
    }

    /// Binds the retained request copy from an admitted target and the stable
    /// operation identity the correlation minted.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] under the same conditions as
    /// [`Self::new`].
    pub(crate) fn from_target(
        service: String,
        operation_id: String,
        target: &RecoveryTarget,
        evidence_refs: Vec<String>,
    ) -> Result<Self, SpoolError> {
        validate_service(&service)?;
        if operation_id.is_empty() || operation_id.len() > MAX_ATTEMPT_OPERATION_ID_LEN {
            return Err(SpoolError::Corrupt(
                "watchdog containment request operation identity is unusable".to_owned(),
            ));
        }
        for digest in [
            &target.recipe_digest,
            &target.owner_epoch,
            &target.registration,
            &target.identity_digest,
        ] {
            if !is_bounded_handle_text(digest.as_str()) {
                return Err(SpoolError::Corrupt(
                    "watchdog containment request target bound is unusable".to_owned(),
                ));
            }
        }
        validate_evidence_refs(&evidence_refs)?;
        Ok(Self {
            service,
            operation_id,
            recipe_digest: target.recipe_digest.as_str().to_owned(),
            owner_epoch_digest: target.owner_epoch.as_str().to_owned(),
            registration_digest: target.registration.as_str().to_owned(),
            target_identity_digest: target.identity_digest.as_str().to_owned(),
            evidence_refs,
        })
    }

    /// Projects the record onto its spool payload.
    #[must_use]
    pub(crate) fn to_payload(&self) -> WatchdogSpoolPayload {
        WatchdogSpoolPayload::ContainmentRequest {
            service: self.service.clone(),
            operation_id: self.operation_id.clone(),
            recipe_digest: self.recipe_digest.clone(),
            owner_epoch_digest: self.owner_epoch_digest.clone(),
            registration_digest: self.registration_digest.clone(),
            target_identity_digest: self.target_identity_digest.clone(),
            evidence_refs: self.evidence_refs.clone(),
        }
    }
}

/// Revalidates one stored attempt/request payload against the constructor
/// bounds.
///
/// Intent payloads are revalidated by [`super::intent::check_stored_intent_payload`]
/// and the three original classes pass through untouched; this is the same
/// persistence-boundary gate for the two categories below it, so a forged or
/// non-canonical row fails closed at encode/decode instead of entering the
/// spool.
pub(crate) fn check_stored_attempt_payload(
    _observed_at_ms: u64,
    payload: &WatchdogSpoolPayload,
) -> Result<(), SpoolError> {
    match payload {
        WatchdogSpoolPayload::HostAttempt {
            service,
            attempt,
            uncertainty,
            verdict,
            bounded_wait_secs,
            target_identity_digest,
            evidence_refs,
        } => {
            let attempt = match attempt.as_str() {
                "COMPETENT_TIMEOUT" => ChallengeAttemptOutcome::CompetentTimeout,
                "UNCERTAIN" => {
                    ChallengeAttemptOutcome::Uncertain(stored_uncertainty(uncertainty.as_deref())?)
                }
                _ => {
                    return Err(SpoolError::Corrupt(
                        "watchdog attempt record carries an unknown attempt code".to_owned(),
                    ));
                }
            };
            let verdict = match verdict.as_str() {
                "RESPONSIVE" => HostResponsiveness::Responsive,
                "ALIVE_UNRESPONSIVE" => HostResponsiveness::AliveUnresponsive,
                "UNCERTAIN" => {
                    HostResponsiveness::Uncertain(stored_uncertainty(uncertainty.as_deref())?)
                }
                _ => {
                    return Err(SpoolError::Corrupt(
                        "watchdog attempt record carries an unknown verdict code".to_owned(),
                    ));
                }
            };
            HostAttemptRecord::new(
                service.clone(),
                attempt,
                verdict,
                *bounded_wait_secs,
                target_identity_digest.clone(),
                evidence_refs.clone(),
            )?;
            Ok(())
        }
        WatchdogSpoolPayload::ContainmentRequest {
            service,
            operation_id,
            recipe_digest,
            owner_epoch_digest,
            registration_digest,
            target_identity_digest,
            evidence_refs,
        } => {
            validate_service(service)?;
            if operation_id.is_empty() || operation_id.len() > MAX_ATTEMPT_OPERATION_ID_LEN {
                return Err(SpoolError::Corrupt(
                    "watchdog containment request operation identity is unusable".to_owned(),
                ));
            }
            for digest in [
                recipe_digest,
                owner_epoch_digest,
                registration_digest,
                target_identity_digest,
            ] {
                if !is_bounded_handle_text(digest) {
                    return Err(SpoolError::Corrupt(
                        "watchdog containment request target bound is unusable".to_owned(),
                    ));
                }
            }
            validate_evidence_refs(evidence_refs)?;
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Resolves one stored uncertainty code back to its closed variant.
fn stored_uncertainty(code: Option<&str>) -> Result<ChallengeUncertainty, SpoolError> {
    match code {
        Some("UNAUTHENTICATED") => Ok(ChallengeUncertainty::Unauthenticated),
        Some("CONNECTION_DENIED") => Ok(ChallengeUncertainty::ConnectionDenied),
        Some("TARGET_CHANGED") => Ok(ChallengeUncertainty::TargetChanged),
        Some("INADEQUATE_COVERAGE") => Ok(ChallengeUncertainty::InadequateCoverage),
        Some("TARGET_NOT_LIVE") => Ok(ChallengeUncertainty::TargetNotLive),
        _ => Err(SpoolError::Corrupt(
            "watchdog attempt record carries an unknown uncertainty code".to_owned(),
        )),
    }
}

/// Digest over one bounded observation's own content, used as evidence reference.
///
/// It is taken over the observation's canonical bytes through the owner clock
/// reading it already carries, so the reference binds what was observed instead
/// of a value this Watchdog restated about it.
#[must_use]
pub(crate) fn observation_evidence_ref(
    service: &str,
    state: &str,
    identity_digest: Option<&str>,
    wait_secs: u64,
) -> String {
    sha256_hex(
        format!(
            "watchdog-host-attempt-v1\0{service}\0{state}\0{}\0{wait_secs}",
            identity_digest.unwrap_or("-")
        )
        .as_bytes(),
    )
}

/// Default service identity these records carry.
#[must_use]
pub(crate) fn attempt_service() -> String {
    SERVICE_NAME.to_owned()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::host_identity_observation::{BoundedChallengeWait, MAX_CHALLENGE_WAIT_SECS};

    fn evidence(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    #[test]
    fn attempt_record_round_trips_and_refuses_forged_rows() {
        let record = HostAttemptRecord::new(
            attempt_service(),
            ChallengeAttemptOutcome::Uncertain(ChallengeUncertainty::InadequateCoverage),
            HostResponsiveness::Uncertain(ChallengeUncertainty::InadequateCoverage),
            MAX_CHALLENGE_WAIT_SECS,
            Some(evidence(0x11)),
            vec![evidence(0x0c), evidence(0x0d)],
        )
        .expect("attempt record");
        assert_eq!(record.verdict_code(), "UNCERTAIN");
        let payload = record.to_payload();
        check_stored_attempt_payload(500, &payload).expect("stored attempt is canonical");

        let forged = WatchdogSpoolPayload::HostAttempt {
            service: attempt_service(),
            attempt: "COMPETENT_TIMEOUT".to_owned(),
            uncertainty: Some("INADEQUATE_COVERAGE".to_owned()),
            verdict: "RESPONSIVE".to_owned(),
            bounded_wait_secs: 0,
            target_identity_digest: Some(evidence(0x11)),
            evidence_refs: vec![evidence(0x0c)],
        };
        assert!(check_stored_attempt_payload(500, &forged).is_err());
    }

    #[test]
    fn containment_request_refuses_unbounded_or_unusable_bounds() {
        let target = fixture_target();
        let record = ContainmentRequestRecord::from_target(
            attempt_service(),
            "operation-test".to_owned(),
            &target,
            vec![evidence(0x0c)],
        )
        .expect("containment request");
        check_stored_attempt_payload(600, &record.to_payload())
            .expect("stored request is canonical");

        let wait = BoundedChallengeWait::new(MAX_CHALLENGE_WAIT_SECS).expect("bounded wait");
        assert_eq!(wait.timeout_secs(), MAX_CHALLENGE_WAIT_SECS);
        assert!(
            HostAttemptRecord::new(
                attempt_service(),
                ChallengeAttemptOutcome::CompetentTimeout,
                HostResponsiveness::AliveUnresponsive,
                MAX_CHALLENGE_WAIT_SECS + 1,
                None,
                vec![evidence(0x0c)],
            )
            .is_err()
        );
        assert!(
            HostAttemptRecord::new(
                attempt_service(),
                ChallengeAttemptOutcome::CompetentTimeout,
                HostResponsiveness::Uncertain(ChallengeUncertainty::TargetNotLive),
                1,
                None,
                vec![evidence(0x0c)],
            )
            .is_err()
        );
    }

    /// I8.3 acceptance: a bounded Host attempt and a pre-authorized
    /// containment request each land in the Watchdog's own `watchdog.redb` with
    /// their evidence references and timestamp, travel inside their export
    /// window under the existing `Recovery` class, and are never compaction
    /// candidates below an acknowledged cursor so later canonical
    /// reconciliation can still read them.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the acceptance proof reads one journaled record back, checks its exact material, and then checks its export class and compaction status in one place"
    )]
    fn attempt_and_containment_records_land_in_watchdog_redb_and_survive_compaction() {
        use crate::watchdog_spool::{WatchdogSpool, watchdog_spool_path};
        use eliot_watchdog_core::{WatchdogSpoolCursor, WatchdogSpoolPayloadKind};

        let dir = std::env::temp_dir().join(format!(
            "eliot-watchdog-attempt-rows-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("attempt test state dir");
        let spool =
            WatchdogSpool::open_test(&watchdog_spool_path(&dir)).expect("open attempt spool");

        let target = fixture_target();
        let attempt_observed_at_ms = 4_000;
        let attempt = HostAttemptRecord::new(
            attempt_service(),
            ChallengeAttemptOutcome::Uncertain(ChallengeUncertainty::InadequateCoverage),
            HostResponsiveness::Uncertain(ChallengeUncertainty::InadequateCoverage),
            MAX_CHALLENGE_WAIT_SECS,
            Some(evidence(0x25)),
            vec![
                observation_evidence_ref(
                    attempt_service().as_str(),
                    "RUNNING",
                    Some(evidence(0x25).as_str()),
                    MAX_CHALLENGE_WAIT_SECS,
                ),
                observation_evidence_ref(
                    attempt_service().as_str(),
                    "UNKNOWN",
                    None,
                    MAX_CHALLENGE_WAIT_SECS,
                ),
            ],
        )
        .expect("bounded attempt record");
        let attempt_entry = spool
            .journal_host_attempt(attempt_observed_at_ms, &attempt)
            .expect("journal bounded attempt");

        let request_observed_at_ms = 4_001;
        let request = ContainmentRequestRecord::from_target(
            attempt_service(),
            "watchdog-recovery-operation-test".to_owned(),
            &target,
            vec![evidence(0x24), evidence(0x25)],
        )
        .expect("containment request record");
        let request_entry = spool
            .journal_containment_request(request_observed_at_ms, &request)
            .expect("journal containment request");

        // Both records are in the owner's own file, in sequence order, with
        // their evidence references and timestamps exactly as journaled.
        let entries = spool.readback().expect("read back attempt spool");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, attempt_entry.sequence);
        assert_eq!(entries[0].observed_at_ms, attempt_observed_at_ms);
        match &entries[0].payload {
            WatchdogSpoolPayload::HostAttempt {
                attempt,
                uncertainty,
                verdict,
                bounded_wait_secs,
                evidence_refs,
                ..
            } => {
                assert_eq!(attempt, "UNCERTAIN");
                // The named uncertainty travels verbatim: an attempt that
                // resolved nothing is never collapsed into a bare timeout.
                assert_eq!(uncertainty.as_deref(), Some("INADEQUATE_COVERAGE"));
                assert_eq!(verdict, "UNCERTAIN");
                assert_eq!(*bounded_wait_secs, MAX_CHALLENGE_WAIT_SECS);
                assert_eq!(evidence_refs.len(), 2);
            }
            other => panic!("expected a Host attempt record, found {other:?}"),
        }
        assert_eq!(entries[1].sequence, request_entry.sequence);
        assert_eq!(entries[1].observed_at_ms, request_observed_at_ms);
        match &entries[1].payload {
            WatchdogSpoolPayload::ContainmentRequest {
                operation_id,
                recipe_digest,
                target_identity_digest,
                evidence_refs,
                ..
            } => {
                assert_eq!(operation_id, "watchdog-recovery-operation-test");
                assert_eq!(recipe_digest, target.recipe_digest.as_str());
                assert_eq!(target_identity_digest, target.identity_digest.as_str());
                assert_eq!(evidence_refs, &vec![evidence(0x24), evidence(0x25)]);
            }
            other => panic!("expected a containment request record, found {other:?}"),
        }
        assert!(is_forensically_linked_payload(&entries[0].payload));
        assert!(is_forensically_linked_payload(&entries[1].payload));

        // Both travel inside one bounded export window under the existing
        // owner-neutral `Recovery` class; the shared class is not widened.
        let predecessor = WatchdogSpoolCursor {
            schema_version: 1,
            acknowledged_sequence: 0,
            watchdog_generation: 7,
            watchdog_epoch: 3,
            installation_id: "installation-test".to_owned(),
            sink_id: "sink-test".to_owned(),
        };
        let high_water = spool.high_water_sequence().expect("attempt high-water");
        assert_eq!(high_water, 2);
        let (batch, raws) = spool
            .export_batch(
                &predecessor,
                high_water,
                crate::WatchdogSpoolExportLimits::default(),
            )
            .expect("export carries both records");
        assert_eq!(batch.entries.len(), 2);
        assert!(
            batch
                .entries
                .iter()
                .all(|entry| entry.payload_kind == WatchdogSpoolPayloadKind::Recovery)
        );
        assert_eq!(raws.len(), 2);

        // Compaction below the acknowledged cursor never selects either, even
        // though the cursor is past them: the later canonical reconciliation has
        // to be readable against both, and retention-pressure eviction is the
        // only thing that may drop them.
        assert!(
            !super::super::compaction_plan(&entries, 2).contains(&attempt_entry.sequence),
            "a journalled Host attempt became a compaction candidate"
        );
        assert!(
            !super::super::compaction_plan(&entries, 2).contains(&request_entry.sequence),
            "a journalled containment request became a compaction candidate"
        );

        drop(spool);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn fixture_target() -> RecoveryTarget {
        let handle =
            |byte: u8| eliot_platform::PlatformHandle::new(evidence(byte)).expect("bound handle");
        RecoveryTarget {
            registration: handle(0x21),
            generation: handle(0x22),
            owner_epoch: handle(0x23),
            recipe_digest: handle(0x24),
            identity_digest: handle(0x25),
        }
    }
}
