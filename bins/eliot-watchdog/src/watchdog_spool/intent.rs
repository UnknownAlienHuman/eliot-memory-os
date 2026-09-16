//! Watchdog-owned intent records for Governor-unavailable reconciliation.
//!
//! Architecture: ARCH-MOD-01, ARCH-MOD-02, ARCH-PORT-01, ARCH-WDG-01.
//! Implementation: I8.1, I8.2, I2.23.
//! I8.1 direct binding: canonical Problem/Incident transitions are performed
//! by the Governor. When the Governor is unavailable, the Watchdog writes
//! `problem_intent` / `incident_intent` records into its own physically
//! separate minimal spool (`watchdog.redb`) for later reconciliation. The
//! records reuse the same restricted non-semantic envelope shape as the ORS
//! owner (`RecoveryPayloadEnvelope`: sha256 payload/record/batch digests over
//! timestamp-free material) but are never stored in the Kernel ORS failure
//! domain (`kernel-ors.redb`) or the host journal
//! (`host-state-journal.redb`), which stay readback-only from this lane.
//!
//! Case-(b) construction: the shared owner-neutral export classes
//! (`WatchdogSpoolPayloadKind` in `eliot-watchdog-core`, mirrored by the
//! Governor `WatchdogEntryKind` and consumed exhaustively by the eliotd
//! adapter) are intentionally NOT extended here — out-of-lane exhaustive
//! matches without a wildcard would break (see the MGR02 handoff). Intent
//! records are spool-local types persisted as new `WatchdogSpoolPayload`
//! variants through the existing spool tables, batch builder, and digests,
//! and export under the existing `Recovery` (gap-like) class, so ordering,
//! retention, and the terminal disposition table are unchanged. Governor-side
//! kind admission and any new named mutation are slice 2 (MGR02 handoff).

use super::codec::WatchdogSpoolPayload;
use crate::{GapRecoveryReason, SERVICE_NAME, SpoolError};

/// Schema revision of the spool-local intent record shape.
///
/// Bumped only by an explicit review that re-checks the canonical-semantics
/// firewall documented on the record types below.
pub(crate) const INTENT_SCHEMA_VERSION: u16 = 1;

const _: () = assert!(INTENT_SCHEMA_VERSION == 1);

/// Maximum number of evidence references carried by one intent record.
///
/// Sixteen 64-hex digests bound the record far below
/// `SPOOL_MAX_RECORD_BYTES` while leaving room for more than one
/// corroborating observation.
pub(crate) const MAX_INTENT_EVIDENCE_REFS: usize = 16;

const _: () = assert!(MAX_INTENT_EVIDENCE_REFS == 16);

/// Maximum accepted length of the intent lineage installation identity.
///
/// Mirrors `SPOOL_EXPORT_CURSOR_IDENTITY_MAX` so intent lineage never exceeds
/// the cursor identity frame it reconciles against.
pub(crate) const MAX_INTENT_LINEAGE_ID_LEN: usize = 1024;

const _: () = assert!(MAX_INTENT_LINEAGE_ID_LEN == 1024);

/// Length of one lowercase or uppercase hex SHA-256 evidence digest.
const SHA256_HEX_LEN: usize = 64;

/// True for an opaque caller-supplied digest with exact SHA-256 hex shape.
fn is_sha256_hex_shape(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Watchdog-owned lineage bound to one intent record.
///
/// Carries only the owner identities the export cursor already binds
/// (installation, generation, epoch) so a later reconciliation can place the
/// intent without inventing authority. Every field is private and [`IntentLineage::new`]
/// is the only construction path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IntentLineage {
    installation_id: String,
    watchdog_generation: u64,
    watchdog_epoch: u64,
}

impl IntentLineage {
    /// Binds one intent lineage; fails closed on blank, oversized, or
    /// uninitialized identities.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the installation identity is empty
    /// or exceeds the bounded frame, or the generation is uninitialized.
    pub(crate) fn new(
        installation_id: String,
        watchdog_generation: u64,
        watchdog_epoch: u64,
    ) -> Result<Self, SpoolError> {
        if installation_id.is_empty() || installation_id.len() > MAX_INTENT_LINEAGE_ID_LEN {
            return Err(SpoolError::Corrupt(
                "watchdog intent lineage installation identity is unusable".to_owned(),
            ));
        }
        if watchdog_generation == 0 {
            return Err(SpoolError::Corrupt(
                "watchdog intent lineage generation is uninitialized".to_owned(),
            ));
        }
        Ok(Self {
            installation_id,
            watchdog_generation,
            watchdog_epoch,
        })
    }
}

/// Proof that the Governor admission path is unavailable, gating intent append.
///
/// The type has no "available" state by construction: the only constructor
/// accepts the bounded unavailability reasons the gap path already owns and
/// rejects [`GapRecoveryReason::SpoolPressure`], which is retention pressure,
/// not Governor unavailability. A caller holding a live Governor admission
/// has no value of this type to pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GovernorUnavailability {
    reason: GapRecoveryReason,
}

impl GovernorUnavailability {
    /// Admits one Governor-unavailable reason; fails closed on retention
    /// pressure, which must never mint an intent.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when `reason` is
    /// [`GapRecoveryReason::SpoolPressure`].
    pub(crate) fn admission_unavailable(reason: GapRecoveryReason) -> Result<Self, SpoolError> {
        if reason == GapRecoveryReason::SpoolPressure {
            return Err(SpoolError::Corrupt(
                "watchdog spool pressure is not Governor unavailability; refusing to mint an intent"
                    .to_owned(),
            ));
        }
        Ok(Self { reason })
    }

    /// Returns the bounded unavailability reason carried by this proof.
    #[must_use]
    pub(crate) const fn reason(self) -> GapRecoveryReason {
        self.reason
    }
}

/// Shared bounds for both intent record shapes: watchdog-owned service, one or
/// more hex evidence digests, and an initialized observation timestamp.
fn validate_intent_fields(
    service: &str,
    evidence_refs: &[String],
    observed_at_ms: u64,
) -> Result<(), SpoolError> {
    if service != SERVICE_NAME {
        return Err(SpoolError::Corrupt(
            "watchdog intent record service is not the watchdog owner".to_owned(),
        ));
    }
    if evidence_refs.is_empty() || evidence_refs.len() > MAX_INTENT_EVIDENCE_REFS {
        return Err(SpoolError::Corrupt(
            "watchdog intent record carries no usable evidence reference".to_owned(),
        ));
    }
    if !evidence_refs
        .iter()
        .all(|digest| is_sha256_hex_shape(digest))
    {
        return Err(SpoolError::Corrupt(
            "watchdog intent evidence reference is not a 64-character hex digest".to_owned(),
        ));
    }
    if observed_at_ms == 0 {
        return Err(SpoolError::Corrupt(
            "watchdog intent observation timestamp is uninitialized".to_owned(),
        ));
    }
    Ok(())
}

/// Spool-local problem intent: evidence refs plus lineage, no semantics.
///
/// Compile-time canonical-semantics firewall (I8.1 "Watchdog does not own"):
/// this record exposes no Current Epistemic Position, task-decision,
/// module-repair, Architecture-change, completion, or model/swarm-budget
/// field by construction. Every field is private and [`ProblemIntentRecord::new`]
/// accepts only `(proof, service, evidence_refs, lineage, observed_at_ms)`; a
/// forbidden category cannot be smuggled through a struct literal outside this
/// module, and any new field requires editing this module plus bumping
/// `INTENT_SCHEMA_VERSION`, which the `const` assertion above pins. No runtime
/// string scan is relied upon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProblemIntentRecord {
    service: String,
    evidence_refs: Vec<String>,
    lineage: IntentLineage,
    observed_at_ms: u64,
    governor_unavailable_reason: GapRecoveryReason,
}

impl ProblemIntentRecord {
    /// Mints one problem intent under a Governor-unavailable proof; fails
    /// closed on any bound violation.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the service, evidence refs,
    /// lineage, or timestamp fail [`validate_intent_fields`] or the lineage
    /// is unusable.
    pub(crate) fn new(
        proof: GovernorUnavailability,
        service: String,
        evidence_refs: Vec<String>,
        lineage: IntentLineage,
        observed_at_ms: u64,
    ) -> Result<Self, SpoolError> {
        validate_intent_fields(&service, &evidence_refs, observed_at_ms)?;
        Ok(Self {
            service,
            evidence_refs,
            lineage,
            observed_at_ms,
            governor_unavailable_reason: proof.reason(),
        })
    }

    /// Projects this record onto its spool payload for [`super::WatchdogSpool::append`].
    pub(crate) fn to_payload(&self) -> WatchdogSpoolPayload {
        WatchdogSpoolPayload::ProblemIntent {
            service: self.service.clone(),
            evidence_refs: self.evidence_refs.clone(),
            lineage_installation_id: self.lineage.installation_id.clone(),
            lineage_generation: self.lineage.watchdog_generation,
            lineage_epoch: self.lineage.watchdog_epoch,
            governor_unavailable_reason: self.governor_unavailable_reason,
        }
    }
}

/// Spool-local incident intent: evidence refs plus lineage, no semantics.
///
/// Same compile-time canonical-semantics firewall as [`ProblemIntentRecord`]:
/// private fields, sole proof-gated constructor, schema pinned by
/// `INTENT_SCHEMA_VERSION`. No runtime string scan is relied upon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IncidentIntentRecord {
    service: String,
    evidence_refs: Vec<String>,
    lineage: IntentLineage,
    observed_at_ms: u64,
    governor_unavailable_reason: GapRecoveryReason,
}

impl IncidentIntentRecord {
    /// Mints one incident intent under a Governor-unavailable proof; fails
    /// closed on any bound violation.
    ///
    /// # Errors
    ///
    /// Returns [`SpoolError::Corrupt`] when the service, evidence refs,
    /// lineage, or timestamp fail [`validate_intent_fields`] or the lineage
    /// is unusable.
    pub(crate) fn new(
        proof: GovernorUnavailability,
        service: String,
        evidence_refs: Vec<String>,
        lineage: IntentLineage,
        observed_at_ms: u64,
    ) -> Result<Self, SpoolError> {
        validate_intent_fields(&service, &evidence_refs, observed_at_ms)?;
        Ok(Self {
            service,
            evidence_refs,
            lineage,
            observed_at_ms,
            governor_unavailable_reason: proof.reason(),
        })
    }

    /// Projects this record onto its spool payload for [`super::WatchdogSpool::append`].
    pub(crate) fn to_payload(&self) -> WatchdogSpoolPayload {
        WatchdogSpoolPayload::IncidentIntent {
            service: self.service.clone(),
            evidence_refs: self.evidence_refs.clone(),
            lineage_installation_id: self.lineage.installation_id.clone(),
            lineage_generation: self.lineage.watchdog_generation,
            lineage_epoch: self.lineage.watchdog_epoch,
            governor_unavailable_reason: self.governor_unavailable_reason,
        }
    }
}

/// Revalidates one stored intent payload against the constructor bounds.
///
/// Heartbeat, Gap, and Recovery payloads pass through untouched. Intent
/// payloads are reconstructed through the proof-gated constructors and must
/// round-trip byte-equivalent, so a forged or non-canonical row fails closed
/// at the persistence boundary instead of entering the spool. Called from the
/// codec encode/decode paths, which own bounded structural validation.
pub(crate) fn check_stored_intent_payload(
    observed_at_ms: u64,
    payload: &WatchdogSpoolPayload,
) -> Result<(), SpoolError> {
    match payload {
        WatchdogSpoolPayload::Heartbeat { .. }
        | WatchdogSpoolPayload::Gap { .. }
        | WatchdogSpoolPayload::Recovery { .. } => Ok(()),
        WatchdogSpoolPayload::ProblemIntent {
            service,
            evidence_refs,
            lineage_installation_id,
            lineage_generation,
            lineage_epoch,
            governor_unavailable_reason,
        } => {
            let proof = GovernorUnavailability::admission_unavailable(*governor_unavailable_reason)?;
            let lineage = IntentLineage::new(
                lineage_installation_id.clone(),
                *lineage_generation,
                *lineage_epoch,
            )?;
            let record = ProblemIntentRecord::new(
                proof,
                service.clone(),
                evidence_refs.clone(),
                lineage,
                observed_at_ms,
            )?;
            if record.to_payload() != *payload {
                return Err(SpoolError::Corrupt(
                    "watchdog problem intent payload is not in canonical form".to_owned(),
                ));
            }
            Ok(())
        }
        WatchdogSpoolPayload::IncidentIntent {
            service,
            evidence_refs,
            lineage_installation_id,
            lineage_generation,
            lineage_epoch,
            governor_unavailable_reason,
        } => {
            let proof = GovernorUnavailability::admission_unavailable(*governor_unavailable_reason)?;
            let lineage = IntentLineage::new(
                lineage_installation_id.clone(),
                *lineage_generation,
                *lineage_epoch,
            )?;
            let record = IncidentIntentRecord::new(
                proof,
                service.clone(),
                evidence_refs.clone(),
                lineage,
                observed_at_ms,
            )?;
            if record.to_payload() != *payload {
                return Err(SpoolError::Corrupt(
                    "watchdog incident intent payload is not in canonical form".to_owned(),
                ));
            }
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::super::{WatchdogSpool, watchdog_spool_path};
    use super::*;
    use crate::{SpoolAppendOutcome, WatchdogSpoolExportLimits};
    use eliot_watchdog_core::{WatchdogSpoolCursor, WatchdogSpoolPayloadKind};

    fn evidence_ref(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn test_proof() -> GovernorUnavailability {
        GovernorUnavailability::admission_unavailable(GapRecoveryReason::AdmissionUnavailable)
            .expect("Governor-unavailable proof")
    }

    fn test_lineage() -> IntentLineage {
        IntentLineage::new("installation-test".to_owned(), 7, 3).expect("intent lineage")
    }

    fn temp_root(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("eliot-watchdog-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("intent test state dir");
        dir
    }

    #[test]
    fn intent_rows_land_in_watchdog_redb_and_export_as_recovery() {
        let dir = temp_root("intent-rows");
        let spool = WatchdogSpool::open_test(&dir.join("watchdog.redb")).expect("open intent spool");
        let proof = test_proof();
        let observed_problem = 1_000;
        let problem = ProblemIntentRecord::new(
            proof, SERVICE_NAME.to_owned(), vec![evidence_ref(0x0c), evidence_ref(0x0d)],
            test_lineage(), observed_problem,
        ).expect("problem intent");
        assert!(matches!(
            spool.append(observed_problem, problem.to_payload()).expect("append problem intent"),
            SpoolAppendOutcome::Stored
        ));
        let observed_incident = 2_000;
        let incident = IncidentIntentRecord::new(
            proof, SERVICE_NAME.to_owned(), vec![evidence_ref(0x0e)], test_lineage(), observed_incident,
        ).expect("incident intent");
        assert!(matches!(
            spool.append(observed_incident, incident.to_payload()).expect("append incident intent"),
            SpoolAppendOutcome::Stored
        ));
        let entries = spool.readback().expect("intent readback");
        assert_eq!(entries.len(), 2);
        assert!(matches!(&entries[0].payload, WatchdogSpoolPayload::ProblemIntent {
            evidence_refs, lineage_installation_id, lineage_generation, lineage_epoch,
            governor_unavailable_reason, ..
        } if evidence_refs.len() == 2 && lineage_installation_id == "installation-test"
            && *lineage_generation == 7 && *lineage_epoch == 3
            && *governor_unavailable_reason == GapRecoveryReason::AdmissionUnavailable));
        assert_eq!(entries[0].observed_at_ms, observed_problem);
        assert!(matches!(&entries[1].payload, WatchdogSpoolPayload::IncidentIntent { .. }));
        assert_eq!(entries[1].observed_at_ms, observed_incident);
        let predecessor = WatchdogSpoolCursor {
            schema_version: 1, acknowledged_sequence: 0, watchdog_generation: 7,
            watchdog_epoch: 3, installation_id: "installation-test".to_owned(),
            sink_id: "sink-test".to_owned(),
        };
        let high_water = spool.high_water_sequence().expect("intent high-water");
        let (batch, _) = spool.export_batch(&predecessor, high_water, WatchdogSpoolExportLimits::default())
            .expect("export intents");
        assert_eq!(batch.entries.len(), 2);
        assert!(batch.entries.iter().all(|entry| entry.payload_kind == WatchdogSpoolPayloadKind::Recovery));
        assert!(GovernorUnavailability::admission_unavailable(GapRecoveryReason::SpoolPressure).is_err());
        drop(spool);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn intent_bytes_touch_only_watchdog_redb() {
        let dir = temp_root("intent-isolation");
        let kernel_path = dir.join("kernel-ors.redb");
        let journal_path = dir.join("host-state-journal.redb");
        std::fs::write(&kernel_path, b"kernel-sentinel").expect("kernel sentinel");
        std::fs::write(&journal_path, b"journal-sentinel").expect("journal sentinel");
        let spool_path = watchdog_spool_path(&dir);
        assert_eq!(spool_path, dir.join("watchdog.redb"));
        assert_ne!(spool_path, kernel_path);
        assert_ne!(spool_path, journal_path);
        let spool = WatchdogSpool::open_test(&spool_path).expect("open isolated spool");
        let intent = ProblemIntentRecord::new(
            test_proof(), SERVICE_NAME.to_owned(), vec![evidence_ref(0x1c)], test_lineage(), 3_000,
        ).expect("isolated intent");
        assert!(matches!(
            spool.append(3_000, intent.to_payload()).expect("append isolated intent"),
            SpoolAppendOutcome::Stored
        ));
        drop(spool);
        assert_eq!(std::fs::read(&kernel_path).expect("kernel reread"), b"kernel-sentinel");
        assert_eq!(std::fs::read(&journal_path).expect("journal reread"), b"journal-sentinel");
        let probe = WatchdogSpool::open_test(&spool_path).expect("reopen isolated spool");
        let entries = probe.readback().expect("isolated readback");
        assert_eq!(entries.len(), 1);
        assert!(matches!(entries[0].payload, WatchdogSpoolPayload::ProblemIntent { .. }));
        drop(probe);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
