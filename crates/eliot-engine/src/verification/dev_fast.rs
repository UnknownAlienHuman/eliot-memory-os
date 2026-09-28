//! Canonical `dev-fast` governed evidence commit path (issue #1802, I18.6
//! step 9).
//!
//! This edge commits one [`VerificationProfileRun`] with its bound
//! [`TestSelectionReceipt`] through the existing evidence owner, the
//! content-addressed [`BlobStore`] the governed profile lane already
//! persists run and aggregate records to. Assembly binds raw retained
//! output references, executable/argv/configuration identity, stage
//! outcomes, and the receipt into the single record; a receipt or
//! aggregate for another configuration at the same source revision is
//! refused before anything persists. When no store is supplied the
//! assembled record is returned with pending publication instead of
//! failing the run.
//!
//! Readback verifies the admitted record version and the record digest
//! before trusting a deserialized record. Replay resolves a lost
//! acknowledgement against the retained inputs and returns the retained
//! record; it takes no store, executor, or launcher, so it starts no
//! process and reruns no build/test effect.
//!
//! No process launches here and no task completes here: execution
//! provisions belong to the Kernel/`testd` composition roots, evidence
//! admission to the Governor, and completion to `FinishService`.

use eliot_instrument_runner::{
    DevFastCandidate, ProfileAggregate, TestSelectionReceipt, VERIFICATION_PROFILE_RUN_VERSION,
    VerificationProfileRun, dev_fast_replay,
};
use eliot_store::BlobStore;
use eliot_types::BlobRef;

use super::rejected;
use crate::EngineError;

/// One committed `dev-fast` profile run with its evidence-owner handles.
#[derive(Clone, Debug)]
pub struct DevFastEvidenceCommit {
    /// Assembled profile-run record bound to its aggregate and receipt.
    pub run: VerificationProfileRun,
    /// Canonical handle of the persisted record, when a store was supplied.
    pub record_blob: Option<BlobRef>,
    /// Canonical handle of the persisted receipt, when a store was supplied.
    pub receipt_blob: Option<BlobRef>,
}

/// Governed `dev-fast` evidence commit behind the verify entries.
pub struct DevFastGovernedService;

impl DevFastGovernedService {
    /// Commits one `dev-fast` run with its receipt through the evidence
    /// owner.
    ///
    /// [`VerificationProfileRun::assemble`] binds the candidate,
    /// aggregate, receipt, and raw retained output references into the
    /// single record and refuses any aggregate or receipt that is not
    /// the admitted `dev-fast` revision bound to the observed complete
    /// candidate/configuration identity. The record and the receipt
    /// persist as canonical JSON through `blob_store` when supplied;
    /// without a store the commit keeps pending publication and still
    /// returns the assembled record. Identical input always yields
    /// identical persisted bytes.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when assembly refuses the inputs or blob
    /// persistence fails.
    pub fn commit_run(
        &self,
        candidate: &DevFastCandidate,
        aggregate: &ProfileAggregate,
        receipt: &TestSelectionReceipt,
        raw_refs: Vec<String>,
        slice: &str,
        blob_store: Option<&BlobStore>,
    ) -> Result<DevFastEvidenceCommit, EngineError> {
        let run = VerificationProfileRun::assemble(candidate, aggregate, receipt, raw_refs, slice)
            .map_err(|error| rejected("dev-fast", &error.to_string()))?;
        let record_blob = match blob_store {
            Some(store) => Some(store.put_bytes(&serde_json::to_vec(&run)?)?),
            None => None,
        };
        let receipt_blob = match blob_store {
            Some(store) => Some(store.put_bytes(&serde_json::to_vec(receipt)?)?),
            None => None,
        };
        Ok(DevFastEvidenceCommit {
            run,
            record_blob,
            receipt_blob,
        })
    }

    /// Reads one committed record back from the evidence owner.
    ///
    /// The bytes are verified against their content address, then the
    /// record must carry the admitted record version and a digest that
    /// still binds its fields; anything else fails here instead of
    /// travelling on as retained evidence.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the handle cannot be read or verified,
    /// the bytes are not the admitted record shape, or the record digest
    /// does not bind its fields.
    pub fn read_record(
        &self,
        blob_store: &BlobStore,
        record: &BlobRef,
    ) -> Result<VerificationProfileRun, EngineError> {
        let bytes = blob_store.read_verified(record)?;
        let run: VerificationProfileRun = serde_json::from_slice(&bytes)?;
        if run.version != VERIFICATION_PROFILE_RUN_VERSION {
            return Err(rejected(
                "dev-fast",
                "profile run record is not the admitted record version",
            ));
        }
        run.check_digest()
            .map_err(|error| rejected("dev-fast", &error.to_string()))?;
        Ok(run)
    }

    /// Replays the retained run without starting any process.
    ///
    /// The retained record resolves against the retained candidate,
    /// aggregate, and receipt: when they name this exact record the
    /// retained record itself is the answer. This takes no store,
    /// executor, or launcher, so replay cannot rerun build/test effects
    /// to reconstruct an answer.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError`] when the retained inputs do not resolve
    /// the retained record.
    pub fn replay_run(
        &self,
        retained: &VerificationProfileRun,
        candidate: &DevFastCandidate,
        aggregate: &ProfileAggregate,
        receipt: &TestSelectionReceipt,
    ) -> Result<VerificationProfileRun, EngineError> {
        dev_fast_replay(retained, candidate, aggregate, receipt)
            .map_err(|error| rejected("dev-fast", &error.to_string()))
    }
}
