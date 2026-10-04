//! Owner-side typed load and compare-and-swap publication for the Human
//! model preference policy (issue #485, audit 5872395796 steps 2-4).
//!
//! Owner: `eliot-host-state`. The schema stays where step 1 put it
//! (`eliot-agent-contracts::model_preference`, I/O-free); the pure validator
//! stays in `eliot-config` (no I/O added there); the A-02 coordinator only
//! consumes the published policy. This crate durably publishes exactly one
//! versioned preference document per configured store file and arbitrates
//! every replacement against the exact current store/policy identity inside
//! one redb write transaction. redb takes an exclusive OS file lock and
//! serializes writers across processes, so the read/compare/commit section
//! is a genuine interprocess CAS: no new mutex, `&mut` handle, or
//! last-writer-wins file overwrite stands in for it.
//!
//! Semantics owned here are purely mechanical: absolute-path and
//! symlink/reparse guards, versioned-envelope classification, byte-size
//! bound, identity/digest equality, and monotonically checked store-revision
//! advance. Policy meaning (roles, selectors, billing) is interpreted only
//! by the contract owner through
//! [`HumanModelPreferencePolicy::validate`](eliot_agent_contracts::model_preference::HumanModelPreferencePolicy::validate)
//! and
//! [`preference_policy_digest`](eliot_agent_contracts::model_preference::preference_policy_digest);
//! this module never branches on preference content.
//!
//! Residuals: none in this module. R4 reconstructs the immutable
//! publication receipt from the retained committed document via
//! [`ModelPreferenceStore::read_publication_receipt`]; R5 wires the #484
//! candidate-side CAS anchor to this owner recheck via
//! [`PreferenceCasExpected::from_candidate_anchor`].
//!
//! Production caller: the daemon submit leg
//! (`bins/eliotd/src/daemon_runtime.rs::submit_replace_preference_policy_candidate`)
//! reaches every operation here through the settings-owner publisher
//! (`bins/eliotd/src/capability_admission.rs::publish_replace_preference_policy_candidate`):
//! [`ModelPreferenceStore::load_model_preferences`] (fresh predecessor
//! re-read), [`PreferenceCasExpected::from_candidate_anchor`] (candidate triple
//! pinned against that fresh load),
//! [`ModelPreferenceStore::compare_and_swap_model_preferences`] (atomic
//! predecessor recheck inside the committing write transaction), and
//! [`ModelPreferenceStore::read_publication_receipt`] (immutable receipt
//! rebuilt from the retained committed document).
//!
//! Callers (CHECK R1, audit 5872395796): the policy schema lives at
//! `crates/agent/eliot-agent-contracts/src/model_preference.rs`
//! ([`HumanModelPreferencePolicy::validate`](eliot_agent_contracts::model_preference::HumanModelPreferencePolicy::validate),
//! [`preference_policy_digest`](eliot_agent_contracts::model_preference::preference_policy_digest));
//! it is re-exported for A-02 consumption at
//! `crates/agent/eliot-agent-coordinator/src/model_control.rs`
//! (catalogue-dependent matching stays there). The candidate-side CAS anchor
//! lives at
//! `crates/agent/eliot-agent-coordinator/src/swarm_command_candidate.rs`
//! (`SwarmCommandKind::ReplacePreferencePolicy::{expected_policy_id,
//! expected_policy_revision, expected_policy_digest}`, compiled by
//! `compile_replace_policy_candidate`); the authenticated submitter is
//! `crates/surfaces/eliot-controlboard/src/swarm_command.rs`
//! (`ControlBoard::swarm_command_candidate`,
//! `OperatorAction::ReplaceSwarmPolicy`). This owner never imports either
//! crate: the anchor crosses as three plain strings, and A-02/A-08 read back
//! the committed document through the receipt below.
//!
//! Critical-section discipline (step 3): the CAS opens the store with a
//! single open-or-create, then performs the entire predecessor re-read,
//! identity compare, and staged commit inside one redb write transaction,
//! so two publishers against one predecessor cannot both commit. Replay
//! stages no write and aborts instead of committing. Retained table values
//! are length-checked before any heap copy, so an oversized value fails
//! closed during reading. Publication stages no temporary path, removes no
//! file, and inserts the replacement only after the byte-bound check: the
//! last valid document stays retained until the atomic commit lands.

use std::path::{Path, PathBuf};

use eliot_agent_contracts::{
    HumanModelPreferencePolicy, ModelControlError, preference_policy_digest,
};
use redb::{Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Magic of the preference store metadata envelope.
pub const MODEL_PREFERENCE_STORE_MAGIC: &str = "ELIOT-MODEL-PREFERENCE-STORE-V1";
/// Version of the preference store metadata and document envelopes.
pub const MODEL_PREFERENCE_ENVELOPE_VERSION: u16 = 1;
/// Largest retained preference document (envelope bytes) accepted on read
/// or offered for commit. Oversized input fails closed; it is never
/// truncated or partially applied.
pub const MAX_MODEL_PREFERENCE_DOCUMENT_BYTES: usize = 262_144;

const META_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_model_preference_meta_v1");
const PREFS_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_model_preferences_v1");
const META_KEY: &str = "meta";
const CURRENT_KEY: &str = "current";

/// Typed failure of preference load or compare-and-swap.
///
/// Every variant fails closed: stale, mismatched, corrupt, oversized, or
/// unknown-version input never commits, never invents a publication, and
/// never reports success.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelPreferenceStoreError {
    /// The store file or database backend is unavailable.
    #[error("model preference store is unavailable")]
    Unavailable,
    /// Stored bytes are not a valid versioned preference publication.
    #[error("model preference store is corrupt")]
    Corrupt,
    /// The retained or offered document exceeds the byte bound.
    #[error("model preference document exceeds the byte bound")]
    Oversized,
    /// The store carries an envelope version this owner does not publish.
    #[error("model preference store envelope version {version} is not supported")]
    Legacy { version: u16 },
    /// The expected predecessor identity does not match the retained
    /// publication. Includes the absent-store/nonzero-expectation case and
    /// the second-writer-loses case: the same expected predecessor with
    /// different replacement bytes commits at most once.
    #[error("model preference predecessor is stale")]
    Stale,
    /// The replacement changes the account scope of the retained policy.
    #[error("model preference replacement changes account scope")]
    ScopeMismatch,
    /// The replacement changes the policy ID of the retained policy.
    #[error("model preference replacement changes policy ID")]
    PolicyIdMismatch,
    /// The offered replacement policy is structurally invalid.
    #[error(transparent)]
    Policy(#[from] ModelControlError),
}

/// Validated read view of the retained preference publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelPreferencePublication {
    /// Monotonic store revision of the retained document. Genesis is 1;
    /// 0 never names a committed publication.
    pub store_revision: u64,
    /// The exact retained policy. Structural validity and digest match
    /// against `policy_digest` were both rechecked on load.
    pub policy: HumanModelPreferencePolicy,
    /// Canonical digest of `policy` recomputed by the owner on load, never
    /// copied from an unverified caller claim.
    pub policy_digest: String,
}

/// Exact expected predecessor identity for compare-and-swap.
///
/// Revision 0 with empty policy fields names the absent store (genesis
/// publication). Any other expectation must match the retained publication
/// field-for-field or the CAS fails closed with
/// [`ModelPreferenceStoreError::Stale`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreferenceCasExpected {
    /// Expected store revision of the retained document; 0 means the store
    /// must hold no publication.
    pub store_revision: u64,
    /// Expected policy ID of the retained document; empty for genesis.
    pub policy_id: String,
    /// Expected policy revision of the retained document; empty for genesis.
    pub policy_revision: String,
    /// Expected canonical digest of the retained document; empty for genesis.
    pub policy_digest: String,
}

impl PreferenceCasExpected {
    /// Genesis expectation: names the absent store (revision 0 with empty
    /// policy identity). Only a store holding no publication accepts it;
    /// anything retained fails closed with
    /// [`ModelPreferenceStoreError::Stale`].
    #[must_use]
    pub fn genesis() -> Self {
        Self {
            store_revision: 0,
            policy_id: String::new(),
            policy_revision: String::new(),
            policy_digest: String::new(),
        }
    }

    /// Builds the owner-side CAS expectation from the #484 candidate-side CAS
    /// anchor (`SwarmCommandKind::ReplacePreferencePolicy::{expected_policy_id,
    /// expected_policy_revision, expected_policy_digest}` in
    /// `crates/agent/eliot-agent-coordinator/src/swarm_command_candidate.rs`,
    /// submitted via `OperatorAction::ReplaceSwarmPolicy` in
    /// `crates/surfaces/eliot-controlboard/src/swarm_command.rs`) pinned
    /// against the publisher's freshly loaded publication.
    ///
    /// The anchor crosses as three plain strings: this owner never imports
    /// the coordinator or `ControlBoard` crates. An anchor that does not match
    /// the loaded predecessor field-for-field — including the absent-store /
    /// non-empty-anchor case — fails closed with
    /// [`ModelPreferenceStoreError::Stale`]. The store revision comes from the
    /// loaded publication, never from the candidate: the candidate carries no
    /// store revision. This check is view-time only; the atomic recheck
    /// happens inside
    /// [`ModelPreferenceStore::compare_and_swap_model_preferences`], which
    /// re-reads the predecessor in the committing write transaction, so a
    /// publisher that loses a race still observes `Stale` and the same
    /// expected identity with different replacement bytes commits at most
    /// once.
    pub fn from_candidate_anchor(
        current: Option<&ModelPreferencePublication>,
        expected_policy_id: &str,
        expected_policy_revision: &str,
        expected_policy_digest: &str,
    ) -> Result<Self, ModelPreferenceStoreError> {
        match current {
            None => {
                if expected_policy_id.is_empty()
                    && expected_policy_revision.is_empty()
                    && expected_policy_digest.is_empty()
                {
                    Ok(Self::genesis())
                } else {
                    Err(ModelPreferenceStoreError::Stale)
                }
            }
            Some(current) => {
                if expected_policy_id != current.policy.policy_id
                    || expected_policy_revision != current.policy.revision
                    || expected_policy_digest != current.policy_digest
                {
                    return Err(ModelPreferenceStoreError::Stale);
                }
                Ok(Self {
                    store_revision: current.store_revision,
                    policy_id: expected_policy_id.to_owned(),
                    policy_revision: expected_policy_revision.to_owned(),
                    policy_digest: expected_policy_digest.to_owned(),
                })
            }
        }
    }
}

/// Outcome of
/// [`ModelPreferenceStore::compare_and_swap_model_preferences`].
///
/// There are exactly two success shapes: a committed advance and an
/// identical replay. A replay performs no write and bumps no revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelPreferenceCasOutcome {
    /// The replacement committed as a new store revision.
    Committed {
        /// The newly committed store revision (predecessor + 1).
        store_revision: u64,
    },
    /// The replacement was canonically identical to the retained policy
    /// under a matching predecessor: idempotent, no write performed.
    Replayed {
        /// The retained store revision, unchanged.
        store_revision: u64,
    },
}

impl ModelPreferenceCasOutcome {
    /// The store revision this outcome leaves retained.
    #[must_use]
    pub const fn store_revision(self) -> u64 {
        match self {
            Self::Committed { store_revision } | Self::Replayed { store_revision } => {
                store_revision
            }
        }
    }
}

/// Immutable publication receipt for later A-02/A-08 readback (issue #485
/// R4, audit 5872395796 step 4).
///
/// The receipt carries the committed versioned-document identity: exact
/// policy identity (ID, revision, owner-recomputed digest), the monotonic
/// store revision, and the prior revision/digest link. Genesis carries prior
/// revision 0 and an empty prior digest. The receipt is constructed only by
/// this owner from the retained committed document (see
/// [`ModelPreferenceStore::read_publication_receipt`]), never manufactured
/// from caller fields or a bare path: after a restart the same receipt
/// reconstructs from the same retained bytes. It exposes no mutation API.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPreferencePublicationReceipt {
    /// Monotonic store revision of the committed document.
    pub store_revision: u64,
    /// Policy ID of the committed policy.
    pub policy_id: String,
    /// Policy revision of the committed policy.
    pub policy_revision: String,
    /// Owner-recomputed canonical digest of the committed policy.
    pub policy_digest: String,
    /// Store revision of the superseded document; 0 for genesis.
    pub prior_store_revision: u64,
    /// Canonical digest of the superseded document; empty for genesis.
    pub prior_policy_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreMeta {
    magic: String,
    version: u16,
}

/// The retained versioned preference document: exact policy, exact policy
/// digest, monotonically changing store revision, and the prior
/// revision/digest link. Genesis carries prior revision 0 and an empty
/// prior digest; every later document links its verified predecessor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredModelPreferenceEnvelope {
    /// Store magic. Must equal [`MODEL_PREFERENCE_STORE_MAGIC`].
    pub magic: String,
    /// Envelope version. Must equal [`MODEL_PREFERENCE_ENVELOPE_VERSION`].
    pub envelope_version: u16,
    /// Monotonic store revision. Genesis is 1; 0 never commits.
    pub store_revision: u64,
    /// Store revision of the superseded document; 0 for genesis.
    pub prior_store_revision: u64,
    /// Canonical policy digest of the superseded document; empty for genesis.
    pub prior_policy_digest: String,
    /// The exact published policy.
    pub policy: HumanModelPreferencePolicy,
    /// Owner-recomputed canonical digest of `policy`.
    pub policy_digest: String,
}

/// Owner handle for one configured preference store file.
///
/// Bound with [`ModelPreferenceStore::open`], which validates the
/// configured absolute path and existing-file shape but performs no
/// publication. Reads never create; the first committed publication mints
/// the file inside the genesis CAS. Parent directories are never created:
/// a missing parent fails closed with
/// [`ModelPreferenceStoreError::Unavailable`].
#[derive(Clone, Debug)]
pub struct ModelPreferenceStore {
    path: PathBuf,
}

fn validate_store_path(path: &Path) -> Result<PathBuf, ModelPreferenceStoreError> {
    if !path.is_absolute() {
        return Err(ModelPreferenceStoreError::Unavailable);
    }
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ModelPreferenceStoreError::Unavailable);
            }
        }
        Err(_) => return Err(ModelPreferenceStoreError::Unavailable),
    }
    Ok(path.to_path_buf())
}

fn map_database_error(error: &redb::DatabaseError) -> ModelPreferenceStoreError {
    match error {
        redb::DatabaseError::Storage(redb::StorageError::Corrupted(_)) => {
            ModelPreferenceStoreError::Corrupt
        }
        redb::DatabaseError::UpgradeRequired(version) => ModelPreferenceStoreError::Legacy {
            version: u16::from(*version),
        },
        _ => ModelPreferenceStoreError::Unavailable,
    }
}

/// Copies a retained table value into memory only after its length passes
/// the document byte bound, so an oversized value fails closed during
/// reading instead of forcing an unbounded heap allocation first.
fn copy_bounded_table_value(value: &[u8]) -> Result<Vec<u8>, ModelPreferenceStoreError> {
    if value.len() > MAX_MODEL_PREFERENCE_DOCUMENT_BYTES {
        return Err(ModelPreferenceStoreError::Oversized);
    }
    Ok(value.to_vec())
}

fn classify_meta(bytes: &[u8]) -> Result<(), ModelPreferenceStoreError> {
    if bytes.len() > MAX_MODEL_PREFERENCE_DOCUMENT_BYTES {
        return Err(ModelPreferenceStoreError::Oversized);
    }
    let meta: StoreMeta =
        serde_json::from_slice(bytes).map_err(|_| ModelPreferenceStoreError::Corrupt)?;
    if meta.magic != MODEL_PREFERENCE_STORE_MAGIC {
        return Err(ModelPreferenceStoreError::Corrupt);
    }
    if meta.version != MODEL_PREFERENCE_ENVELOPE_VERSION {
        return Err(ModelPreferenceStoreError::Legacy {
            version: meta.version,
        });
    }
    Ok(())
}

fn decode_envelope(
    bytes: &[u8],
) -> Result<StoredModelPreferenceEnvelope, ModelPreferenceStoreError> {
    if bytes.len() > MAX_MODEL_PREFERENCE_DOCUMENT_BYTES {
        return Err(ModelPreferenceStoreError::Oversized);
    }
    let envelope: StoredModelPreferenceEnvelope =
        serde_json::from_slice(bytes).map_err(|_| ModelPreferenceStoreError::Corrupt)?;
    if envelope.magic != MODEL_PREFERENCE_STORE_MAGIC
        || envelope.envelope_version != MODEL_PREFERENCE_ENVELOPE_VERSION
    {
        return Err(ModelPreferenceStoreError::Corrupt);
    }
    if envelope.store_revision == 0 {
        return Err(ModelPreferenceStoreError::Corrupt);
    }
    Ok(envelope)
}

fn validated_publication(
    envelope: StoredModelPreferenceEnvelope,
) -> Result<ModelPreferencePublication, ModelPreferenceStoreError> {
    envelope.policy.validate()?;
    let digest = preference_policy_digest(&envelope.policy)?;
    if digest != envelope.policy_digest {
        return Err(ModelPreferenceStoreError::Corrupt);
    }
    Ok(ModelPreferencePublication {
        store_revision: envelope.store_revision,
        policy: envelope.policy,
        policy_digest: envelope.policy_digest,
    })
}

/// Rebuilds the immutable publication receipt from an already decoded
/// retained envelope. The policy is revalidated and its digest recomputed by
/// the owner; a retained digest that does not match the retained policy
/// fails closed as corrupt. The prior revision/digest link is carried
/// verbatim from the committed document.
fn receipt_from_envelope(
    envelope: StoredModelPreferenceEnvelope,
) -> Result<ModelPreferencePublicationReceipt, ModelPreferenceStoreError> {
    envelope.policy.validate()?;
    let digest = preference_policy_digest(&envelope.policy)?;
    if digest != envelope.policy_digest {
        return Err(ModelPreferenceStoreError::Corrupt);
    }
    Ok(ModelPreferencePublicationReceipt {
        store_revision: envelope.store_revision,
        policy_id: envelope.policy.policy_id.clone(),
        policy_revision: envelope.policy.revision.clone(),
        policy_digest: envelope.policy_digest,
        prior_store_revision: envelope.prior_store_revision,
        prior_policy_digest: envelope.prior_policy_digest,
    })
}

/// Pending CAS envelope for a validated predecessor: genesis demands a
/// zero/empty expectation; a retained publication demands an exact
/// predecessor match with scope/policy continuity, then replay on identical
/// digest or the next-revision envelope. No I/O, no writes.
enum CasPendingEnvelope {
    /// Canonically identical replacement under a matching predecessor:
    /// idempotent, persists nothing.
    Replayed {
        /// The retained store revision, unchanged.
        store_revision: u64,
    },
    /// Fresh envelope to persist as the next store revision.
    Commit(Box<StoredModelPreferenceEnvelope>),
}

/// Decides the CAS envelope for `compare_and_swap_model_preferences`
/// without touching the store.
fn decide_cas_envelope(
    expected: &PreferenceCasExpected,
    replacement: &HumanModelPreferencePolicy,
    replacement_digest: &str,
    current: Option<ModelPreferencePublication>,
) -> Result<CasPendingEnvelope, ModelPreferenceStoreError> {
    match current {
        None => {
            if expected.store_revision != 0
                || !expected.policy_id.is_empty()
                || !expected.policy_revision.is_empty()
                || !expected.policy_digest.is_empty()
            {
                return Err(ModelPreferenceStoreError::Stale);
            }
            Ok(CasPendingEnvelope::Commit(Box::new(
                StoredModelPreferenceEnvelope {
                    magic: MODEL_PREFERENCE_STORE_MAGIC.to_owned(),
                    envelope_version: MODEL_PREFERENCE_ENVELOPE_VERSION,
                    store_revision: 1,
                    prior_store_revision: 0,
                    prior_policy_digest: String::new(),
                    policy: replacement.clone(),
                    policy_digest: replacement_digest.to_owned(),
                },
            )))
        }
        Some(current) => {
            if expected.store_revision != current.store_revision
                || expected.policy_id != current.policy.policy_id
                || expected.policy_revision != current.policy.revision
                || expected.policy_digest != current.policy_digest
            {
                return Err(ModelPreferenceStoreError::Stale);
            }
            if replacement.account_scope != current.policy.account_scope {
                return Err(ModelPreferenceStoreError::ScopeMismatch);
            }
            if replacement.policy_id != current.policy.policy_id {
                return Err(ModelPreferenceStoreError::PolicyIdMismatch);
            }
            if replacement_digest == current.policy_digest {
                return Ok(CasPendingEnvelope::Replayed {
                    store_revision: current.store_revision,
                });
            }
            let next = current
                .store_revision
                .checked_add(1)
                .ok_or(ModelPreferenceStoreError::Unavailable)?;
            Ok(CasPendingEnvelope::Commit(Box::new(
                StoredModelPreferenceEnvelope {
                    magic: MODEL_PREFERENCE_STORE_MAGIC.to_owned(),
                    envelope_version: MODEL_PREFERENCE_ENVELOPE_VERSION,
                    store_revision: next,
                    prior_store_revision: current.store_revision,
                    prior_policy_digest: current.policy_digest,
                    policy: replacement.clone(),
                    policy_digest: replacement_digest.to_owned(),
                },
            )))
        }
    }
}

impl ModelPreferenceStore {
    /// Binds this owner to one configured absolute store path.
    ///
    /// Unlike the journal's creating open, this performs no I/O beyond the
    /// path-shape check: no file, directory, table, or publication is
    /// created here. A relative path, a symlink or reparse point, or a
    /// non-file object fails closed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ModelPreferenceStoreError> {
        Ok(Self {
            path: validate_store_path(path.as_ref())?,
        })
    }

    /// The configured absolute store path this handle is bound to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the retained versioned document without interpreting it.
    ///
    /// Read-only: never creates a file, table, or publication. Returns
    /// `Ok(None)` only for explicit absence: a missing file, a missing
    /// metadata table, or a metadata envelope that was never initialized.
    /// A missing preferences table or current document against initialized
    /// metadata is corrupt, not absent. Retained values are length-checked
    /// before any heap copy.
    fn read_retained_envelope(
        &self,
    ) -> Result<Option<StoredModelPreferenceEnvelope>, ModelPreferenceStoreError> {
        validate_store_path(&self.path)?;
        let database = match ReadOnlyDatabase::open(&self.path) {
            Ok(database) => database,
            Err(error) => {
                if matches!(
                    error,
                    redb::DatabaseError::Storage(redb::StorageError::Io(ref io))
                        if io.kind() == std::io::ErrorKind::NotFound
                ) {
                    return Ok(None);
                }
                return Err(map_database_error(&error));
            }
        };
        let read = database
            .begin_read()
            .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
        let meta = match read.open_table(META_TABLE) {
            Ok(meta) => meta,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(_) => return Err(ModelPreferenceStoreError::Corrupt),
        };
        match meta
            .get(META_KEY)
            .map_err(|_| ModelPreferenceStoreError::Corrupt)?
        {
            None => return Ok(None),
            Some(guard) => {
                let bytes = copy_bounded_table_value(guard.value())?;
                classify_meta(&bytes)?;
            }
        }
        let prefs = match read.open_table(PREFS_TABLE) {
            Ok(prefs) => prefs,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Err(ModelPreferenceStoreError::Corrupt);
            }
            Err(_) => return Err(ModelPreferenceStoreError::Corrupt),
        };
        match prefs
            .get(CURRENT_KEY)
            .map_err(|_| ModelPreferenceStoreError::Corrupt)?
        {
            None => Err(ModelPreferenceStoreError::Corrupt),
            Some(guard) => {
                let bytes = copy_bounded_table_value(guard.value())?;
                decode_envelope(&bytes).map(Some)
            }
        }
    }

    /// Loads and validates the retained preference publication.
    ///
    /// Returns `Ok(None)` only for explicit absence: a missing file, or a
    /// reachable store whose metadata envelope was never initialized.
    /// Corrupt, oversized, unknown-version, digest-mismatched, or
    /// structurally invalid content fails closed; it is never returned
    /// as a publication.
    pub fn load_model_preferences(
        &self,
    ) -> Result<Option<ModelPreferencePublication>, ModelPreferenceStoreError> {
        match self.read_retained_envelope()? {
            None => Ok(None),
            Some(envelope) => validated_publication(envelope).map(Some),
        }
    }

    /// Reconstructs the immutable publication receipt from the retained
    /// committed document (issue #485 R4, audit 5872395796 step 4).
    ///
    /// Read-only like [`ModelPreferenceStore::load_model_preferences`]:
    /// after a restart the same retained bytes yield the same receipt, so
    /// A-02/A-08 read back what the owner committed, never a caller claim.
    /// Returns `Ok(None)` only for explicit absence; corrupt, oversized,
    /// unknown-version, digest-mismatched, or structurally invalid content
    /// fails closed. After a committed or replayed CAS, this is how the
    /// publisher obtains the receipt for the retained revision.
    pub fn read_publication_receipt(
        &self,
    ) -> Result<Option<ModelPreferencePublicationReceipt>, ModelPreferenceStoreError> {
        match self.read_retained_envelope()? {
            None => Ok(None),
            Some(envelope) => receipt_from_envelope(envelope).map(Some),
        }
    }

    /// Atomically compares the retained publication against the exact
    /// expected predecessor identity and, on match, publishes the full
    /// replacement as the next store revision.
    ///
    /// The read/compare/commit section runs inside one redb write
    /// transaction, which the backend serializes across processes: the
    /// predecessor is re-read from the same transaction that commits, so
    /// two writers against one predecessor cannot both commit and the
    /// loser observes [`ModelPreferenceStoreError::Stale`]. The stored
    /// policy digest and the replacement digest are always recomputed by
    /// the owner; caller-supplied digests are expectations to check, never
    /// values to retain.
    ///
    /// Genesis (first publication) requires
    /// `expected.store_revision == 0` with empty policy identity fields and
    /// a store holding no publication; anything else is
    /// [`ModelPreferenceStoreError::Stale`]. A non-genesis CAS requires
    /// the full expected triple plus policy ID to match the retained
    /// document, stable account scope and policy ID in the replacement,
    /// and commits revision predecessor + 1 with the prior revision/digest
    /// link. A canonically identical replacement under a matching
    /// predecessor replays without writing.
    ///
    /// The store handle opens with a single open-or-create (no
    /// check-then-create race: file minting is decided inside the same
    /// serialized write transaction that re-reads the predecessor), and
    /// retained values are length-checked before any heap copy. Replay
    /// aborts the write transaction instead of committing it; only a staged
    /// replacement reaches `commit`, after the byte-bound check, so the
    /// retained document is never displaced by an oversized write and no
    /// temporary path is staged or removed.
    ///
    /// The `expected` predecessor is built with
    /// [`PreferenceCasExpected::from_candidate_anchor`] from the #484
    /// candidate anchor pinned against a fresh
    /// [`ModelPreferenceStore::load_model_preferences`]; after a committed
    /// or replayed outcome the publisher reads the immutable receipt back
    /// with [`ModelPreferenceStore::read_publication_receipt`]. On
    /// [`ModelPreferenceStoreError::Stale`] the publisher reloads, re-pins,
    /// and retries: the atomic recheck inside this transaction is what makes
    /// the retry converge.
    pub fn compare_and_swap_model_preferences(
        &self,
        expected: &PreferenceCasExpected,
        replacement: &HumanModelPreferencePolicy,
    ) -> Result<ModelPreferenceCasOutcome, ModelPreferenceStoreError> {
        replacement.validate()?;
        let replacement_digest = preference_policy_digest(replacement)?;
        validate_store_path(&self.path)?;
        let database = Database::create(&self.path).map_err(|error| map_database_error(&error))?;
        let write = database
            .begin_write()
            .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
        let outcome = {
            let mut meta = write
                .open_table(META_TABLE)
                .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
            let mut prefs = write
                .open_table(PREFS_TABLE)
                .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
            let current_meta: Option<Vec<u8>> = meta
                .get(META_KEY)
                .map_err(|_| ModelPreferenceStoreError::Corrupt)?
                .map(|guard| copy_bounded_table_value(guard.value()))
                .transpose()?;
            let current = match current_meta {
                None => {
                    let meta_bytes = serde_json::to_vec(&StoreMeta {
                        magic: MODEL_PREFERENCE_STORE_MAGIC.to_owned(),
                        version: MODEL_PREFERENCE_ENVELOPE_VERSION,
                    })
                    .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
                    meta.insert(META_KEY, meta_bytes.as_slice())
                        .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
                    None
                }
                Some(bytes) => {
                    classify_meta(&bytes)?;
                    match prefs
                        .get(CURRENT_KEY)
                        .map_err(|_| ModelPreferenceStoreError::Corrupt)?
                    {
                        None => return Err(ModelPreferenceStoreError::Corrupt),
                        Some(guard) => {
                            let bytes = copy_bounded_table_value(guard.value())?;
                            Some(validated_publication(decode_envelope(&bytes)?)?)
                        }
                    }
                }
            };
            match decide_cas_envelope(expected, replacement, &replacement_digest, current)? {
                CasPendingEnvelope::Replayed { store_revision } => {
                    ModelPreferenceCasOutcome::Replayed { store_revision }
                }
                CasPendingEnvelope::Commit(envelope) => {
                    let bytes = serde_json::to_vec(&*envelope)
                        .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
                    if bytes.len() > MAX_MODEL_PREFERENCE_DOCUMENT_BYTES {
                        return Err(ModelPreferenceStoreError::Oversized);
                    }
                    prefs
                        .insert(CURRENT_KEY, bytes.as_slice())
                        .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
                    ModelPreferenceCasOutcome::Committed {
                        store_revision: envelope.store_revision,
                    }
                }
            }
        };
        if matches!(outcome, ModelPreferenceCasOutcome::Replayed { .. }) {
            drop(write);
            return Ok(outcome);
        }
        write
            .commit()
            .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
        Ok(outcome)
    }
}

/// In-crate proof of the owner's own refusal families (issue #485).
///
/// Every case here is a fixture over the production functions above; no
/// non-test line of this module is changed to make a case pass. The split is
/// deliberate: the caller-leg proof that a committed advance, a stale
/// predecessor and a restart readback all behave lives in
/// `bins/eliotd/src/daemon_runtime.rs::tests::model_preference_publication`,
/// and this module does NOT duplicate those three. What exists nowhere else,
/// and what this module owns, is the refusal half: the two refusals
/// (`ScopeMismatch`, `PolicyIdMismatch`) that are unreachable through any
/// production caller because
/// `crates/agent/eliot-agent-coordinator/src/swarm_command_candidate.rs`
/// refuses both before a candidate exists, plus the identity-only stale
/// digest, the byte bound on both the retained and the offered side, the
/// legacy/corrupt classification, the path refusals, and the interrupted
/// publication.
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::error::Error;
    use std::sync::atomic::{AtomicU64, Ordering};

    use eliot_agent_contracts::{
        BillingClass, MODEL_PREFERENCE_SCHEMA_VERSION, ModelRole, ModelSelector,
        RoleModelPreference,
    };

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    static NEXT: AtomicU64 = AtomicU64::new(0);

    /// A store path that no other case in this module can collide with, and
    /// that removes its own file when the case ends.
    struct TempStore {
        path: PathBuf,
    }

    impl TempStore {
        fn new(label: &str) -> TestResult<Self> {
            let n = NEXT.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            Ok(Self {
                path: std::env::temp_dir()
                    .join(format!("model-pref-{label}-{pid}-{nanos}-{n}.redb")),
            })
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn owner(&self) -> TestResult<ModelPreferenceStore> {
            Ok(ModelPreferenceStore::open(&self.path)?)
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn selector(model_id: &str) -> ModelSelector {
        ModelSelector {
            host_family: None,
            provider_id: None,
            model_id: Some(model_id.to_owned()),
            model_family: None,
        }
    }

    /// A structurally valid policy. `policy_id`, `revision` and
    /// `account_scope` are the three identity fields the CAS compares, so
    /// every case varies exactly the one it is about.
    fn policy(
        policy_id: &str,
        revision: &str,
        account_scope: &str,
        model_id: &str,
    ) -> HumanModelPreferencePolicy {
        HumanModelPreferencePolicy {
            schema_version: MODEL_PREFERENCE_SCHEMA_VERSION.to_owned(),
            policy_id: policy_id.to_owned(),
            revision: revision.to_owned(),
            account_scope: account_scope.to_owned(),
            roles: vec![RoleModelPreference {
                role: ModelRole::MainAgent,
                preferred: vec![selector(model_id)],
                denied: Vec::new(),
                allowed_billing: BTreeSet::from([BillingClass::SubscriptionIncluded]),
                allow_paid_fallback: false,
                allow_degraded_routes: false,
                minimum_context_window: 8_000,
                maximum_cost_class: 2,
                maximum_latency_class: 2,
                required_capabilities: BTreeSet::new(),
            }],
        }
    }

    /// Commits `policy` as the genesis publication of a fresh store and
    /// returns the owner plus the revision it committed at.
    fn committed_genesis(
        store: &ModelPreferenceStore,
        policy: &HumanModelPreferencePolicy,
    ) -> TestResult<u64> {
        let outcome =
            store.compare_and_swap_model_preferences(&PreferenceCasExpected::genesis(), policy)?;
        Ok(outcome.store_revision())
    }

    /// The expectation a publisher builds from a fresh load. Mirrors
    /// `PreferenceCasExpected::from_candidate_anchor` with the loaded
    /// publication's own identity.
    fn expectation_for(
        publication: &ModelPreferencePublication,
    ) -> TestResult<PreferenceCasExpected> {
        Ok(PreferenceCasExpected::from_candidate_anchor(
            Some(publication),
            &publication.policy.policy_id,
            &publication.policy.revision,
            &publication.policy_digest,
        )?)
    }

    /// `ModelPreferenceStore` deliberately derives no `PartialEq`, so a
    /// refused bind is asserted by shape rather than by comparing the whole
    /// `Result`.
    fn assert_bind_refused(path: &Path) {
        match ModelPreferenceStore::open(path) {
            Err(ModelPreferenceStoreError::Unavailable) => {}
            other => panic!("{path:?} must be refused as unavailable, got {other:?}"),
        }
    }

    /// `JoinHandle::join` returns `Box<dyn Any + Send>`, which is not an
    /// `Error`; a panicked writer thread is a fixture failure, not a result.
    fn join_writer<T>(handle: std::thread::JoinHandle<T>) -> TestResult<T> {
        Ok(handle.join().map_err(|_| "a writer thread panicked")?)
    }

    /// Absence is never an `expect` in this module: the workspace lint turns
    /// `expect_used` into a finding, and a missing publication is a fixture
    /// failure that must name itself rather than a panic message.
    fn retained_publication(
        store: &ModelPreferenceStore,
    ) -> TestResult<ModelPreferencePublication> {
        store
            .load_model_preferences()?
            .ok_or_else(|| Box::<dyn Error>::from("no publication is retained"))
    }

    /// The receipt reader's counterpart to [`retained_publication`].
    fn retained_receipt(
        store: &ModelPreferenceStore,
    ) -> TestResult<ModelPreferencePublicationReceipt> {
        store
            .read_publication_receipt()?
            .ok_or_else(|| Box::<dyn Error>::from("no publication receipt is retained"))
    }

    /// The retained document bytes; absence after a committed genesis is a
    /// fixture failure, not an `expect`.
    fn retained_document(path: &Path) -> TestResult<Vec<u8>> {
        retained_bytes(path)?.ok_or_else(|| Box::<dyn Error>::from("no retained document"))
    }

    /// One concurrent CAS writer bound to its own handle on the shared path.
    fn spawn_writer(
        path: PathBuf,
        expected: PreferenceCasExpected,
        replacement: HumanModelPreferencePolicy,
    ) -> std::thread::JoinHandle<Result<ModelPreferenceCasOutcome, ModelPreferenceStoreError>> {
        std::thread::spawn(move || {
            let owner = ModelPreferenceStore::open(&path)?;
            owner.compare_and_swap_model_preferences(&expected, &replacement)
        })
    }

    /// The raw retained document bytes, read behind this owner's back, so a
    /// case can assert that a refused or replayed call wrote nothing at all
    /// rather than only that it returned a value.
    fn retained_bytes(path: &Path) -> TestResult<Option<Vec<u8>>> {
        if std::fs::symlink_metadata(path).is_err() {
            return Ok(None);
        }
        let database = ReadOnlyDatabase::open(path)?;
        let read = database.begin_read()?;
        match read.open_table(PREFS_TABLE) {
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(error) => Err(Box::new(error)),
            Ok(prefs) => match prefs.get(CURRENT_KEY)? {
                None => Ok(None),
                Some(guard) => Ok(Some(guard.value().to_vec())),
            },
        }
    }

    /// Overwrites the retained metadata envelope, so a case can plant a
    /// version this owner does not publish.
    fn plant_meta(path: &Path, version: u16) -> TestResult {
        let database = Database::create(path)?;
        let write = database.begin_write()?;
        {
            let mut meta = write.open_table(META_TABLE)?;
            let bytes = serde_json::to_vec(&StoreMeta {
                magic: MODEL_PREFERENCE_STORE_MAGIC.to_owned(),
                version,
            })?;
            meta.insert(META_KEY, bytes.as_slice())?;
        }
        write.commit()?;
        Ok(())
    }

    /// Overwrites the retained document with arbitrary bytes, so a case can
    /// plant content the owner must refuse rather than interpret.
    fn plant_document(path: &Path, bytes: &[u8]) -> TestResult {
        let database = Database::create(path)?;
        let write = database.begin_write()?;
        {
            let mut prefs = write.open_table(PREFS_TABLE)?;
            prefs.insert(CURRENT_KEY, bytes)?;
        }
        write.commit()?;
        Ok(())
    }

    /// Encodes a document envelope exactly as the owner retains it.
    fn envelope_bytes(
        store_revision: u64,
        prior_store_revision: u64,
        prior_policy_digest: &str,
        policy: &HumanModelPreferencePolicy,
        policy_digest: &str,
    ) -> TestResult<Vec<u8>> {
        Ok(serde_json::to_vec(&StoredModelPreferenceEnvelope {
            magic: MODEL_PREFERENCE_STORE_MAGIC.to_owned(),
            envelope_version: MODEL_PREFERENCE_ENVELOPE_VERSION,
            store_revision,
            prior_store_revision,
            prior_policy_digest: prior_policy_digest.to_owned(),
            policy: policy.clone(),
            policy_digest: policy_digest.to_owned(),
        })?)
    }

    /// Exact replay is idempotent: the same predecessor and the same
    /// replacement bytes commit nothing and leave the retained document
    /// byte-identical, which is the distinction from a committed advance.
    #[test]
    fn exact_replay_is_idempotent_and_persists_nothing() -> TestResult {
        let store = TempStore::new("replay")?;
        let owner = store.owner()?;
        let first = policy("policy-a", "1", "account-a", "model-1");
        assert_eq!(
            owner.compare_and_swap_model_preferences(&PreferenceCasExpected::genesis(), &first)?,
            ModelPreferenceCasOutcome::Committed { store_revision: 1 }
        );
        let before = retained_bytes(store.path())?;

        let loaded = retained_publication(&owner)?;
        let expected = expectation_for(&loaded)?;
        let outcome = owner.compare_and_swap_model_preferences(
            &expected,
            &policy("policy-a", "1", "account-a", "model-1"),
        )?;
        assert_eq!(
            outcome,
            ModelPreferenceCasOutcome::Replayed { store_revision: 1 },
            "a canonically identical replacement under a matching predecessor replays"
        );
        assert_eq!(
            retained_bytes(store.path())?,
            before,
            "replay performs no write, so the retained document is unchanged"
        );
        assert_eq!(
            owner.load_model_preferences()?.map(|p| p.store_revision),
            Some(1),
            "replay bumps no revision"
        );
        Ok(())
    }

    /// Two writers against ONE predecessor commit at most once, and the
    /// loser never displaces the winner's document.
    ///
    /// Two shapes are proven deliberately and separately. The first is the
    /// deterministic identity proof: both writers hold the same expected
    /// predecessor and the second one is refused with
    /// [`ModelPreferenceStoreError::Stale`] exactly, because
    /// `decide_cas_envelope` compares all four identity fields. The second
    /// is genuinely concurrent: both threads call the CAS at once, and the
    /// invariant asserted is the one the owner documents — at most one
    /// `Committed`, the other fail-closed, and the retained document is the
    /// winner's. Which typed refusal the concurrent loser observes depends on
    /// whether redb 4.1.0 blocks on the exclusive lock or fails fast, which
    /// is not decidable from this repository; the invariant is asserted, and
    /// the exact variant is not guessed.
    #[test]
    fn two_writers_against_one_predecessor_commit_at_most_once() -> TestResult {
        let store = TempStore::new("two-writers")?;
        let owner = store.owner()?;
        committed_genesis(&owner, &policy("policy-a", "1", "account-a", "model-1"))?;
        let loaded = retained_publication(&owner)?;
        let expected = expectation_for(&loaded)?;

        // Deterministic half: the second writer against the SAME predecessor.
        let first_replacement = policy("policy-a", "2", "account-a", "model-2");
        let second_replacement = policy("policy-a", "2", "account-a", "model-3");
        assert_eq!(
            owner.compare_and_swap_model_preferences(&expected, &first_replacement)?,
            ModelPreferenceCasOutcome::Committed { store_revision: 2 }
        );
        let after_first = retained_bytes(store.path())?;
        assert_eq!(
            owner.compare_and_swap_model_preferences(&expected, &second_replacement),
            Err(ModelPreferenceStoreError::Stale),
            "the same expected predecessor with different replacement bytes commits at most once"
        );
        assert_eq!(
            retained_bytes(store.path())?,
            after_first,
            "the refused second writer does not overwrite the winner"
        );

        // Concurrent half: a fresh store, two threads, one shared predecessor.
        let racers = TempStore::new("two-writers-race")?;
        let race_owner = racers.owner()?;
        committed_genesis(
            &race_owner,
            &policy("policy-a", "1", "account-a", "model-1"),
        )?;
        let race_loaded = retained_publication(&race_owner)?;
        let race_expected = expectation_for(&race_loaded)?;
        let racers_path = racers.path().to_path_buf();
        let left = spawn_writer(
            racers_path.clone(),
            race_expected.clone(),
            policy("policy-a", "2", "account-a", "model-2"),
        );
        let right = spawn_writer(
            racers_path,
            race_expected,
            policy("policy-a", "2", "account-a", "model-3"),
        );
        let outcomes = [join_writer(left)?, join_writer(right)?];

        let committed = outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Ok(ModelPreferenceCasOutcome::Committed { .. })))
            .count();
        assert_eq!(committed, 1, "exactly one concurrent writer commits");
        let losers: Vec<_> = outcomes
            .iter()
            .filter(|outcome| !matches!(outcome, Ok(ModelPreferenceCasOutcome::Committed { .. })))
            .collect();
        assert_eq!(losers.len(), 1, "exactly one concurrent writer loses");
        // MEASURED on this host, not assumed: `Database::create` takes redb's
        // exclusive lock, and redb 4.1.0 fails fast on contention rather than
        // blocking until the winner commits, so the concurrent loser's typed
        // refusal is `Unavailable` — the owner never reaches its own
        // predecessor re-read. The sequential loser is a different refusal
        // and is asserted exactly as `Stale` above. A future redb that blocks
        // instead would fail this assertion, which is the point: the variant
        // is pinned rather than relaxed to whichever one happens to appear.
        for outcome in losers {
            assert!(
                matches!(outcome, Err(ModelPreferenceStoreError::Unavailable)),
                "the concurrent loser fails closed on lock contention, never reports success: \
                 {outcome:?}"
            );
        }
        let winner = retained_publication(&racers.owner()?)?;
        assert_eq!(
            winner.store_revision, 2,
            "the retained document is the winner's advance, not a merge"
        );
        Ok(())
    }

    /// The stale-digest refusal is ISOLATED: store revision, policy ID and
    /// policy revision all match the retained publication and only the
    /// expected digest differs, so nothing but the digest comparison can
    /// produce the refusal.
    #[test]
    fn isolated_stale_digest_fails_closed_without_overwriting() -> TestResult {
        let store = TempStore::new("stale-digest")?;
        let owner = store.owner()?;
        committed_genesis(&owner, &policy("policy-a", "1", "account-a", "model-1"))?;
        let before = retained_bytes(store.path())?;
        let loaded = retained_publication(&owner)?;

        let mut stale = expectation_for(&loaded)?;
        stale.policy_digest =
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned();
        assert_ne!(
            stale.policy_digest, loaded.policy_digest,
            "the fixture must differ from the retained digest only"
        );
        assert_eq!(stale.store_revision, loaded.store_revision);
        assert_eq!(stale.policy_id, loaded.policy.policy_id);
        assert_eq!(stale.policy_revision, loaded.policy.revision);

        assert_eq!(
            owner.compare_and_swap_model_preferences(
                &stale,
                &policy("policy-a", "2", "account-a", "model-2")
            ),
            Err(ModelPreferenceStoreError::Stale)
        );
        assert_eq!(
            retained_bytes(store.path())?,
            before,
            "a stale digest never writes"
        );
        Ok(())
    }

    /// Account scope and policy ID cannot change under replacement. These two
    /// refusals are unreachable through any production caller, because
    /// `swarm_command_candidate.rs` refuses both before a candidate exists,
    /// so an in-crate case is the only place they can be proven at all.
    #[test]
    fn scope_and_policy_id_cannot_change_under_replacement() -> TestResult {
        let store = TempStore::new("identity")?;
        let owner = store.owner()?;
        committed_genesis(&owner, &policy("policy-a", "1", "account-a", "model-1"))?;
        let before = retained_bytes(store.path())?;
        let loaded = retained_publication(&owner)?;
        let expected = expectation_for(&loaded)?;

        assert_eq!(
            owner.compare_and_swap_model_preferences(
                &expected,
                &policy("policy-a", "2", "account-b", "model-2")
            ),
            Err(ModelPreferenceStoreError::ScopeMismatch),
            "a replacement may not move the policy to another account scope"
        );
        assert_eq!(
            owner.compare_and_swap_model_preferences(
                &expected,
                &policy("policy-b", "2", "account-a", "model-2")
            ),
            Err(ModelPreferenceStoreError::PolicyIdMismatch),
            "a replacement may not change the policy ID"
        );
        assert_eq!(
            retained_bytes(store.path())?,
            before,
            "neither identity refusal writes"
        );
        Ok(())
    }

    /// The byte bound holds on BOTH sides, and on the offered side it holds
    /// before the retained document is displaced.
    #[test]
    fn oversized_input_fails_closed_on_read_and_on_offer() -> TestResult {
        // Retained side: the retained value is longer than the bound.
        let store = TempStore::new("oversized-read")?;
        let owner = store.owner()?;
        committed_genesis(&owner, &policy("policy-a", "1", "account-a", "model-1"))?;
        let retained = retained_document(store.path())?;
        let mut oversized = retained.clone();
        oversized.resize(MAX_MODEL_PREFERENCE_DOCUMENT_BYTES + 1, b'x');
        plant_document(store.path(), &oversized)?;
        assert_eq!(
            owner.load_model_preferences(),
            Err(ModelPreferenceStoreError::Oversized),
            "an oversized retained document fails closed during reading"
        );
        assert_eq!(
            owner.read_publication_receipt(),
            Err(ModelPreferenceStoreError::Oversized)
        );

        // Offered side: a structurally valid policy whose encoded envelope
        // exceeds the bound. The bloat has to live in a field the CAS does
        // NOT compare as identity — `policy_id` and `account_scope` are
        // refused by `PolicyIdMismatch`/`ScopeMismatch` before the bound is
        // ever reached — so the selectors carry it. 256 selectors is the
        // contract's own `MAX_SELECTORS`, so this is a policy the owner must
        // accept structurally and must still refuse on size.
        let store = TempStore::new("oversized-offer")?;
        let owner = store.owner()?;
        committed_genesis(&owner, &policy("policy-a", "1", "account-a", "model-1"))?;
        let before = retained_bytes(store.path())?;
        let loaded = retained_publication(&owner)?;
        let mut huge = policy("policy-a", "2", "account-a", "model-2");
        huge.roles[0].preferred = (0..256)
            .map(|index| selector(&format!("model-{index}-{}", "x".repeat(1_200))))
            .collect();
        assert!(
            huge.validate().is_ok(),
            "the oversized offer must be structurally valid, so the bound is what refuses it"
        );
        assert_eq!(
            owner.compare_and_swap_model_preferences(&expectation_for(&loaded)?, &huge),
            Err(ModelPreferenceStoreError::Oversized)
        );
        assert_eq!(
            retained_bytes(store.path())?,
            before,
            "an oversized offer never displaces the last valid version"
        );
        Ok(())
    }

    /// Legacy, unknown-version and corrupt retained content each fail closed
    /// with their own typed refusal, and none of them is returned as a
    /// publication.
    ///
    /// A deliberate asymmetry is pinned here rather than tidied: a bad
    /// `envelope_version` in the retained METADATA yields `Legacy`, while the
    /// same mismatch in the retained DOCUMENT yields `Corrupt`. Both are
    /// fail-closed; only the classification differs, and this case records
    /// the actual behaviour rather than the tidier taxonomy.
    #[test]
    fn legacy_corrupt_and_unknown_version_content_fails_closed() -> TestResult {
        // Metadata carries a version this owner does not publish.
        let store = TempStore::new("legacy")?;
        let owner = store.owner()?;
        committed_genesis(&owner, &policy("policy-a", "1", "account-a", "model-1"))?;
        plant_meta(store.path(), MODEL_PREFERENCE_ENVELOPE_VERSION + 1)?;
        assert_eq!(
            owner.load_model_preferences(),
            Err(ModelPreferenceStoreError::Legacy {
                version: MODEL_PREFERENCE_ENVELOPE_VERSION + 1
            })
        );
        assert_eq!(
            owner.read_publication_receipt(),
            Err(ModelPreferenceStoreError::Legacy {
                version: MODEL_PREFERENCE_ENVELOPE_VERSION + 1
            })
        );

        // The same mismatch inside the document is Corrupt, not Legacy.
        let store = TempStore::new("legacy-document")?;
        let owner = store.owner()?;
        committed_genesis(&owner, &policy("policy-a", "1", "account-a", "model-1"))?;
        let bytes = retained_document(store.path())?;
        let mut envelope: StoredModelPreferenceEnvelope = serde_json::from_slice(&bytes)?;
        envelope.envelope_version = MODEL_PREFERENCE_ENVELOPE_VERSION + 1;
        plant_document(store.path(), &serde_json::to_vec(&envelope)?)?;
        assert_eq!(
            owner.load_model_preferences(),
            Err(ModelPreferenceStoreError::Corrupt),
            "a document version mismatch is corrupt, not legacy"
        );

        // Unparseable retained bytes.
        let store = TempStore::new("corrupt")?;
        let owner = store.owner()?;
        committed_genesis(&owner, &policy("policy-a", "1", "account-a", "model-1"))?;
        plant_document(store.path(), b"{ not an envelope")?;
        assert_eq!(
            owner.load_model_preferences(),
            Err(ModelPreferenceStoreError::Corrupt)
        );
        assert_eq!(
            owner.read_publication_receipt(),
            Err(ModelPreferenceStoreError::Corrupt)
        );

        // A retained digest that does not match the retained policy: the
        // owner recomputes, so a plausible-looking document is still refused.
        // A genesis CAS runs first so the metadata table exists: a store
        // with no metadata is `Ok(None)` (explicit absence), which is a
        // different refusal and would make this case vacuous.
        let store = TempStore::new("digest-mismatch")?;
        let owner = store.owner()?;
        committed_genesis(&owner, &policy("policy-a", "1", "account-a", "model-1"))?;
        let forged = policy("policy-a", "1", "account-a", "model-1");
        let honest = preference_policy_digest(&forged)?;
        plant_document(
            store.path(),
            &envelope_bytes(1, 0, "", &forged, "sha256:forged")?,
        )?;
        assert_eq!(
            owner.load_model_preferences(),
            Err(ModelPreferenceStoreError::Corrupt),
            "a retained digest that is not the recomputed digest is corrupt"
        );
        assert_eq!(
            owner.read_publication_receipt(),
            Err(ModelPreferenceStoreError::Corrupt)
        );
        // ...and the same document with its owner-recomputed digest is accepted.
        plant_document(store.path(), &envelope_bytes(1, 0, "", &forged, &honest)?)?;
        assert_eq!(
            owner.load_model_preferences()?.map(|p| p.policy_digest),
            Some(honest)
        );
        Ok(())
    }

    /// Path-shape refusals. `validate_store_path` refuses a relative path and
    /// any object that is not a plain file, and a missing parent directory
    /// fails closed at the commit rather than being created.
    #[test]
    fn non_absolute_and_non_file_store_paths_fail_closed() -> TestResult {
        let relative = PathBuf::from("relative").join("model-preferences.redb");
        assert_bind_refused(&relative);

        let directory = TempStore::new("directory")?;
        std::fs::create_dir(directory.path())?;
        assert_bind_refused(directory.path());

        let missing_parent = directory
            .path()
            .with_extension("absent")
            .join("model-preferences.redb");
        let owner = ModelPreferenceStore::open(&missing_parent)?;
        assert_eq!(
            owner.compare_and_swap_model_preferences(
                &PreferenceCasExpected::genesis(),
                &policy("policy-a", "1", "account-a", "model-1")
            ),
            Err(ModelPreferenceStoreError::Unavailable),
            "a missing parent directory fails closed instead of being created"
        );
        assert_eq!(
            retained_bytes(&missing_parent)?,
            None,
            "no publication and no file are manufactured"
        );
        std::fs::remove_dir(directory.path())?;
        Ok(())
    }

    /// A symlinked store path is refused. Creating a symlink needs a
    /// privilege this test cannot assume, so a host that cannot create one
    /// asserts the same `!metadata.is_file()` arm of `validate_store_path`
    /// through a directory instead of silently passing.
    #[test]
    fn symlinked_store_path_fails_closed() -> TestResult {
        let target = TempStore::new("symlink-target")?;
        committed_genesis(
            &target.owner()?,
            &policy("policy-a", "1", "account-a", "model-1"),
        )?;
        let link = TempStore::new("symlink-link")?;
        let link_path = link.path().with_extension("link");

        #[cfg(windows)]
        let created = std::os::windows::fs::symlink_file(target.path(), &link_path);
        #[cfg(unix)]
        let created = std::os::unix::fs::symlink(target.path(), &link_path);
        #[cfg(not(any(windows, unix)))]
        let created: std::io::Result<()> = Err(std::io::Error::other("no symlink API"));

        match created {
            Ok(()) => {
                assert!(
                    std::fs::symlink_metadata(&link_path)?
                        .file_type()
                        .is_symlink(),
                    "the fixture must have produced a symlink for this arm to mean anything"
                );
                assert_bind_refused(&link_path);
                std::fs::remove_file(&link_path)?;
            }
            Err(refusal) => {
                // Documented fallback, not a silent pass: this host refused
                // to mint a symlink, so the symlink arm of
                // `validate_store_path` is UNPROVEN here and only the
                // non-file arm of the same guard is asserted. The weaker
                // proof is named rather than presented as the stronger one.
                assert!(
                    refusal.kind() != std::io::ErrorKind::NotFound,
                    "the symlink arm was skipped because its target vanished, not because this \
                     host lacks the privilege: {refusal}"
                );
                let as_directory = link.path().with_extension("dir");
                std::fs::create_dir(&as_directory)?;
                assert_bind_refused(&as_directory);
                std::fs::remove_dir(&as_directory)?;
            }
        }
        Ok(())
    }

    /// An interrupted publication preserves the last valid version. The
    /// dropped write transaction is the interruption: redb aborts it, so the
    /// retained document, the loaded publication and the receipt must all be
    /// exactly what they were before it began.
    #[test]
    fn interrupted_publication_preserves_the_last_valid_version() -> TestResult {
        let store = TempStore::new("interrupted")?;
        let owner = store.owner()?;
        committed_genesis(&owner, &policy("policy-a", "1", "account-a", "model-1"))?;
        let before_bytes = retained_document(store.path())?;
        let before_receipt = retained_receipt(&owner)?;

        // Begin a replacement, write it, and abandon the transaction without
        // committing: this is the interrupted publication.
        let dropped = policy("policy-a", "2", "account-a", "model-2");
        let dropped_digest = preference_policy_digest(&dropped)?;
        let replacement_bytes = envelope_bytes(
            2,
            1,
            &before_receipt.policy_digest,
            &dropped,
            &dropped_digest,
        )?;
        {
            let database = Database::create(store.path())?;
            let write = database.begin_write()?;
            {
                let mut prefs = write.open_table(PREFS_TABLE)?;
                prefs.insert(CURRENT_KEY, replacement_bytes.as_slice())?;
            }
            // `write` is dropped here, never committed.
        }

        assert_eq!(
            retained_bytes(store.path())?,
            Some(before_bytes.clone()),
            "the abandoned write left the last valid version in place"
        );
        let after = retained_publication(&owner)?;
        assert_eq!(after.store_revision, 1);
        assert_eq!(
            owner.read_publication_receipt()?,
            Some(before_receipt),
            "the receipt reconstructs from the retained committed document after the interruption"
        );
        assert_eq!(
            owner.load_model_preferences()?.map(|p| p.policy_digest),
            Some(after.policy_digest)
        );
        Ok(())
    }

    /// The receipt is rebuilt by the owner from the retained bytes, so a
    /// restart reads back the genesis shape and the linked shape, and a
    /// receipt never carries a digest the owner did not recompute.
    #[test]
    fn publication_receipt_is_rebuilt_from_the_retained_document() -> TestResult {
        let store = TempStore::new("receipt")?;
        let owner = store.owner()?;
        let genesis = policy("policy-a", "1", "account-a", "model-1");
        committed_genesis(&owner, &genesis)?;
        let genesis_digest = preference_policy_digest(&genesis)?;

        let genesis_receipt = retained_receipt(&owner)?;
        assert_eq!(genesis_receipt.store_revision, 1);
        assert_eq!(genesis_receipt.policy_id, "policy-a");
        assert_eq!(genesis_receipt.policy_revision, "1");
        assert_eq!(genesis_receipt.policy_digest, genesis_digest);
        assert_eq!(
            genesis_receipt.prior_store_revision, 0,
            "genesis links to no predecessor"
        );
        assert_eq!(genesis_receipt.prior_policy_digest, "");

        // A replacement links to the superseded revision and digest.
        let second = policy("policy-a", "2", "account-a", "model-2");
        let loaded = retained_publication(&owner)?;
        assert_eq!(
            owner.compare_and_swap_model_preferences(
                &expectation_for(&loaded)?,
                &policy("policy-a", "2", "account-a", "model-2")
            )?,
            ModelPreferenceCasOutcome::Committed { store_revision: 2 }
        );
        let linked = retained_receipt(&owner)?;
        assert_eq!(linked.store_revision, 2);
        assert_eq!(linked.prior_store_revision, 1);
        assert_eq!(linked.prior_policy_digest, genesis_digest);
        assert_eq!(
            linked.policy_digest,
            preference_policy_digest(&second)?,
            "the receipt carries the owner-recomputed digest"
        );

        // A fresh handle over the same bytes reads back an identical receipt:
        // the receipt is a property of the retained document, not of a handle.
        let reopened = ModelPreferenceStore::open(store.path())?;
        assert_eq!(reopened.read_publication_receipt()?, Some(linked));
        Ok(())
    }
}
