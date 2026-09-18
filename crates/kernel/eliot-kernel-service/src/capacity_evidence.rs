//! Versioned latency and capacity audit schemas (I16.6, issue #1848).
//!
//! These types are report/audit artifacts only. Every measurement-bearing
//! field is `Option`-marked so unavailable data stays explicitly unknown:
//! `None` serializes as JSON `null`, and no constructor manufactures a
//! plausible-looking value. There is deliberately no instrumentation here —
//! no clocks, counters, or resource samplers. Population happens when the
//! product is operated; this crate only stores, validates, and qualifies the
//! resulting records.
//!
//! The issue acceptance rules enforced here are:
//!
//! - a versioned artifact may be stored while incomplete, with every missing
//!   measurement enumerated as unknown;
//! - a single observed run (`n = 1`) is an observation, never `p50`/`p95`/
//!   `p99` evidence;
//! - a protocol or process-boundary optimization request without an observed
//!   bottleneck and linked recovery plus semantic-equivalence evidence is
//!   marked unqualified.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Schema version shared by every profile in this module.
///
/// A record carrying any other version is rejected on validation so schema
/// evolution stays explicit instead of silently reinterpreted.
pub const CAPACITY_EVIDENCE_SCHEMA_VERSION: &str = "1.0.0";

/// Minimum sample count that may back percentile evidence.
///
/// `n = 1` is an observation, never percentile evidence.
pub const MIN_PERCENTILE_SAMPLES: u64 = 2;

/// Maximum length of free-text identity fields, in UTF-8 bytes.
const MAX_TEXT_LEN: usize = 1024;

/// Failures while constructing or validating a latency/capacity artifact.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum CapacityEvidenceError {
    /// An identity or evidence-reference field was blank or carried control characters.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText {
        /// Name of the rejected field.
        field: &'static str,
    },
    /// An identity or evidence-reference field exceeded the length bound.
    #[error("{field} must not exceed 1024 UTF-8 bytes")]
    TextTooLong {
        /// Name of the rejected field.
        field: &'static str,
    },
    /// A record carried a schema version this module does not understand.
    #[error("unsupported capacity-evidence schema version: {0}")]
    UnsupportedSchemaVersion(String),
    /// A percentile distribution was attached to fewer than [`MIN_PERCENTILE_SAMPLES`].
    #[error(
        "sample count {0} is an observation, not percentile evidence; leave the distribution unknown"
    )]
    SingleSampleNotPercentile(u64),
    /// Canonical JSON for the artifact could not be produced or consumed.
    #[error("capacity-evidence serialization failed: {0}")]
    Serialization(String),
}

/// What a sample count supports: one run is an observation, never percentiles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceClass {
    /// Fewer than [`MIN_PERCENTILE_SAMPLES`] samples: an observation only.
    Observation,
    /// At least [`MIN_PERCENTILE_SAMPLES`] measured samples with a distribution attached.
    PercentileEvidence,
}

/// Measured latency distribution backing a percentile claim.
///
/// Presence of this value asserts all five components were measured together.
/// A single observation must not be wrapped in this type; see
/// [`MIN_PERCENTILE_SAMPLES`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LatencyDistribution {
    /// Number of measured samples backing these percentiles.
    pub sample_count: u64,
    /// Fiftieth percentile latency, in nanoseconds.
    pub p50_nanos: u64,
    /// Ninety-fifth percentile latency, in nanoseconds.
    pub p95_nanos: u64,
    /// Ninety-ninth percentile latency, in nanoseconds.
    pub p99_nanos: u64,
    /// Maximum observed latency, in nanoseconds.
    pub max_nanos: u64,
}

impl LatencyDistribution {
    /// Builds a measured distribution, rejecting single-sample percentiles.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityEvidenceError::SingleSampleNotPercentile`] when
    /// `sample_count` is below [`MIN_PERCENTILE_SAMPLES`].
    pub fn new(
        sample_count: u64,
        p50_nanos: u64,
        p95_nanos: u64,
        p99_nanos: u64,
        max_nanos: u64,
    ) -> Result<Self, CapacityEvidenceError> {
        if sample_count < MIN_PERCENTILE_SAMPLES {
            return Err(CapacityEvidenceError::SingleSampleNotPercentile(
                sample_count,
            ));
        }
        Ok(Self {
            sample_count,
            p50_nanos,
            p95_nanos,
            p99_nanos,
            max_nanos,
        })
    }
}

/// Decomposed canonical-write latency claim (I16.6 `CanonicalWriteLatencyProfile`).
///
/// Every stage is independently unknown until measured on the operated
/// product. `distribution` stays `None` until at least
/// [`MIN_PERCENTILE_SAMPLES`] runs are observed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanonicalWriteLatencyProfile {
    /// Schema version; must equal [`CAPACITY_EVIDENCE_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Stable identity of this profile record.
    pub profile_id: String,
    /// Exact product, machine, storage, and contention identity, if recorded.
    pub exact_product_machine_storage_and_contention_profile: Option<String>,
    /// Canonical payload size in bytes, if recorded.
    pub payload_bytes: Option<u64>,
    /// Payload encoding label (for example `"json-ebp"`), if recorded.
    pub payload_encoding: Option<String>,
    /// Bridge-to-Kernel serialization and IPC stage, in nanoseconds, if measured.
    pub bridge_to_kernel_serialization_and_ipc_nanos: Option<u64>,
    /// Kernel-to-daemon serialization and IPC stage, in nanoseconds, if measured.
    pub kernel_to_daemon_serialization_and_ipc_nanos: Option<u64>,
    /// Validation, admission, and reservation stage, in nanoseconds, if measured.
    pub validation_admission_and_reservation_nanos: Option<u64>,
    /// ORS staging and durability stage, in nanoseconds, if measured.
    pub ors_stage_and_durability_nanos: Option<u64>,
    /// Daemon-to-store-bridge serialization and IPC stage, in nanoseconds, if measured.
    pub daemon_to_store_bridge_serialization_and_ipc_nanos: Option<u64>,
    /// Store-bridge-to-database transport stage, in nanoseconds, if measured.
    pub store_bridge_to_database_transport_nanos: Option<u64>,
    /// Database commit and durability stage, in nanoseconds, if measured.
    pub database_commit_and_durability_nanos: Option<u64>,
    /// Receipt return, ORS reconciliation, and outbox stage, in nanoseconds, if measured.
    pub receipt_return_ors_reconciliation_and_outbox_nanos: Option<u64>,
    /// Measured percentile distribution; `None` until enough runs are observed.
    pub distribution: Option<LatencyDistribution>,
    /// CPU, allocation, I/O, fsync, and queue-wait account, if recorded.
    pub cpu_allocations_io_fsync_and_queue_wait: Option<String>,
    /// Observed bottleneck and candidate change, if any bottleneck was observed.
    pub bottleneck_and_candidate_change: Option<String>,
}

impl CanonicalWriteLatencyProfile {
    /// Builds an explicitly incomplete profile: every measurement is unknown.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityEvidenceError`] when `profile_id` is blank,
    /// carries control characters, or exceeds the length bound.
    pub fn unknown(profile_id: &str) -> Result<Self, CapacityEvidenceError> {
        valid_identity(profile_id, "profile_id")?;
        Ok(Self {
            schema_version: CAPACITY_EVIDENCE_SCHEMA_VERSION.to_owned(),
            profile_id: profile_id.to_owned(),
            exact_product_machine_storage_and_contention_profile: None,
            payload_bytes: None,
            payload_encoding: None,
            bridge_to_kernel_serialization_and_ipc_nanos: None,
            kernel_to_daemon_serialization_and_ipc_nanos: None,
            validation_admission_and_reservation_nanos: None,
            ors_stage_and_durability_nanos: None,
            daemon_to_store_bridge_serialization_and_ipc_nanos: None,
            store_bridge_to_database_transport_nanos: None,
            database_commit_and_durability_nanos: None,
            receipt_return_ors_reconciliation_and_outbox_nanos: None,
            distribution: None,
            cpu_allocations_io_fsync_and_queue_wait: None,
            bottleneck_and_candidate_change: None,
        })
    }

    /// Validates identity, schema version, and the observation/percentile rule.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityEvidenceError`] for a blank identity, a foreign
    /// schema version, or a distribution backed by fewer than
    /// [`MIN_PERCENTILE_SAMPLES`] samples.
    pub fn validate(&self) -> Result<(), CapacityEvidenceError> {
        valid_identity(&self.profile_id, "profile_id")?;
        check_schema_version(&self.schema_version)?;
        if let Some(distribution) = &self.distribution
            && distribution.sample_count < MIN_PERCENTILE_SAMPLES
        {
            return Err(CapacityEvidenceError::SingleSampleNotPercentile(
                distribution.sample_count,
            ));
        }
        Ok(())
    }

    /// Reports whether any measurement is still explicitly unknown.
    pub fn is_complete(&self) -> bool {
        self.unknown_field_names().is_empty()
    }

    /// Names every measurement field still explicitly marked unknown.
    pub fn unknown_field_names(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self
            .exact_product_machine_storage_and_contention_profile
            .is_none()
        {
            missing.push("exact_product_machine_storage_and_contention_profile");
        }
        if self.payload_bytes.is_none() {
            missing.push("payload_bytes");
        }
        if self.payload_encoding.is_none() {
            missing.push("payload_encoding");
        }
        if self.bridge_to_kernel_serialization_and_ipc_nanos.is_none() {
            missing.push("bridge_to_kernel_serialization_and_ipc_nanos");
        }
        if self.kernel_to_daemon_serialization_and_ipc_nanos.is_none() {
            missing.push("kernel_to_daemon_serialization_and_ipc_nanos");
        }
        if self.validation_admission_and_reservation_nanos.is_none() {
            missing.push("validation_admission_and_reservation_nanos");
        }
        if self.ors_stage_and_durability_nanos.is_none() {
            missing.push("ors_stage_and_durability_nanos");
        }
        if self
            .daemon_to_store_bridge_serialization_and_ipc_nanos
            .is_none()
        {
            missing.push("daemon_to_store_bridge_serialization_and_ipc_nanos");
        }
        if self.store_bridge_to_database_transport_nanos.is_none() {
            missing.push("store_bridge_to_database_transport_nanos");
        }
        if self.database_commit_and_durability_nanos.is_none() {
            missing.push("database_commit_and_durability_nanos");
        }
        if self
            .receipt_return_ors_reconciliation_and_outbox_nanos
            .is_none()
        {
            missing.push("receipt_return_ors_reconciliation_and_outbox_nanos");
        }
        if self.distribution.is_none() {
            missing.push("distribution");
        }
        if self.cpu_allocations_io_fsync_and_queue_wait.is_none() {
            missing.push("cpu_allocations_io_fsync_and_queue_wait");
        }
        if self.bottleneck_and_candidate_change.is_none() {
            missing.push("bottleneck_and_candidate_change");
        }
        missing
    }

    /// Classifies this profile as an observation or percentile evidence.
    pub fn evidence_class(&self) -> EvidenceClass {
        match &self.distribution {
            Some(distribution) if distribution.sample_count >= MIN_PERCENTILE_SAMPLES => {
                EvidenceClass::PercentileEvidence
            }
            Some(_) | None => EvidenceClass::Observation,
        }
    }

    /// Serializes this profile to JSON, preserving explicit `null` unknowns.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityEvidenceError`] when validation or serialization fails.
    pub fn to_json(&self) -> Result<Vec<u8>, CapacityEvidenceError> {
        self.validate()?;
        serde_json::to_vec(self)
            .map_err(|error| CapacityEvidenceError::Serialization(error.to_string()))
    }

    /// Deserializes and validates a stored profile record.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityEvidenceError`] when the bytes are not a valid
    /// versioned profile.
    pub fn from_json(bytes: &[u8]) -> Result<Self, CapacityEvidenceError> {
        let profile: Self = serde_json::from_slice(bytes)
            .map_err(|error| CapacityEvidenceError::Serialization(error.to_string()))?;
        profile.validate()?;
        Ok(profile)
    }
}

/// Published performance/capacity claim (I16.6 `CapacityEnvelope`).
///
/// A claim with fewer than [`MIN_PERCENTILE_SAMPLES`] samples is an
/// observation: `distribution` must stay `None` and [`Self::evidence_class`]
/// reports [`EvidenceClass::Observation`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CapacityEnvelope {
    /// Schema version; must equal [`CAPACITY_EVIDENCE_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Stable identity of this envelope record.
    pub envelope_id: String,
    /// Product and runtime identity, if recorded.
    pub product_and_runtime_identity: Option<String>,
    /// Hardware, OS, storage, and network fingerprint, if recorded.
    pub hardware_os_storage_and_network_fingerprint: Option<String>,
    /// Corpus/storage tier and data shape, if recorded.
    pub corpus_storage_tier_and_data_shape: Option<String>,
    /// Workload, task, profile, and route fingerprint, if recorded.
    pub workload_task_profile_and_route_fingerprint: Option<String>,
    /// Concurrency, queue/backlog, and reserve configuration, if recorded.
    pub concurrency_queue_backlog_and_reserve_config: Option<String>,
    /// Measured sample count, if recorded; `None` means unknown.
    pub sample_count: Option<u64>,
    /// Warmup and error/uncertainty method, if recorded.
    pub warmup_and_error_method: Option<String>,
    /// Measured percentile distribution; `None` until enough runs are observed.
    pub distribution: Option<LatencyDistribution>,
    /// Saturation point account, if recorded.
    pub saturation_point: Option<String>,
    /// CPU, RSS, handle, I/O, WAL, and device-write account, if recorded.
    pub cpu_rss_handles_io_wal_device_write: Option<String>,
    /// Crash, restart, recovery, backup, and restore timings, if recorded.
    pub crash_restart_recovery_backup_restore_timings: Option<String>,
    /// Semantic-equality and proof-ceiling account, if recorded.
    pub semantic_equality_proof_ceiling: Option<String>,
    /// Validity, expiry, and invalidation conditions, if recorded.
    pub validity_expiry_and_invalidation_conditions: Option<String>,
}

impl CapacityEnvelope {
    /// Builds an explicitly incomplete envelope: every measurement is unknown.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityEvidenceError`] when `envelope_id` is blank,
    /// carries control characters, or exceeds the length bound.
    pub fn unknown(envelope_id: &str) -> Result<Self, CapacityEvidenceError> {
        valid_identity(envelope_id, "envelope_id")?;
        Ok(Self {
            schema_version: CAPACITY_EVIDENCE_SCHEMA_VERSION.to_owned(),
            envelope_id: envelope_id.to_owned(),
            product_and_runtime_identity: None,
            hardware_os_storage_and_network_fingerprint: None,
            corpus_storage_tier_and_data_shape: None,
            workload_task_profile_and_route_fingerprint: None,
            concurrency_queue_backlog_and_reserve_config: None,
            sample_count: None,
            warmup_and_error_method: None,
            distribution: None,
            saturation_point: None,
            cpu_rss_handles_io_wal_device_write: None,
            crash_restart_recovery_backup_restore_timings: None,
            semantic_equality_proof_ceiling: None,
            validity_expiry_and_invalidation_conditions: None,
        })
    }

    /// Validates identity, schema version, and the observation/percentile rule.
    ///
    /// A distribution requires a recorded sample count of at least
    /// [`MIN_PERCENTILE_SAMPLES`]; anything less is an observation and the
    /// distribution must stay unknown.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityEvidenceError`] for a blank identity, a foreign
    /// schema version, or percentile evidence without sufficient samples.
    pub fn validate(&self) -> Result<(), CapacityEvidenceError> {
        valid_identity(&self.envelope_id, "envelope_id")?;
        check_schema_version(&self.schema_version)?;
        if let Some(distribution) = &self.distribution {
            match self.sample_count {
                Some(count)
                    if count >= MIN_PERCENTILE_SAMPLES
                        && distribution.sample_count >= MIN_PERCENTILE_SAMPLES => {}
                Some(count) => {
                    return Err(CapacityEvidenceError::SingleSampleNotPercentile(count));
                }
                None => {
                    return Err(CapacityEvidenceError::SingleSampleNotPercentile(0));
                }
            }
        }
        Ok(())
    }

    /// Reports whether any measurement is still explicitly unknown.
    pub fn is_complete(&self) -> bool {
        self.unknown_field_names().is_empty()
    }

    /// Names every measurement field still explicitly marked unknown.
    pub fn unknown_field_names(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.product_and_runtime_identity.is_none() {
            missing.push("product_and_runtime_identity");
        }
        if self.hardware_os_storage_and_network_fingerprint.is_none() {
            missing.push("hardware_os_storage_and_network_fingerprint");
        }
        if self.corpus_storage_tier_and_data_shape.is_none() {
            missing.push("corpus_storage_tier_and_data_shape");
        }
        if self.workload_task_profile_and_route_fingerprint.is_none() {
            missing.push("workload_task_profile_and_route_fingerprint");
        }
        if self.concurrency_queue_backlog_and_reserve_config.is_none() {
            missing.push("concurrency_queue_backlog_and_reserve_config");
        }
        if self.sample_count.is_none() {
            missing.push("sample_count");
        }
        if self.warmup_and_error_method.is_none() {
            missing.push("warmup_and_error_method");
        }
        if self.distribution.is_none() {
            missing.push("distribution");
        }
        if self.saturation_point.is_none() {
            missing.push("saturation_point");
        }
        if self.cpu_rss_handles_io_wal_device_write.is_none() {
            missing.push("cpu_rss_handles_io_wal_device_write");
        }
        if self.crash_restart_recovery_backup_restore_timings.is_none() {
            missing.push("crash_restart_recovery_backup_restore_timings");
        }
        if self.semantic_equality_proof_ceiling.is_none() {
            missing.push("semantic_equality_proof_ceiling");
        }
        if self.validity_expiry_and_invalidation_conditions.is_none() {
            missing.push("validity_expiry_and_invalidation_conditions");
        }
        missing
    }

    /// Classifies this envelope as an observation or percentile evidence.
    pub fn evidence_class(&self) -> EvidenceClass {
        match (&self.distribution, self.sample_count) {
            (Some(distribution), Some(count))
                if count >= MIN_PERCENTILE_SAMPLES
                    && distribution.sample_count >= MIN_PERCENTILE_SAMPLES =>
            {
                EvidenceClass::PercentileEvidence
            }
            _ => EvidenceClass::Observation,
        }
    }
}

/// Corpus scale account (I16.6 `CorpusScaleProfile`).
///
/// A capacity result transfers only to a compatible profile: the envelope
/// identity must appear in [`Self::applicable_capacity_envelope_refs`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CorpusScaleProfile {
    /// Schema version; must equal [`CAPACITY_EVIDENCE_SCHEMA_VERSION`].
    pub schema_version: String,
    /// Stable identity of this corpus profile record.
    pub profile_id: String,
    /// Scope this profile covers, if recorded.
    pub scope: Option<String>,
    /// Source classes and privacy domains, if recorded.
    pub source_classes_and_privacy_domains: Option<String>,
    /// Canonical record bytes, if recorded.
    pub canonical_record_bytes: Option<u64>,
    /// Blob bytes, if recorded.
    pub blob_bytes: Option<u64>,
    /// Index bytes, if recorded.
    pub index_bytes: Option<u64>,
    /// Record count, if recorded.
    pub record_count: Option<u64>,
    /// Episode count, if recorded.
    pub episode_count: Option<u64>,
    /// Document count, if recorded.
    pub document_count: Option<u64>,
    /// Log count, if recorded.
    pub log_count: Option<u64>,
    /// Artifact count, if recorded.
    pub artifact_count: Option<u64>,
    /// Graph node count, if recorded.
    pub graph_nodes: Option<u64>,
    /// Graph edge count, if recorded.
    pub graph_edges: Option<u64>,
    /// Projection generation count, if recorded.
    pub projection_generations: Option<u64>,
    /// History window and active/archive ratio, if recorded.
    pub history_window_and_active_archive_ratio: Option<String>,
    /// Query, ingest, compaction, backup, and restore workloads, if recorded.
    pub query_ingest_compaction_backup_and_restore_workloads: Option<String>,
    /// Expected growth and retention, if recorded.
    pub expected_growth_and_retention: Option<String>,
    /// Envelope identities whose capacity results transfer to this profile.
    pub applicable_capacity_envelope_refs: Vec<String>,
    /// Qualification uncertainty, expiry, and kill condition, if recorded.
    pub qualification_uncertainty_expiry_and_kill_condition: Option<String>,
}

impl CorpusScaleProfile {
    /// Builds an explicitly incomplete corpus profile: every measurement is unknown.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityEvidenceError`] when `profile_id` is blank,
    /// carries control characters, or exceeds the length bound.
    pub fn unknown(profile_id: &str) -> Result<Self, CapacityEvidenceError> {
        valid_identity(profile_id, "profile_id")?;
        Ok(Self {
            schema_version: CAPACITY_EVIDENCE_SCHEMA_VERSION.to_owned(),
            profile_id: profile_id.to_owned(),
            scope: None,
            source_classes_and_privacy_domains: None,
            canonical_record_bytes: None,
            blob_bytes: None,
            index_bytes: None,
            record_count: None,
            episode_count: None,
            document_count: None,
            log_count: None,
            artifact_count: None,
            graph_nodes: None,
            graph_edges: None,
            projection_generations: None,
            history_window_and_active_archive_ratio: None,
            query_ingest_compaction_backup_and_restore_workloads: None,
            expected_growth_and_retention: None,
            applicable_capacity_envelope_refs: Vec::new(),
            qualification_uncertainty_expiry_and_kill_condition: None,
        })
    }

    /// Validates identity, schema version, and envelope references.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityEvidenceError`] for a blank identity, a foreign
    /// schema version, or a blank envelope reference.
    pub fn validate(&self) -> Result<(), CapacityEvidenceError> {
        valid_identity(&self.profile_id, "profile_id")?;
        check_schema_version(&self.schema_version)?;
        for envelope_ref in &self.applicable_capacity_envelope_refs {
            valid_identity(envelope_ref, "applicable_capacity_envelope_refs")?;
        }
        Ok(())
    }

    /// Reports whether the named envelope transfers to this corpus profile.
    pub fn covers_envelope(&self, envelope_id: &str) -> bool {
        self.applicable_capacity_envelope_refs
            .iter()
            .any(|candidate| candidate == envelope_id)
    }

    /// Reports whether any measurement is still explicitly unknown.
    pub fn is_complete(&self) -> bool {
        self.unknown_field_names().is_empty()
    }

    /// Names every measurement field still explicitly marked unknown.
    ///
    /// An empty envelope-reference list counts as unknown: with no linked
    /// envelope, no capacity result transfers here.
    pub fn unknown_field_names(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if self.scope.is_none() {
            missing.push("scope");
        }
        if self.source_classes_and_privacy_domains.is_none() {
            missing.push("source_classes_and_privacy_domains");
        }
        if self.canonical_record_bytes.is_none() {
            missing.push("canonical_record_bytes");
        }
        if self.blob_bytes.is_none() {
            missing.push("blob_bytes");
        }
        if self.index_bytes.is_none() {
            missing.push("index_bytes");
        }
        if self.record_count.is_none() {
            missing.push("record_count");
        }
        if self.episode_count.is_none() {
            missing.push("episode_count");
        }
        if self.document_count.is_none() {
            missing.push("document_count");
        }
        if self.log_count.is_none() {
            missing.push("log_count");
        }
        if self.artifact_count.is_none() {
            missing.push("artifact_count");
        }
        if self.graph_nodes.is_none() {
            missing.push("graph_nodes");
        }
        if self.graph_edges.is_none() {
            missing.push("graph_edges");
        }
        if self.projection_generations.is_none() {
            missing.push("projection_generations");
        }
        if self.history_window_and_active_archive_ratio.is_none() {
            missing.push("history_window_and_active_archive_ratio");
        }
        if self
            .query_ingest_compaction_backup_and_restore_workloads
            .is_none()
        {
            missing.push("query_ingest_compaction_backup_and_restore_workloads");
        }
        if self.expected_growth_and_retention.is_none() {
            missing.push("expected_growth_and_retention");
        }
        if self.applicable_capacity_envelope_refs.is_empty() {
            missing.push("applicable_capacity_envelope_refs");
        }
        if self
            .qualification_uncertainty_expiry_and_kill_condition
            .is_none()
        {
            missing.push("qualification_uncertainty_expiry_and_kill_condition");
        }
        missing
    }
}

/// Request to replace JSON-first EBP, Protobuf, or an existing process boundary.
///
/// The request carries only references: the observed bottleneck plus the
/// linked versioned profile/envelope and the recovery and
/// semantic-equivalence evidence. It performs no measurement itself.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundaryOptimizationProposal {
    /// Stable identity of this proposal.
    pub proposal_id: String,
    /// Observed bottleneck reference; `None` means no bottleneck was observed.
    pub observed_bottleneck: Option<String>,
    /// Linked versioned profile or envelope identity, if any.
    pub linked_profile_id: Option<String>,
    /// Linked recovery-evidence reference, if any.
    pub recovery_evidence_ref: Option<String>,
    /// Linked semantic-equivalence-evidence reference, if any.
    pub semantic_equivalence_evidence_ref: Option<String>,
}

impl BoundaryOptimizationProposal {
    /// Builds a proposal; every evidence link starts explicitly unknown.
    ///
    /// # Errors
    ///
    /// Returns [`CapacityEvidenceError`] when `proposal_id` is blank,
    /// carries control characters, or exceeds the length bound.
    pub fn without_evidence(proposal_id: &str) -> Result<Self, CapacityEvidenceError> {
        valid_identity(proposal_id, "proposal_id")?;
        Ok(Self {
            proposal_id: proposal_id.to_owned(),
            observed_bottleneck: None,
            linked_profile_id: None,
            recovery_evidence_ref: None,
            semantic_equivalence_evidence_ref: None,
        })
    }

    /// Qualifies the proposal against the observed-bottleneck gate.
    ///
    /// A paper estimate cannot promote the change: without an observed
    /// bottleneck, a linked versioned profile, recovery evidence, and
    /// semantic-equivalence evidence the proposal is unqualified, with every
    /// missing link enumerated.
    pub fn qualify(&self) -> OptimizationQualification {
        let mut reasons = Vec::new();
        if is_blank_or_unset(self.observed_bottleneck.as_deref()) {
            reasons.push(UnqualifiedReason::NoObservedBottleneck);
        }
        if is_blank_or_unset(self.linked_profile_id.as_deref()) {
            reasons.push(UnqualifiedReason::NoLinkedProfile);
        }
        if is_blank_or_unset(self.recovery_evidence_ref.as_deref()) {
            reasons.push(UnqualifiedReason::NoRecoveryEvidence);
        }
        if is_blank_or_unset(self.semantic_equivalence_evidence_ref.as_deref()) {
            reasons.push(UnqualifiedReason::NoSemanticEvidence);
        }
        if reasons.is_empty() {
            OptimizationQualification::Qualified
        } else {
            OptimizationQualification::Unqualified { reasons }
        }
    }
}

/// Outcome of the protocol/process-boundary optimization gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub enum OptimizationQualification {
    /// An observed bottleneck plus linked recovery and semantic evidence exist.
    Qualified,
    /// The proposal lacks required evidence; every gap is enumerated.
    Unqualified {
        /// Missing links that keep this proposal unqualified.
        reasons: Vec<UnqualifiedReason>,
    },
}

impl OptimizationQualification {
    /// Reports whether the proposal passed the evidence gate.
    pub fn is_qualified(&self) -> bool {
        matches!(self, Self::Qualified)
    }
}

/// One missing link that keeps a boundary-optimization proposal unqualified.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnqualifiedReason {
    /// No bottleneck was observed; a paper estimate cannot promote the change.
    NoObservedBottleneck,
    /// No versioned latency profile or capacity envelope is linked.
    NoLinkedProfile,
    /// No recovery evidence is linked.
    NoRecoveryEvidence,
    /// No semantic-equivalence evidence is linked.
    NoSemanticEvidence,
}

fn valid_identity(value: &str, field: &'static str) -> Result<(), CapacityEvidenceError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CapacityEvidenceError::InvalidText { field });
    }
    if value.len() > MAX_TEXT_LEN {
        return Err(CapacityEvidenceError::TextTooLong { field });
    }
    Ok(())
}

fn check_schema_version(value: &str) -> Result<(), CapacityEvidenceError> {
    if value != CAPACITY_EVIDENCE_SCHEMA_VERSION {
        return Err(CapacityEvidenceError::UnsupportedSchemaVersion(
            value.to_owned(),
        ));
    }
    Ok(())
}

fn is_blank_or_unset(value: Option<&str>) -> bool {
    match value {
        None => true,
        Some(text) => text.trim().is_empty() || text.chars().any(char::is_control),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_artifact_marks_every_measurement_unknown() {
        let profile = CanonicalWriteLatencyProfile::unknown("latency-1848").expect("profile");
        assert!(!profile.is_complete());
        assert!(!profile.unknown_field_names().is_empty());
        assert_eq!(profile.evidence_class(), EvidenceClass::Observation);
        assert!(profile.validate().is_ok());

        let envelope = CapacityEnvelope::unknown("envelope-1848").expect("envelope");
        assert!(!envelope.is_complete());
        assert!(!envelope.unknown_field_names().is_empty());
        assert_eq!(envelope.evidence_class(), EvidenceClass::Observation);
        assert!(envelope.validate().is_ok());

        let corpus = CorpusScaleProfile::unknown("corpus-1848").expect("corpus");
        assert!(!corpus.is_complete());
        assert!(!corpus.unknown_field_names().is_empty());
        assert!(corpus.validate().is_ok());

        // Unknown stays explicit on the wire: JSON carries null, never a
        // manufactured zero or empty string.
        let bytes = profile.to_json().expect("json");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("value");
        assert!(value["payload_bytes"].is_null());
        assert!(value["distribution"].is_null());
        assert!(value["bottleneck_and_candidate_change"].is_null());
        assert_eq!(value["schema_version"], CAPACITY_EVIDENCE_SCHEMA_VERSION);

        let round_trip = CanonicalWriteLatencyProfile::from_json(&bytes).expect("round trip");
        assert_eq!(round_trip, profile);
    }

    #[test]
    fn single_observation_is_not_percentile_evidence() {
        // A single run cannot be wrapped as a distribution.
        let single = LatencyDistribution::new(1, 10, 10, 10, 10);
        assert!(matches!(
            single,
            Err(CapacityEvidenceError::SingleSampleNotPercentile(1))
        ));

        // A stored record claiming percentiles from one run is rejected.
        let mut profile = CanonicalWriteLatencyProfile::unknown("latency-n1").expect("profile");
        profile.distribution = Some(LatencyDistribution {
            sample_count: 1,
            p50_nanos: 10,
            p95_nanos: 10,
            p99_nanos: 10,
            max_nanos: 10,
        });
        assert!(matches!(
            profile.validate(),
            Err(CapacityEvidenceError::SingleSampleNotPercentile(1))
        ));
        assert_eq!(profile.evidence_class(), EvidenceClass::Observation);

        let mut envelope = CapacityEnvelope::unknown("envelope-n1").expect("envelope");
        envelope.sample_count = Some(1);
        envelope.distribution =
            Some(LatencyDistribution::new(2, 10, 12, 14, 20).expect("distribution"));
        assert!(matches!(
            envelope.validate(),
            Err(CapacityEvidenceError::SingleSampleNotPercentile(1))
        ));
        assert_eq!(envelope.evidence_class(), EvidenceClass::Observation);

        // Enough measured runs qualify as percentile evidence.
        let distribution = LatencyDistribution::new(32, 10, 12, 14, 20).expect("distribution");
        profile.distribution = Some(distribution);
        assert!(profile.validate().is_ok());
        assert_eq!(profile.evidence_class(), EvidenceClass::PercentileEvidence);
    }

    #[test]
    fn unqualified_boundary_optimization_without_bottleneck_or_linked_evidence() {
        let bare =
            BoundaryOptimizationProposal::without_evidence("proposal-1848").expect("proposal");
        match bare.qualify() {
            OptimizationQualification::Unqualified { reasons } => {
                assert!(reasons.contains(&UnqualifiedReason::NoObservedBottleneck));
                assert!(reasons.contains(&UnqualifiedReason::NoLinkedProfile));
                assert!(reasons.contains(&UnqualifiedReason::NoRecoveryEvidence));
                assert!(reasons.contains(&UnqualifiedReason::NoSemanticEvidence));
            }
            OptimizationQualification::Qualified => panic!("bare proposal must not qualify"),
        }
        assert!(!bare.qualify().is_qualified());

        // A bottleneck alone still leaves the proposal unqualified.
        let mut partial = bare.clone();
        partial.observed_bottleneck = Some("ors-stage-durability".to_owned());
        match partial.qualify() {
            OptimizationQualification::Unqualified { reasons } => {
                assert!(!reasons.contains(&UnqualifiedReason::NoObservedBottleneck));
                assert!(reasons.contains(&UnqualifiedReason::NoRecoveryEvidence));
                assert!(reasons.contains(&UnqualifiedReason::NoSemanticEvidence));
            }
            OptimizationQualification::Qualified => {
                panic!("partial proposal must not qualify");
            }
        }

        let qualified = BoundaryOptimizationProposal {
            proposal_id: "proposal-1848".to_owned(),
            observed_bottleneck: Some("ors-stage-durability".to_owned()),
            linked_profile_id: Some("latency-1848".to_owned()),
            recovery_evidence_ref: Some("recovery-1848".to_owned()),
            semantic_equivalence_evidence_ref: Some("semantic-1848".to_owned()),
        };
        assert_eq!(qualified.qualify(), OptimizationQualification::Qualified);
        assert!(qualified.qualify().is_qualified());
    }

    #[test]
    fn capacity_result_transfers_only_to_compatible_corpus_profile() {
        let mut corpus = CorpusScaleProfile::unknown("corpus-1848").expect("corpus");
        assert!(!corpus.covers_envelope("envelope-1848"));

        corpus
            .applicable_capacity_envelope_refs
            .push("envelope-1848".to_owned());
        assert!(corpus.covers_envelope("envelope-1848"));
        assert!(!corpus.covers_envelope("foreign-envelope"));
        assert!(corpus.validate().is_ok());
    }
}
