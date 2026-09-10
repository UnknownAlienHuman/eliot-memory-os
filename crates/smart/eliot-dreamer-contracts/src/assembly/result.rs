//! Frozen result envelope for Dreamer bundle assembly.
//!
//! The result keeps the ordinary bundle projection together with the richer
//! material closure. It carries only assembly state and accounting; source
//! selection, screening, interpretation, and authority remain elsewhere.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_context_contracts::{MeasurementStatus, MeasurementUnit};
use eliot_security_contracts::{
    ClosureCompleteness, DeclassificationReceipt, DisclosureDecision, DisclosureDecisionKind,
    DisclosureDependencyClosure,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::budget::{BudgetDimension, BudgetUsage, OUTPUT_BYTES_CEILING, REPORT_BYTES_CEILING};
use crate::bundle::{BundleCompleteness, BundleStatus, DreamInputBundle};
use crate::encoding::digest_hex;
use crate::error::{ContractViolation, check_text, check_vec_bound, is_hex64_lower};

use super::material::{
    AssemblyMaterialSet, AssemblyOmissionConstraint, BundleMeasurement, ConditionalEvaluationState,
    MaterialDisposition, MaterialLedgerEntry, MaterialOutcomeReason, RoleOutcome, RoleOutcomeState,
    SuppliedItemIdentity,
};
use super::recipe::{AssemblyReserveSet, DreamInputRole, RoleDisposition};

const RESULT_SCHEMA_VERSION: u32 = 1;
const MAX_FRONTIER: usize = 1_024;

/// Explicit reason why assembly stopped at the retained frontier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum AssemblyStopReason {
    /// All required bundle material was retained.
    Completed,
    /// An injected cancellation was observed and retained.
    Cancelled,
    /// A required closure or source remained unresolved.
    Incomplete,
    /// A declared independent budget dimension was exhausted.
    BudgetExhausted,
}

/// Stop record retaining a bounded reason without consulting an ambient clock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssemblyStop {
    /// Closed stop category.
    pub reason: AssemblyStopReason,
    /// Explicit bounded detail for non-terminal-complete stops.
    pub detail: Option<String>,
}

impl AssemblyStop {
    /// Validates the explicit stop detail rule.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if let Some(detail) = &self.detail {
            check_text(detail, "result.stop.detail", 256)?;
        }
        if matches!(self.reason, AssemblyStopReason::Completed) && self.detail.is_some() {
            return Err(ContractViolation::BindingMismatch {
                field: "result.stop.detail",
                reason: "completed assembly cannot carry a stop detail".to_owned(),
            });
        }
        if !matches!(self.reason, AssemblyStopReason::Completed) && self.detail.is_none() {
            return Err(ContractViolation::MissingField("result.stop.detail"));
        }
        Ok(())
    }
}

/// Exact unprocessed role/reference frontier retained by a stopped assembly.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssemblyFrontier {
    /// Roles still requiring material or an explicit ledger outcome.
    pub roles: Vec<DreamInputRole>,
    /// Manifest references not yet admitted to the bundle.
    pub references: Vec<eliot_contracts::ArtifactId>,
    /// Supplied identities still outstanding, including identities rejected
    /// against the current manifest.
    pub supplied_items: Vec<SuppliedItemIdentity>,
}

impl AssemblyFrontier {
    /// Validates bounded, duplicate-free frontier identities.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_vec_bound(self.roles.len(), MAX_FRONTIER, "result.frontier.roles")?;
        check_vec_bound(
            self.references.len(),
            MAX_FRONTIER,
            "result.frontier.references",
        )?;
        check_vec_bound(
            self.supplied_items.len(),
            MAX_FRONTIER,
            "result.frontier.supplied_items",
        )?;
        let mut roles = BTreeSet::new();
        for role in &self.roles {
            if !roles.insert(role.as_str()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.frontier.roles",
                    reason: "frontier roles must be unique".to_owned(),
                });
            }
        }
        let mut references = BTreeSet::new();
        for reference in &self.references {
            check_text(reference.as_str(), "result.frontier.references", 128)?;
            if !references.insert(reference) {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.frontier.references",
                    reason: "frontier references must be unique".to_owned(),
                });
            }
        }
        let mut supplied = BTreeSet::new();
        for item in &self.supplied_items {
            item.validate()?;
            if !supplied.insert(item.clone()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.frontier.supplied_items",
                    reason: "frontier supplied identities must be unique".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Qualified reserve consumption for one assembly result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReserveUsage {
    /// Shared qualified basis for all six reserve dimensions.
    pub profile: eliot_contracts::ArtifactId,
    /// Unit qualified by that profile.
    pub unit: MeasurementUnit,
    pub fixed: u64,
    pub protocol: u64,
    pub model_output: u64,
    pub grounding: u64,
    pub review: u64,
    pub headroom: u64,
}

/// Owner-issued disclosure authorization for the assembled model input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DisclosureAuthorization {
    pub closure: DisclosureDependencyClosure,
    pub decision: DisclosureDecision,
    /// Owner receipts keyed by their exact closure reference. The security
    /// contract intentionally keeps receipt identity outside the receipt body.
    pub declassification_receipts: BTreeMap<String, DeclassificationReceipt>,
    pub redacted_output_digest: Option<String>,
}

impl DisclosureAuthorization {
    #[allow(clippy::too_many_lines)]
    fn validate_retained(
        &self,
        input_digest: &str,
        route_id: &str,
        policy_ref: &str,
        state_fence: &eliot_contracts::StateFence,
    ) -> Result<(), ContractViolation> {
        self.closure
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "result.disclosure.closure",
                reason: error.to_string(),
            })?;
        self.decision
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "result.disclosure.decision",
                reason: error.to_string(),
            })?;
        if self.closure.subject_ref != input_digest
            || self.decision.subject_and_closure_ref != self.closure.closure_id
            || self.decision.recipient_principal_or_route != route_id
            || self.closure.policy_snapshot_id != policy_ref
            || self
                .decision
                .policy_snapshot_and_state_fence
                .policy_snapshot_id
                != policy_ref
            || self.closure.state_fence != *state_fence
            || self.decision.policy_snapshot_and_state_fence.state_fence != *state_fence
            || !self.closure.inherited_closure_refs.is_empty()
            || !self.closure.derivation_or_transformation_refs.is_empty()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "result.disclosure",
                reason: "disclosure authorization does not close the exact model input".to_owned(),
            });
        }
        let closure_domains: BTreeSet<_> = self
            .closure
            .direct_domain_refs
            .iter()
            .map(|domain| domain.domain_id.as_str())
            .collect();
        let covered_domains: BTreeSet<_> = self
            .decision
            .covered_domains
            .iter()
            .map(String::as_str)
            .collect();
        if matches!(
            self.decision.decision,
            DisclosureDecisionKind::Allow | DisclosureDecisionKind::AllowRedacted
        ) && closure_domains != covered_domains
        {
            let uncovered_domains: BTreeSet<_> = self
                .decision
                .uncovered_domains
                .iter()
                .map(String::as_str)
                .collect();
            let mut accounted_domains = covered_domains.clone();
            accounted_domains.extend(uncovered_domains);
            if closure_domains != accounted_domains {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.disclosure.covered_domains",
                    reason:
                        "covered and uncovered domains differ from the exact dependency closure"
                            .to_owned(),
                });
            }
        }
        let mut declared_receipts = BTreeSet::new();
        for receipt_ref in &self.closure.declassification_receipt_refs {
            check_text(
                receipt_ref,
                "result.disclosure.declassification_receipt_refs",
                256,
            )?;
            if !declared_receipts.insert(receipt_ref.as_str()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.disclosure.declassification_receipt_refs",
                    reason: "declassification receipt references must be unique".to_owned(),
                });
            }
        }
        let mut supplied_receipts = BTreeSet::new();
        for (receipt_ref, receipt) in &self.declassification_receipts {
            check_text(
                receipt_ref,
                "result.disclosure.declassification_receipts.key",
                256,
            )?;
            receipt
                .validate()
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "result.disclosure.declassification_receipts",
                    reason: error.to_string(),
                })?;
            if receipt.input_closure_ref != self.closure.closure_id
                || receipt.state_fence != *state_fence
                || receipt.exact_input_hash != input_digest
                || !supplied_receipts.insert(receipt_ref.as_str())
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.disclosure.declassification_receipts",
                    reason: "declassification receipt is bound to another input or fence"
                        .to_owned(),
                });
            }
        }
        if supplied_receipts != declared_receipts {
            return Err(ContractViolation::BindingMismatch {
                field: "result.disclosure.declassification_receipts",
                reason: "declassification references do not exactly cover retained receipts"
                    .to_owned(),
            });
        }
        match self.decision.decision {
            DisclosureDecisionKind::Allow => {
                if self.redacted_output_digest.is_some()
                    || !self.declassification_receipts.is_empty()
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "result.disclosure",
                        reason: "plain allow cannot carry redaction output evidence".to_owned(),
                    });
                }
            }
            DisclosureDecisionKind::AllowRedacted => {
                let output = self.redacted_output_digest.as_deref().ok_or(
                    ContractViolation::MissingField("result.disclosure.redacted_output_digest"),
                )?;
                if !is_hex64_lower(output)
                    || !self
                        .declassification_receipts
                        .iter()
                        .any(|(_, receipt)| receipt.exact_output_hash == output)
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "result.disclosure.redacted_output_digest",
                        reason: "redacted output lacks a matching verified receipt".to_owned(),
                    });
                }
            }
            DisclosureDecisionKind::RecomputeNarrower
            | DisclosureDecisionKind::ForkPrivate
            | DisclosureDecisionKind::RequireAuthority
            | DisclosureDecisionKind::Deny => {}
        }
        Ok(())
    }

    fn validate_for(
        &self,
        input_digest: &str,
        route_id: &str,
        policy_ref: &str,
        state_fence: &eliot_contracts::StateFence,
    ) -> Result<(), ContractViolation> {
        self.validate_retained(input_digest, route_id, policy_ref, state_fence)?;
        if self.closure.completeness != ClosureCompleteness::Complete
            || self.decision.closure_completeness != ClosureCompleteness::Complete
            || !self.decision.uncovered_domains.is_empty()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "result.disclosure",
                reason: "complete result requires complete disclosure domain coverage".to_owned(),
            });
        }
        let closure_domains: BTreeSet<_> = self
            .closure
            .direct_domain_refs
            .iter()
            .map(|domain| domain.domain_id.as_str())
            .collect();
        let covered_domains: BTreeSet<_> = self
            .decision
            .covered_domains
            .iter()
            .map(String::as_str)
            .collect();
        if closure_domains != covered_domains {
            return Err(ContractViolation::BindingMismatch {
                field: "result.disclosure.covered_domains",
                reason: "covered domains differ from the exact dependency closure".to_owned(),
            });
        }
        if self.decision.decision != DisclosureDecisionKind::Allow {
            return Err(ContractViolation::BindingMismatch {
                field: "result.disclosure.decision",
                reason: "only an owner-issued plain allow can certify completion".to_owned(),
            });
        }
        if self.decision.decision == DisclosureDecisionKind::Allow
            && (!self.declassification_receipts.is_empty()
                || !self.closure.declassification_receipt_refs.is_empty()
                || self.redacted_output_digest.is_some())
        {
            return Err(ContractViolation::BindingMismatch {
                field: "result.disclosure",
                reason: "plain allow cannot carry declassification evidence".to_owned(),
            });
        }
        Ok(())
    }
}

impl ReserveUsage {
    /// Validates basis identity, per-category ceilings, and checked totals.
    pub fn validate_against(&self, declared: &AssemblyReserveSet) -> Result<(), ContractViolation> {
        declared.validate()?;
        for (used, reserve) in [
            (self.fixed, &declared.fixed),
            (self.protocol, &declared.protocol),
            (self.model_output, &declared.model_output),
            (self.grounding, &declared.grounding),
            (self.review, &declared.review),
            (self.headroom, &declared.headroom),
        ] {
            if self.profile != reserve.profile || self.unit != reserve.unit {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.reserve_usage",
                    reason: "reserve usage basis differs from declared reserve".to_owned(),
                });
            }
            if used > reserve.value {
                return Err(ContractViolation::Budget {
                    dimension: "assembly_reserve",
                    reason: "reserve usage exceeds declared category".to_owned(),
                });
            }
        }
        self.fixed
            .checked_add(self.protocol)
            .and_then(|total| total.checked_add(self.model_output))
            .and_then(|total| total.checked_add(self.grounding))
            .and_then(|total| total.checked_add(self.review))
            .and_then(|total| total.checked_add(self.headroom))
            .ok_or(ContractViolation::Budget {
                dimension: "assembly_reserve",
                reason: "reserve usage total overflow".to_owned(),
            })?;
        Ok(())
    }

    fn validate_route_fit(
        &self,
        declared: &AssemblyReserveSet,
        measurement: &BundleMeasurement,
        input_bytes: u64,
        require_fit: bool,
    ) -> Result<(), ContractViolation> {
        if !require_fit {
            return Ok(());
        }
        if measurement.profile.unit != MeasurementUnit::Utf8Bytes
            || self.profile != measurement.profile.profile_id
            || self.unit != MeasurementUnit::Utf8Bytes
        {
            return Err(ContractViolation::BindingMismatch {
                field: "result.reserve_usage",
                reason: "complete route fit requires one exact UTF-8 reserve profile".to_owned(),
            });
        }
        let declared_total =
            declared.total_for(&measurement.profile.profile_id, MeasurementUnit::Utf8Bytes)?;
        if declared.fixed.value < measurement.profile.capacity.fixed_overhead
            || declared.model_output.value < measurement.profile.capacity.output_reserve
            || declared.review.value < measurement.profile.capacity.review_reserve
        {
            return Err(ContractViolation::Budget {
                dimension: "assembly_reserve",
                reason: "declared reserve under-covers the route profile capacity reserves"
                    .to_owned(),
            });
        }
        let required =
            input_bytes
                .checked_add(declared_total)
                .ok_or(ContractViolation::Budget {
                    dimension: "assembly_reserve",
                    reason: "route fit arithmetic overflow".to_owned(),
                })?;
        if required > measurement.profile.capacity.route_capacity {
            return Err(ContractViolation::Budget {
                dimension: "assembly_reserve",
                reason: "model input plus all declared reserves exceeds route capacity".to_owned(),
            });
        }
        Ok(())
    }
}

/// Immutable A-04 result carrying the selected bundle and exact closure.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssemblyResult {
    /// Exact result schema version.
    pub schema_version: u32,
    /// Ordinary v1 projection consumed by existing Dreamer handlers. Its
    /// source-scope completeness remains partial or unknown; A-04 certifies
    /// the finite recipe closure separately.
    pub bundle: DreamInputBundle,
    /// Exact recipe, manifest, material, context and Curation closure.
    pub materials: AssemblyMaterialSet,
    /// Bounded assembly outcome.
    pub status: BundleStatus,
    /// Explicit stop category/detail.
    pub stop: AssemblyStop,
    /// Unprocessed role/reference frontier.
    pub frontier: AssemblyFrontier,
    /// Consumption against the recipe's qualified reserves.
    pub reserve_usage: ReserveUsage,
    /// Independent observed consumption for every job budget dimension.
    pub budget_usage: BudgetUsage,
    /// Qualified measurement of the exact model-visible assembly input.
    pub bundle_measurement: BundleMeasurement,
    /// Optional owner-issued disclosure authorization for model exposure.
    pub disclosure: Option<DisclosureAuthorization>,
    /// Canonical digest of this result with this field zeroed.
    pub result_digest: String,
}

impl AssemblyResult {
    /// Returns the exact canonical bytes presented to the model route.
    pub fn canonical_input_bytes(&self) -> Result<Vec<u8>, ContractViolation> {
        self.materials.model_input_bytes()
    }

    /// Returns the exact canonical version-one bundle projection bytes.
    pub fn canonical_output_bytes(&self) -> Result<Vec<u8>, ContractViolation> {
        if matches!(
            self.bundle.completeness,
            BundleCompleteness::CompleteForScope | BundleCompleteness::KnownEmpty
        ) {
            return Err(ContractViolation::BindingMismatch {
                field: "result.bundle.completeness",
                reason:
                    "v1 source-scope complete and known-empty claims are unsupported by assembly"
                        .to_owned(),
            });
        }
        if self.bundle.authoritative_denominator.is_some() {
            return Err(ContractViolation::BindingMismatch {
                field: "result.bundle.authoritative_denominator",
                reason: "v1 source-scope denominator is not owned by assembly".to_owned(),
            });
        }
        self.bundle.validate()?;
        super::canonical_bytes(
            &self.bundle,
            "output_bytes",
            usize::try_from(OUTPUT_BYTES_CEILING).map_err(|_| ContractViolation::Budget {
                dimension: "output_bytes",
                reason: "output byte ceiling does not fit this platform".to_owned(),
            })?,
        )
    }

    /// Returns the exact canonical audit payload bytes. Raw selected material
    /// bodies and mutable budget/result digest fields are intentionally absent.
    pub fn canonical_audit_bytes(&self) -> Result<Vec<u8>, ContractViolation> {
        self.audit_bytes_unchecked()
    }

    /// Computes the canonical result digest after validating all joins.
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        self.validate_preimage_shape()?;
        self.computed_digest_unchecked()
    }

    fn computed_digest_unchecked(&self) -> Result<String, ContractViolation> {
        #[derive(Serialize)]
        struct ResultDigestPreimage<'a> {
            schema_version: u32,
            bundle: &'a DreamInputBundle,
            materials: &'a AssemblyMaterialSet,
            status: BundleStatus,
            stop: &'a AssemblyStop,
            frontier: &'a AssemblyFrontier,
            reserve_usage: &'a ReserveUsage,
            budget_usage: &'a BudgetUsage,
            bundle_measurement: &'a BundleMeasurement,
            disclosure: &'a Option<DisclosureAuthorization>,
            result_digest: &'a str,
        }

        let zero_digest = "0".repeat(64);
        let preimage = ResultDigestPreimage {
            schema_version: self.schema_version,
            bundle: &self.bundle,
            materials: &self.materials,
            status: self.status,
            stop: &self.stop,
            frontier: &self.frontier,
            reserve_usage: &self.reserve_usage,
            budget_usage: &self.budget_usage,
            bundle_measurement: &self.bundle_measurement,
            disclosure: &self.disclosure,
            result_digest: &zero_digest,
        };
        let bytes = super::canonical_bytes(
            &preimage,
            "assembly_carrier",
            super::ASSEMBLY_CARRIER_CEILING,
        )?;
        Ok(digest_hex(&bytes))
    }

    /// Validates the immutable result identity and digest.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.validate_preimage_shape()?;
        if !is_hex64_lower(&self.result_digest) {
            return Err(ContractViolation::Malformed {
                field: "result_digest",
                reason: "expected lowercase SHA-256 digest".to_owned(),
            });
        }
        if self.computed_digest_unchecked()? != self.result_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "result_digest",
                reason: "result preimage digest mismatch".to_owned(),
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn validate_preimage_shape(&self) -> Result<(), ContractViolation> {
        super::preflight(self, "assembly_carrier", super::ASSEMBLY_CARRIER_CEILING)?;
        if self.schema_version != RESULT_SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "result.schema_version",
                min: i64::from(RESULT_SCHEMA_VERSION),
                max: i64::from(RESULT_SCHEMA_VERSION),
                got: i64::from(self.schema_version),
            });
        }
        if matches!(
            self.bundle.completeness,
            BundleCompleteness::CompleteForScope | BundleCompleteness::KnownEmpty
        ) {
            return Err(ContractViolation::BindingMismatch {
                field: "result.bundle.completeness",
                reason:
                    "v1 source-scope complete and known-empty claims are unsupported by assembly"
                        .to_owned(),
            });
        }
        if self.bundle.authoritative_denominator.is_some() {
            return Err(ContractViolation::BindingMismatch {
                field: "result.bundle.authoritative_denominator",
                reason: "v1 source-scope denominator is not owned by assembly".to_owned(),
            });
        }
        self.bundle.validate()?;
        self.materials.validate()?;
        self.stop.validate()?;
        self.frontier.validate()?;
        self.reserve_usage
            .validate_against(&self.materials.recipe.reserves)?;
        self.bundle_measurement.validate_for(&self.materials)?;
        validate_omission_accounting(&self.materials, &self.bundle_measurement)?;
        let job = &self.materials.recipe.job;
        if self.status == BundleStatus::KnownEmpty {
            validate_known_empty(&self.materials, &self.bundle)?;
        }
        if let Some(disclosure) = &self.disclosure {
            disclosure.validate_retained(
                &self.bundle_measurement.input_digest,
                &self.bundle_measurement.profile.route_id,
                &job.policy_ref,
                &job.state_fence,
            )?;
        }
        let input_bytes = self.materials.model_input_bytes_unchecked()?;
        let output_bytes = super::canonical_bytes(
            &self.bundle,
            "output_bytes",
            usize::try_from(OUTPUT_BYTES_CEILING).map_err(|_| ContractViolation::Budget {
                dimension: "output_bytes",
                reason: "output byte ceiling does not fit this platform".to_owned(),
            })?,
        )?;
        let audit_bytes = self.audit_bytes_unchecked()?;
        self.validate_accounting(
            job,
            input_bytes.len(),
            output_bytes.len(),
            audit_bytes.len(),
        )?;
        if self.status == BundleStatus::Complete {
            let disclosure = self
                .disclosure
                .as_ref()
                .ok_or(ContractViolation::MissingField("result.disclosure"))?;
            disclosure.validate_for(
                &self.bundle_measurement.input_digest,
                &self.bundle_measurement.profile.route_id,
                &job.policy_ref,
                &job.state_fence,
            )?;
        }
        if self.bundle.job_id != job.canonical_id()
            || self.bundle.task_id != job.task_id
            || self.bundle.scope_id != job.scope_id
            || self.bundle.state_fence != job.state_fence
            || self.bundle.manifest_digest != self.materials.manifest.digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "result.bundle",
                reason: "bundle differs from recipe or material identity".to_owned(),
            });
        }
        self.validate_bundle_projection()?;
        if !bundle_status_matches(self.status, self.bundle.completeness) {
            return Err(ContractViolation::BindingMismatch {
                field: "result.status",
                reason: "status and bundle completeness disagree".to_owned(),
            });
        }
        if self.status == BundleStatus::Complete
            && job.job_class == crate::job::JobClass::Curation
            && !self.materials.has_complete_curation_material()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "result.curation",
                reason: "complete Curation result requires the complete screen closure".to_owned(),
            });
        }
        if self.status == BundleStatus::Complete {
            if self.materials.recipe.context_required && self.materials.context.is_none() {
                return Err(ContractViolation::MissingField("result.materials.context"));
            }
            validate_complete_roles(&self.materials)?;
        }
        validate_stop_and_frontier(self.status, &self.stop, &self.frontier, &self.materials)
    }

    fn audit_bytes_unchecked(&self) -> Result<Vec<u8>, ContractViolation> {
        #[derive(Serialize)]
        struct AuditProjection<'a> {
            schema_version: u32,
            status: BundleStatus,
            stop: &'a AssemblyStop,
            frontier: &'a AssemblyFrontier,
            role_outcomes: &'a [RoleOutcome],
            ledger: &'a [MaterialLedgerEntry],
            conditional_evaluations: &'a [super::material::ConditionalEvaluation],
            reserve_usage: &'a ReserveUsage,
            bundle_measurement: &'a BundleMeasurement,
            disclosure: &'a Option<DisclosureAuthorization>,
        }

        super::canonical_bytes(
            &AuditProjection {
                schema_version: RESULT_SCHEMA_VERSION,
                status: self.status,
                stop: &self.stop,
                frontier: &self.frontier,
                role_outcomes: &self.materials.role_outcomes,
                ledger: &self.materials.ledger,
                conditional_evaluations: &self.materials.conditional_evaluations,
                reserve_usage: &self.reserve_usage,
                bundle_measurement: &self.bundle_measurement,
                disclosure: &self.disclosure,
            },
            "report_bytes",
            usize::try_from(REPORT_BYTES_CEILING).map_err(|_| ContractViolation::Budget {
                dimension: "report_bytes",
                reason: "report byte ceiling does not fit this platform".to_owned(),
            })?,
        )
    }

    fn validate_accounting(
        &self,
        job: &crate::job::DreamJobInput,
        input_len: usize,
        output_len: usize,
        audit_len: usize,
    ) -> Result<(), ContractViolation> {
        let input_bytes = u64::try_from(input_len).map_err(|_| ContractViolation::Budget {
            dimension: "input_bytes",
            reason: "canonical input byte count overflows budget accounting".to_owned(),
        })?;
        let output_bytes = u64::try_from(output_len).map_err(|_| ContractViolation::Budget {
            dimension: "output_bytes",
            reason: "canonical output byte count overflows budget accounting".to_owned(),
        })?;
        let report_bytes = u64::try_from(audit_len).map_err(|_| ContractViolation::Budget {
            dimension: "report_bytes",
            reason: "canonical audit byte count overflows budget accounting".to_owned(),
        })?;
        if self.budget_usage.input_bytes != input_bytes
            || self.budget_usage.output_bytes != output_bytes
            || self.budget_usage.report_bytes != report_bytes
        {
            return Err(ContractViolation::BindingMismatch {
                field: "result.budget_usage",
                reason: "byte usage differs from the exact canonical artifacts".to_owned(),
            });
        }

        let reference_width =
            u64::try_from(self.materials.selected_references.len()).map_err(|_| {
                ContractViolation::Budget {
                    dimension: "reference_width",
                    reason: "selected reference count overflows budget accounting".to_owned(),
                }
            })?;
        let source_width = selected_source_owner_count(&self.materials)?;
        if self.budget_usage.reference_width != reference_width
            || self.budget_usage.source_width != source_width
        {
            return Err(ContractViolation::BindingMismatch {
                field: "result.budget_usage",
                reason: "source/reference width does not match selected closure".to_owned(),
            });
        }
        if self.budget_usage.model_calls != 0
            || self.budget_usage.candidates != 0
            || self.budget_usage.work_fan_out != 0
        {
            return Err(ContractViolation::BindingMismatch {
                field: "result.budget_usage",
                reason:
                    "assembly cannot claim model calls, candidates, or fan-out it did not execute"
                        .to_owned(),
            });
        }
        // STU is an independent supplied planning observation. It is checked
        // against usage and both recipe/job limits below, without converting
        // it into bytes or tokens.
        if let Some(estimate) = &self.bundle_measurement.stu_estimate {
            if self.budget_usage.stu_used != estimate.value {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.budget_usage.stu_used",
                    reason: "STU usage differs from the supplied planning observation".to_owned(),
                });
            }
        } else if self.budget_usage.stu_used != 0 {
            return Err(ContractViolation::BindingMismatch {
                field: "result.budget_usage.stu_used",
                reason: "STU usage requires a supplied planning observation".to_owned(),
            });
        }
        if self.status == BundleStatus::Complete && self.bundle_measurement.stu_estimate.is_none() {
            return Err(ContractViolation::BindingMismatch {
                field: "result.bundle_measurement.stu_estimate",
                reason: "complete result requires a supplied STU observation".to_owned(),
            });
        }
        if self.status != BundleStatus::BudgetExhausted {
            self.budget_usage.fits(&self.materials.recipe.limits)?;
            self.budget_usage.fits(&job.budget)?;
        }
        self.reserve_usage.validate_route_fit(
            &self.materials.recipe.reserves,
            &self.bundle_measurement,
            input_bytes,
            self.status == BundleStatus::Complete,
        )?;
        if self.status == BundleStatus::Complete
            && !matches!(self.bundle_measurement.status, MeasurementStatus::ExactUtf8)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "result.bundle_measurement.status",
                reason: "complete result requires an exact fitted UTF-8 measurement".to_owned(),
            });
        }
        if self.status == BundleStatus::BudgetExhausted {
            validate_budget_exhausted_evidence(self, input_bytes)?;
        }
        Ok(())
    }

    fn validate_bundle_projection(&self) -> Result<(), ContractViolation> {
        let expected_materials: BTreeSet<_> = self
            .materials
            .materials
            .iter()
            .map(|material| material.material.handle.as_str())
            .collect();
        let projected_materials: BTreeSet<_> = self
            .bundle
            .materials
            .iter()
            .map(|material| material.handle.as_str())
            .collect();
        if expected_materials != projected_materials {
            return Err(ContractViolation::BindingMismatch {
                field: "result.bundle.materials",
                reason: "bundle material handles differ from the exact selected set".to_owned(),
            });
        }
        for material in &self.materials.materials {
            let Some(bundle_material) = self
                .bundle
                .materials
                .iter()
                .find(|candidate| candidate.handle == material.material.handle)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.bundle.materials",
                    reason: "selected material is absent from bundle projection".to_owned(),
                });
            };
            if bundle_material != &material.material {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.bundle.materials",
                    reason: "bundle material differs from selected closure".to_owned(),
                });
            }
        }
        let mut ledger_omission_handles = BTreeSet::new();
        for entry in &self.materials.ledger {
            if let Some(omission) = &entry.omission
                && !ledger_omission_handles.insert(omission.handle.as_str())
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.bundle.omissions",
                    reason: "omission handles must be unique before projection".to_owned(),
                });
            }
        }
        let mut bundle_omission_handles = BTreeSet::new();
        for omission in &self.bundle.omissions {
            if !bundle_omission_handles.insert(omission.handle.as_str()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.bundle.omissions",
                    reason: "omission handles must be unique before projection".to_owned(),
                });
            }
        }
        let expected_omissions: BTreeMap<_, _> = self
            .materials
            .ledger
            .iter()
            .filter_map(|entry| {
                entry
                    .omission
                    .as_ref()
                    .map(|omission| (omission.handle.as_str(), omission))
            })
            .collect();
        let projected_omissions: BTreeMap<_, _> = self
            .bundle
            .omissions
            .iter()
            .map(|omission| (omission.handle.as_str(), omission))
            .collect();
        if expected_omissions != projected_omissions {
            return Err(ContractViolation::BindingMismatch {
                field: "result.bundle.omissions",
                reason: "bundle omissions differ from the exact permitted omission ledger"
                    .to_owned(),
            });
        }
        for entry in &self.materials.ledger {
            if entry.disposition == MaterialDisposition::Included
                && entry
                    .handle
                    .as_ref()
                    .is_some_and(|handle| !projected_materials.contains(handle.as_str()))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.bundle.materials",
                    reason: "included ledger item is absent from bundle projection".to_owned(),
                });
            }
        }
        Ok(())
    }
}

fn validate_budget_exhausted_evidence(
    result: &AssemblyResult,
    input_bytes: u64,
) -> Result<(), ContractViolation> {
    let recipe = &result.materials.recipe;
    let usage = &result.budget_usage;
    let exceeds = |limits: &crate::budget::BudgetLimits| {
        [
            (usage.input_bytes, limits.input_bytes),
            (usage.output_bytes, limits.output_bytes),
            (usage.source_width, limits.source_width),
            (usage.reference_width, limits.reference_width),
            (usage.model_calls, limits.model_calls),
            (usage.attempts, limits.attempts),
            (usage.candidates, limits.candidates),
            (usage.wall_ms, limits.wall_ms),
            (usage.work_fan_out, limits.work_fan_out),
            (usage.report_bytes, limits.report_bytes),
        ]
        .iter()
        .any(|(used, limit)| limit.is_some_and(|limit| *used > limit))
            || limits.max_stu.is_some_and(|limit| usage.stu_used > limit)
    };
    let budget_overage = exceeds(&recipe.limits) || exceeds(&recipe.job.budget);
    let route_overage = if result.bundle_measurement.profile.unit == MeasurementUnit::Utf8Bytes
        && result.reserve_usage.profile == result.bundle_measurement.profile.profile_id
        && result.reserve_usage.unit == MeasurementUnit::Utf8Bytes
    {
        recipe
            .reserves
            .total_for(
                &result.bundle_measurement.profile.profile_id,
                MeasurementUnit::Utf8Bytes,
            )
            .ok()
            .and_then(|reserves| input_bytes.checked_add(reserves))
            .is_some_and(|required| {
                required > result.bundle_measurement.profile.capacity.route_capacity
            })
    } else {
        false
    };
    let frontier_overage = result.frontier.supplied_items.iter().any(|identity| {
        result.materials.ledger.iter().any(|entry| {
            entry.role == identity.role
                && entry.ordinal == identity.ordinal
                && entry.handle == identity.handle
                && entry.content_digest == identity.content_digest
                && entry.source_revision == identity.source_revision
                && matches!(
                    entry.disposition,
                    MaterialDisposition::Blocked | MaterialDisposition::Unavailable
                )
                && entry.reason == Some(MaterialOutcomeReason::BudgetExceeded)
        })
    });
    let omission_overage = result.materials.ledger.iter().any(|entry| {
        entry.disposition == MaterialDisposition::Omitted
            && entry.reason == Some(MaterialOutcomeReason::BudgetExceeded)
            && entry
                .omission_accounting
                .as_ref()
                .is_some_and(|accounting| !accounting.constraints.is_empty())
    });
    if !(budget_overage || route_overage || frontier_overage || omission_overage) {
        return Err(ContractViolation::BindingMismatch {
            field: "result.status",
            reason: "budget-exhausted status lacks an independent retained budget-stop observation"
                .to_owned(),
        });
    }
    Ok(())
}

fn validate_omission_accounting(
    materials: &AssemblyMaterialSet,
    measurement: &BundleMeasurement,
) -> Result<(), ContractViolation> {
    let recipe = &materials.recipe;
    for entry in materials
        .ledger
        .iter()
        .filter(|entry| entry.disposition == MaterialDisposition::Omitted)
    {
        let accounting =
            entry
                .omission_accounting
                .as_ref()
                .ok_or(ContractViolation::MissingField(
                    "material.ledger.omission_accounting",
                ))?;
        if entry.reason == Some(MaterialOutcomeReason::BudgetExceeded)
            && accounting.constraints.is_empty()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "material.ledger.omission_accounting.constraints",
                reason: "budget-exceeded omission requires a competing accounting constraint"
                    .to_owned(),
            });
        }
        for constraint in &accounting.constraints {
            match constraint {
                AssemblyOmissionConstraint::Budget {
                    dimension, limit, ..
                } => {
                    let recipe_limit = budget_limit(&recipe.limits, *dimension);
                    let job_limit = budget_limit(&recipe.job.budget, *dimension);
                    if Some(*limit)
                        != recipe_limit
                            .zip(job_limit)
                            .map(|(recipe, job)| recipe.min(job))
                    {
                        return Err(ContractViolation::BindingMismatch {
                            field: "material.ledger.omission_accounting.constraints",
                            reason: "omitted budget constraint differs from recipe and job limits"
                                .to_owned(),
                        });
                    }
                }
                AssemblyOmissionConstraint::RouteCapacity {
                    profile,
                    unit,
                    limit,
                    ..
                } => {
                    if profile != &measurement.profile.profile_id
                        || unit != &measurement.profile.unit
                        || *limit != measurement.profile.capacity.route_capacity
                    {
                        return Err(ContractViolation::BindingMismatch {
                            field: "material.ledger.omission_accounting.constraints",
                            reason: "omitted route constraint differs from the exact measurement profile"
                                .to_owned(),
                        });
                    }
                }
                AssemblyOmissionConstraint::RoleMaximum {
                    maximum,
                    supplied_count,
                } => {
                    let role = recipe
                        .roles
                        .iter()
                        .find(|role| role.role == entry.role)
                        .ok_or(ContractViolation::BindingMismatch {
                            field: "material.ledger.omission_accounting.constraints",
                            reason: "omitted role constraint names an absent recipe role"
                                .to_owned(),
                        })?;
                    let actual_count = u32::try_from(
                        materials
                            .supplied_items
                            .iter()
                            .filter(|item| item.role == entry.role)
                            .count(),
                    )
                    .map_err(|_| ContractViolation::Budget {
                        dimension: "omission_role_maximum",
                        reason: "supplied role count overflows accounting".to_owned(),
                    })?;
                    if *maximum != role.maximum || *supplied_count != actual_count {
                        return Err(ContractViolation::BindingMismatch {
                            field: "material.ledger.omission_accounting.constraints",
                            reason:
                                "omitted role maximum does not match the exact recipe denominator"
                                    .to_owned(),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

fn budget_limit(limits: &crate::budget::BudgetLimits, dimension: BudgetDimension) -> Option<u64> {
    match dimension {
        BudgetDimension::InputBytes => limits.input_bytes,
        BudgetDimension::OutputBytes => limits.output_bytes,
        BudgetDimension::SourceWidth => limits.source_width,
        BudgetDimension::ReferenceWidth => limits.reference_width,
        BudgetDimension::ModelCalls => limits.model_calls,
        BudgetDimension::Attempts => limits.attempts,
        BudgetDimension::Candidates => limits.candidates,
        BudgetDimension::WallMs => limits.wall_ms,
        BudgetDimension::WorkFanOut => limits.work_fan_out,
        BudgetDimension::ReportBytes => limits.report_bytes,
    }
}

fn validate_known_empty(
    materials: &AssemblyMaterialSet,
    bundle: &DreamInputBundle,
) -> Result<(), ContractViolation> {
    if !bundle.materials.is_empty()
        || !bundle.omissions.is_empty()
        || !materials.materials.is_empty()
        || !materials.supplied_items.is_empty()
        || materials
            .ledger
            .iter()
            .any(|entry| entry.disposition != MaterialDisposition::NotApplicable)
    {
        return Err(ContractViolation::BindingMismatch {
            field: "result.bundle.completeness",
            reason: "known-empty bundle cannot retain or account for supplied items".to_owned(),
        });
    }
    for role in &materials.recipe.roles {
        if role.disposition == RoleDisposition::Required && role.minimum > 0 {
            return Err(ContractViolation::BindingMismatch {
                field: "result.roles",
                reason: "known-empty bundle cannot satisfy a positive required role".to_owned(),
            });
        }
        if role.disposition == RoleDisposition::Conditional {
            let evaluation = materials
                .conditional_evaluations
                .iter()
                .find(|evaluation| evaluation.role == role.role)
                .ok_or(ContractViolation::MissingField(
                    "material.conditional_evaluations",
                ))?;
            if evaluation.state == ConditionalEvaluationState::True && role.minimum > 0 {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.roles",
                    reason: "known-empty bundle cannot satisfy a true conditional role".to_owned(),
                });
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn validate_complete_roles(materials: &AssemblyMaterialSet) -> Result<(), ContractViolation> {
    for role in &materials.recipe.roles {
        let entries: Vec<_> = materials
            .ledger
            .iter()
            .filter(|entry| entry.role == role.role)
            .collect();
        let included = entries
            .iter()
            .filter(|entry| entry.disposition == MaterialDisposition::Included)
            .count();
        let outcome = materials
            .role_outcomes
            .iter()
            .find(|outcome| outcome.role == role.role)
            .ok_or(ContractViolation::MissingField("material.role_outcomes"))?;
        match role.disposition {
            RoleDisposition::Required if included < role.minimum as usize => {
                return Err(ContractViolation::BindingMismatch {
                    field: "result.roles",
                    reason: "complete result does not meet a required role minimum".to_owned(),
                });
            }
            RoleDisposition::Conditional => {
                let evaluation = materials
                    .conditional_evaluations
                    .iter()
                    .find(|evaluation| evaluation.role == role.role)
                    .ok_or(ContractViolation::MissingField(
                        "material.conditional_evaluations",
                    ))?;
                match evaluation.state {
                    super::material::ConditionalEvaluationState::KnownFalse if included != 0 => {
                        return Err(ContractViolation::BindingMismatch {
                            field: "result.roles",
                            reason: "known-false conditional role retained an item".to_owned(),
                        });
                    }
                    super::material::ConditionalEvaluationState::KnownFalse => {}
                    super::material::ConditionalEvaluationState::Unresolved => {
                        return Err(ContractViolation::BindingMismatch {
                            field: "result.roles",
                            reason: "complete result has an unresolved conditional role".to_owned(),
                        });
                    }
                    super::material::ConditionalEvaluationState::True => {
                        if included < role.minimum as usize {
                            return Err(ContractViolation::BindingMismatch {
                                field: "result.roles",
                                reason: "true conditional role misses its positive minimum"
                                    .to_owned(),
                            });
                        }
                    }
                }
            }
            _ => {}
        }
        if outcome.state == super::material::RoleOutcomeState::Unresolved {
            return Err(ContractViolation::BindingMismatch {
                field: "result.roles",
                reason: "complete result has an unresolved role outcome".to_owned(),
            });
        }
        if outcome.state == super::material::RoleOutcomeState::Missing
            && role.disposition == RoleDisposition::Required
        {
            return Err(ContractViolation::BindingMismatch {
                field: "result.roles",
                reason: "required role is marked missing".to_owned(),
            });
        }
        if role.disposition != RoleDisposition::NotApplicable
            && (role.protected
                || matches!(
                    role.representation_loss,
                    eliot_context_contracts::LossPolicy::NonDroppable
                ))
        {
            for supplied in materials
                .supplied_items
                .iter()
                .filter(|identity| identity.role == role.role)
            {
                if !materials.ledger.iter().any(|entry| {
                    entry.disposition == MaterialDisposition::Included
                        && entry.role == supplied.role
                        && entry.ordinal == supplied.ordinal
                        && entry.handle == supplied.handle
                        && entry.content_digest == supplied.content_digest
                        && entry.source_revision == supplied.source_revision
                }) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "result.roles",
                        reason: "protected or non-droppable role dropped a supplied item"
                            .to_owned(),
                    });
                }
            }
        }
        if included > 0 {
            for dependency in &role.interpretation_dependencies {
                let dependency_role = materials
                    .recipe
                    .roles
                    .iter()
                    .find(|candidate| candidate.role == *dependency)
                    .ok_or(ContractViolation::BindingMismatch {
                        field: "result.roles",
                        reason: "role dependency is absent from recipe".to_owned(),
                    })?;
                if dependency_role.disposition == RoleDisposition::NotApplicable
                    || dependency_role.maximum == 0
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "result.roles",
                        reason: "role dependency must target an applicable non-empty role"
                            .to_owned(),
                    });
                }
                let minimum = usize::max(1, dependency_role.minimum as usize);
                let dependency_included = materials
                    .ledger
                    .iter()
                    .filter(|entry| {
                        entry.role == *dependency
                            && entry.disposition == MaterialDisposition::Included
                    })
                    .count();
                if dependency_included < minimum {
                    return Err(ContractViolation::BindingMismatch {
                        field: "result.roles",
                        reason: "included role lacks its dependency minimum".to_owned(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn selected_source_owner_count(materials: &AssemblyMaterialSet) -> Result<u64, ContractViolation> {
    let mut owners = BTreeSet::new();
    for reference in materials.selected_references.values() {
        let owner = reference
            .source_lineage
            .as_ref()
            .map(|lineage| lineage.owner.clone())
            .or_else(|| {
                reference.provenance.as_ref().and_then(|provenance| {
                    provenance
                        .lineage
                        .iter()
                        .find(|lineage| {
                            lineage.content_digest == reference.content_digest
                                && lineage.revision == reference.source_revision
                        })
                        .map(|lineage| lineage.owner.clone())
                })
            })
            .ok_or(ContractViolation::BindingMismatch {
                field: "result.budget_usage.source_width",
                reason: "selected source lacks an exact owner lineage binding".to_owned(),
            })?;
        owners.insert(owner);
    }
    u64::try_from(owners.len()).map_err(|_| ContractViolation::Budget {
        dimension: "source_width",
        reason: "selected source owner count overflows budget accounting".to_owned(),
    })
}

#[allow(clippy::too_many_lines)]
fn validate_stop_and_frontier(
    status: BundleStatus,
    stop: &AssemblyStop,
    frontier: &AssemblyFrontier,
    materials: &AssemblyMaterialSet,
) -> Result<(), ContractViolation> {
    let expected_roles: BTreeSet<_> = materials
        .recipe
        .roles
        .iter()
        .filter_map(|role| {
            let outcome = materials
                .role_outcomes
                .iter()
                .find(|outcome| outcome.role == role.role)?;
            let retained = outcome.retained_count;
            let unresolved = matches!(
                outcome.state,
                RoleOutcomeState::Missing | RoleOutcomeState::Unresolved
            ) || (role.disposition == RoleDisposition::Required
                && retained < role.minimum)
                || (role.disposition == RoleDisposition::Conditional
                    && materials
                        .conditional_evaluations
                        .iter()
                        .find(|evaluation| evaluation.role == role.role)
                        .is_some_and(|evaluation| {
                            evaluation.state == ConditionalEvaluationState::Unresolved
                                || (evaluation.state == ConditionalEvaluationState::True
                                    && retained < role.minimum)
                        }));
            unresolved.then_some(role.role.as_str())
        })
        .collect();
    let actual_roles: BTreeSet<_> = frontier.roles.iter().map(|role| role.as_str()).collect();
    if actual_roles != expected_roles {
        return Err(ContractViolation::BindingMismatch {
            field: "result.frontier.roles",
            reason: "frontier roles differ from unresolved declared roles".to_owned(),
        });
    }
    let outstanding: BTreeSet<_> = materials
        .supplied_items
        .iter()
        .filter(|identity| {
            materials.ledger.iter().any(|entry| {
                entry.role == identity.role
                    && entry.ordinal == identity.ordinal
                    && entry.handle == identity.handle
                    && entry.content_digest == identity.content_digest
                    && entry.source_revision == identity.source_revision
                    && matches!(
                        entry.disposition,
                        MaterialDisposition::Unavailable | MaterialDisposition::Blocked
                    )
            })
        })
        .cloned()
        .collect();
    let actual_outstanding: BTreeSet<_> = frontier.supplied_items.iter().cloned().collect();
    if actual_outstanding != outstanding {
        return Err(ContractViolation::BindingMismatch {
            field: "result.frontier.supplied_items",
            reason: "frontier supplied identities differ from outstanding ledger items".to_owned(),
        });
    }
    let expected_references: BTreeSet<_> = outstanding
        .iter()
        .filter_map(|identity| identity.handle.as_ref())
        .filter(|handle| materials.manifest.references.contains_key(*handle))
        .cloned()
        .collect();
    let actual_references: BTreeSet<_> = frontier.references.iter().cloned().collect();
    if expected_references != actual_references {
        return Err(ContractViolation::BindingMismatch {
            field: "result.frontier.references",
            reason: "frontier references differ from outstanding current-manifest identities"
                .to_owned(),
        });
    }
    if status == BundleStatus::Complete
        && (stop.reason != AssemblyStopReason::Completed
            || !frontier.roles.is_empty()
            || !frontier.references.is_empty()
            || !frontier.supplied_items.is_empty())
    {
        return Err(ContractViolation::BindingMismatch {
            field: "result.frontier",
            reason: "complete result must have a completed empty frontier".to_owned(),
        });
    }
    if status == BundleStatus::BudgetExhausted && stop.reason != AssemblyStopReason::BudgetExhausted
    {
        return Err(ContractViolation::BindingMismatch {
            field: "result.stop.reason",
            reason: "budget-exhausted result requires a budget stop".to_owned(),
        });
    }
    if status != BundleStatus::Complete && stop.reason == AssemblyStopReason::Completed {
        return Err(ContractViolation::BindingMismatch {
            field: "result.stop.reason",
            reason: "noncomplete result cannot claim completion".to_owned(),
        });
    }
    if status != BundleStatus::BudgetExhausted && stop.reason == AssemblyStopReason::BudgetExhausted
    {
        return Err(ContractViolation::BindingMismatch {
            field: "result.stop.reason",
            reason: "budget stop requires an explicitly budget-exhausted status".to_owned(),
        });
    }
    Ok(())
}

fn bundle_status_matches(status: BundleStatus, completeness: BundleCompleteness) -> bool {
    match status {
        BundleStatus::Complete | BundleStatus::KnownEmpty => {
            matches!(
                completeness,
                BundleCompleteness::PartialForScope | BundleCompleteness::Unknown
            )
        }
        BundleStatus::Partial => completeness == BundleCompleteness::PartialForScope,
        BundleStatus::Blocked
        | BundleStatus::Stale
        | BundleStatus::Unavailable
        | BundleStatus::BudgetExhausted => completeness != BundleCompleteness::CompleteForScope,
    }
}

/// Schema version used by result envelopes.
pub const fn result_schema_version() -> u32 {
    RESULT_SCHEMA_VERSION
}
