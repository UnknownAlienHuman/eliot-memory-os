//! Cold-start privacy/source input join at the daemon admission boundary.
//!
//! Host discovery contributes bounded identities and filename-only source
//! candidates. This module never promotes those names to authority. It joins
//! later owner-produced values to the exact Host candidate, onboarding lease,
//! Kernel scan binding, and authenticated scanner readback. The join checks
//! consistency; it does not authenticate the provenance of a privacy profile
//! or source set. The current daemon route has no producer/readback for those
//! values, so callers must not construct this join from ticket or filename
//! data and W3 remains partial until that owner route exists.

use super::{ColdStartDiscoveryInput, TaskBindingError};
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_governor::{GoverningSourceSet, InstallationScanDisclosureStore, PrivacyProfile};
use eliot_workscope::{
    BootstrapScanEvidence, OnboardingLease, PrivacyBoundary, ScanDisclosureOwnerBinding,
    ScanDisclosureReceipt, ScanDisclosureStore, ScanReceiptHandle, WorkScopeCandidate,
};

/// Owner inputs absent from the current authenticated discovery route.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ColdStartAuthorityInputGap {
    CandidatePrivacyClass,
    PrivacyBoundary,
    ScannerPolicy,
    PrivacyProfile,
    OwnerReadbackForPrivacyBoundaryAndProfile,
    OwnerAdmittedSourcesWithContentDigests,
    AuthenticatedScanBindingAndDurableReadback,
}

/// Explicit gap view for the observed Host discovery. Candidate paths are
/// intentionally omitted so a bridge cannot mistake filenames for authority
/// or disclose them as an inferred governing-source set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ColdStartAuthorityInputReadiness {
    missing: Vec<ColdStartAuthorityInputGap>,
}

impl ColdStartAuthorityInputReadiness {
    fn from_discovery(discovery: &ColdStartDiscoveryInput) -> Self {
        let mut missing = Vec::new();
        if discovery.discovery.candidate_privacy.is_none() {
            missing.push(ColdStartAuthorityInputGap::CandidatePrivacyClass);
        }
        if discovery.discovery.privacy_boundary.is_none() {
            missing.push(ColdStartAuthorityInputGap::PrivacyBoundary);
        }
        if discovery.discovery.policy.is_none() {
            missing.push(ColdStartAuthorityInputGap::ScannerPolicy);
        }
        // BootstrapDiscoveryInputs has only candidate references. It carries
        // neither the admitted profile nor the content-bound source set.
        missing.push(ColdStartAuthorityInputGap::PrivacyProfile);
        // Presence of plain option fields is not proof of their producer.
        // This owner readback gap remains until the applicable authority
        // returns a provenance-bearing record, which this route lacks.
        missing.push(ColdStartAuthorityInputGap::OwnerReadbackForPrivacyBoundaryAndProfile);
        missing.push(ColdStartAuthorityInputGap::OwnerAdmittedSourcesWithContentDigests);
        // The scan binding and receipt handle are produced by the Kernel /
        // scanner owner path after an authorized scan; they are not in the
        // activation ticket or Host discovery input.
        missing.push(ColdStartAuthorityInputGap::AuthenticatedScanBindingAndDurableReadback);
        Self { missing }
    }

    /// Owner-produced evidence still required for a sound readiness join.
    #[must_use]
    pub fn missing(&self) -> &[ColdStartAuthorityInputGap] {
        &self.missing
    }
}

impl ColdStartDiscoveryInput {
    /// Describes the authority-bearing inputs absent from this Host
    /// observation. In the current route this remains incomplete because
    /// source candidates are names only and no owner readback supplies the
    /// privacy profile or governing-source content digests.
    #[must_use]
    pub fn authority_input_readiness(&self) -> ColdStartAuthorityInputReadiness {
        ColdStartAuthorityInputReadiness::from_discovery(self)
    }
}

/// A cross-owner consistency join for values required by
/// `GovernorComposition::build_cold_start_readiness_claim`.
///
/// Construction re-reads the durable scan receipt through the installation
/// store and binds every supplied value to the Host observation and current
/// fence presented by the caller. It does not authenticate who produced the
/// privacy boundary/profile/source set; that must come from the missing
/// applicable owner readback. The Governor composition must still revalidate
/// its live fence and perform its own receipt readback immediately before
/// building a claim.
#[derive(Clone, Debug)]
pub struct ColdStartAuthorityInputJoin {
    candidate: WorkScopeCandidate,
    proposed: OnboardingLease,
    boundary: PrivacyBoundary,
    privacy: PrivacyProfile,
    sources: GoverningSourceSet,
    scan: BootstrapScanEvidence,
    scan_binding: ScanDisclosureOwnerBinding,
    scan_receipt: ScanReceiptHandle,
    scan_readback: ScanDisclosureReceipt,
}

impl ColdStartAuthorityInputJoin {
    /// Checks an owner-provided candidate/profile/source snapshot against the
    /// exact retained Host discovery and owner-authenticated scanner receipt.
    /// This is a consistency boundary only; callers must supply real owner
    /// readbacks for the privacy and source values.
    #[allow(clippy::too_many_arguments)]
    pub fn try_join(
        discovery: &ColdStartDiscoveryInput,
        state_fence: &StateFence,
        candidate: &WorkScopeCandidate,
        proposed: &OnboardingLease,
        boundary: &PrivacyBoundary,
        privacy: &PrivacyProfile,
        sources: &GoverningSourceSet,
        scan_store: &InstallationScanDisclosureStore,
        scan_binding: &ScanDisclosureOwnerBinding,
        scan_receipt: &ScanReceiptHandle,
    ) -> Result<Self, TaskBindingError> {
        let fail = |detail: &str| TaskBindingError::scope_incompatible(detail);
        let host = &discovery.discovery;
        let evidence = &host.evidence;

        state_fence
            .validate()
            .map_err(|error| fail(&format!("cold-start state fence is invalid: {error}")))?;
        discovery.key.validate().map_err(|error| {
            fail(&format!("Host discovery lease key is invalid: {error}"))
        })?;
        discovery.lease.validate().map_err(|error| {
            fail(&format!("Host discovery lease is invalid: {error}"))
        })?;
        if !discovery.lease.key_matches(
            &discovery.key.proposer_ref,
            &discovery.key.session_ref,
            &discovery.key.host_ref,
            &discovery.key.root_filesystem_identity_ref,
        ) || discovery.lease.proposer_ref != discovery.key.proposer_ref
            || discovery.lease.session_ref != discovery.key.session_ref
            || discovery.lease.host_ref != discovery.key.host_ref
            || discovery.lease.root_filesystem_identity_ref
                != discovery.key.root_filesystem_identity_ref
        {
            return Err(fail("Host discovery lease and key do not match exactly"));
        }
        host.observed.validate().map_err(|error| {
            fail(&format!("Host discovery observation is invalid: {error}"))
        })?;
        evidence.validate().map_err(|error| {
            fail(&format!("Host scan evidence is invalid: {error}"))
        })?;
        let policy = host
            .policy
            .as_ref()
            .ok_or_else(|| fail("scanner policy is not present in the Host discovery"))?;
        policy.validate().map_err(|error| {
            fail(&format!("Host scanner policy is invalid: {error}"))
        })?;
        if host.scan_ref.trim().is_empty()
            || host.identity_fingerprint != candidate.instance.instance_ref
            || evidence.canonical_root_ref != candidate.scope.root_identity
            || evidence.filesystem_identity_ref != candidate.instance.root_identity
            || discovery.lease.candidate_root_ref != candidate.scope.root_identity
            || discovery.lease.root_filesystem_identity_ref != candidate.scope.root_identity
            || !host
                .observed
                .root_identities
                .contains(&candidate.scope.root_identity)
            || !host.observed.instances.iter().any(|instance| {
                instance.instance_ref == candidate.instance.instance_ref
                    && instance.root_identity == candidate.instance.root_identity
            })
            || evidence.vcs_branch_ref != host.observed.generation.branch_ref
            || evidence.vcs_commit_ref != host.observed.generation.commit_ref
            || evidence.vcs_dirty_summary_ref != host.observed.generation.dirty_summary_ref
            || candidate.instance.root_identity != candidate.scope.root_identity
            || candidate.scope.instance_ref != candidate.instance.instance_ref
            || candidate.scope.lineage_ref.as_deref()
                != Some(proposed.lineage_candidate_ref.as_str())
            || proposed.workspace_instance_candidate_ref != candidate.instance.instance_ref
            || proposed.privacy_class != candidate.privacy_class
        {
            return Err(fail(
                "candidate and onboarding lease do not match the retained Host identity",
            ));
        }
        candidate.scope.validate().map_err(|error| {
            fail(&format!("cold-start candidate scope is invalid: {error}"))
        })?;
        candidate.instance.validate().map_err(|error| {
            fail(&format!("cold-start candidate instance is invalid: {error}"))
        })?;
        proposed.validate().map_err(|error| {
            fail(&format!("cold-start onboarding lease is invalid: {error}"))
        })?;

        boundary.validate().map_err(|error| {
            fail(&format!("cold-start privacy boundary is invalid: {error}"))
        })?;
        privacy.validate().map_err(|error| {
            fail(&format!("cold-start privacy profile is invalid: {error}"))
        })?;
        if host.candidate_privacy != Some(candidate.privacy_class)
            || host.privacy_boundary.as_ref() != Some(boundary)
            || !boundary.admits(candidate.privacy_class)
            || !privacy.admits(candidate.privacy_class)
            || privacy
                .admitted_classes
                .iter()
                .any(|class| !boundary.admits(*class))
        {
            return Err(fail(
                "privacy values do not match the Host scan and owner boundary",
            ));
        }

        sources
            .validate_for(&candidate.scope, privacy)
            .map_err(|error| {
                fail(&format!("governing-source set is not admitted for this scope: {error}"))
            })?;
        if sources.generation != proposed.governing_source_generation {
            return Err(fail(
                "governing-source generation does not match the onboarding lease",
            ));
        }
        let host_candidates = evidence
            .governing_source_candidates
            .as_deref()
            .ok_or_else(|| fail("Host discovery did not attest source candidates"))?;
        let mut requested_refs = host.governing_source_refs.clone();
        let mut observed_refs: Vec<String> =
            host_candidates.iter().map(|item| item.source_ref.clone()).collect();
        requested_refs.sort();
        requested_refs.dedup();
        observed_refs.sort();
        observed_refs.dedup();
        if requested_refs != observed_refs {
            return Err(fail(
                "Host source references disagree with the bounded candidate observation",
            ));
        }
        for source in &sources.sources {
            if !is_lowercase_sha256(&source.digest) {
                return Err(fail(
                    "governing-source content digest is not a lowercase SHA-256",
                ));
            }
            if !host_candidates.iter().any(|candidate| {
                candidate.source_ref == source.source_ref && candidate.role == source.role
            }) {
                return Err(fail(
                    "owner-admitted source is outside the exact Host candidate set",
                ));
            }
        }

        scan_binding.admit().map_err(|error| {
            fail(&format!("Kernel scan binding is invalid: {error}"))
        })?;
        scan_receipt.validate().map_err(|error| {
            fail(&format!("scan receipt handle is invalid: {error}"))
        })?;
        let fence_bytes = canonical_json_bytes(state_fence)
            .map_err(|error| fail(&format!("state fence cannot be canonically encoded: {error}")))?;
        let state_fence_ref = sha256_hex(&fence_bytes);
        if scan_binding.lease_ref != discovery.lease.lease_ref
            || scan_binding.candidate_root_ref != candidate.scope.root_identity
            || scan_binding.privacy_boundary_ref != boundary.boundary_ref
            || scan_binding.state_fence_ref.as_deref() != Some(state_fence_ref.as_str())
            || scan_binding.lease_consumed > u64::from(discovery.lease.consumed)
            || scan_store.contour().installation_id() != scan_binding.installation_id
        {
            return Err(fail(
                "Kernel scan binding does not match the retained Host and current fence",
            ));
        }

        let readback =
            ScanDisclosureStore::readback(scan_store, scan_receipt, scan_binding).map_err(|error| {
                fail(&format!("authenticated scanner receipt readback failed: {error}"))
            })?;
        readback.validate().map_err(|error| {
            fail(&format!("authenticated scanner receipt is invalid: {error}"))
        })?;
        if readback.scan_ref != host.scan_ref
            || readback.scan_ref != scan_receipt.receipt_ref
            || readback.lease_ref != discovery.lease.lease_ref
            || readback.candidate_root_ref != candidate.scope.root_identity
            || readback.privacy_boundary_ref.as_deref() != Some(boundary.boundary_ref.as_str())
            || readback.unresolved != evidence.unresolved_fields
            || readback.redacted != evidence.redacted_literal_identities
            || !same_set(&readback.allowed, &evidence.attested_reads)
        {
            return Err(fail(
                "durable scanner readback does not match the exact Host evidence",
            ));
        }

        Ok(Self {
            candidate: candidate.clone(),
            proposed: proposed.clone(),
            boundary: boundary.clone(),
            privacy: privacy.clone(),
            sources: sources.clone(),
            scan: evidence.clone(),
            scan_binding: scan_binding.clone(),
            scan_receipt: scan_receipt.clone(),
            scan_readback: readback,
        })
    }

    #[must_use]
    pub fn candidate(&self) -> &WorkScopeCandidate {
        &self.candidate
    }

    #[must_use]
    pub fn proposed_lease(&self) -> &OnboardingLease {
        &self.proposed
    }

    #[must_use]
    pub fn privacy_boundary(&self) -> &PrivacyBoundary {
        &self.boundary
    }

    #[must_use]
    pub fn privacy_profile(&self) -> &PrivacyProfile {
        &self.privacy
    }

    #[must_use]
    pub fn governing_sources(&self) -> &GoverningSourceSet {
        &self.sources
    }

    #[must_use]
    pub fn scan_evidence(&self) -> &BootstrapScanEvidence {
        &self.scan
    }

    #[must_use]
    pub fn scan_binding(&self) -> &ScanDisclosureOwnerBinding {
        &self.scan_binding
    }

    #[must_use]
    pub fn scan_receipt(&self) -> &ScanReceiptHandle {
        &self.scan_receipt
    }

    /// Owner-authenticated receipt content returned by the installation
    /// store. Composition must re-read the handle before building a claim.
    #[must_use]
    pub fn scan_readback(&self) -> &ScanDisclosureReceipt {
        &self.scan_readback
    }
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn same_set<T: Copy + Ord>(left: &[T], right: &[T]) -> bool {
    let mut left = left.to_vec();
    let mut right = right.to_vec();
    left.sort_unstable();
    left.dedup();
    right.sort_unstable();
    right.dedup();
    left == right
}
