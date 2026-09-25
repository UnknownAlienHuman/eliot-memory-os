//! Governor-owned canonical closure provider for the P-07 durable owner.
//!
//! Architecture traceability: I6.15 makes the Governor the owner of canonical
//! grant semantics, parent lineage, policy reconciliation, and introduction
//! compilation, while the Kernel owns activation/revocation enforcement.
//! This module is the Governor side of that split: it restores the canonical
//! grant graph under explicit CURRENT revocation-history evidence, owns the
//! exact-revision enumeration authority, and compiles admitted hydrations
//! (semantic intents plus opaque ORS records) that the Kernel port fences
//! verbatim through [`eliot_kernel_core::bind_canonical_owner`].
//!
//! Ownership stays exact:
//!
//! - the graph, history, fence, and revision all arrive from canonical
//!   Governor state using existing authority types; the provider invents no
//!   graph edge, member, root, revision, holder, or facet;
//! - admitted hydrations enter only through explicit admission calls that
//!   name every semantic field; the compiler validates lineage, revision,
//!   and binding agreement against the restored graph and refuses anything
//!   else — a thin request can never conjure authority the Governor did not
//!   admit;
//! - the opaque record plaintext is the canonical JSON of the admitted
//!   intent, sealed under the admitting service's secret reference; the
//!   provider never mints, stores, or logs secret bytes (the reference names
//!   a provider and key only);
//! - rotation is an explicit [`OwnerClosureProvider::refresh`] from newer
//!   durable state with monotonicity enforcement, never an incremental
//!   mutation.
//!
//! Forbidden boundary: no Kernel I/O, no ORS writes, no epoch invention, no
//! second graph owner. The Kernel-side mirror
//! ([`eliot_kernel_core::GovernorClosureSource`]) restores from exactly the
//! bundle served here and revalidates everything before any mutation.

use std::collections::{BTreeMap, BTreeSet};

use eliot_authority::{
    GrantClosureDelegation, GrantGraphRecoverySnapshot, GrantId, GrantRecoveryRecord, GrantStatus,
    RevocationHistoryEvidence,
};
use eliot_contracts::{StateFence, canonical_json_bytes};
use eliot_kernel_core::{
    GovernorClosureRestore, GrantActivationIntent, GrantClosureMember, GrantClosureSurvivor,
    IntroductionActivationIntent, IntroductionHydration, RootGrantHydration,
};
use eliot_ors::{
    CapabilityIntroductionActivation, EpochIdentity, EpochLineage, OpaqueLabel,
    OperationalRecordContext, OperationalRecordInput, StateFenceSnapshot,
};
use eliot_platform::SecretReference;
use eliot_receipts::{AuthorityBinding, EffectClass, ProofCeiling};
use serde::{Deserialize, Serialize};

use crate::{AuthorityOwner, AuthorityOwnerSnapshot, CompositionError};

/// Versioned admitted-hydration snapshot retained by the Governor owner.
pub const OWNER_HYDRATION_SNAPSHOT_SCHEMA: &str = "eliot.governor.owner-hydrations.v1";
/// Versioned admitted-hydration snapshot version.
pub const OWNER_HYDRATION_SNAPSHOT_VERSION: u16 = 1;

/// Canonical Governor closure owner behind the P-07 durable boundary.
///
/// Built once from a validated owner snapshot plus explicit CURRENT
/// revocation-history evidence, refreshed only from newer durable state.
/// Every enumeration, hydration, and served bundle is bound to the exact
/// restored graph revision and fence.
pub struct OwnerClosureProvider {
    state_fence: StateFence,
    snapshot: AuthorityOwnerSnapshot,
    history: RevocationHistoryEvidence,
    owner: AuthorityOwner,
    registry: AdmittedHydrations,
}

/// Governor-side admitted-hydration registry.
///
/// Hydrations enter only through the explicit `admit_*` calls on
/// [`OwnerClosureProvider`], each validated against the restored graph at
/// the provider revision. The registry exports/imports a versioned snapshot
/// so daemon state can persist and rehydrate admissions across restarts
/// without re-admission.
#[derive(Clone, Debug, Default)]
struct AdmittedHydrations {
    members: BTreeMap<String, GrantClosureMember>,
    roots: BTreeMap<String, RootGrantHydration>,
    introductions: BTreeMap<String, IntroductionHydration>,
    preserved: BTreeMap<String, Vec<GrantClosureSurvivor>>,
}

/// Complete semantic admission context for one grant hydration.
///
/// Every field is caller-supplied Governor admission state: the compiler
/// validates it against the restored graph and seals it into the intent plus
/// the opaque record. The graph revision is never caller-supplied — the
/// compiler binds the provider's exact restored revision.
#[derive(Clone, Debug)]
pub struct GrantAdmissionParams {
    /// Idempotency identity. Ledger key and receipt-derivation root.
    pub operation_id: String,
    /// Grant identity to admit. Must name a graph entry.
    pub grant_id: String,
    /// Delegating parent identity. Must equal the graph entry's parent
    /// (`None` only when the graph entry is itself an authority root).
    pub parent_grant_id: Option<String>,
    /// Lineage domain. Must equal the graph entry's root.
    pub authority_root_ref: String,
    /// Governor snapshot this admission is presented under.
    pub snapshot_id: String,
    /// Holder principal the grant is admitted for.
    pub holder_principal: String,
    /// Session the grant is admitted for.
    pub session_id: String,
    /// Scope the grant is admitted for.
    pub scope_id: String,
    /// Authority binding pinning owner, epoch, fence, effect and ceiling.
    /// Must equal the graph entry's binding.
    pub binding: AuthorityBinding,
    /// Admitted effect ceiling.
    pub allowed_effect: EffectClass,
    /// Admitted proof ceiling.
    pub proof_ceiling: ProofCeiling,
    /// Logical issuance time in Unix milliseconds.
    pub issued_at_ms: i64,
    /// Logical expiry time in Unix milliseconds, if the grant expires.
    pub expires_at_ms: Option<i64>,
    /// Receipt obligations the effect path must discharge.
    pub receipt_obligations: Vec<String>,
}

/// Complete semantic admission context for one introduction hydration.
///
/// Supporting grants must name restored, active graph entries on the
/// introduction's root; the resource handle, facet manifest, and holder
/// come from Governor admission and are never defaulted.
#[derive(Clone, Debug)]
pub struct IntroductionAdmissionParams {
    /// Idempotency identity. Ledger key and receipt-derivation root.
    pub operation_id: String,
    /// Introduction identity to admit.
    pub introduction_id: String,
    /// Lineage domain. Every supporting grant must share it.
    pub authority_root_ref: String,
    /// Governor snapshot this admission is presented under.
    pub snapshot_id: String,
    /// Supporting grant identities. At least one is required.
    pub supporting_grant_ids: Vec<String>,
    /// Exact resource handle being introduced.
    pub resource_handle: String,
    /// Facet manifest reference for the introduced surface.
    pub facet_manifest_ref: String,
    /// Holder principal the introduction is admitted for.
    pub holder_principal: String,
    /// Session the introduction is admitted for.
    pub session_id: String,
    /// Scope the introduction is admitted for.
    pub scope_id: String,
    /// Authority binding pinning owner, epoch, fence, effect and ceiling.
    pub binding: AuthorityBinding,
    /// Admitted effect ceiling.
    pub allowed_effect: EffectClass,
    /// Admitted proof ceiling.
    pub proof_ceiling: ProofCeiling,
    /// Logical issuance time in Unix milliseconds.
    pub issued_at_ms: i64,
    /// Logical expiry time in Unix milliseconds, if the introduction expires.
    pub expires_at_ms: Option<i64>,
    /// Receipt obligations the effect path must discharge.
    pub receipt_obligations: Vec<String>,
}

/// One owner-declared alternate-path survivor admission.
#[derive(Clone, Debug)]
pub struct PreservedAdmission {
    /// Closure target the survivor is declared for. Must name a graph entry.
    pub target_grant_id: String,
    /// Preserved descendant grant identity. Must name a graph entry.
    pub grant_id: String,
    /// Covering grant identity on the surviving alternate path. Must name a
    /// graph entry; its root may differ (independent authority lines stay
    /// separate grants).
    pub covering_grant_id: String,
    /// Lineage domain of the surviving alternate path.
    pub covering_root_ref: String,
}

impl OwnerClosureProvider {
    /// Restores the canonical owner from a validated snapshot plus explicit
    /// CURRENT revocation-history evidence.
    ///
    /// `None` history refuses: unavailable history is not absence of
    /// revocation. A stale fence, a revision disagreement, or an invalid
    /// snapshot refuses likewise, before any owner state is installed.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Recovery`] for an invalid snapshot, an
    /// absent or stale history, or a failed graph restore.
    pub fn restore(
        snapshot: AuthorityOwnerSnapshot,
        history: Option<RevocationHistoryEvidence>,
        expected_fence: &StateFence,
    ) -> Result<Self, CompositionError> {
        snapshot.validate()?;
        if snapshot.state_fence != *expected_fence {
            return Err(CompositionError::Recovery(
                "owner snapshot fence disagrees with the expected recovery fence".to_owned(),
            ));
        }
        let history = history.ok_or_else(|| {
            CompositionError::Recovery(
                "authority revocation history is unavailable; unavailable history is not absence of revocation"
                    .to_owned(),
            )
        })?;
        let outcome = AuthorityOwner::from_snapshot_with_revocation_history(
            &snapshot,
            expected_fence,
            Some(&history),
        )?;
        Ok(Self {
            state_fence: snapshot.state_fence.clone(),
            snapshot,
            history,
            owner: outcome.owner,
            registry: AdmittedHydrations::default(),
        })
    }

    /// Returns the exact restored graph revision this provider serves.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.owner.grants.revision()
    }

    /// Returns the exact recovery fence this provider is bound to.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Returns the validated owner snapshot this provider restored from.
    #[must_use]
    pub const fn owner_snapshot(&self) -> &AuthorityOwnerSnapshot {
        &self.snapshot
    }

    /// Returns the distinct lineage roots in the restored snapshot, sorted.
    #[must_use]
    pub fn authority_roots(&self) -> Vec<String> {
        let mut roots = BTreeSet::new();
        for grant in &self.snapshot.grant_graph.grants {
            roots.insert(grant.authority_root_ref.clone());
        }
        roots.into_iter().collect()
    }

    /// Enumerates the complete durable descendant closure for one grant at
    /// the restored revision: the canonical enumeration authority behind
    /// the Kernel-side closure gate.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Recovery`] for an unknown grant identity.
    pub fn delegated_closure(
        &self,
        grant_id: &str,
    ) -> Result<GrantClosureDelegation, CompositionError> {
        let target = GrantId::new(grant_id)
            .map_err(|_| CompositionError::Recovery("grant identity is invalid".to_owned()))?;
        self.owner
            .grants
            .delegated_closure(&target)
            .map_err(|error| CompositionError::Recovery(error.to_string()))
    }

    /// Returns the durable snapshot plus the CURRENT history evidence the
    /// Kernel-side mirror restores from. Both clones carry the exact
    /// revision and fence this provider serves.
    #[must_use]
    pub fn snapshot_bundle(&self) -> (GrantGraphRecoverySnapshot, RevocationHistoryEvidence) {
        (self.snapshot.grant_graph.clone(), self.history.clone())
    }

    /// Rebinds the owner from newer durable Governor state.
    ///
    /// The fence must equal the retained fence (a fence advance is a new
    /// restoration, not a refresh) and the revision must not move backwards.
    /// The admitted registry carries over only when every admitted entry
    /// still resolves at the new revision; otherwise refresh refuses and the
    /// live provider is untouched.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Recovery`] for a fence change, a stale
    /// revision, an invalid snapshot or history, or admitted material that
    /// disagrees with the new state.
    pub fn refresh(
        &mut self,
        snapshot: AuthorityOwnerSnapshot,
        history: Option<RevocationHistoryEvidence>,
        expected_revision: u64,
    ) -> Result<(), CompositionError> {
        if expected_revision < self.revision() {
            return Err(CompositionError::Recovery(
                "owner refresh must not move the served revision backwards".to_owned(),
            ));
        }
        let fence = self.state_fence.clone();
        let mut candidate = Self::restore(snapshot, history, &fence)?;
        if candidate.revision() != expected_revision {
            return Err(CompositionError::Recovery(
                "restored owner revision disagrees with the expected revision".to_owned(),
            ));
        }
        let registry = std::mem::take(&mut self.registry);
        candidate.revalidate_registry(&registry)?;
        candidate.registry = registry;
        *self = candidate;
        Ok(())
    }

    /// Admits one delegated member hydration, compiling the opaque record
    /// under the admitting service's secret reference.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Owner`] for lineage, revision, binding,
    /// or identity disagreement, and [`CompositionError::Recovery`] for an
    /// unusable secret reference or opaque record.
    pub fn admit_grant_member(
        &mut self,
        params: &GrantAdmissionParams,
        secret: &SecretReference,
        observed_at_ms: i64,
    ) -> Result<GrantClosureMember, CompositionError> {
        let member = self.compile_grant_member(params, secret, observed_at_ms)?;
        if self
            .registry
            .members
            .insert(member.intent.grant_id.clone(), member.clone())
            .is_some()
        {
            return Err(CompositionError::Owner(
                "admitted member identity is already registered".to_owned(),
            ));
        }
        Ok(member)
    }

    /// Admits one authority-root hydration for single-root requests.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`Self::admit_grant_member`], plus a
    /// refusal when the grant is not an authority root in the restored
    /// graph.
    pub fn admit_grant_root(
        &mut self,
        params: &GrantAdmissionParams,
        secret: &SecretReference,
        observed_at_ms: i64,
    ) -> Result<RootGrantHydration, CompositionError> {
        let member = self.compile_grant_member(params, secret, observed_at_ms)?;
        if member.intent.parent_grant_id.is_some() {
            return Err(CompositionError::Owner(
                "root admission requires a graph authority root".to_owned(),
            ));
        }
        let hydration = RootGrantHydration {
            intent: member.intent,
            durable_record: member.durable_record,
            observed_at_ms,
        };
        if self
            .registry
            .roots
            .insert(hydration.intent.grant_id.clone(), hydration.clone())
            .is_some()
        {
            return Err(CompositionError::Owner(
                "admitted root identity is already registered".to_owned(),
            ));
        }
        Ok(hydration)
    }

    /// Admits one introduction hydration, compiling the opaque record under
    /// the admitting service's secret reference.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Owner`] for unknown, fenced, cross-root,
    /// or missing supporting lineage, and [`CompositionError::Recovery`]
    /// for an unusable secret reference or opaque record.
    pub fn admit_introduction(
        &mut self,
        params: &IntroductionAdmissionParams,
        secret: &SecretReference,
        observed_at_ms: i64,
    ) -> Result<IntroductionHydration, CompositionError> {
        let hydration = self.compile_introduction(params, secret, observed_at_ms)?;
        if self
            .registry
            .introductions
            .insert(hydration.intent.introduction_id.clone(), hydration.clone())
            .is_some()
        {
            return Err(CompositionError::Owner(
                "admitted introduction identity is already registered".to_owned(),
            ));
        }
        Ok(hydration)
    }

    /// Admits one owner-declared alternate-path survivor.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Owner`] for unknown target, survivor, or
    /// covering lineage.
    pub fn admit_preserved(
        &mut self,
        admission: PreservedAdmission,
    ) -> Result<(), CompositionError> {
        reject_blank(&admission.target_grant_id, "preserved.target_grant_id")?;
        reject_blank(&admission.grant_id, "preserved.grant_id")?;
        reject_blank(&admission.covering_grant_id, "preserved.covering_grant_id")?;
        reject_blank(&admission.covering_root_ref, "preserved.covering_root_ref")?;
        for grant_id in [
            &admission.target_grant_id,
            &admission.grant_id,
            &admission.covering_grant_id,
        ] {
            if self.snapshot_grant(grant_id).is_none() {
                return Err(CompositionError::Owner(
                    "preserved admission names unknown grant lineage".to_owned(),
                ));
            }
        }
        self.registry
            .preserved
            .entry(admission.target_grant_id.clone())
            .or_default()
            .push(GrantClosureSurvivor {
                grant_id: admission.grant_id,
                covering_grant_id: admission.covering_grant_id,
                covering_root_ref: admission.covering_root_ref,
            });
        Ok(())
    }

    /// Serves the complete restore bundle the Kernel-side mirror binds at
    /// the provider revision: durable snapshot, CURRENT history, admitted
    /// members, roots, introductions, and preserved survivors.
    ///
    /// Refuses with no admitted grant hydrations: an empty registry binds
    /// nothing, and the Kernel-side bootstrap refuses an empty bundle the
    /// same way.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Recovery`] when no grant hydration is
    /// admitted.
    pub fn serve_restore(&self) -> Result<GovernorClosureRestore, CompositionError> {
        if self.registry.members.is_empty() && self.registry.roots.is_empty() {
            return Err(CompositionError::Recovery(
                "no admitted grant hydrations to serve".to_owned(),
            ));
        }
        Ok(GovernorClosureRestore {
            graph_snapshot: self.snapshot.grant_graph.clone(),
            revocation_history: Some(self.history.clone()),
            members: self.registry.members.values().cloned().collect(),
            roots: self.registry.roots.values().cloned().collect(),
            introductions: self.registry.introductions.values().cloned().collect(),
            preserved: self
                .registry
                .preserved
                .iter()
                .map(|(target, survivors)| (target.clone(), survivors.clone()))
                .collect(),
        })
    }

    /// Exports the admitted registry as versioned canonical bytes for daemon
    /// state persistence. The bytes carry intents plus opaque records only;
    /// secret bytes never appear (the secret reference names a provider and
    /// key).
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Recovery`] when the snapshot cannot be
    /// rendered.
    pub fn export_registry(&self) -> Result<Vec<u8>, CompositionError> {
        let snapshot = AdmittedHydrationsSnapshot {
            schema: OWNER_HYDRATION_SNAPSHOT_SCHEMA.to_owned(),
            version: OWNER_HYDRATION_SNAPSHOT_VERSION,
            state_fence: self.state_fence.clone(),
            grant_graph_revision: self.revision(),
            members: self.registry.members.values().cloned().collect(),
            roots: self.registry.roots.values().cloned().collect(),
            introductions: self.registry.introductions.values().cloned().collect(),
            preserved: self
                .registry
                .preserved
                .iter()
                .map(|(target, survivors)| (target.clone(), survivors.clone()))
                .collect(),
        };
        canonical_json_bytes(&snapshot).map_err(recovery)
    }

    /// Imports a registry snapshot exported by
    /// [`Self::export_registry`], re-admitting every entry through full
    /// validation against the current provider state. The import builds a
    /// shadow registry first: any disagreement aborts with the live registry
    /// untouched.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Recovery`] for malformed bytes, schema or
    /// version drift, fence or revision disagreement, or any entry that
    /// fails admission validation.
    pub fn import_registry(&mut self, bytes: &[u8]) -> Result<(), CompositionError> {
        let snapshot: AdmittedHydrationsSnapshot =
            serde_json::from_slice(bytes).map_err(|error| {
                CompositionError::Recovery(format!("hydration snapshot is malformed: {error}"))
            })?;
        if snapshot.schema != OWNER_HYDRATION_SNAPSHOT_SCHEMA
            || snapshot.version != OWNER_HYDRATION_SNAPSHOT_VERSION
        {
            return Err(CompositionError::Recovery(
                "hydration snapshot has an invalid schema or version".to_owned(),
            ));
        }
        if snapshot.state_fence != self.state_fence
            || snapshot.grant_graph_revision != self.revision()
        {
            return Err(CompositionError::Recovery(
                "hydration snapshot disagrees with the provider fence or revision".to_owned(),
            ));
        }
        let mut shadow = AdmittedHydrations::default();
        for member in &snapshot.members {
            self.check_member_admission(
                &member.intent.grant_id,
                member.intent.parent_grant_id.as_deref(),
                &member.intent.authority_root_ref,
                &member.intent.binding,
            )?;
            verify_imported_grant_seal(
                &member.intent.grant_id,
                &member.intent.operation_id,
                member.durable_record.record(),
            )?;
            if shadow
                .members
                .insert(member.intent.grant_id.clone(), member.clone())
                .is_some()
            {
                return Err(CompositionError::Recovery(
                    "hydration snapshot carries a duplicate member identity".to_owned(),
                ));
            }
        }
        for root in &snapshot.roots {
            self.check_member_admission(
                &root.intent.grant_id,
                root.intent.parent_grant_id.as_deref(),
                &root.intent.authority_root_ref,
                &root.intent.binding,
            )?;
            verify_imported_grant_seal(
                &root.intent.grant_id,
                &root.intent.operation_id,
                root.durable_record.record(),
            )?;
            if root.intent.parent_grant_id.is_some() {
                return Err(CompositionError::Recovery(
                    "hydration snapshot carries a non-root identity as a root".to_owned(),
                ));
            }
            if shadow
                .roots
                .insert(root.intent.grant_id.clone(), root.clone())
                .is_some()
            {
                return Err(CompositionError::Recovery(
                    "hydration snapshot carries a duplicate root identity".to_owned(),
                ));
            }
        }
        for hydration in &snapshot.introductions {
            self.check_introduction_admission(
                &hydration.intent.supporting_grant_ids,
                &hydration.intent.authority_root_ref,
            )?;
            verify_imported_introduction_seal(
                &hydration.intent.introduction_id,
                &hydration.intent.operation_id,
                hydration.durable_record.record(),
            )?;
            if shadow
                .introductions
                .insert(hydration.intent.introduction_id.clone(), hydration.clone())
                .is_some()
            {
                return Err(CompositionError::Recovery(
                    "hydration snapshot carries a duplicate introduction identity".to_owned(),
                ));
            }
        }
        for (target, survivors) in &snapshot.preserved {
            for survivor in survivors {
                self.check_preserved_admission(target, survivor)?;
            }
            shadow
                .preserved
                .entry(target.clone())
                .or_default()
                .extend(survivors.clone());
        }
        self.registry = shadow;
        Ok(())
    }

    /// Revalidates a previously admitted registry against this provider
    /// state: every member, root, introduction, and survivor must still
    /// resolve. Used by [`Self::refresh`] before carrying admissions over.
    fn revalidate_registry(&self, registry: &AdmittedHydrations) -> Result<(), CompositionError> {
        for member in registry.members.values() {
            self.check_member_admission(
                &member.intent.grant_id,
                member.intent.parent_grant_id.as_deref(),
                &member.intent.authority_root_ref,
                &member.intent.binding,
            )?;
        }
        for root in registry.roots.values() {
            self.check_member_admission(
                &root.intent.grant_id,
                root.intent.parent_grant_id.as_deref(),
                &root.intent.authority_root_ref,
                &root.intent.binding,
            )?;
        }
        for hydration in registry.introductions.values() {
            self.check_introduction_admission(
                &hydration.intent.supporting_grant_ids,
                &hydration.intent.authority_root_ref,
            )?;
        }
        for (target, survivors) in &registry.preserved {
            for survivor in survivors {
                self.check_preserved_admission(target, survivor)?;
            }
        }
        Ok(())
    }

    /// Compiles one delegated member hydration from explicit admission
    /// context, sealing the opaque record under the admitting service's
    /// secret reference. The bound revision is always the provider's exact
    /// restored revision; the caller never supplies one.
    fn compile_grant_member(
        &self,
        params: &GrantAdmissionParams,
        secret: &SecretReference,
        observed_at_ms: i64,
    ) -> Result<GrantClosureMember, CompositionError> {
        reject_blank(&params.operation_id, "admission.operation_id")?;
        reject_blank(&params.grant_id, "admission.grant_id")?;
        if let Some(parent) = &params.parent_grant_id {
            reject_blank(parent, "admission.parent_grant_id")?;
        }
        reject_blank(&params.authority_root_ref, "admission.authority_root_ref")?;
        reject_blank(&params.snapshot_id, "admission.snapshot_id")?;
        reject_blank(&params.holder_principal, "admission.holder_principal")?;
        reject_blank(&params.session_id, "admission.session_id")?;
        reject_blank(&params.scope_id, "admission.scope_id")?;
        for obligation in &params.receipt_obligations {
            reject_blank(obligation, "admission.receipt_obligation")?;
        }
        if params
            .expires_at_ms
            .is_some_and(|expires| expires <= params.issued_at_ms)
        {
            return Err(CompositionError::Owner(
                "admission expiry must be strictly later than issuance".to_owned(),
            ));
        }
        self.check_member_admission(
            &params.grant_id,
            params.parent_grant_id.as_deref(),
            &params.authority_root_ref,
            &params.binding,
        )?;
        let intent = GrantActivationIntent {
            operation_id: params.operation_id.clone(),
            grant_id: params.grant_id.clone(),
            parent_grant_id: params.parent_grant_id.clone(),
            authority_root_ref: params.authority_root_ref.clone(),
            snapshot_id: params.snapshot_id.clone(),
            grant_graph_revision: self.revision(),
            holder_principal: params.holder_principal.clone(),
            session_id: params.session_id.clone(),
            scope_id: params.scope_id.clone(),
            binding: params.binding.clone(),
            allowed_effect: params.allowed_effect,
            proof_ceiling: params.proof_ceiling,
            issued_at_ms: params.issued_at_ms,
            expires_at_ms: params.expires_at_ms,
            receipt_obligations: params.receipt_obligations.clone(),
        };
        let record = Self::opaque_grant_record(&intent, secret)?;
        Ok(GrantClosureMember {
            intent,
            durable_record: record,
            observed_at_ms,
        })
    }

    /// Validates one grant admission against the restored graph: the grant
    /// must be a known, non-revoked entry; the presented parent must equal
    /// the graph entry's parent; the root and binding must equal the entry's
    /// own. Anything else is not admitted lineage.
    fn check_member_admission(
        &self,
        grant_id: &str,
        parent_grant_id: Option<&str>,
        authority_root_ref: &str,
        binding: &AuthorityBinding,
    ) -> Result<(), CompositionError> {
        let record = self.snapshot_grant(grant_id).ok_or_else(|| {
            CompositionError::Owner("admission names unknown grant lineage".to_owned())
        })?;
        if record.status == GrantStatus::Revoked {
            return Err(CompositionError::Owner(
                "admission names revoked grant lineage".to_owned(),
            ));
        }
        if record.parent_grant_id.as_deref() != parent_grant_id {
            return Err(CompositionError::Owner(
                "admission parent disagrees with the restored graph entry".to_owned(),
            ));
        }
        if record.authority_root_ref != authority_root_ref {
            return Err(CompositionError::Owner(
                "admission root disagrees with the restored graph entry".to_owned(),
            ));
        }
        if record.binding != *binding {
            return Err(CompositionError::Owner(
                "admission binding disagrees with the restored graph entry".to_owned(),
            ));
        }
        Ok(())
    }

    /// Compiles one introduction hydration from explicit admission context.
    /// Every supporting grant must be a restored, active graph entry on the
    /// introduction's root; the opaque record seals the exact admitted
    /// bytes under the admitting service's secret reference.
    fn compile_introduction(
        &self,
        params: &IntroductionAdmissionParams,
        secret: &SecretReference,
        observed_at_ms: i64,
    ) -> Result<IntroductionHydration, CompositionError> {
        reject_blank(&params.operation_id, "admission.operation_id")?;
        reject_blank(&params.introduction_id, "admission.introduction_id")?;
        reject_blank(&params.authority_root_ref, "admission.authority_root_ref")?;
        reject_blank(&params.snapshot_id, "admission.snapshot_id")?;
        reject_blank(&params.resource_handle, "admission.resource_handle")?;
        reject_blank(&params.facet_manifest_ref, "admission.facet_manifest_ref")?;
        reject_blank(&params.holder_principal, "admission.holder_principal")?;
        reject_blank(&params.session_id, "admission.session_id")?;
        reject_blank(&params.scope_id, "admission.scope_id")?;
        for obligation in &params.receipt_obligations {
            reject_blank(obligation, "admission.receipt_obligation")?;
        }
        if params.supporting_grant_ids.is_empty() {
            return Err(CompositionError::Owner(
                "introduction admission requires at least one supporting grant".to_owned(),
            ));
        }
        self.check_introduction_admission(
            &params.supporting_grant_ids,
            &params.authority_root_ref,
        )?;
        if params
            .expires_at_ms
            .is_some_and(|expires| expires <= params.issued_at_ms)
        {
            return Err(CompositionError::Owner(
                "admission expiry must be strictly later than issuance".to_owned(),
            ));
        }
        let intent = IntroductionActivationIntent {
            operation_id: params.operation_id.clone(),
            introduction_id: params.introduction_id.clone(),
            authority_root_ref: params.authority_root_ref.clone(),
            snapshot_id: params.snapshot_id.clone(),
            grant_graph_revision: self.revision(),
            supporting_grant_ids: params.supporting_grant_ids.clone(),
            resource_handle: params.resource_handle.clone(),
            facet_manifest_ref: params.facet_manifest_ref.clone(),
            holder_principal: params.holder_principal.clone(),
            session_id: params.session_id.clone(),
            scope_id: params.scope_id.clone(),
            binding: params.binding.clone(),
            allowed_effect: params.allowed_effect,
            proof_ceiling: params.proof_ceiling,
            issued_at_ms: params.issued_at_ms,
            expires_at_ms: params.expires_at_ms,
            receipt_obligations: params.receipt_obligations.clone(),
        };
        let input = Self::opaque_input(
            &params.operation_id,
            &params.introduction_id,
            &params.binding,
            params.issued_at_ms,
            secret,
            &intent,
        )?;
        let durable_record = CapabilityIntroductionActivation::new(input).map_err(recovery)?;
        Ok(IntroductionHydration {
            intent,
            durable_record,
            observed_at_ms,
        })
    }

    /// Validates one introduction admission: every supporting grant must be
    /// a restored, active graph entry on the introduction's root.
    fn check_introduction_admission(
        &self,
        supporting_grant_ids: &[String],
        authority_root_ref: &str,
    ) -> Result<(), CompositionError> {
        for supporting in supporting_grant_ids {
            reject_blank(supporting, "admission.supporting_grant_id")?;
            let record = self.snapshot_grant(supporting).ok_or_else(|| {
                CompositionError::Owner("admission names unknown supporting lineage".to_owned())
            })?;
            if record.status != GrantStatus::Active {
                return Err(CompositionError::Owner(
                    "admission names non-active supporting lineage".to_owned(),
                ));
            }
            if record.authority_root_ref != authority_root_ref {
                return Err(CompositionError::Owner(
                    "supporting lineage is on a different authority root".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Validates one preserved admission against the restored graph.
    fn check_preserved_admission(
        &self,
        target_grant_id: &str,
        survivor: &GrantClosureSurvivor,
    ) -> Result<(), CompositionError> {
        for grant_id in [
            target_grant_id,
            survivor.grant_id.as_str(),
            survivor.covering_grant_id.as_str(),
        ] {
            if self.snapshot_grant(grant_id).is_none() {
                return Err(CompositionError::Recovery(
                    "preserved admission names unknown grant lineage".to_owned(),
                ));
            }
        }
        Ok(())
    }

    /// Looks up one restored graph entry by grant identity.
    fn snapshot_grant(&self, grant_id: &str) -> Option<&GrantRecoveryRecord> {
        self.snapshot
            .grant_graph
            .grants
            .iter()
            .find(|grant| grant.grant_id == grant_id)
    }

    /// Seals one grant intent into its opaque ORS activation record. The
    /// plaintext is the canonical JSON of the admitted intent; only the
    /// record identity, lineage contour, fence, and times travel outside
    /// the ciphertext.
    fn opaque_grant_record(
        intent: &GrantActivationIntent,
        secret: &SecretReference,
    ) -> Result<eliot_ors::CapabilityGrantActivation, CompositionError> {
        let input = Self::opaque_input(
            &intent.operation_id,
            &intent.grant_id,
            &intent.binding,
            intent.issued_at_ms,
            secret,
            intent,
        )?;
        eliot_ors::CapabilityGrantActivation::new(input).map_err(recovery)
    }

    /// Builds the opaque record input shared by grant and introduction
    /// admissions: exact identity contour, epoch lineage, and fence snapshot
    /// travel in the clear; the admitted bytes travel sealed.
    fn opaque_input<T: Serialize>(
        operation_id: &str,
        subject_id: &str,
        binding: &AuthorityBinding,
        issued_at_ms: i64,
        secret: &SecretReference,
        intent: &T,
    ) -> Result<OperationalRecordInput, CompositionError> {
        let epoch = &binding.authority_epoch;
        let plaintext = canonical_json_bytes(intent).map_err(recovery)?;
        let context = OperationalRecordContext {
            record_id: eliot_ors::OperationIdentity::new(operation_id).map_err(recovery)?,
            subject_id: eliot_ors::OperationIdentity::new(subject_id).map_err(recovery)?,
            authority_epoch: EpochLineage {
                current: EpochIdentity {
                    lineage_id: OpaqueLabel::new(epoch.lineage_id.as_str()).map_err(recovery)?,
                    epoch: epoch.sequence.get(),
                },
                predecessor: None,
            },
            state_fence: StateFenceSnapshot::capture(&binding.state_fence, epoch.sequence.get())
                .map_err(recovery)?,
            created_at_ms: issued_at_ms,
            cleanup_after_ms: None,
        };
        OperationalRecordInput::encrypted(context, secret.clone(), plaintext).map_err(recovery)
    }
}

/// Maps any displayable failure into the Governor recovery error. ORS,
/// envelope, and validation failures stay typed here; only the Governor
/// recovery surface crosses into `CompositionError`.
#[allow(
    clippy::needless_pass_by_value,
    reason = "the helper erases heterogeneous displayable failures at every map_err call site"
)]
fn recovery(error: impl ToString) -> CompositionError {
    CompositionError::Recovery(error.to_string())
}

/// Proves the opaque↔intent seal for one imported grant record: exact
/// identity contour plus shape/integrity reconstruction exactly as ORS
/// construction enforces. Imported bytes bypass the admission compiler,
/// so the seal is proven here before the bytes re-enter the registry.
fn verify_imported_grant_seal(
    grant_id: &str,
    operation_id: &str,
    record: &eliot_ors::OperationalRecordInput,
) -> Result<(), CompositionError> {
    if record.record_id.as_str() != operation_id || record.subject_id.as_str() != grant_id {
        return Err(CompositionError::Recovery(
            "imported opaque record identity disagrees with the imported intent".to_owned(),
        ));
    }
    eliot_ors::CapabilityGrantActivation::new(record.clone()).map_err(recovery)?;
    Ok(())
}

/// Proves the opaque↔intent seal for one imported introduction record,
/// mirroring [`verify_imported_grant_seal`].
fn verify_imported_introduction_seal(
    introduction_id: &str,
    operation_id: &str,
    record: &eliot_ors::OperationalRecordInput,
) -> Result<(), CompositionError> {
    if record.record_id.as_str() != operation_id || record.subject_id.as_str() != introduction_id {
        return Err(CompositionError::Recovery(
            "imported opaque record identity disagrees with the imported intent".to_owned(),
        ));
    }
    eliot_ors::CapabilityIntroductionActivation::new(record.clone()).map_err(recovery)?;
    Ok(())
}

/// Rejects blank or control-character identities before admission.
fn reject_blank(value: &str, field: &'static str) -> Result<(), CompositionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CompositionError::Owner(format!(
            "{field} is blank or malformed"
        )));
    }
    if value.len() > 1_024 {
        return Err(CompositionError::Owner(format!(
            "{field} exceeds the identity bound"
        )));
    }
    Ok(())
}

/// Versioned admitted-registry snapshot for daemon state persistence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmittedHydrationsSnapshot {
    schema: String,
    version: u16,
    state_fence: StateFence,
    grant_graph_revision: u64,
    members: Vec<GrantClosureMember>,
    roots: Vec<RootGrantHydration>,
    introductions: Vec<IntroductionHydration>,
    preserved: Vec<(String, Vec<GrantClosureSurvivor>)>,
}

#[cfg(test)]
mod owner_closure_provider_tests {
    #![allow(clippy::expect_used)]
    use std::num::NonZeroU64;

    use super::*;
    use eliot_authority::{
        AuthoritySet, CapabilityGrant, EffectAuthorizer, GrantGraph, GrantId, GrantStatus,
        LogicalTime, PrincipalRef,
    };
    use eliot_contracts::{ContractId, EpochId, EpochLineageId, ResourceGeneration};

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"))
    }

    fn binding(fence: &StateFence) -> AuthorityBinding {
        AuthorityBinding {
            authority_id: ContractId::new("authority:test").expect("contract"),
            authority_owner: "G-01".to_owned(),
            authority_epoch: fence.authority_epoch.clone(),
            state_fence: fence.clone(),
            allowed_effect: EffectClass::ExternalEffect,
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
        }
    }

    fn grant_entry(fence: &StateFence, grant_id: &str, parent: Option<&str>) -> CapabilityGrant {
        CapabilityGrant {
            grant_id: GrantId::new(grant_id).expect("id"),
            parent_grant_id: parent.map(|id| GrantId::new(id).expect("parent")),
            authority_root_ref: "root:alpha".to_owned(),
            issuer: PrincipalRef::new("principal:issuer").expect("issuer"),
            holder: PrincipalRef::new("principal:holder").expect("holder"),
            authority: AuthoritySet::new(
                ["op.read".to_owned()],
                ["res:1".to_owned()],
                EffectClass::Read,
            )
            .expect("authority"),
            inherited_source_ceiling: None,
            binding: binding(fence),
            issued_at: LogicalTime::new(1),
            expires_at: LogicalTime::new(10),
            max_uses: 2,
            status: GrantStatus::Active,
        }
    }

    fn owner_snapshot(fence: &StateFence) -> AuthorityOwnerSnapshot {
        let graph = GrantGraph::from_grants(
            [
                grant_entry(fence, "grant:origin", None),
                grant_entry(fence, "grant:child", Some("grant:origin")),
            ],
            7,
        )
        .expect("graph");
        let effect_authorizer = EffectAuthorizer::default().snapshot().expect("authorizer");
        AuthorityOwnerSnapshot::new(
            fence.clone(),
            graph.recovery_snapshot().expect("snapshot"),
            effect_authorizer,
        )
        .expect("owner snapshot")
    }

    fn history(fence: &StateFence) -> RevocationHistoryEvidence {
        RevocationHistoryEvidence {
            state_fence: fence.clone(),
            source_revision: 7,
            closures: Vec::new(),
        }
    }

    fn secret() -> SecretReference {
        SecretReference::new("test-provider", "test-key").expect("secret reference")
    }

    fn provider() -> Result<OwnerClosureProvider, CompositionError> {
        let fence = test_fence();
        OwnerClosureProvider::restore(owner_snapshot(&fence), Some(history(&fence)), &fence)
    }

    fn grant_params(
        fence: &StateFence,
        operation_id: &str,
        grant_id: &str,
        parent: Option<&str>,
    ) -> GrantAdmissionParams {
        GrantAdmissionParams {
            operation_id: operation_id.to_owned(),
            grant_id: grant_id.to_owned(),
            parent_grant_id: parent.map(str::to_owned),
            authority_root_ref: "root:alpha".to_owned(),
            snapshot_id: "snap-1".to_owned(),
            holder_principal: "principal:holder".to_owned(),
            session_id: "session-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            binding: binding(fence),
            allowed_effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::ScopedVerification,
            issued_at_ms: 1_000,
            expires_at_ms: Some(10_000),
            receipt_obligations: vec!["obligation-1".to_owned()],
        }
    }

    #[test]
    fn restore_serves_exact_revision_and_subtree_closure() -> Result<(), CompositionError> {
        let provider = provider()?;
        assert_eq!(provider.revision(), 7);
        assert_eq!(provider.authority_roots(), vec!["root:alpha".to_owned()]);
        let closure = provider.delegated_closure("grant:origin")?;
        assert_eq!(closure.revision, 7);
        assert_eq!(closure.members.len(), 2);
        assert_eq!(closure.members[0].grant_id.as_str(), "grant:origin");
        let leaf = provider.delegated_closure("grant:child")?;
        assert_eq!(leaf.members.len(), 1);
        assert!(provider.delegated_closure("grant:ghost").is_err());
        Ok(())
    }

    #[test]
    fn restore_refuses_absent_history() {
        let fence = test_fence();
        assert!(OwnerClosureProvider::restore(owner_snapshot(&fence), None, &fence).is_err());
    }

    #[test]
    fn admit_serve_round_trip_covers_grants_and_introductions() -> Result<(), CompositionError> {
        let fence = test_fence();
        let mut provider = provider()?;
        assert!(provider.serve_restore().is_err());
        provider.admit_grant_root(
            &grant_params(&fence, "op-admit-origin", "grant:origin", None),
            &secret(),
            1_000,
        )?;
        provider.admit_grant_member(
            &grant_params(
                &fence,
                "op-admit-child",
                "grant:child",
                Some("grant:origin"),
            ),
            &secret(),
            1_000,
        )?;
        provider.admit_introduction(
            &IntroductionAdmissionParams {
                operation_id: "op-admit-intro".to_owned(),
                introduction_id: "intro:1".to_owned(),
                authority_root_ref: "root:alpha".to_owned(),
                snapshot_id: "snap-1".to_owned(),
                supporting_grant_ids: vec!["grant:origin".to_owned(), "grant:child".to_owned()],
                resource_handle: "handle-1".to_owned(),
                facet_manifest_ref: "facet-1".to_owned(),
                holder_principal: "principal:holder".to_owned(),
                session_id: "session-1".to_owned(),
                scope_id: "scope-1".to_owned(),
                binding: binding(&fence),
                allowed_effect: EffectClass::Read,
                proof_ceiling: ProofCeiling::ScopedVerification,
                issued_at_ms: 1_000,
                expires_at_ms: None,
                receipt_obligations: Vec::new(),
            },
            &secret(),
            1_000,
        )?;
        provider.admit_preserved(PreservedAdmission {
            target_grant_id: "grant:origin".to_owned(),
            grant_id: "grant:child".to_owned(),
            covering_grant_id: "grant:origin".to_owned(),
            covering_root_ref: "root:alpha".to_owned(),
        })?;
        let restore = provider.serve_restore()?;
        assert_eq!(restore.members.len(), 1);
        assert_eq!(restore.roots.len(), 1);
        assert_eq!(restore.introductions.len(), 1);
        assert_eq!(restore.preserved.len(), 1);
        assert!(restore.revocation_history.is_some());
        // The sealed opaque record carries the admitted identity contour.
        assert_eq!(
            restore.members[0]
                .durable_record
                .record()
                .subject_id
                .as_str(),
            "grant:child"
        );
        assert_eq!(
            restore.introductions[0]
                .durable_record
                .record()
                .subject_id
                .as_str(),
            "intro:1"
        );
        Ok(())
    }

    #[test]
    fn admit_refuses_unknown_and_cross_parent_lineage() -> Result<(), CompositionError> {
        let fence = test_fence();
        let mut provider = provider()?;
        assert!(
            provider
                .admit_grant_member(
                    &grant_params(&fence, "op-ghost", "grant:ghost", Some("grant:origin")),
                    &secret(),
                    1_000,
                )
                .is_err()
        );
        assert!(
            provider
                .admit_grant_member(
                    &grant_params(&fence, "op-cross", "grant:child", Some("grant:child")),
                    &secret(),
                    1_000,
                )
                .is_err()
        );
        assert!(
            provider
                .admit_grant_root(
                    &grant_params(&fence, "op-root", "grant:child", Some("grant:origin")),
                    &secret(),
                    1_000,
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn registry_snapshot_round_trip_and_tamper_refusal() -> Result<(), CompositionError> {
        let fence = test_fence();
        let mut provider = provider()?;
        provider.admit_grant_root(
            &grant_params(&fence, "op-admit-origin", "grant:origin", None),
            &secret(),
            1_000,
        )?;
        let bytes = provider.export_registry()?;
        let fence2 = test_fence();
        let mut fresh = OwnerClosureProvider::restore(
            owner_snapshot(&fence2),
            Some(history(&fence2)),
            &fence2,
        )?;
        assert!(fresh.serve_restore().is_err());
        fresh.import_registry(&bytes)?;
        assert_eq!(fresh.serve_restore()?.roots.len(), 1);
        let mut tampered = bytes.clone();
        tampered[10] ^= 0xFF;
        assert!(fresh.import_registry(&tampered).is_err());
        Ok(())
    }

    #[test]
    fn refresh_rejects_stale_revision() -> Result<(), CompositionError> {
        let fence = test_fence();
        let mut provider = provider()?;
        assert!(
            provider
                .refresh(owner_snapshot(&fence), Some(history(&fence)), 6)
                .is_err()
        );
        assert_eq!(provider.revision(), 7);
        Ok(())
    }
}
