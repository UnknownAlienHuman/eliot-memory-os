//! Durable managed-resource identity shared by effect execution and redb
//! readback.
//!
//! Managed-resource and managed-root lookups are read-only projections of the
//! existing installation transaction table. Original transactions and their
//! effect progress remain the authority for package receipts and
//! ownership-secret references.

use std::path::{Path, PathBuf};

use eliot_contracts::sha256_hex;
use eliot_platform::{PortError, PortOutcome, UnknownReason};
use eliot_platform_windows::{
    FileIdentity, PackageStager, PackageStagingError, PackageStagingObservation, StagingReceipt,
    TrustedSourceBundle,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{InstallationError, PlatformHandle, handle, sha256_handle};

use super::package::{
    BoundPackageStagingInputs, build_package_snapshot, package_absent_with_snapshot,
    package_matching_observation, package_pending, package_stager_for_source,
    package_staging_outcome, package_staging_profile,
    stage_package_authorization_for_bound_package, validate_observed_against_plan,
    validate_staging_receipt_for_observation, validate_staging_receipt_for_plan,
    verify_managed_destination_parent_identity,
};
use super::{
    InstallationCreateDisposition, InstallationEffectAction, InstallationEffectDisposition,
    InstallationEffectExecution, InstallationEffectObservation, InstallationEffectProgress,
    InstallationEffectProgressState, InstallationEffectRequest, InstallationProfile,
    InstallationSecretLifecycle, InstallationSecretProvisionDisposition, InstallationStage,
    InstallationTransaction, ManagedEffectOperation, ManagedEffectRecipe, same_windows_root,
};

/// Current wire version of one same-store managed-resource projection.
pub(crate) const MANAGED_RESOURCE_PROJECTION_WIRE_VERSION: u32 = 1;

/// Stable lookup identity for one admitted external family and exact candidate.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedResourceKey {
    /// Accepted catalogue family identity.
    pub family_id: PlatformHandle,
    /// Exact candidate identity requested by the owner.
    pub exact_candidate: PlatformHandle,
}

impl ManagedResourceKey {
    /// Validate the exact lookup pair before using it as a store key.
    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        handle(&self.family_id, "managed_resource.family_id")?;
        handle(&self.exact_candidate, "managed_resource.exact_candidate")
    }
}

/// Frozen reference to the original transaction that owns one managed parent
/// root. This is persisted in the current managed effect and rechecked against
/// the same transaction table before its intent is admitted.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationManagedRootEffectProof {
    /// Original installation transaction that created this exact root.
    pub owner_transaction_id: PlatformHandle,
    /// Digest of the original transaction's complete immutable effect plan.
    pub installer_plan_digest: PlatformHandle,
    /// Exact original `CreateRoot` effect plan.
    pub original_plan: super::InstallerEffectPlan,
    /// Exact original durable effect progress, including ownership reference.
    pub original_progress: InstallationEffectProgress,
}

impl InstallationManagedRootEffectProof {
    pub(super) fn validate(&self, root: &PlatformHandle) -> Result<(), InstallationError> {
        handle(
            &self.owner_transaction_id,
            "managed_root.owner_transaction_id",
        )?;
        sha256_handle(
            &self.installer_plan_digest,
            "managed_root.installer_plan_digest",
        )?;
        let super::InstallerEffectPlan::CreateRoot {
            effect_id,
            root: original_root,
        } = &self.original_plan
        else {
            return Err(InstallationError::IdentityConflict);
        };
        if &self.original_progress.effect_id != effect_id
            || !same_windows_root(original_root.as_str(), root.as_str())?
        {
            return Err(InstallationError::IdentityConflict);
        }
        let InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            ..
        } = &self.original_progress.state
        else {
            return Err(InstallationError::IdentityConflict);
        };
        let ownership = self
            .original_progress
            .ownership_secret
            .as_ref()
            .ok_or(InstallationError::IdentityConflict)?;
        if ownership.create_disposition != InstallationCreateDisposition::Created
            || ownership.secret_provision_disposition
                != InstallationSecretProvisionDisposition::Created
            || ownership.lifecycle != InstallationSecretLifecycle::Active
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Derives the original managed-root owner from the current transaction
/// table. The current anchor supplies the exact installation epoch and
/// principal binding; every matching path must resolve to one completed or
/// `ActiveVerified` transaction-created root.
#[allow(
    clippy::too_many_lines,
    reason = "the complete owner-transaction and effect-progress proof must be checked as one read-only join"
)]
pub(super) fn derive_managed_root_effect_proof(
    transactions: &[InstallationTransaction],
    anchor_transaction_id: &PlatformHandle,
    installation_root: &PlatformHandle,
    profile: InstallationProfile,
    root: &PlatformHandle,
) -> Result<Option<InstallationManagedRootEffectProof>, InstallationError> {
    handle(anchor_transaction_id, "managed_root.anchor_transaction_id")?;
    let anchor = transactions
        .iter()
        .find(|transaction| transaction.transaction_id == *anchor_transaction_id)
        .ok_or_else(|| InstallationError::TransactionNotFound {
            transaction_id: anchor_transaction_id.as_str().to_owned(),
        })?;
    anchor.validate()?;
    if !matches!(
        anchor.stage(),
        InstallationStage::Completed | InstallationStage::ActiveVerified
    ) || anchor.profile != profile
        || !same_windows_root(
            anchor
                .candidate_manifest
                .runtime_launch
                .runtime_state_roots
                .installation_root
                .as_str(),
            installation_root.as_str(),
        )?
    {
        return Err(InstallationError::IdentityConflict);
    }
    let mut anchor_principal = None;
    for (effect, progress) in anchor
        .installer_effects
        .iter()
        .zip(anchor.effect_progress())
    {
        if !matches!(effect, super::InstallerEffectPlan::CreateRoot { .. }) {
            continue;
        }
        let Some(ownership) = progress.ownership_secret.as_ref() else {
            continue;
        };
        if !matches!(
            &progress.state,
            InstallationEffectProgressState::Applied { .. }
        ) {
            continue;
        }
        if ownership.secret_provision_disposition != InstallationSecretProvisionDisposition::Created
            || ownership.lifecycle != InstallationSecretLifecycle::Active
        {
            continue;
        }
        match &anchor_principal {
            Some(principal) if principal != &ownership.reference.expected_principal_sid => {
                return Err(InstallationError::IdentityConflict);
            }
            None => {
                anchor_principal = Some(ownership.reference.expected_principal_sid.clone());
            }
            _ => {}
        }
    }
    let anchor_principal = anchor_principal.ok_or_else(|| {
        InstallationError::IncompleteObservation(
            "anchor transaction has no active root ownership principal binding".to_owned(),
        )
    })?;

    let mut owner = None;
    for transaction in transactions {
        transaction.validate()?;
        for (effect, progress) in transaction
            .installer_effects
            .iter()
            .zip(transaction.effect_progress())
        {
            let super::InstallerEffectPlan::CreateRoot {
                effect_id,
                root: observed_root,
            } = effect
            else {
                continue;
            };
            if !same_windows_root(observed_root.as_str(), root.as_str())? {
                continue;
            }
            if transaction.profile != profile
                || transaction.installation_epoch != anchor.installation_epoch
                || !same_windows_root(
                    transaction
                        .candidate_manifest
                        .runtime_launch
                        .runtime_state_roots
                        .installation_root
                        .as_str(),
                    installation_root.as_str(),
                )?
            {
                return Err(InstallationError::IdentityConflict);
            }
            if !matches!(
                transaction.stage(),
                InstallationStage::Completed | InstallationStage::ActiveVerified
            ) {
                return Err(InstallationError::IncompleteObservation(
                    "matching root has an unfinished original transaction".to_owned(),
                ));
            }
            let state = &progress.state;
            if matches!(
                state,
                InstallationEffectProgressState::Applied {
                    disposition: InstallationEffectDisposition::PreexistingMatching,
                    ..
                }
            ) {
                continue;
            }
            let ownership = progress
                .ownership_secret
                .as_ref()
                .ok_or(InstallationError::IdentityConflict)?;
            if ownership.reference.expected_principal_sid != anchor_principal {
                return Err(InstallationError::IdentityConflict);
            }
            let proof = InstallationManagedRootEffectProof {
                owner_transaction_id: transaction.transaction_id.clone(),
                installer_plan_digest: transaction.installer_plan_digest.clone(),
                original_plan: effect.clone(),
                original_progress: progress.clone(),
            };
            proof.validate(root)?;
            if progress.effect_id != *effect_id {
                return Err(InstallationError::IdentityConflict);
            }
            if owner.replace(proof).is_some() {
                return Err(InstallationError::IdentityConflict);
            }
        }
    }
    Ok(owner)
}

/// Atomically revalidates every frozen managed-root proof against the source
/// transactions in the same table and refuses any unrecorded original owner.
#[allow(
    clippy::too_many_lines,
    reason = "all prior-root ownership and retained receipt checks form one fail-closed admission boundary"
)]
pub(super) fn validate_managed_prior_root_effects(
    transactions: &[InstallationTransaction],
    current: &InstallationTransaction,
) -> Result<(), InstallationError> {
    let managed = current
        .installer_effects
        .iter()
        .find_map(|effect| match effect {
            super::InstallerEffectPlan::ManagedEnvironmentChange {
                managed_tools_root,
                recipe,
                prior_root_effects,
                ..
            } => Some((managed_tools_root, recipe, prior_root_effects)),
            _ => None,
        });
    let Some((managed_tools_root, recipe, prior_root_effects)) = managed else {
        return Ok(());
    };
    let roots_required = if managed_operation_stages(recipe.operation)
        || recipe.operation == ManagedEffectOperation::RemoveOwnedPortableGeneration
    {
        vec![
            managed_tools_root.clone(),
            PlatformHandle::new(
                Path::new(managed_tools_root.as_str())
                    .join(recipe.target_family.as_str())
                    .to_string_lossy()
                    .into_owned(),
            )
            .map_err(|error| InstallationError::InvalidField {
                field: "managed_root.family_root".to_owned(),
                reason: error.to_string(),
            })?,
        ]
    } else {
        Vec::new()
    };
    if prior_root_effects.len() > roots_required.len() {
        return Err(InstallationError::IdentityConflict);
    }
    let mut principal = None;
    let mut consumed_proofs = vec![false; prior_root_effects.len()];
    for root in &roots_required {
        let mut expected_proof = None;
        for (proof_index, proof) in prior_root_effects.iter().enumerate() {
            let super::InstallerEffectPlan::CreateRoot {
                root: proof_root, ..
            } = &proof.original_plan
            else {
                return Err(InstallationError::IdentityConflict);
            };
            if same_windows_root(proof_root.as_str(), root.as_str())? {
                if expected_proof.replace(proof).is_some() || consumed_proofs[proof_index] {
                    return Err(InstallationError::IdentityConflict);
                }
                consumed_proofs[proof_index] = true;
            }
        }
        if let Some(proof) = expected_proof {
            proof.validate(root)?;
        }
        let mut owner = None;
        for transaction in transactions {
            transaction.validate()?;
            for (effect, progress) in transaction
                .installer_effects
                .iter()
                .zip(transaction.effect_progress())
            {
                let super::InstallerEffectPlan::CreateRoot {
                    root: recorded_root,
                    ..
                } = effect
                else {
                    continue;
                };
                if !same_windows_root(recorded_root.as_str(), root.as_str())? {
                    continue;
                }
                if transaction.profile != current.profile
                    || transaction.installation_epoch != current.installation_epoch
                    || !same_windows_root(
                        transaction
                            .candidate_manifest
                            .runtime_launch
                            .runtime_state_roots
                            .installation_root
                            .as_str(),
                        current
                            .candidate_manifest
                            .runtime_launch
                            .runtime_state_roots
                            .installation_root
                            .as_str(),
                    )?
                {
                    return Err(InstallationError::IdentityConflict);
                }
                if transaction.transaction_id == current.transaction_id {
                    continue;
                }
                if !matches!(
                    transaction.stage(),
                    InstallationStage::Completed | InstallationStage::ActiveVerified
                ) {
                    return Err(InstallationError::IncompleteObservation(
                        "matching root has an unfinished original transaction".to_owned(),
                    ));
                }
                if matches!(
                    &progress.state,
                    InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::PreexistingMatching,
                        ..
                    }
                ) {
                    continue;
                }
                let proof = InstallationManagedRootEffectProof {
                    owner_transaction_id: transaction.transaction_id.clone(),
                    installer_plan_digest: transaction.installer_plan_digest.clone(),
                    original_plan: effect.clone(),
                    original_progress: progress.clone(),
                };
                proof.validate(root)?;
                let owner_principal = proof
                    .original_progress
                    .ownership_secret
                    .as_ref()
                    .ok_or(InstallationError::IdentityConflict)?
                    .reference
                    .expected_principal_sid
                    .clone();
                match &principal {
                    Some(previous) if previous != &owner_principal => {
                        return Err(InstallationError::IdentityConflict);
                    }
                    None => principal = Some(owner_principal),
                    _ => {}
                }
                if owner.replace(proof).is_some() {
                    return Err(InstallationError::IdentityConflict);
                }
            }
        }
        if owner.as_ref() != expected_proof {
            return Err(InstallationError::IdentityConflict);
        }
    }
    if consumed_proofs.iter().any(|consumed| !consumed) {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}

/// Exact transaction/effect pointer that owns a managed resource operation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedResourceEffectRef {
    /// Existing `InstallationTransaction` that owns effect intent and outcome.
    pub transaction_id: PlatformHandle,
    /// Exact immutable effect inside that transaction.
    pub effect_id: PlatformHandle,
    /// Digest recorded by that transaction for its complete immutable plan.
    pub installer_plan_digest: PlatformHandle,
    /// Identity recorded after transaction readback for the external object.
    pub external_identity: PlatformHandle,
    /// Existing package receipt digest, absent only for metadata registration.
    pub staging_receipt_digest: Option<PlatformHandle>,
}

impl ManagedResourceEffectRef {
    pub(crate) fn validate(&self, field: &str) -> Result<(), InstallationError> {
        handle(&self.transaction_id, &format!("{field}.transaction_id"))?;
        handle(&self.effect_id, &format!("{field}.effect_id"))?;
        sha256_handle(
            &self.installer_plan_digest,
            &format!("{field}.installer_plan_digest"),
        )?;
        handle(
            &self.external_identity,
            &format!("{field}.external_identity"),
        )?;
        if let Some(receipt) = &self.staging_receipt_digest {
            sha256_handle(receipt, &format!("{field}.staging_receipt_digest"))?;
        }
        Ok(())
    }
}

/// What the original admitted effect made durable for this exact candidate.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagedResourceDisposition {
    /// A transaction-owned immutable artifact or configuration generation.
    Installed,
    /// A retained metadata-only registration of an observed artifact.
    Registered,
    /// A transaction-owned configuration generation was reconfigured.
    Reconfigured,
    /// The previous exact transaction-owned resource was removed.
    Removed,
}

/// Same-store lookup projection. Package bytes, receipts and ownership-key
/// references are read from `origin`, never copied or reconstructed from this
/// row. `last_effect` supplies an exact tombstone/update provenance.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedResourceProjection {
    /// Strict projection wire discriminator.
    pub wire_version: u32,
    /// Exact catalogue family and candidate lookup key.
    pub key: ManagedResourceKey,
    /// Current metadata-only lifecycle classification.
    pub disposition: ManagedResourceDisposition,
    /// Original effect that owns the package receipt or registration record.
    pub origin: ManagedResourceEffectRef,
    /// Every immutable generation this installation has created for the
    /// exact family/candidate. They remain independently owned by their
    /// original transaction receipts across side-by-side updates.
    pub owned_generations: Vec<ManagedResourceEffectRef>,
    /// Latest admitted effect that changed this projection.
    pub last_effect: ManagedResourceEffectRef,
    /// Exact System Owner recipe registration identity, when present.
    pub registration_identity: Option<PlatformHandle>,
}

impl ManagedResourceProjection {
    pub(crate) fn validate(&self) -> Result<(), InstallationError> {
        if self.wire_version != MANAGED_RESOURCE_PROJECTION_WIRE_VERSION {
            return Err(InstallationError::InvalidField {
                field: "managed_resource.wire_version".to_owned(),
                reason: format!(
                    "must equal current wire version {MANAGED_RESOURCE_PROJECTION_WIRE_VERSION}"
                ),
            });
        }
        self.key.validate()?;
        self.origin.validate("managed_resource.origin")?;
        self.last_effect.validate("managed_resource.last_effect")?;
        for generation in &self.owned_generations {
            generation.validate("managed_resource.owned_generations")?;
            if generation.staging_receipt_digest.is_none() {
                return Err(InstallationError::IdentityConflict);
            }
        }
        if self.disposition == ManagedResourceDisposition::Registered {
            handle(
                self.registration_identity
                    .as_ref()
                    .ok_or(InstallationError::IdentityConflict)?,
                "managed_resource.registration_identity",
            )?;
            if self.origin.staging_receipt_digest.is_some() {
                return Err(InstallationError::IdentityConflict);
            }
            if !self.owned_generations.is_empty() {
                return Err(InstallationError::IdentityConflict);
            }
        } else if self.disposition != ManagedResourceDisposition::Removed
            && (self.origin.staging_receipt_digest.is_none() || self.owned_generations.is_empty())
        {
            return Err(InstallationError::IdentityConflict);
        }
        if self.disposition == ManagedResourceDisposition::Removed
            && (self.last_effect == self.origin || self.owned_generations.is_empty())
        {
            return Err(InstallationError::IdentityConflict);
        }
        Ok(())
    }
}

/// Rebuilds the current exact-family projection from the original transaction
/// and effect receipts in `installation_transactions_v7`. The projection is
/// derived data: every resource owner and package receipt is resolved through
/// its immutable transaction/effect identity.
#[allow(
    clippy::too_many_lines,
    reason = "the current projection is derived from one ordered walk of the original transaction table"
)]
pub(super) fn derive_managed_resource_projection(
    transactions: &[InstallationTransaction],
    key: &ManagedResourceKey,
) -> Result<Option<ManagedResourceProjection>, InstallationError> {
    key.validate()?;
    let mut candidates = Vec::new();
    for transaction in transactions {
        transaction.validate()?;
        match transaction.stage() {
            InstallationStage::RollbackRequired | InstallationStage::Quarantined => {
                if transaction.installer_effects.iter().any(|effect| {
                    matches!(
                        effect,
                        super::InstallerEffectPlan::ManagedEnvironmentChange { request, .. }
                            if request.target_family == key.family_id
                                && request.exact_candidate == key.exact_candidate
                    )
                }) {
                    return Err(InstallationError::IncompleteObservation(
                        "managed resource has an unresolved original transaction".to_owned(),
                    ));
                }
            }
            InstallationStage::Completed => {
                for (index, effect) in transaction.installer_effects.iter().enumerate() {
                    let super::InstallerEffectPlan::ManagedEnvironmentChange {
                        request,
                        recipe,
                        prior_resource,
                        prior_receipts,
                        ..
                    } = effect
                    else {
                        continue;
                    };
                    if request.target_family != key.family_id
                        || request.exact_candidate != key.exact_candidate
                    {
                        continue;
                    }
                    let progress = transaction
                        .effect_progress()
                        .get(index)
                        .ok_or(InstallationError::IdentityConflict)?;
                    let InstallationEffectProgressState::Applied {
                        disposition: InstallationEffectDisposition::CreatedByTransaction,
                        external_identity,
                        ..
                    } = &progress.state
                    else {
                        return Err(InstallationError::IdentityConflict);
                    };
                    let effect_ref = ManagedResourceEffectRef {
                        transaction_id: transaction.transaction_id.clone(),
                        effect_id: effect.effect_id().clone(),
                        installer_plan_digest: transaction.installer_plan_digest.clone(),
                        external_identity: external_identity.clone(),
                        staging_receipt_digest: progress
                            .staging_receipt
                            .as_ref()
                            .map(|receipt| {
                                PlatformHandle::new(receipt.digest()).map_err(|error| {
                                    InstallationError::InvalidField {
                                        field: "managed_resource.staging_receipt_digest".to_owned(),
                                        reason: error.to_string(),
                                    }
                                })
                            })
                            .transpose()?,
                    };
                    effect_ref.validate("managed_resource.effect")?;
                    let prior = prior_resource.as_deref().cloned();
                    validate_prior_effect_references(transactions, prior.as_ref(), prior_receipts)?;
                    let projection = transition_managed_resource(
                        key,
                        recipe,
                        prior,
                        effect_ref,
                        progress.staging_receipt.as_ref(),
                        prior_receipts,
                    )?;
                    candidates.push((prior_resource.as_deref().cloned(), projection));
                }
            }
            _ => {}
        }
    }

    let mut current = None;
    let mut consumed = vec![false; candidates.len()];
    loop {
        let next = candidates
            .iter()
            .enumerate()
            .filter(|(index, (prior, _))| !consumed[*index] && *prior == current)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if next.is_empty() {
            break;
        }
        if next.len() != 1 {
            return Err(InstallationError::IdentityConflict);
        }
        let index = next[0];
        consumed[index] = true;
        current = Some(candidates[index].1.clone());
    }
    if consumed.iter().any(|used| !used) {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(current)
}

/// Confirms that the exact previous projection and all of its package receipts
/// still resolve to the original transaction/effect progress rows.
pub(super) fn validate_managed_prior_receipts(
    transactions: &[InstallationTransaction],
    plan: &super::InstallerEffectPlan,
) -> Result<(), InstallationError> {
    let super::InstallerEffectPlan::ManagedEnvironmentChange {
        prior_resource,
        prior_receipts,
        ..
    } = plan
    else {
        return Ok(());
    };
    validate_prior_effect_references(transactions, prior_resource.as_deref(), prior_receipts)
}

fn validate_prior_effect_references(
    transactions: &[InstallationTransaction],
    prior: Option<&ManagedResourceProjection>,
    prior_receipts: &[StagingReceipt],
) -> Result<(), InstallationError> {
    let Some(prior) = prior else {
        if prior_receipts.is_empty() {
            return Ok(());
        }
        return Err(InstallationError::IdentityConflict);
    };
    prior.validate()?;
    let mut expected_receipts = Vec::with_capacity(prior.owned_generations.len());
    for generation in &prior.owned_generations {
        let receipt = resolve_applied_managed_effect(transactions, generation)?
            .ok_or(InstallationError::IdentityConflict)?;
        expected_receipts.push(receipt);
    }
    if expected_receipts != prior_receipts {
        return Err(InstallationError::IdentityConflict);
    }
    resolve_applied_managed_effect(transactions, &prior.origin)?;
    resolve_applied_managed_effect(transactions, &prior.last_effect)?;
    Ok(())
}

pub(super) fn resolve_applied_managed_effect(
    transactions: &[InstallationTransaction],
    effect_ref: &ManagedResourceEffectRef,
) -> Result<Option<StagingReceipt>, InstallationError> {
    effect_ref.validate("managed_resource.effect_ref")?;
    let transaction = transactions
        .iter()
        .find(|transaction| transaction.transaction_id == effect_ref.transaction_id)
        .ok_or(InstallationError::IdentityConflict)?;
    if transaction.stage() != InstallationStage::Completed
        || transaction.installer_plan_digest != effect_ref.installer_plan_digest
    {
        return Err(InstallationError::IdentityConflict);
    }
    let (index, effect) = transaction
        .installer_effects
        .iter()
        .enumerate()
        .find(|(_, effect)| effect.effect_id() == &effect_ref.effect_id)
        .ok_or(InstallationError::IdentityConflict)?;
    if !matches!(
        effect,
        super::InstallerEffectPlan::ManagedEnvironmentChange { .. }
    ) {
        return Err(InstallationError::IdentityConflict);
    }
    let progress = transaction
        .effect_progress()
        .get(index)
        .ok_or(InstallationError::IdentityConflict)?;
    match &progress.state {
        InstallationEffectProgressState::Applied {
            disposition: InstallationEffectDisposition::CreatedByTransaction,
            external_identity,
            ..
        } if external_identity == &effect_ref.external_identity => {}
        _ => return Err(InstallationError::IdentityConflict),
    }
    let receipt = progress.staging_receipt.clone();
    match (&effect_ref.staging_receipt_digest, &receipt) {
        (Some(expected), Some(receipt)) if expected.as_str() == receipt.digest() => {
            Ok(Some(receipt.clone()))
        }
        (None, None) => Ok(None),
        _ => Err(InstallationError::IdentityConflict),
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "the exact managed operation transition and ownership revision must remain one auditable mapping"
)]
fn transition_managed_resource(
    key: &ManagedResourceKey,
    recipe: &ManagedEffectRecipe,
    prior: Option<ManagedResourceProjection>,
    effect_ref: ManagedResourceEffectRef,
    receipt: Option<&StagingReceipt>,
    prior_receipts: &[StagingReceipt],
) -> Result<ManagedResourceProjection, InstallationError> {
    let has_receipt = receipt.is_some();
    let mut projection = match recipe.operation {
        ManagedEffectOperation::InstallPortableGeneration => {
            if prior.is_some() || !has_receipt {
                return Err(InstallationError::IdentityConflict);
            }
            ManagedResourceProjection {
                wire_version: MANAGED_RESOURCE_PROJECTION_WIRE_VERSION,
                key: key.clone(),
                disposition: ManagedResourceDisposition::Installed,
                origin: effect_ref.clone(),
                owned_generations: vec![effect_ref.clone()],
                last_effect: effect_ref,
                registration_identity: Some(recipe.registration_identity.clone()),
            }
        }
        ManagedEffectOperation::RegisterObservedPortableGeneration => {
            if prior.is_some() || has_receipt {
                return Err(InstallationError::IdentityConflict);
            }
            ManagedResourceProjection {
                wire_version: MANAGED_RESOURCE_PROJECTION_WIRE_VERSION,
                key: key.clone(),
                disposition: ManagedResourceDisposition::Registered,
                origin: effect_ref.clone(),
                owned_generations: Vec::new(),
                last_effect: effect_ref,
                registration_identity: Some(recipe.registration_identity.clone()),
            }
        }
        ManagedEffectOperation::UpdatePortableGeneration => {
            let mut prior = prior.ok_or(InstallationError::IdentityConflict)?;
            if prior.disposition == ManagedResourceDisposition::Removed || !has_receipt {
                return Err(InstallationError::IdentityConflict);
            }
            if prior_receipts
                .iter()
                .any(|previous| previous.generation == recipe.package_manifest.generation)
            {
                return Err(InstallationError::IdentityConflict);
            }
            if prior.disposition == ManagedResourceDisposition::Registered {
                prior.origin = effect_ref.clone();
            }
            prior.owned_generations.push(effect_ref.clone());
            prior.last_effect = effect_ref;
            prior.registration_identity = Some(recipe.registration_identity.clone());
            prior.disposition = ManagedResourceDisposition::Installed;
            prior
        }
        ManagedEffectOperation::RepairPortableGeneration => {
            let mut prior = prior.ok_or(InstallationError::IdentityConflict)?;
            if prior.disposition == ManagedResourceDisposition::Removed {
                return Err(InstallationError::IdentityConflict);
            }
            let receipt = receipt.ok_or(InstallationError::IdentityConflict)?;
            let prior_receipt_index = prior_receipts
                .iter()
                .position(|previous| previous.generation == receipt.generation)
                .ok_or(InstallationError::IdentityConflict)?;
            let prior_digest = PlatformHandle::new(prior_receipts[prior_receipt_index].digest())
                .map_err(|error| InstallationError::InvalidField {
                    field: "managed_resource.staging_receipt_digest".to_owned(),
                    reason: error.to_string(),
                })?;
            let generation_ref_index = prior
                .owned_generations
                .iter()
                .position(|owner| owner.staging_receipt_digest.as_ref() == Some(&prior_digest))
                .ok_or(InstallationError::IdentityConflict)?;
            prior.owned_generations[generation_ref_index] = effect_ref.clone();
            prior.last_effect = effect_ref;
            prior.registration_identity = Some(recipe.registration_identity.clone());
            prior.disposition = ManagedResourceDisposition::Installed;
            prior
        }
        ManagedEffectOperation::ReconfigurePortableGeneration => {
            let mut prior = prior.ok_or(InstallationError::IdentityConflict)?;
            if prior.disposition == ManagedResourceDisposition::Removed || !has_receipt {
                return Err(InstallationError::IdentityConflict);
            }
            if prior.disposition == ManagedResourceDisposition::Registered {
                prior.origin = effect_ref.clone();
            }
            prior.owned_generations.push(effect_ref.clone());
            prior.last_effect = effect_ref;
            prior.registration_identity = Some(recipe.registration_identity.clone());
            prior.disposition = ManagedResourceDisposition::Reconfigured;
            prior
        }
        ManagedEffectOperation::RemoveOwnedPortableGeneration => {
            let mut prior = prior.ok_or(InstallationError::IdentityConflict)?;
            if prior.disposition == ManagedResourceDisposition::Removed || has_receipt {
                return Err(InstallationError::IdentityConflict);
            }
            if !prior_receipts
                .iter()
                .any(|previous| previous.generation == recipe.package_manifest.generation)
            {
                return Err(InstallationError::IdentityConflict);
            }
            prior.last_effect = effect_ref;
            prior.disposition = ManagedResourceDisposition::Removed;
            prior
        }
    };
    projection.key = key.clone();
    projection.validate()?;
    Ok(projection)
}

/// Whether an operation stages a new immutable package generation.
pub(super) const fn managed_operation_stages(operation: ManagedEffectOperation) -> bool {
    matches!(
        operation,
        ManagedEffectOperation::InstallPortableGeneration
            | ManagedEffectOperation::UpdatePortableGeneration
            | ManagedEffectOperation::RepairPortableGeneration
            | ManagedEffectOperation::ReconfigurePortableGeneration
    )
}

/// Classifies the repair crash window using the exact candidate and prior
/// generation readbacks. Only two independently observed absences authorize
/// the original committed effect to resume.
pub(super) fn managed_repair_restart_readback(
    candidate: PackageStagingObservation,
    prior: PackageStagingObservation,
) -> PackageStagingObservation {
    match candidate {
        PackageStagingObservation::Absent => match prior {
            PackageStagingObservation::Absent => PackageStagingObservation::Absent,
            PackageStagingObservation::Matching(_) => {
                PackageStagingObservation::Mismatch(PackageStagingError::IdentityMismatch)
            }
            PackageStagingObservation::Mismatch(error) => {
                PackageStagingObservation::Mismatch(error)
            }
            PackageStagingObservation::Unknown(error) => PackageStagingObservation::Unknown(error),
        },
        candidate => candidate,
    }
}

pub(super) const fn managed_operation_requires_destination_parent(
    operation: ManagedEffectOperation,
) -> bool {
    managed_operation_stages(operation)
        || matches!(
            operation,
            ManagedEffectOperation::RemoveOwnedPortableGeneration
        )
}

fn managed_destination(
    request: &InstallationEffectRequest,
    recipe: &ManagedEffectRecipe,
) -> Result<PlatformHandle, InstallationError> {
    let root = match &request.plan {
        super::InstallerEffectPlan::ManagedEnvironmentChange {
            managed_tools_root, ..
        } => PathBuf::from(managed_tools_root.as_str()),
        _ => return Err(InstallationError::IdentityConflict),
    };
    let destination = root.join(&recipe.package_manifest.generation);
    PlatformHandle::new(destination.to_string_lossy().into_owned()).map_err(|error| {
        InstallationError::InvalidField {
            field: "managed_effect.destination_root".to_owned(),
            reason: error.to_string(),
        }
    })
}

fn prior_generation_receipt<'a>(
    request: &'a InstallationEffectRequest,
    recipe: &ManagedEffectRecipe,
) -> Result<&'a StagingReceipt, PackageStagingError> {
    let super::InstallerEffectPlan::ManagedEnvironmentChange { prior_receipts, .. } = &request.plan
    else {
        return Err(PackageStagingError::IdentityMismatch);
    };
    let receipt = prior_receipts
        .iter()
        .rev()
        .find(|receipt| receipt.generation == recipe.package_manifest.generation)
        .ok_or(PackageStagingError::IdentityMismatch)?;
    validate_staging_receipt_for_plan(&request.plan, receipt)
        .map_err(|_| PackageStagingError::IdentityMismatch)?;
    Ok(receipt)
}

fn managed_absence(
    request: &InstallationEffectRequest,
    snapshot: &super::PackageObservationSnapshot,
    evidence: Vec<PlatformHandle>,
) -> Result<InstallationEffectObservation, PortError> {
    let (external_identity, postcondition_digest) = managed_external_binding(request, snapshot)?;
    Ok(InstallationEffectObservation::Matching {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity,
        evidence,
        postcondition_digest,
        service_control_grant: None,
        credential_receipt: None,
        staging_receipt: None,
        phase_b_receipt: None,
        service_runtime_lineage: None,
    })
}

fn managed_recipe(
    request: &InstallationEffectRequest,
) -> Result<&ManagedEffectRecipe, PackageStagingError> {
    let super::InstallerEffectPlan::ManagedEnvironmentChange {
        request: managed_request,
        recipe,
        ..
    } = &request.plan
    else {
        return Err(PackageStagingError::Io);
    };
    if recipe.action != managed_request.action
        || recipe.target_family != managed_request.target_family
        || recipe.package_manifest.generation
            != format!("{}/{}", recipe.target_family, recipe.package_version)
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    Ok(recipe)
}

fn signed_source_snapshot(
    recipe: &ManagedEffectRecipe,
) -> Result<super::PackageObservationSnapshot, PackageStagingError> {
    let source = TrustedSourceBundle::open(Path::new(recipe.source_bundle.as_str()))?;
    if source.identity() != recipe.source_bundle_identity {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let observed = source.observe()?;
    validate_observed_against_plan(&observed, &recipe.package_manifest, &recipe.expected_files)?;
    let generation = PlatformHandle::new(recipe.package_manifest.generation.clone())
        .map_err(|_| PackageStagingError::IdentityMismatch)?;
    let manifest_digest = PlatformHandle::new(recipe.package_manifest.canonical_digest())
        .map_err(|_| PackageStagingError::IdentityMismatch)?;
    build_package_snapshot(source.identity(), generation, manifest_digest, &observed)
}

fn managed_external_binding(
    request: &InstallationEffectRequest,
    snapshot: &super::PackageObservationSnapshot,
) -> Result<(PlatformHandle, PlatformHandle), PortError> {
    let recipe = managed_recipe(request).map_err(|_| PortError::InvalidRequestMetadata)?;
    let external_identity = PlatformHandle::new(sha256_hex(
        &serde_json::to_vec(&(
            "managed-source-identity-v1",
            recipe.source_bundle_identity,
            snapshot.generation.as_str(),
            snapshot.manifest_digest.as_str(),
            snapshot.digest.as_str(),
            recipe.registration_identity.as_str(),
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)?,
    ))
    .map_err(|_| PortError::InvalidRequestMetadata)?;
    let postcondition_digest = PlatformHandle::new(sha256_hex(
        &serde_json::to_vec(&(
            "managed-source-postcondition-v1",
            request.plan_digest.as_str(),
            snapshot.digest.as_str(),
            recipe.registration_identity.as_str(),
            recipe.executable_relative_paths.as_slice(),
        ))
        .map_err(|_| PortError::InvalidRequestMetadata)?,
    ))
    .map_err(|_| PortError::InvalidRequestMetadata)?;
    Ok((external_identity, postcondition_digest))
}

/// Confirms the exact readback binding for the two managed operations that do
/// not retain a new package-generation receipt. The adapter's operation
/// postcondition is tied to the signed plan and its fresh source observation;
/// removal additionally carries the digest of the original receipt it removed.
pub(super) fn validate_nonstaging_managed_readback(
    request: &InstallationEffectRequest,
    external_identity: &PlatformHandle,
    evidence: &[PlatformHandle],
    postcondition_digest: &PlatformHandle,
) -> Result<(), InstallationError> {
    let recipe = managed_recipe(request).map_err(|_| InstallationError::IdentityConflict)?;
    let snapshot =
        signed_source_snapshot(recipe).map_err(|_| InstallationError::IdentityConflict)?;
    if request.precondition.package_snapshot.as_ref() != Some(&snapshot) {
        return Err(InstallationError::IdentityConflict);
    }
    let (expected_external_identity, expected_postcondition_digest) =
        managed_external_binding(request, &snapshot)
            .map_err(|_| InstallationError::IdentityConflict)?;
    let expected_evidence = match recipe.operation {
        ManagedEffectOperation::RegisterObservedPortableGeneration => vec![snapshot.digest],
        ManagedEffectOperation::RemoveOwnedPortableGeneration => {
            let prior = prior_generation_receipt(request, recipe)
                .map_err(|_| InstallationError::IdentityConflict)?;
            vec![PlatformHandle::new(prior.digest()).map_err(|error| {
                InstallationError::InvalidField {
                    field: "managed_effect.prior_receipt".to_owned(),
                    reason: error.to_string(),
                }
            })?]
        }
        _ => return Err(InstallationError::IdentityConflict),
    };
    if external_identity != &expected_external_identity
        || postcondition_digest != &expected_postcondition_digest
        || evidence != expected_evidence.as_slice()
    {
        return Err(InstallationError::IdentityConflict);
    }
    Ok(())
}

fn managed_matching_source(
    request: &InstallationEffectRequest,
    snapshot: super::PackageObservationSnapshot,
) -> Result<InstallationEffectObservation, PortError> {
    if let Some(retained) = request.precondition.package_snapshot.as_ref()
        && retained != &snapshot
    {
        return Ok(package_pending(&PackageStagingError::HashMismatch));
    }
    let (external_identity, postcondition_digest) = managed_external_binding(request, &snapshot)?;
    Ok(InstallationEffectObservation::Matching {
        disposition: InstallationEffectDisposition::CreatedByTransaction,
        external_identity,
        evidence: vec![snapshot.digest],
        postcondition_digest,
        service_control_grant: None,
        credential_receipt: None,
        staging_receipt: None,
        phase_b_receipt: None,
        service_runtime_lineage: None,
    })
}

/// Inspects the signed source and the exact managed generation destination.
///
/// This does not create or adopt a destination. Package actions use the
/// existing `PackageStager` open contract, which retains the existing signed
/// family parent and refuses a destination that already exists without the
/// original receipt. Registration reads only the signed source inventory.
pub(super) fn inspect_managed_change(
    request: &InstallationEffectRequest,
    destination_parent_identity: Option<FileIdentity>,
) -> Result<InstallationEffectObservation, PackageStagingError> {
    let recipe = managed_recipe(request)?;
    if managed_operation_requires_destination_parent(recipe.operation)
        && destination_parent_identity.is_none()
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let snapshot = signed_source_snapshot(recipe)?;
    if let Some(persisted) = request.precondition.package_snapshot.as_ref()
        && persisted != &snapshot
    {
        return Err(PackageStagingError::HashMismatch);
    }
    match recipe.operation {
        ManagedEffectOperation::RegisterObservedPortableGeneration => {
            package_absent_with_snapshot(request, snapshot)
        }
        ManagedEffectOperation::InstallPortableGeneration
        | ManagedEffectOperation::UpdatePortableGeneration
        | ManagedEffectOperation::RepairPortableGeneration
        | ManagedEffectOperation::ReconfigurePortableGeneration => {
            let destination = managed_destination(request, recipe)
                .map_err(|_| PackageStagingError::InvalidRelativePath)?;
            verify_managed_destination_parent_identity(&destination, destination_parent_identity)?;
            if recipe.operation == ManagedEffectOperation::RepairPortableGeneration {
                let prior = prior_generation_receipt(request, recipe)?;
                match PackageStager::reconcile_profile_destination_only(
                    Path::new(destination.as_str()),
                    prior,
                    package_staging_profile(request.profile),
                )? {
                    PackageStagingObservation::Matching(_) | PackageStagingObservation::Absent => {
                        return package_absent_with_snapshot(request, snapshot);
                    }
                    PackageStagingObservation::Mismatch(error) => {
                        return Ok(package_pending(&error));
                    }
                    PackageStagingObservation::Unknown(error) => return Err(error),
                }
            }
            let staging_root = match &request.plan {
                super::InstallerEffectPlan::ManagedEnvironmentChange { .. } => {
                    request.installation_root.clone()
                }
                _ => return Err(PackageStagingError::Io),
            };
            let stager = package_stager_for_source(
                &recipe.source_bundle,
                &recipe.source_bundle_identity,
                &staging_root,
                Some(&destination),
                package_staging_profile(request.profile),
            )?;
            if stager.destination_parent_identity() != destination_parent_identity {
                return Err(PackageStagingError::IdentityMismatch);
            }
            package_absent_with_snapshot(request, snapshot)
        }
        ManagedEffectOperation::RemoveOwnedPortableGeneration => {
            let receipt = prior_generation_receipt(request, recipe)?;
            let destination = managed_destination(request, recipe)
                .map_err(|_| PackageStagingError::InvalidRelativePath)?;
            verify_managed_destination_parent_identity(&destination, destination_parent_identity)?;
            match PackageStager::reconcile_profile_destination_only(
                Path::new(destination.as_str()),
                receipt,
                package_staging_profile(request.profile),
            )? {
                PackageStagingObservation::Matching(_) => {
                    package_absent_with_snapshot(request, snapshot)
                }
                PackageStagingObservation::Absent => {
                    Ok(package_pending(&PackageStagingError::IdentityMismatch))
                }
                PackageStagingObservation::Mismatch(error) => Ok(package_pending(&error)),
                PackageStagingObservation::Unknown(error) => Err(error),
            }
        }
    }
}

/// Performs only the recipe's bounded file stage or metadata-registration
/// precondition. The registration itself is committed by the same redb CAS
/// that records `Applied`; this adapter never launches the observed program.
#[allow(
    clippy::too_many_lines,
    reason = "this effect owner revalidates and records one dependent managed operation in its required transaction order"
)]
pub(super) fn execute_managed_change(
    request: &InstallationEffectRequest,
    ownership_key: &[u8],
    destination_parent_identity: Option<FileIdentity>,
) -> PortOutcome<InstallationEffectExecution> {
    let Ok(recipe) = managed_recipe(request) else {
        return PortOutcome::Error(PortError::InvalidRequestMetadata);
    };
    if request.profile != InstallationProfile::PortableDev
        || recipe.require_supported().is_err()
        || request.action != InstallationEffectAction::Apply
        || (managed_operation_requires_destination_parent(recipe.operation)
            && destination_parent_identity.is_none())
    {
        return PortOutcome::Error(PortError::InvalidRequestMetadata);
    }
    match recipe.operation {
        ManagedEffectOperation::RegisterObservedPortableGeneration => {
            let snapshot = match signed_source_snapshot(recipe) {
                Ok(snapshot) => snapshot,
                Err(error) => return PortOutcome::Error(super::package_port_error(&error)),
            };
            if request
                .precondition
                .package_snapshot
                .as_ref()
                .is_none_or(|precondition| precondition != &snapshot)
            {
                return PortOutcome::Unknown(UnknownReason::Indeterminate);
            }
            PortOutcome::Known(InstallationEffectExecution {
                evidence: vec![snapshot.digest],
                create_disposition: None,
                credential_receipt: None,
                staging_receipt: None,
                phase_b_receipt: None,
                service_start_disposition: None,
                service_runtime_lineage: None,
            })
        }
        ManagedEffectOperation::InstallPortableGeneration
        | ManagedEffectOperation::UpdatePortableGeneration
        | ManagedEffectOperation::RepairPortableGeneration
        | ManagedEffectOperation::ReconfigurePortableGeneration => {
            if ownership_key.is_empty() {
                return PortOutcome::Error(PortError::InvalidRequestMetadata);
            }
            let Some(snapshot) = request.precondition.package_snapshot.as_ref() else {
                return PortOutcome::Error(PortError::InvalidRequestMetadata);
            };
            let Ok(destination) = managed_destination(request, recipe) else {
                return PortOutcome::Error(PortError::InvalidRequestMetadata);
            };
            if let Err(error) = verify_managed_destination_parent_identity(
                &destination,
                destination_parent_identity,
            ) {
                return PortOutcome::Error(super::package_port_error(&error));
            }
            let mut repair_preflight = None;
            if recipe.operation == ManagedEffectOperation::RepairPortableGeneration {
                // Repair retires an existing receipt-owned generation before
                // opening the create-only destination stager. Prove the exact
                // source snapshot and construct the original package-stage
                // authorization first, so stale source or invalid binding can
                // never destroy the prior generation.
                let source_stager = match package_stager_for_source(
                    &recipe.source_bundle,
                    &recipe.source_bundle_identity,
                    &request.installation_root,
                    None,
                    package_staging_profile(request.profile),
                ) {
                    Ok(stager) => stager,
                    Err(error) => return PortOutcome::Error(super::package_port_error(&error)),
                };
                let source_observation = match source_stager.source().observe() {
                    Ok(observation) => observation,
                    Err(error) => return PortOutcome::Error(super::package_port_error(&error)),
                };
                if source_stager.source().identity() != snapshot.source_bundle_identity {
                    return PortOutcome::Error(super::package_port_error(
                        &PackageStagingError::IdentityMismatch,
                    ));
                }
                if let Err(error) = validate_observed_against_plan(
                    &source_observation,
                    &recipe.package_manifest,
                    &recipe.expected_files,
                ) {
                    return PortOutcome::Error(super::package_port_error(&error));
                }
                let Ok(generation) =
                    PlatformHandle::new(recipe.package_manifest.generation.clone())
                else {
                    return PortOutcome::Error(PortError::InvalidRequestMetadata);
                };
                let Ok(manifest_digest) =
                    PlatformHandle::new(recipe.package_manifest.canonical_digest())
                else {
                    return PortOutcome::Error(PortError::InvalidRequestMetadata);
                };
                let current_snapshot = match build_package_snapshot(
                    source_stager.source().identity(),
                    generation.clone(),
                    manifest_digest,
                    &source_observation,
                ) {
                    Ok(snapshot) => snapshot,
                    Err(error) => return PortOutcome::Error(super::package_port_error(&error)),
                };
                if &current_snapshot != snapshot {
                    return PortOutcome::Error(super::package_port_error(
                        &PackageStagingError::HashMismatch,
                    ));
                }
                let installation_root_identity = source_stager.installation_root_identity();
                let authorization =
                    match stage_package_authorization_for_bound_package(BoundPackageStagingInputs {
                        request,
                        source_bundle_identity: &recipe.source_bundle_identity,
                        generation: &generation,
                        manifest: &recipe.package_manifest,
                        staging_root: &request.installation_root,
                        destination_root: Some(&destination),
                        installation_root_identity: Some(installation_root_identity),
                        destination_parent_identity,
                    }) {
                        Ok(authorization) => authorization,
                        Err(error) => return PortOutcome::Error(super::package_port_error(&error)),
                    };
                let prior = match prior_generation_receipt(request, recipe) {
                    Ok(receipt) => receipt,
                    Err(error) => return PortOutcome::Error(super::package_port_error(&error)),
                };
                match PackageStager::reconcile_profile_destination_only(
                    Path::new(destination.as_str()),
                    prior,
                    package_staging_profile(request.profile),
                ) {
                    Ok(PackageStagingObservation::Matching(_)) => {
                        if let Err(error) = PackageStager::rollback_profile_destination_only(
                            Path::new(destination.as_str()),
                            prior,
                            package_staging_profile(request.profile),
                        ) {
                            return PortOutcome::Error(super::package_port_error(&error));
                        }
                    }
                    Ok(PackageStagingObservation::Absent) => {}
                    Ok(
                        PackageStagingObservation::Mismatch(error)
                        | PackageStagingObservation::Unknown(error),
                    )
                    | Err(error) => {
                        return PortOutcome::Error(super::package_port_error(&error));
                    }
                }
                repair_preflight = Some((installation_root_identity, authorization));
            }
            let stager = match package_stager_for_source(
                &recipe.source_bundle,
                &recipe.source_bundle_identity,
                &request.installation_root,
                Some(&destination),
                package_staging_profile(request.profile),
            ) {
                Ok(stager) => stager,
                Err(error) => return PortOutcome::Error(super::package_port_error(&error)),
            };
            if stager.source().identity() != snapshot.source_bundle_identity {
                return PortOutcome::Error(super::package_port_error(
                    &PackageStagingError::IdentityMismatch,
                ));
            }
            if stager.destination_parent_identity() != destination_parent_identity {
                return PortOutcome::Error(super::package_port_error(
                    &PackageStagingError::IdentityMismatch,
                ));
            }
            let Ok(generation) = PlatformHandle::new(recipe.package_manifest.generation.clone())
            else {
                return PortOutcome::Error(PortError::InvalidRequestMetadata);
            };
            let authorization = match repair_preflight {
                Some((installation_root_identity, authorization))
                    if installation_root_identity == stager.installation_root_identity() =>
                {
                    authorization
                }
                Some(_) => {
                    return PortOutcome::Error(super::package_port_error(
                        &PackageStagingError::IdentityMismatch,
                    ));
                }
                None => {
                    match stage_package_authorization_for_bound_package(BoundPackageStagingInputs {
                        request,
                        source_bundle_identity: &recipe.source_bundle_identity,
                        generation: &generation,
                        manifest: &recipe.package_manifest,
                        staging_root: &request.installation_root,
                        destination_root: Some(&destination),
                        installation_root_identity: Some(stager.installation_root_identity()),
                        destination_parent_identity,
                    }) {
                        Ok(authorization) => authorization,
                        Err(error) => return PortOutcome::Error(super::package_port_error(&error)),
                    }
                }
            };
            match stager.stage_authorized(&recipe.package_manifest, &authorization, ownership_key) {
                Ok(receipt) => {
                    if validate_staging_receipt_for_plan(&request.plan, &receipt).is_err()
                        || validate_staging_receipt_for_observation(snapshot, &receipt).is_err()
                    {
                        return PortOutcome::Error(super::package_port_error(
                            &PackageStagingError::IdentityMismatch,
                        ));
                    }
                    PortOutcome::Known(InstallationEffectExecution {
                        evidence: vec![
                            PlatformHandle::new(receipt.digest())
                                .unwrap_or_else(|_| unreachable!()),
                        ],
                        create_disposition: None,
                        credential_receipt: None,
                        staging_receipt: Some(receipt),
                        phase_b_receipt: None,
                        service_start_disposition: None,
                        service_runtime_lineage: None,
                    })
                }
                Err(error) => PortOutcome::Error(super::package_port_error(&error)),
            }
        }
        ManagedEffectOperation::RemoveOwnedPortableGeneration => {
            let Ok(prior) = prior_generation_receipt(request, recipe) else {
                return PortOutcome::Error(PortError::InvalidRequestMetadata);
            };
            let Ok(destination) = managed_destination(request, recipe) else {
                return PortOutcome::Error(PortError::InvalidRequestMetadata);
            };
            if let Err(error) = verify_managed_destination_parent_identity(
                &destination,
                destination_parent_identity,
            ) {
                return PortOutcome::Error(super::package_port_error(&error));
            }
            match PackageStager::rollback_profile_destination_only(
                Path::new(destination.as_str()),
                prior,
                package_staging_profile(request.profile),
            ) {
                Ok(()) => PortOutcome::Known(InstallationEffectExecution {
                    evidence: vec![
                        PlatformHandle::new(prior.digest()).unwrap_or_else(|_| unreachable!()),
                    ],
                    create_disposition: None,
                    credential_receipt: None,
                    staging_receipt: None,
                    phase_b_receipt: None,
                    service_start_disposition: None,
                    service_runtime_lineage: None,
                }),
                Err(error) => package_staging_outcome(&error),
            }
        }
    }
}

/// Reconciles a committed managed operation from its original package marker
/// and exact source readback. A missing marker or conflicting tree stays
/// indeterminate; it never becomes a second stage attempt.
#[allow(
    clippy::too_many_lines,
    reason = "all provider readback states must reconcile under the original managed effect identity"
)]
pub(super) fn reconcile_managed_change(
    request: &InstallationEffectRequest,
    ownership_key: &[u8],
    destination_parent_identity: Option<FileIdentity>,
) -> Result<InstallationEffectObservation, PackageStagingError> {
    let recipe = managed_recipe(request)?;
    if managed_operation_requires_destination_parent(recipe.operation)
        && destination_parent_identity.is_none()
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let snapshot = signed_source_snapshot(recipe)?;
    if request
        .precondition
        .package_snapshot
        .as_ref()
        .is_none_or(|precondition| precondition != &snapshot)
    {
        return Err(PackageStagingError::HashMismatch);
    }
    match recipe.operation {
        ManagedEffectOperation::RegisterObservedPortableGeneration => {
            managed_matching_source(request, snapshot)
                .map_err(|_| PackageStagingError::IdentityMismatch)
        }
        ManagedEffectOperation::InstallPortableGeneration
        | ManagedEffectOperation::UpdatePortableGeneration
        | ManagedEffectOperation::RepairPortableGeneration
        | ManagedEffectOperation::ReconfigurePortableGeneration => {
            let destination = managed_destination(request, recipe)
                .map_err(|_| PackageStagingError::InvalidRelativePath)?;
            verify_managed_destination_parent_identity(&destination, destination_parent_identity)?;
            let observation = if let Some(receipt) = request.staging_receipt.as_ref() {
                validate_staging_receipt_for_plan(&request.plan, receipt)
                    .map_err(|_| PackageStagingError::IdentityMismatch)?;
                validate_staging_receipt_for_observation(&snapshot, receipt)
                    .map_err(|_| PackageStagingError::IdentityMismatch)?;
                let observation = PackageStager::reconcile_profile_destination_only(
                    Path::new(destination.as_str()),
                    receipt,
                    package_staging_profile(request.profile),
                )?;
                if recipe.operation == ManagedEffectOperation::RepairPortableGeneration
                    && matches!(observation, PackageStagingObservation::Absent)
                {
                    // A durable new-generation receipt means the original
                    // package effect already returned. Its later absence is
                    // a lost owned object, not the narrow crash gap between
                    // retiring the prior generation and receiving a new
                    // receipt; never overwrite that receipt with a re-stage.
                    PackageStagingObservation::Mismatch(PackageStagingError::IdentityMismatch)
                } else {
                    observation
                }
            } else if recipe.operation == ManagedEffectOperation::RepairPortableGeneration {
                let generation = PlatformHandle::new(recipe.package_manifest.generation.clone())
                    .map_err(|_| PackageStagingError::IdentityMismatch)?;
                let authorization =
                    stage_package_authorization_for_bound_package(BoundPackageStagingInputs {
                        request,
                        source_bundle_identity: &recipe.source_bundle_identity,
                        generation: &generation,
                        manifest: &recipe.package_manifest,
                        staging_root: &request.installation_root,
                        destination_root: Some(&destination),
                        installation_root_identity: None,
                        destination_parent_identity,
                    })?;
                let candidate_observation =
                    PackageStager::reconcile_prepared_profile_destination_only(
                        Path::new(request.installation_root.as_str()),
                        &recipe.package_manifest,
                        &authorization,
                        ownership_key,
                        package_staging_profile(request.profile),
                    )?;
                let candidate_absence = match candidate_observation {
                    PackageStagingObservation::Matching(receipt) => {
                        return package_matching_observation(request, receipt)
                            .map_err(|_| PackageStagingError::IdentityMismatch);
                    }
                    PackageStagingObservation::Mismatch(error) => {
                        return Ok(package_pending(&error));
                    }
                    PackageStagingObservation::Unknown(error) => return Err(error),
                    PackageStagingObservation::Absent => PackageStagingObservation::Absent,
                };
                let prior = prior_generation_receipt(request, recipe)?;
                let prior_observation = PackageStager::reconcile_profile_destination_only(
                    Path::new(destination.as_str()),
                    prior,
                    package_staging_profile(request.profile),
                )?;
                managed_repair_restart_readback(candidate_absence, prior_observation)
            } else if request.ownership_secret.as_ref().is_some_and(|ownership| {
                ownership.create_disposition == InstallationCreateDisposition::Created
                    && ownership.secret_provision_disposition
                        == super::InstallationSecretProvisionDisposition::Created
                    && ownership.lifecycle != super::InstallationSecretLifecycle::Deleted
            }) {
                let generation = PlatformHandle::new(recipe.package_manifest.generation.clone())
                    .map_err(|_| PackageStagingError::IdentityMismatch)?;
                let authorization =
                    stage_package_authorization_for_bound_package(BoundPackageStagingInputs {
                        request,
                        source_bundle_identity: &recipe.source_bundle_identity,
                        generation: &generation,
                        manifest: &recipe.package_manifest,
                        staging_root: &request.installation_root,
                        destination_root: Some(&destination),
                        installation_root_identity: None,
                        destination_parent_identity,
                    })?;
                PackageStager::reconcile_prepared_profile_destination_only(
                    Path::new(request.installation_root.as_str()),
                    &recipe.package_manifest,
                    &authorization,
                    ownership_key,
                    package_staging_profile(request.profile),
                )?
            } else {
                return Err(PackageStagingError::IdentityMismatch);
            };
            match observation {
                PackageStagingObservation::Absent => Ok(InstallationEffectObservation::Absent {
                    observed_precondition: request.precondition.clone(),
                    evidence: vec![snapshot.digest],
                    service_runtime_lineage: None,
                }),
                PackageStagingObservation::Matching(receipt) => {
                    package_matching_observation(request, receipt)
                        .map_err(|_| PackageStagingError::IdentityMismatch)
                }
                PackageStagingObservation::Mismatch(error) => Ok(package_pending(&error)),
                PackageStagingObservation::Unknown(error) => Err(error),
            }
        }
        ManagedEffectOperation::RemoveOwnedPortableGeneration => {
            let prior = prior_generation_receipt(request, recipe)?;
            let destination = managed_destination(request, recipe)
                .map_err(|_| PackageStagingError::InvalidRelativePath)?;
            verify_managed_destination_parent_identity(&destination, destination_parent_identity)?;
            match PackageStager::reconcile_profile_destination_only(
                Path::new(destination.as_str()),
                prior,
                package_staging_profile(request.profile),
            )? {
                PackageStagingObservation::Absent => managed_absence(
                    request,
                    &snapshot,
                    vec![PlatformHandle::new(prior.digest()).unwrap_or_else(|_| unreachable!())],
                )
                .map_err(|_| PackageStagingError::IdentityMismatch),
                PackageStagingObservation::Matching(_) => {
                    Ok(InstallationEffectObservation::Absent {
                        observed_precondition: request.precondition.clone(),
                        evidence: vec![snapshot.digest],
                        service_runtime_lineage: None,
                    })
                }
                PackageStagingObservation::Mismatch(error) => Ok(package_pending(&error)),
                PackageStagingObservation::Unknown(error) => Err(error),
            }
        }
    }
}
