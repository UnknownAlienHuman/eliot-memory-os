//! Same-fence canonical Policy and WorkScope readback for bridge-event privacy.
//!
//! The bridge caller supplies event selectors only. Before any source bytes
//! are retained, this module rereads the two current owner records through the
//! Kernel's retained canonical Store gateway and checks their exact wire
//! identity, fence, revision, digest and WorkScope guard receipt.

use std::collections::BTreeSet;

use eliot_contracts::{PolicyRevision, StateFence, canonical_json_bytes, sha256_hex};
use eliot_kernel_service::KernelStoreGateway;
use eliot_security_contracts::{PolicyFence, PrivacyClass};
use eliot_store_api::{
    CONTRACT_VERSION, OWNER_SNAPSHOT_SCHEMA, RecoveryRecord, RecoveryRecordKey,
    StoreRecoveryRequest,
};
use eliot_workscope::{ScopeBindingDisposition, WorkScopeBindingSnapshot};
use serde::{Deserialize, Serialize};

const BRIDGE_PRIVACY_TERMS_KEY: &str = "bridge.events.privacy_terms";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyOwnerWire {
    state_fence: StateFence,
    revision: u64,
    policy_digest: String,
    snapshot: PolicySnapshotWire,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicySnapshotWire {
    snapshot_id: String,
    machine_id: String,
    scope_id: String,
    revision: PolicyRevision,
    source_completeness: SourceCompletenessWire,
    settings: Vec<PolicySettingWire>,
    policy_owner: PolicyHumanOwnerWire,
    policy_fence: PolicyFence,
    state_fence: StateFence,
    parent_snapshot_id: Option<String>,
    rollback_of: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SourceCompletenessWire {
    Complete,
    Partial,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicySettingWire {
    key: String,
    value_ref: String,
    owner_ref: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PolicyHumanOwnerWire {
    owner_ref: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BridgePrivacyTermsWire {
    pub(crate) schema_version: u16,
    pub(crate) rules: Vec<BridgePrivacyRuleWire>,
}

#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct BridgePrivacyRuleWire {
    pub(crate) source_class: BridgeSourceClassWire,
    pub(crate) workscope_privacy_class: PrivacyClass,
    pub(crate) provider_restriction: BridgeProviderRestrictionWire,
    pub(crate) retention: BridgeRetentionWire,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum BridgeSourceClassWire {
    PublicSummary,
    RedactedSummary,
    RestrictedHandleOnly,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum BridgeProviderRestrictionWire {
    HiddenReasoningExcluded,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum BridgeRetentionWire {
    RawAllowed,
    RedactedOnly,
    Denied,
}

/// Current Policy terms and active binding read together at one Store fence.
#[derive(Clone, Debug)]
pub(crate) struct BridgeEventPolicyOwnerRead {
    pub(crate) policy_owner_digest: String,
    pub(crate) policy_snapshot_digest: String,
    pub(crate) policy_snapshot_id: String,
    pub(crate) policy_revision: u64,
    pub(crate) work_scope_owner_digest: String,
    pub(crate) work_scope_owner_revision: u64,
    pub(crate) scope_ref: String,
    pub(crate) privacy_class: PrivacyClass,
    pub(crate) terms: Option<BridgePrivacyTermsWire>,
}

impl BridgeEventPolicyOwnerRead {
    /// Re-read exact Policy and WorkScope owners through the retained gateway.
    pub(crate) async fn recover(
        gateway: &KernelStoreGateway,
        state_fence: &StateFence,
        expected_scope_ref: &str,
    ) -> Result<Self, String> {
        state_fence.validate().map_err(|error| error.to_string())?;
        if expected_scope_ref.trim().is_empty()
            || expected_scope_ref.chars().any(char::is_control)
        {
            return Err("bridge WorkScope selector is invalid".to_owned());
        }
        let policy_key = RecoveryRecordKey::new("owner", "policy")
            .map_err(|error| error.to_string())?;
        let work_scope_key = RecoveryRecordKey::new("owner", "work_scope")
            .map_err(|error| error.to_string())?;
        let expected_keys = BTreeSet::from([policy_key.clone(), work_scope_key.clone()]);
        let recovery = gateway
            .recovery(StoreRecoveryRequest {
                contract_version: CONTRACT_VERSION,
                state_fence: state_fence.clone(),
                records: vec![policy_key, work_scope_key],
                include_receipts: false,
                include_jobs: false,
            })
            .await?;
        recovery.validate().map_err(|error| error.to_string())?;
        let observed_keys = recovery
            .owner_records
            .iter()
            .map(RecoveryRecord::record_key)
            .collect::<BTreeSet<_>>();
        if recovery.state_fence != *state_fence
            || recovery.canonical_scope.state_fence != *state_fence
            || observed_keys != expected_keys
            || recovery.owner_records.len() != 2
            || !recovery.job_records.is_empty()
            || !recovery.receipts.is_empty()
        {
            return Err("Policy/WorkScope owner readback is not the exact requested set".to_owned());
        }
        let policy_record = recovery
            .owner_records
            .iter()
            .find(|record| record.namespace == "owner" && record.key == "policy")
            .ok_or_else(|| "canonical Policy owner is unavailable".to_owned())?;
        let scope_record = recovery
            .owner_records
            .iter()
            .find(|record| record.namespace == "owner" && record.key == "work_scope")
            .ok_or_else(|| "canonical WorkScope owner is unavailable".to_owned())?;
        validate_owner_record(policy_record, state_fence)?;
        validate_owner_record(scope_record, state_fence)?;

        let policy: PolicyOwnerWire = serde_json::from_slice(&policy_record.payload)
            .map_err(|_| "canonical Policy owner payload is invalid".to_owned())?;
        if canonical_json_bytes(&policy).map_err(|error| error.to_string())? != policy_record.payload
            || policy.state_fence != *state_fence
            || policy.revision != policy_record.revision
            || policy.revision == 0
            || policy.snapshot.state_fence != *state_fence
            || policy.snapshot.revision.value() != policy.revision
            || state_fence.policy_revision.map(PolicyRevision::value) != Some(policy.revision)
            || policy.snapshot.source_completeness != SourceCompletenessWire::Complete
            || policy.snapshot.machine_id.trim().is_empty()
            || policy.snapshot.scope_id != expected_scope_ref
            || policy.snapshot.policy_fence.state_fence != *state_fence
            || policy.snapshot.policy_fence.policy_snapshot_id != policy.snapshot.snapshot_id
            || policy.snapshot.policy_owner.owner_ref.trim().is_empty()
            || policy.policy_digest != digest_json(&policy.snapshot)?
        {
            return Err("canonical Policy snapshot identity, applicability, revision or digest mismatch".to_owned());
        }
        let matching_settings = policy
            .snapshot
            .settings
            .iter()
            .filter(|setting| setting.key == BRIDGE_PRIVACY_TERMS_KEY)
            .collect::<Vec<_>>();
        let terms = if matching_settings.len() == 1
            && matching_settings[0].owner_ref == policy.snapshot.policy_owner.owner_ref
        {
            matching_settings[0]
                .value_ref
                .strip_prefix("literal:")
                .and_then(|literal| {
                    serde_json::from_str::<BridgePrivacyTermsWire>(literal)
                        .ok()
                        .filter(|terms| {
                            serde_json::to_string(terms).ok().as_deref() == Some(literal)
                                && validate_terms(terms).is_ok()
                        })
                })
        } else {
            None
        };

        let work_scope: WorkScopeBindingSnapshot = serde_json::from_slice(&scope_record.payload)
            .map_err(|_| "canonical WorkScope owner payload is invalid".to_owned())?;
        work_scope.validate().map_err(|error| error.to_string())?;
        if canonical_json_bytes(&work_scope).map_err(|error| error.to_string())?
            != scope_record.payload
            || work_scope.state_fence != *state_fence
            || work_scope.owner_revision != scope_record.revision
            || work_scope.guard_receipt.disposition != ScopeBindingDisposition::Matched
            || work_scope.binding.scope.scope_ref != expected_scope_ref
        {
            return Err("current WorkScope binding does not match the guarded event scope".to_owned());
        }
        Ok(Self {
            policy_owner_digest: policy_record.value_digest.clone(),
            policy_snapshot_digest: policy.policy_digest,
            policy_snapshot_id: policy.snapshot.snapshot_id,
            policy_revision: policy.revision,
            work_scope_owner_digest: scope_record.value_digest.clone(),
            work_scope_owner_revision: work_scope.owner_revision,
            scope_ref: work_scope.binding.scope.scope_ref,
            privacy_class: work_scope.binding.privacy_class,
            terms,
        })
    }
}

fn validate_owner_record(record: &RecoveryRecord, state_fence: &StateFence) -> Result<(), String> {
    record.validate().map_err(|error| error.to_string())?;
    if record.namespace != "owner"
        || record.state_fence != *state_fence
        || record.schema != OWNER_SNAPSHOT_SCHEMA
        || sha256_hex(&record.payload) != record.value_digest
    {
        return Err("canonical bridge privacy owner record failed identity checks".to_owned());
    }
    let value: serde_json::Value = serde_json::from_slice(&record.payload)
        .map_err(|_| "canonical bridge privacy owner is not JSON".to_owned())?;
    if canonical_json_bytes(&value).map_err(|error| error.to_string())? != record.payload {
        return Err("canonical bridge privacy owner payload is not canonical JSON".to_owned());
    }
    Ok(())
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, String> {
    let bytes = canonical_json_bytes(value).map_err(|error| error.to_string())?;
    Ok(sha256_hex(&bytes))
}

fn validate_terms(terms: &BridgePrivacyTermsWire) -> Result<(), String> {
    let required = [
        BridgeSourceClassWire::PublicSummary,
        BridgeSourceClassWire::RedactedSummary,
        BridgeSourceClassWire::RestrictedHandleOnly,
    ];
    if terms.schema_version != 1
        || terms.rules.len() != required.len()
        || required.iter().any(|class| {
            terms
                .rules
                .iter()
                .filter(|rule| rule.source_class == *class)
                .count()
                != 1
        })
        || terms.rules.iter().any(|rule| {
            rule.retention == BridgeRetentionWire::RawAllowed
                && rule.provider_restriction == BridgeProviderRestrictionWire::Unavailable
        })
    {
        return Err("explicit bridge privacy terms are incomplete or unsafe".to_owned());
    }
    Ok(())
}
