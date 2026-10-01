//! Typed, fail-closed projection of explicit Bridge-event privacy terms from
//! the admitted canonical Policy snapshot.

use super::{Applicability, ApplicabilityContext, ConfigError, ConfigPolicySnapshot};
use eliot_contracts::{PolicyRevision, StateFence};
use eliot_security_contracts::PrivacyClass;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const BRIDGE_EVENT_PRIVACY_TERMS_KEY: &str = "bridge.events.privacy_terms";

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BridgeEventSourceClass {
    PublicSummary,
    RedactedSummary,
    RestrictedHandleOnly,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BridgeProviderRestriction {
    HiddenReasoningExcluded,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BridgeRawRetention {
    RawAllowed,
    RedactedOnly,
    Denied,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeEventPrivacyRule {
    pub source_class: BridgeEventSourceClass,
    pub workscope_privacy_class: PrivacyClass,
    pub provider_restriction: BridgeProviderRestriction,
    pub retention: BridgeRawRetention,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeEventPrivacyTerms {
    pub schema_version: u16,
    pub rules: Vec<BridgeEventPrivacyRule>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeEventPrivacyProjection {
    pub terms: BridgeEventPrivacyTerms,
    pub policy_owner_ref: String,
    pub policy_snapshot_id: String,
    pub policy_revision: PolicyRevision,
    pub state_fence: StateFence,
    pub canonical_snapshot_digest: String,
}

impl BridgeEventPrivacyTerms {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let required = [
            BridgeEventSourceClass::PublicSummary,
            BridgeEventSourceClass::RedactedSummary,
            BridgeEventSourceClass::RestrictedHandleOnly,
        ];
        if self.schema_version != 1
            || self.rules.len() != required.len()
            || required.iter().any(|class| {
                self.rules.iter().filter(|rule| rule.source_class == *class).count() != 1
            })
        {
            return Err(ConfigError::InvalidSnapshot(
                "bridge privacy schema or class coverage",
            ));
        }
        if self.rules.iter().any(|rule| {
            rule.retention == BridgeRawRetention::RawAllowed
                && rule.provider_restriction == BridgeProviderRestriction::Unavailable
        }) {
            return Err(ConfigError::InvalidSnapshot(
                "raw bridge retention lacks provider restriction",
            ));
        }
        Ok(())
    }
}

/// Resolves only canonical literal terms from the exact applicable snapshot.
/// Opaque references require an owner resolver and never act as permission.
pub fn project_bridge_event_privacy(
    snapshot: &ConfigPolicySnapshot,
    context: &ApplicabilityContext,
    canonical_snapshot_digest: &str,
) -> Result<BridgeEventPrivacyProjection, ConfigError> {
    let applicability = snapshot.applicability(context)?;
    if applicability.outcome != Applicability::Applicable
        || snapshot.state_fence.policy_revision != Some(snapshot.revision)
        || context.active_revision != snapshot.revision
        || context.state_fence != snapshot.state_fence
        || canonical_snapshot_digest.len() != 64
        || !canonical_snapshot_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(ConfigError::InvalidSnapshot(
            "bridge privacy policy fence, revision or applicability mismatch",
        ));
    }
    let setting = snapshot
        .settings
        .iter()
        .find(|setting| setting.key == BRIDGE_EVENT_PRIVACY_TERMS_KEY)
        .ok_or(ConfigError::InvalidSnapshot("bridge privacy terms missing"))?;
    if setting.owner_ref != snapshot.policy_owner.owner_ref {
        return Err(ConfigError::InvalidSnapshot(
            "bridge privacy setting has a foreign owner",
        ));
    }
    let literal = setting
        .value_ref
        .strip_prefix("literal:")
        .ok_or(ConfigError::InvalidSnapshot("bridge privacy terms are opaque"))?;
    let terms: BridgeEventPrivacyTerms = serde_json::from_str(literal)
        .map_err(|_| ConfigError::InvalidSnapshot("bridge privacy terms malformed"))?;
    if serde_json::to_string(&terms)
        .map_err(|_| ConfigError::InvalidSnapshot("bridge privacy terms malformed"))?
        != literal
    {
        return Err(ConfigError::InvalidSnapshot(
            "bridge privacy terms are not canonical",
        ));
    }
    terms.validate()?;
    Ok(BridgeEventPrivacyProjection {
        terms,
        policy_owner_ref: setting.owner_ref.clone(),
        policy_snapshot_id: snapshot.snapshot_id.clone(),
        policy_revision: snapshot.revision,
        state_fence: snapshot.state_fence.clone(),
        canonical_snapshot_digest: canonical_snapshot_digest.to_ascii_lowercase(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, reason = "issue 1935 owner projection fixtures")]
mod issue_1935_tests {
    use super::*;
    use crate::{HumanOwner, Setting, SourceCompleteness};
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_security_contracts::PolicyFence;
    use std::num::NonZeroU64;

    fn fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440020")
                .expect("lineage"),
            NonZeroU64::new(1).expect("nonzero sequence"),
        )
        .expect("epoch");
        let mut fence = StateFence::new(epoch, ResourceGeneration::genesis());
        fence.policy_revision = Some(PolicyRevision::genesis());
        fence
    }

    fn terms() -> BridgeEventPrivacyTerms {
        BridgeEventPrivacyTerms {
            schema_version: 1,
            rules: vec![
                BridgeEventPrivacyRule {
                    source_class: BridgeEventSourceClass::PublicSummary,
                    workscope_privacy_class: PrivacyClass::Public,
                    provider_restriction: BridgeProviderRestriction::Unavailable,
                    retention: BridgeRawRetention::RedactedOnly,
                },
                BridgeEventPrivacyRule {
                    source_class: BridgeEventSourceClass::RedactedSummary,
                    workscope_privacy_class: PrivacyClass::Private,
                    provider_restriction: BridgeProviderRestriction::Unavailable,
                    retention: BridgeRawRetention::RedactedOnly,
                },
                BridgeEventPrivacyRule {
                    source_class: BridgeEventSourceClass::RestrictedHandleOnly,
                    workscope_privacy_class: PrivacyClass::Secret,
                    provider_restriction: BridgeProviderRestriction::HiddenReasoningExcluded,
                    retention: BridgeRawRetention::RawAllowed,
                },
            ],
        }
    }

    fn snapshot(value: Option<String>) -> ConfigPolicySnapshot {
        let fence = fence();
        ConfigPolicySnapshot {
            snapshot_id: "policy-1935".to_owned(),
            machine_id: "machine-1935".to_owned(),
            scope_id: "scope-1935".to_owned(),
            revision: PolicyRevision::genesis(),
            source_completeness: SourceCompleteness::Complete,
            settings: value
                .into_iter()
                .map(|value_ref| Setting {
                    key: BRIDGE_EVENT_PRIVACY_TERMS_KEY.to_owned(),
                    value_ref,
                    owner_ref: "human-owner".to_owned(),
                })
                .collect(),
            policy_owner: HumanOwner {
                owner_ref: "human-owner".to_owned(),
            },
            policy_fence: PolicyFence {
                policy_snapshot_id: "policy-1935".to_owned(),
                state_fence: fence.clone(),
            },
            state_fence: fence,
            parent_snapshot_id: None,
            rollback_of: None,
        }
    }

    fn context() -> ApplicabilityContext {
        ApplicabilityContext {
            machine_id: "machine-1935".to_owned(),
            scope_id: Some("scope-1935".to_owned()),
            state_fence: fence(),
            active_revision: PolicyRevision::genesis(),
        }
    }

    #[test]
    fn issue_1935_current_explicit_terms_project_with_owner_readback() {
        let raw = serde_json::to_string(&terms()).expect("terms JSON");
        let projection = project_bridge_event_privacy(
            &snapshot(Some(format!("literal:{raw}"))),
            &context(),
            &"a".repeat(64),
        )
        .expect("explicit current policy projection");
        assert_eq!(projection.terms, terms());
        assert_eq!(projection.policy_owner_ref, "human-owner");
        assert_eq!(projection.policy_revision, PolicyRevision::genesis());
        assert_eq!(projection.state_fence, fence());
    }

    #[test]
    fn issue_1935_absent_or_opaque_terms_refuse() {
        assert_eq!(
            project_bridge_event_privacy(&snapshot(None), &context(), &"a".repeat(64)),
            Err(ConfigError::InvalidSnapshot("bridge privacy terms missing"))
        );
        assert_eq!(
            project_bridge_event_privacy(
                &snapshot(Some("ref:terms".to_owned())),
                &context(),
                &"a".repeat(64),
            ),
            Err(ConfigError::InvalidSnapshot("bridge privacy terms are opaque"))
        );
    }

    #[test]
    fn issue_1935_raw_terms_without_provider_evidence_refuse() {
        let mut invalid = terms();
        invalid.rules[2].provider_restriction = BridgeProviderRestriction::Unavailable;
        assert_eq!(
            invalid.validate(),
            Err(ConfigError::InvalidSnapshot(
                "raw bridge retention lacks provider restriction"
            ))
        );
    }
}
