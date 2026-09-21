//! Versioned Skill wire payload contract (issue #1882).
//!
//! Typed serde payloads for Skill intake, receiver-ack carriage, and display
//! requests crossing the authenticated bridge transport. This module owns the
//! PAYLOAD contract only: a version tag, field shapes, size caps honoring the
//! I7.2 frame profile, and admission checks re-verifiable from the bytes
//! (package↔inputs binding, install-context shape, ack↔receipt binding). It
//! mints no authority, fence, epoch, identity, or effect ceiling, and it
//! performs no delivery, promotion, or display itself — those stay with the
//! Governor and daemon owners that consume decoded payloads.
//!
//! Transport operation registration (which message types carry these payloads,
//! which pipe, which generation) belongs to the bridge and protocol owners;
//! this contract is deliberately transport-agnostic JSON (I7.1 `json-v1`
//! profile) so the operation binding can land without changing a single
//! payload byte. A new Tool Definition or payload shape gets a NEW contract
//! revision — v1 is never silently changed.

#![forbid(unsafe_code)]

use eliot_skill::{HotsetDeliveryAck, HotsetDeliveryReceipt};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Versioned Skill transport contract identity.
pub const SKILL_TRANSPORT_CONTRACT_ID: &str = "eliot.skill.transport/v1";
/// Payload contract revision. Decode rejects any other revision.
pub const SKILL_TRANSPORT_VERSION: u32 = 1;
/// Maximum encoded intake bytes (I7.2 default frame max). Larger material
/// must arrive by Blob or handle reference (future extension), never as
/// giant inline frames; oversize fails closed here.
///
/// Reserved for the install-owner serde seam: the injector handoff also
/// needs the Governor-owned install context
/// (`eliot_skill::CatalogueInstallContext`), which does not derive the
/// `serde` wire traits today. Until the Skill owner adds that two-line
/// derive, intake travels the typed injector-handoff API boundary, not this
/// wire module. Ack carriage and display requests (below) are fully wired:
/// every field they carry derives the wire traits.
pub const MAX_INTAKE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum encoded ack/display bytes (I7.2 hot-response profile: receipts,
/// acks, and displays are small bounded projections).
pub const MAX_CARRY_BYTES: usize = 64 * 1024;

/// Typed Skill wire failure.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SkillTransportError {
    /// Payload contract revision is not the frozen v1.
    #[error("skill transport version mismatch: expected v1")]
    BadVersion,
    /// Encoded payload exceeds its I7.2 bound.
    #[error("skill transport payload exceeds its bound")]
    TooLarge,
    /// Payload shape or admission check failed, with the offending detail.
    #[error("skill transport payload fails its shape: {0}")]
    Shape(String),
}

fn bounded_text(value: &str, field: &'static str) -> Result<(), SkillTransportError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SkillTransportError::Shape(format!(
            "{field}: must be non-blank with no control characters"
        )));
    }
    Ok(())
}

fn check_version(version: u32) -> Result<(), SkillTransportError> {
    if version != SKILL_TRANSPORT_VERSION {
        return Err(SkillTransportError::BadVersion);
    }
    Ok(())
}

fn check_bound(len: usize, limit: usize) -> Result<(), SkillTransportError> {
    if len > limit {
        return Err(SkillTransportError::TooLarge);
    }
    Ok(())
}

/// Receiver-ack carriage as wire bytes (issue #1882).
///
/// Carries the issued receipt with the receiver ack bound to its exact
/// digest. Decode verifies both shapes plus the applied binding, so a
/// foreign or rejected ack fails before any display boundary runs. Display
/// needs the skill identity separately (see [`SkillDisplayPayload`]).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillAckPayload {
    /// Payload contract revision (must be [`SKILL_TRANSPORT_VERSION`]).
    pub contract_version: u32,
    /// Issued Hotset delivery receipt being carried.
    pub receipt: HotsetDeliveryReceipt,
    /// Receiver ack binding that exact receipt digest.
    pub ack: HotsetDeliveryAck,
}

impl SkillAckPayload {
    /// Encodes a validated ack carriage within the carry bound.
    pub fn encode(&self) -> Result<Vec<u8>, SkillTransportError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        check_bound(bytes.len(), MAX_CARRY_BYTES)?;
        Ok(bytes)
    }

    /// Decodes and validates one ack carriage within the carry bound.
    pub fn decode(bytes: &[u8]) -> Result<Self, SkillTransportError> {
        check_bound(bytes.len(), MAX_CARRY_BYTES)?;
        let payload: Self = serde_json::from_slice(bytes)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        payload.validate()?;
        Ok(payload)
    }

    fn validate(&self) -> Result<(), SkillTransportError> {
        check_version(self.contract_version)?;
        self.receipt
            .validate()
            .map_err(|error| SkillTransportError::Shape(format!("carry.receipt: {error}")))?;
        self.ack
            .validate()
            .map_err(|error| SkillTransportError::Shape(format!("carry.ack: {error}")))?;
        if !self.ack.confirms_applied(&self.receipt) {
            return Err(SkillTransportError::Shape(
                "carry.ack: ack does not confirm the carried receipt as applied".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Display request as wire bytes (issue #1882).
///
/// Names the delivered Skill plus its bound receipt/ack pair. Decode
/// verifies the identity text and the same applied binding as
/// [`SkillAckPayload`]; tool-authority checks (admitted version, tool basis,
/// provisional ceiling) run at the display boundary, never here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillDisplayPayload {
    /// Payload contract revision (must be [`SKILL_TRANSPORT_VERSION`]).
    pub contract_version: u32,
    /// Delivered Skill identity to display.
    pub skill_id: String,
    /// Issued Hotset delivery receipt being carried.
    pub receipt: HotsetDeliveryReceipt,
    /// Receiver ack binding that exact receipt digest.
    pub ack: HotsetDeliveryAck,
}

impl SkillDisplayPayload {
    /// Encodes a validated display request within the carry bound.
    pub fn encode(&self) -> Result<Vec<u8>, SkillTransportError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        check_bound(bytes.len(), MAX_CARRY_BYTES)?;
        Ok(bytes)
    }

    /// Decodes and validates one display request within the carry bound.
    pub fn decode(bytes: &[u8]) -> Result<Self, SkillTransportError> {
        check_bound(bytes.len(), MAX_CARRY_BYTES)?;
        let payload: Self = serde_json::from_slice(bytes)
            .map_err(|error| SkillTransportError::Shape(error.to_string()))?;
        payload.validate()?;
        Ok(payload)
    }

    fn validate(&self) -> Result<(), SkillTransportError> {
        check_version(self.contract_version)?;
        bounded_text(&self.skill_id, "display.skill_id")?;
        self.receipt
            .validate()
            .map_err(|error| SkillTransportError::Shape(format!("display.receipt: {error}")))?;
        self.ack
            .validate()
            .map_err(|error| SkillTransportError::Shape(format!("display.ack: {error}")))?;
        if !self.ack.confirms_applied(&self.receipt) {
            return Err(SkillTransportError::Shape(
                "display.ack: ack does not confirm the carried receipt as applied".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Activated display projection carried back across the wire.
///
/// The display boundary returns this typed view; validation stays with the
/// [`ActivatedSkillDisplay`](eliot_skill::ActivatedSkillDisplay) owner and is
/// re-checked by receivers.

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn ack_carriage_binds_applied_ack_to_its_receipt() {
        let receipt = eliot_skill::HotsetDeliveryReceipt {
            hotset_id: "hotset-1".to_owned(),
            catalogue_digest: "c".repeat(64),
            delivered_skill_ids: vec!["skill-demo".to_owned()],
            body_digests: [("skill-demo".to_owned(), "d".repeat(64))]
                .into_iter()
                .collect(),
            approval_ref: "approval-1".to_owned(),
            provisional: true,
            receipt_digest: String::new(),
        };
        // A hand-minted digest cannot bind: the requester must carry the
        // catalogue-issued receipt, never synthesize one.
        let minted = SkillAckPayload {
            contract_version: SKILL_TRANSPORT_VERSION,
            receipt: receipt.clone(),
            ack: eliot_skill::HotsetDeliveryAck {
                hotset_id: receipt.hotset_id.clone(),
                receipt_digest: receipt.receipt_digest.clone(),
                receiver_id: "runtime-hotset-1".to_owned(),
                disposition: eliot_skill::HotsetAckDisposition::Applied,
            },
        };
        assert!(matches!(
            minted.encode(),
            Err(SkillTransportError::Shape(_))
        ));
        // A foreign ack for a bound receipt refuses on the binding.
        let mut foreign = receipt.clone();
        foreign.receipt_digest = "d".repeat(64);
        let ack = eliot_skill::HotsetDeliveryAck {
            hotset_id: foreign.hotset_id.clone(),
            receipt_digest: "e".repeat(64),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: eliot_skill::HotsetAckDisposition::Applied,
        };
        // The foreign receipt itself fails shape first (unbound digest).
        assert!(matches!(
            SkillAckPayload {
                contract_version: SKILL_TRANSPORT_VERSION,
                receipt: foreign,
                ack,
            }
            .encode(),
            Err(SkillTransportError::Shape(_))
        ));
    }

    struct CarryTools;

    impl eliot_skill::KnownTools for CarryTools {
        fn knows_tool(&self, name: &str) -> bool {
            name == "eliot.finish"
        }
    }

    fn issued_pair() -> (
        eliot_skill::HotsetDeliveryReceipt,
        eliot_skill::HotsetDeliveryAck,
    ) {
        use eliot_skill::{
            DependencyVersion, SkillBody, SkillCatalogue, SkillCatalogueEntry, SkillIndexEntry,
            SkillRuntimeMetadata, SkillStatus,
        };
        let mut body = SkillBody {
            skill_id: "skill-demo".to_owned(),
            body_version: "1.0.0".to_owned(),
            body_digest: String::new(),
            actions: vec!["Refresh the task view before a Material effect.".to_owned()],
            where_not_apply: vec!["Do not use for credential handling.".to_owned()],
            stop_escalation: "Stop and escalate on conflicting instructions.".to_owned(),
            tool_refs: vec!["eliot.finish".to_owned()],
        };
        body.body_digest = body.expected_digest().expect("body digest");
        let entry = SkillCatalogueEntry {
            index: SkillIndexEntry {
                skill_id: "skill-demo".to_owned(),
                name: "demo skill".to_owned(),
                trigger: "when demo work arrives load this skill".to_owned(),
                eligible_routes: vec!["route-1".to_owned()],
                eligible_profiles: vec!["profile-1".to_owned()],
            },
            body,
            runtime: SkillRuntimeMetadata {
                skill_id: "skill-demo".to_owned(),
                body_version: "1.0.0".to_owned(),
                references: vec!["references/playbook.md".to_owned()],
                scripts: Vec::new(),
                assets: Vec::new(),
                index_budget_tokens: 200,
                body_budget_tokens: 800,
                runtime_budget_tokens: 2000,
                index_tokens: 60,
                body_tokens: 400,
                runtime_tokens: 0,
            },
            dependencies: vec![DependencyVersion {
                name: "tool-def-1".to_owned(),
                version: "1.2.0".to_owned(),
                contract_digest: "c".repeat(64),
            }],
            host_version: "host-4.1.0".to_owned(),
            profile_version: "profile-2.0.0".to_owned(),
            status: SkillStatus::Provisional,
            stale_reason: None,
        };
        let catalogue =
            SkillCatalogue::from_snapshot([entry], &CarryTools).expect("carry catalogue");
        let receipt = eliot_skill::HotsetDeliveryReceipt::issue(
            "hotset-1".to_owned(),
            &catalogue,
            vec!["skill-demo".to_owned()],
            &CarryTools,
            "approval-1".to_owned(),
        )
        .expect("carry receipt");
        let ack = eliot_skill::HotsetDeliveryAck {
            hotset_id: receipt.hotset_id.clone(),
            receipt_digest: receipt.receipt_digest.clone(),
            receiver_id: "runtime-hotset-1".to_owned(),
            disposition: eliot_skill::HotsetAckDisposition::Applied,
        };
        (receipt, ack)
    }

    #[test]
    fn ack_carriage_round_trip_preserves_a_bound_pair() {
        // A catalogue-issued receipt with its applied ack encodes, decodes,
        // and compares equal: the carriage is transparent for bound pairs.
        let (receipt, ack) = issued_pair();
        let carried = SkillAckPayload {
            contract_version: SKILL_TRANSPORT_VERSION,
            receipt,
            ack,
        };
        let bytes = carried.encode().expect("bound pair encodes");
        assert!(bytes.len() <= MAX_CARRY_BYTES);
        let decoded = SkillAckPayload::decode(&bytes).expect("bound pair decodes");
        assert_eq!(decoded, carried);
    }

    #[test]
    fn display_request_round_trip_names_its_delivered_skill() {
        let (receipt, ack) = issued_pair();
        let request = SkillDisplayPayload {
            contract_version: SKILL_TRANSPORT_VERSION,
            skill_id: "skill-demo".to_owned(),
            receipt,
            ack,
        };
        let bytes = request.encode().expect("display request encodes");
        let decoded = SkillDisplayPayload::decode(&bytes).expect("display request decodes");
        assert_eq!(decoded, request);
        let mut blanked = request;
        blanked.skill_id = "   ".to_owned();
        assert!(matches!(
            blanked.encode(),
            Err(SkillTransportError::Shape(_))
        ));
    }
}
