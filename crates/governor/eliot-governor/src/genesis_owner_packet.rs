//! Versioned closed exact Governor-owned genesis snapshot packet and validation only.
//! Architecture: A4.3 A12.3 A13.2 A13.6 ARCH-AUTH-01 ARCH-SEC-02 ARCH-RES-03
//! Implementation: I1.8 I2.2 I2.23 P.3 I14.21 I14.26
//! Ownership: versioned closed exact Governor-owned genesis snapshot packet and validation only.
//! Forbidden: Store SDK/types, Kernel Governor dependency, defaults/synthesized owners,
//! canonical Store write authority, transport/session authority, and semantic reconstruction
//! outside Governor.

use super::{
    AuthorityOwnerSnapshot, BudgetOwnerSnapshot, BudgetOwnerState, CanonicalAdmissionSnapshot,
    CompositionError, ConfigOwnerSnapshot, EmptyOwnerSnapshot, MAX_OWNER_SNAPSHOT_BYTES,
    OWNER_SNAPSHOT_SCHEMA, ProblemOwnerSnapshot, ReadOwnerSnapshot, RecoveryOwner,
};
use eliot_authority::{EffectAuthorizer, GrantGraph};
use eliot_contracts::{OperationId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_coordination::CoordinationOwner;
use eliot_module_registry::ModuleCatalog;
use eliot_observation::ObservationJournalEntry;
use eliot_session::SessionLifecycleSnapshot;
use eliot_skill::SkillLifecycleView;
use eliot_task::TaskLifecycleSnapshot;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
pub const GOVERNOR_GENESIS_PACKET_SCHEMA: &str = "eliot.governor.genesis-packet.v1";
pub const GOVERNOR_GENESIS_PACKET_VERSION: u16 = 1;
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GovernorGenesisOwnerRecord {
    pub owner: RecoveryOwner,
    pub revision: u64,
    pub schema: String,
    pub payload: Vec<u8>,
    pub value_digest: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GovernorGenesisPacket {
    pub schema: String,
    pub version: u16,
    pub state_fence: StateFence,
    pub protected_snapshot_digest: String,
    pub operation_id: OperationId,
    pub owner_records: Vec<GovernorGenesisOwnerRecord>,
}
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
fn genesis_operation_id(state_fence: &StateFence) -> Result<OperationId, CompositionError> {
    OperationId::new(format!(
        "eliotd:governor-genesis:{}:{}",
        state_fence.authority_epoch.value(),
        state_fence.resource_generation.value()
    ))
    .map_err(|e| CompositionError::Recovery(e.to_string()))
}
impl GovernorGenesisOwnerRecord {
    fn validate(&self, expected_fence: &StateFence) -> Result<(), CompositionError> {
        if self.revision == 0 {
            return Err(CompositionError::Recovery(
                "genesis owner record has zero revision".to_owned(),
            ));
        }
        if self.schema != OWNER_SNAPSHOT_SCHEMA {
            return Err(CompositionError::Recovery(format!(
                "genesis owner {} has invalid schema",
                self.owner.as_str()
            )));
        }
        if self.payload.is_empty() || self.payload.len() > MAX_OWNER_SNAPSHOT_BYTES {
            return Err(CompositionError::Recovery(format!(
                "genesis owner {} has invalid payload bounds",
                self.owner.as_str()
            )));
        }
        if !is_sha256(&self.value_digest) || sha256_hex(&self.payload) != self.value_digest {
            return Err(CompositionError::Recovery(format!(
                "genesis owner {} has invalid value digest",
                self.owner.as_str()
            )));
        }
        let value: serde_json::Value = serde_json::from_slice(&self.payload).map_err(|e| {
            CompositionError::Recovery(format!(
                "genesis owner {} payload schema rejected: {e}",
                self.owner.as_str()
            ))
        })?;
        let canonical = canonical_json_bytes(&value).map_err(|e| {
            CompositionError::Recovery(format!(
                "genesis owner {} payload could not be canonicalized: {e}",
                self.owner.as_str()
            ))
        })?;
        if canonical != self.payload {
            return Err(CompositionError::Recovery(format!(
                "genesis owner {} payload is not canonical JSON",
                self.owner.as_str()
            )));
        }
        if let Some(fence_value) = value.get("state_fence") {
            let fence: StateFence = serde_json::from_value(fence_value.clone()).map_err(|e| {
                CompositionError::Recovery(format!(
                    "genesis owner {} fence decode failed: {e}",
                    self.owner.as_str()
                ))
            })?;
            if fence != *expected_fence {
                return Err(CompositionError::Recovery(format!(
                    "genesis owner {} has stale state fence",
                    self.owner.as_str()
                )));
            }
        }
        Ok(())
    }
}
impl GovernorGenesisPacket {
    pub fn new(
        state_fence: StateFence,
        protected_snapshot_digest: String,
        operation_id: OperationId,
        owner_records: Vec<GovernorGenesisOwnerRecord>,
    ) -> Result<Self, CompositionError> {
        let packet = Self {
            schema: GOVERNOR_GENESIS_PACKET_SCHEMA.to_owned(),
            version: GOVERNOR_GENESIS_PACKET_VERSION,
            state_fence,
            protected_snapshot_digest,
            operation_id,
            owner_records,
        };
        packet.validate(
            &packet.state_fence.clone(),
            &packet.protected_snapshot_digest.clone(),
        )?;
        Ok(packet)
    }
    pub fn genesis(
        state_fence: &StateFence,
        protected_snapshot_digest: &str,
    ) -> Result<Self, CompositionError> {
        state_fence
            .validate()
            .map_err(|e| CompositionError::Recovery(e.to_string()))?;
        if !is_sha256(protected_snapshot_digest) {
            return Err(CompositionError::Recovery(
                "protected_snapshot_digest must be a lowercase SHA-256 digest".to_owned(),
            ));
        }
        let operation_id = genesis_operation_id(state_fence)?;
        let mut owner_records = Vec::with_capacity(RecoveryOwner::ALL.len());
        for owner in RecoveryOwner::ALL {
            let (payload, revision) =
                genesis_payload(owner, state_fence, protected_snapshot_digest)?;
            let value_digest = sha256_hex(&payload);
            owner_records.push(GovernorGenesisOwnerRecord {
                owner,
                revision,
                schema: OWNER_SNAPSHOT_SCHEMA.to_owned(),
                payload,
                value_digest,
            });
        }
        Self::new(
            state_fence.clone(),
            protected_snapshot_digest.to_owned(),
            operation_id,
            owner_records,
        )
    }
    pub fn validate(
        &self,
        expected_fence: &StateFence,
        expected_digest: &str,
    ) -> Result<(), CompositionError> {
        self.state_fence
            .validate()
            .map_err(|e| CompositionError::Recovery(e.to_string()))?;
        if self.schema != GOVERNOR_GENESIS_PACKET_SCHEMA
            || self.version != GOVERNOR_GENESIS_PACKET_VERSION
        {
            return Err(CompositionError::Recovery(
                "genesis packet has invalid schema or version".to_owned(),
            ));
        }
        if &self.state_fence != expected_fence
            || self.protected_snapshot_digest != expected_digest
            || !is_sha256(&self.protected_snapshot_digest)
        {
            return Err(CompositionError::Recovery(
                "genesis packet is not bound to the active fence and protected snapshot".to_owned(),
            ));
        }
        let expected_op = genesis_operation_id(expected_fence)?;
        if self.operation_id != expected_op {
            return Err(CompositionError::Recovery(
                "genesis packet has invalid operation identity".to_owned(),
            ));
        }
        if self.owner_records.len() != RecoveryOwner::ALL.len() {
            return Err(CompositionError::Recovery(
                "genesis packet does not contain every owner record".to_owned(),
            ));
        }
        let mut seen = BTreeSet::new();
        for (idx, record) in self.owner_records.iter().enumerate() {
            let expected_owner = RecoveryOwner::ALL[idx];
            if record.owner != expected_owner {
                return Err(CompositionError::Recovery(format!(
                    "genesis packet owner order mismatch at index {idx}: expected {}, observed {}",
                    expected_owner.as_str(),
                    record.owner.as_str()
                )));
            }
            if !seen.insert(record.owner) {
                return Err(CompositionError::Recovery(format!(
                    "genesis packet has duplicate owner {}",
                    record.owner.as_str()
                )));
            }
            if record.revision == 0 {
                return Err(CompositionError::Recovery(format!(
                    "genesis owner {} has zero revision",
                    record.owner.as_str()
                )));
            }
            let (expected_payload, expected_revision) =
                genesis_payload(expected_owner, expected_fence, expected_digest)?;
            if record.schema != OWNER_SNAPSHOT_SCHEMA {
                return Err(CompositionError::Recovery(format!(
                    "genesis owner {} has invalid schema",
                    record.owner.as_str()
                )));
            }
            if record.revision != expected_revision {
                return Err(CompositionError::Recovery(format!(
                    "genesis owner {} has invalid revision",
                    record.owner.as_str()
                )));
            }
            if record.payload != expected_payload {
                return Err(CompositionError::Recovery(format!(
                    "genesis owner {} payload is not the exact canonical all-absent genesis payload",
                    record.owner.as_str()
                )));
            }
            let expected_digest_calc = sha256_hex(&expected_payload);
            if record.value_digest != expected_digest_calc {
                return Err(CompositionError::Recovery(format!(
                    "genesis owner {} has invalid value digest",
                    record.owner.as_str()
                )));
            }
            record.validate(expected_fence)?;
        }
        let observed: BTreeSet<RecoveryOwner> =
            self.owner_records.iter().map(|r| r.owner).collect();
        let expected: BTreeSet<RecoveryOwner> = RecoveryOwner::ALL.into_iter().collect();
        if observed != expected {
            return Err(CompositionError::Recovery(
                "genesis packet does not contain exactly one record per owner".to_owned(),
            ));
        }
        Ok(())
    }
}
fn genesis_payload(
    owner: RecoveryOwner,
    state_fence: &StateFence,
    protected_snapshot_digest: &str,
) -> Result<(Vec<u8>, u64), CompositionError> {
    let revision = 1u64;
    let value = match owner {
        RecoveryOwner::WorkScope | RecoveryOwner::Maintenance => {
            serde_json::to_value(EmptyOwnerSnapshot {
                state_fence: state_fence.clone(),
                revision,
            })
            .map_err(|e| CompositionError::Recovery(e.to_string()))?
        }
        RecoveryOwner::Canonical => serde_json::to_value(CanonicalAdmissionSnapshot {
            state_fence: state_fence.clone(),
            owner_revision: revision,
            current_plan: None,
        })
        .map_err(|e| CompositionError::Recovery(e.to_string()))?,
        RecoveryOwner::Task => serde_json::to_value(TaskLifecycleSnapshot {
            next_sequence: 1,
            tasks: BTreeMap::new(),
            events: Vec::new(),
        })
        .map_err(|e| CompositionError::Recovery(e.to_string()))?,
        RecoveryOwner::Session => serde_json::to_value(SessionLifecycleSnapshot {
            next_sequence: 1,
            sessions: BTreeMap::new(),
            events: Vec::new(),
        })
        .map_err(|e| CompositionError::Recovery(e.to_string()))?,
        RecoveryOwner::Authority => {
            let grant_graph = GrantGraph::from_grants(std::iter::empty(), 1)
                .and_then(|g| g.recovery_snapshot())
                .map_err(|e| CompositionError::Recovery(e.to_string()))?;
            let effect_authorizer = EffectAuthorizer::default()
                .snapshot()
                .map_err(|e| CompositionError::Recovery(e.to_string()))?;
            serde_json::to_value(
                AuthorityOwnerSnapshot::new(state_fence.clone(), grant_graph, effect_authorizer)
                    .map_err(|e| CompositionError::Recovery(e.to_string()))?,
            )
            .map_err(|e| CompositionError::Recovery(e.to_string()))?
        }
        RecoveryOwner::Budget => serde_json::to_value(BudgetOwnerSnapshot {
            schema: "eliot.governor.budget-owner.v1".to_owned(),
            version: 1,
            state_fence: state_fence.clone(),
            revision,
            state: BudgetOwnerState::Unconfigured,
        })
        .map_err(|e| CompositionError::Recovery(e.to_string()))?,
        RecoveryOwner::Config => serde_json::to_value(ConfigOwnerSnapshot {
            state_fence: state_fence.clone(),
            revision,
            config_digest: protected_snapshot_digest.to_owned(),
        })
        .map_err(|e| CompositionError::Recovery(e.to_string()))?,
        RecoveryOwner::Coordination => serde_json::to_value(CoordinationOwner::new())
            .map_err(|e| CompositionError::Recovery(e.to_string()))?,
        RecoveryOwner::Finish => {
            serde_json::to_value(Vec::<eliot_finish::FinishDecisionReceipt>::new())
                .map_err(|e| CompositionError::Recovery(e.to_string()))?
        }
        RecoveryOwner::Problem => serde_json::to_value(ProblemOwnerSnapshot {
            state_fence: state_fence.clone(),
            revisions: BTreeMap::new(),
        })
        .map_err(|e| CompositionError::Recovery(e.to_string()))?,
        RecoveryOwner::Observation => serde_json::to_value(Vec::<ObservationJournalEntry>::new())
            .map_err(|e| CompositionError::Recovery(e.to_string()))?,
        RecoveryOwner::Read => serde_json::to_value(ReadOwnerSnapshot {
            state_fence: state_fence.clone(),
            revision,
        })
        .map_err(|e| CompositionError::Recovery(e.to_string()))?,
        RecoveryOwner::Skill => serde_json::to_value(Vec::<SkillLifecycleView>::new())
            .map_err(|e| CompositionError::Recovery(e.to_string()))?,
        RecoveryOwner::ModuleRegistry => {
            let snap = ModuleCatalog::new(state_fence.clone())
                .map_err(|e| CompositionError::Recovery(e.to_string()))?
                .snapshot()
                .map_err(|e| CompositionError::Recovery(e.to_string()))?;
            serde_json::to_value(snap).map_err(|e| CompositionError::Recovery(e.to_string()))?
        }
        RecoveryOwner::ChangeMonitor => {
            serde_json::to_value(eliot_change_monitor::ChangeMonitorSnapshot::default())
                .map_err(|e| CompositionError::Recovery(e.to_string()))?
        }
    };
    let bytes =
        canonical_json_bytes(&value).map_err(|e| CompositionError::Recovery(e.to_string()))?;
    Ok((bytes, revision))
}
