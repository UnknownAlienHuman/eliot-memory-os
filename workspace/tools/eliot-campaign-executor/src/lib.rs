//! Development-only D-02 campaign control.
//!
//! This package owns scheduling and recovery evidence only.  It deliberately
//! has no product evaluator, oracle, threshold, or finish authority.  A
//! caller supplies the already materialized seed, receipt, and event suffix;
//! adoption verifies those immutable bytes and never repairs them in place.

use anyhow::{Context, Result, ensure};
use blake3::Hasher as Blake3Hasher;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

pub mod control;
pub mod coordination;

pub const PLAN_ID: &str = "D-02:plan-v4";
pub const PRIMARY_OPENCODE_MODEL: &str = "opencode-go/deepseek-v4-flash";
pub const PRIMARY_OPENCODE_PROVIDER_ID: &str = "opencode-go";
pub const PRIMARY_OPENCODE_MODEL_ID: &str = "deepseek-v4-flash";
pub const BOOTSTRAP_RECEIPT_SHA256: &str =
    "4d38d4089245a360ce36b6060e0fe1f487affda8aac68206b493c21c6b2fdf18";
pub const CHECKPOINT0_SHA256: &str =
    "a6e1e1a532fd31b839952a9ec5bb13ddb3ace85f526530aefc267d970f5d56d8";
pub const D01_REPORT_SHA256: &str =
    "1734908ea5451bc11f066631dcda61f3f709b8dac081ce9dfb8399c966d1334b";
pub const D01_HANDLE_SHA256: &str =
    "87732fdfc6d04c2ec152a5d5c081b71f2913bf9f2ebf9f3da36364cecbdcd9a5";
pub const CHECKPOINT1_SHA256: &str =
    "022cd30103e830efdb789c58262ad8cc5d1dcd5b1327a575ff052b41bc02e00f";
pub const EVENT9_HEAD_SHA256: &str =
    "b731694168b002ab7311e0c0ba0762fef122b86d303b058a0d242e04d8c65db2";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeRoutePolicy {
    pub model: String,
}

impl OpenCodeRoutePolicy {
    pub fn verify(&self) -> Result<()> {
        ensure!(
            self.model == PRIMARY_OPENCODE_MODEL,
            "OpenCode model differs from the only admitted bootstrap route"
        );
        Ok(())
    }
}

/// Epoch identity is lineage plus monotonic sequence; sequence alone cannot
/// prevent stale-controller resurrection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EpochId {
    pub lineage: Uuid,
    pub sequence: u64,
}

impl EpochId {
    pub fn fresh(sequence: u64) -> Result<Self> {
        ensure!(sequence != 0, "controller epoch sequence must be nonzero");
        Ok(Self {
            lineage: Uuid::new_v4(),
            sequence,
        })
    }
    fn genesis() -> Self {
        Self {
            lineage: Uuid::nil(),
            sequence: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum HashAlgorithm {
    #[default]
    Sha256,
    Blake3,
}

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn blake3(bytes: &[u8]) -> String {
    let mut hasher = Blake3Hasher::new();
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn digest(bytes: &[u8], algorithm: HashAlgorithm) -> String {
    match algorithm {
        HashAlgorithm::Sha256 => sha256(bytes),
        HashAlgorithm::Blake3 => blake3(bytes),
    }
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut ordered = Map::new();
            let mut entries: Vec<_> = object.iter().collect();
            entries.sort_by_key(|(left, _)| *left);
            for (key, child) in entries {
                ordered.insert(key.clone(), canonical(child));
            }
            Value::Object(ordered)
        }
        Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
        scalar => scalar.clone(),
    }
}

#[allow(clippy::manual_unwrap_or_default)]
fn canonical_bytes(value: &Value) -> Vec<u8> {
    match serde_json::to_vec(&canonical(value)) {
        Ok(bytes) => bytes,
        Err(_) => Vec::new(),
    }
}

/// An immutable event in the external campaign ledger.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LedgerEvent {
    #[serde(alias = "campaign_sequence")]
    pub sequence: u64,
    #[serde(alias = "event_kind")]
    pub event_type: String,
    #[serde(default = "legacy_actor")]
    pub actor: String,
    #[serde(default = "EpochId::genesis")]
    pub controller_epoch: EpochId,
    #[serde(default)]
    pub hash_algorithm: HashAlgorithm,
    pub payload: Value,
    #[serde(alias = "previous_segment_sha256")]
    pub previous_segment_hash: String,
    #[serde(alias = "event_sha256")]
    pub event_hash: String,
    #[serde(skip)]
    raw_bytes: Option<Vec<u8>>,
}

fn legacy_actor() -> String {
    "legacy".to_owned()
}

impl LedgerEvent {
    fn unsigned_value(
        sequence: u64,
        event_type: &str,
        actor: &str,
        controller_epoch: &EpochId,
        payload: &Value,
        previous_segment_hash: &str,
    ) -> Value {
        json!({
            "sequence": sequence,
            "event_type": event_type,
            "actor": actor,
            "controller_epoch": controller_epoch,
            "payload": payload,
            "previous_segment_hash": previous_segment_hash,
        })
    }

    fn new(
        sequence: u64,
        event_type: &str,
        actor: &str,
        controller_epoch: &EpochId,
        payload: Value,
        previous_segment_hash: String,
        hash_algorithm: HashAlgorithm,
    ) -> Self {
        let unsigned = Self::unsigned_value(
            sequence,
            event_type,
            actor,
            controller_epoch,
            &payload,
            &previous_segment_hash,
        );
        let event_hash = digest(&canonical_bytes(&unsigned), hash_algorithm);
        Self {
            sequence,
            event_type: event_type.to_owned(),
            actor: actor.to_owned(),
            controller_epoch: controller_epoch.clone(),
            hash_algorithm,
            payload,
            previous_segment_hash,
            event_hash,
            raw_bytes: None,
        }
    }

    fn verify(&self, expected_sequence: u64, previous_hash: &str) -> Result<()> {
        ensure!(
            self.sequence == expected_sequence,
            "campaign event sequence gap: expected {expected_sequence}, got {}",
            self.sequence
        );
        ensure!(
            self.previous_segment_hash == previous_hash,
            "campaign event {} previous hash mismatch",
            self.sequence
        );
        let unsigned = Self::unsigned_value(
            self.sequence,
            &self.event_type,
            &self.actor,
            &self.controller_epoch,
            &self.payload,
            &self.previous_segment_hash,
        );
        let computed = self.raw_bytes.as_deref().map_or_else(
            || digest(&canonical_bytes(&unsigned), self.hash_algorithm),
            |bytes| digest(bytes, HashAlgorithm::Sha256),
        );
        ensure!(
            self.event_hash == computed,
            "campaign event {} hash mismatch",
            self.sequence
        );
        Ok(())
    }

    pub fn from_raw_json(bytes: &[u8]) -> Result<Self> {
        // D-01's frozen event files are legacy flat objects.  They do not
        // contain the current nested `payload` or a self-reported hash; the
        // segment identity is the SHA-256 of the exact immutable file bytes.
        let value: Value = serde_json::from_slice(bytes).context("parse raw campaign event")?;
        let object = value
            .as_object()
            .context("legacy campaign event must be an object")?;
        if object.get("payload").is_some()
            && object.get("event_hash").is_some()
            && object.get("hash_algorithm").and_then(Value::as_str) == Some("Blake3")
        {
            return serde_json::from_slice(bytes).context("parse D-02 campaign event");
        }
        let sequence = object
            .get("sequence")
            .or_else(|| object.get("campaign_sequence"))
            .and_then(Value::as_u64)
            .context("legacy campaign event sequence is missing")?;
        let event_type = object
            .get("event_type")
            .or_else(|| object.get("event_kind"))
            .and_then(Value::as_str)
            .context("legacy campaign event kind is missing")?
            .to_owned();
        let actor = object
            .get("actor")
            .and_then(Value::as_str)
            .unwrap_or("legacy")
            .to_owned();
        let controller_epoch = match object.get("controller_epoch") {
            Some(Value::Object(_)) => serde_json::from_value(object["controller_epoch"].clone())
                .context("parse legacy controller epoch")?,
            Some(Value::Number(number)) => EpochId {
                lineage: Uuid::nil(),
                sequence: number.as_u64().unwrap_or(0),
            },
            _ => EpochId::genesis(),
        };
        let previous_segment_hash = object
            .get("previous_segment_hash")
            .or_else(|| object.get("previous_segment_sha256"))
            .and_then(Value::as_str)
            .context("legacy campaign previous segment hash is missing")?
            .to_owned();
        let payload = object.get("payload").cloned().unwrap_or_else(|| {
            let mut flat = object.clone();
            for key in [
                "sequence",
                "campaign_sequence",
                "event_type",
                "event_kind",
                "actor",
                "controller_epoch",
                "hash_algorithm",
                "previous_segment_hash",
                "previous_segment_sha256",
                "event_hash",
                "event_sha256",
            ] {
                flat.remove(key);
            }
            Value::Object(flat)
        });
        let computed_hash = sha256(bytes);
        if let Some(reported) = object
            .get("event_hash")
            .or_else(|| object.get("event_sha256"))
            .and_then(Value::as_str)
        {
            ensure!(
                reported == computed_hash,
                "legacy event hash does not match immutable bytes"
            );
        }
        Ok(Self {
            sequence,
            event_type,
            actor,
            controller_epoch,
            hash_algorithm: HashAlgorithm::Sha256,
            payload,
            previous_segment_hash,
            event_hash: computed_hash,
            raw_bytes: Some(bytes.to_vec()),
        })
    }
}

/// The existing seed and receipt are the immutable sequence-0 genesis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Genesis {
    pub sequence: u64,
    pub seed_digest: String,
    pub receipt_digest: String,
    pub segment_hash: String,
}

/// An adoption receipt emitted after the existing suffix has been verified.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AdoptionReceipt {
    /// Sequence zero is a separate adoption receipt; the bridge event is
    /// appended after the existing legacy suffix.
    pub sequence: u64,
    pub controller_epoch: EpochId,
    pub seed_digest: String,
    pub receipt_digest: String,
    pub adopted_suffix_head: String,
    pub adoption_event_sequence: u64,
    pub adoption_event_hash: String,
}

/// Replays seed + receipt + suffix without rewriting any input bytes.
#[derive(Debug, Clone)]
pub struct CampaignLedger {
    seed: Value,
    receipt: Value,
    genesis: Genesis,
    suffix: Vec<LedgerEvent>,
    active_controller_epoch: Option<EpochId>,
    genesis_from_raw: bool,
}

impl CampaignLedger {
    /// Parses the shipped byte-oriented seed/receipt and raw legacy JSONL
    /// suffix. Artifact hashes are calculated from the original bytes; no
    /// canonical re-serialization is used for the logical genesis.
    pub fn from_raw_seed_and_receipt(
        seed_bytes: &[u8],
        receipt_bytes: &[u8],
        suffix_bytes: &[u8],
    ) -> Result<Self> {
        let seed: Value = serde_json::from_slice(seed_bytes).context("parse raw campaign seed")?;
        let receipt: Value =
            serde_json::from_slice(receipt_bytes).context("parse raw campaign receipt")?;
        let seed_sha256 = sha256(seed_bytes);
        ensure!(
            seed.get("schema_version").and_then(Value::as_str)
                == Some("eliot-bootstrap-campaign-seed-v1"),
            "bootstrap seed schema mismatch"
        );
        ensure!(
            receipt.get("schema_version").and_then(Value::as_str)
                == Some("eliot-bootstrap-campaign-seed-receipt-v1"),
            "bootstrap seed receipt schema mismatch"
        );
        ensure!(
            seed.get("campaign_id").and_then(Value::as_str)
                == receipt.get("campaign_id").and_then(Value::as_str),
            "bootstrap seed/receipt campaign mismatch"
        );
        ensure!(
            seed.get("controller_epoch").and_then(Value::as_u64) == Some(0),
            "bootstrap seed controller epoch must be zero"
        );
        ensure!(
            receipt.get("seed_sha256").and_then(Value::as_str) == Some(seed_sha256.as_str()),
            "bootstrap receipt does not bind the exact seed bytes"
        );
        let suffix = std::str::from_utf8(suffix_bytes)
            .context("campaign suffix must be UTF-8")?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| LedgerEvent::from_raw_json(line.as_bytes()))
            .collect::<Result<Vec<_>>>()?;
        let mut receipt_shape = receipt.clone();
        if let Some(object) = receipt_shape.as_object_mut() {
            object.remove("seed_digest");
        }
        let mut ledger = Self::from_seed_and_suffix(seed, receipt_shape, suffix)?;
        ledger.receipt = receipt;
        ledger.genesis.seed_digest = seed_sha256;
        ledger.genesis.receipt_digest = sha256(receipt_bytes);
        ledger
            .genesis
            .segment_hash
            .clone_from(&ledger.genesis.receipt_digest);
        ledger.genesis_from_raw = true;
        let mut previous = ledger.genesis.segment_hash.clone();
        for (index, event) in ledger.suffix.iter().enumerate() {
            event.verify((index + 1) as u64, &previous)?;
            previous.clone_from(&event.event_hash);
        }
        ledger.active_controller_epoch = Self::active_epoch_from_events(&ledger.suffix)?;
        ledger.verify_active_bootstrap()?;
        Ok(ledger)
    }

    fn active_epoch_from_events(events: &[LedgerEvent]) -> Result<Option<EpochId>> {
        let mut active: Option<EpochId> = None;
        for event in events {
            if event.event_type == "controller_epoch_adopted" {
                ensure!(active.is_none(), "duplicate controller adoption");
                ensure!(
                    event.controller_epoch.sequence == 1,
                    "bootstrap controller adoption must open epoch one"
                );
                active = Some(event.controller_epoch.clone());
            } else if let Some(epoch) = &active {
                ensure!(
                    &event.controller_epoch == epoch,
                    "campaign event carries a stale controller epoch"
                );
            }
        }
        Ok(active)
    }

    fn verify_active_bootstrap(&self) -> Result<()> {
        let Some(active_epoch) = &self.active_controller_epoch else {
            return Ok(());
        };
        ensure!(
            self.genesis_from_raw
                && self.genesis.receipt_digest == BOOTSTRAP_RECEIPT_SHA256
                && self.suffix.len() >= 10,
            "active controller epoch lacks the immutable bootstrap prefix"
        );
        for event in self.suffix.iter().take(9) {
            ensure!(
                event.hash_algorithm == HashAlgorithm::Sha256
                    && event.controller_epoch.sequence == 0,
                "active controller epoch has a malformed legacy prefix"
            );
        }
        ensure!(
            self.suffix[8].event_hash == EVENT9_HEAD_SHA256,
            "active controller epoch has the wrong immutable event-9 head"
        );
        let bridge = &self.suffix[9];
        ensure!(
            bridge.sequence == 10
                && bridge.event_type == "controller_epoch_adopted"
                && bridge.hash_algorithm == HashAlgorithm::Blake3
                && &bridge.controller_epoch == active_epoch
                && bridge.previous_segment_hash == EVENT9_HEAD_SHA256,
            "active controller epoch has an invalid adoption bridge"
        );
        ensure!(
            json_string(&bridge.payload, &["seed_digest"])? == self.genesis.seed_digest
                && json_string(&bridge.payload, &["receipt_digest"])?
                    == self.genesis.receipt_digest
                && json_string(&bridge.payload, &["adopted_suffix_head"])? == EVENT9_HEAD_SHA256,
            "adoption bridge does not bind the immutable bootstrap evidence"
        );
        Ok(())
    }

    /// Replay exact per-segment event files.  Each file is an immutable
    /// segment; joining files into JSONL would change the hash input.
    pub fn from_raw_event_files(
        seed_bytes: &[u8],
        receipt_bytes: &[u8],
        event_files: &[Vec<u8>],
    ) -> Result<Self> {
        let suffix = event_files
            .iter()
            .map(|bytes| LedgerEvent::from_raw_json(bytes))
            .collect::<Result<Vec<_>>>()?;
        let mut ledger = Self::from_raw_seed_and_receipt(seed_bytes, receipt_bytes, b"")?;
        ledger.suffix = suffix;
        ledger.genesis_from_raw = true;
        let mut previous = ledger.genesis.segment_hash.clone();
        for (index, event) in ledger.suffix.iter().enumerate() {
            event.verify((index + 1) as u64, &previous)?;
            previous.clone_from(&event.event_hash);
        }
        ledger.active_controller_epoch = Self::active_epoch_from_events(&ledger.suffix)?;
        ledger.verify_active_bootstrap()?;
        Ok(ledger)
    }

    pub fn from_seed_and_suffix(
        seed: Value,
        receipt: Value,
        suffix: Vec<LedgerEvent>,
    ) -> Result<Self> {
        ensure!(seed.is_object(), "bootstrap seed must be an object");
        ensure!(receipt.is_object(), "bootstrap receipt must be an object");
        let seed_digest = sha256(&canonical_bytes(&seed));
        let receipt_digest = sha256(&canonical_bytes(&receipt));
        if let Some(epoch) = seed.get("controller_epoch").and_then(Value::as_u64) {
            ensure!(epoch == 0, "bootstrap seed controller epoch must be zero");
        }
        if let Some(sequence) = receipt.get("sequence").and_then(Value::as_u64) {
            ensure!(sequence == 0, "bootstrap receipt must be sequence zero");
        }
        if let Some(referenced) = receipt.get("seed_digest").and_then(Value::as_str) {
            ensure!(
                referenced == seed_digest,
                "bootstrap receipt seed digest mismatch"
            );
        }
        let segment_hash = sha256(&canonical_bytes(&json!({
            "sequence": 0,
            "seed_digest": seed_digest,
            "receipt_digest": receipt_digest,
        })));
        let genesis = Genesis {
            sequence: 0,
            seed_digest,
            receipt_digest,
            segment_hash,
        };
        let mut previous_hash = genesis.segment_hash.clone();
        for (index, event) in suffix.iter().enumerate() {
            event.verify((index + 1) as u64, &previous_hash)?;
            previous_hash.clone_from(&event.event_hash);
        }
        let active_controller_epoch = Self::active_epoch_from_events(&suffix)?;
        ensure!(
            active_controller_epoch.is_none(),
            "synthetic ledger input cannot establish controller authority"
        );
        Ok(Self {
            seed,
            receipt,
            genesis,
            suffix,
            active_controller_epoch,
            genesis_from_raw: false,
        })
    }

    pub fn verify_suffix(&self) -> Result<()> {
        if self.genesis_from_raw {
            let mut previous = self.genesis.segment_hash.clone();
            for (index, event) in self.suffix.iter().enumerate() {
                event.verify((index + 1) as u64, &previous)?;
                previous.clone_from(&event.event_hash);
            }
            self.verify_active_bootstrap()?;
        } else {
            let replayed = Self::from_seed_and_suffix(
                self.seed.clone(),
                self.receipt.clone(),
                self.suffix.clone(),
            )?;
            ensure!(replayed.genesis == self.genesis, "campaign genesis changed");
        }
        Ok(())
    }

    /// D-01's existing suffix is the SHA-256 legacy chain. D-02 bridges it
    /// only after the exact nine-event head is verified; epoch-one events use
    /// BLAKE3 and therefore cannot rewrite the legacy bytes.
    pub fn verify_legacy_suffix(&self) -> Result<()> {
        self.verify_legacy_suffix_with_head(EVENT9_HEAD_SHA256)
    }

    pub fn verify_legacy_suffix_with_head(&self, expected_event9_head: &str) -> Result<()> {
        self.verify_suffix()?;
        ensure!(
            self.suffix.len() >= 9,
            "recovery suffix must contain events 1..9"
        );
        for event in self.suffix.iter().take(9) {
            ensure!(
                event.hash_algorithm == HashAlgorithm::Sha256,
                "legacy suffix must use SHA-256"
            );
            ensure!(
                event.controller_epoch.sequence == 0,
                "legacy suffix has a non-genesis epoch"
            );
        }
        ensure!(
            self.suffix[8].event_hash == expected_event9_head,
            "legacy event-9 head mismatch"
        );
        Ok(())
    }

    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }
    pub fn suffix(&self) -> &[LedgerEvent] {
        &self.suffix
    }
    pub fn active_controller_epoch(&self) -> Option<&EpochId> {
        self.active_controller_epoch.as_ref()
    }
    pub fn head_hash(&self) -> &str {
        self.suffix
            .last()
            .map_or(&self.genesis.segment_hash, |event| &event.event_hash)
    }

    pub fn state_fence(&self) -> String {
        let epoch = self.active_controller_epoch.as_ref().map_or_else(
            || "genesis".to_owned(),
            |id| format!("{}:{}", id.lineage, id.sequence),
        );
        format!("{epoch}:{}:{}", self.suffix.len(), self.head_hash())
    }

    fn adopt_epoch(&mut self, controller_epoch: EpochId) -> Result<AdoptionReceipt> {
        ensure!(
            self.genesis_from_raw
                && self.genesis.receipt_digest == BOOTSTRAP_RECEIPT_SHA256
                && self.suffix.len() == 9,
            "controller adoption requires the exact immutable bootstrap ledger"
        );
        self.verify_legacy_suffix_with_head(EVENT9_HEAD_SHA256)?;
        ensure!(
            controller_epoch.sequence == 1,
            "bootstrap controller adoption must open epoch one"
        );
        ensure!(
            self.active_controller_epoch.is_none(),
            "campaign already has an adopted controller epoch"
        );
        let sequence = self.suffix.len() as u64 + 1;
        let event = LedgerEvent::new(
            sequence,
            "controller_epoch_adopted",
            "D-02",
            &controller_epoch,
            json!({
                "seed_digest": self.genesis.seed_digest,
                "receipt_digest": self.genesis.receipt_digest,
                "adopted_suffix_head": self.head_hash(),
            }),
            self.head_hash().to_owned(),
            HashAlgorithm::Blake3,
        );
        let adopted_suffix_head = self.head_hash().to_owned();
        let adoption_event_hash = event.event_hash.clone();
        self.suffix.push(event);
        self.active_controller_epoch = Some(controller_epoch.clone());
        Ok(AdoptionReceipt {
            sequence: 0,
            controller_epoch,
            seed_digest: self.genesis.seed_digest.clone(),
            receipt_digest: self.genesis.receipt_digest.clone(),
            adopted_suffix_head,
            adoption_event_sequence: sequence,
            adoption_event_hash,
        })
    }

    fn append(&mut self, event_type: &str, payload: Value) -> Result<&LedgerEvent> {
        let epoch = self
            .active_controller_epoch
            .as_ref()
            .context("campaign has not adopted a controller epoch")?;
        let sequence = self.suffix.len() as u64 + 1;
        let previous = self.head_hash().to_owned();
        self.suffix.push(LedgerEvent::new(
            sequence,
            event_type,
            "D-02",
            epoch,
            payload,
            previous,
            HashAlgorithm::Blake3,
        ));
        self.suffix
            .last()
            .ok_or_else(|| anyhow::anyhow!("event append did not produce an event"))
    }
}

/// Distinct route capacities recorded after adoption and before staffing.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RouteStatus {
    Qualified,
    DegradedSequential,
    RouteUnfitForCampaign,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityProbe {
    pub phase: String,
    pub mutating_slots: u16,
    pub reviewer_slots: u16,
    pub read_only_slots: u16,
    pub assembly_slots: u16,
    pub build_slots: u16,
    pub codex_slots_admitted: u8,
    pub codex_slots_used: u8,
    #[serde(default)]
    pub codex_slot_ids: Vec<String>,
    pub opencode_headless_lanes: u8,
    pub shared_total_slot_ceiling: u16,
    pub role_capacities: BTreeMap<String, u16>,
    pub role_status: BTreeMap<String, RouteStatus>,
    pub status: RouteStatus,
}

impl CapabilityProbe {
    pub fn post_adoption(
        mutating_slots: u16,
        reviewer_slots: u16,
        read_only_slots: u16,
        assembly_slots: u16,
        build_slots: u16,
    ) -> Self {
        Self::post_adoption_with_codex_slots(
            mutating_slots,
            reviewer_slots,
            read_only_slots,
            assembly_slots,
            build_slots,
            (1..=4).map(|slot| format!("codex-{slot}")).collect(),
            4,
        )
    }

    pub fn post_adoption_with_codex_slots(
        mutating_slots: u16,
        reviewer_slots: u16,
        read_only_slots: u16,
        assembly_slots: u16,
        build_slots: u16,
        codex_slot_ids: Vec<String>,
        shared_total_slot_ceiling: u16,
    ) -> Self {
        let status = if mutating_slots > 0
            && reviewer_slots > 0
            && read_only_slots > 0
            && assembly_slots > 0
            && build_slots > 0
        {
            RouteStatus::Qualified
        } else if mutating_slots > 0 && reviewer_slots > 0 && assembly_slots > 0 && build_slots > 0
        {
            RouteStatus::DegradedSequential
        } else {
            RouteStatus::RouteUnfitForCampaign
        };
        Self {
            phase: "post_adoption".to_owned(),
            mutating_slots,
            reviewer_slots,
            read_only_slots,
            assembly_slots,
            build_slots,
            codex_slots_admitted: u8::try_from(codex_slot_ids.len()).unwrap_or(u8::MAX),
            codex_slots_used: 0,
            codex_slot_ids,
            opencode_headless_lanes: 1,
            shared_total_slot_ceiling,
            role_capacities: BTreeMap::from([
                ("mutating".to_owned(), mutating_slots),
                ("reviewer".to_owned(), reviewer_slots),
                ("read_only".to_owned(), read_only_slots),
                ("assembly".to_owned(), assembly_slots),
                ("build_exclusive".to_owned(), build_slots),
            ]),
            role_status: BTreeMap::from([
                (
                    "mutating".to_owned(),
                    if mutating_slots > 0 {
                        RouteStatus::Qualified
                    } else {
                        RouteStatus::RouteUnfitForCampaign
                    },
                ),
                (
                    "reviewer".to_owned(),
                    if reviewer_slots > 0 {
                        RouteStatus::Qualified
                    } else {
                        RouteStatus::RouteUnfitForCampaign
                    },
                ),
                (
                    "read_only".to_owned(),
                    if read_only_slots > 0 {
                        RouteStatus::Qualified
                    } else {
                        RouteStatus::DegradedSequential
                    },
                ),
                (
                    "assembly".to_owned(),
                    if assembly_slots > 0 {
                        RouteStatus::Qualified
                    } else {
                        RouteStatus::RouteUnfitForCampaign
                    },
                ),
                (
                    "build_exclusive".to_owned(),
                    if build_slots > 0 {
                        RouteStatus::Qualified
                    } else {
                        RouteStatus::RouteUnfitForCampaign
                    },
                ),
            ]),
            status,
        }
    }

    pub fn validate_before_staffing(&self) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            self.status == RouteStatus::Qualified,
            "all campaign routes must be qualified before staffing"
        );
        for role in [
            "mutating",
            "reviewer",
            "read_only",
            "assembly",
            "build_exclusive",
        ] {
            ensure!(
                self.role_capacities
                    .get(role)
                    .copied()
                    .is_some_and(|capacity| capacity > 0),
                "role capacity missing: {role}"
            );
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    pub fn validate_shape(&self) -> Result<()> {
        ensure!(
            self.phase == "post_adoption",
            "capability probe must be post-adoption"
        );
        ensure!(
            self.codex_slots_admitted as usize == self.codex_slot_ids.len(),
            "Codex admission count does not match slot identities"
        );
        ensure!(
            self.codex_slots_admitted > 0,
            "at least one Codex slot must be admitted"
        );
        let mut unique_slot_ids = std::collections::BTreeSet::new();
        for slot_id in &self.codex_slot_ids {
            ensure!(!slot_id.trim().is_empty(), "Codex slot identity is blank");
            ensure!(
                unique_slot_ids.insert(slot_id),
                "duplicate Codex slot identity: {slot_id}"
            );
        }
        ensure!(
            self.codex_slots_used as usize <= self.codex_slot_ids.len(),
            "Codex usage count exceeds admitted slot identities"
        );
        ensure!(
            u16::from(self.codex_slots_admitted) <= self.shared_total_slot_ceiling,
            "Codex slots exceed shared slot ceiling"
        );
        let expected_capacities = BTreeMap::from([
            ("mutating".to_owned(), self.mutating_slots),
            ("reviewer".to_owned(), self.reviewer_slots),
            ("read_only".to_owned(), self.read_only_slots),
            ("assembly".to_owned(), self.assembly_slots),
            ("build_exclusive".to_owned(), self.build_slots),
        ]);
        ensure!(
            self.role_capacities == expected_capacities,
            "role capacities contradict the typed capability projection"
        );
        for capacity in self.role_capacities.values() {
            ensure!(
                *capacity <= self.shared_total_slot_ceiling,
                "role capacity exceeds the shared slot ceiling"
            );
        }
        let expected_role_status = BTreeMap::from([
            (
                "mutating".to_owned(),
                if self.mutating_slots > 0 {
                    RouteStatus::Qualified
                } else {
                    RouteStatus::RouteUnfitForCampaign
                },
            ),
            (
                "reviewer".to_owned(),
                if self.reviewer_slots > 0 {
                    RouteStatus::Qualified
                } else {
                    RouteStatus::RouteUnfitForCampaign
                },
            ),
            (
                "read_only".to_owned(),
                if self.read_only_slots > 0 {
                    RouteStatus::Qualified
                } else {
                    RouteStatus::DegradedSequential
                },
            ),
            (
                "assembly".to_owned(),
                if self.assembly_slots > 0 {
                    RouteStatus::Qualified
                } else {
                    RouteStatus::RouteUnfitForCampaign
                },
            ),
            (
                "build_exclusive".to_owned(),
                if self.build_slots > 0 {
                    RouteStatus::Qualified
                } else {
                    RouteStatus::RouteUnfitForCampaign
                },
            ),
        ]);
        ensure!(
            self.role_status == expected_role_status,
            "role status contradicts the typed capability projection"
        );
        let expected_status = if self.mutating_slots > 0
            && self.reviewer_slots > 0
            && self.read_only_slots > 0
            && self.assembly_slots > 0
            && self.build_slots > 0
        {
            RouteStatus::Qualified
        } else if self.mutating_slots > 0
            && self.reviewer_slots > 0
            && self.assembly_slots > 0
            && self.build_slots > 0
        {
            RouteStatus::DegradedSequential
        } else {
            RouteStatus::RouteUnfitForCampaign
        };
        ensure!(
            self.status == expected_status,
            "overall route status contradicts the typed capability projection"
        );
        ensure!(
            self.opencode_headless_lanes == 1,
            "exactly one OpenCode lane is supported"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CodexRole {
    Mutating,
    Reviewer,
    ReadOnly,
    Assembly,
    BuildExclusive,
}

impl CodexRole {
    fn capacity_key(self) -> &'static str {
        match self {
            Self::Mutating => "mutating",
            Self::Reviewer => "reviewer",
            Self::ReadOnly => "read_only",
            Self::Assembly => "assembly",
            Self::BuildExclusive => "build_exclusive",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodexSlotAdmission {
    pub slot: u8,
    pub slot_id: String,
    pub role: CodexRole,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DispatchIntent {
    pub slot_id: String,
    pub provider: String,
    pub agent_id: String,
    pub role: CodexRole,
    pub campaign_epoch: EpochId,
    pub no_authority: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SlotLaunchReceipt {
    pub intent: DispatchIntent,
    pub host_ack_id: String,
    pub accepted: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum OpenCodeAttemptKind {
    Primary,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Authority {
    None,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum LaunchScope {
    UnscopedSupervisedPlanCandidateOnly,
}

/// The intentionally small `OpenCode` launch surface. Forbidden authority
/// fields are absent by construction (task, leases, write paths, caller
/// idempotency and timeout are not launch inputs).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeLaunch {
    pub lane_id: String,
    pub model: String,
    pub headless: bool,
    pub supervised: bool,
    pub authority: Authority,
    pub scope: LaunchScope,
    pub candidate_only: bool,
}

impl OpenCodeLaunch {
    fn new(lane_id: &str, model: &str) -> Self {
        Self {
            lane_id: lane_id.to_owned(),
            model: model.to_owned(),
            headless: true,
            supervised: true,
            authority: Authority::None,
            scope: LaunchScope::UnscopedSupervisedPlanCandidateOnly,
            candidate_only: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenCodeAttempt {
    pub attempt_id: String,
    pub kind: OpenCodeAttemptKind,
    pub launch: OpenCodeLaunch,
    pub explicit_admission: bool,
    pub automatic_retry: bool,
}

/// A route can be disabled without converting an unavailable external
/// capability into a successful attempt.  The reason is candidate evidence;
/// it never selects another provider or model.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum OpenCodeRouteState {
    Available,
    Unavailable { reason: String },
    Degraded { reason: String },
}

impl OpenCodeRouteState {
    fn validate(&self) -> Result<()> {
        if let Self::Unavailable { reason } | Self::Degraded { reason } = self {
            ensure!(
                !reason.trim().is_empty(),
                "OpenCode route state reason is required"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenCodeLane {
    pub lane_id: String,
    pub state: OpenCodeRouteState,
    pub primary: Option<OpenCodeAttempt>,
    policy: OpenCodeRoutePolicy,
}

impl OpenCodeLane {
    pub fn new() -> Self {
        Self::with_policy(OpenCodeRoutePolicy {
            model: PRIMARY_OPENCODE_MODEL.to_owned(),
        })
    }
    pub fn with_policy(policy: OpenCodeRoutePolicy) -> Self {
        Self {
            lane_id: "opencode-headless-plan".to_owned(),
            state: OpenCodeRouteState::Available,
            primary: None,
            policy,
        }
    }
    pub fn admit_primary(&mut self) -> Result<OpenCodeAttempt> {
        self.state.validate()?;
        ensure!(
            matches!(self.state, OpenCodeRouteState::Available),
            "OpenCode route is not available: {:?}",
            self.state
        );
        ensure!(
            self.primary.is_none(),
            "OpenCode primary is already admitted"
        );
        let attempt = OpenCodeAttempt {
            attempt_id: format!("{}:primary", self.lane_id),
            kind: OpenCodeAttemptKind::Primary,
            launch: OpenCodeLaunch::new(&self.lane_id, &self.policy.model),
            explicit_admission: true,
            automatic_retry: false,
        };
        self.primary = Some(attempt.clone());
        Ok(attempt)
    }
    pub fn disable(&mut self, reason: impl Into<String>) -> Result<()> {
        ensure!(
            self.primary.is_none(),
            "cannot disable OpenCode after admission"
        );
        let reason = reason.into();
        ensure!(
            !reason.trim().is_empty(),
            "OpenCode disable reason is required"
        );
        self.state = OpenCodeRouteState::Unavailable { reason };
        Ok(())
    }

    pub fn set_state(&mut self, state: OpenCodeRouteState) -> Result<()> {
        ensure!(
            self.primary.is_none(),
            "cannot change OpenCode route after admission"
        );
        state.validate()?;
        self.state = state;
        Ok(())
    }
}

impl Default for OpenCodeLane {
    fn default() -> Self {
        Self::new()
    }
}

/// Candidate-only output; D-02 never evaluates it or issues a verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateResult {
    pub attempt_id: String,
    pub status: String,
    pub output_digest: String,
    pub evaluator_owner: String,
    pub oracle_owner: String,
}

#[derive(Debug, Clone)]
pub struct CampaignExecutor {
    pub ledger: CampaignLedger,
    capability_probe: Option<CapabilityProbe>,
    staffed_codex: Vec<CodexSlotAdmission>,
    planned_codex: Vec<DispatchIntent>,
    opencode: OpenCodeLane,
    verified_opencode_attempts: std::collections::BTreeSet<String>,
}

/// Small external store for the development ledger. The lock is exclusive,
/// journal lines are append-only, and the rebuildable projection is replaced
/// only through a flushed temporary file.
pub struct CampaignStore {
    root: PathBuf,
    lock: File,
}

fn event_filename_sequence(path: &std::path::Path) -> Option<u64> {
    if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
        return None;
    }
    let stem = path.file_stem().and_then(|stem| stem.to_str())?;
    let prefix = stem.split('-').next()?;
    if prefix.is_empty() || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    prefix.parse().ok()
}

impl CampaignStore {
    pub fn acquire(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)
            .with_context(|| format!("create campaign state root: {}", root.display()))?;
        let lock_path = root.join("controller.lock");
        let lock = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("open campaign controller lock: {}", lock_path.display()))?;
        lock.try_lock().with_context(|| {
            format!("acquire campaign controller lock: {}", lock_path.display())
        })?;
        Ok(Self { root, lock })
    }

    pub fn load(&self) -> Result<CampaignLedger> {
        let seed = fs::read(self.root.join("bootstrap-campaign-seed.json"))
            .context("read campaign seed")?;
        let receipt = fs::read(self.root.join("bootstrap-campaign-seed.receipt.json"))
            .context("read campaign receipt")?;
        let events_root = self.root.join("events");
        let mut paths = fs::read_dir(&events_root)
            .with_context(|| format!("read campaign events: {}", events_root.display()))?
            .collect::<std::io::Result<Vec<_>>>()?;
        paths.sort_by_key(|entry| event_filename_sequence(&entry.path()).unwrap_or(u64::MAX));
        let mut events = Vec::new();
        for entry in paths {
            let path = entry.path();
            let valid_name = event_filename_sequence(&path).is_some();
            ensure!(
                valid_name,
                "quarantine unexpected campaign event file: {}",
                path.display()
            );
            events.push(
                fs::read(&path)
                    .with_context(|| format!("read campaign event: {}", path.display()))?,
            );
        }
        CampaignLedger::from_raw_event_files(&seed, &receipt, &events)
    }

    fn append_event(&self, event: &LedgerEvent) -> Result<()> {
        let events_root = self.root.join("events");
        fs::create_dir_all(&events_root)?;
        let kind = event
            .event_type
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character
                } else {
                    '-'
                }
            })
            .collect::<String>();
        let path = events_root.join(format!("{:06}-{kind}.json", event.sequence));
        ensure!(
            !path.exists(),
            "campaign event sequence already exists: {}",
            event.sequence
        );
        let temp = events_root.join(format!("{:06}-{kind}.json.tmp", event.sequence));
        ensure!(
            !temp.exists(),
            "quarantine unfinished campaign event temp: {}",
            temp.display()
        );
        let mut file = File::create(&temp)?;
        let bytes = serde_json::to_vec(event)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(temp, path)?;
        Ok(())
    }

    /// Append only if the caller's observed head, epoch, and projection fence
    /// still describe this controller's current state.
    pub fn append_event_checked(
        &self,
        event: &LedgerEvent,
        expected_head: &str,
        expected_epoch: Option<&EpochId>,
        expected_state_fence: &str,
    ) -> Result<()> {
        let ledger = self.load()?;
        ensure!(
            ledger.head_hash() == expected_head,
            "campaign head changed during append"
        );
        ensure!(
            ledger.active_controller_epoch() == expected_epoch,
            "campaign epoch changed during append"
        );
        ensure!(
            ledger.state_fence() == expected_state_fence,
            "campaign state fence changed during append"
        );
        ensure!(
            event.sequence == ledger.suffix().len() as u64 + 1,
            "campaign append sequence is stale"
        );
        ensure!(
            event.previous_segment_hash == expected_head,
            "campaign append previous head is stale"
        );
        event.verify(event.sequence, expected_head)?;
        ensure!(
            event.hash_algorithm == HashAlgorithm::Blake3 && event.raw_bytes.is_none(),
            "new campaign event must use the D-02 BLAKE3 event format"
        );
        match expected_epoch {
            Some(epoch) => ensure!(
                &event.controller_epoch == epoch,
                "campaign append controller epoch is stale"
            ),
            None => ensure!(
                event.event_type == "controller_epoch_adopted"
                    && event.controller_epoch.sequence == 1,
                "genesis append must be the epoch-one adoption bridge"
            ),
        }
        self.append_event(event)
    }

    pub fn write_projection(&self, projection: &Value) -> Result<()> {
        let version = format!(
            "projection-{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let target = self.root.join(version);
        let temp = target.with_extension("json.tmp");
        let mut file = File::create(&temp)?;
        file.write_all(&canonical_bytes(projection))?;
        file.sync_all()?;
        drop(file);
        fs::rename(temp, target)?;
        Ok(())
    }

    pub fn root(&self) -> &PathBuf {
        &self.root
    }
}

impl Drop for CampaignStore {
    fn drop(&mut self) {
        let _ = self.lock.sync_all();
        let _ = self.lock.unlock();
    }
}

impl CampaignExecutor {
    pub fn new(ledger: CampaignLedger) -> Self {
        Self {
            ledger,
            capability_probe: None,
            staffed_codex: Vec::new(),
            planned_codex: Vec::new(),
            opencode: OpenCodeLane::new(),
            verified_opencode_attempts: std::collections::BTreeSet::new(),
        }
    }

    /// Rebuild the executor's non-authoritative projection from verified
    /// ledger events. Missing or contradictory projection fields fail closed;
    /// the journal is never repaired or rewritten here.
    #[allow(clippy::too_many_lines)]
    pub fn from_replayed_ledger(ledger: CampaignLedger) -> Result<Self> {
        ledger.verify_suffix()?;
        let projection_events = ledger
            .suffix()
            .iter()
            .map(|event| (event.event_type.clone(), event.payload.clone()))
            .collect::<Vec<_>>();
        let mut executor = Self::new(ledger);
        for (event_type, payload) in projection_events {
            match event_type.as_str() {
                "capability_probe_recorded" => {
                    ensure!(
                        executor.capability_probe.is_none(),
                        "duplicate capability probe in campaign ledger"
                    );
                    let probe: CapabilityProbe = serde_json::from_value(payload)
                        .context("replay capability probe projection")?;
                    probe.validate_shape()?;
                    ensure!(
                        probe.codex_slots_used == 0,
                        "persisted capability probe pre-claims Codex slot usage"
                    );
                    executor.capability_probe = Some(probe);
                }
                "codex_slots_staffed" => {
                    ensure!(
                        executor.staffed_codex.is_empty(),
                        "duplicate Codex staffing projection"
                    );
                    let admissions: Vec<CodexSlotAdmission> =
                        serde_json::from_value(json_value(&payload, &["admissions"])?.clone())
                            .context("replay Codex staffing admissions")?;
                    executor.validate_staffing_admissions(&admissions)?;
                    ensure!(
                        json_u64(&payload, &["count"])? == admissions.len() as u64,
                        "Codex staffing count contradicts its admissions"
                    );
                    executor.staffed_codex = admissions;
                }
                "codex_slot_launch_receipts" => {
                    ensure!(
                        executor
                            .capability_probe
                            .as_ref()
                            .is_some_and(|probe| probe.codex_slots_used == 0),
                        "duplicate Codex launch receipt projection"
                    );
                    let receipts: Vec<SlotLaunchReceipt> =
                        serde_json::from_value(payload).context("replay Codex launch receipts")?;
                    let used = executor.validate_slot_launch_receipts(&receipts)?;
                    let probe = executor
                        .capability_probe
                        .as_mut()
                        .context("launch receipts precede capability probe")?;
                    probe.codex_slots_used = used;
                }
                "codex_dispatch_intents_planned" => {
                    ensure!(
                        executor.planned_codex.is_empty(),
                        "duplicate Codex dispatch intent projection"
                    );
                    let intents: Vec<DispatchIntent> =
                        serde_json::from_value(payload).context("replay Codex dispatch intents")?;
                    executor.validate_dispatch_intents(&intents)?;
                    executor.planned_codex = intents;
                }
                "opencode_attempt_admitted" => {
                    ensure!(
                        executor.capability_probe.is_some(),
                        "OpenCode admission precedes the capability probe"
                    );
                    ensure!(
                        json_string(&payload, &["kind"])? == "primary",
                        "only the fixed primary OpenCode bootstrap lane can be replayed"
                    );
                    let attempt = executor.opencode.admit_primary()?;
                    ensure!(
                        json_string(&payload, &["attempt_id"])? == attempt.attempt_id
                            && json_string(&payload, &["model"])? == attempt.launch.model,
                        "OpenCode admission projection mismatch"
                    );
                }
                "opencode_route_state" => {
                    ensure!(
                        json_value(&payload, &["candidate_only"])? == &Value::Bool(true)
                            && json_string(&payload, &["authority"])? == "none",
                        "OpenCode route state is not candidate-only"
                    );
                    let state: OpenCodeRouteState =
                        serde_json::from_value(json_value(&payload, &["state"])?.clone())
                            .context("replay OpenCode route state")?;
                    executor.opencode.set_state(state)?;
                }
                "opencode_attempt_verified" => {
                    let attempt_id = json_string(&payload, &["attempt_id"])?;
                    let primary = executor
                        .opencode
                        .primary
                        .as_ref()
                        .context("OpenCode verification precedes admission")?;
                    ensure!(
                        attempt_id == primary.attempt_id
                            && json_value(&payload, &["candidate_only"])? == &Value::Bool(true)
                            && json_string(&payload, &["authority"])? == "none"
                            && json_value(&payload, &["actual_route"])?.is_object(),
                        "OpenCode verification projection mismatch"
                    );
                    executor
                        .verified_opencode_attempts
                        .insert(attempt_id.to_owned());
                }
                _ => {}
            }
        }
        Ok(executor)
    }

    /// Adoption is inseparable from verification of the immutable recovery
    /// report, handle, checkpoint, and exact legacy suffix.
    pub fn adopt(
        &mut self,
        epoch: EpochId,
        recovery: &RecoveryEvidence,
    ) -> Result<AdoptionReceipt> {
        let policy = OpenCodeRoutePolicy {
            model: PRIMARY_OPENCODE_MODEL.to_owned(),
        };
        self.adopt_with_policy(epoch, recovery, &policy)
    }

    pub fn adopt_with_policy(
        &mut self,
        epoch: EpochId,
        recovery: &RecoveryEvidence,
        policy: &OpenCodeRoutePolicy,
    ) -> Result<AdoptionReceipt> {
        policy.verify()?;
        recovery.verify_with_policy(policy)?;
        ensure!(
            self.ledger.genesis().receipt_digest == recovery.bootstrap_receipt.expected_sha256,
            "loaded campaign receipt differs from recovery evidence"
        );
        ensure!(
            self.ledger.suffix().len() == 9,
            "bootstrap adoption requires the exact immutable events 1..9"
        );
        self.ledger
            .verify_legacy_suffix_with_head(EVENT9_HEAD_SHA256)?;
        self.ledger.adopt_epoch(epoch)
    }

    fn validate_staffing_admissions(&self, admissions: &[CodexSlotAdmission]) -> Result<()> {
        let probe = self
            .capability_probe
            .as_ref()
            .context("staffing projection precedes capability probe")?;
        ensure!(
            admissions.len() == probe.codex_slot_ids.len(),
            "staffing projection must cover every admitted Codex slot"
        );
        let mut role_usage = BTreeMap::<&str, u16>::new();
        for (index, admission) in admissions.iter().enumerate() {
            ensure!(
                admission.slot as usize == index + 1
                    && admission.slot_id == probe.codex_slot_ids[index],
                "Codex staffing order or identity mismatch"
            );
            let capacity = probe
                .role_capacities
                .get(admission.role.capacity_key())
                .copied()
                .context("Codex staffing role has no typed capacity")?;
            let used = role_usage.entry(admission.role.capacity_key()).or_default();
            *used += 1;
            ensure!(
                *used <= capacity,
                "Codex staffing exceeds a typed role capacity"
            );
        }
        Ok(())
    }

    fn validate_dispatch_intents(&self, intents: &[DispatchIntent]) -> Result<()> {
        ensure!(
            intents.len() == self.staffed_codex.len() && !intents.is_empty(),
            "dispatch intents must cover every staffed Codex slot"
        );
        let epoch = self
            .ledger
            .active_controller_epoch()
            .context("dispatch intents require an adopted controller epoch")?;
        for (intent, admission) in intents.iter().zip(&self.staffed_codex) {
            ensure!(
                intent.slot_id == admission.slot_id
                    && intent.provider == "codex"
                    && intent.agent_id == admission.slot_id
                    && intent.role == admission.role
                    && &intent.campaign_epoch == epoch
                    && intent.no_authority,
                "Codex dispatch intent contradicts staffing or authority fences"
            );
        }
        Ok(())
    }

    fn validate_slot_launch_receipts(&self, receipts: &[SlotLaunchReceipt]) -> Result<u8> {
        let probe = self
            .capability_probe
            .as_ref()
            .context("probe capabilities before launch receipts")?;
        ensure!(
            probe.codex_slots_used == 0,
            "Codex launch receipts are already recorded"
        );
        ensure!(
            !self.staffed_codex.is_empty(),
            "staff Codex slots before launch receipts"
        );
        ensure!(
            self.planned_codex.len() == self.staffed_codex.len(),
            "persist dispatch intents before launch receipts"
        );
        ensure!(
            receipts.len() == probe.codex_slot_ids.len()
                && receipts.len() == self.staffed_codex.len(),
            "host receipts must cover every admitted Codex slot exactly once"
        );
        let epoch = self
            .ledger
            .active_controller_epoch()
            .context("adopt before launch receipts")?;
        let mut slots = std::collections::BTreeSet::new();
        let mut agents = std::collections::BTreeSet::new();
        let mut acknowledgements = std::collections::BTreeSet::new();
        for receipt in receipts {
            ensure!(receipt.accepted, "host rejected Codex launch receipt");
            ensure!(
                !receipt.host_ack_id.trim().is_empty(),
                "host launch acknowledgement is missing"
            );
            ensure!(
                acknowledgements.insert(&receipt.host_ack_id),
                "duplicate host launch acknowledgement"
            );
            ensure!(
                receipt.intent.no_authority,
                "Codex launch intent carries authority"
            );
            ensure!(
                &receipt.intent.campaign_epoch == epoch,
                "Codex launch epoch fence mismatch"
            );
            ensure!(
                probe.codex_slot_ids.contains(&receipt.intent.slot_id),
                "Codex launch slot was not admitted"
            );
            ensure!(
                receipt.intent.provider == "codex",
                "Codex launch receipt has the wrong provider"
            );
            ensure!(
                !receipt.intent.agent_id.trim().is_empty(),
                "Codex launch agent identity is missing"
            );
            ensure!(
                agents.insert(&receipt.intent.agent_id),
                "duplicate Codex launch agent identity"
            );
            let admission = self
                .staffed_codex
                .iter()
                .find(|admission| admission.slot_id == receipt.intent.slot_id)
                .context("Codex launch has no staffing admission")?;
            ensure!(
                admission.role == receipt.intent.role,
                "Codex launch role differs from its staffing admission"
            );
            let planned = self
                .planned_codex
                .iter()
                .find(|intent| intent.slot_id == receipt.intent.slot_id)
                .context("Codex launch has no persisted dispatch intent")?;
            ensure!(
                planned == &receipt.intent,
                "Codex launch receipt differs from its persisted dispatch intent"
            );
            ensure!(
                slots.insert(receipt.intent.slot_id.clone()),
                "duplicate Codex launch receipt"
            );
        }
        let used = u8::try_from(slots.len()).context("too many Codex slot receipts")?;
        ensure!(
            used == probe.codex_slots_admitted,
            "not all admitted Codex slots were used"
        );
        Ok(used)
    }

    pub fn record_capability_probe(&mut self, probe: CapabilityProbe) -> Result<()> {
        ensure!(
            self.ledger.active_controller_epoch().is_some(),
            "adopt before probing capabilities"
        );
        ensure!(
            self.capability_probe.is_none(),
            "capability probe is immutable"
        );
        probe.validate_shape()?;
        ensure!(
            probe.codex_slots_used == 0,
            "new capability probe cannot pre-claim Codex slot usage"
        );
        self.ledger
            .append("capability_probe_recorded", serde_json::to_value(&probe)?)?;
        self.capability_probe = Some(probe);
        Ok(())
    }

    pub fn staff_codex_slots(&mut self) -> Result<&[CodexSlotAdmission]> {
        ensure!(
            self.staffed_codex.is_empty(),
            "Codex slots are already staffed"
        );
        let probe = self
            .capability_probe
            .as_ref()
            .context("probe capabilities before staffing")?;
        probe.validate_before_staffing()?;
        let role_specs = [
            (CodexRole::Mutating, "mutating"),
            (CodexRole::Reviewer, "reviewer"),
            (CodexRole::ReadOnly, "read_only"),
            (CodexRole::Assembly, "assembly"),
            (CodexRole::BuildExclusive, "build_exclusive"),
        ];
        let max_capacity = role_specs
            .iter()
            .filter_map(|(_, role)| probe.role_capacities.get(*role))
            .copied()
            .max()
            .unwrap_or(0);
        let mut role_pool = Vec::new();
        for level in 0..max_capacity {
            for (role, name) in role_specs {
                if probe.role_capacities.get(name).copied().unwrap_or(0) > level {
                    role_pool.push(role);
                }
            }
        }
        ensure!(
            role_pool.len() >= probe.codex_slot_ids.len(),
            "typed role capacities cannot staff every admitted Codex slot"
        );
        self.staffed_codex = probe
            .codex_slot_ids
            .iter()
            .enumerate()
            .map(|(index, slot_id)| CodexSlotAdmission {
                slot: u8::try_from(index + 1).unwrap_or(u8::MAX),
                slot_id: slot_id.clone(),
                role: role_pool[index],
            })
            .collect();
        ensure!(
            !self.staffed_codex.is_empty(),
            "no Codex slots were admitted"
        );
        self.validate_staffing_admissions(&self.staffed_codex)?;
        self.ledger.append(
            "codex_slots_staffed",
            json!({
                "count": self.staffed_codex.len(),
                "admissions": &self.staffed_codex,
            }),
        )?;
        Ok(&self.staffed_codex)
    }

    pub fn plan_codex_dispatches(&mut self) -> Result<&[DispatchIntent]> {
        ensure!(
            self.planned_codex.is_empty(),
            "Codex dispatch intents are already planned"
        );
        let epoch = self
            .ledger
            .active_controller_epoch()
            .context("adopt before planning Codex dispatches")?
            .clone();
        let intents = self
            .staffed_codex
            .iter()
            .map(|admission| DispatchIntent {
                slot_id: admission.slot_id.clone(),
                provider: "codex".to_owned(),
                agent_id: admission.slot_id.clone(),
                role: admission.role,
                campaign_epoch: epoch.clone(),
                no_authority: true,
            })
            .collect::<Vec<_>>();
        self.validate_dispatch_intents(&intents)?;
        self.ledger.append(
            "codex_dispatch_intents_planned",
            serde_json::to_value(&intents)?,
        )?;
        self.planned_codex = intents;
        Ok(&self.planned_codex)
    }

    /// A slot becomes used only after a host acknowledgement binds the exact
    /// intent, provider/agent, role, epoch, and no-authority ceiling.
    pub fn record_slot_launch_receipts(&mut self, receipts: &[SlotLaunchReceipt]) -> Result<()> {
        let used = self.validate_slot_launch_receipts(receipts)?;
        let mut updated = self
            .capability_probe
            .clone()
            .context("probe capabilities before launch receipts")?;
        updated.codex_slots_used = used;
        self.ledger.append(
            "codex_slot_launch_receipts",
            serde_json::to_value(receipts)?,
        )?;
        self.capability_probe = Some(updated);
        Ok(())
    }

    pub fn admit_opencode_primary(&mut self) -> Result<OpenCodeAttempt> {
        ensure!(
            self.capability_probe.is_some(),
            "probe capabilities before OpenCode admission"
        );
        let attempt = self.opencode.admit_primary()?;
        self.ledger.append(
            "opencode_attempt_admitted",
            json!({
                "attempt_id": attempt.attempt_id,
                "kind": "primary",
                "model": PRIMARY_OPENCODE_MODEL,
                "authority": "none",
                "candidate_only": true,
            }),
        )?;
        Ok(attempt)
    }

    pub fn record_opencode_route_state(&mut self, state: &OpenCodeRouteState) -> Result<()> {
        self.opencode.set_state(state.clone())?;
        self.ledger.append(
            "opencode_route_state",
            json!({
                "state": state,
                "candidate_only": true,
                "authority": "none",
            }),
        )?;
        Ok(())
    }

    pub fn verify_opencode_attempt(
        &mut self,
        attempt: &OpenCodeAttempt,
        evidence: &OpenCodeEvidence,
    ) -> Result<Value> {
        let admitted = match attempt.kind {
            OpenCodeAttemptKind::Primary => self.opencode.primary.as_ref(),
        }
        .context("OpenCode attempt was not admitted by this executor")?;
        ensure!(
            admitted == attempt,
            "OpenCode verification attempt differs from its admission"
        );
        let value = evidence.verify_with_policy(&self.opencode.policy)?;
        ensure!(
            format!(
                "{}/{}",
                evidence.result.actual_route.requested.provider_id,
                evidence.result.actual_route.requested.model_id
            ) == attempt.launch.model,
            "OpenCode attempt model differs from verified contract"
        );
        ensure!(
            self.verified_opencode_attempts
                .insert(attempt.attempt_id.clone()),
            "OpenCode attempt evidence is already verified"
        );
        self.ledger.append(
            "opencode_attempt_verified",
            json!({
                "attempt_id": attempt.attempt_id,
                "actual_route": evidence.result.actual_route,
                "status": evidence.result.status,
                "candidate_only": true,
                "authority": "none",
            }),
        )?;
        Ok(value)
    }

    pub fn opencode_primary(&self) -> Option<&OpenCodeAttempt> {
        self.opencode.primary.as_ref()
    }

    pub fn capability_probe(&self) -> Option<&CapabilityProbe> {
        self.capability_probe.as_ref()
    }

    pub fn record_candidate(
        &mut self,
        attempt: &OpenCodeAttempt,
        output: &[u8],
    ) -> Result<CandidateResult> {
        ensure!(
            attempt.launch.candidate_only,
            "OpenCode output must remain candidate-only"
        );
        ensure!(
            self.verified_opencode_attempts
                .contains(&attempt.attempt_id),
            "candidate attempt has no verified live receipt"
        );
        let result = CandidateResult {
            attempt_id: attempt.attempt_id.clone(),
            status: "CANDIDATE_ONLY".to_owned(),
            output_digest: sha256(output),
            evaluator_owner: "I-11".to_owned(),
            oracle_owner: "I-07/I-11".to_owned(),
        };
        self.ledger
            .append("candidate_recorded", serde_json::to_value(&result)?)?;
        Ok(result)
    }
}

/// A read-only evidence file used by the pre-adoption recovery fence.
#[derive(Debug, Clone)]
pub struct EvidenceFile {
    pub path: PathBuf,
    pub expected_sha256: String,
}

impl EvidenceFile {
    fn verify(&self, label: &str) -> Result<Vec<u8>> {
        ensure!(!self.path.as_os_str().is_empty(), "{label} path is missing");
        ensure!(
            !self.expected_sha256.trim().is_empty(),
            "{label} expected hash is missing"
        );
        let bytes = fs::read(&self.path)
            .with_context(|| format!("read {label}: {}", self.path.display()))?;
        ensure!(
            sha256(&bytes) == self.expected_sha256,
            "{label} hash mismatch"
        );
        Ok(bytes)
    }
}

/// Recovery material that must already exist before D-02 adoption.
#[derive(Debug, Clone)]
pub struct RecoveryEvidence {
    pub bootstrap_receipt: EvidenceFile,
    pub checkpoint0: EvidenceFile,
    pub d01_report: EvidenceFile,
    pub d01_handle: EvidenceFile,
    pub checkpoint: EvidenceFile,
    pub event9: EvidenceFile,
    pub repository_root: PathBuf,
    pub event9_head_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitFrontierEvidence {
    pub head: String,
    pub tree: String,
    pub branch: String,
    pub dirty_status_sha256: String,
}

impl RecoveryEvidence {
    pub fn verify(&self) -> Result<()> {
        self.verify_with_policy(&OpenCodeRoutePolicy {
            model: PRIMARY_OPENCODE_MODEL.to_owned(),
        })
    }

    #[allow(clippy::too_many_lines)]
    pub fn verify_with_policy(&self, policy: &OpenCodeRoutePolicy) -> Result<()> {
        policy.verify()?;
        ensure!(
            self.bootstrap_receipt.expected_sha256 == BOOTSTRAP_RECEIPT_SHA256
                && self.checkpoint0.expected_sha256 == CHECKPOINT0_SHA256
                && self.d01_report.expected_sha256 == D01_REPORT_SHA256
                && self.d01_handle.expected_sha256 == D01_HANDLE_SHA256
                && self.checkpoint.expected_sha256 == CHECKPOINT1_SHA256
                && self.event9.expected_sha256 == EVENT9_HEAD_SHA256,
            "recovery evidence differs from the immutable bootstrap contract"
        );
        let receipt_bytes = self.bootstrap_receipt.verify("bootstrap seed receipt")?;
        let checkpoint0_bytes = self.checkpoint0.verify("global integration checkpoint 0")?;
        let report_bytes = self.d01_report.verify("D-01 report")?;
        let handle_bytes = self.d01_handle.verify("D-01 handle")?;
        let checkpoint1_bytes = self.checkpoint.verify("global integration checkpoint")?;
        let event9_bytes = self.event9.verify("global integration checkpoint event")?;
        let receipt: Value =
            serde_json::from_slice(&receipt_bytes).context("parse bootstrap seed receipt")?;
        let checkpoint0: Value = serde_json::from_slice(&checkpoint0_bytes)
            .context("parse global integration checkpoint 0")?;
        let report: Value = serde_json::from_slice(&report_bytes).context("parse D-01 report")?;
        let handle: Value = serde_json::from_slice(&handle_bytes).context("parse D-01 handle")?;
        let checkpoint: Value = serde_json::from_slice(&checkpoint1_bytes)
            .context("parse global integration checkpoint")?;
        let event9: Value = serde_json::from_slice(&event9_bytes)
            .context("parse global integration checkpoint event")?;

        ensure!(
            json_string(&receipt, &["schema_version"])?
                == "eliot-bootstrap-campaign-seed-receipt-v1"
                && json_string(&checkpoint0, &["schema_version"])?
                    == "eliot-global-integration-checkpoint-v1"
                && json_u64(&checkpoint0, &["checkpoint_sequence"])? == 0,
            "bootstrap receipt/checkpoint-0 identity mismatch"
        );
        let campaign_id = json_string(&receipt, &["campaign_id"])?;
        ensure!(
            json_string(&checkpoint0, &["campaign_id"])? == campaign_id
                && json_string(&handle, &["campaign_id"])? == campaign_id
                && json_string(&checkpoint, &["campaign_id"])? == campaign_id
                && json_string(&event9, &["campaign_id"])? == campaign_id,
            "recovery evidence crosses campaign identities"
        );
        ensure!(
            json_string(&receipt, &["checkpoint_0_sha256"])? == self.checkpoint0.expected_sha256,
            "bootstrap receipt does not bind checkpoint 0"
        );

        ensure!(
            json_string(&report, &["schema_version"])? == "eliot-runtime-compiler-receipt-v1"
                && json_string(&report, &["work_id"])? == "D-01"
                && json_string(&report, &["plan_id"])? == "D-01:plan-v2",
            "D-01 report identity mismatch"
        );
        ensure!(
            json_string(&report, &["verdict"])? == "FAIL"
                && json_u64(&report, &["checks_passed"])? == 90
                && json_u64(&report, &["checks_total"])? == 91,
            "D-01 compiler receipt projection mismatch"
        );
        let errors = report
            .get("errors")
            .and_then(Value::as_array)
            .context("D-01 compiler errors are missing")?;
        ensure!(
            errors.len() == 1,
            "D-01 compiler receipt must contain one typed PLAN_GAP"
        );
        ensure!(
            json_string(&errors[0], &["check_id"])? == "provider.binary_active_alignment"
                && contains_string_value(&errors[0], "PLAN_GAP"),
            "D-01 compiler PLAN_GAP identity mismatch"
        );

        ensure!(
            json_string(&handle, &["schema_version"])? == "eliot-development-evidence-handle-v1"
                && json_string(&handle, &["work_id"])? == "D-01"
                && json_string(&handle, &["plan_id"])? == "D-01:plan-v2",
            "D-01 evidence handle identity mismatch"
        );
        ensure!(
            json_string(&handle, &["durable_artifact", "sha256"])?
                == self.d01_report.expected_sha256
                && json_u64(&handle, &["durable_artifact", "byte_length"])?
                    == report_bytes.len() as u64,
            "D-01 evidence handle does not bind the exact report"
        );
        ensure!(
            json_u64(&handle, &["terminal_event", "sequence"])? == 8,
            "D-01 evidence handle terminal event mismatch"
        );

        ensure!(
            json_string(&checkpoint, &["schema_version"])?
                == "eliot-global-integration-checkpoint-v1"
                && json_u64(&checkpoint, &["checkpoint_sequence"])? == 1,
            "global integration checkpoint identity mismatch"
        );
        ensure!(
            json_string(&checkpoint, &["previous_checkpoint", "sha256"])?
                == self.checkpoint0.expected_sha256,
            "global integration checkpoint does not extend checkpoint 0"
        );
        ensure!(
            json_string(
                &checkpoint,
                &["d01_bootstrap_control", "evidence_handle_sha256"]
            )? == self.d01_handle.expected_sha256
                && json_string(
                    &checkpoint,
                    &["d01_bootstrap_control", "compiler_report_sha256"]
                )? == self.d01_report.expected_sha256,
            "global integration checkpoint evidence binding mismatch"
        );
        let event8_sha256 =
            json_string(&checkpoint, &["accepted_campaign_frontier", "event_sha256"])?;
        ensure!(
            json_string(&handle, &["terminal_event", "sha256"])? == event8_sha256,
            "D-01 evidence handle and checkpoint disagree on event 8"
        );
        ensure!(
            json_u64(
                &checkpoint,
                &["accepted_campaign_frontier", "through_sequence"]
            )? == 8,
            "global integration checkpoint frontier sequence mismatch"
        );

        ensure!(
            json_string(&event9, &["schema_version"])? == "eliot-bootstrap-campaign-event-v1"
                && json_u64(&event9, &["campaign_sequence"])? == 9
                && json_string(&event9, &["event_kind"])?
                    == "global_integration_checkpoint_recorded",
            "global integration checkpoint event identity mismatch"
        );
        ensure!(
            json_string(&event9, &["previous_segment_sha256"])? == event8_sha256,
            "global integration checkpoint event predecessor mismatch"
        );
        ensure!(
            json_string(&event9, &["checkpoint_sha256"])? == self.checkpoint.expected_sha256
                && json_string(&event9, &["evidence_handle_sha256"])?
                    == self.d01_handle.expected_sha256
                && json_string(&event9, &["compiler_report_sha256"])?
                    == self.d01_report.expected_sha256,
            "global integration checkpoint event evidence mismatch"
        );
        ensure!(
            sha256(&event9_bytes) == self.event9_head_sha256,
            "event-9 raw-byte hash mismatch"
        );
        ensure!(
            self.event9_head_sha256 == EVENT9_HEAD_SHA256,
            "event-9 head mismatch"
        );

        let expected_frontier = GitFrontierEvidence {
            head: json_string(&checkpoint, &["current_source_frontier", "head"])?.to_owned(),
            tree: json_string(&checkpoint, &["current_source_frontier", "tree"])?.to_owned(),
            branch: json_string(&checkpoint, &["current_source_frontier", "branch"])?.to_owned(),
            dirty_status_sha256: json_string(
                &checkpoint,
                &["current_source_frontier", "dirty_status_sha256"],
            )?
            .to_owned(),
        };
        ensure!(
            json_string(&event9, &["source_head"])? == expected_frontier.head,
            "checkpoint event source head mismatch"
        );
        ensure!(
            json_string(&handle, &["integrated_commit"])? == expected_frontier.head,
            "D-01 integrated commit differs from checkpoint frontier"
        );
        let checkpoint_root =
            json_string(&checkpoint, &["current_source_frontier", "repository_root"])?;
        ensure!(
            normalize_path(&self.repository_root) == checkpoint_root.replace('\\', "/"),
            "checkpoint repository root mismatch"
        );
        Self::verify_git_frontier(&self.repository_root, &expected_frontier)?;
        Ok(())
    }

    /// Compare recovery's claimed repository frontier against live Git. This
    /// is intentionally separate from JSON parsing so a caller cannot replace
    /// a live frontier with a projection string.
    pub fn verify_git_frontier(
        repository_root: impl AsRef<Path>,
        expected: &GitFrontierEvidence,
    ) -> Result<()> {
        let root = repository_root.as_ref();
        let git = |args: &[&str]| -> Result<String> {
            let output = Command::new("git").args(args).current_dir(root).output()?;
            ensure!(output.status.success(), "git command failed: {args:?}");
            Ok(String::from_utf8(output.stdout)?.trim().to_owned())
        };
        ensure!(
            git(&["rev-parse", "HEAD"])? == expected.head,
            "Git HEAD frontier mismatch"
        );
        ensure!(
            git(&["rev-parse", "HEAD^{tree}"])? == expected.tree,
            "Git tree frontier mismatch"
        );
        ensure!(
            git(&["branch", "--show-current"])? == expected.branch,
            "Git branch frontier mismatch"
        );
        let output = Command::new("git")
            .args(["status", "--porcelain=v1", "--untracked-files=all"])
            .current_dir(root)
            .output()?;
        ensure!(output.status.success(), "git status failed");
        let normalized = output
            .stdout
            .into_iter()
            .filter(|byte| *byte != b'\r')
            .collect::<Vec<_>>();
        ensure!(
            sha256(&normalized) == expected.dirty_status_sha256,
            "Git dirty frontier mismatch"
        );
        Ok(())
    }
}

fn json_value<'a>(value: &'a Value, path: &[&str]) -> Result<&'a Value> {
    let mut current = value;
    for key in path {
        current = current
            .get(*key)
            .with_context(|| format!("missing JSON field: {}", path.join(".")))?;
    }
    Ok(current)
}

fn json_string<'a>(value: &'a Value, path: &[&str]) -> Result<&'a str> {
    json_value(value, path)?
        .as_str()
        .with_context(|| format!("JSON field is not a string: {}", path.join(".")))
}

fn json_u64(value: &Value, path: &[&str]) -> Result<u64> {
    json_value(value, path)?
        .as_u64()
        .with_context(|| format!("JSON field is not an unsigned integer: {}", path.join(".")))
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// The A-04 public HTTP/OpenAPI/SSE route receipt, kept provider-neutral so
/// D-02 does not depend on A-04's Rust types or perform a live call itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeModelIdentity {
    #[serde(rename = "providerID", alias = "provider_id")]
    pub provider_id: String,
    #[serde(rename = "modelID", alias = "model_id")]
    pub model_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OpenCodeActualRouteState {
    Observed,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpenCodeActualRouteReceipt {
    pub requested: OpenCodeModelIdentity,
    pub observed: Option<OpenCodeModelIdentity>,
    pub provider: Option<String>,
    pub endpoint: Option<String>,
    pub route_fingerprint: Option<String>,
    pub session_id: Option<String>,
    pub directory: Option<String>,
    pub server_version: Option<String>,
    pub workspace_id: Option<String>,
    pub state: OpenCodeActualRouteState,
}

impl OpenCodeActualRouteReceipt {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.requested.provider_id.trim().is_empty(),
            "requested provider is required"
        );
        ensure!(
            !self.requested.model_id.trim().is_empty(),
            "requested model is required"
        );
        match self.state {
            OpenCodeActualRouteState::Observed => {
                let observed = self
                    .observed
                    .as_ref()
                    .context("observed route identity is missing")?;
                ensure!(
                    !observed.provider_id.trim().is_empty(),
                    "observed provider is required"
                );
                ensure!(
                    !observed.model_id.trim().is_empty(),
                    "observed model is required"
                );
                ensure!(
                    self.provider.as_deref() == Some(observed.provider_id.as_str()),
                    "observed provider differs from route identity"
                );
                let endpoint = self
                    .endpoint
                    .as_deref()
                    .context("observed endpoint is missing")?;
                ensure!(
                    is_loopback_endpoint(endpoint),
                    "observed endpoint is not loopback"
                );
                ensure!(
                    self.route_fingerprint
                        .as_deref()
                        .is_some_and(|v| !v.trim().is_empty()),
                    "observed route fingerprint is missing"
                );
                ensure!(
                    self.session_id
                        .as_deref()
                        .is_some_and(|v| !v.trim().is_empty()),
                    "observed session identity is missing"
                );
                ensure!(
                    self.directory
                        .as_deref()
                        .is_some_and(|v| Path::new(v).is_absolute()),
                    "observed directory must be absolute"
                );
                ensure!(
                    self.server_version
                        .as_deref()
                        .is_some_and(|v| !v.trim().is_empty()),
                    "observed server version is missing"
                );
            }
            OpenCodeActualRouteState::Unavailable => {
                ensure!(
                    self.observed.is_none()
                        && self.provider.is_none()
                        && self.endpoint.is_none()
                        && self.route_fingerprint.is_none()
                        && self.session_id.is_none()
                        && self.directory.is_none()
                        && self.server_version.is_none()
                        && self.workspace_id.is_none(),
                    "unavailable route carries observed identity"
                );
            }
        }
        Ok(())
    }
}

fn is_loopback_endpoint(endpoint: &str) -> bool {
    endpoint.starts_with("http://127.0.0.1:")
        || endpoint.starts_with("http://localhost:")
        || endpoint.starts_with("http://[::1]:")
}

/// Typed candidate-only result emitted by A-04 after HTTP/SSE reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenCodeHttpSseResult {
    pub status: String,
    pub candidate_only: bool,
    pub authority: String,
    pub actual_route: OpenCodeActualRouteReceipt,
    pub session_id: Option<String>,
    pub output: Option<Value>,
    #[serde(default)]
    pub events: Vec<Value>,
    #[serde(default)]
    pub diff: Vec<Value>,
}

#[derive(Debug, Clone)]
pub struct OpenCodeEvidence {
    pub result: OpenCodeHttpSseResult,
}

pub type OpenCodeHttpSseEvidence = OpenCodeEvidence;

impl OpenCodeEvidence {
    pub fn from_result(result: OpenCodeHttpSseResult) -> Self {
        Self { result }
    }

    pub fn verify(&self) -> Result<Value> {
        self.verify_with_policy(&OpenCodeRoutePolicy {
            model: PRIMARY_OPENCODE_MODEL.to_owned(),
        })
    }

    pub fn verify_with_policy(&self, policy: &OpenCodeRoutePolicy) -> Result<Value> {
        policy.verify()?;
        let result = &self.result;
        ensure!(
            result.candidate_only && result.authority == "candidate_only",
            "OpenCode result must remain candidate-only"
        );
        ensure!(
            matches!(
                result.status.as_str(),
                "succeeded" | "partial" | "failed" | "cancelled" | "unknown"
            ),
            "OpenCode result status is not typed"
        );
        result.actual_route.validate()?;
        ensure!(
            result.actual_route.requested.provider_id == PRIMARY_OPENCODE_PROVIDER_ID
                && result.actual_route.requested.model_id == PRIMARY_OPENCODE_MODEL_ID,
            "requested OpenCode provider/model differs from policy"
        );
        if let OpenCodeActualRouteState::Observed = result.actual_route.state {
            let observed = result
                .actual_route
                .observed
                .as_ref()
                .context("observed route identity is missing")?;
            ensure!(
                observed.provider_id == PRIMARY_OPENCODE_PROVIDER_ID
                    && observed.model_id == PRIMARY_OPENCODE_MODEL_ID,
                "observed OpenCode route differs from policy"
            );
            ensure!(
                result.session_id == result.actual_route.session_id,
                "result session differs from actual-route receipt"
            );
        }
        ensure!(
            result.diff.is_empty(),
            "OpenCode read-only result contains file diff"
        );
        serde_json::to_value(result).context("serialize OpenCode HTTP/SSE result")
    }
}

fn contains_string_value(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(actual) => actual == expected,
        Value::Object(object) => object
            .values()
            .any(|child| contains_string_value(child, expected)),
        Value::Array(values) => values
            .iter()
            .any(|child| contains_string_value(child, expected)),
        _ => false,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn fixture() -> CampaignLedger {
        let seed = json!({"controller_epoch":0,"campaign_id":"test"});
        let seed_digest = sha256(&canonical_bytes(&seed));
        let receipt = json!({"sequence":0,"seed_digest":seed_digest});
        CampaignLedger::from_seed_and_suffix(seed, receipt, Vec::new()).expect("genesis")
    }

    #[test]
    fn synthetic_ledger_cannot_bypass_bootstrap_adoption() {
        let mut ledger = fixture();
        let genesis = ledger.genesis().clone();
        assert!(
            ledger
                .adopt_epoch(EpochId::fresh(1).expect("fresh epoch"))
                .is_err()
        );
        assert_eq!(&genesis, ledger.genesis());
        assert!(
            ledger
                .adopt_epoch(EpochId::fresh(2).expect("fresh epoch"))
                .is_err()
        );
    }

    #[test]
    fn capability_shape_precedes_verified_executor_staffing() {
        let mut executor = CampaignExecutor::new(fixture());
        assert!(executor.staff_codex_slots().is_err());
        let probe = CapabilityProbe::post_adoption(1, 1, 1, 1, 1);
        probe.validate_before_staffing().expect("typed probe");
        assert_eq!(probe.codex_slot_ids.len(), 4);
        assert!(executor.record_capability_probe(probe).is_err());
    }

    #[test]
    fn opencode_lane_is_single_route_and_candidate_only() {
        let mut lane = OpenCodeLane::new();
        let primary = lane.admit_primary().expect("primary");
        assert_eq!(primary.launch.model, PRIMARY_OPENCODE_MODEL);
        assert!(
            serde_json::to_value(&primary.launch)
                .expect("json")
                .get("timeout")
                .is_none()
        );
        assert!(lane.disable("route is unavailable").is_err());
    }

    #[test]
    fn evidence_verifier_rejects_untrusted_recovery_contract() {
        let root = std::env::temp_dir().join(format!(
            "d02-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("mkdir");
        let write = |name: &str, bytes: &[u8]| {
            let path = root.join(name);
            fs::write(&path, bytes).expect("write");
            EvidenceFile {
                path,
                expected_sha256: sha256(bytes),
            }
        };
        let evidence = RecoveryEvidence {
            bootstrap_receipt: write("receipt", b"receipt"),
            checkpoint0: write("checkpoint0", b"checkpoint0"),
            d01_report: write("report", b"report frontier=HEAD"),
            d01_handle: write("handle", b"handle"),
            checkpoint: write("checkpoint", b"checkpoint"),
            event9: write("event9", b"event9"),
            repository_root: root.clone(),
            event9_head_sha256: EVENT9_HEAD_SHA256.to_owned(),
        };
        assert!(evidence.verify().is_err());
        let _ = fs::remove_dir_all(root);
    }
}
