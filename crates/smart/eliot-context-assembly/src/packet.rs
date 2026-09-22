//! Packet-offset binding of rank traces into the assembled view.
//!
//! [`bind_packet_traces`] binds per-material trace handles — produced by the
//! admission-side rank-trace linkage — to the deterministic packet positions
//! of one [`ActiveUnderstandingView`](eliot_context_contracts::ActiveUnderstandingView).
//! Offsets index rendered order, which the renderer fixes by
//! role/provider/atom identity, so each offset names exactly one packet
//! position. The binding record addresses the view by its output digest and
//! carries its own content-addressed digest, resolving to exactly one view
//! revision and one trace set; a swapped view, slot, or handle fails
//! [`AssembledPacketBinding::validate`]. Assembly performs no retrieval,
//! ranking, or admission here: traces arrive fully formed from their owner,
//! and every rendered atom requires exactly one trace — never fewer, never
//! inferred.

use eliot_context_contracts::{ActiveUnderstandingView, ContextError, canonical_digest};
use eliot_contracts::{ArtifactId, DecisionId};
use serde::{Deserialize, Serialize};

use crate::AssemblyError;

/// Maximum packet slots admitted in one binding, mirroring the contracts
/// candidate-set bound so a binding can never outgrow the closure it binds.
pub const MAX_PACKET_SLOTS: usize = 4096;

/// One admitted packet slot binding a material to its packet position.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssembledPacketSlot {
    /// Deterministic position inside the rendered packet.
    pub offset: u32,
    /// Stable identity of the slotted material.
    pub atom_id: ArtifactId,
    /// Handle resolving to the material trace carrying the full evidence.
    pub trace_handle: String,
}

/// Digest-bound packet/trace binding for one assembled view revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssembledPacketBinding {
    /// Output digest of the exact view revision this binding resolves to.
    pub view_digest: String,
    /// Decision anchor locating the packet in its compilation.
    pub decision_id: DecisionId,
    /// Admitted packet slots in rendered order.
    pub slots: Vec<AssembledPacketSlot>,
    /// Content-addressed digest (`packet-binding:<sha256>`) of this record.
    pub binding_digest: String,
}

impl AssembledPacketBinding {
    /// Validate that the digest resolves to exactly this record with a
    /// gapless offset sequence over unique materials.
    pub fn validate(&self) -> Result<(), AssemblyError> {
        if self.binding_digest != packet_binding_digest(self)? {
            return Err(AssemblyError::Contract(ContextError::InvalidField(
                "packet_binding.digest",
            )));
        }
        let mut seen = std::collections::BTreeSet::new();
        for (index, slot) in self.slots.iter().enumerate() {
            let expected = u32::try_from(index).unwrap_or(u32::MAX);
            if slot.offset != expected || !seen.insert(slot.atom_id.clone()) {
                return Err(AssemblyError::Contract(
                    ContextError::SelectionIntegrityMismatch,
                ));
            }
        }
        Ok(())
    }
}

/// Derive the deterministic delivery digest for one packet binding.
///
/// The digest is content-addressed (`packet-binding:<sha256>`) over the
/// canonical bytes of the digest-cleared record, so it resolves to exactly
/// the bound view revision and slot set.
fn packet_binding_digest(binding: &AssembledPacketBinding) -> Result<String, AssemblyError> {
    let unsigned = AssembledPacketBinding {
        binding_digest: String::new(),
        ..binding.clone()
    };
    Ok(format!("packet-binding:{}", canonical_digest(&unsigned)?))
}

/// Bind per-material trace handles to the packet positions of one view.
///
/// Requires exactly one `(atom identity, trace handle)` pair per rendered
/// atom — a missing, duplicate, or foreign identity fails closed with
/// [`ContextError::SelectionIntegrityMismatch`], and a blank handle fails
/// with [`ContextError::InvalidField`]. Offsets follow rendered order.
/// Pure over its inputs: no retrieval, ranking, admission, or retention.
pub fn bind_packet_traces(
    view: &ActiveUnderstandingView,
    traces: &[(ArtifactId, String)],
) -> Result<AssembledPacketBinding, AssemblyError> {
    if view.rendered.len() > MAX_PACKET_SLOTS || traces.len() > MAX_PACKET_SLOTS {
        return Err(AssemblyError::Contract(ContextError::Bounds {
            field: "packet_binding.slots",
        }));
    }
    if view.rendered.len() != traces.len() {
        return Err(AssemblyError::Contract(
            ContextError::SelectionIntegrityMismatch,
        ));
    }
    let mut pairs = std::collections::BTreeMap::new();
    for (atom_id, handle) in traces {
        if handle.trim().is_empty() {
            return Err(AssemblyError::Contract(ContextError::InvalidField(
                "packet_binding.trace_handle",
            )));
        }
        if pairs.insert(atom_id.clone(), handle.clone()).is_some() {
            return Err(AssemblyError::Contract(ContextError::Duplicate(
                "packet_binding.atom_id",
            )));
        }
    }
    let mut slots = Vec::with_capacity(view.rendered.len());
    for (index, rendered) in view.rendered.iter().enumerate() {
        let handle = pairs
            .remove(&rendered.atom_id)
            .ok_or(AssemblyError::Contract(
                ContextError::SelectionIntegrityMismatch,
            ))?;
        slots.push(AssembledPacketSlot {
            offset: u32::try_from(index).unwrap_or(u32::MAX),
            atom_id: rendered.atom_id.clone(),
            trace_handle: handle,
        });
    }
    if !pairs.is_empty() {
        return Err(AssemblyError::Contract(
            ContextError::SelectionIntegrityMismatch,
        ));
    }
    let mut binding = AssembledPacketBinding {
        view_digest: view.output_digest.clone(),
        decision_id: view.binding.decision_id.clone(),
        slots,
        binding_digest: String::new(),
    };
    binding.binding_digest = packet_binding_digest(&binding)?;
    binding.validate()?;
    Ok(binding)
}
