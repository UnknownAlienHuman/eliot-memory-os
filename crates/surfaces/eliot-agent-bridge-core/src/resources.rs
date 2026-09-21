//! I7.18/I7.24 revisioned-resource read surface (A-16 bridge projection).
//!
//! Large or progressive data are addressed by immutable or revisioned
//! `eliot://` resources. Hot bridge responses carry only bounded previews
//! plus resource handles; full evidence, audit, and large-report content is
//! expanded explicitly. Tool-result projection records delivery completeness,
//! and a truncated delivery can never satisfy a complete-evidence requirement.
//!
//! This module owns no canonical state. The [`ResourceRegistry`] is a
//! bridge-local transport projection scoped to the current attach: entries are
//! content-addressed snapshots handed to the bridge by the owning provider,
//! cleared on every new attach, and resolvable only while attached. Canonical
//! ownership (tasks, evidence, store) stays with the existing owners; the
//! bridge never mints principal, Session, task, fence, or digest identity.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, de};
use sha2::{Digest, Sha256};

use crate::{BridgeError, validate_text};

/// Maximum preview bytes carried inline in a hot bridge response.
pub const MAX_PREVIEW_BYTES: usize = 1024;
/// Maximum immutable snapshots retained in one attach-scoped projection.
pub const MAX_REGISTRY_ENTRIES: usize = 128;
/// Maximum bytes accepted for one immutable snapshot.
pub const MAX_CONTENT_BYTES: usize = 1024 * 1024;
/// Maximum length of one validated `eliot://` URI.
pub const MAX_URI_BYTES: usize = 512;

const URI_SCHEME: &str = "eliot://";

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Canonical I7.18 resource family of one validated `eliot://` URI.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceKind {
    ScopeState,
    TaskPacket,
    Evidence,
    Conflict,
    Problem,
    SessionAttention,
    SessionMailbox,
    JobResult,
    Report,
    ArchitectureAnchor,
}

/// Validated canonical `eliot://` resource identity.
///
/// Only the ten I7.18 forms are admissible, with immutable IDs or explicit
/// revisions exactly where the contract demands them:
///
/// ```text
/// eliot://scope/<id>/state
/// eliot://task/<id>/packet/<revision>
/// eliot://evidence/<id>
/// eliot://conflict/<id>
/// eliot://problem/<id>
/// eliot://session/<id>/attention
/// eliot://session/<id>/mailbox
/// eliot://job/<id>/result
/// eliot://report/<id>
/// eliot://architecture/<revision>/<anchor>
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceUri {
    raw: String,
    kind: ResourceKind,
    revision: Option<String>,
}

impl Serialize for ResourceUri {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for ResourceUri {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(de::Error::custom)
    }
}

impl ResourceUri {
    /// Validates one canonical `eliot://` resource identity.
    pub fn parse(raw: impl Into<String>) -> Result<Self, BridgeError> {
        let raw = raw.into();
        parse_uri(&raw)
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }

    pub const fn kind(&self) -> ResourceKind {
        self.kind
    }

    /// Explicit revision for revisioned families (`task` packets and
    /// `architecture` anchors); `None` for immutable ID-only families.
    pub fn revision(&self) -> Option<&str> {
        self.revision.as_deref()
    }
}

impl std::fmt::Display for ResourceUri {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.raw)
    }
}

fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.len() <= 128
        && segment != "."
        && segment != ".."
        && segment.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
        })
}

fn parse_uri(raw: &str) -> Result<ResourceUri, BridgeError> {
    validate_text(raw, "resource_uri").map_err(|_| BridgeError::InvalidResourceUri {
        reason: "must be non-blank and contain no control characters",
    })?;
    if raw.len() > MAX_URI_BYTES {
        return Err(BridgeError::InvalidResourceUri {
            reason: "exceeds maximum URI length",
        });
    }
    let rest = raw
        .strip_prefix(URI_SCHEME)
        .ok_or(BridgeError::InvalidResourceUri {
            reason: "must use the eliot:// scheme",
        })?;
    if rest.bytes().any(|byte| byte.is_ascii_whitespace()) {
        return Err(BridgeError::InvalidResourceUri {
            reason: "must not contain whitespace",
        });
    }
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.iter().any(|segment| !valid_segment(segment)) {
        return Err(BridgeError::InvalidResourceUri {
            reason: "path segments must be non-empty portable identities",
        });
    }
    let (kind, revision) = match segments.as_slice() {
        ["scope", _, "state"] => (ResourceKind::ScopeState, None),
        ["task", _, "packet", revision] => (ResourceKind::TaskPacket, Some((*revision).to_owned())),
        ["evidence", _] => (ResourceKind::Evidence, None),
        ["conflict", _] => (ResourceKind::Conflict, None),
        ["problem", _] => (ResourceKind::Problem, None),
        ["session", _, "attention"] => (ResourceKind::SessionAttention, None),
        ["session", _, "mailbox"] => (ResourceKind::SessionMailbox, None),
        ["job", _, "result"] => (ResourceKind::JobResult, None),
        ["report", _] => (ResourceKind::Report, None),
        ["architecture", revision, _] => (
            ResourceKind::ArchitectureAnchor,
            Some((*revision).to_owned()),
        ),
        _ => {
            return Err(BridgeError::InvalidResourceUri {
                reason: "not a canonical I7.18 resource form",
            });
        }
    };
    Ok(ResourceUri {
        raw: raw.to_owned(),
        kind,
        revision,
    })
}

/// Immutable bridge-local handle: the canonical URI plus the exact SHA-256
/// digest of the referenced content bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceHandle {
    uri: ResourceUri,
    digest: String,
}

impl ResourceHandle {
    pub(crate) fn bind(uri: ResourceUri, content: &[u8]) -> Self {
        Self {
            uri,
            digest: sha256_hex(content),
        }
    }

    pub fn uri(&self) -> &ResourceUri {
        &self.uri
    }

    /// Exact lowercase SHA-256 hex of the immutable referenced content.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

/// Bounded hot-response projection: a preview plus the handle for explicit
/// expansion. `preview` never exceeds [`MAX_PREVIEW_BYTES`]; anything beyond
/// it is retrievable only through [`ResourceRegistry::expand`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HotResourceView {
    handle: ResourceHandle,
    kind: ResourceKind,
    preview: Vec<u8>,
    total_bytes: usize,
    is_truncated: bool,
}

impl HotResourceView {
    pub fn handle(&self) -> &ResourceHandle {
        &self.handle
    }

    pub const fn kind(&self) -> ResourceKind {
        self.kind
    }

    pub fn preview(&self) -> &[u8] {
        &self.preview
    }

    pub const fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    /// Whether the hot response withheld bytes behind the handle.
    pub const fn is_truncated(&self) -> bool {
        self.is_truncated
    }
}

/// Byte prefix of `content` that fits the hot path, cut back to a UTF-8
/// character boundary when the content is text.
fn truncate_preview(content: &[u8]) -> &[u8] {
    let mut end = content.len().min(MAX_PREVIEW_BYTES);
    if end < content.len() && std::str::from_utf8(content).is_ok() {
        // Valid UTF-8 text: step back over every non-ASCII byte to land on a
        // character boundary (possibly dropping one split character).
        while end > 0 && content[end - 1] >= 0x80 {
            end -= 1;
        }
    }
    &content[..end]
}

/// Attach-scoped transport projection of immutable resource snapshots.
///
/// Entries are content-addressed: republishing the same URI with different
/// bytes is rejected, so a handle always resolves to the exact bytes its
/// digest names. The registry is cleared on every new attach and resolves
/// only through the attached bridge methods, which is the scope
/// authorization on resolution: no attach, no resolution.
#[derive(Clone, Debug, Default)]
pub struct ResourceRegistry {
    entries: BTreeMap<String, Vec<u8>>,
}

impl ResourceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    /// Publishes one canonical resource snapshot and returns its bounded
    /// hot-response projection (preview plus handle).
    pub fn publish(
        &mut self,
        uri: &ResourceUri,
        content: Vec<u8>,
    ) -> Result<HotResourceView, BridgeError> {
        if content.len() > MAX_CONTENT_BYTES {
            return Err(BridgeError::ResourceTooLarge {
                bytes: content.len(),
                capacity: MAX_CONTENT_BYTES,
            });
        }
        if let Some(previous) = self.entries.get(uri.as_str()) {
            if *previous != content {
                return Err(BridgeError::ResourceImmutableConflict);
            }
            return Ok(hot_view(uri, previous));
        }
        if self.entries.len() >= MAX_REGISTRY_ENTRIES {
            return Err(BridgeError::ResourceRegistryFull {
                capacity: MAX_REGISTRY_ENTRIES,
            });
        }
        let view = hot_view(uri, &content);
        self.entries.insert(uri.as_str().to_owned(), content);
        Ok(view)
    }

    /// Publishes one large evidence snapshot under its content digest, so the
    /// `eliot://evidence/<id>` handle is immutable by construction. Returns
    /// the bounded preview plus the handle; the full bytes require explicit
    /// [`ResourceRegistry::expand`].
    pub fn publish_evidence(&mut self, content: Vec<u8>) -> Result<HotResourceView, BridgeError> {
        let uri = ResourceUri::parse(format!("{URI_SCHEME}evidence/{}", sha256_hex(&content)))?;
        self.publish(&uri, content)
    }

    /// Explicitly expands one previously published handle to its immutable
    /// referenced content. Unknown handles and digest mismatches fail closed.
    pub fn expand(&self, handle: &ResourceHandle) -> Result<Vec<u8>, BridgeError> {
        let stored = self.entries.get(handle.uri().as_str()).ok_or_else(|| {
            BridgeError::UnknownResource {
                uri: handle.uri().as_str().to_owned(),
            }
        })?;
        if sha256_hex(stored) != handle.digest {
            return Err(BridgeError::ResourceDigestMismatch);
        }
        Ok(stored.clone())
    }
}

fn hot_view(uri: &ResourceUri, content: &[u8]) -> HotResourceView {
    let preview = truncate_preview(content);
    HotResourceView {
        handle: ResourceHandle::bind(uri.clone(), content),
        kind: uri.kind(),
        preview: preview.to_vec(),
        total_bytes: content.len(),
        is_truncated: preview.len() < content.len(),
    }
}

/// Tool-result delivery completeness, measured separately from transport
/// completion. Mirrors the I7.24 result receipt vocabulary.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeliveryStatus {
    Full,
    Partial,
    Truncated,
    Missing,
}

/// Projected tool-result receipt: exact result digest, admissible source
/// handle, rendered bytes, tokens rendered under the actual route tokenizer,
/// and delivery completeness.
///
/// The bridge never estimates tokens: `tokens_rendered` is the count measured
/// by the projecting owner with the route's actual tokenizer. A truncated
/// delivery keeps its digest and measured cost so a verifier can cite what
/// was actually delivered instead of mistaking it for complete evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResultReceipt {
    result_digest: String,
    source_handle: ResourceUri,
    bytes_rendered: usize,
    tokens_rendered: u64,
    delivery: DeliveryStatus,
}

impl ToolResultReceipt {
    /// Projects one tool result. The digest is computed over the exact
    /// delivered bytes, so it always names what was rendered, including for
    /// `PARTIAL`, `TRUNCATED`, and `MISSING` deliveries.
    pub fn project(
        result_bytes: &[u8],
        source_handle: ResourceUri,
        tokens_rendered: u64,
        delivery: DeliveryStatus,
    ) -> Self {
        Self {
            result_digest: sha256_hex(result_bytes),
            source_handle,
            bytes_rendered: result_bytes.len(),
            tokens_rendered,
            delivery,
        }
    }

    /// Exact lowercase SHA-256 hex of the delivered result bytes.
    pub fn result_digest(&self) -> &str {
        &self.result_digest
    }

    pub fn source_handle(&self) -> &ResourceUri {
        &self.source_handle
    }

    pub const fn bytes_rendered(&self) -> usize {
        self.bytes_rendered
    }

    pub const fn tokens_rendered(&self) -> u64 {
        self.tokens_rendered
    }

    pub const fn delivery(&self) -> DeliveryStatus {
        self.delivery
    }

    /// Complete-evidence gate: only a `FULL` delivery satisfies a
    /// complete-evidence or verifier prerequisite. `PARTIAL`, `TRUNCATED`,
    /// and `MISSING` results fail closed.
    pub fn check_complete_evidence(&self) -> Result<(), BridgeError> {
        match self.delivery {
            DeliveryStatus::Full => Ok(()),
            delivery => Err(BridgeError::IncompleteDelivery { delivery }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_forms_parse_with_expected_kind_and_revision() -> Result<(), BridgeError> {
        let uri = ResourceUri::parse("eliot://task/t-1/packet/r-7")?;
        assert_eq!(uri.kind(), ResourceKind::TaskPacket);
        assert_eq!(uri.revision(), Some("r-7"));
        let uri = ResourceUri::parse("eliot://session/s-1/mailbox")?;
        assert_eq!(uri.kind(), ResourceKind::SessionMailbox);
        assert_eq!(uri.revision(), None);
        let uri = ResourceUri::parse("eliot://architecture/0.29-draft/anchor")?;
        assert_eq!(uri.kind(), ResourceKind::ArchitectureAnchor);
        assert_eq!(uri.revision(), Some("0.29-draft"));
        Ok(())
    }

    #[test]
    fn non_canonical_or_unrevised_forms_are_rejected() {
        for raw in [
            "https://evidence/1",
            "eliot://evidence/",
            "eliot://task/t-1/packet",
            "eliot://task/t-1",
            "eliot://architecture/anchor",
            "eliot://unknown/1",
            "eliot://evidence/../escape",
        ] {
            assert!(
                ResourceUri::parse(raw).is_err(),
                "must reject canonical violation: {raw}"
            );
        }
    }

    #[test]
    fn preview_cut_keeps_utf8_boundary() {
        let mut content = vec![b'a'; MAX_PREVIEW_BYTES - 2];
        content.extend_from_slice("héllo".as_bytes());
        while content.len() <= MAX_PREVIEW_BYTES + 8 {
            content.extend_from_slice("héllo".as_bytes());
        }
        let preview = truncate_preview(&content);
        assert!(preview.len() <= MAX_PREVIEW_BYTES);
        assert!(std::str::from_utf8(preview).is_ok());
    }
}
