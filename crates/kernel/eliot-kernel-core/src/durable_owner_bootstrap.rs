//! Canonical Governor owner bootstrap for the P-07 port.
//!
//! The production [`GrantActivationPort`](crate::grant_activation_port::GrantActivationPort)
//! serves closures from exactly one canonical owner: the durable Governor
//! grant graph at one exact revision. This module is the only production
//! constructor that binds the two together:
//!
//! ```text
//! Governor service durable state
//!   (grant-graph snapshot + current revocation history + admitted
//!    member/root/preserved material)
//! → GovernorClosureSource::restore (refuses absent history)
//! → exact-revision check against the daemon/service expectation
//! → durable per-root revision-watermark advance (atomic stale refusal)
//! → GrantActivationPort::with_durable_root_grant
//! ```
//!
//! Ownership stays exact:
//!
//! - the graph, revisions, snapshots, and member hydrations all arrive from
//!   the Governor service's canonical state using existing Governor
//!   authority types; the bootstrap invents no graph edge, member, root, or
//!   revision;
//! - the Kernel fences presented authority through the bound source and the
//!   durable watermark; it never re-derives lineage;
//! - rotation is an explicit [`BoundCanonicalOwner::refresh`] from newer
//!   durable state with monotonicity enforcement, never an incremental
//!   mutation: a stale expected revision refuses before the live source is
//!   touched.
//!
//! The daemon/service composition roots (`eliot-kernel`, `eliotd`) call
//! [`bind_canonical_owner`] at startup and [`BoundCanonicalOwner::refresh`]
//! on Governor-state rotation. Those call sites live in the composition
//! roots and are not implemented here.

use std::sync::Arc;

use eliot_ors::{OpaqueLabel, OperationalRecoveryStore};

use crate::error::{KernelError, validate_id};
use crate::governor_closure_source::{
    GovernorClosureRestore, GovernorClosureSource, GovernorClosureSourceHandle,
};
use crate::grant_activation_port::{GrantActivationPort, activation_bytes_equal};

/// Binds the canonical Governor owner to a fresh P-07 port at one exact
/// graph revision.
///
/// `expected_revision` is the daemon/service's durable expectation (Governor
/// manifest or the ORS revision watermark read before startup): the restored
/// graph revision must equal it exactly. A zero revision, an absent
/// revocation history, an invalid snapshot, admitted material that disagrees
/// with the graph, a revision disagreement, a stale presentation against the
/// durable watermark, or admitted bytes that disagree with an already-committed
/// durable row all refuse before any port is built.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] for a zero or disagreeing revision,
/// [`KernelError::RecoveryUnavailable`] for an unavailable history, invalid
/// snapshot, disagreeing material, or stale watermark presentation, and
/// [`KernelError::RecoveryState`] for an unusable ORS identity.
pub fn bind_canonical_owner(
    restore: GovernorClosureRestore,
    expected_revision: u64,
    store: Arc<dyn OperationalRecoveryStore>,
) -> Result<BoundCanonicalOwner, KernelError> {
    verify_bundle_provenance(&restore, &store)?;
    let bound_digest = owner_bundle_digest(&restore)?;
    let (source, roots) = checked_source(restore, expected_revision)?;
    let revoked_grants = source.revoked_grants();
    advance_revision_watermark(&store, &roots, expected_revision)?;
    let source_handle: GovernorClosureSourceHandle = Arc::new(source);
    let port = GrantActivationPort::with_durable_root_grant(
        Arc::clone(&source_handle)
            as Arc<dyn crate::grant_activation_port::RootGrantHydrationSource>,
        store,
    );
    port.rehydrate_committed_authority(&roots, expected_revision, &revoked_grants)?;
    Ok(BoundCanonicalOwner {
        port,
        source: source_handle,
        bound_revision: expected_revision,
        bound_roots: roots,
        bound_digest,
    })
}

/// The bound production owner: the P-07 port plus its canonical source.
///
/// The port shares the source behind [`GovernorClosureSourceHandle`], so a
/// [`refresh`](BoundCanonicalOwner::refresh) swaps the admitted state
/// atomically for every port operation that follows.
pub struct BoundCanonicalOwner {
    port: GrantActivationPort,
    source: GovernorClosureSourceHandle,
    bound_revision: u64,
    bound_roots: Vec<String>,
    bound_digest: String,
}

impl BoundCanonicalOwner {
    /// Returns the bound P-07 port.
    #[must_use]
    pub const fn port(&self) -> &GrantActivationPort {
        &self.port
    }

    /// Returns the shared canonical closure source.
    #[must_use]
    pub fn source(&self) -> &GovernorClosureSourceHandle {
        &self.source
    }

    /// Returns the exact graph revision this binding serves.
    #[must_use]
    pub const fn bound_revision(&self) -> u64 {
        self.bound_revision
    }

    /// Returns the admitted lineage roots this binding serves, in order.
    #[must_use]
    pub fn bound_roots(&self) -> &[String] {
        &self.bound_roots
    }

    /// Rebinds the owner from newer durable Governor state.
    ///
    /// The expected revision must be nonzero and must not move backwards
    /// from the current binding; the restore is validated on a shadow copy
    /// first, so a stale or disagreeing presentation refuses before the live
    /// source is touched. Admitted bytes are provenance-checked against
    /// durable readback exactly like at bind time. The durable per-root
    /// watermark advances atomically with the swap.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`bind_canonical_owner`], plus a stale
    /// refusal when `expected_revision` is below the current binding.
    pub fn refresh(
        &mut self,
        restore: GovernorClosureRestore,
        expected_revision: u64,
        store: &Arc<dyn OperationalRecoveryStore>,
    ) -> Result<(), KernelError> {
        if expected_revision < self.bound_revision {
            return Err(KernelError::InvalidField {
                field: "grant_graph_revision",
                reason: "owner refresh must not move the bound revision backwards",
            });
        }
        let candidate_digest = owner_bundle_digest(&restore)?;
        if expected_revision == self.bound_revision && candidate_digest != self.bound_digest {
            return Err(KernelError::RecoveryUnavailable(
                "same-revision owner refresh carries different canonical bytes".to_owned(),
            ));
        }
        verify_bundle_provenance(&restore, store)?;
        let (checked, roots) = checked_source(restore, expected_revision)?;
        let revoked_grants = checked.revoked_grants();
        let candidate_source: GovernorClosureSourceHandle = Arc::new(checked);
        advance_revision_watermark(store, &roots, expected_revision)?;
        let candidate_port = GrantActivationPort::with_durable_root_grant(
            Arc::clone(&candidate_source)
                as Arc<dyn crate::grant_activation_port::RootGrantHydrationSource>,
            Arc::clone(store),
        );
        candidate_port.rehydrate_committed_authority(&roots, expected_revision, &revoked_grants)?;
        self.source = candidate_source;
        self.port = candidate_port;
        self.bound_revision = self.source.revision();
        self.bound_digest = candidate_digest;
        self.bound_roots = self.source.authority_roots();
        Ok(())
    }

    /// Splits the binding into its port and shared source for service state.
    #[must_use]
    pub fn into_parts(self) -> (GrantActivationPort, GovernorClosureSourceHandle) {
        (self.port, self.source)
    }
}

/// Computes the canonical content digest of one owner bundle.
///
/// The Kernel composition records this digest beside the binding and the
/// daemon feed computes it before publishing; a readback digest comparison
/// then proves the Kernel bound the exact bundle the Governor served —
/// never merely the same revision. Both sides call this one definition
/// over the same bytes, so the digests agree by construction.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] when the bundle cannot be
/// rendered into canonical bytes.
pub fn owner_bundle_digest(restore: &GovernorClosureRestore) -> Result<String, KernelError> {
    let bytes =
        eliot_contracts::canonical_json_bytes(restore).map_err(|_| KernelError::InvalidField {
            field: "restore",
            reason: "owner bundle digest serialization failed",
        })?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

impl std::fmt::Debug for BoundCanonicalOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BoundCanonicalOwner")
            .field("bound_revision", &self.bound_revision)
            .field("bound_roots", &self.bound_roots)
            .finish_non_exhaustive()
    }
}

/// Restores the source and checks the exact revision and root expectations
/// without touching live state or the durable watermark.
fn checked_source(
    restore: GovernorClosureRestore,
    expected_revision: u64,
) -> Result<(GovernorClosureSource, Vec<String>), KernelError> {
    if expected_revision == 0 {
        return Err(KernelError::InvalidField {
            field: "grant_graph_revision",
            reason: "bound grant-graph revision must be nonzero",
        });
    }
    let source = GovernorClosureSource::restore(restore)?;
    let bound = source.revision();
    if bound != expected_revision {
        return Err(KernelError::InvalidField {
            field: "grant_graph_revision",
            reason: "restored owner revision disagrees with the bound revision",
        });
    }
    let roots = source.authority_roots();
    for root in &roots {
        validate_id(root, "restore.root.authority_root_ref")?;
    }
    Ok((source, roots))
}

/// Proves admitted-byte provenance against durable ORS readback before
/// the bundle becomes the trust anchor.
///
/// For every admitted grant member, root, and introduction that already
/// has a committed durable row, the presented bytes must agree byte-exactly
/// with the stored row: the row is the canonical provenance (committed
/// through the fenced port path with its own read-back), and disagreeing
/// bytes under a committed identity are a forgery or a fork, never a
/// refresh. Identities with no row yet are allowed through: their
/// provenance is established at commit time with exact read-back. Fenced
/// rows with identical bytes stay proven — fence evidence, not conflict.
///
/// # Errors
///
/// Returns [`KernelError::InvalidField`] when presented bytes disagree
/// with an already-committed durable row.
fn verify_bundle_provenance(
    restore: &GovernorClosureRestore,
    store: &Arc<dyn OperationalRecoveryStore>,
) -> Result<(), KernelError> {
    for member in restore
        .members
        .iter()
        .map(|member| (&member.intent, member.durable_record.record()))
        .chain(
            restore
                .roots
                .iter()
                .map(|root| (&root.intent, root.durable_record.record())),
        )
    {
        let (intent, record) = member;
        let subject = eliot_ors::OperationIdentity::new(&intent.grant_id)
            .map_err(KernelError::RecoveryState)?;
        if let Some(existing) = store
            .load_capability_grant(&subject)
            .map_err(KernelError::RecoveryState)?
            && existing.record() != record
            && !(existing.phase() == eliot_ors::OperationalPhase::Fenced
                && activation_bytes_equal(existing.record(), record))
        {
            return Err(KernelError::InvalidField {
                field: "restore.durable_record",
                reason: "admitted bytes disagree with the committed durable row",
            });
        }
    }
    for hydration in &restore.introductions {
        let subject = eliot_ors::OperationIdentity::new(&hydration.intent.introduction_id)
            .map_err(KernelError::RecoveryState)?;
        if let Some(existing) = store
            .load_capability_introduction(&subject)
            .map_err(KernelError::RecoveryState)?
            && existing.record() != hydration.durable_record.record()
            && !(existing.phase() == eliot_ors::OperationalPhase::Fenced
                && activation_bytes_equal(existing.record(), hydration.durable_record.record()))
        {
            return Err(KernelError::InvalidField {
                field: "restore.durable_record",
                reason: "admitted bytes disagree with the committed durable row",
            });
        }
    }
    Ok(())
}

/// Advances the durable per-root revision watermark and refuses a stale
/// presentation atomically: the stored value is the maximum of the retained
/// and presented revisions, so anything below the retained value fails
/// closed even across restarts.
fn advance_revision_watermark(
    store: &Arc<dyn OperationalRecoveryStore>,
    roots: &[String],
    revision: u64,
) -> Result<(), KernelError> {
    let revisions = roots
        .iter()
        .map(|root| OpaqueLabel::new(root).map(|label| (label, revision)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(KernelError::RecoveryState)?;
    store
        .note_grant_graph_revisions(&revisions)
        .map_err(KernelError::RecoveryState)
}
