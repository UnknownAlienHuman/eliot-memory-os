//! Governor-owned attachment ownership domains (issue #2017 item 3).
//!
//! This module names the four ownership domains over which swarm plan to
//! durable-job singularity must hold, and records exactly which of them the
//! current single-service implementation covers.
//!
//! Domains:
//! - `Process`: one winner per plan key inside one service/store image. Holds
//!   now through [`SwarmPlanAttachmentService`](super::SwarmPlanAttachmentService)
//!   over one [`CanonicalSwarmPlanAttachmentStore`](super::CanonicalSwarmPlanAttachmentStore):
//!   lookup plus insert run inside a single critical section and every
//!   unbound-to-bound success escapes only after the conditional commit
//!   reports committed.
//! - `Daemon`: one winner per plan key across every thread/task owned by one
//!   daemon process. Holds once the daemon owns exactly one
//!   [`SwarmAttachmentComposition`](super::SwarmAttachmentComposition) (one
//!   service instance) and routes every swarm consumer through it; two
//!   independently constructed services in one daemon are two owners and prove
//!   nothing about each other.
//! - `Host`: one winner per plan key across daemon restarts on one host.
//!   Deferred: restart recovery rebuilds the owner from its snapshot, but the
//!   snapshot has no host-durable home yet. Like slice 2, this module does not
//!   fake durability: it names the deferred envelope wiring instead.
//! - `CrossProcessDurable`: one winner per plan key across processes/hosts
//!   through the canonical write path. Deferred until the daemon composes the
//!   mapped revision/ordering expectations
//!   ([`CanonicalSwarmPlanAttachmentStore::revision_expectations`](super::CanonicalSwarmPlanAttachmentStore::revision_expectations)
//!   /
//!   [`CanonicalSwarmPlanAttachmentStore::ordering_expectations`](super::CanonicalSwarmPlanAttachmentStore::ordering_expectations))
//!   into a real `CanonicalWriteEnvelope` and every writer routes through it.
//!   Contention then reloads and observes `OwnershipConflict` naming the
//!   canonical winner instead of escaping with a second success.
//!
//! Honest scope: single-service ownership until the envelope wiring lands.
//! The composition in
//! [`swarm_plan_attachment_composition`](super::swarm_plan_attachment_composition)
//! owns one service instance (process scope, daemon scope once the daemon owns
//! exactly one composition); host and cross-process composition is remainder,
//! not claimed here.

use eliot_coordination::{SwarmPlanAttachmentError, SwarmPlanBinding};

/// One ownership domain over which plan-to-job singularity must hold.
///
/// The ordering is widening: each larger domain contains the smaller ones. A
/// claim about a larger domain requires everything the smaller ones require,
/// plus the named durable wiring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentOwnershipDomain {
    /// One winner per plan key inside one service/store image. Holds now.
    Process,
    /// One winner per plan key across one daemon's threads/tasks. Holds once
    /// the daemon owns exactly one composition and routes every consumer
    /// through it.
    Daemon,
    /// One winner per plan key across daemon restarts on one host. Deferred:
    /// no host-durable snapshot home exists yet.
    Host,
    /// One winner per plan key across processes/hosts via the canonical write
    /// path. Deferred until the daemon wires the mapped expectations into a
    /// real envelope write.
    CrossProcessDurable,
}

impl AttachmentOwnershipDomain {
    /// Returns whether the current single-service implementation covers this
    /// domain without further wiring.
    #[must_use]
    pub const fn covered_in_process(self) -> bool {
        matches!(self, Self::Process)
    }
}

/// The exact single-service ownership scope one composition instance covers.
///
/// This is the process-domain claim: one service, one store image, one winner
/// per plan key. Two independently constructed scopes are two owners; a second
/// job bound through a different scope is out of scope for this claim and is
/// precisely why the daemon must own exactly one composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttachmentOwnershipScope {
    domain: AttachmentOwnershipDomain,
    /// Number of service instances covered by this scope. Always one: the
    /// composition owns a single service, never a pool.
    services: usize,
}

impl AttachmentOwnershipScope {
    /// The process-domain scope one composition instance covers.
    #[must_use]
    pub const fn single_service() -> Self {
        Self {
            domain: AttachmentOwnershipDomain::Process,
            services: 1,
        }
    }

    /// The ownership domain this scope covers.
    #[must_use]
    pub const fn domain(self) -> AttachmentOwnershipDomain {
        self.domain
    }

    /// The number of service instances covered. Always one.
    #[must_use]
    pub const fn services(self) -> usize {
        self.services
    }
}

impl Default for AttachmentOwnershipScope {
    fn default() -> Self {
        Self::single_service()
    }
}

/// Classifies a bind refusal inside the covered process domain.
///
/// A conflict carries the canonical winner already recorded for the plan key;
/// every other decision failure (invalid input, invalid snapshot image)
/// carries through unchanged. Failures outside the covered domain (host or
/// cross-process contention once the envelope wiring lands) surface through
/// the store boundary, never here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnershipOutcome {
    /// The bind committed (or identically replayed) inside this scope.
    Bound(SwarmPlanBinding),
    /// The plan key is already bound to a different exact binding: the
    /// payload is the canonical winner.
    Conflict {
        /// The canonical binding already recorded for this plan key.
        existing: SwarmPlanBinding,
    },
}

impl OwnershipOutcome {
    /// Splits a canonical attach result into the covered-domain outcome.
    pub fn from_attach(
        result: Result<SwarmPlanBinding, SwarmPlanAttachmentError>,
    ) -> Result<Self, SwarmPlanAttachmentError> {
        match result {
            Ok(binding) => Ok(Self::Bound(binding)),
            Err(SwarmPlanAttachmentError::OwnershipConflict { existing }) => {
                Ok(Self::Conflict { existing })
            }
            Err(other) => Err(other),
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn only_process_domain_is_covered_in_process() {
        assert!(AttachmentOwnershipDomain::Process.covered_in_process());
        for domain in [
            AttachmentOwnershipDomain::Daemon,
            AttachmentOwnershipDomain::Host,
            AttachmentOwnershipDomain::CrossProcessDurable,
        ] {
            assert!(
                !domain.covered_in_process(),
                "wider domain must stay deferred: {domain:?}"
            );
        }
    }

    #[test]
    fn single_service_scope_covers_exactly_one_service() {
        let scope = AttachmentOwnershipScope::single_service();
        assert_eq!(scope.domain(), AttachmentOwnershipDomain::Process);
        assert_eq!(scope.services(), 1);
        assert_eq!(scope, AttachmentOwnershipScope::default());
    }
}
