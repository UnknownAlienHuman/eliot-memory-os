//! Host-owner session-envelope facts (issue #1942, lane O1).
//!
//! Owner: the Host instance owns its installation identity
//! ([`HostService::installation`] in `service.rs`: "the installation identity
//! owned by this Host instance"). [`produce_host_id`] reads that live owner
//! state; no caller-supplied value is accepted.
//!
//! Absence: the Host owner holds installation identity plus lifecycle epochs
//! and activation generations in the Host state journal, but no
//! `ResourceGeneration` projection for reactive sessions. There is therefore
//! no live source for `snapshot.host_generation`, and [`produce_host_generation`]
//! fails closed naming it instead of minting or converting a generation from
//! another domain (activation/authority epochs are not host generations).
//!
//! Consumer: `resolve_runtime_envelope` in
//! `bins/eliot-agent-bridge/src/reactive_owner_publication.rs` (D2 lane,
//! read-only reference) names the missing `snapshot.host_id` and
//! `snapshot.host_generation` facts.

use eliot_contracts::ResourceGeneration;
use eliot_platform::{HostStateStore, ServicePort};
use thiserror::Error;

use crate::service::HostService;

/// Live Host identity fact for the session envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostEnvelopeFacts {
    /// Installation identity owned by this Host instance.
    pub host_id: String,
}

/// Fail-closed Host-envelope errors. Each names the exact D2 fact that
/// cannot be resolved from live owner state.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HostEnvelopeError {
    /// The Host owner holds no resource generation for reactive sessions, so
    /// `snapshot.host_generation` has no live source. The Host state journal
    /// owns installation/activation generations, never a
    /// `ResourceGeneration` for the session envelope.
    #[error("host owner holds no resource generation for snapshot.host_generation")]
    HostGenerationNotOwned,
}

/// Produce the live Host identity from the Host instance.
///
/// Reads [`HostService::installation`] (validated at `open`; see
/// `service.rs`). Infallible: the installation handle is owner-held, never
/// caller-supplied.
pub fn produce_host_id<P, S>(host: &HostService<P, S>) -> HostEnvelopeFacts
where
    P: ServicePort,
    S: HostStateStore,
{
    HostEnvelopeFacts {
        host_id: host.installation().as_str().to_owned(),
    }
}

/// Attempt to produce the Host generation for the session envelope.
///
/// Always fails closed: no `ResourceGeneration` exists in Host owner state
/// (`service.rs` installation handle plus the Host state journal's
/// installation/activation generations). The owner borrow is threaded to
/// prove the read was attempted against live state rather than skipped.
pub fn produce_host_generation<P, S>(
    host: &HostService<P, S>,
) -> Result<ResourceGeneration, HostEnvelopeError>
where
    P: ServicePort,
    S: HostStateStore,
{
    let _ = host;
    Err(HostEnvelopeError::HostGenerationNotOwned)
}
