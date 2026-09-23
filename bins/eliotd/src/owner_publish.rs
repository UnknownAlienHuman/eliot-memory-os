//! O1-owned daemon OwnerPublishPort: typed front-door publish/readback calls
//! against the Kernel P-07 owner route (issue #2100 owner-closure feed).
//!
//! [`DaemonOwnerPublishPort`] implements
//! [`OwnerPublishPort`](eliot_governor::owner_closure_feed::OwnerPublishPort)
//! over [`DaemonKernelClient`] with the exact wire shapes the Kernel route
//! serves (`publish_owner_bundle` receipt, `query_owner_bundle`
//! readback). It mints nothing, stores nothing, and interprets nothing:
//! transport failures surface with their exact detail, and the owning
//! feed (`synchronize_owner_feed`) performs every comparison that decides
//! whether a publish committed. Daemon errors crossing into Governor
//! territory unwrap back to their inner composition error when they came
//! from one, and otherwise surface as recovery detail with the full
//! daemon-side context preserved.

use eliot_governor::OwnerPublishPort;
use eliot_governor::CompositionError;
use eliot_kernel_core::GovernorClosureRestore;

use super::{DaemonError, DaemonKernelClient};

/// Daemon Kernel client bound as the Governor owner publish port.
///
/// Constructed per trigger evaluation over the already-connected client;
/// holds no state beyond the borrow, retains no bundle, and spawns no
/// task. The client borrow keeps the authenticated session proof with the
/// transport that owns it.
pub struct DaemonOwnerPublishPort<'a> {
    kernel: &'a DaemonKernelClient,
}

impl<'a> DaemonOwnerPublishPort<'a> {
    /// Binds the live client as the publish port for one trigger evaluation.
    #[must_use]
    pub const fn new(kernel: &'a DaemonKernelClient) -> Self {
        Self { kernel }
    }
}

/// Unwraps a daemon error back to its inner composition error when it came
/// from one; any other daemon failure surfaces as recovery detail with the
/// full daemon-side context (transport vs lifecycle vs config) preserved in
/// the message instead of flattened.
fn daemon_to_composition(error: DaemonError) -> CompositionError {
    match error {
        DaemonError::Composition(inner) => inner,
        other => CompositionError::Recovery(other.to_string()),
    }
}

impl OwnerPublishPort for DaemonOwnerPublishPort<'_> {
    async fn publish_owner_bundle(
        &self,
        bundle: GovernorClosureRestore,
        expected_revision: u64,
    ) -> Result<u64, CompositionError> {
        self.kernel
            .publish_owner_bundle(bundle, expected_revision)
            .await
            .map_err(daemon_to_composition)
    }

    async fn query_owner_readback(
        &self,
    ) -> Result<(bool, Option<u64>, Option<String>), CompositionError> {
        self.kernel
            .query_owner_readback()
            .await
            .map_err(daemon_to_composition)
    }
}
