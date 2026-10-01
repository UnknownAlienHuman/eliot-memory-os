//! Thin daemon composition entry for Governor-owned instrument registration.
//!
//! The daemon supplies its existing Governor composition and authenticated
//! named-read capability. All action, identity, WorkScope, task, write and
//! readback semantics remain in `eliot-governor`; this module only retains the
//! original committed proof for read-only stage consumers.

use eliot_governor::{
    InstrumentRegistryRegistrationAdmission, InstrumentRegistryRegistrationError,
    commit_instrument_registry_registration,
};
use eliot_store_api::CanonicalReadClient;

use crate::DaemonComposition;

impl DaemonComposition {
    /// Commits an already Governor-admitted instrument registry registration
    /// and retains the original receipt/readback as the sole stage-use proof.
    ///
    /// A second registration cannot silently replace the proof held by this
    /// composition; callers must start a new composition after changing the
    /// registered snapshot.
    pub async fn register_instrument_registry<R: CanonicalReadClient + ?Sized>(
        &mut self,
        admitted: &InstrumentRegistryRegistrationAdmission,
        read: &R,
    ) -> Result<(), InstrumentRegistryRegistrationError> {
        if self.instrument_registry_registration_proof().is_some() {
            return Err(InstrumentRegistryRegistrationError::Binding(
                "a registration proof is already retained by this daemon composition",
            ));
        }
        let proof = commit_instrument_registry_registration(
            &self.governor,
            admitted,
            read,
        )
        .await?;
        self.retain_instrument_registry_registration_proof(proof)
            .map_err(|_| {
                InstrumentRegistryRegistrationError::Binding(
                    "a competing registration proof was retained before this commit returned",
                )
            })
    }

}
