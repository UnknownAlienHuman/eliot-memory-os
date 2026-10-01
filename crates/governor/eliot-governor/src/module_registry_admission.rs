//! Compatibility export for the shared Module Catalog owner-readback seam.
//!
//! Validation and the verified lifecycle projection live with the canonical
//! module-registry contract so Governor and Kernel consumers use one validator.

pub use eliot_module_registry::{
    ModuleCatalogOwnerReadback, ModuleRegistryAdmissionError, VerifiedModuleCatalogGeneration,
};
