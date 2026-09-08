//! A-12 cue binding candidate derivation over admitted observations.
#![forbid(unsafe_code)]
mod bounds;
mod contracts;
mod derive;
mod error;
pub use contracts::*;
pub use derive::derive_cue_binding_candidates;
pub use error::CueBindingError;
