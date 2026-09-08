//! Typed local failures for the A14 evaluator.
use eliot_cue_contracts::CueContractError;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ActivationError {
    #[error("cue contract rejected {0}")]
    Contract(#[from] CueContractError),
    #[error("activation profile is incompatible with the candidate or request")]
    ProfileBinding,
    #[error("activation input is stale or unavailable for the requested fence")]
    StaleInput,
    #[error("activation input is unsupported by this bounded evaluator")]
    Unsupported,
    #[error("activation was cancelled before evaluation")]
    Cancelled,
    #[error("activation deadline has passed")]
    Deadline,
    #[error("activation bound exceeded for {field}")]
    Limit { field: &'static str },
}
