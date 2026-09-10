//! Errors for the pure `ArchitectureBrief` projection boundary.

/// The projection reuses the exact self-query contract error vocabulary.
///
/// Semantic outcomes such as `Partial`, `Blocked`, and `NoSource` are carried
/// by the candidate disposition; this error is reserved for malformed or
/// internally unrepresentable contract values.
pub use eliot_dreamer_contracts::SelfQueryContractError as ArchitectureBriefError;
