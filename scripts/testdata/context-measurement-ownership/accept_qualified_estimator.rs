// Bounded accept fixture: a qualified estimator carrying BOTH independent
// error directions, as I2.16 requires. An estimator is QUALIFIED_FOR_PROFILE
// only after measuring false-safe overflow/truncation AND false
// rejection/decomposition. Each direction has its own independent artifact id
// and its own evidence; neither is derived from the other.

pub struct EstimatorQualification {
    pub estimator_id: String,
    pub estimator_version: String,
    pub profile_tokenizer_hash: String,
    pub false_safe_overflow: Option<ArtifactId>,
    pub false_reject_or_unnecessary_decomposition: Option<ArtifactId>,
    pub absolute_error: u64,
    pub relative_error_micros: u64,
    pub valid_until: ArtifactId,
}

pub fn qualified_estimate(
    qualification: &EstimatorQualification,
    final_serialized_bytes: &[u8],
) -> Result<u64, ContextError> {
    // Both directions must be independently evidenced before any
    // QUALIFIED_FOR_PROFILE claim is honoured.
    if qualification.false_safe_overflow.is_none()
        || qualification.false_reject_or_unnecessary_decomposition.is_none()
    {
        return Err(ContextError::EstimatorNotQualified);
    }
    run_qualified_tokenizer(
        &qualification.estimator_id,
        &qualification.estimator_version,
        &qualification.profile_tokenizer_hash,
        final_serialized_bytes,
    )
}
