//! Deterministic measurement receipt: a canonical digest over every
//! load-bearing input and output.
//!
//! Identical semantic inputs produce identical digests regardless of
//! set-like order (cited estimator candidates are sorted before encoding),
//! and every load-bearing change alters the digest or fails validation.
//! The receipt proves measurement only, never completeness, delivery,
//! visibility, use, benefit or Finish.

use eliot_contracts::sha256_hex;

/// Every load-bearing field bound into one receipt digest.
#[derive(Clone, Debug)]
pub struct ReceiptInput {
    /// Stable measurement identity.
    pub measurement_id: String,
    /// Accepted A-15 revision spelling.
    pub contract_revision: String,
    /// Exact envelope digest and byte length.
    pub envelope_digest: String,
    /// Exact envelope byte length.
    pub byte_len: u64,
    /// Normative STU estimate.
    pub stu: u64,
    /// Serializer identity.
    pub serializer_id: String,
    /// Serializer revision.
    pub serializer_version: String,
    /// Serializer-options digest.
    pub serializer_options_digest: String,
    /// Route, provider and model identities.
    pub route_id: String,
    /// Provider identity.
    pub provider_id: String,
    /// Model identity.
    pub model_id: String,
    /// Tokenizer identity.
    pub tokenizer_id: String,
    /// Tokenizer revision.
    pub tokenizer_version: String,
    /// Tokenizer digest.
    pub tokenizer_hash: String,
    /// Tokenizer configuration digest.
    pub tokenizer_config_digest: String,
    /// Estimator identity and revision.
    pub estimator_id: String,
    /// Estimator revision.
    pub estimator_revision: String,
    /// Estimator empirical flag (always false: UNVALIDATED).
    pub estimator_empirical: bool,
    /// Cited candidate digests; sorted before encoding.
    pub candidate_digests: Vec<String>,
    /// Capacity unit wire spelling.
    pub capacity_unit: &'static str,
    /// Known route capacity, when known.
    pub route_capacity: Option<u64>,
    /// Independent reserves in fixed order: fixed, output, review, tool,
    /// verifier, decision-tail.
    pub reserves: [u64; 6],
    /// Decision-policy identity, when one is accepted.
    pub policy_id: Option<String>,
    /// Decision-policy digest, when one is accepted.
    pub policy_digest: Option<String>,
    /// Policy rate numerator/denominator, when accepted.
    pub policy_numer: Option<u64>,
    /// Policy rate denominator, when accepted.
    pub policy_denom: Option<u64>,
    /// Observation status wire spelling.
    pub observation_status: &'static str,
    /// Evidence source wire spelling, when an exact observation was supplied.
    pub source: Option<&'static str>,
    /// Observed count, when the observation is exact.
    pub observed_tokens: Option<u64>,
    /// Observation identity, when one was supplied.
    pub observation_id: Option<String>,
    /// Rewrite kind wire spelling, when transformed.
    pub rewrite_kind: Option<&'static str>,
    /// Rewrite evidence digest, when transformed.
    pub rewrite_evidence: Option<String>,
    /// Estimated total and fit, when known.
    pub estimated_total: Option<u64>,
    /// Estimated fit, when known.
    pub estimated_fit: Option<bool>,
    /// Observed total and fit, when known.
    pub observed_total: Option<u64>,
    /// Observed fit, when known.
    pub observed_fit: Option<bool>,
    /// False-safe overflow flag, when comparable.
    pub false_safe: Option<bool>,
    /// False-reject flag, when comparable.
    pub false_reject: Option<bool>,
}

/// Append one length-prefixed field so concatenation stays unambiguous.
fn push_field(out: &mut String, field: &str, value: &str) {
    out.push_str(field);
    out.push('\n');
    out.push_str(&value.len().to_string());
    out.push('\n');
    out.push_str(value);
    out.push('\n');
}

/// Append one optional field with an explicit present/absent marker.
fn push_optional(out: &mut String, field: &str, value: Option<String>) {
    match value {
        Some(text) => {
            push_field(out, field, "present");
            push_field(out, field, &text);
        }
        None => push_field(out, field, "absent"),
    }
}

/// Compute the canonical receipt digest for one receipt input.
pub fn receipt_digest(input: &ReceiptInput) -> String {
    let mut sorted_candidates = input.candidate_digests.clone();
    sorted_candidates.sort();
    let mut out = String::from("eliot-context-measurement-receipt/v1\n");
    push_field(&mut out, "measurement_id", &input.measurement_id);
    push_field(&mut out, "contract_revision", &input.contract_revision);
    push_field(&mut out, "envelope_digest", &input.envelope_digest);
    push_field(&mut out, "byte_len", &input.byte_len.to_string());
    push_field(&mut out, "stu", &input.stu.to_string());
    push_field(&mut out, "serializer_id", &input.serializer_id);
    push_field(&mut out, "serializer_version", &input.serializer_version);
    push_field(
        &mut out,
        "serializer_options_digest",
        &input.serializer_options_digest,
    );
    push_field(&mut out, "route_id", &input.route_id);
    push_field(&mut out, "provider_id", &input.provider_id);
    push_field(&mut out, "model_id", &input.model_id);
    push_field(&mut out, "tokenizer_id", &input.tokenizer_id);
    push_field(&mut out, "tokenizer_version", &input.tokenizer_version);
    push_field(&mut out, "tokenizer_hash", &input.tokenizer_hash);
    push_field(
        &mut out,
        "tokenizer_config_digest",
        &input.tokenizer_config_digest,
    );
    push_field(&mut out, "estimator_id", &input.estimator_id);
    push_field(&mut out, "estimator_revision", &input.estimator_revision);
    push_field(
        &mut out,
        "estimator_empirical",
        &input.estimator_empirical.to_string(),
    );
    push_field(
        &mut out,
        "candidate_count",
        &sorted_candidates.len().to_string(),
    );
    for candidate in &sorted_candidates {
        push_field(&mut out, "candidate_digest", candidate);
    }
    push_field(&mut out, "capacity_unit", input.capacity_unit);
    push_optional(
        &mut out,
        "route_capacity",
        input.route_capacity.map(|value| value.to_string()),
    );
    for (name, value) in [
        ("reserve.fixed_overhead", input.reserves[0]),
        ("reserve.output", input.reserves[1]),
        ("reserve.review", input.reserves[2]),
        ("reserve.tool_result", input.reserves[3]),
        ("reserve.verifier", input.reserves[4]),
        ("reserve.decision_tail", input.reserves[5]),
    ] {
        push_field(&mut out, name, &value.to_string());
    }
    push_optional(&mut out, "policy_id", input.policy_id.clone());
    push_optional(&mut out, "policy_digest", input.policy_digest.clone());
    push_optional(
        &mut out,
        "policy_numer",
        input.policy_numer.map(|value| value.to_string()),
    );
    push_optional(
        &mut out,
        "policy_denom",
        input.policy_denom.map(|value| value.to_string()),
    );
    push_field(&mut out, "observation_status", input.observation_status);
    push_optional(
        &mut out,
        "observation_source",
        input.source.map(str::to_owned),
    );
    push_optional(
        &mut out,
        "observed_tokens",
        input.observed_tokens.map(|value| value.to_string()),
    );
    push_optional(
        &mut out,
        "observation_id",
        input.observation_id.clone(),
    );
    push_optional(
        &mut out,
        "rewrite_kind",
        input.rewrite_kind.map(str::to_owned),
    );
    push_optional(
        &mut out,
        "rewrite_evidence",
        input.rewrite_evidence.clone(),
    );
    push_optional(
        &mut out,
        "estimated_total",
        input.estimated_total.map(|value| value.to_string()),
    );
    push_optional(
        &mut out,
        "estimated_fit",
        input.estimated_fit.map(|value| value.to_string()),
    );
    push_optional(
        &mut out,
        "observed_total",
        input.observed_total.map(|value| value.to_string()),
    );
    push_optional(
        &mut out,
        "observed_fit",
        input.observed_fit.map(|value| value.to_string()),
    );
    push_optional(
        &mut out,
        "false_safe",
        input.false_safe.map(|value| value.to_string()),
    );
    push_optional(
        &mut out,
        "false_reject",
        input.false_reject.map(|value| value.to_string()),
    );
    sha256_hex(out.as_bytes())
}
