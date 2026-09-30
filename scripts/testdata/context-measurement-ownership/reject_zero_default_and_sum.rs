// Bounded reject fixture: a missing tokenizer defaulted to zero, an
// unvalidated STU estimate labelled as an actual/proven-fit count, and a
// sum of rounded parts labelled as exact final tokens. All three are named
// prohibited constructs and must be rejected.

pub struct MeasurementOutcome {
    pub estimated_tokens: u64,
    pub actual_tokens: u64,
    pub proves_fit: bool,
    pub exact_final_tokens: u64,
}

pub fn measure_without_tokenizer(
    route: &Route,
    system_tokens: u64,
    history_tokens: u64,
    tool_tokens: u64,
) -> MeasurementOutcome {
    // A missing tokenizer is defaulted to zero rather than unknown.
    let actual_tokens = route.observed_tokens.unwrap_or(0);
    // A sum of independently rounded component parts is labelled exact.
    let exact_final_tokens = (system_tokens / 4 + history_tokens / 4 + tool_tokens / 4) * 4;
    // An unvalidated STU estimate is escalated to a proven fit.
    let estimated_tokens = exact_final_tokens;
    MeasurementOutcome {
        estimated_tokens,
        actual_tokens,
        proves_fit: estimated_tokens <= route.capacity,
        exact_final_tokens,
    }
}
