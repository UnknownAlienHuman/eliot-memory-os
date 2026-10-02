// Frozen fixture for #787 case 21: a sum of ROUNDED parts labeled exact final
// tokens.
//
// The audit rejects "rounded component sums labeled exact final tokens". Each
// component is independently divided by four and rounded UP, and the rounded
// parts are then summed and presented as the EXACT final token count. Rounding
// each part before summing is not the same number as rounding the sum, so the
// aggregate is an estimate and can never carry an exact-observation label.
pub struct ComponentEstimate {
    pub system_hint: usize,
    pub history_hint: usize,
    pub tool_hint: usize,
}

pub fn exact_final_tokens(components: &ComponentEstimate) -> u64 {
    let system_hint = components.system_hint / 4;
    let history_hint = components.history_hint / 4;
    let tool_hint = components.tool_hint / 4;
    (system_hint + history_hint + tool_hint) as u64
}
