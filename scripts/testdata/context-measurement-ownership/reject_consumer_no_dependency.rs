// Bounded reject fixture: a consumer that measures without the canonical
// dependency or an exact approved adapter. The seam imports no canonical
// measurement crate and reaches a token count through a local ratio, so
// canonical measurement is used without its dependency.

pub fn context_cost_for_packet(packet: &ContextPacketL3) -> usize {
    let rendered = serde_json::to_vec(packet).unwrap_or_default();
    rendered.len().div_ceil(4)
}
