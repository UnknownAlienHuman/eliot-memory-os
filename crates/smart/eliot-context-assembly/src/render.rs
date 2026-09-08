//! Exact record-to-view projection.

use eliot_context_contracts::{AdmittedContextSet, RenderedAtom};

/// Render in the admitted order, preserving every A-15 load-bearing field.
pub(crate) fn render(admitted: &AdmittedContextSet) -> Vec<RenderedAtom> {
    let mut rendered: Vec<_> = admitted
        .records
        .iter()
        .map(RenderedAtom::from_admitted)
        .collect();
    rendered.sort_by(|left, right| {
        left.role
            .cmp(&right.role)
            .then_with(|| left.provider.cmp(&right.provider))
            .then_with(|| left.atom_id.cmp(&right.atom_id))
    });
    rendered
}
