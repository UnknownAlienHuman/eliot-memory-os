//! Exact record-to-view projection.

use eliot_context_contracts::{AdmittedContextSet, ContextError, RenderedAtom, SemanticRole};

use crate::AssemblyError;

/// The one rendered role order this execution path applies.
///
/// #1724 W4. The emitted order used to be whatever `SemanticRole`'s own derived
/// `Ord` happened to be, so the order a View's bytes are in was an accident of
/// the enum's declaration order. Nothing named that order, nothing compared it
/// with an approved recipe's declared layout, and a recipe publishing
/// `layout.role_positions` in the reverse order still validated, was certified
/// into `policy_sha256`, and was ignored by this projection. I12.13 makes the
/// ordering a property of a versioned `ContextRecipe`, so the order this path
/// applies is stated here as one explicit, published fact of the execution
/// owner, and the approved policy is compared against THAT value
/// (`ContextRecipePolicy::require_executable` against
/// `RecipeExecutionSupport::role_order`) rather than against an implicit sort.
///
/// This is the only ordering notion in this crate. `render` orders by a
/// position in this list and refuses a role the list does not cover, so a role
/// added to `SemanticRole` later stops being silently sorted into a payload
/// that claims to be `crate::ASSEMBLY_ORDERING_REVISION` output, instead of
/// producing a certified revision whose order nothing declared. Ordering a
/// policy declares that this list does not implement is refused at the recipe
/// boundary, not silently narrowed here: the approved `ContextRecipePolicy` is
/// not reachable from this projection, which receives only the
/// compilation-bound `ContextRecipe` instance and its own `AssemblyPolicy`.
///
/// The sequence below is the `SemanticRole` declaration order, so the bytes
/// this path emits today are unchanged; what changes is that the order is a
/// stated execution fact rather than a property of a derived `Ord`.
pub const EXECUTED_CONTEXT_ROLE_ORDER: [SemanticRole; 15] = [
    SemanticRole::Authority,
    SemanticRole::Goal,
    SemanticRole::Scope,
    SemanticRole::Acceptance,
    SemanticRole::Source,
    SemanticRole::Verifier,
    SemanticRole::MaterialUnknown,
    SemanticRole::Negative,
    SemanticRole::Security,
    SemanticRole::Evidence,
    SemanticRole::Instruction,
    SemanticRole::Optional,
    SemanticRole::Conflict,
    SemanticRole::Constraint,
];

/// Render under the executed role order, preserving every A-15 load-bearing
/// field.
///
/// `role_order` is the position order this path applies, and it is the caller's
/// executed order rather than a second derivation here: `render` reads the
/// positions it is given and refuses a record whose role that order does not
/// position, instead of falling back to the enum's own ordering for that one
/// record. Within one role, records keep the stable provider-then-atom order,
/// which is a total order over the atom identity rather than a policy setting.
pub(crate) fn render(
    admitted: &AdmittedContextSet,
    role_order: &[SemanticRole],
) -> Result<Vec<RenderedAtom>, AssemblyError> {
    let position = |role: &SemanticRole| -> Result<usize, AssemblyError> {
        role_order
            .iter()
            .position(|declared| declared == role)
            .ok_or(AssemblyError::Contract(ContextError::InvalidField(
                "assembly.render.role_order",
            )))
    };
    let mut ranked: Vec<(usize, RenderedAtom)> = Vec::with_capacity(admitted.records.len());
    for record in &admitted.records {
        let atom = RenderedAtom::from_admitted(record);
        ranked.push((position(&atom.role)?, atom));
    }
    ranked.sort_by(|(left_position, left), (right_position, right)| {
        left_position
            .cmp(right_position)
            .then_with(|| left.provider.cmp(&right.provider))
            .then_with(|| left.atom_id.cmp(&right.atom_id))
    });
    Ok(ranked.into_iter().map(|(_, atom)| atom).collect())
}