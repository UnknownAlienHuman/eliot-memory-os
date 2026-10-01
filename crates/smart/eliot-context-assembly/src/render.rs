//! Exact record-to-view projection.

use std::collections::{BTreeMap, BTreeSet};

use eliot_context_contracts::{
    AdmittedContextSet, ContextError, ContextRecipePolicy, RenderedAtom, SemanticRole,
};

use crate::AssemblyError;

/// The rendered position each semantic role occupies in the approved policy.
///
/// #1724 W4. I12.13 makes the layout order a member of the approved recipe, so
/// the executed order is read off [`ContextRecipePolicy::layout`] rather than off
/// the [`SemanticRole`] enum's own ordinal: a revision that declares `Negative`
/// before `Goal` renders `Negative` first, because the revision says so. The enum
/// order is not consulted anywhere in this module.
///
/// Both declared-uniqueness properties are proved here rather than assumed, because
/// a tie has no executed order and this path must refuse it instead of resolving
/// it by a second, local rule: the position is a total order over the roles the
/// approved revision configures.
fn declared_positions(
    approved: &ContextRecipePolicy,
) -> Result<BTreeMap<SemanticRole, u32>, AssemblyError> {
    let mut positions: BTreeMap<SemanticRole, u32> = BTreeMap::new();
    let mut taken: BTreeSet<u32> = BTreeSet::new();
    for declared in &approved.layout.role_positions {
        if positions
            .insert(declared.semantic_role, declared.position)
            .is_some()
        {
            return Err(AssemblyError::Contract(ContextError::Duplicate(
                "assembly.layout.role_positions.semantic_role",
            )));
        }
        if !taken.insert(declared.position) {
            return Err(AssemblyError::Contract(ContextError::Duplicate(
                "assembly.layout.role_positions.position",
            )));
        }
    }
    Ok(positions)
}

/// Render in the order the approved recipe's layout policy declares.
///
/// The executed order is a function of the approved `ContextRecipePolicy`: role
/// order comes from its declared `layout.role_positions`, and only the two
/// intra-role tie-breaks — provider, then atom identity — remain this
/// projection's own, because no approved declaration separates two atoms of one
/// role. Every one of those three keys is certified content of the approved
/// revision, so a re-hashed revision that reverses the declared order changes the
/// rendered order and the `output_digest` with it, instead of being ignored.
///
/// Two declarations are refused rather than resolved locally, because both would
/// otherwise leave the executed order undefined while still being certified:
///
/// - a repeated role or a repeated position is
///   [`ContextError::Duplicate`];
/// - a rendered atom whose role the approved revision does not position is
///   [`ContextError::MissingField`]. Such a revision declares an order this
///   projection cannot execute, so the dependent compilation is blocked by name
///   instead of falling back to the enum order.
///
/// The refusal is the assembly owner's own typed
/// [`AssemblyError::Contract`] over the exact [`ContextError`], so it survives the
/// boundary and stays distinguishable from a measurement or bounds failure.
pub(crate) fn render(
    admitted: &AdmittedContextSet,
    approved: &ContextRecipePolicy,
) -> Result<Vec<RenderedAtom>, AssemblyError> {
    let positions = declared_positions(approved)?;
    let mut rendered: Vec<_> = admitted
        .records
        .iter()
        .map(RenderedAtom::from_admitted)
        .collect();
    for atom in &rendered {
        if !positions.contains_key(&atom.role) {
            return Err(AssemblyError::Contract(ContextError::MissingField(
                "assembly.layout.role_positions",
            )));
        }
    }
    rendered.sort_by(|left, right| {
        positions[&left.role]
            .cmp(&positions[&right.role])
            .then_with(|| left.provider.cmp(&right.provider))
            .then_with(|| left.atom_id.cmp(&right.atom_id))
    });
    Ok(rendered)
}
