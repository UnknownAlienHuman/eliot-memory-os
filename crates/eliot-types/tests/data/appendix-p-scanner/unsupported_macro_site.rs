// EXPECTED: default=0 form=none helper=0 paired=0 bare-option=0
// unsupported-macro=1 unresolved=0 manual-visitor=0 raise=none keys=(none) detail=none
// unsupported-macro-key=unsupported_macro_site.rs:23:derive_serde_wire
// grade=unknown/BLOCKED/NOT_SAFE kind=unsupported-macro
// Deserialize is NOT derived here. A serde-like macro generates it, and
// neither scanner can resolve generated code, so the site names a position
// and never a field: it is held out of the field exception table by
// construction, which is the whole reason it is a separate denominator.
// Naming, derived from the owner patterns rather than invented: the
// unsupported pattern at owner:682 needs serde, deser or Deser at an offset
// PAST the first character of the macro name, and the three whole-name
// alternatives at owner:683 are make_deser, make_serde and
// serde_derive_magic. derive_serde_wire satisfies the first pattern and the
// oracle tail rule at the same time, so both must report exactly one site.
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct WireFixture {
    pub label: String,
    pub revision: u32,
}

derive_serde_wire!(WireFixture);
