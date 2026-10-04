// EXPECTED: default=1 form=direct paired=0 helper=0 bare-option=0
// unsupported-macro=0 unresolved=0 manual-visitor=0 raise=none
// keys=direct_default_site.rs::Fixture.field_a
// default= counts every discovered default site; form= splits that one site by
// its recognised shape. One struct, one plain serde(default) on a String
// member, and no other absence shape anywhere in the file. The single site
// must resolve to a named member of a named type, so the unresolved sentinel
// must stay at zero.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fixture {
    #[serde(default)]
    pub field_a: String,
    pub field_b: u32,
}
