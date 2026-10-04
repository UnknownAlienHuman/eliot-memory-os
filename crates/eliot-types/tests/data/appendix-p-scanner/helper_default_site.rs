// EXPECTED: default=1 form=helper helper=1 paired=0 bare-option=0
// unsupported-macro=0 unresolved=0 manual-visitor=0 raise=none
// keys=helper_default_site.rs::Fixture.probe_depth
// The helper form, recognised by shape and not by name: the tokens default and
// = must be ADJACENT, which is what separates this from the direct form. The
// helper name follows the frozen-domain convention
// default_<member_in_snake_case>, which is the shape the oracle expects from a
// live site rather than an invented spelling. The helper is defined here, so
// the file is honest Rust and the attribute resolves.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fixture {
    pub label: String,
    #[serde(default = "default_probe_depth")]
    pub probe_depth: u8,
}

const fn default_probe_depth() -> u8 {
    8
}
