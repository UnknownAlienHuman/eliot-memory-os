// EXPECTED: default=0 form=none helper=0 paired=0 bare-option=0
// unsupported-macro=0 unresolved=0 manual-visitor=0 raise=none keys=(none)
// The most important positive control in this directory: it is what proves the
// oracle does not invent sites. A struct that declares no defaulted field, no
// bare Option member and no serde-like macro must yield ZERO sites in every
// class. The attribute below is deliberate: the attribute-span scanner must
// find the span, find no default token inside it, and record nothing. Every
// member type here is deliberately not a bare Option, so the bare-option
// denominator stays at zero too.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Fixture {
    pub label: String,
    pub revision: u32,
    pub enabled: bool,
}
