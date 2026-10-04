// EXPECTED: default=0 form=none helper=0 paired=0 bare-option=1
// unsupported-macro=0 unresolved=0 manual-visitor=0 raise=none
// keys=bare_option_site.rs::Fixture.note
// bare-option-line=bare_option_site.rs:16
// One bare Option member carrying no serde token at all. serde emits a
// missing_field error whose deserializer visits None for a missing Option, so
// absence decodes to None instead of being refused, and this shape is a site
// with no default attribute anywhere near it. No default site may be invented
// from it: the default denominator and the bare-option denominator are two
// independent reads of one masked pass.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fixture {
    pub label: String,
    pub note: Option<String>,
}
