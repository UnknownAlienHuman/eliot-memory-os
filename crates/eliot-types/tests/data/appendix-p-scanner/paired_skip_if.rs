// EXPECTED: default=1 form=paired paired=1 helper=0 bare-option=0
// unsupported-macro=0 unresolved=0 manual-visitor=0 raise=none
// keys=paired_skip_if.rs::Fixture.optional_note
// The paired form is a separate class, not a flavour of the direct form: this
// attribute carries default AND skip_serializing_if, but default and = are not
// adjacent, so it is Paired and not Helper. The Option member also carries the
// default token, so it is suppressed from the bare-option class and the two
// denominators cannot double-count one member.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fixture {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional_note: Option<String>,
    pub label: String,
}
