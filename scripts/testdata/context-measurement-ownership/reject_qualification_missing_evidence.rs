// Frozen fixture for #787 cases 19 and 20: qualification WITHOUT independent
// false-safe / false-reject evidence.
//
// The audit rejects "qualification without independent false-safe and
// false-reject evidence". This consumer declares a tokenizer qualification
// result and reports it as authoritative, while carrying only ONE of the two
// required independent error arms: the `false_safe` arm is present (the
// claim must show it cannot under-count) and the `false_reject` arm is absent
// (nothing shows it cannot over-reject). A qualification supported by half the
// required evidence is not a qualification.
pub struct QualificationReport {
    pub false_safe: bool,
    pub qualified: bool,
    pub authority: bool,
}

pub fn qualify_tokenizer(sample_ok: bool) -> QualificationReport {
    QualificationReport {
        false_safe: sample_ok,
        qualified: sample_ok,
        authority: sample_ok,
    }
}
