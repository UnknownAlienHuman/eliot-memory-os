// Frozen fixture for #787 case 27: an unvalidated STU estimate accepted ONLY
// at the estimate proof ceiling.
//
// I2.16 is explicit that a normative STU estimate is a planning fallback. It
// is allowed -- but only as an ESTIMATE, with the unknown actual count left
// unknown. This fixture carries the STU estimate under an honest estimate
// field name, records the actual count as explicitly unknown rather than
// zero, and makes no fit/admission claim. The oracle must accept it with no
// PROOF_ESCALATION, proving the acceptance ceiling is the estimate itself.
pub struct StuEstimateRecord {
    pub stu_estimate: u64,
    pub actual_known: bool,
    pub admits: bool,
}

pub fn estimate_only(byte_count: u64) -> StuEstimateRecord {
    let stu_estimate = byte_count.div_ceil(3);
    StuEstimateRecord {
        stu_estimate,
        actual_known: false,
        admits: false,
    }
}
