// Frozen fixture for #787 case 14: an UNVALIDATED STU labeled actual/proven-fit.
//
// The audit rejects "unvalidated estimates as ProvenFits/Safety-Floor
// proof/authority" and "bare numeric fit/admission claims without qualified
// measurement evidence". A normative STU estimate -- I2.16 says it is a
// planning fallback only -- is stored in a field that claims the safety floor
// is proven, and a bare numeric admission threshold is applied on top of it.
pub struct FitDecision {
    pub stu_estimate: u64,
    pub mandatory_floor_tokens: u64,
    pub proves_fit: bool,
    pub admit: bool,
}

pub fn decide_admission(stu: u64) -> FitDecision {
    let stu_estimate = stu;
    let mandatory_floor_tokens = stu * 4;
    FitDecision {
        stu_estimate,
        mandatory_floor_tokens,
        proves_fit: true,
        admit: mandatory_floor_tokens < 65_536,
    }
}
