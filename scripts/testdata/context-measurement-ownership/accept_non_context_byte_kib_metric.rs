// Frozen fixture for #787 case 24: an exact NON-CONTEXT byte/KiB/UI-character/
// line metric.
//
// The audit requires "True storage bytes/KiB, line and UI-character metrics
// require exact non-Context classification". This is a genuine, legitimate
// documentation/storage metric: it counts nonblank markdown LINES and sums
// description CHARACTERS for a listing, and never divides or relabels either
// as tokens or STU. The oracle must accept it -- classify it as a legitimate
// non-Context metric and raise no unit/name or proof-escalation finding.
pub fn count_skill_body_lines(body: &str) -> usize {
    body.lines().filter(|line| !line.trim().is_empty()).count()
}

pub fn sum_listing_characters(descriptions: &[&str]) -> usize {
    let mut total = 0usize;
    for description in descriptions {
        total += description.chars().count();
    }
    total
}

pub fn storage_kib(bytes: u64) -> u64 {
    bytes / 1024
}
