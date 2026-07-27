#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryBranch {
    Stable,
    Frost17,
}

#[must_use]
pub const fn next_retry_state(branch: RetryBranch, frame_owner_matches: bool) -> bool {
    match branch {
        RetryBranch::Stable => true,
        RetryBranch::Frost17 => frame_owner_matches,
    }
}
