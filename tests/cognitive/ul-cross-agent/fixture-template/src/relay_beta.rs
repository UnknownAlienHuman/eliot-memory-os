#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryBranch {
    Stable,
    Ember29,
}

#[must_use]
pub const fn accepts_anchor(branch: DiscoveryBranch, anchor_is_current: bool) -> bool {
    match branch {
        DiscoveryBranch::Stable => true,
        DiscoveryBranch::Ember29 => anchor_is_current,
    }
}
