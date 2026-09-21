//! Seeded deterministic random number generator.
//!
//! [`SimRng`] is `SplitMix64`: a tiny, fully specified, allocation-free
//! stream. Every draw is a pure function of the seed and the draw count, so
//! two schedulers built from the same seed produce the same nonces, the same
//! background jitter, and therefore the same schedule. There is no wall
//! clock, no thread-local state, and no operating-system entropy involved.

/// Deterministic `SplitMix64` stream derived from one seed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SimRng(u64);

impl SimRng {
    /// Builds the stream for `seed`.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// Returns the next word of the stream.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut word = self.0;
        word = (word ^ (word >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        word = (word ^ (word >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        word ^ (word >> 31)
    }

    /// Returns a value in `0..bound`. A zero bound yields zero.
    pub fn below(&mut self, bound: u64) -> u64 {
        if bound == 0 {
            return 0;
        }
        self.next_u64() % bound
    }
}

#[cfg(test)]
mod tests {
    use super::SimRng;

    #[test]
    fn same_seed_yields_same_stream() {
        let mut left = SimRng::new(1916);
        let mut right = SimRng::new(1916);
        for _ in 0..64 {
            assert_eq!(left.next_u64(), right.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut left = SimRng::new(1916);
        let mut right = SimRng::new(1917);
        let draws_left: Vec<u64> = (0..8).map(|_| left.next_u64()).collect();
        let draws_right: Vec<u64> = (0..8).map(|_| right.next_u64()).collect();
        assert_ne!(draws_left, draws_right);
    }

    #[test]
    fn bounded_draws_stay_within_bound() {
        let mut rng = SimRng::new(7);
        for _ in 0..128 {
            assert!(rng.below(5) < 5);
        }
        assert_eq!(rng.below(0), 0);
    }
}
