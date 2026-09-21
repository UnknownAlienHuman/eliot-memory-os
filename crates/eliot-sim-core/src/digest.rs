//! Stable deterministic digests over canonical byte encodings.
//!
//! [`SimDigest`] is 64-bit `FNV-1a` over length-prefixed fields. It uses only
//! the standard library so this crate adds no dependency, and it is stable
//! within one build: the same scenario plus seed always folds to the same
//! digest, which is exactly the equality property the simulation boundary
//! promises. Cross-build stability is explicitly out of scope; the host
//! adapter binds the real binary digest outside this crate.

use std::fmt::{Display, Formatter, Result as FmtResult};

/// Deterministic 64-bit digest over a canonical encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SimDigest(u64);

impl SimDigest {
    /// `FNV-1a` offset basis.
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    /// `FNV-1a` prime.
    const PRIME: u64 = 0x0100_0000_01b3;

    /// Starts a fresh digest.
    #[must_use]
    pub const fn new() -> Self {
        Self(Self::OFFSET)
    }

    /// Folds raw bytes into the digest.
    pub fn feed_bytes(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 ^= u64::from(*byte);
            self.0 = self.0.wrapping_mul(Self::PRIME);
        }
    }

    /// Folds one `u64` in little-endian form.
    pub fn feed_u64(&mut self, value: u64) {
        self.feed_bytes(&value.to_le_bytes());
    }

    /// Folds one `u32` in little-endian form.
    pub fn feed_u32(&mut self, value: u32) {
        self.feed_bytes(&value.to_le_bytes());
    }

    /// Folds a string as its byte length followed by its bytes.
    pub fn feed_str(&mut self, value: &str) {
        let len = u64::try_from(value.len()).unwrap_or(u64::MAX);
        self.feed_u64(len);
        self.feed_bytes(value.as_bytes());
    }

    /// Folds a field tag before the field value.
    pub fn feed_tag(&mut self, tag: &str) {
        self.feed_str(tag);
    }

    /// Folds a boolean as one tagged byte.
    pub fn feed_bool(&mut self, value: bool) {
        self.feed_bytes(&[u8::from(value)]);
    }

    /// Returns the raw digest word.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Returns the digest as sixteen lowercase hexadecimal characters.
    #[must_use]
    pub fn hex(self) -> String {
        format!("{:016x}", self.0)
    }

    /// Folds a canonical value into a fresh digest and returns it.
    #[must_use]
    pub fn of(value: &impl Canonical) -> Self {
        let mut digest = Self::new();
        value.feed(&mut digest);
        digest
    }
}

impl Default for SimDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for SimDigest {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str(&self.hex())
    }
}

/// A value with a fixed canonical encoding for digesting.
///
/// Field order, tags, and length prefixes are part of the encoding. Two
/// values that encode differently must digest differently within one build.
pub trait Canonical {
    /// Feeds the canonical encoding into `digest`.
    fn feed(&self, digest: &mut SimDigest);
}

impl Canonical for SimDigest {
    fn feed(&self, digest: &mut SimDigest) {
        digest.feed_tag("sim-digest");
        digest.feed_u64(self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::{Canonical, SimDigest};

    struct Probe(&'static str);

    impl Canonical for Probe {
        fn feed(&self, digest: &mut SimDigest) {
            digest.feed_tag("probe");
            digest.feed_str(self.0);
        }
    }

    #[test]
    fn same_encoding_folds_to_same_digest() {
        let left = SimDigest::of(&Probe("watchdog-loss"));
        let right = SimDigest::of(&Probe("watchdog-loss"));
        assert_eq!(left, right);
    }

    #[test]
    fn different_encoding_folds_to_different_digest() {
        let left = SimDigest::of(&Probe("watchdog-loss"));
        let right = SimDigest::of(&Probe("testd-loss"));
        assert_ne!(left, right);
    }

    #[test]
    fn hex_form_is_sixteen_lowercase_characters() {
        let text = SimDigest::of(&Probe("hex")).hex();
        assert_eq!(text.len(), 16);
        assert!(text.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
