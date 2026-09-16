//! Deterministic digests for the pure synthesis owner.
//!
//! The crate is dependency-free by design (I2.11 standalone gate, `wasm32`
//! portability), so canonical byte encoding and SHA-256 live here on `core`
//! integer operations only: no I/O, no clock, no randomness, no threads.
//! [`sha256`] is verified against the FIPS 180-4 answer vectors inside the
//! 24-case proof matrix (case 22), not trusted by inspection.

/// SHA-256 round constants (FIPS 180-4, section 4.2.2).
const ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1,
    0x923f_82a4, 0xab1c_5ed5, 0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3,
    0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174, 0xe49b_69c1, 0xefbe_4786,
    0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147,
    0x06ca_6351, 0x1429_2967, 0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13,
    0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85, 0xa2bf_e8a1, 0xa81a_664b,
    0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a,
    0x5b9c_ca4f, 0x682e_6ff3, 0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208,
    0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
];

/// SHA-256 initial hash value (FIPS 180-4, section 5.3.3).
const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c,
    0x1f83_d9ab, 0x5be0_cd19,
];

/// Computes the SHA-256 digest of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let bit_len = u64::try_from(data.len())
        .unwrap_or(u64::MAX >> 3)
        .saturating_mul(8);
    let total = data.len().saturating_add(9);
    let capacity = total.saturating_add(63) / 64 * 64;
    let mut padded = Vec::with_capacity(capacity);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    let mut state = INITIAL_STATE;
    for block in padded.chunks_exact(64) {
        let mut schedule = [0_u32; 64];
        for (index, slot) in schedule.iter_mut().take(16).enumerate() {
            let offset = index * 4;
            *slot = u32::from_be_bytes([
                block[offset],
                block[offset + 1],
                block[offset + 2],
                block[offset + 3],
            ]);
        }
        for index in 16..64 {
            let small_sigma_0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let small_sigma_1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(small_sigma_0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(small_sigma_1);
        }
        let mut work = state;
        for index in 0..64 {
            let big_sigma_1 = work[4].rotate_right(6)
                ^ work[4].rotate_right(11)
                ^ work[4].rotate_right(25);
            let choice = (work[4] & work[5]) ^ ((!work[4]) & work[6]);
            let temp_1 = work[7]
                .wrapping_add(big_sigma_1)
                .wrapping_add(choice)
                .wrapping_add(ROUND_CONSTANTS[index])
                .wrapping_add(schedule[index]);
            let big_sigma_0 = work[0].rotate_right(2)
                ^ work[0].rotate_right(13)
                ^ work[0].rotate_right(22);
            let majority =
                (work[0] & work[1]) ^ (work[0] & work[2]) ^ (work[1] & work[2]);
            let temp_2 = big_sigma_0.wrapping_add(majority);
            work[7] = work[6];
            work[6] = work[5];
            work[5] = work[4];
            work[4] = work[3].wrapping_add(temp_1);
            work[3] = work[2];
            work[2] = work[1];
            work[1] = work[0];
            work[0] = temp_1.wrapping_add(temp_2);
        }
        for (slot, addition) in state.iter_mut().zip(work.iter()) {
            *slot = slot.wrapping_add(*addition);
        }
    }

    let mut digest = [0_u8; 32];
    for (index, word) in state.iter().enumerate() {
        let bytes = word.to_be_bytes();
        let offset = index * 4;
        digest[offset..offset + 4].copy_from_slice(&bytes);
    }
    digest
}

/// Renders bytes as 64 lowercase hexadecimal characters.
#[must_use]
pub fn hex_bytes(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for byte in data {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// SHA-256 of `data` rendered as lowercase hexadecimal.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    hex_bytes(&sha256(data))
}

/// Returns `true` when `value` is shaped like a 64-character hex digest.
#[must_use]
pub fn is_digest_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Length of a slice rendered as `u64`, saturating instead of truncating.
#[must_use]
pub fn len_u64<T>(slice: &[T]) -> u64 {
    u64::try_from(slice.len()).unwrap_or(u64::MAX)
}

/// Deterministic length-prefixed byte writer for canonical encodings.
///
/// Every field contributes its tag, its 8-byte big-endian length, then its
/// bytes, so concatenation is unambiguous without an external schema.
#[derive(Clone, Debug, Default)]
pub struct CanonicalWriter {
    buf: Vec<u8>,
}

impl CanonicalWriter {
    /// Creates an empty writer.
    #[must_use]
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Appends one tagged text field.
    pub fn text(&mut self, tag: &str, value: &str) {
        self.raw(tag.as_bytes());
        self.raw(value.as_bytes());
    }

    /// Appends one tagged unsigned integer field.
    pub fn integer(&mut self, tag: &str, value: u64) {
        self.raw(tag.as_bytes());
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    /// Appends one tagged boolean field.
    pub fn flag(&mut self, tag: &str, value: bool) {
        self.integer(tag, u64::from(value));
    }

    /// Appends one already-encoded canonical section.
    pub fn section(&mut self, tag: &str, bytes: &[u8]) {
        self.raw(tag.as_bytes());
        self.raw(bytes);
    }

    /// Consumes the writer into its canonical bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    fn raw(&mut self, bytes: &[u8]) {
        let len = len_u64(bytes);
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(bytes);
    }
}
