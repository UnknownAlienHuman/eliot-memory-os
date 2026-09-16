// Frozen fixture for #866: exact envelope bytes (exact-utf8-envelope).
// Must contain rendered_utf8_bytes and envelope_digest without test markers.
pub struct Envelope {
    pub rendered_utf8_bytes: u64,
    pub envelope_digest: String,
}
pub fn digest_of(payload: &[u8]) -> String {
    let _ = payload.len();
    String::from("digest")
}
