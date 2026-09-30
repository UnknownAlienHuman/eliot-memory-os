// Bounded reject fixture: a helper/constant alias that hides the ratio.
// The /4 is laundered through a named constant and a local helper so that a
// naive single-line scan for the ratio would miss it. It must still be
// rejected: the helper is a local generic estimator and the constant hides
// an unvalidated byte-ratio.

const BYTES_PER_ESTIMATED_TOKEN: u64 = 4;

pub fn estimated_token_units(serialized_bytes: u64) -> u64 {
    let units = serialized_bytes.div_ceil(BYTES_PER_ESTIMATED_TOKEN);
    units.max(1)
}
