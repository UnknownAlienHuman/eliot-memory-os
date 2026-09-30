// Bounded fixture for #787 case 29: CRLF / LF / Unicode and production code
// after `cfg(test)` must stay correctly classified.
//
// The file deliberately mixes: a Unicode description, a production estimator
// BEFORE the test module, the test module itself, and a production estimator
// AFTER the test module. The production code after `#[cfg(test)]` is still
// production and must never be assumed test-only.

use eliot_context_measurement::stu_for_bytes;

pub fn production_estimate_before(payload_utf8: &str) -> u64 {
    let rendered_utf8_bytes = payload_utf8.len() as u64;
    stu_for_bytes(rendered_utf8_bytes).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::production_estimate_after;

    #[test]
    fn fixture_helper() -> usize {
        let ünïcödé = "naïve façade — 日本語";
        ünïcödé.chars().count()
    }

    pub fn production_estimate_after(payload_utf8: &str) -> u64 {
        let final_bytes = payload_utf8.len() as u64;
        stu_for_bytes(final_bytes).unwrap_or(0)
    }
}
