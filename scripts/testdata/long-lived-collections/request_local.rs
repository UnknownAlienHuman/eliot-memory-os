// Fixture: request-local Vec growth (issue #885).
// A function-frame buffer that is pushed and dropped in one call must not be
// reported as long-lived growth.

pub fn render_copy(items: &[String]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    for item in items {
        buf.push(b'>');
        buf.extend(item.as_bytes());
    }
    buf
}
