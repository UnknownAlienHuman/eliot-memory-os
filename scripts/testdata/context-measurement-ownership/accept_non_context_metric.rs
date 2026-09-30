// Bounded accept fixture: an exact non-Context byte/KiB/UI-character/line
// metric. A storage-size bound and a line count are genuine non-Context
// metrics, never divided by a token ratio and never relabelled as tokens.
// The exact non-Context classification is what makes them acceptable.

pub struct SkillBodySizeMetrics {
    pub stored_bytes: u64,
    pub stored_kib: u64,
    pub ui_characters: usize,
    pub nonblank_lines: usize,
}

pub fn measure_skill_body_size(body: &str) -> SkillBodySizeMetrics {
    let stored_bytes = body.len() as u64;
    let stored_kib = stored_bytes.div_ceil(1024);
    let ui_characters = body.chars().count();
    let nonblank_lines = body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count();
    SkillBodySizeMetrics {
        stored_bytes,
        stored_kib,
        ui_characters,
        nonblank_lines,
    }
}
