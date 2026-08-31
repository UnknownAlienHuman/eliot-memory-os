fn contains_defaulted_parse(source: &str, parser: &str) -> bool {
    source.match_indices(parser).any(|(offset, _)| {
        let end = (offset + 320).min(source.len());
        source[offset..end].contains("unwrap_or(0)")
    })
}

#[test]
fn durable_sequence_decoding_never_replaces_corruption_with_genesis() {
    let source = include_str!("../src/lib.rs");

    assert!(
        !contains_defaulted_parse(source, "serde_json::from_slice"),
        "present corrupt project-sequence bytes must return a typed corruption error, not sequence zero"
    );
    assert!(
        !contains_defaulted_parse(source, "parse::<u64>"),
        "malformed persisted event-sequence suffixes must fail closed, not become sequence zero"
    );
}
