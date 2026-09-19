//! Boundary oracle for issue #706 ([F-CUE-L0]).
//!
//! `eliot-types::ul::cue::CueKind` is explicit legacy V1
//! (`LegacyCueKindV1`). This oracle freezes the historical
//! variant/spelling/serialization/hash denominator, every frozen
//! import/alias/reexport/field/constructor/match/fixture row, all duplicate
//! definitions, and the inert V1 to A-10 descriptor, against the manifest at
//! `tests/data/cue_kind_migration.toml` and the fixtures under
//! `tests/data/cue-kind-legacy/`.
//!
//! Every expectation is derived from live source, the manifest, or fixtures;
//! nothing here trusts a hard-coded copy of the denominator except the
//! checked-in frozen files themselves, which this oracle revalidates.

use eliot_types::ul::cue::{LegacyCueKindV1, LegacyCueKindV1MigrationDescriptor as Seam};
use eliot_types::{BlobRef, CueBinding, CueMatchMode, CueStrength};
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn boxed(error: impl std::error::Error + 'static) -> Box<dyn std::error::Error> {
    Box::new(error)
}

fn fail<T>(message: String) -> Result<T, Box<dyn std::error::Error>> {
    Err(boxed(std::io::Error::other(message)))
}

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let root = manifest_dir().join("..").join("..");
    if !root.join("Cargo.toml").is_file() || !root.join("Cargo.lock").is_file() {
        return fail(format!("workspace root not found under {}", root.display()));
    }
    Ok(root)
}

fn read_workspace(relative: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = workspace_root()?.join(relative);
    std::fs::read_to_string(&path).map_err(boxed)
}

fn read_fixture(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let path = manifest_dir()
        .join("tests")
        .join("data")
        .join("cue-kind-legacy")
        .join(name);
    std::fs::read_to_string(&path).map_err(boxed)
}

fn blake3_hex(bytes: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(bytes);
    hasher.finalize().to_hex().to_string()
}

fn matched_lines<'text>(text: &'text str, needle: &str) -> Vec<&'text str> {
    text.lines().filter(|line| line.contains(needle)).collect()
}

fn matched_digest(text: &str, needle: &str) -> (usize, String) {
    let lines = matched_lines(text, needle);
    (lines.len(), blake3_hex(lines.join("\n").as_bytes()))
}

/// Strip line/block comments, string and character literals, and raw strings.
/// Comment/string bytes become spaces; newlines are preserved.
fn strip_code(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        let rest = &bytes[index..];
        if rest.starts_with(b"//") {
            while index < bytes.len() && bytes[index] != b'\n' {
                out.push(' ');
                index += 1;
            }
        } else if rest.starts_with(b"/*") {
            index = consume_block_comment(bytes, index, &mut out);
        } else if rest.starts_with(b"\"") {
            index = consume_string(bytes, index, &mut out);
        } else if raw_prefix_len(rest).is_some() {
            index = consume_raw_string(bytes, index, &mut out);
        } else if rest[0] == b'\'' {
            index = consume_char_or_lifetime(bytes, index, &mut out);
        } else {
            out.push(bytes[index] as char);
            index += 1;
        }
    }
    out
}

/// Length of the `r"..."` opening prefix when `rest` starts a raw string.
fn raw_prefix_len(rest: &[u8]) -> Option<usize> {
    if rest.is_empty() || rest[0] != b'r' {
        return None;
    }
    let hashes = rest[1..].iter().take_while(|byte| **byte == b'#').count();
    if hashes + 1 < rest.len() && rest[hashes + 1] == b'"' {
        Some(hashes)
    } else {
        None
    }
}

fn consume_block_comment(bytes: &[u8], mut index: usize, out: &mut String) -> usize {
    let mut depth = 0;
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            out.push('\n');
            index += 1;
        } else if bytes[index..].starts_with(b"/*") {
            depth += 1;
            out.push_str("  ");
            index += 2;
        } else if bytes[index..].starts_with(b"*/") && depth > 0 {
            depth -= 1;
            out.push_str("  ");
            index += 2;
            if depth == 0 {
                break;
            }
        } else {
            out.push(' ');
            index += 1;
        }
    }
    index
}

fn consume_string(bytes: &[u8], mut index: usize, out: &mut String) -> usize {
    out.push(' ');
    index += 1;
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            out.push('\n');
            index += 1;
        } else if bytes[index] == b'\\' {
            out.push_str("  ");
            index += 2.min(bytes.len() - index);
        } else if bytes[index] == b'"' {
            out.push(' ');
            index += 1;
            break;
        } else {
            out.push(' ');
            index += 1;
        }
    }
    index
}

fn consume_raw_string(bytes: &[u8], mut index: usize, out: &mut String) -> usize {
    let hashes = raw_prefix_len(&bytes[index..]).unwrap_or(0);
    for _ in 0..=hashes + 1 {
        out.push(' ');
    }
    index += hashes + 2;
    loop {
        if index >= bytes.len() {
            break;
        }
        if bytes[index] == b'"'
            && bytes[index + 1..]
                .iter()
                .take(hashes)
                .all(|byte| *byte == b'#')
        {
            for _ in 0..=hashes {
                out.push(' ');
            }
            index += hashes + 1;
            break;
        }
        if bytes[index] == b'\n' {
            out.push('\n');
        } else {
            out.push(' ');
        }
        index += 1;
    }
    index
}

fn consume_char_or_lifetime(bytes: &[u8], index: usize, out: &mut String) -> usize {
    let mut cursor = index + 1;
    if cursor < bytes.len() && bytes[cursor] == b'\\' {
        cursor += 2;
        while cursor < bytes.len() && bytes[cursor] != b'\'' && bytes[cursor] != b'\n' {
            cursor += 1;
        }
        if cursor < bytes.len() && bytes[cursor] == b'\'' {
            cursor += 1;
        }
        for _ in index..cursor {
            out.push(' ');
        }
        return cursor;
    }
    let start = cursor;
    while cursor < bytes.len() && (bytes[cursor].is_ascii_alphanumeric() || bytes[cursor] == b'_') {
        cursor += 1;
    }
    if cursor > start && cursor < bytes.len() && bytes[cursor] == b'\'' {
        for _ in index..=cursor {
            out.push(' ');
        }
        cursor + 1
    } else {
        out.push('\'');
        index + 1
    }
}

fn cue_rs_source() -> Result<String, Box<dyn std::error::Error>> {
    read_workspace("crates/eliot-types/src/ul/cue.rs")
}

fn production_code() -> Result<String, Box<dyn std::error::Error>> {
    let source = cue_rs_source()?;
    let marker = "#[cfg(test)]";
    if source.matches(marker).count() != 1 {
        return fail(format!("expected exactly one {marker} marker in cue.rs"));
    }
    let stripped = strip_code(&source);
    let marker_stripped = "#[cfg(test)]";
    let position = stripped
        .find(marker_stripped)
        .ok_or_else(|| boxed(std::io::Error::other("test marker lost after stripping")))?;
    Ok(stripped[..position].to_owned())
}

/// Attribute lines directly attached to `pub enum {name}` in raw source.
/// Raw source is used so string-valued attributes keep their spelling.
fn enum_serde_attr(source: &str, enum_name: &str) -> Result<String, Box<dyn std::error::Error>> {
    let declaration = format!("pub enum {enum_name}");
    let position = source
        .find(&declaration)
        .ok_or_else(|| boxed(std::io::Error::other(format!("{declaration} not found"))))?;
    let before = source[..position].lines().collect::<Vec<_>>();
    let mut cursor = before.len();
    let mut attrs = Vec::new();
    while cursor > 0 && before[cursor - 1].trim_start().starts_with("#[") {
        cursor -= 1;
        attrs.push(before[cursor].trim());
    }
    attrs.reverse();
    attrs
        .iter()
        .find(|attr| attr.starts_with("#[serde("))
        .map(ToString::to_string)
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "no serde attribute on {enum_name}"
            ))) as Box<dyn std::error::Error>
        })
}

/// Variant names in declaration order for `pub enum {name}` in stripped code.
fn enum_variants(text: &str, enum_name: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let declaration = format!("pub enum {enum_name}");
    let start = text
        .find(&declaration)
        .ok_or_else(|| boxed(std::io::Error::other(format!("{declaration} not found"))))?;
    let brace = text[start..]
        .find('{')
        .ok_or_else(|| boxed(std::io::Error::other(format!("no body for {enum_name}"))))?
        + start;
    let mut depth = 0;
    let mut end = None;
    for (offset, byte) in text[brace..].bytes().enumerate() {
        if byte == b'{' {
            depth += 1;
        } else if byte == b'}' {
            depth -= 1;
            if depth == 0 {
                end = Some(brace + offset);
                break;
            }
        }
    }
    let end = end.ok_or_else(|| {
        boxed(std::io::Error::other(format!(
            "unbalanced body for {enum_name}"
        )))
    })?;
    let mut variants = Vec::new();
    for line in text[brace + 1..end].lines() {
        let trimmed = line.trim().trim_end_matches(',');
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let name = trimmed
            .split(|cell: char| !(cell.is_alphanumeric() || cell == '_'))
            .next()
            .unwrap_or("");
        if name.is_empty() || !name.starts_with(|cell: char| cell.is_uppercase()) {
            return fail(format!("unexpected enum body line: {trimmed}"));
        }
        variants.push(name.to_owned());
    }
    Ok(variants)
}

#[derive(Clone, Debug, PartialEq)]
enum TomlValue {
    Str(String),
    Int(i64),
    Bool(bool),
    Array(Vec<String>),
}

struct TomlDoc {
    sections: Vec<(String, Vec<(String, TomlValue)>)>,
}

fn parse_toml(text: &str) -> Result<TomlDoc, Box<dyn std::error::Error>> {
    let mut doc = TomlDoc {
        sections: Vec::new(),
    };
    for (line_number, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let name = line[1..line.len() - 1].trim().to_owned();
            if name.is_empty() {
                return fail(format!("empty section at line {}", line_number + 1));
            }
            doc.sections.push((name, Vec::new()));
            continue;
        }
        let equals = raw.find('=').ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "no equals at line {}",
                line_number + 1
            )))
        })?;
        if doc.sections.is_empty() {
            return fail(format!("entry before section at line {}", line_number + 1));
        }
        let key = raw[..equals].trim().to_owned();
        if key.is_empty()
            || !key
                .chars()
                .all(|cell| cell.is_alphanumeric() || cell == '_' || cell == '-' || cell == '.')
        {
            return fail(format!("bad key at line {}", line_number + 1));
        }
        let value = parse_toml_value(raw[equals + 1..].trim(), line_number + 1)?;
        if let Some(section) = doc.sections.last_mut() {
            section.1.push((key, value));
        }
    }
    Ok(doc)
}

fn parse_toml_value(
    text: &str,
    line_number: usize,
) -> Result<TomlValue, Box<dyn std::error::Error>> {
    if text == "true" {
        return Ok(TomlValue::Bool(true));
    }
    if text == "false" {
        return Ok(TomlValue::Bool(false));
    }
    if let Ok(number) = text.parse::<i64>() {
        return Ok(TomlValue::Int(number));
    }
    if text.starts_with('"') && text.ends_with('"') && text.len() >= 2 {
        return Ok(TomlValue::Str(unquote(
            &text[1..text.len() - 1],
            line_number,
        )?));
    }
    if text.starts_with('[') && text.ends_with(']') {
        let inner = text[1..text.len() - 1].trim();
        if inner.is_empty() {
            return Ok(TomlValue::Array(Vec::new()));
        }
        let mut items = Vec::new();
        for part in inner.split(',') {
            let part = part.trim();
            if part.starts_with('"') && part.ends_with('"') && part.len() >= 2 {
                items.push(unquote(&part[1..part.len() - 1], line_number)?);
            } else {
                return fail(format!("bad array item at line {line_number}"));
            }
        }
        return Ok(TomlValue::Array(items));
    }
    fail(format!("bad value at line {line_number}: {text}"))
}

fn unquote(text: &str, line_number: usize) -> Result<String, Box<dyn std::error::Error>> {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(cell) = chars.next() {
        if cell == '\\' {
            match chars.next() {
                Some('"') => out.push('"'),
                Some('\\') => out.push('\\'),
                Some('u') => {
                    let digits = chars.by_ref().take(4).collect::<String>();
                    if digits.len() != 4 || !digits.chars().all(|hex| hex.is_ascii_hexdigit()) {
                        return fail(format!("bad unicode escape at line {line_number}"));
                    }
                    let scalar = u32::from_str_radix(&digits, 16).map_err(boxed)?;
                    out.push(char::from_u32(scalar).ok_or_else(|| {
                        boxed(std::io::Error::other(format!(
                            "bad scalar at line {line_number}"
                        )))
                    })?);
                }
                _ => return fail(format!("bad escape at line {line_number}")),
            }
        } else {
            out.push(cell);
        }
    }
    Ok(out)
}

fn manifest_doc() -> Result<TomlDoc, Box<dyn std::error::Error>> {
    let text = read_workspace("crates/eliot-types/tests/data/cue_kind_migration.toml")?;
    parse_toml(&text)
}

fn find_section<'doc>(
    doc: &'doc TomlDoc,
    name: &str,
) -> Result<&'doc Vec<(String, TomlValue)>, Box<dyn std::error::Error>> {
    doc.sections
        .iter()
        .find(|section| section.0 == name)
        .map(|section| &section.1)
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "manifest section missing: {name}"
            ))) as Box<dyn std::error::Error>
        })
}

fn prefixed_sections<'doc>(
    doc: &'doc TomlDoc,
    prefix: &str,
) -> Vec<(&'doc str, &'doc Vec<(String, TomlValue)>)> {
    doc.sections
        .iter()
        .filter(|section| section.0.starts_with(prefix))
        .map(|section| (section.0.as_str(), &section.1))
        .collect()
}

fn row_get<'row>(
    row: &'row [(String, TomlValue)],
    key: &str,
    section: &str,
) -> Result<&'row TomlValue, Box<dyn std::error::Error>> {
    row.iter()
        .find(|entry| entry.0 == key)
        .map(|entry| &entry.1)
        .ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "key {key} missing in {section}"
            ))) as Box<dyn std::error::Error>
        })
}

fn row_str(
    row: &[(String, TomlValue)],
    key: &str,
    section: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match row_get(row, key, section)? {
        TomlValue::Str(value) => Ok(value.clone()),
        _ => fail(format!("key {key} is not a string in {section}")),
    }
}

fn row_int(
    row: &[(String, TomlValue)],
    key: &str,
    section: &str,
) -> Result<i64, Box<dyn std::error::Error>> {
    match row_get(row, key, section)? {
        TomlValue::Int(value) => Ok(*value),
        _ => fail(format!("key {key} is not an integer in {section}")),
    }
}

fn row_bool(
    row: &[(String, TomlValue)],
    key: &str,
    section: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    match row_get(row, key, section)? {
        TomlValue::Bool(value) => Ok(*value),
        _ => fail(format!("key {key} is not a boolean in {section}")),
    }
}

fn row_array(
    row: &[(String, TomlValue)],
    key: &str,
    section: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    match row_get(row, key, section)? {
        TomlValue::Array(value) => Ok(value.clone()),
        _ => fail(format!("key {key} is not an array in {section}")),
    }
}

fn collect_rs_files(
    root: &Path,
    needle: &str,
    hits: &mut Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let entries = std::fs::read_dir(root).map_err(boxed)?;
    for entry in entries {
        let entry = entry.map_err(boxed)?;
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, needle, hits)?;
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let text = std::fs::read_to_string(&path).map_err(boxed)?;
            if text.lines().any(|line| line.contains(needle)) {
                let relative = path
                    .strip_prefix(workspace_root()?)
                    .map_err(boxed)?
                    .to_string_lossy()
                    .replace('\\', "/");
                hits.push(relative);
            }
        }
    }
    Ok(())
}

fn scan_files(dirs: &[&str], needle: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let root = workspace_root()?;
    let mut hits = Vec::new();
    for dir in dirs {
        let candidate = root.join(dir);
        if candidate.is_dir() {
            collect_rs_files(&candidate, needle, &mut hits)?;
        }
    }
    hits.sort();
    hits.dedup();
    Ok(hits)
}

const LEGACY_DIRS: [&str; 5] = [
    "crates/eliot-types",
    "crates/eliot-app",
    "crates/eliot-engine",
    "crates/eliot-store",
    "bins",
];

fn expected_row_paths(doc: &TomlDoc, prefix: &str) -> Vec<String> {
    let mut paths = prefixed_sections(doc, prefix)
        .iter()
        .map(|(name, _)| name[prefix.len()..].trim_matches('"').to_owned())
        .collect::<Vec<_>>();
    paths.sort();
    paths
}

/// A stripped line uses the transitional alias outside its single frozen form.
/// The frozen definition itself is the one inventoried hit; everything else is
/// forbidden local alias use.
fn flag_forbidden_alias_use(stripped_line: &str) -> bool {
    stripped_line
        .replace("LegacyCueKindV1", "")
        .contains("CueKind")
}

/// A stripped enum-region line opens a permissive compatibility escape.
fn flag_permissive_escape(stripped_line: &str) -> bool {
    stripped_line.contains("untagged")
        || stripped_line.contains("alias")
        || stripped_line.contains("Other")
        || stripped_line.contains("Unknown")
        || stripped_line.contains("_ =>")
        || stripped_line.contains("impl Default")
}

fn decode_kind(spelling: &str) -> Result<LegacyCueKindV1, serde_json::Error> {
    serde_json::from_value(Value::String(spelling.to_owned()))
}

fn manifest_variants(doc: &TomlDoc) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut variants = Vec::new();
    for (name, row) in prefixed_sections(doc, "variant.") {
        let spelling = name["variant.".len()..].to_owned();
        let section = format!("variant.{spelling}");
        let variant_name = row_str(row, "name", &section)?;
        let position = row_int(row, "position", &section)?;
        variants.push((variant_name, spelling, position));
    }
    variants.sort_by_key(|entry| entry.2);
    Ok(variants
        .into_iter()
        .map(|(name, spelling, _)| (name, spelling))
        .collect())
}

fn malformed_rows() -> Result<Vec<(String, Value)>, Box<dyn std::error::Error>> {
    let text = read_fixture("malformed_inputs.json")?;
    let entries = serde_json::from_str::<Vec<Value>>(&text).map_err(boxed)?;
    let mut rows = Vec::new();
    for entry in entries {
        let tag = entry
            .get("tag")
            .and_then(Value::as_str)
            .ok_or_else(|| boxed(std::io::Error::other("malformed fixture entry without tag")))?
            .to_owned();
        let value = entry.get("value").cloned().ok_or_else(|| {
            boxed(std::io::Error::other(format!(
                "malformed fixture entry without value: {tag}"
            )))
        })?;
        rows.push((tag, value));
    }
    Ok(rows)
}

fn malformed_value(tag: &str) -> Result<Value, Box<dyn std::error::Error>> {
    for (candidate, value) in malformed_rows()? {
        if candidate == tag {
            return Ok(value);
        }
    }
    fail(format!("malformed fixture tag missing: {tag}"))
}

fn valid_bindings() -> Result<Vec<CueBinding>, Box<dyn std::error::Error>> {
    let text = read_fixture("valid_bindings.json")?;
    serde_json::from_str(&text).map_err(boxed)
}

fn check_row_digest(
    relative: &str,
    needle: &str,
    expected_count: i64,
    expected_digest: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let text = read_workspace(relative)?;
    let (count, digest) = matched_digest(&text, needle);
    if i64::try_from(count).map_err(boxed)? != expected_count {
        return fail(format!(
            "{relative} {needle} count drift: manifest {expected_count}, live {count}"
        ));
    }
    if digest != expected_digest {
        return fail(format!(
            "{relative} {needle} digest drift: manifest {expected_digest}, live {digest}"
        ));
    }
    Ok(())
}

fn check_row_complete(
    doc: &TomlDoc,
    prefix: &str,
    needle: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for (name, row) in prefixed_sections(doc, prefix) {
        let relative = name[prefix.len()..].trim_matches('"').to_owned();
        let expected_count = row_int(row, "match_count", name)?;
        let expected_digest = row_str(row, "matched_digest", name)?;
        check_row_digest(&relative, needle, expected_count, &expected_digest)?;
    }
    Ok(())
}

// WORK_UNIT_CASE: 706/1
#[test]
fn case_01_exact_historical_variants_and_count() -> TestResult {
    let doc = manifest_doc()?;
    let meta = find_section(&doc, "meta")?;
    assert_eq!(row_int(meta, "variant_count", "meta")?, 10);
    assert_eq!(Seam::VARIANT_COUNT, 10);
    let variants = manifest_variants(&doc)?;
    assert_eq!(variants.len(), 10);
    for (position, (_, spelling)) in variants.iter().enumerate() {
        let expected = row_int(
            find_section(&doc, &format!("variant.{spelling}"))?,
            "position",
            &format!("variant.{spelling}"),
        )?;
        assert_eq!(expected, i64::try_from(position).map_err(boxed)? + 1);
    }
    let prod = production_code()?;
    let live = enum_variants(&prod, "LegacyCueKindV1")?;
    let manifest_names = variants
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    assert_eq!(live, manifest_names);
    for (_, spelling) in &variants {
        assert!(decode_kind(spelling).is_ok(), "spelling lost: {spelling}");
    }
    Ok(())
}

// WORK_UNIT_CASE: 706/2
#[test]
fn case_02_every_wire_spelling() -> TestResult {
    let doc = manifest_doc()?;
    let variants = manifest_variants(&doc)?;
    assert_eq!(Seam::WIRE_SPELLINGS.len(), 10);
    for (position, (_, spelling)) in variants.iter().enumerate() {
        assert_eq!(Seam::WIRE_SPELLINGS[position], spelling);
        let kind = decode_kind(spelling).map_err(boxed)?;
        assert_eq!(
            serde_json::to_string(&kind).map_err(boxed)?,
            format!("\"{spelling}\"")
        );
    }
    let schema = schemars::schema_for!(LegacyCueKindV1);
    let schema_value = serde_json::to_value(&schema).map_err(boxed)?;
    let frozen = schema_value
        .get("enum")
        .and_then(Value::as_array)
        .ok_or_else(|| boxed(std::io::Error::other("JsonSchema omitted enum values")))?;
    let live_spellings = frozen.iter().filter_map(Value::as_str).collect::<Vec<_>>();
    let expected = variants
        .iter()
        .map(|(_, spelling)| spelling.as_str())
        .collect::<Vec<_>>();
    assert_eq!(live_spellings, expected);
    Ok(())
}

// WORK_UNIT_CASE: 706/3
#[test]
fn case_03_valid_roundtrip() -> TestResult {
    let doc = manifest_doc()?;
    let variants = manifest_variants(&doc)?;
    let bindings = valid_bindings()?;
    assert_eq!(bindings.len(), variants.len());
    for (binding, (_, spelling)) in bindings.iter().zip(variants.iter()) {
        let encoded = serde_json::to_value(binding).map_err(boxed)?;
        assert_eq!(
            encoded.get("cue_kind").and_then(Value::as_str),
            Some(spelling.as_str())
        );
        let decoded = serde_json::from_value::<CueBinding>(encoded.clone()).map_err(boxed)?;
        assert_eq!(&decoded, binding);
        let reencoded = serde_json::to_value(&decoded).map_err(boxed)?;
        assert_eq!(encoded, reencoded);
    }
    Ok(())
}

// WORK_UNIT_CASE: 706/4
#[test]
fn case_04_unknown_rejected() -> TestResult {
    assert!(decode_kind("bogus_kind").is_err());
    let value = malformed_value("unknown")?;
    assert!(serde_json::from_value::<CueBinding>(value).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 706/5
#[test]
fn case_05_missing_kind_rejected() -> TestResult {
    let value = malformed_value("missing")?;
    match serde_json::from_value::<CueBinding>(value) {
        Ok(_) => fail("missing cue_kind decoded".to_owned()),
        Err(error) => {
            assert!(
                error.to_string().contains("cue_kind"),
                "unexpected error: {error}"
            );
            Ok(())
        }
    }
}

// WORK_UNIT_CASE: 706/6
#[test]
fn case_06_empty_kind_rejected() -> TestResult {
    assert!(decode_kind("").is_err());
    let value = malformed_value("empty")?;
    assert!(serde_json::from_value::<CueBinding>(value).is_err());
    Ok(())
}

// WORK_UNIT_CASE: 706/7
#[test]
fn case_07_no_default_alias_untagged_or_catch_all() -> TestResult {
    let prod = production_code()?;
    let raw = cue_rs_source()?;
    let attr = enum_serde_attr(&raw, "LegacyCueKindV1")?;
    assert_eq!(attr, "#[serde(rename_all = \"snake_case\")]");
    let stripped = strip_code(&raw);
    let declaration = "pub enum LegacyCueKindV1";
    let start = stripped
        .find(declaration)
        .ok_or_else(|| boxed(std::io::Error::other("legacy enum missing")))?;
    let region = stripped[start..].to_owned();
    let end = region.find("impl LegacyCueKindV1").unwrap_or(region.len());
    let region = &region[..end];
    for line in region.lines() {
        assert!(
            !flag_permissive_escape(line),
            "permissive escape in legacy enum: {line}"
        );
    }
    assert!(!prod.contains("impl Default for LegacyCueKindV1"));
    assert!(!prod.contains("_ =>"));
    let doc = manifest_doc()?;
    let wire = find_section(&doc, "wire")?;
    assert_eq!(row_str(wire, "rename_all", "wire")?, "snake_case");
    assert!(!row_bool(wire, "deny_unknown_fields", "wire")?);
    assert!(row_array(wire, "aliases", "wire")?.is_empty());
    assert!(!row_bool(wire, "untagged", "wire")?);
    assert!(!row_bool(wire, "default_impl", "wire")?);
    assert!(!row_bool(wire, "catch_all_variant", "wire")?);
    Ok(())
}

// WORK_UNIT_CASE: 706/8
#[test]
fn case_08_explicit_legacy_v1_name() -> TestResult {
    let prod = production_code()?;
    assert!(prod.contains("pub enum LegacyCueKindV1"));
    assert!(prod.contains("impl LegacyCueKindV1"));
    let without_legacy = prod.replace("LegacyCueKindV1", "");
    // Built at runtime so this oracle never prints a duplicate definition.
    let enum_probe = ["pub enum", " CueKind"].concat();
    let struct_probe = ["pub struct", " CueKind"].concat();
    assert!(!without_legacy.contains(&enum_probe));
    assert!(!without_legacy.contains(&struct_probe));
    assert!(Seam::SOURCE_SCHEMA.contains("LegacyCueKindV1"));
    Ok(())
}

// WORK_UNIT_CASE: 706/9
#[test]
fn case_09_fields_use_legacy_name() -> TestResult {
    let prod = production_code()?;
    assert_eq!(
        prod.matches("pub cue_kind: LegacyCueKindV1").count(),
        2,
        "CueBinding and CueIndexRow must carry the legacy name"
    );
    assert_eq!(
        prod.matches("cue_kind: LegacyCueKindV1,").count(),
        3,
        "two fields plus the row-id parameter must carry the legacy name"
    );
    Ok(())
}

// WORK_UNIT_CASE: 706/10
#[test]
fn case_10_exhaustive_matches_use_legacy_name() -> TestResult {
    let prod = production_code()?;
    let without_legacy = prod.replace("LegacyCueKindV1", "");
    assert!(
        !without_legacy.contains("CueKind::"),
        "bare kind paths remain"
    );
    let doc = manifest_doc()?;
    let variants = manifest_variants(&doc)?;
    for (name, _) in &variants {
        let path = format!("LegacyCueKindV1::{name}");
        assert!(
            prod.contains(&path),
            "variant without explicit legacy match: {name}"
        );
    }
    let source = cue_rs_source()?;
    let stripped = strip_code(&source);
    let marker = "fn as_str";
    let start = stripped
        .find(marker)
        .ok_or_else(|| boxed(std::io::Error::other("as_str missing")))?;
    let region = &stripped[start..];
    let end = region.find("\n}").unwrap_or(region.len());
    let arms = region[..end].matches("=>").count();
    assert_eq!(arms, 10, "as_str must match every variant exactly once");
    Ok(())
}

// WORK_UNIT_CASE: 706/11
#[test]
fn case_11_no_production_alias_use() -> TestResult {
    let prod = production_code()?;
    let mut bare = 0;
    for line in prod.lines() {
        if flag_forbidden_alias_use(line) {
            bare += 1;
        }
    }
    assert_eq!(
        bare, 1,
        "only the frozen alias definition may name bare CueKind"
    );
    assert!(prod.contains("pub type CueKind = LegacyCueKindV1;"));
    Ok(())
}

// WORK_UNIT_CASE: 706/12
#[test]
fn case_12_at_most_one_transitional_alias() -> TestResult {
    let prod = production_code()?;
    assert_eq!(prod.matches("type CueKind").count(), 1);
    Ok(())
}

// WORK_UNIT_CASE: 706/13
#[test]
fn case_13_alias_names_migrations_and_removal() -> TestResult {
    let source = cue_rs_source()?;
    let marker = "note = \"";
    let start = source
        .find(marker)
        .ok_or_else(|| boxed(std::io::Error::other("deprecated note missing")))?
        + marker.len();
    let rest = &source[start..];
    let end = rest
        .find('"')
        .ok_or_else(|| boxed(std::io::Error::other("deprecated note unterminated")))?;
    let note = &rest[..end];
    for issue in ["#831", "#832", "#833", "#834", "#835"] {
        assert!(note.contains(issue), "alias note omits {issue}");
    }
    assert!(note.contains("removal"), "alias note omits removal");
    Ok(())
}

// WORK_UNIT_CASE: 706/14
#[test]
fn case_14_alias_adds_no_alternate_wire() -> TestResult {
    let prod = production_code()?;
    assert!(prod.contains("pub type CueKind = LegacyCueKindV1;"));
    assert!(!prod.contains("impl CueKind"));
    let schema = schemars::schema_for!(LegacyCueKindV1);
    let schema_value = serde_json::to_value(&schema).map_err(boxed)?;
    assert_eq!(
        schema_value.get("title").and_then(Value::as_str),
        Some("LegacyCueKindV1")
    );
    let doc = manifest_doc()?;
    let wire = find_section(&doc, "wire")?;
    assert_eq!(row_str(wire, "schema_title", "wire")?, "LegacyCueKindV1");
    assert_eq!(row_str(wire, "schema_type", "wire")?, "string");
    Ok(())
}

// WORK_UNIT_CASE: 706/15
#[test]
fn case_15_valid_serialized_bytes_unchanged() -> TestResult {
    let text = read_fixture("golden_serialized.json")?;
    let goldens = serde_json::from_str::<Value>(&text).map_err(boxed)?;
    let bindings = valid_bindings()?;
    let doc = manifest_doc()?;
    let variants = manifest_variants(&doc)?;
    assert_eq!(bindings.len(), variants.len());
    for (binding, (_, spelling)) in bindings.iter().zip(variants.iter()) {
        let golden = goldens
            .get(spelling)
            .and_then(Value::as_str)
            .ok_or_else(|| boxed(std::io::Error::other(format!("golden missing: {spelling}"))))?;
        let live = serde_json::to_string(binding).map_err(boxed)?;
        assert_eq!(&live, golden, "wire drift for {spelling}");
    }
    Ok(())
}

// WORK_UNIT_CASE: 706/16
#[test]
fn case_16_page_and_hash_identity_unchanged() -> TestResult {
    let text = read_fixture("golden_page.json")?;
    let golden = serde_json::from_str::<Value>(&text).map_err(boxed)?;
    let binding = serde_json::from_value::<CueBinding>(
        golden
            .get("binding")
            .cloned()
            .ok_or_else(|| boxed(std::io::Error::other("golden binding missing")))?,
    )
    .map_err(boxed)?;
    let blob_value = golden
        .get("blob")
        .cloned()
        .ok_or_else(|| boxed(std::io::Error::other("golden blob missing")))?;
    let blob = serde_json::from_value::<BlobRef>(blob_value).map_err(boxed)?;
    let parent = golden
        .get("parent_handle")
        .and_then(Value::as_str)
        .ok_or_else(|| boxed(std::io::Error::other("golden parent missing")))?;
    let pages = eliot_types::normalize_binding_pages(parent, &blob, vec![binding.clone()], None)
        .map_err(boxed)?;
    assert_eq!(pages.len(), 1);
    let golden_id = golden
        .get("page_id")
        .and_then(Value::as_str)
        .ok_or_else(|| boxed(std::io::Error::other("golden page id missing")))?;
    assert_eq!(pages[0].page_id, golden_id);
    let golden_schema = golden
        .get("schema_version")
        .and_then(Value::as_str)
        .ok_or_else(|| boxed(std::io::Error::other("golden schema missing")))?;
    assert_eq!(pages[0].schema_version, golden_schema);
    let recomputed = eliot_types::cue_binding_page_id(parent, &blob, 0, &pages[0].cue_bindings);
    assert_eq!(recomputed, golden_id);
    let set_hash = eliot_types::cue_binding_page_set_hash(&pages);
    let golden_set = golden
        .get("page_set_hash_blake3")
        .and_then(Value::as_str)
        .ok_or_else(|| boxed(std::io::Error::other("golden set hash missing")))?;
    assert_eq!(set_hash, golden_set);
    let project = eliot_types::ProjectId::new_v7();
    let first = eliot_types::cue_row_id(
        project,
        LegacyCueKindV1::Concept,
        CueMatchMode::Exact,
        "capacity",
        "memory:one",
    );
    let second = eliot_types::cue_row_id(
        project,
        LegacyCueKindV1::Concept,
        CueMatchMode::Exact,
        "capacity",
        "memory:one",
    );
    assert_eq!(first, second);
    let prefixed = eliot_types::cue_row_id(
        project,
        LegacyCueKindV1::Concept,
        CueMatchMode::Prefix,
        "capacity",
        "memory:one",
    );
    assert_ne!(first, prefixed);
    Ok(())
}

// WORK_UNIT_CASE: 706/17
#[test]
fn case_17_schema_change_needs_explicit_migration() -> TestResult {
    let doc = manifest_doc()?;
    let changes = find_section(&doc, "schema_changes")?;
    assert_eq!(row_int(changes, "count", "schema_changes")?, 0);
    let raw = cue_rs_source()?;
    let attr = enum_serde_attr(&raw, "LegacyCueKindV1")?;
    assert_eq!(attr, "#[serde(rename_all = \"snake_case\")]");
    Ok(())
}

// WORK_UNIT_CASE: 706/18
#[test]
fn case_18_descriptor_binds_v1_and_a10() -> TestResult {
    assert_eq!(Seam::SOURCE_SCHEMA, "eliot-types.ul.cue.LegacyCueKindV1");
    assert_eq!(Seam::SOURCE_GENERATION, "v1");
    assert_eq!(Seam::SOURCE_SEAM_ISSUE, 706);
    assert_eq!(Seam::TARGET_MODULE, "smart.cue.contracts");
    assert_eq!(Seam::TARGET_CRATE, "eliot-cue-contracts");
    assert_eq!(
        Seam::TARGET_FILE,
        "crates/smart/eliot-cue-contracts/src/normalization.rs"
    );
    assert_eq!(Seam::TARGET_DIGEST_ALGO, "blake3");
    let target = read_workspace(Seam::TARGET_FILE)?;
    assert_eq!(blake3_hex(target.as_bytes()), Seam::TARGET_DIGEST);
    let lib = read_workspace("crates/smart/eliot-cue-contracts/src/lib.rs")?;
    let revisions = matched_lines(&lib, "pub const CONTRACT_REVISION");
    assert_eq!(revisions.len(), 1);
    assert!(
        revisions[0].contains(Seam::TARGET_REVISION),
        "target revision drift: {}",
        revisions[0].trim()
    );
    let doc = manifest_doc()?;
    let meta = find_section(&doc, "meta")?;
    assert_eq!(
        row_str(meta, "target_revision", "meta")?,
        Seam::TARGET_REVISION
    );
    assert_eq!(row_str(meta, "target_digest", "meta")?, Seam::TARGET_DIGEST);
    assert_eq!(row_str(meta, "source_schema", "meta")?, Seam::SOURCE_SCHEMA);
    assert!(!Seam::INVALIDATION.is_empty());
    assert!(!Seam::PROOF.is_empty());
    Ok(())
}

// WORK_UNIT_CASE: 706/19
#[test]
fn case_19_every_safe_correspondence_exact() -> TestResult {
    assert_eq!(Seam::EXACT_CORRESPONDENCES.len(), 10);
    let doc = manifest_doc()?;
    let correspondence = find_section(&doc, "correspondence")?;
    let target = read_workspace(Seam::TARGET_FILE)?;
    let current_variants = enum_variants(&strip_code(&target), "CueKind")?;
    let prod = production_code()?;
    let legacy_names = enum_variants(&prod, "LegacyCueKindV1")?;
    assert_eq!(current_variants, legacy_names);
    for (legacy, current) in Seam::EXACT_CORRESPONDENCES {
        assert_eq!(legacy, current, "only byte-exact correspondence is safe");
        assert!(decode_kind(legacy).is_ok());
        let recorded = row_str(correspondence, legacy, "correspondence")?;
        assert_eq!(recorded, current);
    }
    Ok(())
}

// WORK_UNIT_CASE: 706/20
#[test]
fn case_20_ambiguous_unsupported_claim_no_conversion() -> TestResult {
    assert_eq!(Seam::UNSUPPORTED_INPUTS.len(), 12);
    for input in Seam::UNSUPPORTED_INPUTS {
        assert!(
            decode_kind(input).is_err(),
            "unsupported input decodes: {input:?}"
        );
        assert!(
            !Seam::WIRE_SPELLINGS.contains(&input),
            "unsupported input listed as wire: {input:?}"
        );
    }
    let prod = production_code()?;
    for token in [
        "convert",
        "to_current",
        "into_current",
        "to_a10",
        "migrate(",
    ] {
        assert!(
            !prod.contains(token),
            "conversion path in legacy crate: {token}"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 706/21
#[test]
fn case_21_descriptor_cannot_construct_or_import_a10() -> TestResult {
    let prod = production_code()?;
    for token in ["eliot_cue_contracts", "smart::", "smart.cue"] {
        assert!(
            !prod.contains(token),
            "upward reference in legacy crate: {token}"
        );
    }
    let source = cue_rs_source()?;
    let descriptor = "impl LegacyCueKindV1MigrationDescriptor";
    let start = source
        .find(descriptor)
        .ok_or_else(|| boxed(std::io::Error::other("descriptor impl missing")))?;
    let region = &source[start..];
    let end = region.find("\n}").unwrap_or(region.len());
    assert!(
        !region[..end].contains("pub fn"),
        "descriptor must stay constructor-free"
    );
    assert!(source.contains("_sealed"));
    Ok(())
}

// WORK_UNIT_CASE: 706/22
#[test]
fn case_22_changed_target_identity_invalidates_descriptor() -> TestResult {
    let target = read_workspace(Seam::TARGET_FILE)?;
    let live = blake3_hex(target.as_bytes());
    assert_eq!(live, Seam::TARGET_DIGEST);
    let mut tampered = target.into_bytes();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert_ne!(
        blake3_hex(&tampered),
        Seam::TARGET_DIGEST,
        "digest comparison cannot tell change apart"
    );
    let doc = manifest_doc()?;
    let meta = find_section(&doc, "meta")?;
    assert_eq!(row_str(meta, "target_digest", "meta")?, Seam::TARGET_DIGEST);
    Ok(())
}

// WORK_UNIT_CASE: 706/23
#[test]
fn case_23_root_and_internal_consumer_denominator() -> TestResult {
    let doc = manifest_doc()?;
    check_row_complete(&doc, "type_row.", "CueKind")?;
    let live = scan_files(&LEGACY_DIRS, "CueKind")?;
    let expected = expected_row_paths(&doc, "type_row.")
        .into_iter()
        .filter(|path| {
            LEGACY_DIRS
                .iter()
                .any(|dir| path == dir || path.starts_with(&format!("{dir}/")))
        })
        .collect::<Vec<_>>();
    assert_eq!(live, expected, "unlisted legacy consumer or lost row");
    Ok(())
}

// WORK_UNIT_CASE: 706/24
#[test]
fn case_24_external_wire_consumers_and_admission_risks_visible() -> TestResult {
    let doc = manifest_doc()?;
    check_row_complete(&doc, "field_row.", "cue_kind")?;
    let live = scan_files(&LEGACY_DIRS, "\"cue_kind\"")?;
    let wire = find_section(&doc, "wire_strings")?;
    let mut expected = row_array(wire, "files", "wire_strings")?;
    expected.sort();
    assert_eq!(live, expected, "unlisted wire consumer or lost wire row");
    let field_paths = expected_row_paths(&doc, "field_row.");
    assert!(field_paths.contains(&"crates/eliot-store/src/canonical_store.rs".to_owned()));
    assert!(field_paths.contains(&"crates/eliot-app/src/ul_cross_agent_runner.rs".to_owned()));
    let inventory = read_workspace(
        "crates/foundation/eliot-contracts/tests/data/shipped_serde_boundaries.toml",
    )?;
    assert!(inventory.contains("eliot-types:crates/eliot-types/src/ul/cue.rs:CueKind"));
    Ok(())
}

// WORK_UNIT_CASE: 706/25
#[test]
fn case_25_duplicate_enum_and_string_table_denominator() -> TestResult {
    let doc = manifest_doc()?;
    for (name, row) in prefixed_sections(&doc, "type_row.") {
        let recorded = row_array(row, "variants", name)?;
        if recorded.is_empty() {
            continue;
        }
        let relative = name["type_row.".len()..].trim_matches('"');
        // The frozen source carries the explicit legacy name; every
        // duplicate keeps the bare historical name.
        let enum_name = if relative == "crates/eliot-types/src/ul/cue.rs" {
            "LegacyCueKindV1"
        } else {
            "CueKind"
        };
        let text = read_workspace(relative)?;
        let live = enum_variants(&strip_code(&text), enum_name)?;
        assert_eq!(live, recorded, "duplicate definition drift: {relative}");
    }
    Ok(())
}

// WORK_UNIT_CASE: 706/26
#[test]
fn case_26_every_row_has_owner_removal_and_invalidation() -> TestResult {
    let doc = manifest_doc()?;
    let allowed_migrations = [706, 804, 831, 832, 833, 834, 835, 929, 710, 598];
    for prefix in ["type_row.", "field_row."] {
        for (name, row) in prefixed_sections(&doc, prefix) {
            let owner = row_str(row, "owner", name)?;
            assert!(!owner.is_empty(), "missing owner in {name}");
            assert!(
                owner.starts_with('#'),
                "owner without issue handle in {name}: {owner}"
            );
            let migration = row_int(row, "migration", name)?;
            assert!(
                allowed_migrations.contains(&migration),
                "unknown migration issue in {name}: {migration}"
            );
            let expiry = row_str(row, "expiry", name)?;
            assert!(expiry.len() >= 8, "empty invalidation in {name}");
            assert!(
                expiry.contains("invalid")
                    || expiry.contains("removal")
                    || expiry.contains("current-authority")
                    || expiry.contains("retain"),
                "no invalidation vocabulary in {name}: {expiry}"
            );
        }
    }
    Ok(())
}

// WORK_UNIT_CASE: 706/27
#[test]
fn case_27_new_unlisted_consumer_fails() -> TestResult {
    let synthetic = "use eliot_types::CueKind;\nlet kind = CueKind::FilePath;\n";
    assert_eq!(matched_lines(synthetic, "CueKind").len(), 2);
    assert_eq!(matched_lines("let kind = 1;\n", "CueKind").len(), 0);
    let doc = manifest_doc()?;
    let live = scan_files(&LEGACY_DIRS, "CueKind")?;
    let expected = expected_row_paths(&doc, "type_row.")
        .into_iter()
        .filter(|path| {
            LEGACY_DIRS
                .iter()
                .any(|dir| path == dir || path.starts_with(&format!("{dir}/")))
        })
        .collect::<Vec<_>>();
    for path in &live {
        assert!(expected.contains(path), "new unlisted consumer: {path}");
    }
    assert_eq!(live.len(), expected.len());
    Ok(())
}

// WORK_UNIT_CASE: 706/28
#[test]
fn case_28_new_duplicate_fails() -> TestResult {
    // Built at runtime so this oracle never prints a duplicate definition.
    let def_needle = ["enum", "CueKind"].join(" ");
    let synthetic = ["pub ", &def_needle, " {\n    FilePath,\n}\n"].concat();
    assert_eq!(matched_lines(&synthetic, &def_needle).len(), 1);
    let live = scan_files(
        &["crates/smart", "crates/foundation", "crates/eliot-types"],
        &def_needle,
    )?;
    let mut expected = vec![
        "crates/smart/eliot-context/src/lib.rs".to_owned(),
        "crates/smart/eliot-cue-contracts/src/normalization.rs".to_owned(),
        "crates/smart/eliot-cues/src/lib.rs".to_owned(),
    ];
    expected.sort();
    assert_eq!(live, expected, "new duplicate definition or lost row");
    Ok(())
}

// WORK_UNIT_CASE: 706/29
#[test]
fn case_29_oracle_detects_forbidden_local_alias_use() -> TestResult {
    assert!(flag_forbidden_alias_use("use crate::CueKind;"));
    assert!(flag_forbidden_alias_use("    pub kind: CueKind,"));
    assert!(flag_forbidden_alias_use("CueKind::FilePath => {}"));
    assert!(flag_forbidden_alias_use("pub type CueKind ="));
    assert!(flag_forbidden_alias_use(
        "pub type CueKind = LegacyCueKindV1;"
    ));
    assert!(!flag_forbidden_alias_use("    pub kind: LegacyCueKindV1,"));
    assert!(!flag_forbidden_alias_use("let kind = 1;"));
    let prod = production_code()?;
    let mut hits = Vec::new();
    for line in prod.lines() {
        if flag_forbidden_alias_use(line) {
            hits.push(line.trim().to_owned());
        }
    }
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0], "pub type CueKind = LegacyCueKindV1;");
    Ok(())
}

// WORK_UNIT_CASE: 706/30
#[test]
fn case_30_oracle_detects_permissive_compatibility_escape() -> TestResult {
    assert!(flag_permissive_escape("#[serde(untagged)]"));
    assert!(flag_permissive_escape("#[serde(alias = \"path\")]"));
    assert!(flag_permissive_escape("    Other,"));
    assert!(flag_permissive_escape("    Unknown(String),"));
    assert!(flag_permissive_escape("        _ => {}"));
    assert!(flag_permissive_escape("impl Default for LegacyCueKindV1 {"));
    assert!(!flag_permissive_escape(
        "#[serde(rename_all = \"snake_case\")]"
    ));
    assert!(!flag_permissive_escape("    FilePath,"));
    let prod = production_code()?;
    let source = cue_rs_source()?;
    let stripped = strip_code(&source);
    let declaration = "pub enum LegacyCueKindV1";
    let start = stripped
        .find(declaration)
        .ok_or_else(|| boxed(std::io::Error::other("legacy enum missing")))?;
    let region = &stripped[start..];
    let end = region.find("impl LegacyCueKindV1").unwrap_or(region.len());
    for line in region[..end].lines() {
        assert!(
            !flag_permissive_escape(line),
            "escape in legacy enum: {line}"
        );
    }
    assert!(!prod.contains("impl Default for LegacyCueKindV1"));
    Ok(())
}

// WORK_UNIT_CASE: 706/31
#[test]
fn case_31_a10_only_future_value_rejected_by_v1() -> TestResult {
    for tag in ["future-binding", "future-comparison", "future-relation"] {
        let value = malformed_value(tag)?;
        let spelling = value
            .get("cue_kind")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                boxed(std::io::Error::other(format!(
                    "fixture without spelling: {tag}"
                )))
            })?;
        assert!(
            decode_kind(spelling).is_err(),
            "future value accepted: {tag}"
        );
        assert!(
            Seam::UNSUPPORTED_INPUTS.contains(&spelling),
            "future value outside descriptor: {tag}"
        );
    }
    let mut found = BTreeSet::new();
    for relative in [
        "crates/smart/eliot-cue-contracts/src/normalization.rs",
        "crates/smart/eliot-cue-contracts/src/version.rs",
        "crates/smart/eliot-cue-contracts/src/binding.rs",
        "crates/smart/eliot-cue-contracts/src/lib.rs",
    ] {
        let text = read_workspace(relative)?;
        for term in ["binding_candidate", "comparison_key", "relation_edge"] {
            if text.contains(term) {
                found.insert(term);
            }
        }
    }
    assert_eq!(
        found.len(),
        3,
        "future terms lack A-10 grounding: {found:?}"
    );
    Ok(())
}

// WORK_UNIT_CASE: 706/32
#[test]
fn case_32_bounded_malformed_input_panic_free() -> TestResult {
    let rows = malformed_rows()?;
    assert_eq!(rows.len(), 14);
    let mut attempted = 0;
    let mut rejected = 0;
    for (tag, value) in &rows {
        attempted += 1;
        if serde_json::from_value::<CueBinding>(value.clone()).is_err() {
            rejected += 1;
        } else {
            return fail(format!("malformed fixture decoded: {tag}"));
        }
    }
    let doc = manifest_doc()?;
    let variants = manifest_variants(&doc)?;
    for (_, spelling) in &variants {
        for probe in [
            format!("{spelling} "),
            format!(" {spelling}"),
            format!("{spelling}\n"),
            format!("{spelling}{}", "x".repeat(64)),
        ] {
            attempted += 1;
            if decode_kind(&probe).is_err() {
                rejected += 1;
            }
        }
    }
    for probe in [
        Value::Null,
        Value::Bool(true),
        Value::from(42),
        Value::Array(Vec::new()),
        Value::Object(serde_json::Map::default()),
    ] {
        attempted += 1;
        if serde_json::from_value::<LegacyCueKindV1>(probe).is_err() {
            rejected += 1;
        }
    }
    attempted += 1;
    let huge = CueBinding {
        cue_kind: LegacyCueKindV1::Concept,
        cue_value: "z".repeat(200_000),
        match_mode: CueMatchMode::Exact,
        strength: CueStrength::Primary,
        expected_reuse_note: Some("bounded probe".to_owned()),
    };
    let encoded = serde_json::to_value(&huge).map_err(boxed)?;
    match serde_json::from_value::<CueBinding>(encoded) {
        Ok(_) => {}
        Err(_) => rejected += 1,
    }
    assert_eq!(attempted, 14 + 40 + 5 + 1);
    assert!(
        rejected >= 14 + 40 + 5,
        "bounded probes unexpectedly decoded"
    );
    Ok(())
}

// WORK_UNIT_CASE: 706/33
#[test]
fn case_33_encode_decode_bijective_over_exact_v1() -> TestResult {
    let mut spellings = BTreeSet::new();
    for spelling in Seam::WIRE_SPELLINGS {
        let kind = decode_kind(spelling).map_err(boxed)?;
        assert_eq!(kind.as_str(), spelling);
        assert_eq!(
            serde_json::to_string(&kind).map_err(boxed)?,
            format!("\"{spelling}\"")
        );
        spellings.insert(spelling);
    }
    assert_eq!(spellings.len(), 10);
    Ok(())
}

// WORK_UNIT_CASE: 706/34
#[test]
fn case_34_unknown_cannot_construct_current_or_legacy_kind() -> TestResult {
    for probe in ["\"__nope__\"", "\"\"", "null", "42", "true", "[]", "{}"] {
        let value = serde_json::from_str::<Value>(probe).map_err(boxed)?;
        assert!(
            serde_json::from_value::<LegacyCueKindV1>(value).is_err(),
            "probe constructed a kind: {probe}"
        );
    }
    let prod = production_code()?;
    for token in [
        "pub fn from_str",
        "pub fn from_string",
        "impl FromStr",
        "From<&str> for LegacyCueKindV1",
        "From<String> for LegacyCueKindV1",
    ] {
        assert!(!prod.contains(token), "unchecked constructor: {token}");
    }
    Ok(())
}

// WORK_UNIT_CASE: 706/35
#[test]
fn case_35_diff_preserves_algorithms_without_self_handoff_or_suppression() -> TestResult {
    let prod = production_code()?;
    assert!(
        !prod.contains("allow(deprecated"),
        "lint suppression in legacy seam"
    );
    assert!(!prod.contains("todo!"));
    assert!(!prod.contains("unimplemented!"));
    let lib = read_workspace("crates/eliot-types/src/lib.rs")?;
    assert!(
        lib.contains("CueKind"),
        "root re-export migrated inside the seam issue"
    );
    let injection = read_workspace("crates/eliot-types/src/ul/injection.rs")?;
    assert!(
        injection.contains("CueKind"),
        "in-crate consumer migrated inside the seam issue"
    );
    let doc = manifest_doc()?;
    let api = find_section(&doc, "api")?;
    let mut live_types = BTreeSet::new();
    for line in prod.lines() {
        if !line.starts_with("pub ") {
            continue;
        }
        let trimmed = line.trim();
        for keyword in ["pub enum ", "pub struct ", "pub type "] {
            if let Some(rest) = trimmed.strip_prefix(keyword) {
                let name = rest
                    .split(|cell: char| !(cell.is_alphanumeric() || cell == '_'))
                    .next()
                    .unwrap_or("");
                if !name.is_empty() {
                    live_types.insert(name.to_owned());
                }
            }
        }
    }
    let recorded_types = row_array(api, "pub_types", "api")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(live_types, recorded_types, "public type surface drift");
    let mut live_fns = BTreeSet::new();
    for line in prod.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("pub fn ") {
            let name = rest.split('(').next().unwrap_or("").trim().to_owned();
            live_fns.insert(name);
        } else if let Some(rest) = trimmed.strip_prefix("pub const fn ") {
            let name = rest.split('(').next().unwrap_or("").trim().to_owned();
            live_fns.insert(name);
        }
    }
    let recorded_fns = row_array(api, "pub_fns", "api")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(live_fns, recorded_fns, "public function surface drift");
    let mut live_consts = BTreeSet::new();
    for line in prod.lines() {
        if !line.starts_with("pub const ") || line.starts_with("pub const fn ") {
            continue;
        }
        if let Some(rest) = line.trim().strip_prefix("pub const ") {
            let name = rest.split(':').next().unwrap_or("").trim().to_owned();
            live_consts.insert(name);
        }
    }
    let recorded_consts = row_array(api, "pub_consts", "api")?
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(live_consts, recorded_consts, "public const surface drift");
    Ok(())
}
