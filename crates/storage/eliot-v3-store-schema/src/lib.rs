//! Deterministic V3 Memory Store schema and fixed `SurrealQL` query corpus.
//!
//! This crate owns bytes and metadata only. It does not open a database connection,
//! execute arbitrary queries, or claim that SurrealDB 3.3.4 has qualified the bundle.

use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;

mod queries;

pub use queries::{query, query_by_name, QUERIES};

pub const SCHEMA_BUNDLE_FORMAT: u32 = 1;
pub const RUNNER_PROTOCOL: u32 = 1;
pub const SCHEMA_GENERATION: u32 = 1;
pub const BUNDLE_DOMAIN: &str = "eliot-memory-schema-bundle-v1";
pub const QUERY_CORPUS_FORMAT: u32 = 1;
pub const QUERY_CORPUS_DOMAIN: &str = "eliot-memory-query-corpus-v1";

const WRAPPER_TEMPLATE: &str = include_str!("../assets/wrapper.surql");
const EXPECTED_CATALOG: &str = include_str!("../assets/expected_catalog.tsv");
const GOLDEN_DIGEST: &str = include_str!("../assets/bundle.sha256");
const QUERY_GOLDEN_DIGEST: &str = include_str!("../assets/query-corpus.sha256");
const MIGRATION_0001: &str = include_str!("../assets/migrations/0001_base.surql");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationAsset {
    pub name: &'static str,
    pub sql: &'static str,
}

pub const MIGRATIONS: &[MigrationAsset] = &[MigrationAsset {
    name: "0001_base.surql",
    sql: MIGRATION_0001,
}];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum QueryId {
    StoreProbe,
    StreamLookup,
    StreamInsert,
    StreamLock,
    StreamAdvance,
    CaptureIdentity,
    ObservationInsert,
    ContinuationTask,
    ContinuationSession,
    OpenMemoryCurrent,
    OpenMemoryHistory,
    OpenObservation,
    LinksForward,
    LinksReverse,
    LexicalObservation,
    LexicalMemory,
    DueJobs,
    ClaimJob,
    BackupStream,
    BackupObservation,
    BackupMemory,
    BackupMemoryHistory,
    BackupLink,
    BackupJob,
    InfoDatabase,
    InfoStream,
    InfoObservation,
    InfoMemory,
    InfoMemoryHistory,
    InfoLink,
    InfoJob,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryClass {
    Read,
    Mutation,
    SchemaRead,
}

impl QueryClass {
    const fn digest_tag(self) -> &'static str {
        match self {
            Self::Read => "Read",
            Self::Mutation => "Mutation",
            Self::SchemaRead => "SchemaRead",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueryBounds {
    pub max_input_bytes: usize,
    pub max_rows: usize,
    pub max_result_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QuerySpec {
    pub id: QueryId,
    pub name: &'static str,
    pub class: QueryClass,
    pub sql: &'static str,
    pub bounds: QueryBounds,
}

const SMALL_READ: QueryBounds = QueryBounds {
    max_input_bytes: 16 * 1024,
    max_rows: 2,
    max_result_bytes: 64 * 1024,
};
const PAGE_READ: QueryBounds = QueryBounds {
    max_input_bytes: 16 * 1024,
    max_rows: 256,
    max_result_bytes: 2 * 1024 * 1024,
};
const BACKUP_PAGE: QueryBounds = QueryBounds {
    max_input_bytes: 4 * 1024,
    max_rows: 512,
    max_result_bytes: 8 * 1024 * 1024,
};
const SCHEMA_READ: QueryBounds = QueryBounds {
    max_input_bytes: 1024,
    max_rows: 1,
    max_result_bytes: 1024 * 1024,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MetadataBindings {
    pub schema_bundle_format: u32,
    pub schema_generation: u32,
    pub schema_bundle_sha256: [u8; 32],
}

#[derive(Debug, Eq, PartialEq)]
pub enum BundleError {
    MissingFinalNewline(&'static str),
    ContainsCarriageReturn(&'static str),
    ContainsNul(&'static str),
    DuplicateAssetName(&'static str),
    DuplicateQueryName(&'static str),
    MissingMigrationPlaceholder,
    MalformedCatalogLine(&'static str),
    MissingCatalogDefinition(&'static str),
    DuplicateCatalogDefinition(&'static str),
    UnlistedCatalogDefinition(&'static str),
    AssetTooLarge(&'static str),
    InvalidGoldenDigest,
    InvalidQueryGoldenDigest,
    GoldenDigestMismatch { expected: [u8; 32], actual: [u8; 32] },
    QueryGoldenDigestMismatch { expected: [u8; 32], actual: [u8; 32] },
}

impl fmt::Display for BundleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFinalNewline(name) => write!(formatter, "asset {name} has no final newline"),
            Self::ContainsCarriageReturn(name) => write!(formatter, "asset {name} contains a carriage return"),
            Self::ContainsNul(name) => write!(formatter, "asset {name} contains a NUL byte"),
            Self::DuplicateAssetName(name) => write!(formatter, "duplicate migration asset name: {name}"),
            Self::DuplicateQueryName(name) => write!(formatter, "duplicate query name: {name}"),
            Self::MissingMigrationPlaceholder => formatter.write_str("wrapper has no migration placeholder"),
            Self::MalformedCatalogLine(line) => write!(formatter, "malformed catalog line: {line}"),
            Self::MissingCatalogDefinition(name) => write!(formatter, "missing catalog definition: {name}"),
            Self::DuplicateCatalogDefinition(name) => write!(formatter, "duplicate catalog definition: {name}"),
            Self::UnlistedCatalogDefinition(line) => write!(formatter, "unlisted catalog definition: {line}"),
            Self::AssetTooLarge(name) => write!(formatter, "asset {name} exceeds the u64 length prefix"),
            Self::InvalidGoldenDigest => formatter.write_str("bundle.sha256 is not one lowercase SHA-256 digest"),
            Self::InvalidQueryGoldenDigest => formatter.write_str("query-corpus.sha256 is not one lowercase SHA-256 digest"),
            Self::GoldenDigestMismatch { expected, actual } => write!(
                formatter,
                "bundle digest mismatch: expected {} actual {}",
                encode_hex(expected),
                encode_hex(actual)
            ),
            Self::QueryGoldenDigestMismatch { expected, actual } => write!(
                formatter,
                "query corpus digest mismatch: expected {} actual {}",
                encode_hex(expected),
                encode_hex(actual)
            ),
        }
    }
}

impl Error for BundleError {}

pub fn validate_assets() -> Result<(), BundleError> {
    validate_source_assets()?;
    let expected = parse_golden_digest()?;
    let actual = compute_bundle_digest()?;
    if expected != actual {
        return Err(BundleError::GoldenDigestMismatch { expected, actual });
    }
    let expected_queries = parse_query_golden_digest()?;
    let actual_queries = compute_query_corpus_digest()?;
    if expected_queries != actual_queries {
        return Err(BundleError::QueryGoldenDigestMismatch {
            expected: expected_queries,
            actual: actual_queries,
        });
    }
    Ok(())
}

fn validate_source_assets() -> Result<(), BundleError> {
    validate_text("wrapper.surql", WRAPPER_TEMPLATE)?;
    validate_text("expected_catalog.tsv", EXPECTED_CATALOG)?;
    validate_text("bundle.sha256", GOLDEN_DIGEST)?;
    validate_text("query-corpus.sha256", QUERY_GOLDEN_DIGEST)?;
    if !WRAPPER_TEMPLATE.contains("{{MIGRATION_ASSETS}}") {
        return Err(BundleError::MissingMigrationPlaceholder);
    }
    let _ = expected_catalog()?;

    for (index, asset) in MIGRATIONS.iter().enumerate() {
        validate_text(asset.name, asset.sql)?;
        if MIGRATIONS[..index].iter().any(|prior| prior.name == asset.name) {
            return Err(BundleError::DuplicateAssetName(asset.name));
        }
    }
    for (index, query) in QUERIES.iter().enumerate() {
        validate_text(query.name, query.sql)?;
        if QUERIES[..index].iter().any(|prior| prior.name == query.name) {
            return Err(BundleError::DuplicateQueryName(query.name));
        }
    }
    Ok(())
}

fn validate_text(name: &'static str, value: &str) -> Result<(), BundleError> {
    if !value.ends_with('\n') {
        return Err(BundleError::MissingFinalNewline(name));
    }
    if value.contains('\r') {
        return Err(BundleError::ContainsCarriageReturn(name));
    }
    if value.contains('\0') {
        return Err(BundleError::ContainsNul(name));
    }
    Ok(())
}

pub fn bundle_preimage() -> Result<Vec<u8>, BundleError> {
    validate_source_assets()?;
    let mut bytes = Vec::new();
    push_segment(&mut bytes, "bundle domain", BUNDLE_DOMAIN.as_bytes())?;
    push_segment(
        &mut bytes,
        "schema bundle format",
        SCHEMA_BUNDLE_FORMAT.to_string().as_bytes(),
    )?;
    push_segment(
        &mut bytes,
        "runner protocol",
        RUNNER_PROTOCOL.to_string().as_bytes(),
    )?;
    push_segment(&mut bytes, "wrapper.surql", WRAPPER_TEMPLATE.as_bytes())?;
    for asset in MIGRATIONS {
        push_segment(&mut bytes, asset.name, asset.name.as_bytes())?;
        push_segment(&mut bytes, asset.name, asset.sql.as_bytes())?;
    }
    push_segment(&mut bytes, "expected_catalog.tsv", EXPECTED_CATALOG.as_bytes())?;
    Ok(bytes)
}

fn push_segment(
    target: &mut Vec<u8>,
    name: &'static str,
    value: &[u8],
) -> Result<(), BundleError> {
    let length = u64::try_from(value.len()).map_err(|_| BundleError::AssetTooLarge(name))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(value);
    Ok(())
}

fn compute_bundle_digest() -> Result<[u8; 32], BundleError> {
    let digest = Sha256::digest(bundle_preimage()?);
    Ok(digest.into())
}

pub fn bundle_digest() -> Result<[u8; 32], BundleError> {
    validate_assets()?;
    compute_bundle_digest()
}

pub fn bundle_digest_hex() -> Result<String, BundleError> {
    Ok(encode_hex(&bundle_digest()?))
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn parse_golden_digest() -> Result<[u8; 32], BundleError> {
    let value = GOLDEN_DIGEST.trim_end_matches('\n');
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(BundleError::InvalidGoldenDigest);
    }
    let mut digest = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| BundleError::InvalidGoldenDigest)?;
        digest[index] = u8::from_str_radix(text, 16).map_err(|_| BundleError::InvalidGoldenDigest)?;
    }
    Ok(digest)
}

fn parse_query_golden_digest() -> Result<[u8; 32], BundleError> {
    let value = QUERY_GOLDEN_DIGEST.trim_end_matches('\n');
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(BundleError::InvalidQueryGoldenDigest);
    }
    let mut digest = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).map_err(|_| BundleError::InvalidQueryGoldenDigest)?;
        digest[index] = u8::from_str_radix(text, 16).map_err(|_| BundleError::InvalidQueryGoldenDigest)?;
    }
    Ok(digest)
}

pub fn query_corpus_preimage() -> Result<Vec<u8>, BundleError> {
    validate_source_assets()?;
    let mut bytes = Vec::new();
    push_segment(
        &mut bytes,
        "query corpus domain",
        QUERY_CORPUS_DOMAIN.as_bytes(),
    )?;
    push_segment(
        &mut bytes,
        "query corpus format",
        QUERY_CORPUS_FORMAT.to_string().as_bytes(),
    )?;
    for specification in QUERIES {
        push_segment(&mut bytes, specification.name, specification.name.as_bytes())?;
        push_segment(
            &mut bytes,
            specification.name,
            specification.class.digest_tag().as_bytes(),
        )?;
        push_segment(
            &mut bytes,
            specification.name,
            specification.bounds.max_input_bytes.to_string().as_bytes(),
        )?;
        push_segment(
            &mut bytes,
            specification.name,
            specification.bounds.max_rows.to_string().as_bytes(),
        )?;
        push_segment(
            &mut bytes,
            specification.name,
            specification.bounds.max_result_bytes.to_string().as_bytes(),
        )?;
        push_segment(&mut bytes, specification.name, specification.sql.as_bytes())?;
    }
    Ok(bytes)
}

fn compute_query_corpus_digest() -> Result<[u8; 32], BundleError> {
    let digest = Sha256::digest(query_corpus_preimage()?);
    Ok(digest.into())
}

pub fn query_corpus_digest() -> Result<[u8; 32], BundleError> {
    validate_assets()?;
    compute_query_corpus_digest()
}

pub fn query_corpus_digest_hex() -> Result<String, BundleError> {
    Ok(encode_hex(&query_corpus_digest()?))
}

pub fn metadata_bindings() -> Result<MetadataBindings, BundleError> {
    Ok(MetadataBindings {
        schema_bundle_format: SCHEMA_BUNDLE_FORMAT,
        schema_generation: SCHEMA_GENERATION,
        schema_bundle_sha256: bundle_digest()?,
    })
}

pub fn render_transaction() -> Result<String, BundleError> {
    validate_assets()?;
    let migrations = MIGRATIONS.iter().map(|asset| asset.sql).collect::<Vec<_>>().join("\n");
    Ok(WRAPPER_TEMPLATE.replacen("{{MIGRATION_ASSETS}}", &migrations, 1))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogEntry {
    pub category: &'static str,
    pub name: &'static str,
    pub definition: &'static str,
}

pub fn expected_catalog_manifest() -> &'static str {
    EXPECTED_CATALOG
}

pub fn expected_catalog() -> Result<Vec<CatalogEntry>, BundleError> {
    let mut entries = Vec::new();
    for line in EXPECTED_CATALOG.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (category, name) = line.split_once('\t').ok_or(BundleError::MalformedCatalogLine(line))?;
        if category.is_empty() || name.is_empty() || name.contains('\t') {
            return Err(BundleError::MalformedCatalogLine(line));
        }
        let mut matches = MIGRATIONS
            .iter()
            .flat_map(|asset| asset.sql.lines())
            .filter(|definition| catalog_definition_matches(definition, category, name));
        let definition = matches.next().ok_or(BundleError::MissingCatalogDefinition(name))?;
        if matches.next().is_some() {
            return Err(BundleError::DuplicateCatalogDefinition(name));
        }
        entries.push(CatalogEntry {
            category,
            name,
            definition,
        });
    }

    for definition in MIGRATIONS
        .iter()
        .flat_map(|asset| asset.sql.lines())
        .filter(|line| line.starts_with("DEFINE "))
    {
        if !entries.iter().any(|entry| entry.definition == definition) {
            return Err(BundleError::UnlistedCatalogDefinition(definition));
        }
    }
    Ok(entries)
}

fn catalog_definition_matches(definition: &str, category: &str, name: &str) -> bool {
    let mut words = definition.split_whitespace();
    if words.next() != Some("DEFINE") {
        return false;
    }
    match category {
        "tables" => words.next() == Some("TABLE") && words.next() == Some(name),
        "analyzers" => words.next() == Some("ANALYZER") && words.next() == Some(name),
        "fields" | "indexes" => {
            let expected_kind = if category == "fields" { "FIELD" } else { "INDEX" };
            if words.next() != Some(expected_kind) {
                return false;
            }
            let Some(item) = words.next() else {
                return false;
            };
            if words.next() != Some("ON") || words.next() != Some("TABLE") {
                return false;
            }
            let Some(table) = words.next() else {
                return false;
            };
            name.strip_prefix(table)
                .and_then(|suffix| suffix.strip_prefix('.'))
                == Some(item)
        }
        _ => false,
    }
}
