use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// Current input schema for the bounded Skill-pack snapshot verifier.
pub const SKILL_PACK_SNAPSHOT_INPUT_SCHEMA_VERSION: &str = "eliot.skill-pack-snapshot.v1";
/// Current output schema for the bounded Skill-pack snapshot verifier.
pub const SKILL_PACK_SNAPSHOT_RESULT_SCHEMA_VERSION: &str = "eliot.skill-pack-snapshot-result.v1";
/// Maximum raw UTF-8 size of the manifest and all four Skill bodies combined.
pub const SKILL_PACK_SNAPSHOT_MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;

const MAX_SKILL_PACK_SNAPSHOT_FILE_BYTES: usize = 1024 * 1024;
const SKILL_PACK_MANIFEST_SCHEMA_VERSION: &str = "eliot-agent-skill-pack-v1";
/// Manifest marker for the canonical ordered BLAKE3 recipe.
pub const SKILL_PACK_HASH_ALGORITHM: &str =
    "blake3(name:content_blake3 joined with LF in manifest order)";
const SKILL_PACK_REFERENCE_ASSETS_SCHEMA: &str = "sha256-path-list-v1";

/// Skills in the order used by the canonical pack hash and manifest.
pub const ELIOT_SKILL_NAMES: [&str; 4] = [
    "eliot-work",
    "eliot-remember",
    "eliot-recover",
    "eliot-finish",
];

/// Host packages that carry a copy of the canonical Skill bodies.
pub const DERIVED_SKILL_PACKAGES: [&str; 4] = [
    "integrations/opencode/skills",
    "integrations/claude/eliot/skills",
    "plugin/eliot-governor/skills",
    "plugin/eliot-antigravity-official/skills",
];

/// One raw UTF-8 Skill body supplied with a snapshot verification request.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillPackSnapshotSkill {
    pub name: String,
    pub body_text: String,
}

/// Hashes for one body in the verified Skill snapshot.
#[derive(Clone, Debug, Serialize)]
pub struct SkillPackSnapshotSkillDigest {
    pub name: String,
    pub source_sha256: String,
    pub content_blake3: String,
}

/// Read-only verification result bound to the exact manifest and ordered bodies.
#[derive(Clone, Debug, Serialize)]
pub struct SkillPackSnapshotVerification {
    pub schema_version: String,
    pub manifest_sha256: String,
    pub pack_hash: String,
    pub skills: Vec<SkillPackSnapshotSkillDigest>,
}

/// A malformed or mismatched Skill-pack snapshot.
#[derive(Debug, Error)]
pub enum SkillPackSnapshotError {
    #[error("{0}")]
    Invalid(String),
    #[error("invalid manifest JSON: {0}")]
    ManifestJson(#[from] serde_json::Error),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillPackSnapshotManifest {
    schema_version: String,
    hash_algorithm: String,
    reference_assets_schema: String,
    pack_hash: String,
    #[serde(rename = "listing_characters")]
    _listing_characters: usize,
    skills: Vec<SkillPackSnapshotManifestSkill>,
    derived_packages: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillPackSnapshotManifestSkill {
    name: String,
    content_blake3: String,
    #[serde(rename = "reference_assets")]
    _reference_assets: Vec<ReferenceAsset>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReferenceAsset {
    #[serde(rename = "path")]
    _path: String,
    #[serde(rename = "sha256")]
    _sha256: String,
}

/// Computes the canonical BLAKE3 identity for one Skill body.
///
/// Only CRLF pairs are normalized for identity. The caller's source bytes are
/// left untouched and should be hashed separately when raw provenance matters.
pub fn canonical_skill_content_hash(body: &str) -> String {
    blake3::hash(body.replace("\r\n", "\n").as_bytes())
        .to_hex()
        .to_string()
}

/// Computes the ordered pack identity using one `name:hash\n` record per Skill.
pub fn canonical_skill_pack_hash(entries: &[(&str, &str)]) -> String {
    let mut pack_material = String::new();
    for &(name, content_blake3) in entries {
        pack_material.push_str(name);
        pack_material.push(':');
        pack_material.push_str(content_blake3);
        pack_material.push('\n');
    }
    blake3::hash(pack_material.as_bytes()).to_hex().to_string()
}

/// Verifies one exact manifest and its ordered raw Skill bodies without I/O.
pub fn verify_skill_pack_snapshot(
    manifest_text: &str,
    skills: &[SkillPackSnapshotSkill],
) -> Result<SkillPackSnapshotVerification, SkillPackSnapshotError> {
    if manifest_text.len() > MAX_SKILL_PACK_SNAPSHOT_FILE_BYTES {
        return Err(invalid("manifest exceeds the 1 MiB file limit"));
    }
    if skills.len() != ELIOT_SKILL_NAMES.len() {
        return Err(invalid(format!(
            "snapshot must contain exactly {} Skills",
            ELIOT_SKILL_NAMES.len()
        )));
    }

    let manifest = validate_skill_snapshot_manifest(manifest_text)?;
    let mut total_snapshot_bytes = manifest_text.len();
    let mut verified_skills = Vec::with_capacity(ELIOT_SKILL_NAMES.len());

    for (index, expected_name) in ELIOT_SKILL_NAMES.iter().enumerate() {
        let declared = &manifest.skills[index];
        if declared.name != *expected_name {
            return Err(invalid(format!(
                "manifest Skill order mismatch at index {index}"
            )));
        }
        let supplied = &skills[index];
        if supplied.name != *expected_name {
            return Err(invalid(format!(
                "snapshot Skill order mismatch at index {index}"
            )));
        }

        let body_bytes = supplied.body_text.as_bytes();
        if body_bytes.len() > MAX_SKILL_PACK_SNAPSHOT_FILE_BYTES {
            return Err(invalid(format!(
                "{} exceeds the 1 MiB file limit",
                supplied.name
            )));
        }
        total_snapshot_bytes = total_snapshot_bytes
            .checked_add(body_bytes.len())
            .ok_or_else(|| invalid("total snapshot size overflow"))?;
        if total_snapshot_bytes > SKILL_PACK_SNAPSHOT_MAX_TOTAL_BYTES {
            return Err(invalid("Skill snapshot exceeds the 8 MiB total limit"));
        }

        let content_blake3 = canonical_skill_content_hash(&supplied.body_text);
        if declared.content_blake3 != content_blake3 {
            return Err(invalid(format!(
                "{} content_blake3 does not match the manifest",
                supplied.name
            )));
        }
        verified_skills.push(SkillPackSnapshotSkillDigest {
            name: supplied.name.clone(),
            source_sha256: format!("{:x}", Sha256::digest(body_bytes)),
            content_blake3,
        });
    }

    let pack_entries = verified_skills
        .iter()
        .map(|skill| (skill.name.as_str(), skill.content_blake3.as_str()))
        .collect::<Vec<_>>();
    let pack_hash = canonical_skill_pack_hash(&pack_entries);
    if manifest.pack_hash != pack_hash {
        return Err(invalid(
            "manifest pack_hash does not match the ordered Skill snapshot",
        ));
    }

    Ok(SkillPackSnapshotVerification {
        schema_version: SKILL_PACK_SNAPSHOT_RESULT_SCHEMA_VERSION.to_owned(),
        manifest_sha256: format!("{:x}", Sha256::digest(manifest_text.as_bytes())),
        pack_hash,
        skills: verified_skills,
    })
}

fn validate_skill_snapshot_manifest(
    manifest_text: &str,
) -> Result<SkillPackSnapshotManifest, SkillPackSnapshotError> {
    let manifest: SkillPackSnapshotManifest = serde_json::from_str(manifest_text)?;
    if manifest.schema_version != SKILL_PACK_MANIFEST_SCHEMA_VERSION {
        return Err(invalid("manifest schema_version is missing or unsupported"));
    }
    if manifest.hash_algorithm != SKILL_PACK_HASH_ALGORITHM {
        return Err(invalid("manifest hash_algorithm is missing or unsupported"));
    }
    if manifest.reference_assets_schema != SKILL_PACK_REFERENCE_ASSETS_SCHEMA {
        return Err(invalid(
            "manifest reference_assets_schema is missing or unsupported",
        ));
    }
    if manifest.skills.len() != ELIOT_SKILL_NAMES.len() {
        return Err(invalid(format!(
            "manifest must declare exactly {} Skills",
            ELIOT_SKILL_NAMES.len()
        )));
    }
    let expected_derived_packages = DERIVED_SKILL_PACKAGES
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if manifest.derived_packages != expected_derived_packages {
        return Err(invalid(
            "manifest derived_packages do not match the canonical host packages",
        ));
    }
    Ok(manifest)
}

fn invalid(reason: impl Into<String>) -> SkillPackSnapshotError {
    SkillPackSnapshotError::Invalid(reason.into())
}
