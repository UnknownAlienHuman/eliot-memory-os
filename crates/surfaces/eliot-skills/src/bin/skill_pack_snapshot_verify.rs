use eliot_skills::{
    SKILL_PACK_SNAPSHOT_INPUT_SCHEMA_VERSION, SKILL_PACK_SNAPSHOT_MAX_TOTAL_BYTES,
    SkillPackSnapshotSkill, verify_skill_pack_snapshot,
};
use serde::Deserialize;
use std::error::Error;
use std::io::{self, Read, Write};

// JSON escapes can expand control characters sixfold; this bounds only the
// wire parser. The owner enforces the raw manifest/file and snapshot limits.
const MAX_REQUEST_BYTES: usize = SKILL_PACK_SNAPSHOT_MAX_TOTAL_BYTES * 6 + 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRequest {
    schema_version: String,
    manifest_text: String,
    skills: Vec<SkillPackSnapshotSkill>,
}

fn main() {
    if let Err(error) = run() {
        let mut stderr = io::stderr().lock();
        let _write_result = writeln!(stderr, "skill pack snapshot verification failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let request_bytes = read_bounded_request()?;
    let request: SnapshotRequest = serde_json::from_slice(&request_bytes)?;
    if request.schema_version != SKILL_PACK_SNAPSHOT_INPUT_SCHEMA_VERSION {
        return Err(invalid_data("unsupported snapshot request schema_version").into());
    }

    let result = verify_skill_pack_snapshot(&request.manifest_text, &request.skills)?;
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &result)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn read_bounded_request() -> Result<Vec<u8>, io::Error> {
    let limit = (MAX_REQUEST_BYTES + 1) as u64;
    let mut reader = io::stdin().lock().take(limit);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes)?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(invalid_data(
            "snapshot request exceeds the bounded wire limit",
        ));
    }
    Ok(bytes)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
