fn finalize_antigravity_contract(
    contract: &mut eliot_types::HostLaunchContract,
    idempotency_key: Option<&str>,
    timeout_seconds: Option<u64>,
) -> Result<()> {
    let idempotency_key = idempotency_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .context("governed Antigravity launch requires --idempotency-key")?;
    if idempotency_key.len() > 256
        || idempotency_key
            .chars()
            .any(|ch| ch.is_control() || ch.is_whitespace())
    {
        bail!("Antigravity --idempotency-key must be 1..=256 visible non-whitespace characters");
    }
    let timeout_seconds = timeout_seconds.unwrap_or(MAX_MANAGED_LAUNCH_SECONDS);
    if !(1..=MAX_MANAGED_LAUNCH_SECONDS).contains(&timeout_seconds) {
        bail!("Antigravity --timeout-seconds must be between 1 and {MAX_MANAGED_LAUNCH_SECONDS}");
    }
    idempotency_key.clone_into(&mut contract.idempotency_key);
    contract.invocation_id = stable_invocation_id(idempotency_key);
    contract.wall_clock_budget_seconds = timeout_seconds;
    contract.contract_hash.clear();
    contract.contract_hash = blake3::hash(&serde_json::to_vec(contract)?)
        .to_hex()
        .to_string();
    Ok(())
}

fn stable_invocation_id(idempotency_key: &str) -> String {
    format!(
        "host-invocation:{}",
        blake3::hash(idempotency_key.as_bytes()).to_hex()
    )
}

fn invocation_root(config_path: &Path, invocation_id: &str) -> PathBuf {
    runtime_root(config_path)
        .join("reports")
        .join("host-invocations")
        .join(invocation_id.replace(':', "_"))
}

impl ManagedInvocationLock {
    fn acquire(root: &Path) -> Result<Self> {
        std::fs::create_dir_all(root)?;
        let path = root.join("dispatch.lock");
        let created_unix_seconds = u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
            .context("managed lock timestamp predates the Unix epoch")?;
        let record_bytes = encode_managed_invocation_lock(ManagedInvocationLockRecord {
            owner_pid: std::process::id(),
            created_unix_seconds,
        });
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| {
                format!(
                    "managed invocation CAS is already owned or unavailable: {}",
                    path.display()
                )
            })?;
        let write_result = (|| -> std::io::Result<()> {
            file.write_all(&record_bytes)?;
            file.flush()?;
            file.sync_all()
        })();
        if let Err(error) = write_result {
            drop(file);
            let _ = std::fs::remove_file(&path);
            return Err(error).context("write durable managed invocation lock");
        }
        Ok(Self {
            path,
            _file: file,
            record_bytes,
        })
    }
}

fn encode_managed_invocation_lock(record: ManagedInvocationLockRecord) -> Vec<u8> {
    let payload = format!(
        "{MANAGED_LOCK_MAGIC}\n{:010}\n{:020}\n",
        record.owner_pid, record.created_unix_seconds
    );
    format!("{payload}{}\n", blake3::hash(payload.as_bytes()).to_hex()).into_bytes()
}

fn decode_managed_invocation_lock(bytes: &[u8]) -> Option<ManagedInvocationLockRecord> {
    let text = std::str::from_utf8(bytes).ok()?.strip_suffix('\n')?;
    let mut lines = text.lines();
    if lines.next()? != MANAGED_LOCK_MAGIC {
        return None;
    }
    let owner = lines.next()?;
    let created = lines.next()?;
    let checksum = lines.next()?;
    if lines.next().is_some()
        || owner.len() != 10
        || created.len() != 20
        || checksum.len() != 64
        || !owner.bytes().all(|byte| byte.is_ascii_digit())
        || !created.bytes().all(|byte| byte.is_ascii_digit())
        || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    let payload = format!("{MANAGED_LOCK_MAGIC}\n{owner}\n{created}\n");
    if blake3::hash(payload.as_bytes()).to_hex().as_str() != checksum {
        return None;
    }
    Some(ManagedInvocationLockRecord {
        owner_pid: owner.parse().ok()?,
        created_unix_seconds: created.parse().ok()?,
    })
}

fn invocation_lock_record(root: &Path) -> Result<ManagedInvocationLockRecordState> {
    let path = root.join("dispatch.lock");
    if !path.is_file() {
        return Ok(ManagedInvocationLockRecordState::Missing);
    }
    let bytes = std::fs::read(&path)?;
    if let Some(record) = decode_managed_invocation_lock(&bytes) {
        return Ok(ManagedInvocationLockRecordState::Valid(record));
    }
    let age = std::fs::metadata(path)?
        .modified()?
        .elapsed()
        .unwrap_or(Duration::ZERO);
    Ok(ManagedInvocationLockRecordState::Malformed { age })
}

fn read_managed_attempt(path: &Path) -> Result<ManagedAttemptJournalState> {
    if !path.is_file() {
        return Ok(ManagedAttemptJournalState::Missing);
    }
    let bytes = std::fs::read(path)?;
    Ok(match serde_json::from_slice(&bytes) {
        Ok(attempt) => ManagedAttemptJournalState::Valid(Box::new(attempt)),
        Err(_) => ManagedAttemptJournalState::Malformed,
    })
}

fn read_contained_antigravity_attempt(
    path: &Path,
) -> Result<Option<ContainedAntigravityAttemptJournal>> {
    if !path.is_file() {
        return Ok(None);
    }
    let bytes = std::fs::read(path)?;
    let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
        return Ok(None);
    };
    if value.get("schema_version").and_then(Value::as_str)
        != Some(CONTAINED_ANTIGRAVITY_ATTEMPT_SCHEMA_V1)
    {
        return Ok(None);
    }
    let attempt: ContainedAntigravityAttemptJournal = serde_json::from_value(value)?;
    validate_contained_antigravity_attempt(&attempt)?;
    Ok(Some(attempt))
}

fn provider_start_marker_path(root: &Path) -> PathBuf {
    root.join(PROVIDER_START_MARKER)
}

fn provider_may_have_started(root: &Path, attempt: Option<&ManagedHostAttemptJournal>) -> bool {
    provider_start_marker_path(root).exists()
        || attempt.is_some_and(|journal| journal.schema_version != MANAGED_ATTEMPT_SCHEMA_V4)
}

fn write_provider_start_marker(root: &Path, attempt_hash: &str) -> Result<()> {
    let path = provider_start_marker_path(root);
    if path.exists() {
        bail!("managed provider-start marker already exists");
    }
    atomic_write_bytes(
        &path,
        format!("ELIOT-PROVIDER-START-V1\n{attempt_hash}\n").as_bytes(),
    )
}

fn lock_owner_is_active(state: &ManagedInvocationLockRecordState) -> Result<bool> {
    match state {
        ManagedInvocationLockRecordState::Missing => Ok(false),
        ManagedInvocationLockRecordState::Valid(record) => {
            let now = u64::try_from(OffsetDateTime::now_utc().unix_timestamp())
                .context("managed lock timestamp predates the Unix epoch")?;
            Ok(eliot_windows_ipc::process_is_alive(record.owner_pid)?
                || now.saturating_sub(record.created_unix_seconds)
                    < MANAGED_LOCK_STALE_AFTER.as_secs())
        }
        ManagedInvocationLockRecordState::Malformed { age } => Ok(*age < MANAGED_LOCK_STALE_AFTER),
    }
}

fn clear_pre_provider_journals(root: &Path) -> Result<()> {
    for path in [root.join("attempt.json"), root.join("dispatch.lock")] {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn clear_contained_antigravity_pre_dispatch(root: &Path) -> Result<()> {
    for path in [
        provider_start_marker_path(root),
        root.join("attempt.json"),
    ] {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

fn hash_file_content(path: &Path) -> Result<String> {
    Ok(hash_bytes(&std::fs::read(path)?))
}

fn candidate_diff_path(value: &str, prefix: &str, allowed_paths: &[String]) -> Option<String> {
    let path = value.strip_prefix(prefix)?;
    if path.is_empty()
        || path
            .chars()
            .any(|character| matches!(character, '\t' | '\r' | '\n' | '"'))
    {
        return None;
    }
    let normalized = normalize_relative_path(path).ok()?;
    allowed_paths
        .iter()
        .any(|allowed| path_in_scope(&normalized, std::slice::from_ref(allowed)))
        .then_some(normalized)
}

fn candidate_metadata_path(value: &str, allowed_paths: &[String]) -> Option<String> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| matches!(character, '\t' | '\r' | '\n' | '"'))
    {
        return None;
    }
    let normalized = normalize_relative_path(value).ok()?;
    allowed_paths
        .iter()
        .any(|allowed| path_in_scope(&normalized, std::slice::from_ref(allowed)))
        .then_some(normalized)
}

fn valid_git_mode(value: &str) -> bool {
    value.len() == 6 && value.bytes().all(|byte| matches!(byte, b'0'..=b'7'))
}

fn valid_index_header(value: &str) -> bool {
    let mut fields = value.split_ascii_whitespace();
    let Some(range) = fields.next() else {
        return false;
    };
    let Some((old, new)) = range.split_once("..") else {
        return false;
    };
    let hashes_are_hex = !old.is_empty()
        && !new.is_empty()
        && old.bytes().all(|byte| byte.is_ascii_hexdigit())
        && new.bytes().all(|byte| byte.is_ascii_hexdigit());
    hashes_are_hex && fields.next().is_none_or(valid_git_mode) && fields.next().is_none()
}

fn valid_similarity_header(value: &str) -> bool {
    value
        .strip_suffix('%')
        .and_then(|percent| percent.parse::<u8>().ok())
        .is_some_and(|percent| percent <= 100)
}

fn parse_hunk_range(value: &str, prefix: char) -> Option<(u64, u64)> {
    let range = value.strip_prefix(prefix)?;
    let (start, count) = range
        .split_once(',')
        .map_or((range, "1"), |(start, count)| (start, count));
    if start.is_empty()
        || count.is_empty()
        || !start.bytes().all(|byte| byte.is_ascii_digit())
        || !count.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let start = start.parse::<u64>().ok()?;
    let count = count.parse::<u64>().ok()?;
    (count == 0 || start > 0).then_some((start, count))
}

fn parse_hunk_header(line: &str) -> Option<(u64, u64, u64, u64)> {
    let rest = line.strip_prefix("@@ ")?;
    let (ranges, section) = rest.split_once(" @@")?;
    if !section.is_empty() && !section.starts_with(' ') {
        return None;
    }
    let mut fields = ranges.split_ascii_whitespace();
    let (old_start, old_count) = parse_hunk_range(fields.next()?, '-')?;
    let (new_start, new_count) = parse_hunk_range(fields.next()?, '+')?;
    fields
        .next()
        .is_none()
        .then_some((old_start, old_count, new_start, new_count))
}

fn consume_hunk_line(line: &str, old_remaining: &mut u64, new_remaining: &mut u64) -> Option<bool> {
    match line.as_bytes().first()? {
        b' ' => {
            *old_remaining = old_remaining.checked_sub(1)?;
            *new_remaining = new_remaining.checked_sub(1)?;
            Some(false)
        }
        b'-' => {
            *old_remaining = old_remaining.checked_sub(1)?;
            Some(true)
        }
        b'+' => {
            *new_remaining = new_remaining.checked_sub(1)?;
            Some(true)
        }
        _ => None,
    }
}

#[derive(Default)]
struct CandidateDiffMetadata {
    seen: BTreeSet<&'static str>,
    rename_from: Option<String>,
    rename_to: Option<String>,
    copy_from: Option<String>,
    copy_to: Option<String>,
}

impl CandidateDiffMetadata {
    fn mark(&mut self, name: &'static str) -> Option<()> {
        self.seen.insert(name).then_some(())
    }
}

fn parse_candidate_metadata_line(
    line: &str,
    metadata: &mut CandidateDiffMetadata,
    allowed_paths: &[String],
) -> Option<()> {
    if let Some(value) = line.strip_prefix("index ") {
        metadata.mark("index")?;
        return valid_index_header(value).then_some(());
    }
    for (prefix, name) in [
        ("new file mode ", "new_file_mode"),
        ("deleted file mode ", "deleted_file_mode"),
        ("old mode ", "old_mode"),
        ("new mode ", "new_mode"),
    ] {
        if let Some(value) = line.strip_prefix(prefix) {
            metadata.mark(name)?;
            return valid_git_mode(value).then_some(());
        }
    }
    for (prefix, name) in [
        ("similarity index ", "similarity"),
        ("dissimilarity index ", "dissimilarity"),
    ] {
        if let Some(value) = line.strip_prefix(prefix) {
            metadata.mark(name)?;
            return valid_similarity_header(value).then_some(());
        }
    }
    let (slot, value) = if let Some(value) = line.strip_prefix("rename from ") {
        (&mut metadata.rename_from, value)
    } else if let Some(value) = line.strip_prefix("rename to ") {
        (&mut metadata.rename_to, value)
    } else if let Some(value) = line.strip_prefix("copy from ") {
        (&mut metadata.copy_from, value)
    } else if let Some(value) = line.strip_prefix("copy to ") {
        (&mut metadata.copy_to, value)
    } else {
        return None;
    };
    slot.replace(candidate_metadata_path(value, allowed_paths)?)
        .is_none()
        .then_some(())
}

fn validate_candidate_metadata(
    metadata: &CandidateDiffMetadata,
    old_path: &str,
    new_path: &str,
) -> Option<()> {
    let valid = metadata.rename_from.is_some() == metadata.rename_to.is_some()
        && metadata.copy_from.is_some() == metadata.copy_to.is_some()
        && !(metadata.rename_from.is_some() && metadata.copy_from.is_some())
        && metadata
            .rename_from
            .as_deref()
            .is_none_or(|path| path == old_path)
        && metadata
            .rename_to
            .as_deref()
            .is_none_or(|path| path == new_path)
        && metadata
            .copy_from
            .as_deref()
            .is_none_or(|path| path == old_path)
        && metadata
            .copy_to
            .as_deref()
            .is_none_or(|path| path == new_path)
        && metadata.seen.contains("old_mode") == metadata.seen.contains("new_mode")
        && !(metadata.seen.contains("new_file_mode")
            && metadata.seen.contains("deleted_file_mode"))
        && !(metadata.seen.contains("similarity") && metadata.seen.contains("dissimilarity"));
    valid.then_some(())
}

fn parse_candidate_file_headers(
    lines: &[&str],
    mut index: usize,
    metadata: &CandidateDiffMetadata,
    old_path: &str,
    new_path: &str,
    allowed_paths: &[String],
) -> Option<usize> {
    let old_header = lines.get(index)?.strip_prefix("--- ")?;
    let old_is_null = old_header == "/dev/null";
    if !old_is_null && candidate_diff_path(old_header, "a/", allowed_paths)? != old_path {
        return None;
    }
    index += 1;
    let new_header = lines.get(index)?.strip_prefix("+++ ")?;
    let new_is_null = new_header == "/dev/null";
    if !new_is_null && candidate_diff_path(new_header, "b/", allowed_paths)? != new_path {
        return None;
    }
    let has_mode_change = metadata.seen.contains("old_mode") || metadata.seen.contains("new_mode");
    let has_move = metadata.rename_from.is_some() || metadata.copy_from.is_some();
    let valid = old_is_null == metadata.seen.contains("new_file_mode")
        && new_is_null == metadata.seen.contains("deleted_file_mode")
        && !(old_is_null && new_is_null)
        && !((old_is_null || new_is_null) && (has_move || has_mode_change));
    valid.then_some(index + 1)
}

fn parse_candidate_hunks(lines: &[&str], mut index: usize) -> Option<usize> {
    let mut hunks = 0_usize;
    let mut section_changed = false;
    let mut prior_old_end = None;
    let mut prior_new_end = None;
    while index < lines.len() && !lines[index].starts_with("diff --git ") {
        let (old_start, mut old_remaining, new_start, mut new_remaining) =
            parse_hunk_header(lines[index])?;
        if prior_old_end.is_some_and(|end| old_start < end)
            || prior_new_end.is_some_and(|end| new_start < end)
        {
            return None;
        }
        prior_old_end = Some(old_start.checked_add(old_remaining)?);
        prior_new_end = Some(new_start.checked_add(new_remaining)?);
        hunks = hunks.checked_add(1)?;
        index += 1;
        let mut saw_data_line = false;
        let mut previous_was_data = false;
        while index < lines.len()
            && !lines[index].starts_with("@@ ")
            && !lines[index].starts_with("diff --git ")
        {
            let line = lines[index];
            if line == "\\ No newline at end of file" {
                if !previous_was_data {
                    return None;
                }
                previous_was_data = false;
            } else {
                section_changed |= consume_hunk_line(line, &mut old_remaining, &mut new_remaining)?;
                saw_data_line = true;
                previous_was_data = true;
            }
            index += 1;
        }
        if !saw_data_line || old_remaining != 0 || new_remaining != 0 {
            return None;
        }
    }
    (hunks > 0 && section_changed).then_some(index)
}

fn parse_candidate_diff_section(
    lines: &[&str],
    mut index: usize,
    allowed_paths: &[String],
) -> Option<usize> {
    let header = lines.get(index)?.strip_prefix("diff --git ")?;
    let mut fields = header.split_ascii_whitespace();
    let old_path = candidate_diff_path(fields.next()?, "a/", allowed_paths)?;
    let new_path = candidate_diff_path(fields.next()?, "b/", allowed_paths)?;
    if fields.next().is_some() {
        return None;
    }
    index += 1;
    let mut metadata = CandidateDiffMetadata::default();
    while index < lines.len() && !lines[index].starts_with("--- ") {
        parse_candidate_metadata_line(lines[index], &mut metadata, allowed_paths)?;
        index += 1;
    }
    validate_candidate_metadata(&metadata, &old_path, &new_path)?;
    index =
        parse_candidate_file_headers(lines, index, &metadata, &old_path, &new_path, allowed_paths)?;
    parse_candidate_hunks(lines, index)
}

fn candidate_unified_diff_hash(bytes: &[u8], allowed_paths: &[String]) -> Option<String> {
    let output = std::str::from_utf8(bytes).ok()?;
    if output.is_empty() || allowed_paths.is_empty() || output.contains("```") {
        return None;
    }
    let lines = output
        .lines()
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect::<Vec<_>>();
    let mut index = 0_usize;
    let mut sections = 0_usize;
    while index < lines.len() {
        index = parse_candidate_diff_section(&lines, index, allowed_paths)?;
        sections = sections.checked_add(1)?;
    }
    (sections > 0).then(|| hash_bytes(bytes))
}

fn managed_attempt_hash(attempt: &ManagedHostAttemptJournal) -> Result<String> {
    let mut material = attempt.clone();
    material.attempt_hash.clear();
    hash_json(&serde_json::to_value(material)?)
}

fn contained_antigravity_attempt_hash(
    attempt: &ContainedAntigravityAttemptJournal,
) -> Result<String> {
    let mut material = attempt.clone();
    material.attempt_hash.clear();
    hash_json(&serde_json::to_value(material)?)
}

fn validate_contained_antigravity_attempt(
    attempt: &ContainedAntigravityAttemptJournal,
) -> Result<()> {
    if attempt.schema_version != CONTAINED_ANTIGRAVITY_ATTEMPT_SCHEMA_V1
        || attempt.host != AgentHostId::Antigravity
        || !attempt.attempt_recorded_before_provider_call
        || !attempt.provider_call_budget_consumed
        || attempt.redispatch_allowed
        || attempt.owner_pid == 0
        || attempt.attempt_hash != contained_antigravity_attempt_hash(attempt)?
    {
        bail!("contained Antigravity attempt journal is incomplete or tampered");
    }
    Ok(())
}

fn validate_attempt_journal(attempt: &ManagedHostAttemptJournal) -> Result<()> {
    if !matches!(attempt.schema_version.as_str(), MANAGED_ATTEMPT_SCHEMA_V4)
        || !attempt.attempt_recorded_before_provider_call
        || attempt.redispatch_allowed
        || attempt.owner_pid == 0
        || attempt.attempt_hash != managed_attempt_hash(attempt)?
    {
        bail!("managed launch attempt journal is incomplete or tampered");
    }
    Ok(())
}

fn managed_launch_boundary_attestation(
    profile: &eliot_types::AgentHostRuntimeProfile,
    program: &str,
    bundle: &Path,
    invocation_root: &Path,
    environment: ManagedSanitizedEnvironment,
) -> Result<ManagedLaunchBoundaryAttestation> {
    if profile.host_id != AgentHostId::Antigravity {
        bail!("managed launch boundary requires the Antigravity host profile");
    }
    let executable = Path::new(program)
        .canonicalize()
        .context("canonicalize managed agy executable")?;
    let profiled_executable = Path::new(&profile.executable_path)
        .canonicalize()
        .context("canonicalize profiled agy executable")?;
    let executable_hash = hash_file_content(&executable)?;
    if executable_hash != profile.executable_hash
        || profile.version.trim().is_empty()
        || profile.capability_probe_receipt.trim().is_empty()
    {
        bail!("managed agy executable identity lacks a current hash, version, or probe receipt");
    }

    let bundle = bundle
        .canonicalize()
        .context("canonicalize managed Antigravity integration bundle")?;
    let (manifest, lifecycle) = integration_refs(&bundle, AgentHostId::Antigravity);
    let manifest: Value = serde_json::from_reader(File::open(manifest)?)?;
    if manifest.get("schema_version").and_then(Value::as_str)
        != Some("eliot-antigravity-integration-v1")
        || manifest.get("host").and_then(Value::as_str) != Some("antigravity")
        || !lifecycle.is_file()
    {
        bail!("managed Antigravity integration bundle is incomplete");
    }

    assert_managed_path_is_local_and_private(invocation_root)?;
    let sandbox_root = Path::new(&environment.sandbox_root);
    assert_managed_path_is_local_and_private(sandbox_root)?;
    let executable_is_profiled = executable == profiled_executable;
    let executable_is_isolated_snapshot =
        path_is_within(&executable, sandbox_root).unwrap_or(false);
    if !executable_is_profiled && !executable_is_isolated_snapshot {
        bail!("managed agy executable identity differs from the probed host profile");
    }
    if !environment.inherited_environment_cleared
        || environment.inherited_environment_allowlist.iter().any(|name| {
            !matches!(
                name.as_str(),
                "SystemRoot"
                    | "WINDIR"
                    | "ComSpec"
                    | "USERPROFILE"
                    | "HOME"
                    | "LOCALAPPDATA"
                    | "APPDATA"
            )
        })
        || environment
            .isolated_paths
            .iter()
            .any(|path| !path_is_within(Path::new(path), sandbox_root).unwrap_or(false))
    {
        bail!("managed Antigravity environment is not isolated under its owned sandbox");
    }

    Ok(ManagedLaunchBoundaryAttestation {
        schema_version: "eliot-managed-launch-boundary-v1".to_owned(),
        executable_path: executable.to_string_lossy().into_owned(),
        executable_hash,
        executable_version: profile.version.clone(),
        capability_probe_receipt: profile.capability_probe_receipt.clone(),
        integration_bundle_ref: bundle.to_string_lossy().into_owned(),
        integration_bundle_hash: bundle_hash(&bundle, AgentHostId::Antigravity)?,
        invocation_root: invocation_root.to_string_lossy().into_owned(),
        environment,
    })
}

fn managed_launch_boundary_is_current(boundary: &ManagedLaunchBoundaryAttestation) -> bool {
    let sandbox_root = Path::new(&boundary.environment.sandbox_root);
    let executable_matches = hash_file_content(Path::new(&boundary.executable_path))
        .is_ok_and(|hash| hash == boundary.executable_hash);
    let bundle_matches = bundle_hash(
        Path::new(&boundary.integration_bundle_ref),
        AgentHostId::Antigravity,
    )
    .is_ok_and(|hash| hash == boundary.integration_bundle_hash);
    executable_matches
        && bundle_matches
        && assert_managed_path_is_local_and_private(Path::new(&boundary.invocation_root)).is_ok()
        && assert_managed_path_is_local_and_private(sandbox_root).is_ok()
        && boundary.environment.inherited_environment_cleared
        && boundary
            .environment
            .isolated_paths
            .iter()
            .all(|path| path_is_within(Path::new(path), sandbox_root).unwrap_or(false))
}

fn managed_worktree_snapshot(root: &Path) -> Result<ManagedWorktreeSnapshot> {
    let head = git_text(root, &["rev-parse", "HEAD"])?;
    let status = git_bytes(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    let diff = git_bytes(root, &["diff", "--binary", "HEAD"])?;
    let untracked = git_bytes(root, &["ls-files", "--others", "--exclude-standard", "-z"])?;
    let mut untracked_hasher = blake3::Hasher::new();
    for name in untracked
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let name = String::from_utf8(name.to_vec())?;
        let relative = normalize_relative_path(&name)?;
        untracked_hasher.update(relative.as_bytes());
        untracked_hasher.update(&[0]);
        untracked_hasher.update(&std::fs::read(root.join(&relative))?);
        untracked_hasher.update(&[0]);
    }
    let status_hash = hash_bytes(&status);
    let diff_hash = hash_bytes(&diff);
    let untracked_hash = format!("blake3:{}", untracked_hasher.finalize().to_hex());
    let aggregate_hash =
        hash_bytes(format!("{head}\n{status_hash}\n{diff_hash}\n{untracked_hash}").as_bytes());
    Ok(ManagedWorktreeSnapshot {
        head,
        status_hash,
        diff_hash,
        untracked_hash,
        aggregate_hash,
    })
}

fn managed_sandbox_root(contract: &eliot_types::HostLaunchContract) -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .context("LOCALAPPDATA is required for managed Antigravity isolation")?;
    let root = local
        .join("Eliot")
        .join("host-sandboxes")
        .join("antigravity")
        .join(contract.invocation_id.replace(':', "_"));
    assert_managed_path_is_local_and_private(&root)?;
    Ok(root)
}

fn prepare_antigravity_executable_snapshot(
    profile: &eliot_types::AgentHostRuntimeProfile,
    contract: &eliot_types::HostLaunchContract,
) -> Result<PathBuf> {
    if profile.host_id != AgentHostId::Antigravity {
        bail!("Antigravity executable isolation requires an Antigravity host profile");
    }
    let source = Path::new(&profile.executable_path)
        .canonicalize()
        .context("canonicalize profiled agy executable for isolation")?;
    if hash_file_content(&source)? != profile.executable_hash {
        bail!("profiled agy executable changed before isolated launch");
    }
    let provider_bin = managed_sandbox_root(contract)?.join("provider-bin");
    std::fs::create_dir_all(&provider_bin)?;
    let file_name = source
        .file_name()
        .context("profiled agy executable has no file name")?;
    let snapshot = provider_bin.join(file_name);
    if snapshot.exists() {
        if hash_file_content(&snapshot)? != profile.executable_hash {
            bail!("isolated agy executable snapshot already exists with a different hash");
        }
        return Ok(snapshot);
    }

    let partial = provider_bin.join(format!(
        "{}.partial-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut input = File::open(&source)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)?;
    std::io::copy(&mut input, &mut output)?;
    output.flush()?;
    output.sync_all()?;
    drop(output);
    std::fs::rename(&partial, &snapshot)?;
    if hash_file_content(&snapshot)? != profile.executable_hash {
        bail!("isolated agy executable snapshot hash differs from the probed profile");
    }
    Ok(snapshot)
}

fn lock_antigravity_executable_snapshot(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        options.share_mode(FILE_SHARE_READ);
    }
    options
        .open(path)
        .context("lock isolated agy executable against self-update")
}

const REDACTED_MANAGED_OUTPUT_LINE: &str = "[REDACTED:SENSITIVE_MANAGED_HOST_OUTPUT]";
const MANAGED_PROVIDER_CREDENTIAL_PREFIXES: &[(&str, &str)] = &[
    ("github_pat_", "provider_credential"),
    ("ghp_", "provider_credential"),
    ("gho_", "provider_credential"),
    ("ghu_", "provider_credential"),
    ("ghs_", "provider_credential"),
    ("ghr_", "provider_credential"),
    ("sk-", "provider_credential"),
    ("sk-proj-", "provider_credential"),
    ("xoxb-", "provider_credential"),
    ("xoxp-", "provider_credential"),
    ("akia", "aws_access_key"),
    ("-----begin private key-----", "private_key"),
    ("-----begin rsa private key-----", "private_key"),
    ("-----begin openssh private key-----", "private_key"),
];
const MANAGED_CREDENTIAL_ASSIGNMENT_KEYS: &[(&str, &str)] = &[
    ("api_key", "api_key"),
    ("api-key", "api_key"),
    ("apikey", "api_key"),
    ("api_token", "api_token"),
    ("api-token", "api_token"),
    ("token", "token"),
    ("password", "password"),
    ("secret", "secret"),
    ("client_secret", "client_secret"),
    ("client-secret", "client_secret"),
    ("access_token", "access_token"),
    ("access-token", "access_token"),
    ("refresh_token", "refresh_token"),
    ("refresh-token", "refresh_token"),
    ("aws_secret_access_key", "aws_secret_access_key"),
];

fn sanitize_managed_output(output: &[u8]) -> SanitizedManagedOutput {
    let text = String::from_utf8_lossy(output);
    let mut retained = String::with_capacity(text.len());
    let mut markers = BTreeSet::new();
    let mut redact_continuation = false;
    for line in text.split_inclusive('\n') {
        let mut line_markers = managed_output_markers(line);
        let is_continuation = line.starts_with(' ') || line.starts_with('\t');
        if redact_continuation && is_continuation {
            line_markers.insert("credential_continuation".to_owned());
        }
        redact_continuation = if is_continuation {
            redact_continuation
        } else {
            managed_header_requires_continuation_redaction(line)
        };
        if line_markers.is_empty() {
            retained.push_str(line);
            continue;
        }
        markers.extend(line_markers);
        retained.push_str(REDACTED_MANAGED_OUTPUT_LINE);
        if line.ends_with('\n') {
            retained.push('\n');
        }
    }
    let bytes = retained.into_bytes();
    SanitizedManagedOutput {
        receipt: ManagedOutputRedactionReceipt {
            redacted: !markers.is_empty(),
            markers: markers.into_iter().collect(),
            original_bytes: output.len(),
            retained_bytes: bytes.len(),
        },
        bytes,
    }
}

fn managed_output_markers(line: &str) -> BTreeSet<String> {
    let lower = line.to_ascii_lowercase();
    let mut markers = MANAGED_PROVIDER_CREDENTIAL_PREFIXES
        .iter()
        .filter(|(prefix, _)| lower.contains(prefix))
        .map(|(_, marker)| (*marker).to_owned())
        .collect::<BTreeSet<_>>();
    if lower.contains("bearer ") {
        markers.insert("bearer".to_owned());
    }
    if lower.contains("basic ") && lower.contains("authorization") {
        markers.insert("basic_authorization".to_owned());
    }
    if contains_compact_jwt(line) {
        markers.insert("jwt".to_owned());
    }
    for (key, marker) in MANAGED_CREDENTIAL_ASSIGNMENT_KEYS {
        let mut remainder = lower.as_str();
        while let Some(index) = remainder.find(key) {
            let after_key = &remainder[index + key.len()..];
            if assigned_credential_value(after_key) {
                markers.insert((*marker).to_owned());
                break;
            }
            remainder = after_key;
        }
    }
    markers
}

fn managed_header_requires_continuation_redaction(line: &str) -> bool {
    let lower = line
        .trim_end_matches(['\r', '\n'])
        .trim_end()
        .to_ascii_lowercase();
    lower.ends_with("authorization:")
        || lower.ends_with("proxy-authorization:")
        || lower.ends_with("api_key:")
        || lower.ends_with("api-token:")
        || lower.ends_with("api_token:")
        || lower.ends_with("password:")
        || lower.ends_with("secret:")
}

fn contains_compact_jwt(text: &str) -> bool {
    text.split(|character: char| {
        character.is_whitespace()
            || matches!(
                character,
                '"' | '\'' | ',' | ':' | ';' | '=' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    })
    .any(|candidate| {
        let mut segments = candidate.split('.');
        let Some(header) = segments.next() else {
            return false;
        };
        let Some(payload) = segments.next() else {
            return false;
        };
        let Some(signature) = segments.next() else {
            return false;
        };
        segments.next().is_none()
            && header.starts_with("eyJ")
            && payload.len() >= 8
            && signature.len() >= 8
            && [header, payload, signature].iter().all(|segment| {
                segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            })
    })
}

fn assigned_credential_value(after_key: &str) -> bool {
    let separator = after_key.trim_start_matches([' ', '\t', '"', '\'']);
    let Some(value) = separator
        .strip_prefix(':')
        .or_else(|| separator.strip_prefix('='))
    else {
        return false;
    };
    let value = value.trim_start_matches([' ', '\t', '"', '\'', '\\']);
    if value.starts_with("null")
        || value.starts_with("none")
        || value.starts_with("redacted")
        || value.starts_with("<redacted")
    {
        return false;
    }
    value
        .chars()
        .take_while(|character| {
            !character.is_whitespace() && !matches!(character, '"' | '\'' | ',' | '}' | ']' | '\\')
        })
        .take(8)
        .count()
        == 8
}

const STANDARD_MANAGED_ENV_ALLOWLIST: &[&str] = &[
    "SystemRoot",
    "WINDIR",
    "ComSpec",
    "PATH",
    "PATHEXT",
    "USERPROFILE",
    "HOME",
    "LOCALAPPDATA",
    "APPDATA",
    "TEMP",
    "TMP",
];

fn configure_standard_managed_environment(command: &mut Command, governor: &str) {
    command.env_clear();
    for name in STANDARD_MANAGED_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.env("ELIOT_GOVERNOR_EXE", governor);
}

fn configure_antigravity_environment(
    command: &mut Command,
    _config_path: &Path,
    contract: &eliot_types::HostLaunchContract,
    governor: &str,
) -> Result<ManagedSanitizedEnvironment> {
    let sandbox = managed_sandbox_root(contract)?;
    let temp = sandbox.join("temp");
    let provider_bin = sandbox.join("provider-bin");
    for path in [&temp, &provider_bin] {
        std::fs::create_dir_all(path)?;
    }
    command.env_clear();
    let mut inherited_environment_allowlist = Vec::new();
    for name in [
        "SystemRoot",
        "WINDIR",
        "ComSpec",
        "USERPROFILE",
        "HOME",
        "LOCALAPPDATA",
        "APPDATA",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
            inherited_environment_allowlist.push(name.to_owned());
        }
    }
    command
        .env("TEMP", &temp)
        .env("TMP", &temp)
        .env("ELIOT_GOVERNOR_EXE", governor)
        .env("AGY_CLI_DISABLE_AUTO_UPDATE", "1")
        .env("AGY_CLI_HIDE_ACCOUNT_INFO", "1");
    let mut environment_names = inherited_environment_allowlist.clone();
    environment_names.extend(["TEMP", "TMP"].into_iter().map(str::to_owned));
    environment_names.extend(
        launch_environment_names(AgentHostId::Antigravity, contract.mode, contract)
            .into_iter()
            .map(str::to_owned),
    );
    environment_names.sort();
    environment_names.dedup();
    Ok(ManagedSanitizedEnvironment {
        inherited_environment_cleared: true,
        inherited_environment_allowlist,
        environment_names,
        sandbox_root: sandbox.to_string_lossy().into_owned(),
        isolated_paths: [&temp, &provider_bin]
            .into_iter()
            .map(|path| path.to_string_lossy().into_owned())
            .collect(),
    })
}

#[allow(clippy::too_many_lines)]
fn launch_argv(
    host: AgentHostId,
    executable: &str,
    bundle: &Path,
    attach_session_plugin: bool,
    contract: &eliot_types::HostLaunchContract,
    structured_output_schema: Option<&Value>,
    prompt: Option<String>,
) -> Result<(String, Vec<String>)> {
    let mut args = Vec::new();
    match host {
        AgentHostId::OpenCode => {
            if contract.mode == HostMode::Supervised {
                args.extend(["run".to_owned(), "--format".to_owned(), "json".to_owned()]);
                args.extend([
                    "--agent".to_owned(),
                    if contract.work_lease_id.is_some() || contract.role_lease_id.is_some() {
                        "build".to_owned()
                    } else {
                        "plan".to_owned()
                    },
                ]);
            }
            args.extend(["--dir".to_owned(), contract.cwd_or_worktree.clone()]);
            if let Some(model) = &contract.model_route_if_selected {
                args.extend(["--model".to_owned(), model.clone()]);
            }
            if let Some(session) = &contract.session_id {
                args.extend(["--session".to_owned(), session.clone()]);
            }
        }
        AgentHostId::Claude => {
            // The plugin carries its own `.mcp.json`, whether Claude discovered
            // it as an installed plugin or we point at it with `--plugin-dir`.
            // Handing Claude that same file again through `--mcp-config`
            // attaches ELIOT a second time, which is how one session ended up
            // exposing the tool set under two MCP namespaces with two
            // competing authorities. Exactly one attachment, either way.
            if attach_session_plugin {
                args.extend([
                    "--plugin-dir".to_owned(),
                    bundle.to_string_lossy().into_owned(),
                ]);
            }
            if let Some(model) = &contract.model_route_if_selected {
                args.extend(["--model".to_owned(), model.clone()]);
            }
            if let Some(session) = &contract.session_id {
                args.extend([
                    if contract.permission_profile == "ul_structured_auditor" {
                        "--session-id"
                    } else {
                        "--resume"
                    }
                    .to_owned(),
                    session.clone(),
                ]);
            }
            if contract.mode == HostMode::Supervised {
                args.extend([
                    "--print".to_owned(),
                    "--output-format".to_owned(),
                    "stream-json".to_owned(),
                    "--verbose".to_owned(),
                    "--include-hook-events".to_owned(),
                    "--permission-mode".to_owned(),
                    if contract.permission_profile == "ul_structured_auditor" {
                        "dontAsk".to_owned()
                    } else if contract.work_lease_id.is_some() {
                        "default".to_owned()
                    } else {
                        "plan".to_owned()
                    },
                ]);
                if let Some(schema) = structured_output_schema {
                    args.extend([
                        "--json-schema".to_owned(),
                        serde_json::to_string(schema)
                            .context("serialize Claude structured output schema")?,
                    ]);
                }
                if contract.permission_profile == "ul_structured_auditor" {
                    args.extend([
                        "--allowedTools".to_owned(),
                        "Read,mcp__plugin_eliot_eliot__*".to_owned(),
                        "--disallowedTools".to_owned(),
                        "Bash,Edit,Write,NotebookEdit,WebFetch,WebSearch".to_owned(),
                    ]);
                }
            }
        }
        AgentHostId::Antigravity => {
            if contract.mode != HostMode::Supervised {
                bail!("Antigravity managed launch is supervised-only");
            }
            if contract.session_id.is_some() {
                bail!("Antigravity managed launch forbids ungoverned conversation resume");
            }
            args.extend([
                "--new-project".to_owned(),
                "--add-dir".to_owned(),
                contract.cwd_or_worktree.clone(),
            ]);
            args.extend([
                "--mode".to_owned(),
                "plan".to_owned(),
                "--sandbox".to_owned(),
            ]);
            if let Some(model) = &contract.model_route_if_selected {
                args.extend(["--model".to_owned(), model.clone()]);
            }
            args.extend([
                "--print-timeout".to_owned(),
                format!("{}s", contract.wall_clock_budget_seconds),
                "--print".to_owned(),
            ]);
        }
        AgentHostId::Codex => {
            bail!("{} is not an L7 managed launch target", host.as_str())
        }
    }
    if let Some(prompt) = prompt {
        if host == AgentHostId::Claude {
            // Claude's tool allow/deny flags accept a variable number of
            // values. Without the option terminator, the positional prompt is
            // consumed as another permission rule and print mode starts with
            // no input.
            args.push("--".to_owned());
        }
        args.push(if host == AgentHostId::Antigravity
            && contract.permission_profile != "ul_structured_auditor"
        {
            format!(
                "READ-ONLY GOVERNED PLAN. Do not create, edit, delete, rename, or commit files. Do not mutate user, global, OneDrive, ProgramData, or provider configuration. Return only a raw git-style candidate unified diff, with no Markdown fences, prose, or summary; the controller will review and apply it later. Exact candidate request: {prompt}"
            )
        } else if host == AgentHostId::Antigravity {
            format!(
                "READ-ONLY STRUCTURED REASONING. Do not create, edit, delete, rename, or commit files. Return only the requested JSON value, with no Markdown fences or prose. Exact request: {prompt}"
            )
        } else {
            prompt
        });
    } else if contract.mode == HostMode::Supervised {
        bail!("supervised host launch requires --prompt");
    }
    Ok((executable.to_owned(), args))
}

fn launch_environment_names(
    host: AgentHostId,
    mode: HostMode,
    contract: &eliot_types::HostLaunchContract,
) -> Vec<&'static str> {
    let mut names = vec!["ELIOT_GOVERNOR_EXE", "ELIOT_GOVERNOR_CONFIG"];
    if host == AgentHostId::Antigravity {
        names.extend([
            "SystemRoot",
            "WINDIR",
            "ComSpec",
            "USERPROFILE",
            "HOME",
            "LOCALAPPDATA",
            "APPDATA",
            "TEMP",
            "TMP",
        ]);
    } else {
        names.extend(STANDARD_MANAGED_ENV_ALLOWLIST.iter().copied());
    }
    if contract.agent_session_id.is_some() {
        names.push("ELIOT_AGENT_SESSION_ID");
    }
    if host == AgentHostId::Antigravity
        && contract.permission_profile == "ul_structured_auditor"
    {
        names.push("ELIOT_MCP_ACCESS_PROFILE");
    }
    if contract.task_id.is_some() {
        names.push("ELIOT_TASK_ID");
    }
    if contract.work_item_id.is_some() {
        names.push("ELIOT_WORK_ITEM_ID");
    }
    if contract.role_lease_id.is_some() {
        names.push("ELIOT_ROLE_LEASE_ID");
    }
    if contract.work_lease_id.is_some() {
        names.push("ELIOT_WORK_LEASE_ID");
    }
    if contract.project_id.is_some() {
        names.push("ELIOT_PROJECT_ID");
    }
    if contract.worktree_lease_id.is_some() {
        names.push("ELIOT_WORKTREE_LEASE_ID");
    }
    if host == AgentHostId::OpenCode {
        names.push("OPENCODE_CONFIG_DIR");
        if mode == HostMode::Supervised {
            names.push("XDG_CONFIG_HOME");
        }
    }
    if host == AgentHostId::Antigravity {
        names.push("AGY_CLI_DISABLE_AUTO_UPDATE");
        names.push("AGY_CLI_HIDE_ACCOUNT_INFO");
    }
    names
}
