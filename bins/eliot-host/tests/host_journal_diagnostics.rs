#![allow(clippy::expect_used, clippy::unwrap_used)]
//! Host journal-boundary family diagnostic tests (issue #981).
//!
//! These tests verify the delivered diagnostic vocabulary of the nine-file
//! journal-boundary family against its shared record shape: one closed typed
//! observation vocabulary, eight per-file seams delegating to the single shared
//! emitter, only already-owned nonsecret handles as identity, every field
//! bounded before allocation, and no second terminal emission path.
//!
//! The six runtime modules (`journal_append`, `host_epoch_reopen`,
//! `readiness_gate`, `runtime_restart_state`, `store_recovery_evidence`,
//! `store_recovery_fence`) are private to the library and `eliot_host_state`'s
//! journal types are never re-exported, so this integration target reaches
//! them by name rather than by call: each instrumented path's runtime
//! execution belongs to the inline case that owns it, named in
//! `inline_owners`, and this target binds those owners by name plus the typed
//! evidence their own source carries. The only real execution here is the
//! family seam every instrumented file calls before it emits,
//! `note_event_log_sink_status()`, read back through a scoped `tracing`
//! subscriber with the clock disabled so the capture is comparable across runs.
//! The facade's own emission entry points (`observe_entrypoint_with_detail`,
//! `observe_terminal_error`) are never called from this target: it proves the
//! family's record shape and never manufactures a record of its own.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use eliot_host::HostKernelRestartReceipt;
use eliot_host::HostRuntimeControlOperation;
use eliot_host::HostRuntimeControlRequest;
use eliot_host::host_diagnostics::{
    DiagnosticSink, HostDiagnosticsError, bound_detail, bound_field, sink_status,
};
use serde_json::Value;

fn path_of(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

fn source_file(relative: &str) -> String {
    std::fs::read_to_string(path_of(relative)).expect("source file")
}

fn fixture() -> &'static Value {
    static FIXTURE: OnceLock<Value> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let bytes = std::fs::read(path_of("tests/data/host_journal_diagnostics.json"))
            .expect("fixture bytes");
        serde_json::from_slice(&bytes).expect("fixture json")
    })
}

fn fixture_array(key: &str) -> &'static Vec<Value> {
    fixture()
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("fixture key {key} must be a string array"))
}

fn fixture_object(key: &str) -> &'static serde_json::Map<String, Value> {
    fixture()
        .get(key)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("fixture key {key} must be an object"))
}

fn fixture_text(key: &str) -> &'static str {
    fixture()
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("fixture key {key} must be a string"))
}

fn strings(key: &str) -> Vec<String> {
    fixture_array(key)
        .iter()
        .map(|item| item.as_str().expect("string entry").to_owned())
        .collect()
}

fn mapping(key: &str) -> Vec<(String, String)> {
    fixture_object(key)
        .iter()
        .map(|(boundary, disposition)| {
            let named = disposition
                .as_str()
                .unwrap_or_else(|| panic!("{key} entry {boundary} must name a disposition"));
            (boundary.clone(), named.to_owned())
        })
        .collect()
}

fn vocabulary(key: &str) -> String {
    let text = fixture_object("vocabulary")
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("fixture vocabulary.{key} must be a string"));
    text.to_owned()
}

fn vocabulary_strings(key: &str) -> Vec<String> {
    let entries = fixture_object("vocabulary")
        .get(key)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("fixture vocabulary.{key} must be a string array"));
    entries
        .iter()
        .map(|item| item.as_str().expect("string entry").to_owned())
        .collect()
}

fn instrumented_paths() -> Vec<String> {
    strings("instrumented_paths")
}

/// Every instrumented source, read once: `(fixture path, file text)`.
fn instrumented_sources() -> &'static [(String, String)] {
    static SOURCES: OnceLock<Vec<(String, String)>> = OnceLock::new();
    SOURCES.get_or_init(|| {
        instrumented_paths()
            .into_iter()
            .map(|relative| {
                let text = source_file(&relative);
                (relative, text)
            })
            .collect()
    })
}

fn source(relative: &str) -> String {
    let entry = instrumented_sources()
        .iter()
        .find(|(path, _)| path == relative)
        .unwrap_or_else(|| panic!("{relative} is not an instrumented path"));
    entry.1.clone()
}

/// Every instrumented source joined in declared order.
fn all_source() -> String {
    static ALL: OnceLock<String> = OnceLock::new();
    ALL.get_or_init(|| {
        instrumented_sources()
            .iter()
            .map(|(_, text)| text.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    })
    .clone()
}

/// Index of the character after the closing paren of the call opened at
/// `open`, or `None` when that call never closes.
fn closing_paren(source_text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, character) in source_text[open..].char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// The source that must carry `boundary`'s typed disposition: the enclosing
/// `HostJournalObservation::new(..)` call when the record names its
/// disposition there, otherwise the bounded source that follows the spelling.
fn disposition_region<'a>(source_text: &'a str, boundary: &str) -> &'a str {
    let literal = format!("\"{boundary}\"");
    let index = source_text
        .find(&literal)
        .unwrap_or_else(|| panic!("boundary {boundary} is absent"));
    if let Some(opened) = source_text[..index].rfind("HostJournalObservation::new(")
        && let Some(closed) = closing_paren(source_text, opened)
        && closed >= index
    {
        return &source_text[opened..=closed];
    }
    let end = (index + literal.len() + 240).min(source_text.len());
    &source_text[index..end]
}

/// Disposition variants named literally inside one source region.
fn region_dispositions(region: &str) -> Vec<String> {
    let mut names: Vec<String> = region
        .match_indices("HostJournalDisposition::")
        .map(|(index, matched)| {
            region[index + matched.len()..]
                .chars()
                .take_while(char::is_ascii_alphanumeric)
                .collect()
        })
        .collect();
    names.sort();
    names.dedup();
    names
}

/// Closed disposition name to the variant spelling the source declares.
fn camel(name: &str) -> String {
    name.split('_')
        .map(|part| {
            let mut characters = part.chars();
            match characters.next() {
                Some(first) => first.to_uppercase().collect::<String>() + characters.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

/// The one instrumented source that carries `boundary`, with its fixture path.
fn boundary_source(boundary: &str) -> (String, String) {
    let literal = format!("\"{boundary}\"");
    let entry = instrumented_sources()
        .iter()
        .find(|(_, text)| text.contains(&literal))
        .unwrap_or_else(|| panic!("no instrumented source carries {boundary}"));
    (entry.0.clone(), entry.1.clone())
}

/// Bounded in-memory writer behind one scoped subscriber, so this target reads
/// back what the facade actually wrote without contending for the
/// process-global subscriber slot.
#[derive(Clone, Default)]
struct DiagnosticCapture {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl Write for DiagnosticCapture {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .lock()
            .map_err(|_| std::io::Error::other("diagnostic capture lock poisoned"))?
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Runs `body` under a scoped subscriber and returns everything written to the
/// shared sink. The clock and ANSI colouring are disabled so two identical
/// runs compare field by field instead of by wall-clock timestamp or styling.
fn emit(body: impl FnOnce()) -> String {
    let capture = DiagnosticCapture::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, body);
    let captured = capture
        .bytes
        .lock()
        .expect("diagnostic capture lock")
        .clone();
    String::from_utf8_lossy(&captured).into_owned()
}

/// Executes the real seam every instrumented file calls before it emits.
fn emit_real() -> String {
    emit(eliot_host::note_event_log_sink_status)
}

fn handle(value: &str) -> eliot_platform::PlatformHandle {
    eliot_platform::PlatformHandle::new(value.to_owned()).expect("platform handle")
}

fn restart_req(
    operation: HostRuntimeControlOperation,
    request_id: &str,
) -> HostRuntimeControlRequest {
    let mutation = handle(&"b1".repeat(32));
    HostRuntimeControlRequest::new_with_mutation_digest(operation, handle(request_id), mutation)
        .expect("typed request")
}

/// One receipt whose `receipt_digest` is the owner's own computed digest, so
/// the identity its record carries is the owner's and never a test constant.
fn receipt(mutation: &str, request_digest: &str) -> HostKernelRestartReceipt {
    let mut value = HostKernelRestartReceipt {
        mutation_digest: handle(mutation),
        request_digest: handle(request_digest),
        old_kernel_generation: handle(&"c".repeat(64)),
        new_kernel_generation: handle(&"d".repeat(64)),
        store_fence: handle(&"e".repeat(64)),
        activation_receipt_digest: handle(&"f".repeat(64)),
        ready_receipt_digest: handle(&"a".repeat(64)),
        receipt_digest: handle(&"0".repeat(64)),
    };
    value.receipt_digest = value.computed_digest().expect("owner receipt digest");
    value
}

/// Every boundary whose record names exactly one typed disposition carries
/// precisely the disposition this delivery's fixture freezes for it.
fn assert_frozen_boundary_dispositions() {
    let names = vocabulary_strings("dispositions");
    let prefixes = strings("inner_prefixes");
    for (boundary, disposition) in mapping("dispositions_by_boundary") {
        assert!(
            prefixes
                .iter()
                .any(|prefix| boundary.starts_with(prefix.as_str())),
            "{boundary} stays inside the inner namespace"
        );
        assert!(
            names.contains(&disposition),
            "{boundary} names a disposition of this vocabulary"
        );
        let (path, text) = boundary_source(&boundary);
        assert_eq!(
            region_dispositions(disposition_region(&text, &boundary)),
            vec![camel(&disposition)],
            "{boundary} carries exactly its declared disposition in {path}"
        );
    }
}

/// The journal owner alone decides an append disposition, so these boundary
/// names reach the record through the owner's own projection.
fn assert_owner_projected_boundaries() {
    let journal = source("src/journal_append.rs");
    let projection = journal
        .split(fixture_text("owner_projection_source"))
        .nth(1)
        .and_then(|body| {
            body.split("pub(super) fn observe_host_journal_boundary")
                .next()
        })
        .expect("the owner's append disposition projection");
    for (boundary, projected) in fixture_object("owner_projected_boundaries") {
        let arm = projected["arm"].as_str().expect("projection arm");
        let disposition = projected["disposition"]
            .as_str()
            .expect("projection disposition");
        let (_, text) = boundary_source(boundary);
        assert!(
            text.contains(&format!("{arm} => \"{boundary}\"")),
            "{boundary} is named by {arm}"
        );
        assert!(
            projection.contains(&format!(
                "{arm} => {}::{}",
                vocabulary("disposition_type"),
                camel(disposition)
            )),
            "{arm} projects onto {disposition}"
        );
    }
}

/// Boundaries typed on an owner's decision carry exactly the dispositions that
/// decision can produce, never one frozen spelling.
fn assert_decided_boundary_dispositions() {
    for (boundary, expected) in fixture_object("boundary_disposition_sets") {
        let (_, text) = boundary_source(boundary);
        let mut declared = region_dispositions(disposition_region(&text, boundary));
        declared.sort();
        let mut members: Vec<String> = expected
            .as_array()
            .expect("disposition set")
            .iter()
            .map(|member| camel(member.as_str().expect("disposition name")))
            .collect();
        members.sort();
        assert_eq!(
            declared, members,
            "{boundary} is typed on the owner's own decision"
        );
    }
    for boundary in strings("variable_disposition_boundaries") {
        let (_, text) = boundary_source(&boundary);
        assert!(
            region_dispositions(disposition_region(&text, &boundary)).is_empty(),
            "{boundary} binds its disposition from the owner's classification"
        );
    }
}

// WORK_UNIT_CASE: 981/1
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "case 981/1 walks the declared denominator, the marker set, the emitter hand-off and the contract non-boundary in one pass, and splitting it would scatter the family's single index proof across two tests"
)]
fn family_instrumentation_index_matches_the_declared_denominator() {
    let self_source = source_file("tests/host_journal_diagnostics.rs");
    let declared = fixture()
        .get("denominator")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .expect("numeric denominator");
    assert_eq!(declared, 16, "the declared marker denominator");
    assert_eq!(
        count(
            &self_source,
            ["// WORK_UNIT_CASE", ": 981/"].concat().as_str()
        ),
        declared,
        "one marker per declared case"
    );
    assert_eq!(
        count(&self_source, ["#[te", "st]"].concat().as_str()),
        declared,
        "one test per declared case"
    );
    let lines: Vec<&str> = self_source.lines().collect();
    let mut markers = 0usize;
    for (index, line) in lines.iter().enumerate() {
        let Some(marker) = line
            .trim()
            .strip_prefix(["// WORK_UNIT_CASE", ": 981/"].concat().as_str())
        else {
            continue;
        };
        markers += 1;
        let position: usize = marker.parse().expect("numeric marker");
        assert_eq!(position, markers, "markers stay ascending and gapless");
        assert_eq!(
            lines[index + 1].trim(),
            ["#[te", "st]"].concat(),
            "every marker sits directly above its own test attribute"
        );
    }
    assert_eq!(markers, declared, "the last marker closes the set");
    assert_eq!(fixture_text("issue"), "981");
    assert!(
        !fixture()["stdout_protocol_contamination"]
            .as_bool()
            .unwrap_or(true)
    );
    let paths = instrumented_paths();
    assert_eq!(paths.len(), 9, "the family is nine files");
    for relative in &paths {
        assert!(path_of(relative).is_file(), "{relative} is instrumented");
    }
    for relative in strings("read_only_paths") {
        assert!(path_of(&relative).is_file(), "{relative} is read only here");
        assert!(
            !paths.contains(&relative),
            "{relative} is never both instrumented and read only"
        );
    }
    let all = all_source();
    for helper in strings("helpers") {
        assert_eq!(
            count(&all, &format!("fn {helper}(")),
            1,
            "{helper} is defined exactly once in the family"
        );
    }
    let journal = source("src/journal_append.rs");
    let emitter = format!("pub(super) fn {}", vocabulary("emitter"));
    for declaration in [
        "pub(super) struct HostJournalObservation",
        "pub(super) enum HostJournalDisposition",
        emitter.as_str(),
    ] {
        assert_eq!(
            count(&journal, declaration),
            1,
            "the shared vocabulary is declared once in journal_append"
        );
    }
    assert_eq!(
        count(&all, &format!("{}(observation);", vocabulary("emitter"))),
        strings("helpers").len(),
        "every per-file seam delegates to the one shared emitter"
    );
    assert_eq!(
        count(&all, "host_diagnostics::observe_entrypoint_with_detail"),
        0
    );
    assert_eq!(count(&all, "observe_terminal_error"), 0);
    assert_eq!(count(&all, "static DEDUP"), 0);
    assert!(source_file("src/lib.rs").contains(fixture_text("outer_terminal")));
    let facade = source_file("src/host_diagnostics.rs");
    assert!(!facade.contains("host.epoch"));
    assert!(!facade.contains(vocabulary("disposition_type").as_str()));
    let contract = source("src/readiness_gate/contract.rs");
    assert!(!contract.contains("observe_"));
    assert!(!contract.contains("host_diagnostics"));
    // Self-referential needles are assembled from parts, so this assertion can
    // never satisfy itself.
    for emission in [
        ["host_diagnostics::observe_entrypoint", "_with_detail("].concat(),
        ["host_diagnostics::observe_terminal", "_error("].concat(),
    ] {
        assert!(
            !self_source.contains(&emission),
            "this target never emits a diagnostic itself: {emission}"
        );
    }
}

// WORK_UNIT_CASE: 981/2
#[test]
fn epoch_reopen_carries_its_real_host_and_prepared_append_counts() {
    let reopen = source("src/host_epoch_reopen.rs");
    for boundary in [
        "host.epoch reopen existing requested",
        "host.epoch install mismatch observed",
        "host.epoch prior kernel unverified observed",
        "host.epoch prior kernel retained live observed",
        "host.epoch owner child epoch observed",
        "host.epoch unclean observed",
        "host.epoch last host observed",
        "host.epoch fence without prior observed",
    ] {
        let (path, text) = boundary_source(boundary);
        assert_eq!(
            path, "src/host_epoch_reopen.rs",
            "{boundary} is the epoch owner"
        );
        assert!(text.contains(boundary));
    }
    assert!(reopen.contains(".with_host(last_host)"));
    assert!(reopen.contains(".with_host(&host)"));
    assert!(reopen.contains(".with_prepared_append(prepared)"));
    assert!(reopen.contains("u64::try_from(prepared_appends.len())"));
    assert!(reopen.contains(".with_cardinality(prepared_total)"));
    assert!(reopen.contains(".with_committed(committed_total)"));
    assert!(!reopen.contains("last_host.epoch.current.sequence.get() + 1"));
    // The two prior-kernel refusal outcomes are separate spellings, one call
    // site each: a running/unknown prior kernel is unverified, while a
    // retained live kernel is named for exactly that state.
    for boundary in [
        "host.epoch prior kernel unverified observed",
        "host.epoch prior kernel retained live observed",
    ] {
        assert_eq!(
            count(&reopen, format!("\"{boundary}\"").as_str()),
            1,
            "{boundary} is emitted from exactly one outcome"
        );
    }
    assert!(reopen.contains("HostJournalDisposition::FenceUnresolved"));
    assert!(reopen.contains("HostJournalDisposition::FenceClear"));
    assert!(reopen.contains("StoreRecoveryStartupFence::Clear"));
    let fence = source("src/store_recovery_fence.rs");
    assert!(fence.contains("HostJournalDisposition::FenceInnerUnresolved"));
}

// WORK_UNIT_CASE: 981/3
#[test]
fn journal_append_records_the_owner_append_disposition_and_receipt() {
    let journal = source("src/journal_append.rs");
    for boundary in [
        "host.journal append requested",
        "host.journal append durable observed",
        "host.journal append replay observed",
        "host.journal append outcome unknown observed",
        "host.journal append rejected observed",
    ] {
        assert!(
            journal.contains(boundary),
            "{boundary} is the journal owner"
        );
    }
    assert!(journal.contains("let disposition = append_disposition(receipt.disposition());"));
    assert!(
        journal.contains("AppendDisposition::Applied => \"host.journal append durable observed\"")
    );
    assert!(
        journal.contains("AppendDisposition::Replayed => \"host.journal append replay observed\"")
    );
    assert!(journal.contains(".with_receipt(&receipt)"));
    let reconciled = journal
        .split("pub(super) fn append_reconciled")
        .nth(1)
        .and_then(|body| body.split("\npub(super) fn ").next())
        .expect("reconciled append body");
    assert_eq!(
        count(reconciled, "host_journal_observe("),
        6,
        "six reconciled call sites, one record each"
    );
    // No single owner effect emits two records under one spelling: every
    // boundary inside the reconciled body belongs to exactly one outcome, so
    // the requested, durable, replayed, readback, unknown and refused effects
    // are six distinct outcomes rather than six views of one effect.
    for boundary in [
        "host.journal append durable observed",
        "host.journal append replay observed",
        "host.journal append outcome unknown observed",
        "host.journal reconcile readback observed",
        "host.journal reconcile readback failed observed",
        "host.journal append rejected observed",
    ] {
        assert_eq!(
            count(reconciled, &format!("\"{boundary}\"")),
            1,
            "{boundary} names exactly one reconciled outcome"
        );
    }
    assert_eq!(
        count(reconciled, "journal.append(record"),
        2,
        "the reconciled path calls the journal twice and never more"
    );
}

// WORK_UNIT_CASE: 981/4
#[test]
fn unknown_commit_reconciliation_stays_typed_and_fail_closed() {
    let journal = source("src/journal_append.rs");
    let reconciled = journal
        .split("fn reconcile_unknown_outcome")
        .nth(1)
        .and_then(|body| body.split("pub(super) fn append_reconciled").next())
        .expect("reconciliation owner");
    assert_eq!(
        count(
            reconciled,
            "Err(HostError::Journal(JournalError::OutcomeUnknown {"
        ),
        2,
        "both unreadable-commit answers stay the typed outcome-unknown error"
    );
    assert!(reconciled.contains("ReconcileOutcome::NotCommitted => {"));
    assert!(reconciled.contains("ReconcileOutcome::StillUnknown => {"));
    assert!(
        !reconciled.contains("ReconcileOutcome::NotCommitted | ReconcileOutcome::StillUnknown")
    );
    let readiness = source("src/journal_append/readiness_append.rs");
    assert!(readiness.contains("host.readiness reconcile readback failed observed"));
    assert!(readiness.contains("HostJournalDisposition::ReconcileStillUnknown"));
}

// WORK_UNIT_CASE: 981/5
#[test]
fn readiness_records_the_owner_contour_and_keeps_the_gate_decision() {
    let readiness = source("src/journal_append/readiness_append.rs");
    for boundary in [
        "host.readiness authenticated requested",
        "host.readiness contour mismatch observed",
        "host.readiness evidence appended",
    ] {
        assert!(
            readiness.contains(boundary),
            "{boundary} is the readiness owner"
        );
    }
    assert!(!readiness.contains("host.readiness grant observed"));
    assert!(readiness.contains("HostJournalDisposition::ReadinessRefused"));
    assert!(readiness.contains(".with_lease(supervision.lease_id.as_str())"));
    assert!(readiness.contains(".with_ors_receipt(supervision.ors_receipt_digest.as_str())"));
    assert!(readiness.contains(".with_watchdog(supervision.publication_digest.as_str())"));
    // The readiness child owns no append disposition of its own: it asks the
    // parent's projection for the verdict, so `CommitApplied`/`CommitReplayed`
    // are reachable here only through that call and are never spelled locally.
    assert!(
        readiness.contains("let disposition = super::append_disposition(receipt.disposition());")
    );
    assert!(
        readiness
            .contains("AppendDisposition::Applied => \"host.readiness append durable observed\"")
    );
    assert!(
        !readiness.contains("HostJournalDisposition::Commit"),
        "the readiness child never re-derives the journal's append disposition"
    );
    let gate = source("src/readiness_gate.rs");
    assert!(gate.contains("host.readiness grant observed"));
    assert!(gate.contains("host.readiness grant rejected observed"));
    assert!(gate.contains("host.readiness lease hit observed"));
    assert!(gate.contains("HostJournalDisposition::ReadinessGranted"));
}

// WORK_UNIT_CASE: 981/6
#[test]
fn readiness_gate_branches_on_the_owner_lease_disposition() {
    let gate = source("src/readiness_gate.rs");
    assert!(gate.contains("enum LeaseDisposition"));
    for variant in [
        "Valid",
        "Expired",
        "ContourMoved",
        "ProofIncomplete",
        "Absent",
    ] {
        assert!(
            gate.contains(&format!("Self::{variant} =>")),
            "{variant} arm"
        );
    }
    assert_eq!(
        count(
            &gate,
            "Self::ContourMoved => HostJournalDisposition::LeaseContourMoved"
        ),
        1,
        "each non-valid arm names exactly one failure kind"
    );
    assert!(gate.contains("fn with_readiness_contour("));
    assert!(gate.contains("contour.supervision_ors_receipt_digest"));
    assert!(gate.contains("contour.watchdog_publication_digest"));
    assert!(gate.contains(".with_failure(failure.as_str())"));
    assert!(gate.contains(".with_failure(retry.failure.as_str())"));
    let contract = source("src/readiness_gate/contract.rs");
    assert!(contract.contains("pub(crate) const fn as_str(self) -> &'static str"));
    assert!(contract.contains("Self::JournalOutcomeUnknown => \"journal_outcome_unknown\""));
    assert!(!contract.contains("observe_"));
    assert!(!contract.contains("host_diagnostics"));
}

// WORK_UNIT_CASE: 981/7
#[test]
fn restart_publication_keeps_its_owner_outcome_and_single_record() {
    let restart = source("src/runtime_restart_state.rs");
    for boundary in [
        "host.restart pending requested",
        "host.restart pending published observed",
        "host.restart pending replay observed",
        "host.restart receipt durable observed",
        "host.restart receipt replay observed",
    ] {
        assert!(
            restart.contains(boundary),
            "{boundary} is the restart owner"
        );
    }
    let pending = restart
        .split("pub(super) fn persist_runtime_restart_pending(")
        .nth(1)
        .and_then(|body| {
            body.split("pub(super) fn persist_runtime_restart_receipt(")
                .next()
        })
        .expect("pending publisher body");
    let race = pending
        .split("Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {")
        .nth(1)
        .and_then(|body| {
            body.split("ordering::record(\"tmp_cleanup_attempt\")")
                .next()
        })
        .expect("create-race arm");
    assert_eq!(
        count(race, "host_restart_observe("),
        0,
        "the create-race arm publishes no record of its own"
    );
    assert_eq!(
        count(pending, "Ok(RuntimeRestartPendingPublication::Replay)"),
        2
    );
    assert_eq!(
        count(pending, "Ok(RuntimeRestartPendingPublication::Created)"),
        1
    );
    assert!(
        restart
            .contains("RuntimeRestartPendingPublication::Created => HostJournalObservation::new(")
    );
    assert!(
        restart
            .contains("RuntimeRestartPendingPublication::Replay => HostJournalObservation::new(")
    );
    assert!(restart.contains("enum RuntimeRestartReceiptPublication"));
    assert!(restart.contains(".with_mutation(request.mutation_digest.as_str())"));
    assert!(restart.contains(".with_request_digest(request.request_digest.as_str())"));
    assert!(restart.contains(".with_operation(request.request_id.as_str())"));
    let request = restart_req(
        HostRuntimeControlOperation::RestartKernel,
        "restart-identity",
    );
    let durable = receipt(&"b1".repeat(32), request.request_digest.as_str());
    assert!(
        durable.validate().is_ok(),
        "the owner's own digest satisfies its own validation"
    );
    let mut tampered = durable.clone();
    tampered.ready_receipt_digest = handle(&"9".repeat(64));
    assert_ne!(
        tampered.computed_digest().expect("digest").as_str(),
        durable.receipt_digest.as_str(),
        "the receipt identity binds every field its record carries"
    );
}

// WORK_UNIT_CASE: 981/8
#[test]
fn pending_codec_records_rejections_without_persisting_anything() {
    let codec = source("src/runtime_restart_state/pending_codec.rs");
    for boundary in [
        "host.restart pending malformed observed",
        "host.restart pending identity malformed observed",
        "host.restart pending digest mismatch observed",
        "host.restart pending too large observed",
        "host.restart pending inspect failed observed",
        "host.restart pending path unbound observed",
        "host.restart pending absent observed",
        "host.restart pending read observed",
    ] {
        assert!(codec.contains(boundary), "{boundary} is the codec owner");
    }
    for disposition in [
        "EvidenceUnusable",
        "EvidenceMismatched",
        "EvidenceAbsent",
        "EvidenceValidated",
    ] {
        assert!(codec.contains(&format!("HostJournalDisposition::{disposition}")));
    }
    assert!(codec.contains("runtime_restart_pending_identity("));
    let restart = source("src/runtime_restart_state.rs");
    assert!(restart.contains("runtime_restart_pending_identity(request, host)"));
    assert!(codec.contains("MAX_PENDING_BYTES: u64 = 16 * 1024"));
    assert!(codec.contains("deny_unknown_fields"));
    assert!(codec.contains("fn created_at_rejects_clock_before_unix_epoch"));
    assert!(codec.contains("fn created_at_preserves_exact_unix_milliseconds"));
    for line in codec.lines().filter(|line| line.contains("_observe(")) {
        assert!(
            !line.contains("bytes"),
            "no observation site carries payload bytes"
        );
        assert!(
            !line.contains("format!"),
            "no observation site formats a value"
        );
        assert!(
            !line.contains("{error}"),
            "no observation site carries error text"
        );
    }
    let decoded = codec
        .split("let record = serde_json::from_slice::<RuntimeRestartPendingRecord>(bytes)")
        .nth(1)
        .and_then(|body| {
            body.split("let identity = RuntimeRestartPendingIdentity {")
                .next()
        })
        .expect("decoded pending arm");
    assert!(decoded.contains("host.restart pending malformed observed"));
    assert!(decoded.contains(".with_recovery_binding(expected_mutation_digest)"));
    assert!(!decoded.contains("&bytes"));
    assert!(!decoded.contains("bytes,"));
}

// WORK_UNIT_CASE: 981/9
#[test]
fn store_recovery_evidence_records_absence_without_inventing_it() {
    let evidence = source("src/store_recovery_evidence.rs");
    for boundary in [
        "host.recovery termination absent observed",
        "host.recovery inner absent observed",
        "host.recovery termination incomplete observed",
        "host.recovery termination digest mismatch observed",
        "host.recovery termination cross-bind mismatch observed",
        "host.recovery inner cross-bind mismatch observed",
        "host.recovery termination observed",
        "host.recovery inner observed",
    ] {
        assert!(
            evidence.contains(boundary),
            "{boundary} is the evidence owner"
        );
    }
    assert_eq!(
        count(&evidence, "HostJournalDisposition::EvidenceAbsent"),
        2,
        "one absence record per reader"
    );
    assert_eq!(count(&evidence, "return Ok(None);"), 2);
    assert!(evidence.contains("HostJournalDisposition::EvidenceMismatched"));
    assert!(evidence.contains("HostJournalDisposition::EvidenceIncomplete"));
    assert!(evidence.contains("HostJournalDisposition::EvidenceValidated"));
    assert!(evidence.contains(".with_mutation(mutation_digest)"));
    assert!(evidence.contains(".with_host_epoch(evidence.host_epoch)"));
    // The inner-evidence verdict is readable from the record itself: it binds
    // both the digest the evidence names and, in the recovery slot, the
    // requested mutation this read is about.
    let inner = evidence
        .split("\"host.recovery inner observed\"")
        .nth(1)
        .and_then(|body| body.split(".with_recovery_binding(mutation_digest)").next())
        .expect("inner evidence record");
    assert!(
        inner.contains("HostJournalDisposition::EvidenceValidated")
            && inner.contains("HostJournalDisposition::EvidenceMismatched"),
        "the inner read reports both verdicts, never one frozen spelling"
    );
    assert!(inner.contains(".with_mutation(binding.external_control_mutation_digest.as_str())"));
    assert!(
        evidence.contains(".with_recovery_binding(mutation_digest)"),
        "the requested mutation is the record's own recovery slot"
    );
}

// WORK_UNIT_CASE: 981/10
#[test]
fn store_recovery_fence_names_the_owner_startup_fence_verdict() {
    let fence = source("src/store_recovery_fence.rs");
    for boundary in [
        "host.recovery fence requested",
        "host.recovery fence bound observed",
        "host.recovery fence no inner observed",
        "host.recovery inner absent unknown observed",
        "host.recovery inner without termination observed",
        "host.recovery inner no activation observed",
        "host.recovery foreign epoch observed",
        "host.recovery predecessor committed observed",
    ] {
        assert!(fence.contains(boundary), "{boundary} is the fence owner");
    }
    assert!(fence.contains("HostJournalDisposition::FenceInnerUnresolved"));
    assert!(fence.contains("HostJournalDisposition::FenceBound"));
    assert!(fence.contains("HostJournalDisposition::EvidenceForeign"));
    assert!(fence.contains(".with_mutation(self.mutation_digest.as_str())"));
    assert!(fence.contains(".with_operation(self.request_id.as_str())"));
    assert!(fence.contains(".with_host_epoch(self.host_epoch)"));
    assert!(fence.contains("return Ok(());"));
    assert!(fence.contains("own no terminal"));
    assert_eq!(count(&fence, "pub(super) fn validate_for_reopen("), 1);
    assert!(fence.contains("pub(super) enum StoreRecoveryStartupFence"));
    let reopen = source("src/host_epoch_reopen.rs");
    assert!(reopen.contains("HostJournalDisposition::FenceUnresolved"));
    assert!(reopen.contains("HostJournalDisposition::FenceClear"));
    assert!(reopen.contains("StoreRecoveryStartupFence::Clear"));
}

// WORK_UNIT_CASE: 981/11
#[test]
fn journal_readback_keeps_the_owner_receipt_as_its_only_proof() {
    let journal = source("src/journal_append.rs");
    assert!(journal.contains("HostJournalDisposition::CommitReplayed"));
    assert!(journal.contains("HostJournalDisposition::ReconcileReadbackVerified"));
    assert_eq!(
        count(&journal, "journal.append(record"),
        2,
        "the readback never journals a second record"
    );
    let readback = journal
        .split("if reconcile_unknown_outcome(journal, &transaction_id)? {")
        .nth(1)
        .and_then(|body| body.split("match journal.append(record)").next())
        .expect("readback body");
    assert_eq!(count(readback, "journal.append("), 0);
    assert!(!journal.contains("let _ = journal.append(record)"));
    let readiness = source("src/journal_append/readiness_append.rs");
    assert!(
        readiness
            .contains("AppendDisposition::Replayed => \"host.readiness append replay observed\"")
    );
    assert_eq!(
        count(
            &readiness,
            "journal.append_readiness_observation(observation"
        ),
        2
    );
}

// WORK_UNIT_CASE: 981/12
#[test]
fn the_family_owns_no_terminal_of_its_own() {
    let all = all_source();
    assert_eq!(count(&all, "observe_terminal_error"), 0);
    assert_eq!(count(&all, "host.terminal_error"), 0);
    assert!(source_file("src/lib.rs").contains(fixture_text("outer_terminal")));
    assert!(source("src/store_recovery_fence.rs").contains("own no terminal"));
    let captured = emit_real();
    assert_eq!(
        count(&captured, fixture_text("terminal_event")),
        0,
        "the real seam never writes a terminal record"
    );
    assert_eq!(
        sink_status(DiagnosticSink::WindowsEventLog),
        Err(HostDiagnosticsError::EventLogUnavailable),
        "the facade never certifies Event Log delivery"
    );
    // This target never calls `install_host_diagnostics`, so the facade's one
    // install cell is unclaimed: `subscriber_setup_observed` answers the
    // fresh-cell `InProgress` state, which `as_result` projects to the typed
    // `SetupInProgress` error. A stderr sink is therefore never reported as
    // certified from here, and the capture above is a scoped subscriber, not a
    // certified facade sink.
    assert_eq!(
        sink_status(DiagnosticSink::TracingStderr),
        Err(HostDiagnosticsError::SetupInProgress),
        "an unclaimed facade subscriber is not a certified stderr sink"
    );
}

// WORK_UNIT_CASE: 981/13
#[test]
fn sink_disposition_cannot_change_family_behavior() {
    let all = all_source();
    assert_eq!(count(&all, "let _ = crate::windows_event_log"), 0);
    assert_eq!(count(&all, "windows_event_log::event_log_sink_status()"), 0);
    assert_eq!(count(&all, "#984 still open"), 0);
    let journal = source("src/journal_append.rs");
    assert!(journal.contains(vocabulary("sink_observer").as_str()));
    assert_eq!(
        count(&journal, "crate::host_diagnostics::info!("),
        1,
        "one bounded record per observed boundary"
    );
    assert_eq!(
        eliot_host::windows_event_log::event_log_sink_status().is_ok(),
        cfg!(windows),
        "the wrapper reports the platform's own support, never its own claim"
    );
    let first = emit_real();
    let second = emit_real();
    assert_eq!(
        first, second,
        "the observed sink disposition cannot change what the seam writes"
    );
    let opening = first.lines().next().unwrap_or_default();
    assert!(
        opening.contains("event_log_sink") || opening.is_empty(),
        "the facade records only its own sink answer"
    );
}

// WORK_UNIT_CASE: 981/14
#[test]
fn observations_are_bounded_nonsecret_and_never_formatted() {
    let all = all_source();
    for canary in strings("canaries") {
        assert!(!all.contains(canary.as_str()), "{canary} is absent");
    }
    for line in all.lines().filter(|line| line.contains("_observe(")) {
        assert!(
            !line.contains("bytes"),
            "no observation site carries payload bytes"
        );
        assert!(
            !line.contains("format!"),
            "no observation site formats a value"
        );
        assert!(
            !line.contains("{error}"),
            "no observation site carries error text"
        );
    }
    let restart = source("src/runtime_restart_state.rs");
    assert!(restart.contains("Publication failure is primary"));
    assert!(restart.contains("cleanup cannot rename it as success"));
    assert!(restart.contains("HostJournalDisposition::CleanupIncomplete"));
    let publication = restart
        .split("pub(super) fn persist_runtime_restart_receipt(")
        .nth(1)
        .and_then(|body| {
            body.split("pub(super) fn has_runtime_restart_pending(")
                .next()
        })
        .expect("receipt publisher body");
    // Scoped to `persist_runtime_restart_receipt`, the one function that holds
    // every marker below: the durable receipt record follows its cleanup verdict
    // and its durability marker, and precedes the pending removal it authorises.
    let cleanup = publication
        .find("host.restart receipt cleanup failed observed")
        .expect("cleanup verdict");
    let durable = publication
        .find("host.restart receipt durable observed")
        .expect("durable record");
    let marker = publication
        .find("receipt_durable_before_pending_remove")
        .expect("durability marker");
    let removal = publication
        .find("remove_receipt_confirmed_runtime_restart_pending(host_state_root, &dir, receipt)?;")
        .expect("pending removal");
    assert!(
        cleanup < durable,
        "the cleanup verdict stays before the record"
    );
    assert!(
        marker < durable,
        "durability is claimed only after the dir sync"
    );
    assert!(
        durable < removal,
        "the receipt is durable before pending removal"
    );
    let replay = publication
        .find("host.restart receipt replay observed")
        .expect("exact-replay record");
    assert!(replay < marker, "the exact-replay record precedes the tail");
    assert!(
        publication[replay..marker].contains("return Ok(());"),
        "the exact-replay path returns before the tail, so one path publishes once"
    );
    assert!(!all.contains("allow(dead_code)"));
    assert!(!all.contains("todo!("));
    let oversized = bound_detail(&"x".repeat(2000));
    assert!(oversized.truncated());
    assert!(oversized.text().len() <= 1024);
    let identity = bound_field("host.journal_identity_slot_that_is_longer_than_the_bound");
    assert!(!identity.truncated());
    assert_eq!(identity.original_bytes(), identity.text().len());
}

// WORK_UNIT_CASE: 981/15
#[test]
fn the_record_vocabulary_is_bounded_closed_and_deterministic() {
    let journal = source("src/journal_append.rs");
    assert!(journal.contains(&format!("event = \"{}\"", fixture_text("boundary_event"))));
    assert!(journal.contains(vocabulary("emitter_target").as_str()));
    assert!(journal.contains("stage = crate::host_diagnostics::EntrypointStage::Startup.as_str()"));
    let names = vocabulary_strings("dispositions");
    assert_eq!(names.len(), 37);
    for name in &names {
        assert!(
            journal.contains(&format!("=> \"{name}\"")),
            "{name} is projected by the shared vocabulary"
        );
    }
    let suffix = vocabulary("missing_flag_suffix");
    for slot in vocabulary_strings("identity_slots") {
        assert!(journal.contains(&format!("{slot} = ")), "{slot} slot");
        assert!(
            journal.contains(&format!("{slot}{suffix} = ")),
            "{slot} carries its own absence flag"
        );
    }
    for field in vocabulary_strings("record_measurements")
        .into_iter()
        .chain(vocabulary_strings("record_fields"))
    {
        assert!(journal.contains(&format!("{field} = ")), "{field} field");
    }
    assert_frozen_boundary_dispositions();
    assert_owner_projected_boundaries();
    assert_decided_boundary_dispositions();
    for relative in instrumented_paths() {
        let text = source(&relative);
        assert!(
            !text.contains("windows_event_log::event_log_sink_status"),
            "{relative} never probes the Event Log sink directly"
        );
        assert!(
            !text.contains("#984 still open"),
            "{relative} carries no stale issue note"
        );
    }
    let delegating = instrumented_paths()
        .into_iter()
        .filter(|relative| {
            source(relative).contains(&format!("{}(observation);", vocabulary("emitter")))
        })
        .count();
    assert_eq!(
        delegating,
        strings("helpers").len(),
        "every boundary-seam file reaches the one shared emitter; the contract module does not"
    );
    let first = emit_real();
    let second = emit_real();
    assert_eq!(
        first, second,
        "the record shape is deterministic in its fields"
    );
}

// WORK_UNIT_CASE: 981/16
#[test]
fn the_delivery_added_no_new_surface() {
    let all = all_source();
    assert!(!all.contains("unsafe "));
    assert!(!all.contains("pub fn "));
    assert!(!all.contains("pub(crate) fn observe"));
    assert!(!all.contains("pub async fn "));
    assert!(!all.contains("#[allow(dead_code)]"));
    assert!(!all.contains("todo!("));
    assert!(!all.contains("unimplemented!("));
    assert!(!all.contains("println!("));
    assert!(!all.contains("dbg!("));
    for relative in instrumented_paths() {
        let text = source(&relative);
        let production = text.split("#[cfg(test)]").next().unwrap_or(&text);
        assert!(
            !production.contains("std::fs::write"),
            "{relative} adds no new persistence path"
        );
    }
    assert_eq!(count(&all, "\nmod "), 7);
    let restart = source("src/runtime_restart_state.rs");
    let start = restart
        .find("enum RuntimeRestartReceiptPublication {")
        .expect("receipt publication enum");
    let block: Vec<&str> = restart[start..].lines().take(4).collect();
    assert_eq!(
        block,
        vec![
            "enum RuntimeRestartReceiptPublication {",
            "    Created,",
            "    Replay,",
            "}",
        ],
        "the receipt publication enum keeps exactly its owner arms"
    );
    assert_eq!(count(&restart, "hard_link(&tmp, &path)"), 2);
    assert_eq!(count(&restart, "std::io::ErrorKind::AlreadyExists"), 2);
    assert!(restart.contains("write_durable_file(&tmp, &bytes)?"));
    let codec = source("src/runtime_restart_state/pending_codec.rs");
    assert!(codec.contains("deny_unknown_fields"));
    assert!(codec.contains("MAX_PENDING_BYTES: u64 = 16 * 1024"));
    let fence = source("src/store_recovery_fence.rs");
    assert_eq!(count(&fence, "pub(super) fn validate_for_reopen("), 1);
    assert!(fence.contains("pub(super) enum StoreRecoveryStartupFence"));
    let composition = source_file("src/lib.rs");
    for module in [
        "mod journal_append;",
        "mod host_epoch_reopen;",
        "mod readiness_gate;",
        "mod runtime_restart_state;",
        "mod store_recovery_evidence;",
        "mod store_recovery_fence;",
    ] {
        assert!(
            composition.contains(module),
            "{module} stays private in the composition root"
        );
    }
    let manifest = std::fs::read_to_string(path_of("Cargo.toml")).expect("manifest");
    assert!(manifest.contains("tracing.workspace = true"));
    assert!(!manifest.contains("host-journal-diagnostics"));
    assert!(!manifest.contains("journal-observation"));
}
