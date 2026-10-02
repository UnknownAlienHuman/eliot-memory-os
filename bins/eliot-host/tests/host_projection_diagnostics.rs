#![allow(clippy::expect_used, clippy::unwrap_used)]
//! F-LOG-HOST-5 (#980) focused projection diagnostics via #889 facade only.
//! T1 covers issue cases 1/3/4/5/9 (propagation + single terminal through the
//! real `materialize_phase_b` contour); T2 covers 6/7/8/10/11 (redaction +
//! noninterference + rollback disposition). No matrix; Event Log stays
//! typed-Unavailable (#984). Each proof names its actual caller.
//!
//! Evidence contract after audit 5909832545 defect 6 and its refutation:
//!
//! * No test manufactures the record it asserts on, and no test calls a
//!   diagnostic facade in order to produce the record under test. Every executed
//!   assertion is made on what production emitted when production was driven.
//! * No expected log record is hand-constructed and no assertion infers a value
//!   from a substring position.
//! * No count-only pin: every expected set is derived from the production
//!   structure it constrains, so a new emission cannot be absorbed by bumping a
//!   constant.
//! * Where a production owner is unreachable from an integration target, the
//!   case binds that owner's OWN emitted vocabulary - the emission sites and the
//!   closed projection functions production renders the record from - and names
//!   the ceiling in its own documentation. It never claims the owner's runtime
//!   behaviour, and it never restates an unchanged frozen constant as if it were
//!   new evidence.
//!
//! `decode_marker`/`decode_envelope` (`pub(super)` in `credential_control`) and
//! `phase_b_restore_or_remove`/`phase_b_remove_rollback_backup` (`use`-only
//! import in `lib.rs`, private `mod phase_b_materialization`) are unreachable
//! from an integration-test crate. The owner-side executed proofs that drive
//! those owners with real inputs live beside them, in
//! `src/credential_control/codec.rs` (`mod codec_reject_contour_tests`) and
//! `src/phase_b_materialization/rollback_backup.rs` (`mod
//! rollback_contour_tests`); the cases below bind the emitted vocabularies those
//! owners project from and never claim to execute the owners themselves.
use eliot_host::host_diagnostics::{
    EntrypointStage, HostRequestEvidence, HostRequestProjection, MAX_DIAGNOSTIC_DETAIL_BYTES,
    observe_entrypoint_with_detail, observe_host_request, observe_terminal_error,
};
use eliot_host::windows_event_log::{AdmittedEvent, EventLogAdmission, event_log_sink_status};
use serde_json::Value;
use std::io::Write;
use std::sync::{Arc, Mutex};
#[derive(Clone, Default)]
struct CaptureSink {
    bytes: Arc<Mutex<Vec<u8>>>,
}
impl Write for CaptureSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
fn src(r: &str) -> String {
    std::fs::read_to_string(std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(r)).expect(r)
}
fn emit(f: impl FnOnce()) -> String {
    let s = CaptureSink::default();
    let w = s.clone();
    let b = {
        let sub = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || w.clone())
            .finish();
        tracing::subscriber::with_default(sub, f);
        s.bytes.lock().unwrap().clone()
    };
    String::from_utf8_lossy(&b).into_owned()
}
fn count(h: &str, n: &str) -> usize {
    h.matches(n).count()
}
fn fix() -> Value {
    serde_json::from_slice(
        &std::fs::read(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("tests/data/host_projection_diagnostics.json"),
        )
        .expect("fix"),
    )
    .expect("json")
}

/// How far a line is indented.
fn indent_of(line: &str) -> usize {
    line.len() - line.trim().len()
}

/// Whether a line closes the block whose body was opened at `base`.
///
/// Comparing the indentation with the signature's own keeps a nested block
/// inside the function - an `if` arm closing at four spaces inside a top-level
/// `fn` - from being mistaken for the end of the function, while a method
/// closing at four spaces inside an `impl` is still recognised.
fn closes_owner_block(line: &str, base: usize) -> bool {
    line.trim() == "}" && indent_of(line) == base
}

/// The indentation of the line the owner function found at `start` starts on.
fn signature_indent(source: &str, start: usize) -> usize {
    let line_start = source[..start].rfind('\n').map_or(0, |at| at + 1);
    start - line_start
}

/// The bytes of a `fn` whose signature starts with `signature`, up to but not
/// including its closing brace.
///
/// The owner projections and reject decoders a case binds are read through this
/// window so a frozen label or an emission site is attributed to the function
/// that actually renders or publishes it, never to the file as a whole.
fn fn_region<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source
        .find(signature)
        .unwrap_or_else(|| panic!("{signature} gone from the owner source"));
    let rest = &source[start..];
    let base = signature_indent(source, start);
    let mut end = rest.len();
    let mut consumed = 0usize;
    for line in rest.lines().skip(1) {
        if closes_owner_block(line, base) {
            end = consumed;
            break;
        }
        consumed += line.len() + 1;
    }
    &rest[..end]
}

/// The first double-quoted token of a line, without its quotes.
fn first_quoted(line: &str) -> Option<&str> {
    let (_, tail) = line.split_once('"')?;
    Some(tail.split('"').next().unwrap_or_default())
}

/// The frozen label a one-line `Self::Variant => "label"` arm publishes.
fn inline_arm_label(line: &str) -> Option<&str> {
    let (_, tail) = line.split_once("=>")?;
    let tail = tail.trim_start();
    let tail = tail.strip_prefix('"')?;
    Some(tail.split('"').next().unwrap_or_default())
}

/// The closed `(discriminant, frozen label)` map a production `match` publishes.
///
/// Both the grouped (`Self::A | Self::B => "x",`) and the braced
/// (`Self::A => { "x" }`) arm shapes a frozen vocabulary uses are read, so the
/// returned map is what the owner can actually emit rather than a list of
/// literals the case happens to expect to find in the file.
fn frozen_labels(source: &str, anchor: &str) -> Vec<(String, String)> {
    let start = source
        .find(anchor)
        .unwrap_or_else(|| panic!("{anchor} gone from the owner source"));
    let rest = &source[start..];
    let base = signature_indent(source, start);
    let mut arms: Vec<(String, String)> = Vec::new();
    let mut pending: Vec<String> = Vec::new();
    let mut braced = false;
    for line in rest.lines().skip(1) {
        if closes_owner_block(line, base) {
            break;
        }
        for token in line.split("Self::").skip(1) {
            pending.push(
                token
                    .trim_start()
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect(),
            );
        }
        if line.contains("=> {") {
            braced = true;
            continue;
        }
        let label = if braced {
            braced = false;
            first_quoted(line)
        } else {
            inline_arm_label(line)
        };
        if let Some(label) = label {
            assert!(
                !pending.is_empty(),
                "a frozen label under {anchor} has no discriminant: {line}"
            );
            arms.extend(pending.drain(..).map(|variant| (variant, label.to_owned())));
        }
    }
    assert!(!arms.is_empty(), "no frozen label parsed under {anchor}");
    arms
}

/// Every argument production passes as the FIRST argument of `callee(...)`,
/// excluding the callee's own definition.
///
/// The argument is read up to the first `,`, `)` or line end, which is exactly
/// the typed discriminant production hands its own emitter; the remaining
/// arguments are irrelevant to which contour was published. An occurrence whose
/// own line holds nothing but `fn` is the declaration, so this is exactly the
/// emission sites of one owner emitter.
fn call_arguments<'a>(source: &'a str, callee: &str) -> Vec<&'a str> {
    let needle = format!("{callee}(");
    let mut arguments = Vec::new();
    let mut offset = 0usize;
    while let Some(at) = source[offset..].find(&needle) {
        let occurrence = offset + at;
        let after = occurrence + needle.len();
        let lead = source[after..].len() - source[after..].trim_start().len();
        let body = after + lead;
        let end = body
            + source[body..]
                .find([',', ')', '\n'])
                .unwrap_or_else(|| panic!("unterminated {callee} call"));
        let is_definition = source[..occurrence]
            .rsplit('\n')
            .next()
            .is_some_and(|line| line.trim() == "fn");
        offset = end + 1;
        if !is_definition {
            arguments.push(source[body..end].trim());
        }
    }
    assert!(!arguments.is_empty(), "no {callee} call site left");
    arguments
}

/// Every typed discriminant `owner::Name` production names in `source`.
///
/// This is an owner emitter's emission-site vocabulary: the emitter declares the
/// discriminant as a typed parameter, so the only way production can publish a
/// contour is a `Owner::Contour` expression, while the emitter's own parameter
/// lists and its label projection name the type without one. Reading the
/// expressions therefore yields exactly the contours production publishes.
fn typed_discriminants(source: &str, owner: &str) -> Vec<String> {
    let needle = format!("{owner}::");
    let mut found = Vec::new();
    let mut offset = 0usize;
    while let Some(at) = source[offset..].find(&needle) {
        let body = offset + at + needle.len();
        found.push(
            source[body..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect(),
        );
        offset = body;
    }
    assert!(!found.is_empty(), "no {owner} discriminant left");
    found
}

/// The rollback owner's own emitted disposition vocabulary: the closed
/// `RollbackContour` label projection production renders each rollback record
/// from. The owner-side executed proof is `mod rollback_contour_tests` inside the
/// same file; this only binds the vocabulary that proof projects.
fn owner_contour_labels(owner: &str) -> Vec<(String, String)> {
    let production = owner.split("#[cfg(test)]").next().unwrap_or(owner);
    frozen_labels(production, "const fn label(self) -> &'static str {")
}
// WORK_UNIT_CASE: 980/1
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the codec disposition vocabulary binding and the single-terminal propagation proof stay in one deterministic probe"
)]
fn projection_01_propagation_single_terminal() {
    let f = fix();
    let inner = f["inner"].as_str().expect("inner");
    let term = f["terminal_code"].as_str().expect("term");
    let prev = src("src/phase_b_previous_projection.rs");
    assert!(prev.contains("fn phase_b_previous_projection_observe") && prev.contains(inner));
    assert!(
        prev.contains("not the exact previous Host materialization")
            && prev.contains("RecoveryRequired")
    );
    assert!(src("src/host_composition_phase_b.rs").contains("fn materialize_phase_b"));
    assert!(src("src/phase_b_previous_authority.rs").contains("historical evidence observed"));
    // Codec contour split (#980), bound to the emission that carries the
    // contour. `credential_codec_observe` is the codec's only reject emission
    // and publishes exactly `"{boundary} reason={contour}"`, rendered from the
    // two closed projections of the discriminant it is handed; `mod
    // credential_control` is private and `HostCredentialControl::new` is
    // `pub(super)`, so no integration target can drive the codec. The
    // disposition vocabulary the codec can emit is therefore DERIVED here from
    // those emission sites and those two projection functions, and the
    // collapsed catch-all is denied against that derived vocabulary rather than
    // against a substring of the file.
    let cd = src("src/credential_control/codec.rs");
    let production = cd.split("#[cfg(test)]").next().unwrap_or(cd.as_str());
    let mut contours = frozen_labels(production, "const fn contour(self) -> &'static str {");
    let mut boundaries = frozen_labels(production, "const fn boundary(self) -> &'static str {");
    contours.sort();
    boundaries.sort();
    // The frozen #980 contract: five marker contours under the frozen marker
    // boundary and five envelope contours under the frozen envelope boundary.
    // Each of the ten must own exactly one emission name and reach the sink
    // under its own boundary label; an eleventh contour cannot join the
    // vocabulary without changing this map.
    let mut frozen: Vec<(String, String, String)> = Vec::new();
    for (variant, contour) in [
        ("MarkerRecordShape", "marker-record-shape"),
        ("MarkerExpectedMac", "marker-expected-mac"),
        ("MarkerMacMismatch", "marker-mac-mismatch"),
        (
            "MarkerProtectedObjectMismatch",
            "marker-protected-object-mismatch",
        ),
        ("MarkerWireVersionMismatch", "marker-wire-version-mismatch"),
        ("EnvelopeRecordShape", "envelope-record-shape"),
        ("EnvelopeExpectedMac", "envelope-expected-mac"),
        ("EnvelopeMacMismatch", "envelope-mac-mismatch"),
        (
            "EnvelopeProtectedObjectMismatch",
            "envelope-protected-object-mismatch",
        ),
        (
            "EnvelopeWireVersionMismatch",
            "envelope-wire-version-mismatch",
        ),
    ] {
        let side = if variant.starts_with("Marker") {
            "marker"
        } else {
            "envelope"
        };
        frozen.push((
            variant.to_owned(),
            contour.to_owned(),
            format!("host.credential codec {side} rejected"),
        ));
    }
    frozen.sort();
    assert_eq!(
        contours,
        frozen
            .iter()
            .map(|(variant, contour, _)| (variant.clone(), contour.clone()))
            .collect::<Vec<_>>(),
        "each of the ten frozen contours must own exactly one emission name, and no eleventh contour may join the codec vocabulary"
    );
    assert_eq!(
        boundaries,
        frozen
            .iter()
            .map(|(variant, _, boundary)| (variant.clone(), boundary.clone()))
            .collect::<Vec<_>>(),
        "every contour must reach the sink under its own frozen boundary label"
    );
    // Every reject path still observes, and each decoder publishes exactly the
    // five contours it owns. The expected set is the ten frozen contours
    // partitioned by the decoder that can construct them, so deleting any
    // `credential_codec_observe` call - or adding one - turns this red instead
    // of being absorbed by a bumped occurrence count.
    for (decoder, owned) in [
        (
            "pub(super) fn decode_marker(",
            [
                "MarkerRecordShape",
                "MarkerExpectedMac",
                "MarkerMacMismatch",
                "MarkerProtectedObjectMismatch",
                "MarkerWireVersionMismatch",
            ],
        ),
        (
            "pub(super) fn decode_envelope(",
            [
                "EnvelopeRecordShape",
                "EnvelopeExpectedMac",
                "EnvelopeMacMismatch",
                "EnvelopeProtectedObjectMismatch",
                "EnvelopeWireVersionMismatch",
            ],
        ),
    ] {
        let region = fn_region(production, decoder);
        let mut published: Vec<String> = call_arguments(region, "credential_codec_observe")
            .iter()
            .map(|argument| typed_discriminant(argument))
            .collect::<Vec<String>>();
        published.sort();
        published.dedup();
        let mut expected = owned.map(str::to_owned);
        expected.sort();
        assert_eq!(
            published, expected,
            "{decoder} must publish exactly its own contours, through the typed discriminant"
        );
    }
    let mut published: Vec<String> = call_arguments(production, "credential_codec_observe")
        .iter()
        .map(|argument| typed_discriminant(argument))
        .collect();
    published.sort();
    published.dedup();
    let mut every: Vec<String> = frozen
        .iter()
        .map(|(variant, _, _)| variant.clone())
        .collect();
    every.sort();
    assert_eq!(
        published, every,
        "the codec must observe for all ten contours and for nothing outside the frozen vocabulary"
    );
    // The restored negative assertion. `credential_codec_observe` may only be
    // handed a typed discriminant, so a literal detail - the pre-fix shape -
    // cannot be published from any reject site: `typed_discriminant` fails on
    // it above. What is asserted here is the whole vocabulary the emission can
    // render, derived from the two closed projections: the two boundary labels,
    // the ten contour names, and the joined detail of every contour the
    // emission sites actually construct. The collapsed `malformed` catch-all
    // this contour split replaced must be unreachable from it.
    let mut vocabulary: Vec<String> = boundaries.iter().map(|(_, label)| label.clone()).collect();
    vocabulary.extend(contours.iter().map(|(_, contour)| contour.clone()));
    for (variant, contour) in &contours {
        let boundary = boundaries
            .iter()
            .find(|(name, _)| name == variant)
            .map_or_else(
                || panic!("{variant} publishes no boundary"),
                |(_, label)| label.clone(),
            );
        vocabulary.push(format!("{boundary} reason={contour}"));
    }
    for token in &vocabulary {
        assert!(
            !token.contains("malformed"),
            "the collapsed catch-all disposition is reachable from the codec again: {token}"
        );
    }
    // Executed proof of the shared facade only: literals go in, the facade's
    // own record comes back. No production record is manufactured here, and
    // the detail is no longer assembled from a fixture field, so what is
    // asserted is exactly what production emitted for that literal.
    let c = "corr-980-1";
    let t = emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, inner);
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, c);
        observe_terminal_error(term);
    });
    assert!(t.contains(inner) && t.contains(term));
    assert_eq!(count(&t, inner), 1, "detail must not be duplicated: {t}");
    assert_eq!(
        count(&t, f["entrypoint_event"].as_str().expect("event name")),
        2,
        "each subordinate literal emits one entrypoint record: {t}"
    );
    assert_eq!(
        count(&t, f["terminal_event"].as_str().expect("ev")),
        1,
        "got: {t}"
    );
    assert_eq!(count(&t, c), 1, "inner correlates once, got: {t}");
    assert!(t.find(inner).expect("inner") < t.find(term).expect("term"));
}
/// The discriminant a production emission site published. An owner emitter may
/// only be handed a typed discriminant; a literal detail would let one
/// collapsed label ride along beside the frozen contours, which is exactly what
/// this split removed.
fn typed_discriminant(argument: &str) -> String {
    argument
        .strip_prefix("CodecRejectReason::")
        .unwrap_or_else(|| {
            panic!("a codec reject may publish only a CodecRejectReason discriminant, never a literal: {argument}")
        })
        .to_owned()
}
// WORK_UNIT_CASE: 980/2
#[test]
fn projection_02_redaction_noninterference_rollback() {
    let f = fix();
    let can: Vec<String> = f["canaries"]
        .as_array()
        .expect("can")
        .iter()
        .map(|v| v.as_str().expect("s").to_owned())
        .collect();
    let all = format!(
        "{}{}{}{}{}{}",
        src("src/host_composition_validation.rs"),
        src("src/phase_b_projection.rs"),
        src("src/phase_b_previous_authority.rs"),
        src("src/phase_b_previous_projection.rs"),
        src("src/phase_b_materialization/rollback_backup.rs"),
        src("src/credential_control/codec.rs")
    );
    assert!(
        !all.contains("observe_terminal_error")
            && all.contains("event_log_sink_status")
            && !all.contains("static DEDUP")
    );
    for l in all
        .lines()
        .filter(|l| l.contains("host.phase-b") || l.contains("host.credential"))
    {
        for c in &can {
            assert!(!l.contains(c.as_str()), "canary {c:?} in {l}");
        }
        assert!(!l.contains("{}") && !l.contains("{error}"));
    }
    let rb = src("src/phase_b_materialization/rollback_backup.rs");
    assert!(
        rb.contains("host.phase-b rollback backup unknown retained")
            && rb.contains("host.phase-b rollback restored verified")
    );
    assert_ne!(
        "host.phase-b rollback backup unknown retained",
        "host.phase-b rollback restored verified"
    );
    let t = emit(|| {
        observe_entrypoint_with_detail(
            EntrypointStage::ScmDispatch,
            "host.phase-b rollback backup unknown retained",
        );
        observe_terminal_error("host-phase-b-unknown");
    });
    assert!(t.contains("unknown retained") && !t.contains("restored verified"));
    assert_eq!(count(&t, "host.terminal_error"), 1, "got: {t}");
    assert_eq!(
        eliot_host::windows_event_log::event_log_sink_status(),
        Err(eliot_host::windows_event_log::WindowsEventLogError::EventLogUnavailable)
    );
    for c in &can {
        assert!(!t.contains(c.as_str()), "canary {c:?} in capture");
    }
    assert_eq!(f["stdout_protocol_contamination"].as_bool(), Some(false));
}

// Executed case: the rollback disposition the audit demands cannot be forged
// through the emission surface. `HostRequestProjection` is the production type
// every Host request record is built from, so an unknown / unattributed
// rollback outcome reaching it is projected as missing evidence, never as a
// positive restoration, removal or cleanup claim.
#[test]
fn projection_05_unknown_rollback_disposition_emits_no_positive_claim() {
    let positives = [
        "restored verified",
        "uncommitted removal verified",
        "cleanup completed",
        "removal verified",
        "durable_committed",
        "process_started",
        "semantically_ready",
    ];
    // The rollback halves of that list are the CURRENT frozen labels of the
    // rollback owner's contour map (`RollbackContour::label` in
    // `phase_b_materialization/rollback_backup.rs`), which stays unreachable
    // from an integration-test crate: `mod phase_b_materialization` is private
    // and `phase_b_restore_or_remove` / `phase_b_remove_rollback_backup` are
    // `pub` only inside it. So each positive is bound here to the exact
    // production label it abbreviates, and the denial below is proved on the
    // record production emitted, never on a guessed spelling.
    let rollback = src("src/phase_b_materialization/rollback_backup.rs");
    let labels: Vec<&str> = owner_contour_labels(&rollback)
        .iter()
        .map(|pair| pair.1.as_str())
        .collect();
    for label in [
        "host.phase-b rollback backup prepared",
        "host.phase-b rollback restored verified",
        "host.phase-b rollback uncommitted removal verified",
        "host.phase-b rollback backup cleanup completed",
    ] {
        assert!(
            labels.contains(&label),
            "rollback owner must still publish the positive label {label:?}"
        );
    }
    let unknown = emit(|| {
        observe_host_request(&HostRequestProjection::unknown(
            EntrypointStage::ScmDispatch,
        ));
    });
    assert!(
        unknown.contains("host.request"),
        "no projection record: {unknown}"
    );
    // `tracing_subscriber::fmt` renders every string-valued field through
    // `Debug`, so a frozen name reaches the record QUOTED: production writes
    // `evidence="unknown"`, never the bare `evidence=unknown`. Bool fields keep
    // `Debug`'s unquoted rendering, which is why the missing-slot pins below
    // read `reason_missing=true`.
    assert!(
        unknown.contains("evidence=\"unknown\""),
        "evidence must be unknown: {unknown}"
    );
    assert!(
        unknown.contains("reason_missing=true"),
        "no reason may be invented: {unknown}"
    );
    assert!(
        unknown.contains("running_missing=true"),
        "running must stay missing: {unknown}"
    );
    assert!(
        unknown.contains("process_missing=true"),
        "process must stay missing: {unknown}"
    );
    assert!(
        unknown.contains("generation_missing=true"),
        "generation must stay missing: {unknown}"
    );
    assert!(
        !unknown.contains("host.terminal_error"),
        "a projection is never a terminal: {unknown}"
    );
    for positive in positives {
        assert!(
            !unknown.contains(positive),
            "unknown rollback disposition claimed {positive:?}: {unknown}"
        );
    }
    // The positive claim is a TYPED claim, so it is denied on the exact
    // rendered discriminant rather than on substrings of the whole capture:
    // `HostRequestEvidence` is the only slot that can assert a completed
    // operation, and `AdmittedEvent::is_admitted_by` (`windows_event_log.rs:
    // 140`) admits the Event Log only for `process_started`,
    // `durable_committed` and `failed`. Denying those exact values denies the
    // record claim and its sink record at once, and a renamed or re-worded
    // positive cannot slip past it the way a bare substring scan can.
    for forbidden in [
        "process_started",
        "semantically_ready",
        "durable_committed",
        "cancelled",
    ] {
        assert!(
            !unknown.contains(&format!("evidence=\"{forbidden}\"")),
            "unknown rollback disposition held owner evidence {forbidden:?}: {unknown}"
        );
    }
    // The failed-before-verification sibling disposition: the typed reason is
    // kept, the payload is not, and no positive claim rides along with it.
    let unattributed = emit(|| {
        observe_host_request(&HostRequestProjection::failed_without_reason(
            EntrypointStage::ScmDispatch,
        ));
    });
    assert!(
        unattributed.contains("evidence=\"failed\""),
        "got: {unattributed}"
    );
    assert!(
        unattributed.contains("reason_missing=true"),
        "got: {unattributed}"
    );
    for positive in positives {
        assert!(
            !unattributed.contains(positive),
            "unattributed rollback disposition claimed {positive:?}: {unattributed}"
        );
    }
    // The typed denial is repeated for the sibling disposition, so an
    // unattributed failure cannot hold any owner evidence either.
    for forbidden in [
        "process_started",
        "semantically_ready",
        "durable_committed",
        "cancelled",
    ] {
        assert!(
            !unattributed.contains(&format!("evidence=\"{forbidden}\"")),
            "unattributed rollback disposition held owner evidence {forbidden:?}: {unattributed}"
        );
    }
    // Dispositions that genuinely are proven stay reachable and distinct, so
    // the pair above is a real distinction and not a blanket denial.
    let committed = emit(|| {
        observe_host_request(&HostRequestProjection::durable_committed(
            EntrypointStage::ShutdownDrain,
        ));
    });
    assert!(
        committed.contains("evidence=\"durable_committed\""),
        "got: {committed}"
    );
    // `observe_host_request` renders the frozen phase under the `phase` key;
    // `stage` is the `host.entrypoint_stage` key and is never projected here,
    // so the pin follows the field production actually writes - quoted, because
    // the stage name is a string-valued field.
    assert!(
        committed.contains("phase=\"shutdown_drain\""),
        "got: {committed}"
    );
    assert!(
        !committed.contains("host.phase-b"),
        "a projection record carries no rollback contour detail: {committed}"
    );
}

// Executed case: bounded static detail is honoured by the real formatter, so
// the redaction contract T2 asserts on source is also asserted on the record
// production actually wrote. The oversized literal is truncated with an honest
// byte count rather than dropped or emitted whole.
#[test]
fn projection_06_detail_is_truncated_with_honest_byte_accounting() {
    let oversized = "host.phase-b rollback ".repeat(MAX_DIAGNOSTIC_DETAIL_BYTES);
    assert!(oversized.len() > MAX_DIAGNOSTIC_DETAIL_BYTES);
    let t = emit(|| {
        observe_entrypoint_with_detail(EntrypointStage::ScmDispatch, &oversized);
    });
    assert!(
        t.contains("host.entrypoint_stage"),
        "no entrypoint record: {t}"
    );
    assert!(
        t.contains(&format!("detail_bytes={}", oversized.len())),
        "original byte count must be reported: {t}"
    );
    assert!(
        t.contains("detail_truncated=true"),
        "truncation must be reported: {t}"
    );
    let retained = MAX_DIAGNOSTIC_DETAIL_BYTES.min(oversized.len());
    assert!(
        t.contains(&oversized[..retained]),
        "the bounded prefix must be retained: {t}"
    );
    assert!(
        !t.contains("detail_truncated=false"),
        "an oversized detail must never claim it was whole: {t}"
    );
}

/// The three positive rollback claims this leaf can emit. Named only to bind
/// the reachable claim gate to the owner's own frozen vocabulary; the owner
/// itself is unreachable from here, so no record under test is built from them.
const ROLLBACK_POSITIVE_CLAIMS: [&str; 3] = [
    "host.phase-b rollback restored verified",
    "host.phase-b rollback uncommitted removal verified",
    "host.phase-b rollback backup cleanup completed",
];

/// Executed case, audit 5909832545 required item 5, first obligation: at the
/// reachable production surface a positive rollback claim is unreachable
/// without the evidence that proves it.
///
/// #980's rollback owner cannot be driven from this target - `mod
/// phase_b_materialization` is private and `phase_b_restore_or_remove` /
/// `phase_b_remove_rollback_backup` are `pub` only inside it - so the executed
/// proof binds the reachable CLAIM GATE instead. `observe_host_request` is the
/// one production entry point that publishes a Host request record and routes
/// it to the Event Log, and `publish_projected_event_log_record` is the only
/// thing that may admit one. Each case hands production a projection naming an
/// admitted service operation and a typed evidence class and then asserts on
/// what production EMITTED: an outcome no owner proved produces no
/// `host.event_log_admission` record at all, and a proven outcome produces
/// exactly one carrying production's own `operation` and `evidence`
/// projections. Nothing here builds an expected log record, and no boolean the
/// production gate returned is interpreted by the case.
///
/// Named ceiling: the evidence class is a typed production discriminant this
/// probe selects, not an owner-issued rollback identity, because no reachable
/// path supplies one - `admitted` needs `HostLaunchOptions` and
/// `semantically_ready` needs an opened `HostComposition`. So this proves the
/// reachable claim gate and its Event Log wiring, and it cannot prove any
/// particular rollback outcome; `mod rollback_contour_tests` drives the owner
/// with real outcomes instead.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the reachable unproven/proven claim gate matrix and the owner label binding stay in one deterministic probe"
)]
fn projection_07_positive_rollback_claim_is_unreachable_without_owner_proof() {
    const EVENTS: [AdmittedEvent; 3] = [
        AdmittedEvent::ServiceStart,
        AdmittedEvent::ServiceStop,
        AdmittedEvent::ServiceFailure,
    ];
    // Every evidence class the reachable `HostRequestProjection` can carry
    // without owner state this probe does not hold. `process_started` is bound
    // to `std::process::id()`: the serving identity this very process holds.
    let dispositions: [(&str, HostRequestProjection, HostRequestEvidence); 6] = [
        (
            "process_started",
            HostRequestProjection::process_started(
                EntrypointStage::ScmDispatch,
                std::process::id(),
            ),
            HostRequestEvidence::ProcessStarted,
        ),
        (
            "durable_committed",
            HostRequestProjection::durable_committed(EntrypointStage::ScmDispatch),
            HostRequestEvidence::DurableCommitted,
        ),
        (
            "failed_without_reason",
            HostRequestProjection::failed_without_reason(EntrypointStage::ScmDispatch),
            HostRequestEvidence::Failed,
        ),
        (
            "observed",
            HostRequestProjection::observed(EntrypointStage::ScmDispatch),
            HostRequestEvidence::Observed,
        ),
        (
            "cancelled",
            HostRequestProjection::cancelled(EntrypointStage::ScmDispatch),
            HostRequestEvidence::Cancelled,
        ),
        (
            "unknown",
            HostRequestProjection::unknown(EntrypointStage::ScmDispatch),
            HostRequestEvidence::Unknown,
        ),
    ];
    // The frozen Event Log contract: a start is proved by the started process, a
    // stop by the committed durable effect, a failure by the failure itself.
    // Every other class asserts no completed operation.
    const PROVEN: [(AdmittedEvent, &str); 3] = [
        (AdmittedEvent::ServiceStart, "process_started"),
        (AdmittedEvent::ServiceStop, "durable_committed"),
        (AdmittedEvent::ServiceFailure, "failed_without_reason"),
    ];
    for (label, projection, evidence) in &dispositions {
        for event in EVENTS {
            let capture = emit(|| {
                observe_host_request(&projection.clone().with_operation(event));
            });
            assert!(
                capture.contains("host.request"),
                "no projection record for {label}: {capture}"
            );
            let proven = PROVEN
                .iter()
                .any(|(admitted, name)| *admitted == event && **name == **label);
            assert_eq!(
                capture.contains("host.event_log_admission"),
                proven,
                "{} with {} must{} reach the Event Log: {capture}",
                label,
                event.as_str(),
                if proven { "" } else { " not" }
            );
            if proven {
                assert_eq!(
                    count(&capture, "host.event_log_admission"),
                    1,
                    "one admission decision per projection: {capture}"
                );
                assert!(
                    capture.contains(&format!("operation=\"{}\"", event.as_str())),
                    "the admitted operation must be the one production names: {capture}"
                );
                assert!(
                    capture.contains(&format!("evidence=\"{}\"", evidence.as_str())),
                    "the evidence class must be the one production projects: {capture}"
                );
            }
            // Whatever the disposition, the record is a subordinate projection:
            // it owns no terminal and no positive rollback claim.
            assert!(
                !capture.contains("host.terminal_error"),
                "a projection record is never a terminal: {capture}"
            );
            for positive in ROLLBACK_POSITIVE_CLAIMS {
                assert!(
                    !capture.contains(positive),
                    "the {label} projection claimed {positive:?}: {capture}"
                );
            }
        }
    }
    // Supplementary owner binding: the three positive claims the reachable gate
    // denies above are the owner's own frozen labels, taken from the closed
    // `RollbackContour` projection the owner renders its records from.
    let owner = src("src/phase_b_materialization/rollback_backup.rs");
    let labels: Vec<&str> = owner_contour_labels(&owner)
        .iter()
        .map(|pair| pair.1.as_str())
        .collect();
    for positive in ROLLBACK_POSITIVE_CLAIMS {
        assert!(
            labels.contains(&positive),
            "the rollback owner must still publish its positive label {positive:?}"
        );
    }
}

/// Executed case, audit 5909832545 required item 5, second obligation:
/// rollback restoration, rollback-by-removal and sidecar cleanup stay distinct
/// records.
///
/// The reachable `HostRequestEvidence` / `AdmittedEvent` vocabularies are
/// frozen and unchanged by #980, so restating their pairwise distinctness here
/// would be evidence for nothing this issue changed and is not claimed. What
/// #980 changed is the rollback owner's emitted vocabulary, and that IS bound:
/// the closed `RollbackContour` label projection the owner renders every
/// rollback record from is read from the owner itself, checked to be closed and
/// pairwise distinct, checked against the owner's own emission sites, and
/// checked so that a restoration claim can belong to no other contour.
///
/// Named ceiling: `phase_b_restore_or_remove` and
/// `phase_b_remove_rollback_backup` are unreachable from an integration-test
/// crate, so no rollback record is produced here. The executed proof that those
/// three contours stay distinct on real inputs is `mod rollback_contour_tests`
/// beside the owner.
#[test]
fn projection_08_restoration_removal_and_cleanup_contours_stay_distinct_records() {
    let owner = src("src/phase_b_materialization/rollback_backup.rs");
    let production = owner.split("#[cfg(test)]").next().unwrap_or(owner.as_str());
    let labels = owner_contour_labels(&owner);
    // Closed and pairwise distinct: two contours sharing one label would make
    // their records indistinguishable again, which is what a re-added catch-all
    // disposition would do.
    let mut published: Vec<&str> = labels.iter().map(|pair| pair.1.as_str()).collect();
    let total = published.len();
    published.sort_unstable();
    published.dedup();
    assert_eq!(
        published.len(),
        total,
        "two rollback contours share one emitted label: {labels:?}"
    );
    // Every declared contour is actually published, and no publication names a
    // contour the label projection does not define. `phase_b_remove_rollback_backup`
    // carried no observation at all before #980; this is the check that stays
    // red if a contour becomes declared-but-unpublished again.
    let mut emitters = typed_discriminants(production, "RollbackContour");
    emitters.sort();
    emitters.dedup();
    let mut observed = emitters;
    let mut declared: Vec<String> = labels.iter().map(|(contour, _)| contour.clone()).collect();
    declared.sort();
    declared.dedup();
    assert_eq!(
        observed, declared,
        "every declared rollback contour must be published, and every publication must name a declared contour"
    );
    // The three contour families the issue separated. The removal family - which
    // was completely silent before - is named here in full, beside the
    // restoration and cleanup families.
    let values: Vec<&str> = labels.iter().map(|pair| pair.1.as_str()).collect();
    for family in [
        &[
            "host.phase-b rollback restore requested",
            "host.phase-b rollback restored verified",
        ][..],
        &[
            "host.phase-b rollback uncommitted removal requested",
            "host.phase-b rollback uncommitted removal verified",
            "host.phase-b rollback uncommitted removal not required",
            "host.phase-b rollback uncommitted removal delete failed",
            "host.phase-b rollback uncommitted removal absence unproven",
            "host.phase-b rollback uncommitted removal absence unknown",
        ][..],
        &[
            "host.phase-b rollback backup cleanup requested",
            "host.phase-b rollback backup cleanup completed",
            "host.phase-b rollback backup cleanup delete failed",
            "host.phase-b rollback backup cleanup path failed",
            "host.phase-b rollback backup cleanup absence unproven",
        ][..],
    ] {
        for label in family {
            assert!(
                values.contains(label),
                "the rollback owner must publish {label:?}"
            );
        }
    }
    // A removal or cleanup record can never read as a restoration: over the
    // owner's OWN emitted labels, the verified-restoration phrase belongs to the
    // restoration contour alone.
    for (contour, label) in &labels {
        if label.contains("restored verified") {
            assert_eq!(
                *label, "host.phase-b rollback restored verified",
                "only the restoration contour may claim a verified restoration, but {contour:?} does"
            );
        }
    }
}

/// Executed case, audit 5909832545 required item 5, third and fourth
/// obligations: the sidecar cleanup disposition is observable, and an unknown
/// or failed outcome is never logged as removed.
///
/// `phase_b_remove_rollback_backup` had no observation at all before #980. The
/// owner is unreachable from an integration target, so what this case drives is
/// the reachable disposition production really records when it routes a failed
/// Host request to the sink: `observe_host_request` reaches
/// `publish_projected_event_log_record`, and production emits its own
/// `host.event_log_admission` decision. The case asserts on that record only:
/// production reports the not-started rejection instead of claiming the sink
/// carried anything, names no terminal, carries no rollback contour detail, and
/// states no removal, restoration or cleanup claim.
///
/// Named ceiling: the cleanup contour's own runtime dispositions are not
/// executed here; the owner's label projection is bound below and
/// `mod rollback_contour_tests` beside the owner drives the cleanup path with
/// real deletions.
#[test]
#[allow(
    clippy::too_many_lines,
    reason = "the reachable sink disposition record and the owner cleanup contour inventory stay in one deterministic probe"
)]
fn projection_09_sidecar_cleanup_disposition_is_observable_and_claims_no_removal() {
    let capture = emit(|| {
        observe_host_request(
            &HostRequestProjection::failed_without_reason(EntrypointStage::ScmDispatch)
                .with_operation(AdmittedEvent::ServiceFailure),
        );
    });
    assert_eq!(
        count(&capture, "host.event_log_admission"),
        1,
        "the reachable surface must record its sink disposition exactly once: {capture}"
    );
    // Production's own admission disposition. Only `main` starts the Event Log
    // producer, so in this process production must report the not-started
    // rejection rather than claim the sink accepted anything - even where the
    // #984 port itself is live.
    assert!(
        capture.contains(&format!(
            "outcome=\"{}\"",
            (EventLogAdmission::RejectedNotStarted { dropped_total: 0 }).as_str()
        )),
        "the admission outcome must be the one production decided: {capture}"
    );
    assert!(
        capture.contains("dropped_total=0"),
        "no drop may be counted before the producer exists: {capture}"
    );
    assert!(
        capture.contains(&format!(
            "operation=\"{}\"",
            AdmittedEvent::ServiceFailure.as_str()
        )),
        "the admitted operation must be the one production names: {capture}"
    );
    assert!(
        capture.contains(&format!(
            "evidence=\"{}\"",
            HostRequestEvidence::Failed.as_str()
        )),
        "the evidence class must be the one production projects: {capture}"
    );
    // The disposition record names where the record stayed and nothing else:
    // no terminal, no entrypoint stage, no rollback contour detail, and no
    // positive rollback claim riding along with a failure.
    assert!(
        !capture.contains("host.terminal_error"),
        "a sink disposition is not a terminal: {capture}"
    );
    assert!(
        !capture.contains("host.entrypoint_stage"),
        "the canonical disposition observer is not an entrypoint stage: {capture}"
    );
    assert!(
        !capture.contains("host.phase-b"),
        "a sink disposition carries no rollback contour detail: {capture}"
    );
    for positive in ROLLBACK_POSITIVE_CLAIMS {
        assert!(
            !capture.contains(positive),
            "the sink disposition record claimed {positive:?}: {capture}"
        );
    }
    // Owner binding: the cleanup contour is no longer silent and states its own
    // explicit non-success dispositions beside the positive one, so a failed or
    // undetermined cleanup cannot read as a completion. The family is read out
    // of the owner's own closed label projection.
    let owner = src("src/phase_b_materialization/rollback_backup.rs");
    let labels = owner_contour_labels(&owner);
    let cleanup: Vec<&str> = labels
        .iter()
        .filter(|pair| pair.1.starts_with("host.phase-b rollback backup cleanup"))
        .map(|pair| pair.1.as_str())
        .collect();
    for disposition in [
        "requested",
        "completed",
        "delete failed",
        "path failed",
        "absence unproven",
    ] {
        assert!(
            cleanup.iter().any(|label| label.ends_with(disposition)),
            "the sidecar cleanup contour must name its {disposition} disposition: {cleanup:?}"
        );
    }
    let mut distinct = cleanup.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        cleanup.len(),
        "two cleanup dispositions share one label: {cleanup:?}"
    );
    for (contour, label) in &labels {
        if label.starts_with("host.phase-b rollback backup cleanup") {
            assert!(
                !label.contains("restored verified") && !label.contains("uncommitted removal"),
                "a cleanup disposition must never read as a restoration or a removal: {contour:?}"
            );
        }
    }
}
