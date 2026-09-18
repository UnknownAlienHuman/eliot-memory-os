//! Current verification consumer edge (T7-S2).
//!
//! The admitted plan supplies the required test ids, the admitted invocation
//! supplies the registered nextest binding together with the declared scope
//! and fence, and the caller supplies the digest-bound raw evidence captured
//! for exactly that invocation. Evaluation itself belongs to
//! `eliot-verifier`; this edge only binds the three admitted inputs together
//! and refuses anything else. No process is launched here: execution belongs
//! to the Testd/P-03 composition root (`bins/eliotd`, S7).

use std::collections::BTreeSet;

use eliot_contracts::ClockReading;
use eliot_instrument_api::{
    InstrumentInvocation, RawEvidence, VerificationRun as CurrentVerificationRun,
};
use eliot_instrument_nextest::NEXTEST_INSTRUMENT;
use eliot_instrument_runner::registry::{ProviderRegistry, RegistryFreshness};
use eliot_types::VerificationPlan;

use super::VerificationRunnerService;
use super::rejected;

impl VerificationRunnerService {
    /// Evaluates one current verification run from admitted inputs only.
    ///
    /// The required test set is derived from the admitted plan's selected
    /// tests, never from caller-supplied ids or from the instrument output.
    /// The invocation must resolve through the provided registry to the
    /// registered nextest provider with the registered parser and verifier
    /// bindings. Raw evidence is checked by digest inside the evaluator; an
    /// all-skipped or otherwise incomplete report never becomes `Pass`.
    ///
    /// # Errors
    ///
    /// Returns a typed [`crate::EngineError`] when the plan names unknown
    /// commands, the invocation does not resolve to the current nextest
    /// binding, or the evaluator rejects the evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn run_current(
        &self,
        plan: &VerificationPlan,
        invocation: &InstrumentInvocation,
        raw: &[RawEvidence],
        started_at: ClockReading,
        finished_at: ClockReading,
        registry: &ProviderRegistry,
        freshness: &RegistryFreshness<'_>,
    ) -> Result<CurrentVerificationRun, crate::EngineError> {
        if !self.plan_uses_only_known_commands(plan) {
            return Err(rejected(
                "verification-runner",
                "verification plan contains unknown commands",
            ));
        }
        let entry = registry
            .resolve_current(invocation, freshness)
            .map_err(|error| {
                rejected(
                    "verification-runner",
                    &format!("registry rejected the current invocation: {error}"),
                )
            })?;
        if entry.adapter != NEXTEST_INSTRUMENT {
            return Err(rejected(
                "verification-runner",
                &format!(
                    "registry resolved adapter '{}'; current verification requires {NEXTEST_INSTRUMENT}",
                    entry.adapter
                ),
            ));
        }
        if entry.parser.as_str() != NEXTEST_INSTRUMENT {
            return Err(rejected(
                "verification-runner",
                "registry parser binding is not the registered nextest parser",
            ));
        }
        if entry.verifier.as_str() != eliot_verifier::CONTRACT_NAME {
            return Err(rejected(
                "verification-runner",
                "registry verifier binding is not the current verifier",
            ));
        }
        let required: BTreeSet<String> = plan.selected_tests.iter().cloned().collect();
        eliot_verifier::evaluate_current(invocation, raw, &required, started_at, finished_at)
            .map_err(|error| {
                rejected(
                    "verification-runner",
                    &format!("current evaluation rejected: {error}"),
                )
            })
    }
}

#[cfg(test)]
mod current_tests {
    use super::*;
    use eliot_contracts::{
        ArtifactId, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SourceId, StateFence, sha256_hex,
    };
    use eliot_instrument_api::{
        EvidenceCoverage, ExecutionStatus, RawEvidenceSource, VerificationOutcome,
    };
    use eliot_instrument_nextest::NextestCommand;
    use eliot_instrument_runner::registry::{InvalidationSet, RegistryFreshness};
    use eliot_types::VerificationRuntimeClass;
    use std::num::NonZeroU64;
    use std::path::{Path, PathBuf};

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const PROBE_ID: &str = "t13s2-engine-probe";
    const NORMATIVE_DIGEST: &str = "normative-pair-digest-fixture";
    const GENERATION: u64 = 3;

    /// Minimal genuine test program; see the verifier crate for the full
    /// rationale. It really executes a checksum comparison and reports
    /// canonical nextest-schema events reflecting its genuine outcome.
    const PROBE_SOURCE: &str = r#"
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("pass");
    let name = args
        .get(2)
        .map(String::as_str)
        .unwrap_or("t13s2-engine-probe");
    println!("{{\"type\":\"test\",\"event\":\"started\",\"name\":\"{name}\"}}");
    if mode == "skip" {
        println!("{{\"type\":\"test\",\"event\":\"completed\",\"name\":\"{name}\",\"status\":\"SKIP\"}}");
        return;
    }
    let total: u64 = (1..=1000).sum();
    let expected: u64 = if mode == "pass" { 500_500 } else { 0 };
    let status = if total == expected { "PASS" } else { "FAIL" };
    println!("{{\"type\":\"test\",\"event\":\"completed\",\"name\":\"{name}\",\"status\":\"{status}\"}}");
    if status != "PASS" {
        std::process::exit(1);
    }
}
"#;

    const FIXTURE_MANIFEST: &str = r#"
[package]
name = "t13s2-nextest-probe"
version = "0.1.0"
edition = "2021"
"#;

    const FIXTURE_LIB: &str = r"
#[test]
fn probe_passes() {
    assert_eq!(1, 1);
}
";

    fn test_error(message: impl Into<String>) -> Box<dyn std::error::Error + Send + Sync> {
        Box::new(std::io::Error::other(message.into()))
    }

    fn scratch_dir(tag: &str) -> TestResult<PathBuf> {
        let dir =
            std::env::temp_dir().join(format!("eliot-t13s2-engine-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn compile_probe(dir: &Path) -> TestResult<PathBuf> {
        let source = dir.join("engine_probe.rs");
        std::fs::write(&source, PROBE_SOURCE)?;
        let exe = dir.join(if cfg!(windows) {
            "engine_probe.exe"
        } else {
            "engine_probe"
        });
        let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
        let output = std::process::Command::new(rustc)
            .arg("--edition=2021")
            .arg(&source)
            .arg("-o")
            .arg(&exe)
            .output()?;
        if !output.status.success() {
            return Err(test_error(format!(
                "probe rustc failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(exe)
    }

    fn fence() -> TestResult<StateFence> {
        let lineage = EpochLineageId::new(TEST_LINEAGE)?;
        let Some(sequence) = NonZeroU64::new(7) else {
            return Err(test_error("sequence must be non-zero"));
        };
        Ok(StateFence::new(
            EpochId::new(lineage, sequence)?,
            ResourceGeneration::genesis(),
        ))
    }

    fn clock(known_ms: i64) -> ClockReading {
        ClockReading {
            valid_time_ms: Some(known_ms - 1),
            known_time_ms: Some(known_ms),
            transaction_sequence: None,
            monotonic_ns: Some(1),
        }
    }

    fn invocation(target: &str) -> TestResult<InstrumentInvocation> {
        let request = RequestMetadata {
            request_id: RequestId::new("engine-current-request-1")?,
            session_id: None,
            task_id: None,
            product_id: ProductId::new("product-1")?,
            source_id: SourceId::new("source-1")?,
            state_fence: fence()?,
            clock: clock(100),
        };
        Ok(InstrumentInvocation {
            request,
            instrument: eliot_contracts::ContractId::new(NEXTEST_INSTRUMENT)?,
            kind: eliot_instrument_api::InstrumentKind::Test,
            profile: "default".to_owned(),
            target: target.to_owned(),
            arguments: vec!["-E".to_owned(), "test(probe)".to_owned()],
            input_artifacts: Vec::new(),
            declared_scope: "engine-probe-scope".to_owned(),
            requested_at: clock(100),
        })
    }

    fn raw_for(invocation: &InstrumentInvocation, bytes: Vec<u8>) -> TestResult<RawEvidence> {
        Ok(RawEvidence {
            artifact_id: ArtifactId::new("raw-engine-probe-output")?,
            invocation_id: invocation.request.request_id.clone(),
            source: RawEvidenceSource::Process,
            content_type: "application/json".to_owned(),
            sha256: sha256_hex(&bytes),
            bytes,
            captured_at: clock(101),
            truncated: false,
        })
    }

    fn admitted_plan(selected: &[&str]) -> VerificationPlan {
        VerificationPlan {
            plan_id: "verification-plan-current".to_owned(),
            profile_id: "change-gate".to_owned(),
            changed_refs: vec!["engine-probe-scope".to_owned()],
            selected_tests: selected.iter().map(|id| (*id).to_owned()).collect(),
            required_commands: vec!["just verify".to_owned()],
            skipped_tests: Vec::new(),
            estimated_runtime_class: VerificationRuntimeClass::Full,
            created_at: time::OffsetDateTime::now_utc(),
        }
    }

    fn fingerprints() -> InvalidationSet {
        InvalidationSet {
            source: "source-fp".to_owned(),
            lock: "lock-fp".to_owned(),
            toolchain: "toolchain-fp".to_owned(),
            env: "env-fp".to_owned(),
            exe: "exe-fp".to_owned(),
            profile: "profile-fp".to_owned(),
            parser: "parser-fp".to_owned(),
        }
    }

    fn ready_registry(fingerprints: &InvalidationSet) -> TestResult<ProviderRegistry> {
        Ok(ProviderRegistry::ready(
            GENERATION,
            NORMATIVE_DIGEST.to_owned(),
            fingerprints,
        )?)
    }

    fn scaffold_nextest_fixture(dir: &Path) -> TestResult<()> {
        std::fs::create_dir_all(dir.join("src"))?;
        std::fs::write(dir.join("Cargo.toml"), FIXTURE_MANIFEST)?;
        std::fs::write(dir.join("src/lib.rs"), FIXTURE_LIB)?;
        Ok(())
    }

    #[test]
    fn current_run_through_registered_nextest_binding_passes() -> TestResult {
        let dir = scratch_dir("current")?;
        let fingerprints = fingerprints();
        let registry = ready_registry(&fingerprints)?;
        let freshness = RegistryFreshness {
            generation: GENERATION,
            normative_pair_digest: NORMATIVE_DIGEST,
            fingerprints: &fingerprints,
        };
        let invocation = invocation("engine-probe-worktree")?;

        // The shipped registry resolves the admitted invocation to exactly
        // the nextest provider with the registered parser/verifier bindings,
        // and stale freshness fails closed.
        let entry = registry.resolve_current(&invocation, &freshness)?;
        assert_eq!(entry.adapter, NEXTEST_INSTRUMENT);
        assert!(entry.supports(eliot_instrument_api::InstrumentKind::Test));
        assert_eq!(entry.parser.as_str(), NEXTEST_INSTRUMENT);
        assert_eq!(entry.verifier.as_str(), eliot_verifier::CONTRACT_NAME);
        let stale = RegistryFreshness {
            generation: GENERATION + 1,
            normative_pair_digest: NORMATIVE_DIGEST,
            fingerprints: &fingerprints,
        };
        assert!(registry.resolve_current(&invocation, &stale).is_err());

        // The registered command shape really executes: one crate test runs
        // through the real `cargo nextest` process in an isolated target dir.
        let fixture = dir.join("nextest-fixture");
        scaffold_nextest_fixture(&fixture)?;
        let filter = "probe_passes".to_owned();
        let target = fixture.to_string_lossy().into_owned();
        let command = NextestCommand::run(target, "default", std::slice::from_ref(&filter))?;
        assert_eq!(command.executable, "cargo");
        assert_eq!(
            command.arguments,
            vec![
                "nextest".to_owned(),
                "run".to_owned(),
                "--profile".to_owned(),
                "default".to_owned(),
                filter.clone(),
            ]
        );
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
        let nextest_output = std::process::Command::new(cargo)
            .args(&command.arguments)
            .current_dir(&fixture)
            .env("CARGO_TARGET_DIR", fixture.join("target-isolated"))
            .env("CARGO_NET_OFFLINE", "true")
            .output()?;
        assert!(
            nextest_output.status.success(),
            "real nextest process must pass: {}",
            String::from_utf8_lossy(&nextest_output.stderr)
        );
        // A piped nextest renders its human UI on stderr; both streams are
        // real process output, so the executed test name may appear in either.
        let mut nextest_transcript = nextest_output.stdout.clone();
        nextest_transcript.extend_from_slice(&nextest_output.stderr);
        let nextest_transcript = String::from_utf8_lossy(&nextest_transcript);
        assert!(
            nextest_transcript.contains(&filter),
            "real nextest output must name the executed test"
        );

        // The consumer edge turns real probe bytes plus the admitted plan
        // into a scope/fence-bound passing run.
        let exe = compile_probe(&dir)?;
        let probe_output = std::process::Command::new(&exe)
            .arg("pass")
            .arg(PROBE_ID)
            .output()?;
        assert!(probe_output.status.success());
        let raw = raw_for(&invocation, probe_output.stdout)?;
        let plan = admitted_plan(&[PROBE_ID]);
        let runner = VerificationRunnerService;
        let run = runner.run_current(
            &plan,
            &invocation,
            std::slice::from_ref(&raw),
            clock(100),
            clock(102),
            &registry,
            &freshness,
        )?;
        assert_eq!(run.outcome, VerificationOutcome::Pass);
        assert_eq!(run.execution, ExecutionStatus::Succeeded);
        assert_eq!(run.coverage, EvidenceCoverage::CompleteForScope);
        assert_eq!(run.scope, "engine-probe-scope");
        assert_eq!(run.invocation_id, invocation.request.request_id);
        assert_eq!(run.state_fence, invocation.request.state_fence);
        assert_eq!(run.raw_evidence, vec![raw.artifact_id.clone()]);
        assert!(run.validate().is_ok());

        // The same edge with an incomplete required set must not pass: the
        // required ids come from the admitted plan, not from the output.
        let partial_plan = admitted_plan(&[PROBE_ID, "never-executed-required-test"]);
        let run = runner.run_current(
            &partial_plan,
            &invocation,
            std::slice::from_ref(&raw),
            clock(100),
            clock(102),
            &registry,
            &freshness,
        )?;
        assert_ne!(run.outcome, VerificationOutcome::Pass);
        assert_eq!(run.outcome, VerificationOutcome::Partial);
        Ok(())
    }

    #[test]
    fn current_run_rejects_unadmitted_inputs() -> TestResult {
        let dir = scratch_dir("rejected")?;
        let fingerprints = fingerprints();
        let registry = ready_registry(&fingerprints)?;
        let freshness = RegistryFreshness {
            generation: GENERATION,
            normative_pair_digest: NORMATIVE_DIGEST,
            fingerprints: &fingerprints,
        };
        let invocation = invocation("engine-probe-worktree")?;
        let exe = compile_probe(&dir)?;
        let probe_output = std::process::Command::new(&exe)
            .arg("pass")
            .arg(PROBE_ID)
            .output()?;
        assert!(probe_output.status.success());
        let raw = raw_for(&invocation, probe_output.stdout)?;
        let runner = VerificationRunnerService;

        // Unknown commands in the admitted plan stay rejected.
        let mut hostile_plan = admitted_plan(&[PROBE_ID]);
        hostile_plan.required_commands = vec!["cargo test -- --ignored".to_owned()];
        assert!(
            runner
                .run_current(
                    &hostile_plan,
                    &invocation,
                    std::slice::from_ref(&raw),
                    clock(100),
                    clock(102),
                    &registry,
                    &freshness,
                )
                .is_err()
        );

        // An empty required set from the admitted plan can never pass.
        let empty_plan = admitted_plan(&[]);
        assert!(
            runner
                .run_current(
                    &empty_plan,
                    &invocation,
                    std::slice::from_ref(&raw),
                    clock(100),
                    clock(102),
                    &registry,
                    &freshness,
                )
                .is_err()
        );

        // Raw evidence captured for a different invocation is foreign.
        let mut foreign = raw.clone();
        foreign.invocation_id = RequestId::new("some-other-request")?;
        assert!(
            runner
                .run_current(
                    &admitted_plan(&[PROBE_ID]),
                    &invocation,
                    std::slice::from_ref(&foreign),
                    clock(100),
                    clock(102),
                    &registry,
                    &freshness,
                )
                .is_err()
        );

        // Legacy profile-record promotion without execution stays removed.
        assert!(
            runner
                .run_profile_record(&admitted_plan(&[PROBE_ID]))
                .is_err()
        );
        Ok(())
    }
}
