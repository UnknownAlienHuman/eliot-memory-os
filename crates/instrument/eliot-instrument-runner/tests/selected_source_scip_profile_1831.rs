//! Module-edge acceptance for the registered rust-analyzer SCIP profile.
//!
//! This exercises the original public profile/provider resolver with typed
//! registry inputs. The executable identity is an explicit test fixture: this
//! test launches no process and proves no Governor/Kernel queue authority.
//!
//! Documentation route receipt: sha256:e8d3b0abd490ad71c1bd26ac320b6e45facd3709d3accd806c7c4f4f7871907b
//! Read receipt: sha256:801f4f9c3bdcac6da7d3263c5a54b7e217ac2494491f73f8532c44502f1be86e
//! Matched routes: generic-source, host-kernel, canonical-storage,
//! instrument-verification, memory-context, security-privacy,
//! workspace-governance. Required handles read: I10.8.4, I10.8.7, I10.10.
//! Relevant fragments: docs/architecture/I10-08-04-ip2-instrumentrunner.md
//! (sha256:b9a020dd270e278e5834a775186c0100c52ab85c35dd1e5e102bedb1e115b638),
//! docs/architecture/I10-08-07-ip4-instrument-profiles.md
//! (sha256:ec5294d8aaa39b29194e1132adb3e36c27e175d4032fceba88778774a1516ad7),
//! docs/architecture/I10-10-lsp-and-diagnostics.md
//! (sha256:fbd98ea953d7339a1961c8f15f2f0aa3bd6b0ad48640e9c3089e096e94151455).
//! Verified bundle sha256:
//! d1675debd73e0b03f277585aa10e30956d54ac8f60da3c2c22bcd35922195196.
//! Reading attestation: I read the routed I10.8.4, I10.8.7, and I10.10
//! fragments and the owner-port bundle before adding these tests.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, ContractId, EpochId, EpochLineageId, ProductId, RequestId, RequestMetadata,
    ResourceGeneration, SourceId, StateFence,
};
use eliot_instrument_api::{InstrumentInvocation, InstrumentKind};
use eliot_instrument_runner::registry::{InvalidationSet, RegistryFreshness};
use eliot_instrument_runner::{
    BUILTIN_PROFILE_REVISION, InstrumentClass, InstrumentRegistry, ProviderRegistry,
    RUST_ANALYZER_DIAGNOSTICS_INSTRUMENT, RUST_ANALYZER_PROFILE, RUST_ANALYZER_SCIP_INSTRUMENT,
    RUST_ANALYZER_VERSION_INSTRUMENT, ResolvedExecutableIdentity, resolve_rust_analyzer_profile,
};

const REGISTRY_GENERATION: u64 = 19;
const NORMATIVE_PAIR_DIGEST: &str = "acceptance-normative-pair";
const INVOCATION_TARGET: &str = "workspace:worktree-7";
const INVOCATION_SCOPE: &str = "workspace-scope:project";

fn fingerprints() -> InvalidationSet {
    InvalidationSet {
        source: "source-fingerprint".to_owned(),
        lock: "lock-fingerprint".to_owned(),
        toolchain: "toolchain-fingerprint".to_owned(),
        env: "environment-fingerprint".to_owned(),
        exe: "executable-fingerprint".to_owned(),
        profile: "profile-fingerprint".to_owned(),
        parser: "parser-fingerprint".to_owned(),
    }
}

fn registries() -> (InstrumentRegistry, ProviderRegistry, InvalidationSet) {
    let profiles = InstrumentRegistry::with_builtin_profiles(REGISTRY_GENERATION)
        .expect("built-in profiles admit the rust-analyzer SCIP spec");
    let fingerprints = fingerprints();
    let providers = ProviderRegistry::ready(
        REGISTRY_GENERATION,
        NORMATIVE_PAIR_DIGEST.to_owned(),
        &fingerprints,
    )
    .expect("ready provider registry contains the original rust-analyzer SCIP binding");
    (profiles, providers, fingerprints)
}

fn invocation(instrument: &str, arguments: Vec<String>) -> InstrumentInvocation {
    let clock = ClockReading {
        valid_time_ms: Some(10),
        known_time_ms: Some(11),
        transaction_sequence: None,
        monotonic_ns: Some(1),
    };
    let lineage =
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("valid lineage");
    let epoch =
        EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero epoch")).expect("valid epoch");
    InstrumentInvocation {
        request: RequestMetadata {
            request_id: RequestId::new("selected-source-scip-request").expect("valid request id"),
            session_id: None,
            task_id: None,
            product_id: ProductId::new("selected-source-scip-product").expect("valid product id"),
            source_id: SourceId::new("selected-source-scip-source").expect("valid source id"),
            state_fence: StateFence::new(epoch, ResourceGeneration::genesis()),
            clock,
        },
        instrument: ContractId::new(instrument).expect("valid instrument contract id"),
        kind: InstrumentKind::Inspect,
        profile: RUST_ANALYZER_PROFILE.to_owned(),
        target: INVOCATION_TARGET.to_owned(),
        arguments,
        input_artifacts: Vec::new(),
        declared_scope: INVOCATION_SCOPE.to_owned(),
        requested_at: clock,
    }
}

fn executable(instrument: &str, arguments: Vec<String>) -> ResolvedExecutableIdentity {
    ResolvedExecutableIdentity::new(
        instrument,
        r"C:\toolchains\1.97.1\bin\rust-analyzer.exe".to_owned(),
        "a".repeat(64),
        Some("rust-analyzer 1.97.1".to_owned()),
        "b".repeat(64),
        arguments,
    )
    .expect("complete typed executable identity")
}

fn freshness(fingerprints: &InvalidationSet) -> RegistryFreshness<'_> {
    RegistryFreshness {
        generation: REGISTRY_GENERATION,
        normative_pair_digest: NORMATIVE_PAIR_DIGEST,
        fingerprints,
    }
}

#[test]
fn builtin_profile_resolves_scip_and_preserves_diagnostics_and_version_bindings() {
    let (profiles, providers, fingerprints) = registries();
    let freshness = freshness(&fingerprints);
    let admitted_profile = profiles
        .admitted(RUST_ANALYZER_PROFILE, BUILTIN_PROFILE_REVISION)
        .expect("exact built-in profile revision remains admitted");

    let cases = [
        (
            RUST_ANALYZER_DIAGNOSTICS_INSTRUMENT,
            "eliot.instrument.diagnostic",
            vec!["diagnostics".to_owned()],
        ),
        (
            RUST_ANALYZER_VERSION_INSTRUMENT,
            "eliot.instrument.lsp-bridge",
            vec!["--version".to_owned()],
        ),
        (
            RUST_ANALYZER_SCIP_INSTRUMENT,
            "eliot.instrument.lsp-bridge",
            vec!["scip".to_owned()],
        ),
    ];

    for (instrument, expected_parser, expected_command) in cases {
        let invocation = invocation(instrument, Vec::new());
        let original_target = invocation.target.clone();
        let original_scope = invocation.declared_scope.clone();
        assert!(invocation.validate().is_ok());

        let stage = admitted_profile
            .dag
            .iter()
            .find(|stage| stage.spec.as_str() == instrument)
            .expect("profile retains the operation's declared stage");
        assert_eq!(stage.kind, InstrumentKind::Inspect);

        let spec = profiles
            .spec(instrument)
            .expect("profile stage resolves to its original spec");
        assert_eq!(spec.kind.as_str(), instrument);
        assert_eq!(spec.class, InstrumentClass::SemanticIndex);
        assert_eq!(spec.executable, "rust-analyzer");
        assert_eq!(spec.parser.as_str(), expected_parser);
        assert!(spec.argument_template.is_empty());
        assert_eq!(spec.verification_command, expected_command);

        let provider = providers
            .resolve_current(&invocation, &freshness)
            .expect("provider entry is current at the supplied freshness");
        assert_eq!(provider.instrument.as_str(), instrument);
        assert_eq!(provider.parser.as_str(), expected_parser);
        assert_eq!(provider.normalizer.as_str(), "eliot.instrument.lsp-bridge");
        assert_eq!(
            provider.executable.executable.as_deref(),
            Some("rust-analyzer")
        );

        let observed = executable(instrument, expected_command.clone());
        let resolved = resolve_rust_analyzer_profile(
            &profiles,
            &providers,
            &invocation,
            &freshness,
            &observed,
        )
        .expect("original typed profile/spec/provider/executable binding resolves");

        assert_eq!(resolved.profile.name, RUST_ANALYZER_PROFILE);
        assert_eq!(resolved.profile.revision, BUILTIN_PROFILE_REVISION);
        assert_eq!(resolved.spec.digest(), spec.digest());
        assert_eq!(resolved.provider, provider);
        assert!(std::ptr::eq(resolved.resolved_executable, &observed));
        assert_eq!(
            resolved.resolved_executable.identity_digest(),
            observed.identity_digest()
        );
        assert_eq!(
            resolved.resolved_executable.canonical_path,
            r"C:\toolchains\1.97.1\bin\rust-analyzer.exe"
        );
        assert_eq!(resolved.resolved_executable.content_digest, "a".repeat(64));
        assert_eq!(
            resolved.resolved_executable.tool_version.as_deref(),
            Some("rust-analyzer 1.97.1")
        );
        assert_eq!(
            resolved.resolved_executable.environment_digest,
            "b".repeat(64)
        );
        assert_eq!(resolved.resolved_executable.arguments, expected_command);
        assert!(
            resolved
                .resolved_executable
                .binds_argv(&spec.verification_command)
        );

        // Resolution borrows the caller's invocation and cannot rewrite its target or scope.
        assert_eq!(invocation.target, original_target);
        assert_eq!(invocation.declared_scope, original_scope);
        assert_eq!(invocation.target, INVOCATION_TARGET);
        assert_eq!(invocation.declared_scope, INVOCATION_SCOPE);
    }
}

#[test]
fn resolver_refuses_substituted_instrument_parser_executable_and_invocation_arguments() {
    let (profiles, providers, fingerprints) = registries();
    let freshness = freshness(&fingerprints);
    let observed = executable(RUST_ANALYZER_SCIP_INSTRUMENT, vec!["scip".to_owned()]);

    let foreign_instrument = invocation("eliot.instrument.rust-analyzer.foreign", Vec::new());
    assert!(matches!(
        resolve_rust_analyzer_profile(
            &profiles,
            &providers,
            &foreign_instrument,
            &freshness,
            &observed
        ),
        Err(eliot_instrument_runner::RustAnalyzerProfileError::UnsupportedInstrument { .. })
    ));

    let injected_arguments = invocation(RUST_ANALYZER_SCIP_INSTRUMENT, vec!["--config".to_owned()]);
    assert!(matches!(
        resolve_rust_analyzer_profile(
            &profiles,
            &providers,
            &injected_arguments,
            &freshness,
            &observed
        ),
        Err(eliot_instrument_runner::RustAnalyzerProfileError::ArgumentMismatch)
    ));

    let mut wrong_executable = executable(RUST_ANALYZER_SCIP_INSTRUMENT, vec!["scip".to_owned()]);
    wrong_executable.canonical_path = r"C:\toolchains\1.97.1\bin\foreign-analyzer.exe".to_owned();
    assert!(matches!(
        resolve_rust_analyzer_profile(
            &profiles,
            &providers,
            &invocation(RUST_ANALYZER_SCIP_INSTRUMENT, Vec::new()),
            &freshness,
            &wrong_executable
        ),
        Err(eliot_instrument_runner::RustAnalyzerProfileError::Registry(
            eliot_instrument_runner::RegistryError::ExecutableMismatch { .. }
        ))
    ));

    let mut entries: Vec<_> = providers.iter().cloned().collect();
    let scip_provider = entries
        .iter_mut()
        .find(|entry| entry.instrument.as_str() == RUST_ANALYZER_SCIP_INSTRUMENT)
        .expect("the original ready registry contains the SCIP provider");
    scip_provider.parser =
        ContractId::new("eliot.instrument.foreign-parser").expect("valid parser id");
    let foreign_parser_providers = ProviderRegistry::build(
        entries,
        REGISTRY_GENERATION,
        NORMATIVE_PAIR_DIGEST.to_owned(),
    )
    .expect("the test registry preserves all original identity slots");

    assert!(matches!(
        resolve_rust_analyzer_profile(
            &profiles,
            &foreign_parser_providers,
            &invocation(RUST_ANALYZER_SCIP_INSTRUMENT, Vec::new()),
            &freshness,
            &observed
        ),
        Err(eliot_instrument_runner::RustAnalyzerProfileError::IdentityMismatch)
    ));

    // The process argv binding stays exact even when a different observed argv is presented.
    let substituted_argv = executable(
        RUST_ANALYZER_SCIP_INSTRUMENT,
        vec!["--config".to_owned(), "foreign.toml".to_owned()],
    );
    let scip_spec = profiles
        .spec(RUST_ANALYZER_SCIP_INSTRUMENT)
        .expect("SCIP spec remains registered");
    assert!(!substituted_argv.binds_argv(&scip_spec.verification_command));
}
