//! Common provider-registry conformance and refusal cases.

use eliot_instrument_api::{ExecutionStatus, InstrumentKind};
use eliot_instrument_runner::registry::{
    FingerprintField, InvalidationSet, RegistryError, StaleReason,
};
use eliot_instrument_runner::{
    ADVERTISED_INSTRUMENTS, AvailabilityInputs, ConformanceCase, ConformanceCorpus,
    ConformanceError, DENOMINATOR_CONTRACT, OmissionReason, ProviderDenominator,
    ProviderDisposition, ProviderFixtureSet, ProviderRegistry, RawEvidence,
    UNMAPPED_IN_PROCESS_INSTRUMENTS, declared_instruments, disposition_for_parts, host_platform,
};

const REGISTRY_GENERATION: u64 = 1;
type FingerprintMutation = (FingerprintField, fn(&mut InvalidationSet));

fn fingerprints() -> InvalidationSet {
    InvalidationSet {
        source: "source".to_owned(),
        lock: "lock".to_owned(),
        toolchain: "toolchain".to_owned(),
        env: "env".to_owned(),
        exe: "exe".to_owned(),
        profile: "profile".to_owned(),
        parser: "parser".to_owned(),
    }
}

fn ready_registry() -> Result<
    (
        ProviderRegistry,
        ProviderDenominator,
        InvalidationSet,
        String,
    ),
    String,
> {
    let fingerprints = fingerprints();
    let normative_pair_digest = format!("test:{DENOMINATOR_CONTRACT}");
    let registry = ProviderRegistry::ready(
        REGISTRY_GENERATION,
        normative_pair_digest.clone(),
        &fingerprints,
    )
    .map_err(|error| format!("ready registry construction failed: {error:?}"))?;
    let denominator = ProviderDenominator::current(&registry)
        .map_err(|error| format!("provider denominator construction failed: {error:?}"))?;
    Ok((registry, denominator, fingerprints, normative_pair_digest))
}

fn common_corpus(
    registry: &ProviderRegistry,
    denominator: &ProviderDenominator,
    fingerprints: &InvalidationSet,
) -> Result<ConformanceCorpus, String> {
    let cases = declared_instruments()
        .map(|advertised| -> Result<_, String> {
            let entry = denominator.entry(advertised.contract);
            let kind = entry
                .and_then(|entry| entry.kinds.first().copied())
                .unwrap_or(InstrumentKind::Build);
            let expected_dispatchable = entry.is_some_and(|entry| {
                registry
                    .availability_parts(
                        &entry.instrument,
                        kind,
                        &AvailabilityInputs {
                            generation: registry.generation(),
                            normative_pair_digest: registry.normative_pair_digest(),
                            fingerprints,
                            platform: host_platform(),
                        },
                    )
                    .is_available()
            });
            Ok(ConformanceCase {
                case_id: advertised.contract.to_owned(),
                instrument: advertised.contract.to_owned(),
                kind,
                expected_dispatchable,
                real_execution: false,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(ConformanceCorpus {
        corpus_id: DENOMINATOR_CONTRACT.to_owned(),
        generation: registry.generation(),
        normative_pair_digest: registry.normative_pair_digest().to_owned(),
        fingerprints: fingerprints.clone(),
        cases,
    })
}

#[test]
fn ready_registry_and_shared_corpus_cover_each_declared_provider_identity() -> Result<(), String> {
    let (registry, denominator, fingerprints, _) = ready_registry()?;
    let corpus = common_corpus(&registry, &denominator, &fingerprints)?;

    assert_eq!(ADVERTISED_INSTRUMENTS.len(), 6);
    assert_eq!(denominator.mapped(), ADVERTISED_INSTRUMENTS.len());
    assert_eq!(corpus.cases.len(), declared_instruments().count());
    assert_eq!(
        declared_instruments().count(),
        ADVERTISED_INSTRUMENTS.len() + UNMAPPED_IN_PROCESS_INSTRUMENTS.len()
    );
    assert!(corpus.validate(&registry, &denominator).is_ok());

    for unmapped in UNMAPPED_IN_PROCESS_INSTRUMENTS {
        let case = corpus
            .cases
            .iter()
            .find(|case| case.instrument == unmapped.contract)
            .ok_or_else(|| {
                format!(
                    "shared corpus omits declared provider {}",
                    unmapped.contract
                )
            })?;
        assert!(!case.expected_dispatchable);
        assert!(!case.real_execution);
        assert!(denominator.entry(unmapped.contract).is_none());
    }

    for advertised in ADVERTISED_INSTRUMENTS {
        let entry = denominator.entry(advertised.contract).ok_or_else(|| {
            format!(
                "advertised provider entry {} is missing",
                advertised.contract
            )
        })?;
        let kind = entry
            .kinds
            .first()
            .copied()
            .ok_or_else(|| format!("provider {} has no kind", advertised.contract))?;
        assert_eq!(entry.instrument.as_str(), advertised.contract);
        assert!(entry.verify_profile_identities().is_ok());
        assert_eq!(
            entry.identities.executable,
            entry.executable.identity_name()
        );
        assert!(registry.resolve_parts(&entry.instrument, kind).is_ok());
    }
    Ok(())
}

#[test]
fn partial_registry_keeps_all_declared_cases_and_marks_the_absent_entry_unavailable()
-> Result<(), String> {
    let (ready, _, fingerprints, normative_pair_digest) = ready_registry()?;
    let missing_identity = ADVERTISED_INSTRUMENTS[0].contract;
    let entries = ready
        .iter()
        .filter(|entry| entry.instrument.as_str() != missing_identity)
        .cloned()
        .collect::<Vec<_>>();
    let partial = ProviderRegistry::build(entries, ready.generation(), normative_pair_digest)
        .map_err(|error| format!("partial registry construction failed: {error:?}"))?;
    let denominator = ProviderDenominator::current(&partial)
        .map_err(|error| format!("partial denominator construction failed: {error:?}"))?;
    let ready_denominator = ProviderDenominator::current(&ready)
        .map_err(|error| format!("ready denominator construction failed: {error:?}"))?;
    let mut corpus = common_corpus(&ready, &ready_denominator, &fingerprints)?;
    {
        let missing_case = corpus
            .cases
            .iter_mut()
            .find(|case| case.instrument == missing_identity)
            .ok_or_else(|| format!("shared corpus omits {missing_identity}"))?;
        missing_case.expected_dispatchable = false;
    }
    assert_eq!(corpus.cases.len(), declared_instruments().count());
    assert!(denominator.entry(missing_identity).is_none());
    assert!(corpus.validate(&partial, &denominator).is_ok());

    let missing_case = corpus
        .cases
        .iter_mut()
        .find(|case| case.instrument == missing_identity)
        .ok_or_else(|| format!("shared corpus omits {missing_identity}"))?;
    missing_case.expected_dispatchable = true;
    assert!(matches!(
        corpus.validate(&partial, &denominator),
        Err(ConformanceError::UnavailableProvider { instrument })
            if instrument == missing_identity
    ));
    Ok(())
}

#[test]
fn corpus_rejects_equal_generation_denominator_from_another_registry() -> Result<(), String> {
    let (registry, denominator, fingerprints, normative_pair_digest) = ready_registry()?;
    let corpus = common_corpus(&registry, &denominator, &fingerprints)?;
    let mut foreign_fingerprints = fingerprints.clone();
    foreign_fingerprints.source.push_str("-foreign");
    let foreign_registry = ProviderRegistry::ready(
        registry.generation(),
        normative_pair_digest,
        &foreign_fingerprints,
    )
    .map_err(|error| format!("foreign registry construction failed: {error:?}"))?;
    let foreign_denominator = ProviderDenominator::current(&foreign_registry)
        .map_err(|error| format!("foreign denominator construction failed: {error:?}"))?;

    assert_eq!(denominator.generation(), foreign_denominator.generation());
    assert_ne!(denominator, foreign_denominator);
    assert!(matches!(
        corpus.validate(&registry, &foreign_denominator),
        Err(ConformanceError::RegistryMismatch { .. })
    ));
    Ok(())
}

#[test]
fn corpus_dispatch_expectation_tracks_the_declared_kind_availability() -> Result<(), String> {
    let (registry, denominator, fingerprints, _) = ready_registry()?;
    let mut corpus = common_corpus(&registry, &denominator, &fingerprints)?;
    let case = corpus
        .cases
        .iter_mut()
        .find(|case| case.expected_dispatchable)
        .ok_or_else(|| "ready registry has no dispatchable corpus case".to_owned())?;
    case.expected_dispatchable = false;
    assert!(matches!(
        corpus.validate(&registry, &denominator),
        Err(ConformanceError::DispatchabilityMismatch {
            expected: false,
            actual: true,
            ..
        })
    ));

    let (instrument, unsupported_kind) = ADVERTISED_INSTRUMENTS
        .iter()
        .find_map(|advertised| {
            let entry = denominator.entry(advertised.contract)?;
            let unsupported_kind = [
                InstrumentKind::Build,
                InstrumentKind::Test,
                InstrumentKind::Lint,
                InstrumentKind::Inspect,
                InstrumentKind::Verify,
                InstrumentKind::Format,
            ]
            .into_iter()
            .find(|kind| !entry.supports(*kind))?;
            Some((advertised.contract, unsupported_kind))
        })
        .ok_or_else(|| "registry has no unsupported provider kind to probe".to_owned())?;
    let case = corpus
        .cases
        .iter_mut()
        .find(|case| case.instrument == instrument)
        .ok_or_else(|| format!("shared corpus omits {instrument}"))?;
    case.expected_dispatchable = true;
    case.kind = unsupported_kind;
    assert!(matches!(
        corpus.validate(&registry, &denominator),
        Err(ConformanceError::UnavailableProvider { .. }
            | ConformanceError::DispatchabilityMismatch { actual: false, .. })
    ));
    Ok(())
}

#[test]
fn shared_corpus_rejects_empty_duplicate_unmapped_and_stale_inputs() -> Result<(), String> {
    let (registry, denominator, fingerprints, _) = ready_registry()?;
    let corpus = common_corpus(&registry, &denominator, &fingerprints)?;

    assert_corpus_rejects_empty_duplicate_and_malformed_cases(&corpus, &registry, &denominator);
    assert_corpus_rejects_missing_and_unknown_providers(&corpus, &registry, &denominator);
    assert_corpus_rejects_stale_generation_and_normative_pair(&corpus, &registry, &denominator);
    assert_corpus_rejects_stale_fingerprints(&corpus, &registry, &denominator);
    Ok(())
}

fn assert_corpus_rejects_empty_duplicate_and_malformed_cases(
    corpus: &ConformanceCorpus,
    registry: &ProviderRegistry,
    denominator: &ProviderDenominator,
) {
    let mut empty = corpus.clone();
    empty.cases.clear();
    assert_eq!(
        empty.validate(registry, denominator),
        Err(ConformanceError::InvalidText { field: "cases" })
    );

    let mut blank_corpus_id = corpus.clone();
    blank_corpus_id.corpus_id.clear();
    assert_eq!(
        blank_corpus_id.validate(registry, denominator),
        Err(ConformanceError::InvalidText { field: "corpus_id" })
    );

    let mut control_corpus_id = corpus.clone();
    control_corpus_id.corpus_id.push('\n');
    assert_eq!(
        control_corpus_id.validate(registry, denominator),
        Err(ConformanceError::InvalidText { field: "corpus_id" })
    );

    let mut blank_case = corpus.clone();
    blank_case.cases[0].case_id.clear();
    assert_eq!(
        blank_case.validate(registry, denominator),
        Err(ConformanceError::InvalidText { field: "case_id" })
    );

    let mut control_case = corpus.clone();
    control_case.cases[0].case_id.push('\n');
    assert_eq!(
        control_case.validate(registry, denominator),
        Err(ConformanceError::InvalidText { field: "case_id" })
    );

    let mut duplicate = corpus.clone();
    duplicate.cases.push(duplicate.cases[0].clone());
    assert!(matches!(
        duplicate.validate(registry, denominator),
        Err(ConformanceError::DuplicateCase { .. })
    ));
}

fn assert_corpus_rejects_missing_and_unknown_providers(
    corpus: &ConformanceCorpus,
    registry: &ProviderRegistry,
    denominator: &ProviderDenominator,
) {
    for identity in UNMAPPED_IN_PROCESS_INSTRUMENTS {
        let mut missing_unmapped = corpus.clone();
        missing_unmapped
            .cases
            .retain(|case| case.instrument != identity.contract);
        assert!(matches!(
            missing_unmapped.validate(registry, denominator),
            Err(ConformanceError::MissingProvider { instrument })
                if instrument == identity.contract
        ));
    }

    let unknown_identity = "eliot.instrument.not-declared";
    let mut unknown = corpus.clone();
    unknown.cases.push(ConformanceCase {
        case_id: unknown_identity.to_owned(),
        instrument: unknown_identity.to_owned(),
        kind: InstrumentKind::Build,
        expected_dispatchable: false,
        real_execution: false,
    });
    assert!(matches!(
        unknown.validate(registry, denominator),
        Err(ConformanceError::UnknownProvider { instrument, .. })
            if instrument == unknown_identity
    ));

    for advertised in declared_instruments() {
        let mut missing_provider = corpus.clone();
        missing_provider
            .cases
            .retain(|case| case.instrument != advertised.contract);
        assert!(matches!(
            missing_provider.validate(registry, denominator),
            Err(ConformanceError::MissingProvider { instrument })
                if instrument == advertised.contract
        ));
    }
}

fn assert_corpus_rejects_stale_generation_and_normative_pair(
    corpus: &ConformanceCorpus,
    registry: &ProviderRegistry,
    denominator: &ProviderDenominator,
) {
    let mut stale_generation = corpus.clone();
    stale_generation.generation += 1;
    assert!(matches!(
        stale_generation.validate(registry, denominator),
        Err(ConformanceError::StaleGeneration { .. })
    ));

    let mut stale_normative_pair = corpus.clone();
    stale_normative_pair
        .normative_pair_digest
        .push_str("-changed");
    assert_eq!(
        stale_normative_pair.validate(registry, denominator),
        Err(ConformanceError::StaleNormativePair)
    );
}

fn assert_corpus_rejects_stale_fingerprints(
    corpus: &ConformanceCorpus,
    registry: &ProviderRegistry,
    denominator: &ProviderDenominator,
) {
    let moved_slots: [FingerprintMutation; 7] = [
        (FingerprintField::Source, |set: &mut InvalidationSet| {
            set.source.push_str("-changed");
        }),
        (FingerprintField::Lock, |set: &mut InvalidationSet| {
            set.lock.push_str("-changed");
        }),
        (FingerprintField::Toolchain, |set: &mut InvalidationSet| {
            set.toolchain.push_str("-changed");
        }),
        (FingerprintField::Env, |set: &mut InvalidationSet| {
            set.env.push_str("-changed");
        }),
        (FingerprintField::Exe, |set: &mut InvalidationSet| {
            set.exe.push_str("-changed");
        }),
        (FingerprintField::Profile, |set: &mut InvalidationSet| {
            set.profile.push_str("-changed");
        }),
        (FingerprintField::Parser, |set: &mut InvalidationSet| {
            set.parser.push_str("-changed");
        }),
    ];
    for (expected, move_slot) in moved_slots {
        let mut stale = corpus.clone();
        move_slot(&mut stale.fingerprints);
        assert!(matches!(
            stale.validate(registry, denominator),
            Err(ConformanceError::StaleFingerprint { field }) if field == expected
        ));
    }
}

#[test]
fn provider_fixture_sets_reject_empty_blank_control_and_duplicate_case_ids() -> Result<(), String> {
    let (_, denominator, fingerprints, _) = ready_registry()?;

    for advertised in ADVERTISED_INSTRUMENTS {
        let entry = denominator.entry(advertised.contract).ok_or_else(|| {
            format!(
                "advertised provider entry {} is missing",
                advertised.contract
            )
        })?;
        let fixture = |real_cases: Vec<String>| ProviderFixtureSet {
            instrument: advertised.contract.to_owned(),
            generation: entry.generation,
            fingerprints: fingerprints.clone(),
            real_cases,
        };

        assert_eq!(
            fixture(Vec::new()).validate(entry),
            Err(ConformanceError::InvalidText {
                field: "real_cases"
            })
        );
        assert_eq!(
            fixture(vec![String::new()]).validate(entry),
            Err(ConformanceError::InvalidText { field: "real_case" })
        );
        assert_eq!(
            fixture(vec!["\n".to_owned()]).validate(entry),
            Err(ConformanceError::InvalidText { field: "real_case" })
        );
        assert!(matches!(
            fixture(vec![advertised.contract.to_owned(), advertised.contract.to_owned()])
                .validate(entry),
            Err(ConformanceError::DuplicateCase { case_id })
                if case_id == advertised.contract
        ));
    }
    Ok(())
}

#[test]
fn registry_refusals_keep_unmapped_unsupported_stale_duplicate_and_ambiguous_distinct()
-> Result<(), String> {
    let (registry, denominator, fingerprints, normative_pair_digest) = ready_registry()?;

    let unmapped = denominator
        .rows()
        .into_iter()
        .find(|row| row.entry.is_none())
        .ok_or_else(|| "declared unmapped provider is absent from the denominator".to_owned())?;
    assert_eq!(unmapped.disposition(), ProviderDisposition::Unmapped);

    let entry = denominator
        .entry(ADVERTISED_INSTRUMENTS[0].contract)
        .ok_or_else(|| "first advertised provider has no entry".to_owned())?;
    let unsupported_kind = [
        InstrumentKind::Build,
        InstrumentKind::Test,
        InstrumentKind::Verify,
        InstrumentKind::Inspect,
        InstrumentKind::Format,
    ]
    .into_iter()
    .find(|kind| !entry.supports(*kind))
    .ok_or_else(|| "entry has no unsupported instrument kind".to_owned())?;
    assert!(matches!(
        registry.resolve_parts(&entry.instrument, unsupported_kind),
        Err(RegistryError::Unsupported { .. })
    ));

    let stale_inputs = AvailabilityInputs {
        generation: registry.generation() + 1,
        normative_pair_digest: &normative_pair_digest,
        fingerprints: &fingerprints,
        platform: host_platform(),
    };
    let stale = registry.availability_parts(&entry.instrument, entry.kinds[0], &stale_inputs);
    assert!(matches!(
        stale.disposition(),
        ProviderDisposition::Stale {
            reason: StaleReason::Generation { .. }
        }
    ));

    let duplicate = ProviderRegistry::build(
        vec![entry.clone(), entry.clone()],
        registry.generation(),
        normative_pair_digest.clone(),
    );
    let Err(duplicate) = duplicate else {
        return Err("duplicate instrument/adapter pair was accepted".to_owned());
    };
    assert!(matches!(duplicate, RegistryError::Duplicate { .. }));

    let mut second_adapter = entry.clone();
    second_adapter.adapter.push_str("-second-adapter");
    let ambiguous_registry = ProviderRegistry::build(
        vec![entry.clone(), second_adapter],
        registry.generation(),
        normative_pair_digest.clone(),
    )
    .map_err(|error| format!("distinct adapter assembly failed: {error:?}"))?;
    let Err(ambiguous_error) = ambiguous_registry.resolve_parts(&entry.instrument, entry.kinds[0])
    else {
        return Err("overlapping adapters were not refused as ambiguous".to_owned());
    };
    assert!(matches!(
        &ambiguous_error,
        RegistryError::Ambiguous { candidates: 2, .. }
    ));
    let ambiguous =
        disposition_for_parts(entry.instrument.as_str(), entry.kinds[0], &ambiguous_error);
    assert!(matches!(ambiguous, ProviderDisposition::Ambiguous { .. }));

    let ready_again =
        ProviderRegistry::ready(registry.generation(), normative_pair_digest, &fingerprints)
            .map_err(|error| format!("unchanged ready path failed: {error:?}"))?;
    assert_eq!(ready_again.len(), ADVERTISED_INSTRUMENTS.len());
    Ok(())
}

#[test]
fn incomplete_or_malformed_raw_evidence_never_reports_success() {
    let evidence = [
        RawEvidence::Omitted {
            reason: OmissionReason::Truncated {
                byte_len: 0,
                limit_bytes: 1,
            },
        },
        RawEvidence::Omitted {
            reason: OmissionReason::Omitted {
                reason: "output omitted by policy or environment".to_owned(),
            },
        },
        RawEvidence::Omitted {
            reason: OmissionReason::Malformed {
                detail: "output failed well-formedness checks before parsing".to_owned(),
            },
        },
    ];

    assert_eq!(evidence[0].execution_status(), ExecutionStatus::Unknown);
    assert_eq!(evidence[1].execution_status(), ExecutionStatus::Unknown);
    assert_eq!(evidence[2].execution_status(), ExecutionStatus::Failed);
    assert!(
        evidence
            .iter()
            .all(|item| item.execution_status() != ExecutionStatus::Succeeded)
    );
}
