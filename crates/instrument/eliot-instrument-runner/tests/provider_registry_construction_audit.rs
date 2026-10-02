use eliot_instrument_api::InstrumentKind;
use eliot_instrument_nextest::NEXTEST_INSTRUMENT;
use eliot_instrument_runner::provider_denominator::ProviderDenominator;
use eliot_instrument_runner::registry::{InvalidationSet, StaleReason};
use eliot_instrument_runner::{
    AvailabilityInputs, IdentitySlot, ProviderAvailability, ProviderDisposition, ProviderRegistry,
    REQUIRED_IDENTITY_SLOTS, RegistryEntry, RegistryError, host_platform,
};

const GENERATION: u64 = 7;
const NORMATIVE_PAIR: &str = "static-description-pair";
type EntryMutation = (IdentitySlot, fn(&mut RegistryEntry));

fn fingerprints_with_empty_attestations() -> InvalidationSet {
    InvalidationSet {
        source: String::new(),
        lock: String::new(),
        toolchain: "toolchain-v1".to_owned(),
        env: "isolated-process".to_owned(),
        exe: "executable-v1".to_owned(),
        profile: "profile-v1".to_owned(),
        parser: "parser-v1".to_owned(),
    }
}

fn ready_registry() -> Result<(ProviderRegistry, InvalidationSet), String> {
    let fingerprints = fingerprints_with_empty_attestations();
    let registry = ProviderRegistry::ready(GENERATION, NORMATIVE_PAIR.to_owned(), &fingerprints)
        .map_err(|error| format!("ready registry construction failed: {error:?}"))?;
    Ok((registry, fingerprints))
}

fn nextest_entry(registry: &ProviderRegistry) -> Result<RegistryEntry, String> {
    registry
        .iter()
        .find(|entry| {
            entry.instrument.as_str() == NEXTEST_INSTRUMENT && entry.supports(InstrumentKind::Test)
        })
        .cloned()
        .ok_or_else(|| "ready registry has no nextest test entry".to_owned())
}

fn blank_identity_slot(entry: &mut RegistryEntry, slot: IdentitySlot) -> bool {
    match slot {
        IdentitySlot::Source | IdentitySlot::Lock => {}
        IdentitySlot::Toolchain => {
            entry.identities.toolchain.clear();
        }
        IdentitySlot::Executable => {
            entry.identities.executable.clear();
        }
        IdentitySlot::Features => {
            entry.identities.features.clear();
        }
        IdentitySlot::Environment => {
            entry.identities.environment.clear();
        }
        IdentitySlot::Artifact => {
            entry.identities.artifact.clear();
        }
        IdentitySlot::Fence => {
            entry.identities.fence.clear();
        }
        IdentitySlot::Operation => {
            entry.identities.operation.clear();
        }
        IdentitySlot::Timeout => {
            entry.identities.timeout.clear();
        }
        IdentitySlot::Cancellation => {
            entry.identities.cancellation.clear();
        }
        IdentitySlot::Resource => {
            entry.identities.resource.clear();
        }
    }
    !matches!(slot, IdentitySlot::Source | IdentitySlot::Lock)
}

#[test]
fn direct_build_rejects_entry_owned_identity_drift_before_registry_publication()
-> Result<(), String> {
    let (ready, _) = ready_registry()?;
    let original = nextest_entry(&ready)?;

    let mutations: [EntryMutation; 5] = [
        (IdentitySlot::Toolchain, |entry| {
            entry.toolchain.push_str("-mutated");
        }),
        (IdentitySlot::Environment, |entry| {
            entry.environment_class.push_str("-mutated");
        }),
        (IdentitySlot::Executable, |entry| {
            entry.executable.executable = Some("mutated-nextest".to_owned());
        }),
        (IdentitySlot::Resource, |entry| {
            entry.resource_contract.push_str("-mutated");
        }),
        (IdentitySlot::Cancellation, |entry| {
            entry.cancellation_contract.push_str("-mutated");
        }),
    ];

    for (slot, mutate_entry_field) in mutations {
        let mut mutated = original.clone();
        let retained_identities = mutated.identities.clone();
        let retained_invalidation = mutated.invalidation.clone();
        mutate_entry_field(&mut mutated);
        if mutated.identities != retained_identities
            || mutated.invalidation != retained_invalidation
        {
            return Err(format!(
                "{slot} drift case changed retained identity inputs"
            ));
        }

        let result = ProviderRegistry::build(vec![mutated], GENERATION, NORMATIVE_PAIR.to_owned());
        assert!(matches!(
            result,
            Err(RegistryError::IdentitySlotDrift { slot: found, .. }) if found == slot
        ));
    }
    Ok(())
}

#[test]
fn direct_build_rejects_each_required_blank_identity_slot() -> Result<(), String> {
    let (ready, _) = ready_registry()?;
    let original = nextest_entry(&ready)?;

    for slot in REQUIRED_IDENTITY_SLOTS {
        let mut entry = original.clone();
        if !blank_identity_slot(&mut entry, slot) {
            return Err(format!("required identity slot {slot} was attested-only"));
        }
        let result = ProviderRegistry::build(vec![entry], GENERATION, NORMATIVE_PAIR.to_owned());
        assert!(matches!(
            result,
            Err(RegistryError::IdentitySlotBlank { slot: found, .. }) if found == slot
        ));
    }
    Ok(())
}

#[test]
fn unchanged_ready_and_static_description_accept_empty_source_and_lock_attestations()
-> Result<(), String> {
    let (registry, fingerprints) = ready_registry()?;
    assert_eq!(registry.len(), 6);

    let nextest = nextest_entry(&registry)?;
    if !nextest.identities.source.is_empty() || !nextest.identities.lock.is_empty() {
        return Err(
            "static ready entry did not preserve empty source/lock attestations".to_owned(),
        );
    }

    let built =
        ProviderRegistry::build(vec![nextest.clone()], GENERATION, NORMATIVE_PAIR.to_owned())
            .map_err(|error| format!("unchanged entry failed direct construction: {error:?}"))?;
    let resolved = built
        .resolve_parts(&nextest.instrument, InstrumentKind::Test)
        .map_err(|error| format!("unchanged nextest entry did not resolve: {error:?}"))?;
    if resolved != &nextest {
        return Err("direct construction changed the unchanged nextest entry".to_owned());
    }

    let denominator = ProviderDenominator::current(&registry)
        .map_err(|error| format!("static description denominator failed: {error:?}"))?;
    if denominator.mapped() != 6 {
        return Err(format!(
            "static description mapped {} ready entries",
            denominator.mapped()
        ));
    }

    let inputs = AvailabilityInputs {
        generation: GENERATION,
        normative_pair_digest: NORMATIVE_PAIR,
        fingerprints: &fingerprints,
        platform: host_platform(),
    };
    match registry.availability_parts(&nextest.instrument, InstrumentKind::Test, &inputs) {
        ProviderAvailability::Ready { entry } if entry.as_ref() == &nextest => {}
        ProviderAvailability::Unavailable {
            disposition: ProviderDisposition::UnsupportedPlatform { .. },
        } => {}
        outcome => {
            return Err(format!(
                "static description returned unexpected outcome: {outcome:?}"
            ));
        }
    }
    Ok(())
}

#[test]
fn duplicate_ambiguous_unsupported_and_stale_results_remain_distinct() -> Result<(), String> {
    let (ready, _) = ready_registry()?;
    let original = nextest_entry(&ready)?;

    let duplicate = ProviderRegistry::build(
        vec![original.clone(), original.clone()],
        GENERATION,
        NORMATIVE_PAIR.to_owned(),
    );
    assert!(matches!(duplicate, Err(RegistryError::Duplicate { .. })));

    let mut second_adapter = original.clone();
    second_adapter.adapter.push_str("-second-adapter");
    let ambiguous = ProviderRegistry::build(
        vec![original.clone(), second_adapter],
        GENERATION,
        NORMATIVE_PAIR.to_owned(),
    )
    .map_err(|error| format!("distinct adapter assembly failed: {error:?}"))?;
    assert!(matches!(
        ambiguous.resolve_parts(&original.instrument, InstrumentKind::Test),
        Err(RegistryError::Ambiguous { candidates: 2, .. })
    ));

    assert!(matches!(
        ready.resolve_parts(&original.instrument, InstrumentKind::Build),
        Err(RegistryError::Unsupported {
            kind: InstrumentKind::Build,
            ..
        })
    ));

    let mut old_generation_entry = original.clone();
    old_generation_entry.generation = GENERATION - 1;
    let stale = ProviderRegistry::build(
        vec![old_generation_entry],
        GENERATION,
        NORMATIVE_PAIR.to_owned(),
    )
    .map_err(|error| format!("stale entry registry assembly failed: {error:?}"))?;
    assert!(matches!(
        stale.resolve_parts(&original.instrument, InstrumentKind::Test),
        Err(RegistryError::Stale {
            reason: StaleReason::Generation { expected, found },
            ..
        }) if expected == GENERATION && found == GENERATION - 1
    ));
    Ok(())
}
