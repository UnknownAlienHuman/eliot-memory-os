use std::{error::Error, str::FromStr};

use eliot_contracts::{ContractId, ResourceGeneration};
use eliot_protocol::{
    ELIOT_PIPE_PREFIX, EliotPipeFamily, EliotPipeName, EliotPipeNameError, EliotPipeSegment,
    EliotPipeSegmentReason, LegacyEliotPipeName, MAX_PIPE_NAME_BYTES, MAX_PIPE_SEGMENT_BYTES,
    MAX_PIPE_SUFFIX_BYTES, PIPE_NAME_CONTRACT_NAME, PIPE_NAME_UNICODE_PROFILE,
    PIPE_NAME_WIRE_REVISION, pipe_name_contract_identity,
};
use serde_json::Value;

#[test]
fn formats_the_closed_current_family_catalogue() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        EliotPipeName::kernel_frontdoor().to_string(),
        r"\\.\pipe\eliot\kernel\frontdoor"
    );
    assert_eq!(
        EliotPipeName::kernel_store().to_string(),
        r"\\.\pipe\eliot\kernel\store"
    );
    assert_eq!(
        EliotPipeName::kernel_daemon(ResourceGeneration::new(7)?)?.to_string(),
        r"\\.\pipe\eliot\kernel\daemon\7"
    );
    assert_eq!(
        EliotPipeName::module(
            ContractId::new("agent.bridge_with_under-score")?,
            ResourceGeneration::new(3)?,
        )?
        .to_string(),
        r"\\.\pipe\eliot\module\agent.bridge_with_under-score\3"
    );
    assert_eq!(
        EliotPipeName::watchdog_signals().to_string(),
        r"\\.\pipe\eliot\watchdog\signals"
    );
    Ok(())
}

#[test]
fn typed_names_roundtrip_through_parse_and_json() -> Result<(), Box<dyn Error>> {
    let source = EliotPipeName::module(
        ContractId::new("agent.bridge_with_under-score")?,
        ResourceGeneration::new(3)?,
    )?;
    let encoded = serde_json::to_string(&source)?;
    let wire: Value = serde_json::from_str(&encoded)?;
    assert_eq!(wire["revision"], "v1");
    assert_eq!(wire["name"], source.to_string());
    let decoded: EliotPipeName = serde_json::from_str(&encoded)?;
    assert_eq!(decoded, source);
    assert_eq!(EliotPipeName::from_str(&source.to_string())?, source);
    assert_eq!(
        decoded
            .module_id()
            .ok_or_else(|| std::io::Error::other("module id missing"))?
            .as_str(),
        "agent.bridge_with_under-score"
    );
    assert_eq!(
        decoded
            .generation()
            .ok_or_else(|| std::io::Error::other("generation missing"))?
            .value(),
        3
    );
    assert!(
        serde_json::from_str::<EliotPipeName>(
            r#"{"revision":"v2","name":"\\\\.\\pipe\\eliot\\module\\agent-bridge\\3"}"#
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn canonical_bytes_and_digest_are_deterministic_and_injective() -> Result<(), Box<dyn Error>> {
    let first = EliotPipeName::kernel_daemon(ResourceGeneration::new(1)?)?;
    let second = EliotPipeName::kernel_daemon(ResourceGeneration::new(2)?)?;
    assert_eq!(first.canonical_bytes(), first.to_string().as_bytes());
    assert_eq!(first.canonical_digest(), first.canonical_digest());
    assert_ne!(first.canonical_digest(), second.canonical_digest());
    assert_ne!(first, second);
    Ok(())
}

#[test]
fn malformed_prefix_family_segments_and_generations_fail_closed() -> Result<(), Box<dyn Error>> {
    for value in [
        r"\\.\pipe\eliot\kernel\frontdoor\",
        r"\\.\pipe\eliot\kernel/frontdoor",
        r"\\.\pipe\eliot\kernel\daemon\0",
        r"\\.\pipe\eliot\kernel\daemon\01",
        r"\\.\pipe\eliot\kernel\daemon\+1",
        r"\\.\pipe\eliot\module\Agent-Bridge\1",
        r"\\.\pipe\eliot\module\agent:bridge\1",
        r"\\.\pipe\eliot\..\other",
        r"\\.\pipe\eliot-governor-0123456789abcdef0123",
        r"\\.\pipe\eliotx\kernel\frontdoor",
    ] {
        assert!(EliotPipeName::parse(value).is_err(), "accepted {value}");
    }
    assert!(matches!(
        EliotPipeName::parse(r"\\.\pipe\eliot\kernel\frontdoor"),
        Ok(name) if name.family() == EliotPipeFamily::Kernel
    ));
    let module_id = ContractId::new("agent.bridge")?;
    assert!(EliotPipeName::module(module_id, ResourceGeneration::default()).is_err());
    Ok(())
}

#[test]
fn bounds_and_legacy_boundary_are_explicit() -> Result<(), Box<dyn Error>> {
    let oversized = format!("{ELIOT_PIPE_PREFIX}module\\{}\\1", "a".repeat(240));
    assert!(matches!(
        EliotPipeName::parse(&oversized),
        Err(EliotPipeNameError::NameTooLong {
            maximum: MAX_PIPE_NAME_BYTES,
            ..
        })
    ));
    let too_long_module = ContractId::new("a".repeat(240))?;
    assert!(EliotPipeName::module(too_long_module, ResourceGeneration::new(1)?).is_err());
    let bounded_module = ContractId::new("a".repeat(220))?;
    let bounded = EliotPipeName::module(bounded_module, ResourceGeneration::new(1)?)?;
    assert_eq!(EliotPipeName::parse(&bounded.to_string())?, bounded);

    let legacy = LegacyEliotPipeName::parse(r"\\.\pipe\eliot-governor-0123456789abcdef0123")?;
    assert_eq!(legacy.digest_prefix(), "0123456789abcdef0123");
    assert!(matches!(
        legacy.map_to_current(),
        Err(EliotPipeNameError::LegacyMappingUnavailable)
    ));
    assert!(matches!(
        LegacyEliotPipeName::parse(r"\\.\pipe\eliot-governor-not-a-digest"),
        Err(EliotPipeNameError::LegacyUnsupported)
    ));
    Ok(())
}

#[test]
fn reserved_device_unicode_and_trailing_names_are_refused() -> Result<(), Box<dyn Error>> {
    assert_eq!(PIPE_NAME_UNICODE_PROFILE, "ascii-lowercase-v1");
    assert_eq!(PIPE_NAME_WIRE_REVISION, "v1");

    let fixture: Value = serde_json::from_str(include_str!("data/pipe-name/rejections.json"))?;
    assert_eq!(fixture["profile"], PIPE_NAME_UNICODE_PROFILE);
    let cases = fixture["cases"]
        .as_array()
        .ok_or_else(|| std::io::Error::other("rejections fixture must list cases"))?;
    assert!(!cases.is_empty(), "rejections fixture must not be empty");

    for case in cases {
        let module_id = case["module_id"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("rejection case needs module_id"))?;
        let generation = case["generation"]
            .as_u64()
            .ok_or_else(|| std::io::Error::other("rejection case needs generation"))?;
        let expected = case["reason"]
            .as_str()
            .ok_or_else(|| std::io::Error::other("rejection case needs reason"))?;
        let name = format!("{ELIOT_PIPE_PREFIX}module\\{module_id}\\{generation}");
        // Panic-free bounded refusal through both the parser and the owner type.
        let parsed = EliotPipeName::parse(&name);
        let segmented = EliotPipeSegment::new(module_id);
        assert!(parsed.is_err(), "accepted refused fixture {name}");
        assert!(segmented.is_err(), "accepted refused segment {module_id}");
        let reason = match segmented {
            Err(EliotPipeNameError::InvalidSegment { reason, .. }) => reason,
            other => {
                panic!("segment refusal for {module_id} must be InvalidSegment, got {other:?}")
            }
        };
        let actual = match reason {
            EliotPipeSegmentReason::ReservedDevice => "ReservedDevice",
            EliotPipeSegmentReason::NonCanonical => "NonCanonical",
            EliotPipeSegmentReason::DotSegment => "DotSegment",
            EliotPipeSegmentReason::Whitespace => "Whitespace",
            other => panic!("unexpected segment reason for {module_id}: {other:?}"),
        };
        assert_eq!(actual, expected, "wrong refusal class for {module_id}");
    }

    // Exact diagnostics for the headline classes (field/offset/reason only).
    assert!(matches!(
        EliotPipeName::parse(r"\\.\pipe\eliot\module\con\1"),
        Err(EliotPipeNameError::InvalidSegment {
            field: "module_id",
            reason: EliotPipeSegmentReason::ReservedDevice,
            ..
        })
    ));
    assert!(matches!(
        EliotPipeSegment::new("CON"),
        Err(EliotPipeNameError::InvalidSegment {
            reason: EliotPipeSegmentReason::ReservedDevice,
            ..
        })
    ));
    assert!(matches!(
        EliotPipeSegment::new("com1"),
        Err(EliotPipeNameError::InvalidSegment {
            reason: EliotPipeSegmentReason::ReservedDevice,
            ..
        })
    ));
    assert!(matches!(
        EliotPipeSegment::new("еliot"),
        Err(EliotPipeNameError::InvalidSegment {
            reason: EliotPipeSegmentReason::NonCanonical,
            ..
        })
    ));
    assert!(matches!(
        EliotPipeSegment::new("agent."),
        Err(EliotPipeNameError::InvalidSegment {
            reason: EliotPipeSegmentReason::DotSegment,
            ..
        })
    ));
    assert!(matches!(
        EliotPipeSegment::new("agent bridge"),
        Err(EliotPipeNameError::InvalidSegment {
            reason: EliotPipeSegmentReason::Whitespace,
            ..
        })
    ));
    Ok(())
}

#[test]
fn segment_boundary_and_owner_segment_wiring() -> Result<(), Box<dyn Error>> {
    let fixture: Value = serde_json::from_str(include_str!("data/pipe-name/boundaries.json"))?;
    assert_eq!(fixture["unicode_profile"], PIPE_NAME_UNICODE_PROFILE);
    assert_eq!(
        fixture["max_suffix_bytes"].as_u64(),
        Some(MAX_PIPE_SUFFIX_BYTES as u64)
    );
    assert_eq!(
        fixture["max_name_bytes"].as_u64(),
        Some(MAX_PIPE_NAME_BYTES as u64)
    );
    assert_eq!(
        fixture["max_segment_bytes"].as_u64(),
        Some(MAX_PIPE_SEGMENT_BYTES as u64)
    );

    // Per-segment bound is a distinct overflow class from the full-name bound.
    let at_segment_max = "a".repeat(MAX_PIPE_SEGMENT_BYTES);
    assert_eq!(
        EliotPipeSegment::new(at_segment_max.clone())?.as_str(),
        at_segment_max
    );
    let one_over_segment = "a".repeat(MAX_PIPE_SEGMENT_BYTES + 1);
    assert!(matches!(
        EliotPipeSegment::new(one_over_segment),
        Err(EliotPipeNameError::InvalidSegment {
            reason: EliotPipeSegmentReason::TooLong,
            ..
        })
    ));
    let segment_overflow_id = ContractId::new("a".repeat(MAX_PIPE_SEGMENT_BYTES + 1))?;
    assert!(matches!(
        EliotPipeName::module(segment_overflow_id, ResourceGeneration::new(1)?),
        Err(EliotPipeNameError::InvalidSegment {
            field: "module_id",
            reason: EliotPipeSegmentReason::TooLong,
            ..
        })
    ));

    // Full-name one-over with a segment-valid id stays NameTooLong.
    let full_overflow_len = usize::try_from(
        fixture["full_name_one_over_module_len"]
            .as_u64()
            .ok_or_else(|| {
                std::io::Error::other("boundaries fixture needs full_name_one_over_module_len")
            })?,
    )
    .map_err(|_| std::io::Error::other("boundaries fixture length out of range"))?;
    let full_overflow_id = ContractId::new("a".repeat(full_overflow_len))?;
    assert!(full_overflow_len <= MAX_PIPE_SEGMENT_BYTES);
    assert!(matches!(
        EliotPipeName::module(full_overflow_id, ResourceGeneration::new(1)?),
        Err(EliotPipeNameError::NameTooLong { .. })
    ));

    // The orphan segment type is wired into the module path.
    let wired = EliotPipeName::module(
        ContractId::new("agent.bridge")?,
        ResourceGeneration::new(3)?,
    )?;
    assert_eq!(
        wired.module_segment().map(EliotPipeSegment::as_str),
        Some("agent.bridge")
    );
    assert_eq!(
        wired.module_id().map(ContractId::as_str),
        Some("agent.bridge")
    );
    assert_eq!(
        wired.module_segment().map(ToString::to_string),
        wired.module_id().map(ToString::to_string)
    );
    let segment = EliotPipeSegment::new("agent.bridge")?;
    assert_eq!(segment.to_string(), "agent.bridge");
    let encoded = serde_json::to_string(&segment)?;
    assert_eq!(
        serde_json::from_str::<EliotPipeSegment>(&encoded)?.as_str(),
        "agent.bridge"
    );
    assert_eq!(
        EliotPipeSegment::try_from("agent.bridge".to_owned())?.as_str(),
        "agent.bridge"
    );
    assert!(wired.module_segment().is_some());
    assert!(EliotPipeName::kernel_frontdoor().module_segment().is_none());

    // Contract identity is stable and versioned without touching v1 wire bytes.
    let first = pipe_name_contract_identity()?;
    let second = pipe_name_contract_identity()?;
    assert_eq!(first, second);
    assert_eq!(first.name.as_str(), PIPE_NAME_CONTRACT_NAME);
    assert_eq!(
        first.version,
        eliot_contracts::ContractVersion::new(1, 0, 0)
    );
    first.validate()?;
    Ok(())
}
