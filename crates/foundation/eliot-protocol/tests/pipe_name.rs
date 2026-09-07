use std::{error::Error, str::FromStr};

use eliot_contracts::{ContractId, ResourceGeneration};
use eliot_protocol::{
    ELIOT_PIPE_PREFIX, EliotPipeFamily, EliotPipeName, EliotPipeNameError, LegacyEliotPipeName,
    MAX_PIPE_NAME_BYTES,
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
