#![allow(clippy::expect_used)]

use std::num::NonZeroU64;

use eliot_contracts::{
    ClockReading, ContractVersion, EpochId, EpochLineageId, ResourceGeneration, StateFence,
    canonical_json_bytes, sha256_hex,
};
use eliot_research_exchange_api::{
    AllowedReferenceManifest, AnchorPrecision, BridgeResourceFamily, CONTRACT_NAME,
    CONTRACT_VERSION, CompletionDisposition, DisclosureClass, ExactCitation,
    InternalLocatorIdentity, LOCATOR_CLASSIFIER, LocatorAmbiguity, LocatorClass, MAX_LOCATOR_BYTES,
    ResearchClaim, ResearchContractError, ResearchEvidenceBundle, ResearchQueryRequest,
    SourceClass, SourceSnapshot, classify_locator,
};

const SOURCE_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const BUNDLE_DIGEST: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn fence(sequence: u64) -> StateFence {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
        .expect("canonical test lineage");
    let epoch = EpochId::new(
        lineage,
        NonZeroU64::new(sequence).expect("non-zero test sequence"),
    )
    .expect("valid test epoch");
    StateFence::new(epoch, ResourceGeneration::genesis())
}

fn manifest(
    state_fence: &StateFence,
    url_handles: &[&str],
    stale_or_revoked_handles: &[&str],
) -> AllowedReferenceManifest {
    AllowedReferenceManifest {
        run_id: "run-2894".to_owned(),
        root_context_revision: "root-2894".to_owned(),
        state_fence: state_fence.clone(),
        source_handles: vec!["src-a".to_owned()],
        evidence_handles: Vec::new(),
        artifact_handles: Vec::new(),
        url_handles: url_handles
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        tool_refs: Vec::new(),
        verifier_refs: Vec::new(),
        allowed_anchor_precision: AnchorPrecision::Section,
        scope_class: "bounded source review".to_owned(),
        disclosure: DisclosureClass::ProjectBound,
        retention_class: "governed-by-caller".to_owned(),
        stale_or_revoked_handles: stale_or_revoked_handles
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        expansion_routes: Vec::new(),
        digest: String::new(),
    }
    .seal()
    .expect("fixture manifest seals")
}

fn request_with_manifest(
    allowed_references: AllowedReferenceManifest,
    state_fence: StateFence,
) -> ResearchQueryRequest {
    ResearchQueryRequest {
        exchange_id: "exchange-2894".to_owned(),
        protocol_revision: ContractVersion::new(1, 0, 0),
        bridge_generation: "bridge-2894".to_owned(),
        idempotency_key: "locator-firewall-2894".to_owned(),
        requester_principal: "reviewer-2894".to_owned(),
        state_fence,
        question: "which admitted source supports this result".to_owned(),
        question_scope: "bounded source review".to_owned(),
        expected_decision: "source admission".to_owned(),
        source_classes: vec![SourceClass::Documentation],
        coverage_goal: "one exact admitted source".to_owned(),
        allowed_references,
        disclosure: DisclosureClass::ProjectBound,
        retention: "governed-by-caller".to_owned(),
        license_policy: "caller-policy".to_owned(),
        budget_units: 1,
        deadline_ms: 1_800_000_000_000,
        required_schema: "research-evidence-bundle/v1".to_owned(),
        predecessor_freeze_digest: None,
        reopen_reason: None,
    }
}

fn request(url_handles: &[&str], stale_or_revoked_handles: &[&str]) -> ResearchQueryRequest {
    let state_fence = fence(7);
    request_with_manifest(
        manifest(&state_fence, url_handles, stale_or_revoked_handles),
        state_fence,
    )
}

fn source_snapshot(locator: &str, source_handle: &str) -> SourceSnapshot {
    SourceSnapshot {
        source_handle: source_handle.to_owned(),
        class: SourceClass::Documentation,
        title: "fixture source".to_owned(),
        locator: locator.to_owned(),
        snapshot_digest: SOURCE_DIGEST.to_owned(),
        captured_at: ClockReading {
            valid_time_ms: Some(1_700_000_000_000),
            known_time_ms: Some(1_700_000_100_000),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        coverage: "covers the requested source claim".to_owned(),
        disclosure: DisclosureClass::ProjectBound,
    }
}

fn bundle(locator: &str, state_fence: StateFence) -> ResearchEvidenceBundle {
    ResearchEvidenceBundle {
        exchange_id: "exchange-2894".to_owned(),
        job_id: "job-2894".to_owned(),
        system_generation: "bridge-2894".to_owned(),
        immutable_bundle_digest: BUNDLE_DIGEST.to_owned(),
        origin_authentication: "fixture-provider-edge".to_owned(),
        state_fence,
        sources: vec![source_snapshot(locator, "src-a")],
        claims: vec![ResearchClaim {
            claim_id: "claim-2894".to_owned(),
            statement: "the fixture source supports the claim".to_owned(),
            citations: vec![ExactCitation {
                source_handle: "src-a".to_owned(),
                anchor: "section-2".to_owned(),
                precision: AnchorPrecision::Section,
                excerpt: Some("the exact supporting excerpt".to_owned()),
            }],
            counterclaim_ids: Vec::new(),
            confidence_note: "bounded fixture claim".to_owned(),
        }],
        bounded_excerpts: vec!["the exact supporting excerpt".to_owned()],
        artifact_handles: Vec::new(),
        coverage_unknowns: Vec::new(),
        failed_acquisition: Vec::new(),
        coverage_gaps: Vec::new(),
        disposition: CompletionDisposition::AnsweredWithSupportedResult,
        synthesis_is_candidate: true,
        disclosure: DisclosureClass::ProjectBound,
        invalidation: None,
    }
}

fn assert_external_locator_denied(locator: &str) {
    assert_eq!(
        classify_locator(locator),
        LocatorClass::ExternalUri {
            exact_original: locator.to_owned(),
        },
        "locator did not reach the expected exact URL admission branch: {locator:?}"
    );

    let request = request(&[], &[]);
    request
        .validate()
        .expect("sealed empty-URL manifest is valid");
    assert!(matches!(
        bundle(locator, request.state_fence.clone()).validate_against(&request),
        Err(ResearchContractError::UrlNotAdmitted)
    ));
}

fn assert_unclassifiable(locator: &str, expected: LocatorAmbiguity) {
    assert_eq!(
        classify_locator(locator),
        LocatorClass::MalformedOrAmbiguous { reason: expected },
        "unexpected closed classification for {locator:?}"
    );

    let request = request(&[], &[]);
    request
        .validate()
        .expect("sealed empty-URL manifest is valid");
    assert!(matches!(
        bundle(locator, request.state_fence.clone()).validate_against(&request),
        Err(ResearchContractError::LocatorNotClassifiable { reason })
            if reason == expected.wire_name()
    ));
}

#[test]
fn external_locator_schemes_reach_empty_manifest_url_refusal() {
    for locator in [
        "https://attacker.example/a",
        "urn:doi:10.1000/182",
        "mailto:reader@example.test",
        "data:text/plain,untrusted",
        "file:///source/snapshot.txt",
        "ws://example.test/socket",
        "tcp://example.test:7443",
        "future+unknown:opaque-value",
        r"C:\Users\reviewer\source.txt",
        "https://example.test/café",
    ] {
        assert_external_locator_denied(locator);
    }
}

#[test]
fn exact_url_admission_requires_current_seal_fence_and_unrevoked_spelling() {
    let exact_url = "https://research.example/source?revision=7";
    let admitted_request = request(&[exact_url], &[]);
    admitted_request
        .validate()
        .expect("exact URL is in the sealed manifest");
    bundle(exact_url, admitted_request.state_fence.clone())
        .validate_against(&admitted_request)
        .expect("exact admitted locator validates at the real bundle boundary");

    for changed_spelling in [
        "HTTPS://research.example/source?revision=7",
        "https://research.example/Source?revision=7",
    ] {
        assert_eq!(
            bundle(changed_spelling, admitted_request.state_fence.clone())
                .validate_against(&admitted_request),
            Err(ResearchContractError::UrlNotAdmitted)
        );
    }

    let revoked = request(&[exact_url], &[exact_url]);
    revoked
        .validate()
        .expect("overlapping admitted/revoked entries are a valid sealed refusal");
    assert_eq!(
        bundle(exact_url, revoked.state_fence.clone()).validate_against(&revoked),
        Err(ResearchContractError::UrlNotAdmitted)
    );

    let wrong_bundle_fence = bundle(exact_url, fence(8));
    assert_eq!(
        wrong_bundle_fence.validate_against(&admitted_request),
        Err(ResearchContractError::InvalidDisposition)
    );
    let mut wrong_request_fence = admitted_request.clone();
    wrong_request_fence.state_fence = fence(8);
    assert_eq!(
        wrong_request_fence.validate(),
        Err(ResearchContractError::FieldNotAccepted {
            field: "allowed_references.state_fence",
        })
    );

    let mut widened_after_seal = admitted_request.clone();
    widened_after_seal
        .allowed_references
        .url_handles
        .push("https://research.example/other".to_owned());
    assert_eq!(
        widened_after_seal.validate(),
        Err(ResearchContractError::InvalidDigest {
            field: "manifest.digest",
        })
    );
}

fn digest_under_classifier(manifest: &AllowedReferenceManifest, classifier: &str) -> String {
    let mut digest_shape = manifest.clone();
    digest_shape.digest.clear();
    let mut preimage = format!(
        "{CONTRACT_NAME}/allowed-reference-manifest/v{CONTRACT_VERSION};\
         locator-classifier={classifier};"
    )
    .into_bytes();
    preimage
        .extend(canonical_json_bytes(&digest_shape).expect("canonical manifest digest preimage"));
    sha256_hex(&preimage)
}

#[test]
fn legacy_classifier_digest_cannot_reverify_under_current_locator_semantics() {
    assert_eq!(LOCATOR_CLASSIFIER, "absolute-locator/3");
    let exact_url = "https://research.example/source?revision=7";
    let mut legacy_request = request(&[exact_url], &[]);
    legacy_request.allowed_references.digest =
        digest_under_classifier(&legacy_request.allowed_references, "absolute-locator/2");

    assert_eq!(
        legacy_request.validate(),
        Err(ResearchContractError::InvalidDigest {
            field: "manifest.digest",
        })
    );
}

#[test]
fn internal_and_namespaced_locators_remain_distinct_from_source_admission() {
    let canonical_internal = "eliot://task/t-1/packet/r-7";
    assert_eq!(
        classify_locator(canonical_internal),
        LocatorClass::InternalUri {
            canonical_scheme: "eliot".to_owned(),
            parsed_identity: InternalLocatorIdentity::BridgeResource {
                family: BridgeResourceFamily::TaskPacket,
                revision: Some("r-7".to_owned()),
            },
        }
    );

    let source_only_request = request(&[], &[]);
    source_only_request
        .validate()
        .expect("sealed source-only manifest is valid");
    bundle(canonical_internal, source_only_request.state_fence.clone())
        .validate_against(&source_only_request)
        .expect("canonical internal URI needs no URL handle");

    let mut unadmitted_source = bundle(canonical_internal, source_only_request.state_fence.clone());
    unadmitted_source.sources[0].source_handle = "src-unlisted".to_owned();
    assert_eq!(
        unadmitted_source.validate_against(&source_only_request),
        Err(ResearchContractError::ReferenceNotAdmitted)
    );

    let url_listed_internal = request(&[canonical_internal], &[]);
    url_listed_internal
        .validate()
        .expect("fixture URL entry is sealed, though it is not a source identity");
    let mut internal_used_as_unadmitted_source =
        bundle(canonical_internal, url_listed_internal.state_fence.clone());
    internal_used_as_unadmitted_source.sources[0].source_handle = canonical_internal.to_owned();
    assert_eq!(
        internal_used_as_unadmitted_source.validate_against(&url_listed_internal),
        Err(ResearchContractError::ReferenceNotAdmitted)
    );

    assert_eq!(
        classify_locator("snapshot::src-a"),
        LocatorClass::OpaqueHandle
    );
    bundle("snapshot::src-a", source_only_request.state_fence.clone())
        .validate_against(&source_only_request)
        .expect("well-formed namespaced handle remains opaque");
    assert_unclassifiable(
        "snapshot::",
        LocatorAmbiguity::MalformedNamespacedHandleEmptyIdentifier,
    );
    assert_unclassifiable(
        "snapshot::..",
        LocatorAmbiguity::MalformedNamespacedHandleRelativeSegment,
    );
    assert_unclassifiable(
        "1snapshot::src-a",
        LocatorAmbiguity::MalformedNamespacedHandleNonPortableSegment,
    );
    assert_unclassifiable("urn:", LocatorAmbiguity::EmptyAfterSchemeSeparator);
    assert_unclassifiable("C:", LocatorAmbiguity::EmptyAfterSchemeSeparator);
}

#[test]
fn control_unicode_and_byte_length_follow_the_closed_classifier_contract() {
    assert_unclassifiable("snapshot::src\u{001f}a", LocatorAmbiguity::ControlCharacter);
    assert_unclassifiable(
        "snapshot::naïve",
        LocatorAmbiguity::MalformedNamespacedHandleNonPortableSegment,
    );

    let at_bound = "x".repeat(MAX_LOCATOR_BYTES);
    assert_eq!(classify_locator(&at_bound), LocatorClass::OpaqueHandle);
    let empty_request = request(&[], &[]);
    empty_request
        .validate()
        .expect("sealed source-only manifest is valid");
    bundle(&at_bound, empty_request.state_fence.clone())
        .validate_against(&empty_request)
        .expect("the declared maximum byte length is accepted");

    let over_bound = "x".repeat(MAX_LOCATOR_BYTES + 1);
    assert_unclassifiable(&over_bound, LocatorAmbiguity::Oversized);
}
