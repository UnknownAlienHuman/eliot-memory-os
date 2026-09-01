#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
#![allow(clippy::manual_string_new)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::items_after_statements)]

use eliot_store_api::{
    CommitId, EventId, OperationManifestDigest, OrderingScopeId, OutboxId, ProjectionPublicationId,
    RevisionKey, ScopeId,
};
use serde::{Deserialize, Serialize};

fn malformed_samples() -> Vec<String> {
    vec![
        "".to_owned(),           // blank
        "   ".to_owned(),        // whitespace-only spaces
        "\t".to_owned(),         // whitespace-only tab
        " \t\n ".to_owned(),     // whitespace-only mixed
        " leading".to_owned(),   // leading whitespace
        "trailing ".to_owned(),  // trailing whitespace
        " both ".to_owned(),     // leading+trailing
        "\tleading".to_owned(),  // leading tab
        "trailing\t".to_owned(), // trailing tab
        "a\u{0000}b".to_owned(), // null control
        "a\u{0001}b".to_owned(), // control U+0001
        "a\nb".to_owned(),       // newline control
        "a\rb".to_owned(),       // carriage return
        "a\tb".to_owned(),       // tab inside (control)
        "a\u{001F}b".to_owned(), // unit separator control
        "a\u{007F}b".to_owned(), // DEL control
    ]
}

fn valid_samples() -> Vec<&'static str> {
    vec![
        "scope-1",
        "revision-key-1",
        "ordering-scope-1",
        "operation-manifest-digest-1",
        "commit-1",
        "event-1",
        "projection-publication-1",
        "outbox-1",
        "a",
        "A1-_-.valid",
        "123",
        "x".repeat(64).leak(), // long valid
    ]
}

// Generic helpers for direct deserialization checks.
fn assert_direct_rejects<T>(samples: &[String])
where
    T: for<'de> Deserialize<'de> + std::fmt::Debug,
{
    for sample in samples {
        let json = serde_json::to_string(sample).unwrap();
        let result: Result<T, _> = serde_json::from_str(&json);
        assert!(
            result.is_err(),
            "direct deserialize should reject {:?} but got {:?}",
            sample,
            result.unwrap()
        );
    }
}

fn assert_nested_rejects<T>(samples: &[String])
where
    T: for<'de> Deserialize<'de> + Serialize + std::fmt::Debug,
{
    #[derive(Serialize, Deserialize, Debug)]
    struct Wrapper<T> {
        value: T,
    }
    for sample in samples {
        let json = serde_json::to_string(sample).unwrap();
        let wrapper_json = format!(r#"{{"value":{}}}"#, json);
        let result: Result<Wrapper<T>, _> = serde_json::from_str(&wrapper_json);
        assert!(
            result.is_err(),
            "nested deserialize should reject {:?} but got {:?} wrapper_json={}",
            sample,
            result.unwrap().value,
            wrapper_json
        );
    }
}

fn _assert_direct_round_trip<T>(value: &str)
where
    T: for<'de> Deserialize<'de> + Serialize + PartialEq + std::fmt::Debug,
    T: TryFrom<String>,
    <T as TryFrom<String>>::Error: std::fmt::Debug,
{
    // Construct via new-equivalent (via TryFrom or direct new). We use serde round trip plus new.
    let json = serde_json::to_string(value).unwrap();
    // Direct deserialize
    let decoded: T = serde_json::from_str(&json).unwrap();
    // Serialize again should be byte-identical JSON string
    let reencoded = serde_json::to_string(&decoded).unwrap();
    assert_eq!(
        json, reencoded,
        "direct round trip bytes differ for {:?}",
        value
    );
    // Direct bytes check: canonical JSON bytes for a string is quoted string
    assert_eq!(json, format!("\"{}\"", value));
}

fn _assert_nested_round_trip<T>(value: &str)
where
    T: for<'de> Deserialize<'de> + Serialize + PartialEq + std::fmt::Debug,
{
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct Wrapper<T> {
        value: T,
    }
    let json = serde_json::to_string(value).unwrap();
    let decoded: T = serde_json::from_str(&json).unwrap();
    let wrapper = Wrapper { value: decoded };
    let wrapper_json = serde_json::to_string(&wrapper).unwrap();
    let decoded_wrapper: Wrapper<T> = serde_json::from_str(&wrapper_json).unwrap();
    assert_eq!(wrapper, decoded_wrapper);
    // Byte compatibility: wrapper JSON should contain exact inner string bytes
    let expected = format!(r#"{{"value":"{}"}}"#, value);
    assert_eq!(wrapper_json, expected);
}

macro_rules! define_opaque_id_tests {
    ($($ty:ty => $valid:expr),* $(,)?) => {
        #[test]
        fn direct_malformed_are_rejected() {
            let samples = malformed_samples();
            $(
                {
                    // Scope the type to ensure each is tested
                    assert_direct_rejects::<$ty>(&samples);
                }
            )*
        }

        #[test]
        fn nested_malformed_are_rejected() {
            let samples = malformed_samples();
            $(
                {
                    assert_nested_rejects::<$ty>(&samples);
                }
            )*
        }

        #[test]
        fn direct_valid_round_trips_are_byte_compatible() {
            $(
                {
                    let v = $valid;
                    // Verify new() succeeds
                    let json = serde_json::to_string(v).unwrap();
                    let decoded: $ty = serde_json::from_str(&json).unwrap();
                    let reencoded = serde_json::to_string(&decoded).unwrap();
                    assert_eq!(json, reencoded, "direct byte mismatch for {} {:?}", stringify!($ty), v);
                    // Also test that decoded debug matches expected
                    // Ensure serde preserves exact bytes (no trimming)
                    assert_eq!(decoded, {
                        let rt: $ty = serde_json::from_str(&format!("\"{}\"", v)).unwrap();
                        rt
                    });
                }
            )*
            // Also test generic valid samples for each type where applicable (using a shared valid token)
            for valid in valid_samples() {
                $(
                    {
                        // Only test with a token that is valid for all; our valid_samples are all valid IDs
                        let json = serde_json::to_string(valid).unwrap();
                        let result: Result<$ty, _> = serde_json::from_str(&json);
                        assert!(result.is_ok(), "valid {:?} should succeed for {}", valid, stringify!($ty));
                        let decoded = result.unwrap();
                        let reencoded = serde_json::to_string(&decoded).unwrap();
                        assert_eq!(json, reencoded);
                    }
                )*
            }
        }

        #[test]
        fn nested_valid_round_trips_are_byte_compatible() {
            $(
                {
                    let v = $valid;
                    #[derive(Serialize, Deserialize, Debug, PartialEq)]
                    struct Wrapper {
                        value: $ty,
                    }
                    let wrapper = Wrapper { value: {
                        let json = serde_json::to_string(v).unwrap();
                        serde_json::from_str::<$ty>(&json).unwrap()
                    }};
                    let wrapper_json = serde_json::to_string(&wrapper).unwrap();
                    let decoded: Wrapper = serde_json::from_str(&wrapper_json).unwrap();
                    assert_eq!(wrapper, decoded);
                    let expected = format!(r#"{{"value":"{}"}}"#, v);
                    assert_eq!(wrapper_json, expected);
                }
            )*
            for valid in valid_samples() {
                $(
                    {
                        #[derive(Serialize, Deserialize, Debug, PartialEq)]
                        struct W {
                            value: $ty,
                        }
                        let json = serde_json::to_string(valid).unwrap();
                        let inner: $ty = serde_json::from_str(&json).unwrap();
                        let w = W { value: inner };
                        let w_json = serde_json::to_string(&w).unwrap();
                        let decoded: W = serde_json::from_str(&w_json).unwrap();
                        assert_eq!(w, decoded);
                        let expected = format!(r#"{{"value":"{}"}}"#, valid);
                        assert_eq!(w_json, expected);
                    }
                )*
            }
        }

        #[test]
        fn new_and_deserialize_agree_on_valid_and_malformed() {
            let malformed = malformed_samples();
            $(
                {
                    for sample in &malformed {
                        // new() should reject
                        // Use a helper to call new via string
                        let new_result = {
                            // Each type has `new` taking Into<String>
                            <$ty>::new(sample.clone()).is_err()
                        };
                        assert!(new_result, "new() should reject {:?} for {}", sample, stringify!($ty));
                        // deserialize should also reject
                        let json = serde_json::to_string(sample).unwrap();
                        let de: Result<$ty, _> = serde_json::from_str(&json);
                        assert!(de.is_err(), "deserialize should reject {:?} for {}", sample, stringify!($ty));
                    }
                    for valid in valid_samples() {
                        let new_ok = <$ty>::new(valid.clone()).is_ok();
                        assert!(new_ok, "new() should accept {:?} for {}", valid, stringify!($ty));
                        let json = serde_json::to_string(valid).unwrap();
                        let de: Result<$ty, _> = serde_json::from_str(&json);
                        assert!(de.is_ok(), "deserialize should accept {:?} for {}", valid, stringify!($ty));
                    }
                }
            )*
        }
    };
}

define_opaque_id_tests! {
    ScopeId => "scope-1",
    RevisionKey => "revision-key-1",
    OrderingScopeId => "ordering-scope-1",
    OperationManifestDigest => "operation-manifest-digest-1",
    CommitId => "commit-1",
    EventId => "event-1",
    ProjectionPublicationId => "projection-publication-1",
    OutboxId => "outbox-1",
}

#[test]
fn store_wire_nested_structs_reject_malformed_ids() {
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration};
    use eliot_store_api::{OrderingHead, RevisionHead, ScopeRevisionView, StateFence};

    let fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
    // Build a valid RevisionHead and try to deserialize with malformed RevisionKey via JSON
    let malformed = malformed_samples();
    for bad in malformed {
        let json_key = serde_json::to_string(&bad).unwrap();
        // RevisionHead nested: {"key": bad, "revision":1, "state_fence": fence}
        let fence_json = serde_json::to_value(&fence).unwrap();
        let head_json = serde_json::json!({
            "key": serde_json::from_str::<serde_json::Value>(&json_key).unwrap(),
            "revision": 1,
            "state_fence": fence_json
        });
        let result: Result<RevisionHead, _> = serde_json::from_value(head_json.clone());
        assert!(
            result.is_err(),
            "RevisionHead should reject malformed RevisionKey {:?}",
            bad
        );

        // OrderingHead with bad OrderingScopeId
        let ohead_json = serde_json::json!({
            "scope": serde_json::from_str::<serde_json::Value>(&json_key).unwrap(),
            "sequence": 1,
            "state_fence": fence_json
        });
        let oresult: Result<OrderingHead, _> = serde_json::from_value(ohead_json);
        assert!(
            oresult.is_err(),
            "OrderingHead should reject malformed OrderingScopeId {:?}",
            bad
        );

        // ScopeRevisionView with bad ScopeId
        let view_json = serde_json::json!({
            "scope_id": serde_json::from_str::<serde_json::Value>(&json_key).unwrap(),
            "revision_heads": [],
            "ordering_heads": [],
            "state_fence": fence_json
        });
        let vresult: Result<ScopeRevisionView, _> = serde_json::from_value(view_json);
        assert!(
            vresult.is_err(),
            "ScopeRevisionView should reject malformed ScopeId {:?}",
            bad
        );
    }

    // Valid round trip for nested structs
    let valid_key = RevisionKey::new("revision-key-1").unwrap();
    let head = RevisionHead {
        key: valid_key,
        revision: 1,
        state_fence: fence.clone(),
    };
    let json = serde_json::to_string(&head).unwrap();
    let decoded: RevisionHead = serde_json::from_str(&json).unwrap();
    assert_eq!(head, decoded);
    assert_eq!(json, serde_json::to_string(&decoded).unwrap());
}
