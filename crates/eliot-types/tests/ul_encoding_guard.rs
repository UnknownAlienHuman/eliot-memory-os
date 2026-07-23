use eliot_types::{TextEncodingViolation, inspect_text_encoding, mojibake};
use serde_json::json;

#[test]
fn t01_encoding_guard_examples() {
    assert_eq!(mojibake("проверка ????? QUARTZ"), Some("qmark_run"));
    assert_eq!(mojibake("what??? really"), None);
    assert_eq!(mojibake("проверка ?? QUARTZ"), None);
    assert_eq!(mojibake("bad � text"), Some("replacement_char"));

    let violations = inspect_text_encoding(&json!({
        "z": "bad � text",
        "payload": {
            "items": [
                {"text": "проверка ????? QUARTZ"}
            ]
        }
    }));
    assert_eq!(
        violations,
        vec![
            TextEncodingViolation {
                path: "$.payload.items[0].text".to_owned(),
                reason: "qmark_run".to_owned(),
            },
            TextEncodingViolation {
                path: "$.z".to_owned(),
                reason: "replacement_char".to_owned(),
            },
        ]
    );
}
