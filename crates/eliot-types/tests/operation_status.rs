use eliot_types::OperationStatus;

#[test]
fn operation_status_serializes_only_contract_vocabulary() -> Result<(), serde_json::Error> {
    let cases = [
        (
            OperationStatus::OperationCompleted,
            "\"OPERATION_COMPLETED\"",
        ),
        (OperationStatus::Active, "\"ACTIVE\""),
        (OperationStatus::Blocked, "\"BLOCKED\""),
        (OperationStatus::Failed, "\"FAILED\""),
    ];

    for (status, expected) in cases {
        assert_eq!(serde_json::to_string(&status)?, expected);
        assert_eq!(serde_json::from_str::<OperationStatus>(expected)?, status);
        assert_eq!(status.to_string(), expected.trim_matches('"'));
    }

    for forbidden in [
        "\"DONE_VERIFIED\"",
        "\"PARTIAL_PROGRESS\"",
        "\"NO_WORK\"",
        "\"NO_WORKTREE\"",
    ] {
        assert!(serde_json::from_str::<OperationStatus>(forbidden).is_err());
    }

    Ok(())
}
