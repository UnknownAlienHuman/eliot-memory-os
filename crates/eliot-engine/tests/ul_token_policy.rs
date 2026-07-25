use eliot_engine::UlTokenPolicyService;
use eliot_types::{
    ProjectId, TaskId, UlExperimentArm, UlInjectionMode, UlTaskClass, UlTaskClassPolicy,
    UlTaskLedger,
};
use std::fs;

#[test]
fn u9_4_positive_median_downgrades_once_and_never_auto_restores_payload()
-> Result<(), Box<dyn std::error::Error>> {
    let project_id = ProjectId::new_v7();
    let class = UlTaskClass {
        action_class: "single_file".to_owned(),
        subsystem: "concept:alpha".to_owned(),
        artifact_class: "code".to_owned(),
    };
    let class_key = class.key();
    let mut ledgers = Vec::new();
    for exploration_tokens in [10, 20, 30, 40, 50] {
        ledgers.push(ledger(
            project_id,
            &class_key,
            UlExperimentArm::Control,
            exploration_tokens,
            0,
        ));
    }
    for net_token_delta in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10] {
        ledgers.push(ledger(
            project_id,
            &class_key,
            UlExperimentArm::Treatment,
            0,
            net_token_delta,
        ));
    }

    let Some(downgraded) =
        UlTokenPolicyService::evaluate_policy(None, project_id, &class_key, &ledgers)
    else {
        return Err("positive median did not downgrade".into());
    };
    assert_eq!(downgraded.injection_mode, UlInjectionMode::HandlesOnly);
    assert_eq!(downgraded.control_median_exploration_tokens, 30);
    assert_eq!(downgraded.treatment_median_net_delta, 6);
    assert_eq!(downgraded.reason, "positive_median_net_token_delta");
    let report_root = std::env::temp_dir().join(format!("eliot-ul-u9-report-{project_id}"));
    let report_path = UlTokenPolicyService::write_downgrade_report(&report_root, &downgraded)?;
    let report: serde_json::Value = serde_json::from_slice(&fs::read(&report_path)?)?;
    assert_eq!(
        report["schema_version"],
        "eliot-ul-token-policy-downgrade-v1"
    );
    assert_eq!(report["reason"], "positive_median_net_token_delta");
    assert!(
        report["report_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("UL-DOWNGRADE-"))
    );

    for ledger in ledgers
        .iter_mut()
        .filter(|ledger| ledger.arm == Some(UlExperimentArm::Treatment))
    {
        ledger.net_token_delta = -100;
    }
    assert_eq!(
        UlTokenPolicyService::evaluate_policy(Some(&downgraded), project_id, &class_key, &ledgers,),
        Some(downgraded)
    );
    fs::remove_dir_all(report_root)?;
    Ok(())
}

fn ledger(
    project_id: ProjectId,
    task_class_key: &str,
    arm: UlExperimentArm,
    exploration_tokens: u64,
    net_token_delta: i64,
) -> UlTaskLedger {
    UlTaskLedger {
        task_id: TaskId::new_v7(),
        project_id,
        task_class_key: task_class_key.to_owned(),
        arm: Some(arm),
        injection_mode: Some(UlInjectionMode::Payload),
        exploration_tokens,
        matched_baseline_tokens: 0,
        net_token_delta,
        injected_tokens: 0,
        read_tool_input_bytes: 0,
        read_tool_output_bytes: 0,
        expanded_injected_handles: 0,
        acknowledged_items: 0,
        first_mutation_seen: true,
    }
}

#[allow(dead_code)]
fn assert_policy_is_send_sync(_: &UlTaskClassPolicy) {}
