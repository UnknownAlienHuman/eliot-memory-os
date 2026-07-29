use eliot_engine::{ProjectContinuityService, ProjectUnderstandingCompiler};
use eliot_types::memory::MemoryApplicabilityPacketView;
use eliot_types::{
    BlastRadiusView, CodeCortexPacketView, CodeCortexScopeBinding, CodeEvidenceSource,
    ContextPacketL3, DecisionLocalitySuffix, EpistemicPacketState, FileEvidence,
    MaterialPacketFrame, MemoryConfidence, MemoryLifecyclePacketView, MemoryRevision, ProjectId,
    ProjectUnderstandingEvidence, SymbolEvidence, TokenBudgetReport, TruncationInfo,
    VerifierEvidence,
};

#[test]
fn canonical_model_exposes_complete_action_chain_and_continuity() {
    let mut packet = packet();
    packet.active_plan = vec!["change compiler".to_owned()];
    packet.completed_work = vec!["inspect current code".to_owned()];
    packet.killed_paths = vec!["rewrite storage".to_owned()];
    packet.codecortex = Some(codecortex_view());
    let frame = MaterialPacketFrame {
        acceptance_items: vec!["focused test passes".to_owned()],
        active_plan: packet.active_plan.clone(),
        completed_work: packet.completed_work.clone(),
        killed_paths: packet.killed_paths.clone(),
        next_allowed_action: "change compiler".to_owned(),
        expected_observable: "verifier:focused=pass".to_owned(),
        verifier: "cargo test -p eliot-engine --test project_understanding".to_owned(),
        stop_condition: "stop on focused verifier failure".to_owned(),
        predicted_changed_paths: vec![
            "crates/eliot-engine/src/project_understanding.rs".to_owned(),
        ],
        predicted_failing_verifiers: vec!["project_understanding".to_owned()],
        negative_memory_checked: true,
        ..MaterialPacketFrame::default()
    };
    let evidence = ProjectUnderstandingEvidence {
        project_purpose: "Compile governed context for agents".to_owned(),
        subsystem_refs: vec!["concept:context-compiler".to_owned()],
        owner_modules: vec!["crates/eliot-engine".to_owned()],
        entrypoint_refs: vec!["symbol:ContextCompiler::compile".to_owned()],
        invariant_refs: vec!["invariant:revision-fence".to_owned()],
        danger_refs: vec!["failure:stale-packet".to_owned()],
        artifact_refs: vec!["charter:eliot".to_owned()],
        flow_evidence_refs: vec!["flow:packet-to-verifier".to_owned()],
        non_goals: vec!["do not expose chain-of-thought".to_owned()],
    };

    let model = ProjectUnderstandingCompiler::compile(&packet, Some(&frame), None, &evidence);

    assert_eq!(model.schema_version, "project-understanding-v1");
    assert_eq!(model.causal_model.hops.len(), 6);
    assert!(model.causal_model.unknown_hops.is_empty());
    assert_eq!(model.system.project_purpose, evidence.project_purpose);
    assert_eq!(
        model.files_to_change,
        vec!["crates/eliot-engine/src/project_understanding.rs"]
    );
    assert_eq!(model.next_allowed_action, "change compiler");
    assert_eq!(
        packet
            .codecortex
            .as_ref()
            .map(|view| view.scope_binding.branch.as_str()),
        Some("codex/c2")
    );
    assert_eq!(packet.killed_paths, vec!["rewrite storage"]);
}

#[test]
fn continuity_restore_never_revives_completed_or_killed_actions() {
    let mut previous = packet();
    previous.active_plan = vec![
        "already complete".to_owned(),
        "killed route".to_owned(),
        "continue safely".to_owned(),
    ];
    previous.completed_work = vec!["already complete".to_owned()];
    previous.killed_paths = vec!["killed route".to_owned()];
    previous.decision_locality_suffix.next_allowed_action = "killed route".to_owned();
    previous.decision_locality_suffix.expected_observable = "verifier:old=pass".to_owned();
    previous.decision_locality_suffix.verifier = "cargo test old".to_owned();

    let mut restored = packet();
    restored.project_id = previous.project_id;
    ProjectContinuityService::restore(&mut restored, Some(&previous));

    assert_eq!(restored.completed_work, vec!["already complete"]);
    assert_eq!(restored.killed_paths, vec!["killed route"]);
    assert_eq!(restored.active_plan, vec!["continue safely"]);
    assert!(
        restored
            .decision_locality_suffix
            .next_allowed_action
            .is_empty()
    );
    assert!(
        restored
            .decision_locality_suffix
            .open_unknowns
            .iter()
            .any(|item| item.contains("replan required"))
    );
    assert_eq!(restored.decision_locality_suffix.verifier, "cargo test old");
}

fn packet() -> ContextPacketL3 {
    ContextPacketL3 {
        packet_id: "eliot/packet/c2".to_owned(),
        project_id: ProjectId::new_v7(),
        task_id: "01930000-0000-7000-8000-000000000002".to_owned(),
        goal: "Add canonical project understanding".to_owned(),
        task_execution_class: eliot_types::TaskExecutionClass::default(),
        project_understanding: None,
        memory_confidence: MemoryConfidence::None,
        acceptance_items: Vec::new(),
        at_revision: MemoryRevision::new(7),
        current_truth: Vec::new(),
        relevant_verified_claims: Vec::new(),
        relevant_supported_claims: Vec::new(),
        weak_claims_warning: Vec::new(),
        negative_memory: Vec::new(),
        recent_failures: Vec::new(),
        known_decisions: Vec::new(),
        open_questions: Vec::new(),
        exact_handles: Vec::new(),
        source_receipts: Vec::new(),
        current_truth_snapshot: None,
        epistemic_state: EpistemicPacketState::default(),
        active_plan: Vec::new(),
        completed_work: Vec::new(),
        killed_paths: Vec::new(),
        causal_bridge: Vec::new(),
        memory_decisions: Vec::new(),
        experience_priors: Vec::new(),
        memory_need_decision: None,
        decision_locality_suffix: DecisionLocalitySuffix::default(),
        packet_quality: None,
        memory_applicability: MemoryApplicabilityPacketView::default(),
        historical_memory: Vec::new(),
        codecortex: None,
        memory_lifecycle: MemoryLifecyclePacketView::default(),
        procedural_skills: eliot_types::ProceduralSkillPacketView::default(),
        token_budget_report: TokenBudgetReport {
            max_tokens: 4_000,
            estimated_tokens: 0,
            truncated: false,
            sections_truncated: Vec::new(),
        },
        truncation: TruncationInfo {
            truncated: false,
            limit: 4_000,
            returned: 0,
        },
    }
}

fn codecortex_view() -> CodeCortexPacketView {
    CodeCortexPacketView {
        report_refs: vec!["codecortex:c2".to_owned()],
        git_head: Some("c2-head".to_owned()),
        scope_binding: CodeCortexScopeBinding {
            branch: "codex/c2".to_owned(),
            commit: "c2-head".to_owned(),
            dirty_state_hash: "dirty-c2".to_owned(),
            adapter_versions: std::collections::BTreeMap::default(),
            verifier_config_hash: "config-c2".to_owned(),
        },
        file_evidence: vec![FileEvidence {
            path: "crates/eliot-engine/src/project_understanding.rs".to_owned(),
            content_hash: Some("file-hash".to_owned()),
            line_start: Some(1),
            line_end: Some(10),
            excerpt: "pub struct ProjectUnderstandingCompiler".to_owned(),
            source: CodeEvidenceSource::Rg,
        }],
        symbol_evidence: vec![SymbolEvidence {
            name: "ProjectUnderstandingCompiler".to_owned(),
            kind: "struct".to_owned(),
            path: "crates/eliot-engine/src/project_understanding.rs".to_owned(),
            line: Some(10),
            source: CodeEvidenceSource::Rg,
        }],
        diagnostic_evidence: Vec::new(),
        verifier_map: vec![VerifierEvidence {
            name: "cargo_test".to_owned(),
            command: "cargo test -p eliot-engine".to_owned(),
            status: "pass".to_owned(),
            summary: "focused verifier".to_owned(),
            source: CodeEvidenceSource::CargoMetadata,
        }],
        blast_radius: BlastRadiusView {
            files: vec!["crates/eliot-engine/src/project_understanding.rs".to_owned()],
            crates: vec!["eliot-engine".to_owned()],
            reasons: vec!["canonical model".to_owned()],
        },
        unknowns: Vec::new(),
    }
}
