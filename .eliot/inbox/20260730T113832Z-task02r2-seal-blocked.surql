BEGIN TRANSACTION;

UPSERT failure_fingerprint:cognitive_completion_task02r2_legacy_schema_20260730 CONTENT {
    project: "eliot-memory-os",
    task_class: "cognitive-completion-recovery-task02r2",
    failed_action_pattern: "Seal run006 provider plan with the four exact U03 reused roles mandated by Task02R2.",
    trigger_pattern: "Task02R2 run006 seal-provider-plan validation of the immutable run003 U03 Worker source call.",
    observed_failure: "Seal attempt 1 failed in 68 ms for an exact-dependency gap; after projecting the current Worker schema, attempt 2 failed in 30484 ms because the immutable run003 provider plan predates canonical_schema_sha256.",
    why_it_failed: "verify_accepted_prior_role requires source_call.canonical_schema_sha256 for every reused role, but Task02R2 mandates an exact run003 Worker whose immutable source plan does not contain that later field even though run005 already accepted it.",
    violated_invariant: "A mandated immutable legacy role must be admitted only through an explicit, tuple-bound, evidence-backed compatibility rule; immutable historical evidence must not be rewritten.",
    affected_files_or_entities: [
        "cq-core-20260730-006 provider-plan seal",
        "cq-core-20260729-003 / 6f04e449-ecab-4555-8bd0-4a6bd762c1b4 / U03 / codex_worker",
        "verify_accepted_prior_role",
        "ELIOT_TASK_02R2_RUNTIME_BOUND_CONTINUATION_v1_0.md"
    ],
    required_discriminative_check: "Add an allow test for only the exact run003 Worker tuple backed by run005 role evidence and current Rust schema equality, plus reject tests for every other missing-schema tuple; then rerun focused gates and seal before provider dispatch.",
    reopen_conditions: [
        "The user authorizes the narrow exact-tuple legacy-admission repair.",
        "The task contract is revised to authorize a fresh U03 Worker instead of reuse."
    ],
    status: "open_blocker",
    created_at: d"2026-07-30T11:38:32Z",
    lifecycle_status: "active",
    visibility: "project",
    recall_priority: 10,
    tags: ["cognitive-completion", "task02r2", "run006", "seal", "blocked", "legacy-schema"]
};

UPSERT trace_span:cognitive_completion_task02r2_20260730t113832z CONTENT {
    project: "eliot-memory-os",
    lane: "cognitive_completion_recovery_task02r2",
    task_ref: task_contract:eliot_memory_os_cognitive_completion_v2_20260729,
    packet_ref: context_packet:cognitive_completion_task02r2_blocked_20260730t113832z,
    actions: [
        "Implemented and pushed hash-bound provider runtime contracts and exact role-reuse validation at c75f8d5.",
        "Passed focused Cargo gates, strict Clippy, and real zero-model Governor MCP preflight.",
        "Prepared immutable run006 at the Task01 product commit with eight fresh U06/U11 calls and four reused U03 roles.",
        "Stopped after two fail-closed seal attempts exposed an immutable legacy source-plan field gap.",
        "Attempted one Opus 5 CLI review with a zero-token authentication failure and inspected a blank Claude GUI.",
        "Attempted one Antigravity review; the client selected Gemini 3.6 Flash High and returned no technical decision."
    ],
    checks_run: [
        "Task02R2 focused tests PASS.",
        "cargo fmt, check, and strict Clippy workspace gates PASS.",
        "Codex Governor zero-model preflight PASS.",
        "run006 prepare PASS.",
        "U03 deterministic evidence import PASS.",
        "run006 provider-plan seal FAIL closed twice."
    ],
    tools_used: ["Cargo", "Git", "PowerShell", "SurrealDB MCP", "Claude Code Opus 5 CLI", "Claude GUI inspection", "Antigravity Gemini 3.6 Flash High"],
    expected_vs_observed_delta: "Task02R2 expects four exact U03 role reuses and eight fresh U06/U11 calls. run006 reached prepared state with zero qualification calls, but seal rejected the mandated immutable run003 Worker because its historical source plan predates the current schema-hash field.",
    outcome: "BLOCKED_BY_POLICY_AMBIGUITY before provider-plan seal; fresh run006 qualification calls dispatched: 0. Report: C:/Users/kleym/Downloads/ELIOT_COGNITIVE_COMPLETION_RECOVERY_PLAN_v3_0/ELIOT_COGNITIVE_COMPLETION_RECOVERY_EXECUTION_REPORT.md",
    created_at: d"2026-07-30T11:38:32Z",
    lifecycle_status: "active",
    visibility: "project",
    recall_priority: 10,
    tags: ["cognitive-completion", "task02r2", "trace", "blocked", "run006"]
};

UPSERT context_packet:cognitive_completion_task02r2_blocked_20260730t113832z CONTENT {
    project: "eliot-memory-os",
    task_ref: task_contract:eliot_memory_os_cognitive_completion_v2_20260729,
    packet_kind: "task02r2_seal_blocked_handoff",
    token_risk: "low",
    current_truth_refs: [
        trace_span:cognitive_completion_task02r2_20260730t113832z,
        failure_fingerprint:cognitive_completion_task02r2_legacy_schema_20260730
    ],
    evidence_refs: [],
    causal_slice_ref: NONE,
    suppressed_items: [],
    verifier: "Two fail-closed run006 seal attempts; exact current Rust schema comparison; zero qualification provider dispatch.",
    created_at: d"2026-07-30T11:38:32Z",
    lifecycle_status: "active",
    visibility: "project",
    recall_priority: 10,
    tags: ["cognitive-completion", "task02r2", "handoff", "blocked", "run006"]
};

RELATE trace_span:cognitive_completion_task02r2_20260730t113832z
    ->produces:cognitive_completion_task02r2_blocked_20260730
    ->context_packet:cognitive_completion_task02r2_blocked_20260730t113832z
CONTENT {
    role: "blocked_checkpoint",
    test_id: "cognitive_completion_task02r2_20260730",
    created_at: d"2026-07-30T11:38:32Z"
};

COMMIT TRANSACTION;

RETURN {
    trace: trace_span:cognitive_completion_task02r2_20260730t113832z,
    packet: context_packet:cognitive_completion_task02r2_blocked_20260730t113832z,
    failure: failure_fingerprint:cognitive_completion_task02r2_legacy_schema_20260730
};
