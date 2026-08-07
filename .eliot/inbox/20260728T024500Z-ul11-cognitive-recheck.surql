USE NS eliot DB system;

BEGIN TRANSACTION;

UPSERT failure_fingerprint:ul11_current_state_bound_task_omission_20260728 CONTENT {
    affected_files_or_entities: [
        "crates/eliot-app/src/mcp_stdio/dispatch.rs",
        "crates/eliot-app/src/mcp_stdio/protocol_tests.rs",
        "Claude provider smoke ul11r3-smoke-claude-019fa5e4-4220-7a21-9331-6caa61168bcf"
    ],
    created_at: d"2026-07-28T02:45:00Z",
    failed_action_pattern: "A bound provider calls eliot_current_state and must return the canonical project, task, and memory revision",
    lifecycle_status: "resolved",
    observed_failure: "Claude called the correct ELIOT MCP tool, but current_state omitted task_id; schema-valid structured output therefore contained an empty task_id and the canonical verifier rejected it",
    project: "eliot-memory-os",
    recall_priority: 10,
    reopen_conditions: [
        "A bound current_state response again omits or changes the canonical task_id",
        "An unbound current_state response unexpectedly gains task_id",
        "A fresh provider-owned smoke fails exact project, task, or revision matching"
    ],
    required_discriminative_check: "Require a regression for bound and unbound response shapes plus fresh provider-owned Claude and Antigravity smokes with controller_substitute_call=false",
    resolved_at: d"2026-07-28T02:45:00Z",
    resolution: "Project the authenticated bound_task_id into MCP current_state output only for bound sessions. The regression passed, Claude Sonnet smoke passed in 24.789s, and Antigravity Gemini 3.6 Flash High smoke passed in 20.964s.",
    status: "resolved",
    tags: ["ul11", "current-state", "task-scope", "claude", "antigravity", "resolved"],
    task_class: "ul11-ul12-cognitive-recheck",
    trigger_pattern: "Provider-owned current_state adoption under a Governor-bound host session",
    violated_invariant: "Bound current_state must expose the exact canonical task scope without changing the unbound response shape",
    visibility: "normal",
    why_it_failed: "The read service response was project-scoped and the MCP dispatch layer did not project AuthenticatedRequestContext.bound_task_id"
};

UPDATE failure_fingerprint:ul12_pr_ci_ipc_wrapper_lifetime MERGE {
    lifecycle_status: "resolved",
    status: "resolved_after_reopen",
    reopened_at: d"2026-07-28T00:47:39Z",
    resolved_at: d"2026-07-28T02:42:25Z",
    observed_failure: "The earlier Process.Dispose resolution passed PR CI but independent main run 30316994468 repeated the exact None versus Some(0) root-process timeout after 60 seconds.",
    resolution: "The managed PowerShell root was removed from the test. A native cmd root launches the descendant with start /B, then the test proves fast root exit, live Job membership, pre-terminate pipe hold, and post-terminate closure under two seconds. Forced-close codes 31, 109, 232, and 233 are accepted only after TerminateJobObject. PR run 30321135074 and merge-SHA main run 30322498639 passed.",
    required_discriminative_check: "Require 104 exact contention runs, sequential IPC suites, full local verify, final PR CI, and an independent merge-SHA main CI; do not accept a single green PR as resolution.",
    reopen_conditions: [
        "The root process again fails to exit promptly",
        "The descendant is absent from the Job Object after root exit",
        "Either pipe reaches EOF before TerminateJobObject",
        "Either pipe fails to terminate inside the two-second post-terminate deadline",
        "PR or merge-SHA Windows CI fails the IPC test"
    ],
    tags: ["ul12", "ci", "windows", "ipc", "test-duration", "reopened", "resolved"]
};

UPSERT failure_fingerprint:ul12_post_terminate_pipe_error31_20260728 CONTENT {
    affected_files_or_entities: [
        "crates/eliot-windows-ipc/src/lib.rs",
        "PR #6 run 30319229224",
        "TerminateJobObject anonymous-pipe drain"
    ],
    created_at: d"2026-07-28T01:33:18Z",
    failed_action_pattern: "A blocked anonymous-pipe read completes after TerminateJobObject and the test treats every non-EOF result as failure",
    lifecycle_status: "resolved",
    observed_failure: "Hosted Windows returned ERROR_GEN_FAILURE 31 after forcible writer teardown; the strengthened test failed in 3.39s rather than hanging",
    project: "eliot-memory-os",
    recall_priority: 9,
    reopen_conditions: [
        "A closure code outside 31, 109, 232, and 233 appears after the same proven pre-terminate hold",
        "An accepted closure code appears before TerminateJobObject",
        "The two-second deadline or stdout payload assertion fails"
    ],
    required_discriminative_check: "Accept only exact forced-closure codes after a proven pre-terminate hold, while preserving Job membership, timeout, and payload assertions",
    resolved_at: d"2026-07-28T02:42:25Z",
    resolution: "Added an exact post-terminate classifier for Win32 31, 109, 232, and 233 plus a regression rejecting 5, 6, and 87. Final PR and main CI passed.",
    status: "resolved",
    tags: ["ul12", "windows", "ipc", "error31", "job-object", "resolved"],
    task_class: "ul11-ul12-cognitive-recheck",
    trigger_pattern: "TerminateJobObject force-closes the last inherited pipe writer on hosted Windows",
    violated_invariant: "Forcible writer teardown is a terminal completion outcome, but unrelated Win32 errors must remain failures",
    visibility: "normal",
    why_it_failed: "The read side assumed clean EOF while Windows can surface non-graceful terminal pipe errors for a forcibly killed writer"
};

UPSERT failure_fingerprint:ul12_parallel_credential_manager_roundtrip_20260728 CONTENT {
    affected_files_or_entities: [
        "crates/eliot-windows-ipc/src/lib.rs",
        "credential_manager_round_trip_is_current_user_scoped",
        "parallel full IPC test binaries"
    ],
    created_at: d"2026-07-28T01:00:00Z",
    failed_action_pattern: "Several full IPC test binaries mutate the Windows Credential Manager concurrently",
    lifecycle_status: "active",
    observed_failure: "One of eight and then two of eight parallel full IPC suites failed in credential_manager_round_trip_is_current_user_scoped, while the target Job/pipe test passed",
    project: "eliot-memory-os",
    recall_priority: 6,
    reopen_conditions: [
        "Parallel full IPC suite execution becomes an acceptance requirement",
        "Credential tests gain per-process isolation and can be stress-validated"
    ],
    required_discriminative_check: "Isolate credential targets and cleanup across concurrent binaries before counting parallel full-suite results",
    status: "accepted_test_isolation_limitation",
    tags: ["ul12", "windows", "credential-manager", "test-isolation", "timing"],
    task_class: "ul11-ul12-cognitive-recheck",
    trigger_pattern: "Full IPC binaries run concurrently under a stress experiment",
    violated_invariant: "A stress verifier should not introduce unrelated shared-global-state interference",
    visibility: "normal",
    why_it_failed: "The Windows Credential Manager round-trip is safe in the normal sequential suite but is not isolated for several concurrent full test processes"
};

UPSERT failure_fingerprint:claude_opus_alias_resolved_4_8_20260728 CONTENT {
    affected_files_or_entities: [
        "Claude Code 2.1.207",
        "--model opus alias",
        "consultation session 2eece1d9-ef60-4eba-afeb-6d22d9514105"
    ],
    created_at: d"2026-07-28T02:45:00Z",
    failed_action_pattern: "A scarce-model escalation requests Opus 5 but uses the floating CLI alias opus without verifying the resolved model id",
    lifecycle_status: "active",
    observed_failure: "Both consultation receipts reported modelUsage claude-opus-4-8, not Opus 5",
    project: "eliot-memory-os",
    recall_priority: 8,
    reopen_conditions: [
        "A future scarce-model escalation is required",
        "Claude Code exposes an explicit Opus 5 model id"
    ],
    required_discriminative_check: "Select an explicit model in the authorized client and verify the selected model or first receipt before sending the expensive prompt",
    status: "accepted_operator_process_error",
    tags: ["claude-code", "model-routing", "opus", "quota", "preflight"],
    task_class: "ul11-ul12-cognitive-recheck",
    trigger_pattern: "The operator requests a specific high-intelligence model",
    violated_invariant: "The actual model must match the explicitly requested model",
    visibility: "normal",
    why_it_failed: "The controller trusted the floating opus alias; Claude Code 2.1.207 resolved it to claude-opus-4-8"
};

UPSERT failure_fingerprint:rust_lsp_unlinked_eliot_memory_os_20260728 CONTENT {
    affected_files_or_entities: [
        "crates/eliot-app/src/mcp_stdio/dispatch.rs",
        "crates/eliot-app/src/mcp_stdio/protocol_tests.rs",
        "rust-analyzer through mcpls"
    ],
    created_at: d"2026-07-28T02:45:00Z",
    failed_action_pattern: "Live Rust LSP diagnostics are requested for files that Cargo includes in a valid workspace",
    lifecycle_status: "active",
    observed_failure: "The LSP returned only unlinked-file hints while Cargo metadata, check, clippy, and tests all resolved the files normally",
    project: "eliot-memory-os",
    recall_priority: 5,
    reopen_conditions: [
        "mcpls or rust-analyzer workspace discovery is repaired",
        "A future code edit requires semantic LSP evidence"
    ],
    required_discriminative_check: "Compare rust-analyzer workspace roots with cargo metadata and require linked-file diagnostics",
    status: "accepted_tooling_limitation",
    tags: ["rust", "lsp", "mcpls", "unlinked-file"],
    task_class: "ul11-ul12-cognitive-recheck",
    trigger_pattern: "Project files are inspected through the current Rust LSP bridge",
    violated_invariant: "The LSP evidence layer should link files that the Cargo source of truth includes",
    visibility: "normal",
    why_it_failed: "The LSP bridge did not attach the current nested repository workspace even though Cargo did"
};

UPSERT failure_fingerprint:github_actions_node20_deprecation_20260728 CONTENT {
    affected_files_or_entities: [
        ".github workflow",
        "actions/cache@v4",
        "actions/checkout@v4"
    ],
    created_at: d"2026-07-28T02:45:00Z",
    failed_action_pattern: "GitHub-hosted Windows executes actions that target deprecated Node.js 20",
    lifecycle_status: "active",
    observed_failure: "GitHub emitted a warning and forced actions/cache@v4 and actions/checkout@v4 to Node.js 24",
    project: "eliot-memory-os",
    recall_priority: 4,
    reopen_conditions: [
        "Updated action majors become available",
        "GitHub stops compatibility forcing and the warning becomes a failure"
    ],
    required_discriminative_check: "Update to action versions that natively target the supported Node runtime and require warning-free CI",
    status: "accepted_infrastructure_warning",
    tags: ["github-actions", "node20", "deprecation", "ci"],
    task_class: "ul11-ul12-cognitive-recheck",
    trigger_pattern: "Any current GitHub Actions workflow run",
    violated_invariant: "CI dependencies should target supported hosted-runner runtimes",
    visibility: "normal",
    why_it_failed: "The current v4 action releases still declare Node.js 20"
};

UPSERT evidence_atom:ul11_ul12_cognitive_recheck_20260728 CONTENT {
    exact_text: "Fresh Claude Sonnet current_state smoke first failed in 17.018s because the bound MCP response omitted task_id. Commit 329241a added bound-task projection without changing the unbound shape. Fresh Claude Sonnet passed in 24.789s; Antigravity Gemini 3.6 Flash High passed in 20.964s. Reciprocal run ul-cross-agent-019fa5ee-a461-7aa3-b0fb-876b2bd546d4 passed exactly 8/8 calls, both directions 14/14, zero unknowns, in 353.008s. PR #5 passed but main run 30316994468 reopened the IPC root-lifetime fingerprint. PR #6 first failed on post-terminate Win32 error 31, then final head 2c1208e passed PR run 30321135074. PR #6 merged as bccb334; main run 30322498639 passed. Final report SHA256 is 3F16BB1AABBE863CC418EF43DB8981E0DF7C7EB117422E282CEC8C8A97057DBF.",
    id: evidence_atom:ul11_ul12_cognitive_recheck_20260728,
    kind: "cognitive_recheck_evidence",
    lifecycle_status: "active",
    normalized_claim: "The bound current-state contract, reciprocal provider memory transfer, deterministic Windows IPC certification harness, and final delivery gates passed after two evidence-driven repairs",
    observed_at: d"2026-07-28T02:45:00Z",
    project: "eliot-memory-os",
    recall_priority: 10,
    scope: {
        antigravity_smoke: "ul11r3-smoke-antigravity-019fa5ed-bc56-72d1-a594-cda8a774a545",
        claude_smoke: "ul11r3-smoke-claude-019fa5ed-3be9-7b53-a383-470a21ad9e7e",
        final_main_ci_run: 30322498639,
        final_merge_sha: "bccb334021749854df1c10733d0e2fadd4b704ca",
        final_pr_ci_run: 30321135074,
        provider_run: "ul-cross-agent-019fa5ee-a461-7aa3-b0fb-876b2bd546d4",
        report: "C:/Users/kleym/Downloads/ELIOT_UL11R_UL12_COGNITIVE_RECHECK_20260728.md",
        report_sha256: "3F16BB1AABBE863CC418EF43DB8981E0DF7C7EB117422E282CEC8C8A97057DBF"
    },
    tags: ["ul11", "ul12", "cognitive-recheck", "claude", "antigravity", "ci", "timing", "merged"],
    taint: "tool_output",
    visibility: "normal"
};

UPSERT verification_run:eliot_ul_v1_4_cognitive_recheck_20260728 CONTENT {
    command_or_tool_call: "fresh Claude and Antigravity smokes; reciprocal eight-call run; focused Rust suites; 104 exact IPC stress runs; sequential IPC suites; repeated just verify; GitHub PR and main CI",
    cwd: "C:\\Users\\kleym\\OneDrive\\Documents\\Rust\\projects\\eliot-memory-os",
    diagnostics: [
        "Claude and Antigravity provider-owned current_state smokes passed with exact project, task, and revision",
        "Reciprocal run passed 8/8 calls, both directions 14/14, with zero unknown outcomes",
        "IPC exact stress passed 104/104 under throttle 8 in 14.238 seconds",
        "Five sequential IPC suites passed; final IPC suite is 18/18",
        "Final just verify passed in 386.4 seconds",
        "PR #6 run 30321135074 passed with a 22m06s Tests step",
        "Final main run 30322498639 passed with a 23m01s Tests step",
        "Code graph indexed 19,337 nodes and 89,953 edges with zero skipped"
    ],
    id: verification_run:eliot_ul_v1_4_cognitive_recheck_20260728,
    observed_at: d"2026-07-28T02:45:00Z",
    output_excerpt: "UL cognitive recheck PASS; provider run 8/8; IPC 104/104; just verify 386.4s; PR CI PASS; merge-SHA main CI PASS",
    project: "eliot-memory-os",
    result: "pass",
    tool: "Cargo, Just, ELIOT governor, Claude Code, Antigravity, GitHub Actions"
};

UPSERT claim_card:eliot_ul_v1_4_cognitive_recheck_20260728 CONTENT {
    authority: "merged_recertification",
    branch_env_scope: {
        branch: "main",
        environment: "Windows local and GitHub-hosted Windows"
    },
    epistemic_grade: "high",
    id: claim_card:eliot_ul_v1_4_cognitive_recheck_20260728,
    known_from: d"2026-07-28T02:45:00Z",
    lifecycle_status: "active",
    project: "eliot-memory-os",
    proposition: "ELIOT Understanding Layer v1.4 remains cognitively correct after fresh Claude and Antigravity model-owned checks, and its repaired bound-scope and Windows CI contracts pass local, PR, and independent merge-SHA verification.",
    recall_priority: 10,
    scope: {
        final_main_ci_run: 30322498639,
        final_merge_sha: "bccb334021749854df1c10733d0e2fadd4b704ca",
        final_pr: 6,
        final_pr_ci_run: 30321135074,
        product_fix_pr: 5,
        run_id: "ul-cross-agent-019fa5ee-a461-7aa3-b0fb-876b2bd546d4",
        task_id: "ELIOT_UL11R_ARCHITECTURE_ALIGNED_MASTER_v3_0"
    },
    status: "verified_merged",
    subject: "ELIOT UL-11R and UL-12 cognitive recheck",
    tags: ["ul11", "ul12", "verified", "cognitive-recheck", "merged"],
    transaction_from: d"2026-07-28T02:45:00Z",
    valid_from: d"2026-07-28T02:45:00Z",
    visibility: "normal"
};

UPSERT trace_span:ul11_ul12_cognitive_recheck_20260728t024500z CONTENT {
    actions: [
        "Re-ran fresh provider-owned Claude and Antigravity current-state smokes",
        "Inspected the immutable Claude transcript and found the missing bound task in the MCP response",
        "Added bound-task response projection and a bound versus unbound regression",
        "Ran one complete reciprocal Opus certification after the product fix",
        "Detected that a green PR was insufficient when independent main CI reopened the IPC fingerprint",
        "Consulted Claude Code once with one follow-up; actual model was Opus 4.8 because the opus alias was not preflighted",
        "Replaced the managed PowerShell test root with a deterministic native cmd root",
        "Added Job membership, pre-terminate pipe hold, exact forced-closure classification, payload, and deadline assertions",
        "Ran local stress, full verification, final PR CI, normal merge, and final merge-SHA CI",
        "Updated the code graph and produced a detailed external report"
    ],
    checks_run: [
        "Claude Sonnet provider smoke",
        "Antigravity Gemini 3.6 Flash High provider smoke",
        "reciprocal eight-call Opus run",
        "focused UL and provider contract suites",
        "104 exact IPC stress runs under throttle 8",
        "five sequential full IPC suites",
        "focused fmt and clippy -D warnings",
        "three final full just verify runs",
        "PR #5 CI and failing main CI",
        "PR #6 failing diagnostic CI, final green PR CI, and green merge-SHA main CI",
        "final code graph index"
    ],
    created_at: d"2026-07-28T02:45:00Z",
    expected_vs_observed_delta: "The original certification appeared complete. Fresh model-owned current_state use found a real missing task field. After that product fix, independent main CI also proved the earlier IPC Process.Dispose resolution was not stable. Both defects were repaired and independently reverified.",
    id: trace_span:ul11_ul12_cognitive_recheck_20260728t024500z,
    lane: "ul11_ul12_cognitive_recheck",
    lifecycle_status: "active",
    outcome: "Cognitive recheck and delivery passed after bound-task and deterministic IPC repairs",
    project: "eliot-memory-os",
    recall_priority: 10,
    report: "C:/Users/kleym/Downloads/ELIOT_UL11R_UL12_COGNITIVE_RECHECK_20260728.md",
    tags: ["ul11", "ul12", "cognitive-recheck", "ci", "timing", "trace"],
    tools_used: ["Cargo", "Just", "Git", "GitHub Actions", "ELIOT governor", "SurrealDB MCP", "Claude Code", "Antigravity", "CodeCortex"],
    updated_at: d"2026-07-28T02:45:00Z",
    visibility: "normal"
};

UPSERT context_packet:eliot_memory_os_ul11_cognitive_recheck_20260728t024500z CONTENT {
    project: "eliot-memory-os",
    task_ref: task_contract:eliot_memory_os_ul11_20260725,
    packet_kind: "ul11_ul12_cognitive_recheck_final",
    token_risk: "low",
    current_truth_refs: [
        claim_card:eliot_ul_v1_4_complete_20260727,
        claim_card:eliot_ul_v1_4_cognitive_recheck_20260728,
        failure_fingerprint:ul11_current_state_bound_task_omission_20260728,
        failure_fingerprint:ul12_pr_ci_ipc_wrapper_lifetime,
        failure_fingerprint:ul12_post_terminate_pipe_error31_20260728,
        verification_run:eliot_ul_v1_4_cognitive_recheck_20260728
    ],
    evidence_refs: [
        evidence_atom:ul11_ul12_final_certification_20260727,
        evidence_atom:ul11_ul12_cognitive_recheck_20260728
    ],
    causal_slice_ref: NONE,
    suppressed_items: [],
    verifier: "Fresh model-owned provider receipts, exact transcript evidence, Rust gates, stress tests, final PR CI, and independent merge-SHA main CI",
    created_at: d"2026-07-28T02:45:00Z",
    lifecycle_status: "active",
    visibility: "normal",
    recall_priority: 100,
    tags: ["ul11", "ul12", "cognitive-recheck", "context-packet", "verified"]
};

RELATE evidence_atom:ul11_ul12_cognitive_recheck_20260728->supports:ul11_ul12_cognitive_recheck_20260728->claim_card:eliot_ul_v1_4_cognitive_recheck_20260728 CONTENT {
    role: "cognitive_recheck_evidence",
    test_id: "ul-cross-agent-019fa5ee-a461-7aa3-b0fb-876b2bd546d4",
    created_at: d"2026-07-28T02:45:00Z"
};

RELATE claim_card:eliot_ul_v1_4_cognitive_recheck_20260728->verified_by:ul11_ul12_cognitive_recheck_20260728->verification_run:eliot_ul_v1_4_cognitive_recheck_20260728 CONTENT {
    role: "merged-recertification-verifier",
    test_id: "pr6-main-ci-20260728",
    created_at: d"2026-07-28T02:45:00Z"
};

UPDATE claim_card:eliot_ul_v1_4_complete_20260727 SET
    scope.cognitive_recheck_run = "ul-cross-agent-019fa5ee-a461-7aa3-b0fb-876b2bd546d4",
    scope.final_main_ci_run = 30322498639,
    scope.final_merge_sha = "bccb334021749854df1c10733d0e2fadd4b704ca",
    scope.final_pr = 6,
    scope.final_pr_ci_run = 30321135074,
    status = "verified_merged_rechecked";

UPDATE current_state:ul11_ul12_final_20260727 MERGE {
    status: "delivered_rechecked",
    summary: "UL-11R and UL-12 passed fresh Claude and Antigravity cognitive checks. The bound current_state task omission and reopened Windows IPC CI fingerprint were repaired. PR #6 merged as bccb334; final main CI run 30322498639 passed. Performance and tooling follow-ups remain non-blocking.",
    updated_at: d"2026-07-28T02:45:00Z"
};

COMMIT TRANSACTION;
