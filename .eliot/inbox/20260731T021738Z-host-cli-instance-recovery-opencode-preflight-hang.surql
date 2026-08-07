BEGIN TRANSACTION;

UPSERT trace_span:host_cli_01_instance_recovery_20260731t021738z CONTENT {
    project: "eliot-memory-os",
    lane: "host_cli_01_headless_adapters",
    task_ref: task_contract:eliot_memory_os_cognitive_completion_v2_20260729,
    source_commit: "29acb8646d5500ffc0618fa953a33067e00725dc",
    report_ref: "reports/cognitive-field/ELIOT_HOST_CLI_01_BLOCKED_REPORT_20260730.md",
    report_sha256: "5e482eef0840a79e59295ea0a1cdbef0b7f0eda05354f9aefcb75f3526db1ba3",
    actions: [
        "Ran the authorized global startup-recovery scan; it reported clean and removed nothing.",
        "Inspected the instance-aware host-launch recovery and verified its double PID-liveness and unchanged-lock safeguards.",
        "Invoked the authorized post-repair free MiMo smoke through that recovery path.",
        "Recovered the stale default instance and published a new ready daemon.",
        "Captured the new zero-model preflight hang before provider journal creation.",
        "Terminated only the orphaned smoke controller after the outer 180-second bound.",
        "Verified no OpenCode or provider child remained."
    ],
    checks_run: [
        "Global startup-recovery scan PASS clean in 0.027 s.",
        "Instance recovery PASS with stale lock and PID reconciliation.",
        "New daemon PID 151892 is live and responsive.",
        "New runtime publication state is ready with stop_requested=false.",
        "Daemon authenticated IPC doctor reports ready.",
        "No provider journal or spool exists for the hung smoke.",
        "No opencode-cli process was dispatched.",
        "No child/provider orphan remains after cleanup."
    ],
    live_observations: [
        "runtime_id=019fb5f1-b409-75f2-97ae-9e094b6fda61",
        "daemon_pid=151892",
        "release_sha256=6443043901b9ee88f4196496dd7515851e23d67e0701a1dcd890fb61c852e98f",
        "hung_smoke=external-agent-smoke-opencode-019fb5f1-b0dc-7822-8e69-2c609b11cabe",
        "hung_controller_pid=55240",
        "outer_bound_seconds=180",
        "provider_model_calls=0"
    ],
    problems: [
        "The governed OpenCode smoke hangs during canonical zero-model preparation before provider dispatch.",
        "Only the smoke workspace is materialized; provider attempt journal and spool are absent.",
        "The outer shell timeout does not terminate the orphaned smoke controller automatically."
    ],
    expected_vs_observed_delta: "Expected instance recovery followed by one free MiMo provider call. Instance recovery succeeded, but canonical zero-model smoke preparation hung before OpenCode dispatch.",
    remaining_actions: [
        "Do not retry OpenCode unchanged after two failed acceptance approaches.",
        "Choose bounded local diagnosis/repair of mcp_reference_exchange or one Claude Opus 5 consultation.",
        "After repair, use the free opencode/mimo-v2.5-free route only.",
        "Keep run006 fresh qualification calls undispatched until OpenCode acceptance passes."
    ],
    outcome: "BLOCKED_OPENCODE_ZERO_MODEL_PREFLIGHT_HANG_AFTER_INSTANCE_RECOVERY",
    created_at: d"2026-07-31T02:17:38Z",
    lifecycle_status: "active",
    visibility: "project",
    recall_priority: 100,
    tags: ["host-cli-01", "instance-recovery", "opencode", "preflight-hang", "no-model-call"]
};

UPSERT failure_fingerprint:host_cli_01_opencode_zero_model_preflight_hang_20260731 CONTENT {
    project: "eliot-memory-os",
    task_ref: task_contract:eliot_memory_os_cognitive_completion_v2_20260729,
    component: "eliot-app::host_runtime::external_agent::mcp_reference_exchange",
    signature: "OpenCode mcp-smoke controller remains alive beyond 180 seconds before provider attempt journal creation",
    trigger: "post-repair opencode/mimo-v2.5-free smoke after successful default-instance recovery",
    symptoms: [
        "only empty smoke workspace exists",
        "provider attempt journal is absent",
        "provider spool is absent",
        "opencode-cli process is absent",
        "smoke controller remains alive after outer shell timeout"
    ],
    bounded_cause: "The smoke blocks in canonical zero-model preparation before provider dispatch; the exact internal exchange step is not yet identified.",
    affected_files_or_entities: [
        "crates/eliot-app/src/host_runtime/external_agent.rs",
        "external-agent-smoke-opencode-019fb5f1-b0dc-7822-8e69-2c609b11cabe",
        "smoke controller PID 55240"
    ],
    non_causes: [
        "stale daemon lock",
        "daemon publication",
        "OpenCode authentication",
        "MiMo model availability",
        "structured JSON parser",
        "provider process cleanup"
    ],
    revalidation: [
        "Instrument or isolate the first three canonical MCP reference exchanges without dispatching a model.",
        "Require a bounded timeout for the whole zero-model preparation phase.",
        "Prove no orphaned smoke controller after timeout.",
        "Run no unchanged third OpenCode acceptance attempt."
    ],
    first_seen_at: d"2026-07-31T02:12:23Z",
    last_seen_at: d"2026-07-31T02:17:38Z",
    occurrence_count: 1,
    lifecycle_status: "active",
    visibility: "project",
    recall_priority: 100,
    tags: ["failure-fingerprint", "opencode", "mcp-preflight", "hang", "orphan-controller"]
};

UPSERT verification_run:host_cli_01_instance_recovery_20260731t021738z CONTENT {
    project: "eliot-memory-os",
    tool: "production Governor CLI, Windows process inspection, runtime publication and filesystem evidence",
    command_or_tool_call: "startup-recovery scan; governed OpenCode mcp-smoke; daemon status/health; process and evidence readback.",
    cwd: "C:/Users/kleym/OneDrive/Documents/Rust/projects/eliot-memory-os",
    commit: "29acb8646d5500ffc0618fa953a33067e00725dc",
    task_ref: task_contract:eliot_memory_os_cognitive_completion_v2_20260729,
    result: "blocked",
    diagnostics: [
        "Default-instance stale recovery succeeds.",
        "New daemon publication and authenticated IPC are ready.",
        "OpenCode smoke blocks before provider dispatch.",
        "No second MiMo model call occurred.",
        "Orphaned smoke controller was removed and no provider child remains.",
        "Updated Eliot transaction is staged because the canonical MCP namespace is unavailable."
    ],
    output_excerpt: "Daemon recovery closed; remaining blocker is a pre-provider zero-model MCP preparation hang.",
    observed_at: d"2026-07-31T02:17:38Z",
    lifecycle_status: "active",
    visibility: "project",
    recall_priority: 100,
    tags: ["host-cli-01", "verification", "blocked", "opencode-preflight", "daemon-ready"]
};

RELATE trace_span:host_cli_01_instance_recovery_20260731t021738z
    ->has_failure:host_cli_01_instance_recovery_20260731t021738z
    ->failure_fingerprint:host_cli_01_opencode_zero_model_preflight_hang_20260731
CONTENT {
    role: "active_pre_provider_blocker",
    created_at: d"2026-07-31T02:17:38Z"
};

RELATE trace_span:host_cli_01_instance_recovery_20260731t021738z
    ->verified_by:host_cli_01_instance_recovery_20260731t021738z
    ->verification_run:host_cli_01_instance_recovery_20260731t021738z
CONTENT {
    role: "instance_recovery_and_preflight_readback",
    created_at: d"2026-07-31T02:17:38Z"
};

COMMIT TRANSACTION;

RETURN {
    trace: trace_span:host_cli_01_instance_recovery_20260731t021738z,
    failure: failure_fingerprint:host_cli_01_opencode_zero_model_preflight_hang_20260731,
    verification: verification_run:host_cli_01_instance_recovery_20260731t021738z
};
