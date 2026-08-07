BEGIN TRANSACTION;

UPSERT failure_fingerprint:ul11_exact_fetch_influence_context_rejection CONTENT {
    project: "eliot-memory-os",
    task_class: "ul11-certification",
    status: "resolved",
    lifecycle_status: "resolved",
    visibility: "normal",
    recall_priority: 10,
    trigger_pattern: "A treatment model performs recall_l0, fetch_l2 for the exact handle, then a minimal eliot_memory_influence_trace acknowledgement",
    failed_action_pattern: "The acknowledgement is rejected with MISSING_PROJECT_PACKET_CONTEXT even though the provider is bound to the exact task and just fetched the exact handle",
    observed_failure: "Claude B2 called recall_l0, exact fetch_l2 and eliot_memory_influence_trace; the server rejected the trace before the model compiled a generic control packet",
    why_it_failed: "TouchedSetRegistry remembered only compile_packet_l3 packet context; exact fetch results did not establish a same-session retrieval context usable by the minimal acknowledgement handler",
    violated_invariant: "Every documented treatment delivery path, including recall_l0 plus fetch_l2, must support a model-owned influence trace without requiring an unrelated L3 packet",
    affected_files_or_entities: [
        "crates/eliot-engine/src/ul/touched.rs",
        "crates/eliot-app/src/mcp_stdio/task_handlers.rs",
        "UL-11 B2 Claude treatment"
    ],
    required_discriminative_check: "Exact fetch must create a deterministic session/project/revision/handle-bound retrieval context; a different handle must be rejected; the accepted trace must not change truth revision",
    resolution: "Exact non-empty fetch_l2 results now establish retrieval:<blake3> context and exact handle set; minimal influence rejects mismatched handles and writes a model-owned trace only after an explicit model call",
    reopen_conditions: [
        "A fresh treatment session still receives MISSING_PROJECT_PACKET_CONTEXT after exact fetch",
        "A retrieval context accepts a handle not returned by that exact fetch",
        "Influence observability changes the truth revision"
    ],
    tags: ["ul11", "resolved", "fetch-l2", "influence-trace", "model-owned", "anti-falsification"],
    created_at: time::now(),
    resolved_at: time::now()
};

UPDATE failure_fingerprint:ul11_final_delivery_surface_receipt_mismatch SET
    status = "resolved",
    lifecycle_status = "resolved",
    why_it_failed = "Canonical injection receipts store internal transport surfaces mcp_auto_boot and mcp_response_piggyback, while the reader contract correctly exposes public surfaces ul_boot and ul_fired; the verifier compared them as identical strings and also lacked trace-backed pull-surface projection",
    required_discriminative_check = "Map internal push receipts to their public surface and require retrieval:* influence context for recall_l0/fetch_l2 or non-retrieval context for packet",
    resolution = "Verifier now binds exact session/task/handle receipts to public push mappings or model-owned influence context, retaining fail-closed unknown-surface rejection",
    resolved_at = time::now(),
    reopen_conditions = [
        "A known internal push surface cannot map to its public contract surface",
        "A pull surface passes without a matching exact-handle model-owned retrieval trace",
        "An unknown receipt surface passes verification"
    ];

UPDATE failure_fingerprint:ul11_final_claude_reader_missing_influence SET
    status = "mitigated_pending_live_verification",
    lifecycle_status = "active",
    why_it_failed = "The prior diagnosis was incorrect: Claude did call eliot_memory_influence_trace after recall_l0 and exact fetch_l2. ELIOT rejected that call with MISSING_PROJECT_PACKET_CONTEXT, then compile_packet_l3 assigned an unrelated generic memory_free_control arm and Claude returned a null receipt",
    required_discriminative_check = "Run one fresh Claude treatment case after the fetch-context repair and require a committed model-owned trace bound to exact project/task/session/handle with packet_id prefix retrieval:",
    reopen_conditions = [
        "Fresh Claude treatment does not call influence after exact fetch",
        "The server rejects the fresh exact-handle acknowledgement",
        "Canonical trace or observability receipt is not exact"
    ];

UPSERT evidence_atom:ul11_fetch_influence_repair_20260727 CONTENT {
    project: "eliot-memory-os",
    kind: "product_repair_verification",
    normalized_claim: "The UL-11 B2 influence failure was a server contract defect, not a provider omission; exact fetch context now supports a bounded model-owned minimal influence acknowledgement",
    exact_text: "Claude transcript tool sequence: Read relay_beta; ToolSearch; eliot_recall_l0; eliot_fetch_l2 exact handle; eliot_memory_influence_trace seen_but_not_used; server MISSING_PROJECT_PACKET_CONTEXT; compile_packet_l3 returned generic control arm. Local repair tests: TouchedSetRegistry 2 tests pass, 7.080s wall with 0.00s bodies; MCP exact-fetch smoke passes, 7.57s body and 26.165s wall after rebuild; legacy packet-context H2 plus exact-fetch H2 pass, 14.79s bodies and 15.111s wall warm; minimal packet acknowledgement regression passes, 8.08s body and 9.967s wall; cargo check 5.813s; clippy 13.431s.",
    scope: {
        phase: "UL-11",
        final_run_id: "ul-cross-agent-019fa36e-3c6b-74c1-9365-3f62bad6c3fe",
        hardware: "AMD Ryzen 9 9950X with fast RAM",
        provider_requested_route: "claude --model opus",
        provider_observed_model: "claude-opus-4-8",
        product_fix: "same-session exact fetch retrieval context plus strict handle binding",
        verifier_fix: "internal-to-public push mapping and influence-context-backed pull mapping"
    },
    taint: "tool_output",
    lifecycle_status: "active",
    visibility: "normal",
    recall_priority: 10,
    tags: ["ul11", "root-cause", "claude", "exact-fetch", "timing", "ryzen-9950x"],
    observed_at: time::now()
};

UPDATE evidence_atom:ul11_certification_timings_20260727 SET
    exact_text = "first full run 257.401s for 6 provider calls; Claude Code Opus 5 max consultation 407.4s for one no-tools request; regression unit gate 33.07s wall with 27.69s compile and 0.01s tests; cross-agent contract 0.83s wall and 0.61s tests; clean release build 91.363s; affected Antigravity Flash smoke 66.902s; final full run 605.432s for 8 provider calls; unknown outcomes 0; exact-fetch registry test 7.080s wall and 0.00s bodies; exact-fetch MCP smoke 7.57s body and 26.165s wall after rebuild; two warm H2 integration tests 14.79s bodies and 15.111s wall; minimal packet ack 8.08s body and 9.967s wall; cargo check 5.813s; clippy 13.431s",
    normalized_claim = "UL-11 wall time is dominated by external provider latency, optimized Rust linking, and per-test isolated SurrealDB/daemon startup; local pure test bodies remain fast on Ryzen 9 9950X",
    scope.interpretation = "Pure unit bodies are effectively instant. Integration bodies spend about 7-8 seconds each starting isolated SurrealDB and daemon; warm two-case wall closely matches summed bodies. The 91.363s clean release build and provider latency deserve separate future profiling, outside UL-11 acceptance."
;

UPSERT current_state:ul11_model_routing_20260727 CONTENT {
    project: "eliot-memory-os",
    phase: "UL-11",
    status: "active",
    routing_policy: {
        antigravity_default_smoke_model: "Gemini Flash",
        antigravity_escalation_model: "Claude Opus 4.6",
        claude_complex_escalation: "Claude Code Opus, Max only for genuinely complex ambiguity",
        rationale: "Model intelligence and tool-use reliability differ; cheap repeatable smokes should conserve scarce Opus quota"
    },
    observed_provider_resolution: {
        requested: "claude --model opus",
        observed: "claude-opus-4-8"
    },
    next_action: "Use local deterministic tests first; use Gemini Flash for cheap Antigravity smoke; reserve Opus for unresolved complex provider behavior",
    lifecycle_status: "active",
    visibility: "normal",
    updated_at: time::now()
};

UPSERT trace_span:ul11_fetch_influence_repair_20260727t123400z CONTENT {
    project: "eliot-memory-os",
    lane: "ul11_cross_agent_certification",
    outcome: "Exact fetch to influence contract and delivery-surface verifier repaired and locally verified; one fresh provider treatment remains required",
    expected_vs_observed_delta: "Expected Claude B2 to omit influence. Transcript proved Claude called it and ELIOT rejected it; local MCP smoke now accepts only the same-session exact fetched handle and preserves truth revision.",
    actions: [
        "Inspected canonical receipts and read-only run evidence",
        "Inspected Claude transcript tool events without exposing signed payloads or private reasoning",
        "Added deterministic exact-fetch retrieval context",
        "Added strict fetched-handle binding",
        "Mapped internal push receipt surfaces to public reader surfaces",
        "Required trace-backed evidence for pull and packet surfaces",
        "Recorded model-intelligence-aware routing policy"
    ],
    checks_run: [
        "eliot-engine touched-set unit regression",
        "UL MVP exact-fetch MCP integration smoke",
        "legacy and exact-fetch H2 context regressions",
        "minimal packet acknowledgement regression",
        "UL cross-agent delivery-surface unit regression",
        "cargo check -p eliot-app --all-targets",
        "cargo clippy -p eliot-engine -p eliot-app --all-targets -- -D warnings",
        "git diff --check"
    ],
    tools_used: ["cargo", "git", "rg", "Claude transcript evidence", "SurrealDB MCP"],
    task_ref: task_contract:eliot_memory_os_ul11_20260725,
    report: "C:/Users/kleym/Downloads/ELIOT_UL11R_UL12_EXECUTION_REPORT_20260727.md",
    lifecycle_status: "active",
    visibility: "normal",
    recall_priority: 10,
    tags: ["ul11", "trace", "product-fix", "exact-fetch", "timing"],
    created_at: time::now(),
    updated_at: time::now()
};

COMMIT TRANSACTION;

RETURN {
    repaired_failure: (SELECT id, status, lifecycle_status, resolution FROM failure_fingerprint:ul11_exact_fetch_influence_context_rejection),
    surface_failure: (SELECT id, status, lifecycle_status, resolution FROM failure_fingerprint:ul11_final_delivery_surface_receipt_mismatch),
    claude_failure: (SELECT id, status, lifecycle_status, why_it_failed FROM failure_fingerprint:ul11_final_claude_reader_missing_influence),
    repair_evidence: (SELECT id, normalized_claim, scope FROM evidence_atom:ul11_fetch_influence_repair_20260727),
    timing_evidence: (SELECT id, exact_text, normalized_claim FROM evidence_atom:ul11_certification_timings_20260727),
    model_routing: (SELECT id, routing_policy, observed_provider_resolution FROM current_state:ul11_model_routing_20260727),
    trace: (SELECT id, outcome, actions, checks_run FROM trace_span:ul11_fetch_influence_repair_20260727t123400z)
};
