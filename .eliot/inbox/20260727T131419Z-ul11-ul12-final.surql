USE NS eliot DB system;

BEGIN TRANSACTION;

UPDATE failure_fingerprint:ul11_final_claude_reader_missing_influence MERGE {
    status: "resolved",
    lifecycle_status: "resolved",
    resolved_at: d"2026-07-27T13:14:19Z",
    resolution: "Claude had called eliot_memory_influence_trace; the server rejected the call because exact fetch_l2 did not establish bound context. Exact-fetch context and fetched-handle binding were added, then fresh reciprocal run ul-cross-agent-019fa39f-64a1-7321-ad19-077ffb616486 produced an exact same-session model-owned retrieval:* trace."
};

UPDATE failure_fingerprint:ul11_final_delivery_surface_receipt_mismatch MERGE {
    status: "resolved",
    lifecycle_status: "resolved",
    resolved_at: d"2026-07-27T13:14:19Z",
    resolution: "The verifier now maps internal mcp_auto_boot and mcp_response_piggyback receipts to public ul_boot and ul_fired surfaces, while recall_l0, fetch_l2, and packet remain fail-closed and require the matching model-owned influence context. Fresh reciprocal run passed both directions."
};

UPDATE failure_fingerprint:ul11_final_full_rerun_budget_exhausted MERGE {
    status: "resolved",
    lifecycle_status: "resolved",
    resolved_at: d"2026-07-27T13:14:19Z",
    resolution: "The earlier run budget belonged to the superseded bounded attempt. The user explicitly opened a new full-goal attempt without an attempt cap, and transcript plus immutable receipt evidence proved a new product defect before the fresh run. The new run passed 8/8 with zero unknown outcomes."
};

UPSERT failure_fingerprint:ul11r3_stale_custom_agent_readiness CONTENT {
    affected_files_or_entities: [
        "crates/eliot-app/src/commands/antigravity.rs",
        "crates/eliot-engine/src/antigravity.rs",
        "crates/eliot-engine/tests/antigravity_runtime.rs",
        "Antigravity official installation receipt"
    ],
    created_at: d"2026-07-27T13:14:19Z",
    failed_action_pattern: "Fresh install-official failed after R1 correctly removed the custom eliot-agent package",
    lifecycle_status: "resolved",
    observed_failure: "Readiness and installation receipt still required agent_visible=true, so a previously installed stale custom-agent file could make readiness appear green",
    project: "eliot-memory-os",
    recall_priority: 10,
    reopen_conditions: [
        "Default-agent official package fails readiness with skills, rules, schema and GUI MCP present",
        "A stale custom agent changes the readiness verdict",
        "Official installation again requires --agent eliot-agent"
    ],
    required_discriminative_check: "Install into a fresh Antigravity package root without agents/eliot-agent.md and require installed/schema/skills/rules/MCP readiness while preserving agent_visible=false as an observed fact",
    resolved_at: d"2026-07-27T13:14:19Z",
    resolution: "Readiness and the install receipt now follow the architecture-aligned default-agent contract. A regression proves agent_visible remains false and nonblocking; fresh install-official and doctor pass.",
    status: "resolved",
    tags: ["ul11r3", "antigravity", "stale-state", "default-agent", "readiness"],
    task_class: "ul11-certification",
    trigger_pattern: "R1 removes the prohibited custom agent while stale readiness logic still treats it as mandatory",
    violated_invariant: "Antigravity must use its default agent and official skills/MCP package without requiring a custom agent",
    visibility: "normal",
    why_it_failed: "The architecture repair removed the custom package but an older readiness predicate and receipt predicate were not changed in the same pass; a stale installed file masked the mismatch"
};

UPSERT evidence_atom:ul11_ul12_final_certification_20260727 CONTENT {
    exact_text: "Fresh release package smokes passed: Antigravity Gemini 3.6 Flash High 24.590s and Claude Sonnet 31.848s. Blind reciprocal run ul-cross-agent-019fa39f-64a1-7321-ad19-077ffb616486 completed exactly 8/8 calls in 347.327s, both directions passed all 14 checks, and unknown outcomes were zero. A2 and B2 each had same-session exact-handle retrieval:* model-owned influence. Focused UL-12 suites passed. cargo fmt/check/clippy passed; just verify passed in 367.242s; cargo test --workspace passed 131 result groups with zero failures in 293.013s. ul_mvp_done was the slowest required suite at 77.38s; two consecutive incremental optimized release builds took 121.480s and 121.982s.",
    id: evidence_atom:ul11_ul12_final_certification_20260727,
    kind: "certification_evidence",
    lifecycle_status: "active",
    normalized_claim: "ELIOT Understanding Layer v1.4 and native Codex, Claude Code, and Antigravity packages satisfy UL-11 and UL-12 acceptance on the certified branch state",
    observed_at: d"2026-07-27T13:14:19Z",
    project: "eliot-memory-os",
    recall_priority: 10,
    scope: {
        antigravity_smoke: "ul11r3-smoke-antigravity-019fa39d-c9e6-71e3-b99f-25f9b2b0dfac",
        claude_smoke: "ul11r3-smoke-claude-019fa39e-3d6a-7682-9b4c-ad9d9802d1f6",
        hardware: "AMD Ryzen 9 9950X with fast RAM",
        provider_run: "ul-cross-agent-019fa39f-64a1-7321-ad19-077ffb616486",
        provider_run_seconds: 347.327,
        release_build_seconds: [121.480, 121.982],
        workspace_test_seconds: 293.013
    },
    tags: ["ul11", "ul12", "certification", "cross-agent", "timing", "ryzen-9950x"],
    taint: "tool_output",
    visibility: "normal"
};

UPDATE evidence_atom:ul11_certification_timings_20260727 MERGE {
    exact_text: "first full run 257.401s for 6 calls; Opus max consultation 407.4s; second diagnostic full run 605.432s for 8 calls; focused exact-fetch and surface regressions passed; two consecutive incremental optimized release builds 121.480s and 121.982s; final Antigravity Flash smoke 24.590s; final Claude Sonnet smoke 31.848s; certified reciprocal run 347.327s for 8/8 calls with zero unknowns; focused ul_mvp_done 79.966s wall and 77.94s body; just verify 367.242s; cargo test --workspace 293.013s, 131 result groups, zero failed; slowest workspace result group 77.38s",
    normalized_claim: "On Ryzen 9 9950X, pure unit and contract bodies are fast; the material costs are isolated daemon fixtures, optimized Rust link/codegen, and provider latency. Fixture and linker profiling are separate non-blocking follow-up work.",
    observed_at: d"2026-07-27T13:14:19Z",
    scope: {
        final_run_id: "ul-cross-agent-019fa39f-64a1-7321-ad19-077ffb616486",
        hardware: "AMD Ryzen 9 9950X with fast RAM",
        interpretation: "ul_mvp_done intentionally starts isolated SurrealDB/Governor fixtures and costs about 77-80 seconds. Two back-to-back incremental optimized builds each cost about 122 seconds, indicating linker/codegen debt worth profiling separately without weakening isolation.",
        phase: "UL-11 and UL-12"
    },
    tags: ["ul11", "ul12", "timing", "ryzen-9950x", "fixture-startup", "release-link"]
};

UPSERT verification_run:eliot_ul_v1_4_final_20260727 CONTENT {
    command_or_tool_call: "focused UL suites; cargo fmt/check/clippy; just verify; cargo test --workspace; fresh provider smokes; eliot-governor ul cross-agent run",
    cwd: "C:\\Users\\kleym\\OneDrive\\Documents\\Rust\\projects\\eliot-memory-os",
    diagnostics: [
        "Both reciprocal directions passed all 14 canonical checks",
        "Exactly 8 provider calls and zero unknown provider outcomes",
        "Memory-free controls remained clean and truth revision moved only for candidate writes",
        "All required focused and workspace verification gates passed",
        "Long-test follow-up isolated to fixture startup and optimized link/codegen profiling"
    ],
    id: verification_run:eliot_ul_v1_4_final_20260727,
    observed_at: d"2026-07-27T13:14:19Z",
    output_excerpt: "UL-11 PASS; UL-12 PASS; final run ul-cross-agent-019fa39f-64a1-7321-ad19-077ffb616486; just verify 367.242s; workspace tests 293.013s",
    project: "eliot-memory-os",
    result: "pass",
    tool: "Cargo, Just, ELIOT governor, Claude Code, Antigravity"
};

UPSERT claim_card:eliot_ul_v1_4_complete_20260727 CONTENT {
    authority: "local_certification",
    branch_env_scope: {
        branch: "codex/ul-cross-agent-certification",
        environment: "Windows local"
    },
    epistemic_grade: "high",
    id: claim_card:eliot_ul_v1_4_complete_20260727,
    known_from: d"2026-07-27T13:14:19Z",
    lifecycle_status: "active",
    project: "eliot-memory-os",
    proposition: "ELIOT Understanding Layer v1.4 implementation, native host packages, and blind reciprocal Claude Code to Antigravity memory transfer meet the UL-11 and UL-12 certification contract on the certified branch state.",
    recall_priority: 10,
    scope: {
        branch: "codex/ul-cross-agent-certification",
        run_id: "ul-cross-agent-019fa39f-64a1-7321-ad19-077ffb616486",
        task_id: "ELIOT_UL11R_ARCHITECTURE_ALIGNED_MASTER_v3_0"
    },
    status: "verified",
    subject: "ELIOT Understanding Layer v1.4 completion",
    tags: ["ul11", "ul12", "verified", "native-packages", "blind-memory-transfer"],
    transaction_from: d"2026-07-27T13:14:19Z",
    valid_from: d"2026-07-27T13:14:19Z",
    visibility: "normal"
};

RELATE evidence_atom:ul11_ul12_final_certification_20260727->supports->claim_card:eliot_ul_v1_4_complete_20260727;
RELATE claim_card:eliot_ul_v1_4_complete_20260727->verified_by->verification_run:eliot_ul_v1_4_final_20260727
    CONTENT {
        role: "certification-verifier",
        test_id: "ul11-ul12-final-20260727"
    };

UPSERT current_state:ul11_ul12_final_20260727 CONTENT {
    id: current_state:ul11_ul12_final_20260727,
    project: "eliot-memory-os",
    lifecycle_status: "active",
    recall_priority: 10,
    status: "certified_pending_delivery",
    summary: "UL-11 and UL-12 are locally certified. Required product repairs, exact provider receipts, focused tests, workspace gates, duration analysis, status docs, and external Markdown report are complete; GitHub PR, review, CI, merge, and main CI remain the delivery tail.",
    tags: ["ul11", "ul12", "current-state", "delivery"],
    updated_at: d"2026-07-27T13:14:19Z",
    visibility: "normal"
};

UPSERT trace_span:ul11_ul12_final_20260727t131419z CONTENT {
    actions: [
        "Reproduced and diagnosed exact-fetch influence rejection from immutable Claude tool-call transcript",
        "Added deterministic exact-fetch context and strict fetched-handle binding",
        "Mapped internal push receipts to public UL delivery surfaces without weakening pull/packet verification",
        "Removed stale custom-agent readiness dependency from the default-agent Antigravity contract",
        "Rebuilt and reinstalled native provider packages and governor",
        "Ran cheap final provider smokes with Antigravity Flash and Claude Sonnet",
        "Used the scarce Opus route only for the high-value reciprocal certification",
        "Ran focused UL-12 suites and full release gates",
        "Measured and classified slow tests and optimized builds",
        "Updated the three permitted UL-12 status documents and detailed external report"
    ],
    checks_run: [
        "Antigravity official install and doctor",
        "Claude package doctor",
        "Antigravity Flash provider smoke",
        "Claude Sonnet provider smoke",
        "blind reciprocal eight-call certification",
        "all required focused UL suites",
        "cargo fmt --all -- --check",
        "cargo check --workspace --all-targets",
        "cargo clippy --workspace --all-targets -- -D warnings",
        "just verify",
        "cargo test --workspace",
        "git diff --check"
    ],
    created_at: d"2026-07-27T13:14:19Z",
    expected_vs_observed_delta: "Earlier evidence was misread as a missing Claude influence call. Exact transcript inspection proved server rejection after the call. After the bound-context repair and receipt mapping, fresh provider evidence passed both directions with exact model ownership and no unknown outcomes.",
    id: trace_span:ul11_ul12_final_20260727t131419z,
    lane: "ul11_ul12_completion",
    lifecycle_status: "active",
    outcome: "UL-11 and UL-12 locally certified; delivery tail pending",
    project: "eliot-memory-os",
    recall_priority: 10,
    report: "C:/Users/kleym/Downloads/ELIOT_UL11R_UL12_EXECUTION_REPORT_20260727.md",
    tags: ["ul11", "ul12", "trace", "certification", "timing"],
    tools_used: ["Cargo", "Just", "Git", "ELIOT governor", "SurrealDB MCP", "Claude Code", "Antigravity"],
    updated_at: d"2026-07-27T13:14:19Z",
    visibility: "normal"
};

COMMIT TRANSACTION;
