USE NS eliot DB system;

BEGIN TRANSACTION;

UPSERT evidence_atom:cognitive_completion_v2_blocked_report_20260729 CONTENT {
    project: "eliot-memory-os",
    kind: "cognitive_completion_v2_final_report",
    exact_text: "Detailed 339-line blocked-handoff report for Cognitive Completion v2. It records accepted C1-C6 implementation, material attempts, exact model receipts, all significant problems and resolutions, test durations, the terminal R01 metrics, Eliot readback, and the explicitly unexecuted certification phases.",
    normalized_claim: "The final report preserves the complete evidence-backed handoff without claiming certification beyond the failed R01 gate.",
    source_ref: source_snapshot:cognitive_completion_v2_contract_20260729,
    file_path: "C:/Users/kleym/OneDrive/Documents/Rust/projects/eliot-memory-os/reports/cognitive-field/COGNITIVE_COMPLETION_V2_BLOCKED_REPORT_20260729.md",
    checksum: "sha256:8f691e07215f8ad61171b1841c2f82d499632f8a31dac5979fd8a525028c079c",
    scope: {
        bytes: 23107,
        lines: 339,
        branch: "codex/cognitive-completion-v2",
        checked_head: "94af9197d1fbaea2438626d8e3d3d41cddf36eeb",
        disposition: "BLOCKED / FAILED_VERIFIER at R01"
    },
    observed_at: d"2026-07-29T12:47:52Z",
    lifecycle_status: "active",
    visibility: "project",
    recall_priority: 10,
    taint: "controller_report",
    tags: ["cognitive-completion-v2", "report", "blocked-handoff", "r01"]
};

UPDATE context_packet:cognitive_completion_v2_blocked_20260729t123511z SET
    evidence_refs = array::distinct(array::concat(
        evidence_refs,
        [evidence_atom:cognitive_completion_v2_blocked_report_20260729]
    ));

UPDATE task_contract:eliot_memory_os_cognitive_completion_v2_20260729 SET
    updated_at = d"2026-07-29T12:47:52Z";

COMMIT TRANSACTION;
