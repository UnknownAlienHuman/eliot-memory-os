### I3.3.1. Ecosystem Discovery Catalogue and managed external tools

The survey is driven by an ELIOT-owned `IntegrationDiscoveryCatalogue`. It is a versioned set of detection, probe, install/update and removal recipes; it is **not** a second Capability Registry and does not assert that anything is installed, healthy or supported. Observed installations and capabilities still enter the Governor-owned registry of I3.4 only through evidence.

```yaml
IntegrationDiscoveryCatalogueEntry:
  family_id:
  category: agent_runtime | editor_host | local_model_runtime | mcp_server |
            code_intelligence | database | toolchain | package_manager |
            browser_professional_tool | cloud_cli
  supported_platforms:
  known_executable_config_and_manifest_locations:
  safe_discovery_and_negative_capability_probes:
  official_install_update_remove_surfaces:
  required_execution_identity_and_credentials:
  license_supply_chain_and_privacy_notes:
  adapter_or_bridge_candidates:
  evidence_expiry_and_revalidation:
```

Initial discovery families are deliberately broader than the first production route set:

```text
agent runtimes/hosts:
  Codex App Server/CLI/Desktop;
  Claude Code/Desktop/Agent SDK;
  OpenCode;
  Gemini CLI;
  Cursor Agent/ACP;
  Zed Agent and external ACP agents;
  Antigravity;
  GitHub Copilot agent/CLI/SDK surfaces;
  Cline, Roo Code and Continue extension families;
  Kiro CLI, Goose, Aider, OpenHands and generic ACP/stdio agents;

local model runtimes:
  LM Studio/llmster;
  Ollama;
  admitted OpenAI-compatible local endpoints;

editors and professional hosts:
  Visual Studio Code, JetBrains IDEs, Zed, Visual Studio;
  registered browsers and professional applications;

development and data tools:
  Git/worktrees, Rustup/Cargo, rust-analyzer, nextest, Miri and admitted Cargo tools;
  SurrealDB and its exact managed generation;
  Codebase Memory MCP, RepoWise or another code-intelligence candidate;
  Docker/VM/laboratory, package managers and optional cloud CLIs.
```

Presence in this seed catalogue is not a popularity, quality or production-support claim. Each family needs an exact runtime/adapter fingerprint and capability evidence. Unknown or closed runtimes may be used through a bounded CLI/ACP/sidecar profile, but their internal database or UI state never becomes ELIOT recovery truth.

The seed is not a closed vendor enum. New families arrive as signed/versioned catalogue data or an admitted bridge manifest with origin, license, detection-only semantics and removal path; catalogue update cannot install software, grant credentials or advertise a capability by itself. The System Owner accepts catalogue revisions through the normal installation/configuration path; Installation Survey consumes them and Governor remains the sole owner of admitted capability state. The Human UI shows `discovered`, `declared`, `probed`, `admitted`, `degraded` and `unsupported` separately.

A Human, Main Agent or Dreamer may request installation, update, repair, removal or registration through a `ManagedEnvironmentChangeRequest`:

```yaml
ManagedEnvironmentChangeRequest:
  requester_and_reason:
  action: install | update | repair | remove | register | reconfigure
  target_family_and_exact_candidate:
  expected_capability_or_problem_delta:
  source_license_signature_and_dependency_closure:
  affected_routes_modules_workscopes_and_credentials:
  impact_class_and_required_owner:
  backup_rollback_or_forward_repair:
  verifier_and_post_change_probe:
  budget_and_stop_condition:
```

The request is compiled into the existing `InstallationTransaction`, Module-generation change or configuration transition. An agent or Dreamer never runs `winget`, `scoop`, `choco`, `npm`, `uv/pipx`, `cargo install`, an updater or a downloaded installer directly as authority. Package-manager output is evidence from an effect executor. Core storage updates require backup/restore and store-gate proof; optional code-intelligence tools begin as sealed pilots and may be removed without affecting canonical memory.

The generic environment planner never updates the active canonical store, Host, Kernel, Watchdog or their protected state in place. SurrealDB/store changes use the store-generation, backup, migration and cutover contracts; Host/Kernel/Watchdog changes use their own side-by-side generation/rollback paths. Code-intelligence servers, MCPs and agent runtimes may use the managed-tool path only behind a bridge manifest and capability requalification. Package-manager success is installation evidence, not production admission.

