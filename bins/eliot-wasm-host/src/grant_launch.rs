//! Governed grant launch path (issue #1955, I14.19).
//!
//! The dedicated executable consumer for the Kernel port grant: one process
//! invocation performs exactly one governed launch — front-door channel
//! binding, grant-request bundle from real bytes, authenticated transport
//! request, authorization against the live installation descriptor,
//! installed-binary resolution, and isolated-child engine staging. Every
//! stage fails closed with a stage-taxonomy [`GrantLaunchError`]; no stage
//! mints admission, grant, or dispatch authority.
//!
//! Trust model, stage by stage:
//! - Channel/session facts (pipe, Kernel SID/session/artifact, timeout) are
//!   explicit staged argv decoded by the CLI contract — never probed,
//!   defaulted, or read from ambient process state. The transport proves
//!   them against the live Kernel server before anything is sent (peer
//!   binding, correlation, wire accept).
//! - Component bytes come from the staged artifact file (bounded,
//!   preflighted); the interface digest comes from the frozen WIT bytes —
//!   both re-hashed, never trusted from any party.
//! - The installation descriptor file is parsed then self-validated by the
//!   B2/installer lane on every read (`wasm_host_artifact_binding`); this
//!   module only reshapes the validated pair.
//! - Local policy constrains only local staging (timeout ceiling, deadline
//!   freshness, component pin): it never admits, issues, or dispatches.
//! - The output [`GrantLaunchReceipt`] stages the verified launch: the
//!   engine binding it derives is the exact binding the future seating
//!   will use. Actually constructing the [`IsolatedChildEngine`] and
//!   dispatching the P03 child require the P-07 dispatch authority and the
//!   admitted `RuntimePorts` — owner lanes B1 must not mint — so this path
//!   stops at the staged receipt. No fabrication anywhere.
//!
//! Failure discipline: stable `stage:field` codes only. No paths, bytes,
//! digests, or descriptor content are echoed.

use std::path::Path;

use eliot_wasm_runtime::{EngineBinding, Sha256Digest};

use crate::artifact_preflight::{PreflightError, read_bounded_artifact};
use crate::child_engine::ISOLATED_CHILD_IMPLEMENTATION_ID;
use crate::cli_contract::GrantLaunchArgs;
use crate::contour::PINNED_WASMTIME_VERSION;
use crate::grant_authorization::{AuthorizedGrant, authorize_grant_against_descriptor};
use crate::grant_client::{
    GrantChannel, GrantClientError, build_grant_bundle, request_grant_via_transport,
};
use crate::installed_binary::{InstalledBinary, InstalledBinaryError, resolve_installed_binary};
use crate::wasmtime_provider::provider_configuration_digest;

/// Allocation guard for the installation descriptor file: JSON text of a
/// few dozen short handles. Anything larger is rejected before parsing.
pub const GRANT_DESCRIPTOR_MAX_BYTES: u64 = 64 * 1024;

/// Local connect-timeout ceiling (ms): the channel already requires
/// non-zero; the policy caps absence-of-server waits.
pub const GRANT_CONNECT_TIMEOUT_MAX_MS: u64 = 60_000;

/// Fail-closed launch error: the pipeline stage plus the stable offending
/// field. No paths, bytes, or digests are echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantLaunchError {
    /// Pipeline stage that denied (`channel`, `policy`, `descriptor`,
    /// `artifact`, `bundle`, `transport`, `authorize`, `resolve`).
    pub stage: &'static str,
    /// Stable field within the stage.
    pub field: &'static str,
}

impl std::fmt::Display for GrantLaunchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "GRANT_LAUNCH_DENIED:stage={}:field={}",
            self.stage, self.field
        )
    }
}

impl std::error::Error for GrantLaunchError {}

/// Staged verified launch: every digest re-proven, every binding matched.
///
/// The isolated-child engine seating consumes exactly this receipt once the
/// owner lanes supply dispatch authority; until then it is proof the
/// executable consumer path ran end-to-end against real external systems.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrantLaunchReceipt {
    /// Admitted component identity, pinned from argv to grant.
    pub component_id: String,
    /// Grant-proven artifact digest (hex).
    pub artifact_digest: String,
    /// Grant-proven interface digest (hex).
    pub interface_digest: String,
    /// Installation-approved host digest the binary resolved against (hex).
    pub host_artifact_digest: String,
    /// Seated engine implementation identity.
    pub engine_implementation_id: String,
    /// Engine artifact digest: the resolved installed image (hex).
    pub engine_artifact_digest: String,
    /// Caller nonce echoed from issuance.
    pub nonce: String,
    /// Deadline echoed from issuance.
    pub deadline_unix_ms: u64,
}

/// Reads one staged descriptor file into bounded bytes. Allocation-guarded
/// like the artifact path: declared size pre-checked, growth re-checked.
fn read_bounded_descriptor(path: &Path) -> Result<Vec<u8>, GrantLaunchError> {
    let denied = |field: &'static str| GrantLaunchError {
        stage: "descriptor",
        field,
    };
    let metadata = std::fs::metadata(path).map_err(|_| denied("unreadable"))?;
    if metadata.len() > GRANT_DESCRIPTOR_MAX_BYTES {
        return Err(denied("too_large"));
    }
    let bytes = std::fs::read(path).map_err(|_| denied("unreadable"))?;
    if bytes.is_empty() {
        return Err(denied("empty"));
    }
    if bytes.len() as u64 > GRANT_DESCRIPTOR_MAX_BYTES {
        return Err(denied("too_large"));
    }
    Ok(bytes)
}

/// Current unix time in milliseconds for deadline freshness.
fn now_unix_ms() -> Result<u64, GrantLaunchError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .map_err(|_| GrantLaunchError {
            stage: "policy",
            field: "clock",
        })
}

/// Derives the exact isolated-child engine binding the future seating will
/// use: grant-proven component digests are already inside the engine via
/// [`for_authorized_grant`](crate::child_engine::IsolatedChildEngine::for_authorized_grant);
/// this binding names the engine implementation, the pinned provider
/// version and configuration, the resolved installed image, and the frozen
/// WIT identity. Pure data — no authority, no launch.
pub fn grant_engine_binding(installed: &InstalledBinary) -> EngineBinding {
    EngineBinding {
        implementation_id: ISOLATED_CHILD_IMPLEMENTATION_ID.to_owned(),
        exact_version: PINNED_WASMTIME_VERSION.to_owned(),
        engine_artifact_digest: installed.digest().clone(),
        engine_configuration_digest: provider_configuration_digest(),
        wit_interface_digest: Sha256Digest::of_bytes(crate::wasmtime_provider::guest_wit_bytes()),
    }
}

/// Binds and shape-checks the staged channel facts. Pure: no I/O.
fn launch_channel(args: &GrantLaunchArgs) -> Result<GrantChannel, GrantLaunchError> {
    let channel = GrantChannel {
        pipe_name: args.pipe_name.clone(),
        kernel_sid: args.kernel_sid.clone(),
        kernel_session_id: args.kernel_session_id,
        kernel_artifact_sha256: args.kernel_artifact_sha256.clone(),
        connect_timeout_ms: args.connect_timeout_ms,
    };
    channel.validate().map_err(|error| match error {
        GrantClientError::Denied { field } | GrantClientError::InvalidField { field } => {
            GrantLaunchError {
                stage: "channel",
                field,
            }
        }
        _ => GrantLaunchError {
            stage: "channel",
            field: "channel",
        },
    })?;
    Ok(channel)
}

/// Enforces local staging policy: timeout ceiling and deadline freshness.
/// Pure clock read plus bounds; never an admission decision.
fn check_launch_policy(args: &GrantLaunchArgs, now_unix_ms: u64) -> Result<(), GrantLaunchError> {
    if args.connect_timeout_ms > GRANT_CONNECT_TIMEOUT_MAX_MS {
        return Err(GrantLaunchError {
            stage: "policy",
            field: "connect_timeout_ms",
        });
    }
    if args.deadline_unix_ms <= now_unix_ms {
        return Err(GrantLaunchError {
            stage: "policy",
            field: "deadline_unix_ms",
        });
    }
    Ok(())
}

/// Reads the staged inputs: descriptor file (bounded, parsed — validated
/// later at auth), artifact file (bounded, preflighted), and the frozen
/// WIT bytes. Real filesystem reads, fail-closed per stage.
fn read_launch_inputs(
    args: &GrantLaunchArgs,
) -> Result<
    (
        eliot_installation::RuntimeLaunchDescriptor,
        Vec<u8>,
        Vec<u8>,
    ),
    GrantLaunchError,
> {
    let descriptor_bytes = read_bounded_descriptor(&args.descriptor_path)?;
    let descriptor: eliot_installation::RuntimeLaunchDescriptor =
        serde_json::from_slice(&descriptor_bytes).map_err(|_| GrantLaunchError {
            stage: "descriptor",
            field: "parse",
        })?;
    let (artifact_bytes, _preflight) =
        read_bounded_artifact(&args.artifact_path).map_err(|error| {
            let field = match error {
                PreflightError::Empty => "empty",
                PreflightError::TooLarge { .. } => "too_large",
                PreflightError::MalformedPreamble => "preamble",
                PreflightError::CoreModuleRejected => "core_module",
                PreflightError::Unreadable(_) => "unreadable",
            };
            GrantLaunchError {
                stage: "artifact",
                field,
            }
        })?;
    Ok((
        descriptor,
        artifact_bytes,
        crate::wasmtime_provider::guest_wit_bytes().to_vec(),
    ))
}

/// Builds the request bundle from real bytes and performs the authenticated
/// transport request. The only stage that touches the network-adjacent
/// external system (the local front-door pipe).
fn request_accepted_grant(
    args: &GrantLaunchArgs,
    artifact_bytes: &[u8],
    wit_bytes: &[u8],
    channel: &GrantChannel,
    channel_fence: &eliot_contracts::StateFence,
) -> Result<crate::grant_client::AcceptedGrant, GrantLaunchError> {
    let bundle = build_grant_bundle(
        &args.component_id,
        artifact_bytes,
        wit_bytes,
        &args.nonce,
        args.deadline_unix_ms,
    )
    .map_err(|error| match error {
        GrantClientError::InvalidField { field } => GrantLaunchError {
            stage: "bundle",
            field,
        },
        _ => GrantLaunchError {
            stage: "bundle",
            field: "bundle",
        },
    })?;
    request_grant_via_transport(&bundle, channel, channel_fence).map_err(|error| match error {
        GrantClientError::Denied { field } | GrantClientError::InvalidField { field } => {
            GrantLaunchError {
                stage: "transport",
                field,
            }
        }
        GrantClientError::Expired => GrantLaunchError {
            stage: "transport",
            field: "expired",
        },
        GrantClientError::NoTransport => GrantLaunchError {
            stage: "transport",
            field: "transport",
        },
    })
}

/// Authorizes the served grant against the live descriptor and staged
/// bytes, re-pins the component identity, and resolves the installed
/// binary. Real descriptor validation plus real filesystem verification.
fn authorize_and_resolve(
    args: &GrantLaunchArgs,
    accepted: &crate::grant_client::AcceptedGrant,
    descriptor: &eliot_installation::RuntimeLaunchDescriptor,
    artifact_bytes: &[u8],
    wit_bytes: &[u8],
) -> Result<(AuthorizedGrant, InstalledBinary), GrantLaunchError> {
    let authorized: AuthorizedGrant =
        authorize_grant_against_descriptor(accepted, descriptor, artifact_bytes, wit_bytes)
            .map_err(|error| match error {
                GrantClientError::Denied { field } | GrantClientError::InvalidField { field } => {
                    GrantLaunchError {
                        stage: "authorize",
                        field,
                    }
                }
                GrantClientError::Expired => GrantLaunchError {
                    stage: "authorize",
                    field: "expired",
                },
                GrantClientError::NoTransport => GrantLaunchError {
                    stage: "authorize",
                    field: "transport",
                },
            })?;
    if authorized.component_id() != args.component_id {
        return Err(GrantLaunchError {
            stage: "policy",
            field: "component_id",
        });
    }
    let installed = resolve_installed_binary(authorized.host_binding()).map_err(|error| {
        let field = match error {
            InstalledBinaryError::EmptyPath => "empty_path",
            InstalledBinaryError::Empty => "empty",
            InstalledBinaryError::NotAFile => "not_a_file",
            InstalledBinaryError::Unreadable(_) => "unreadable",
            InstalledBinaryError::DigestMismatch => "digest_mismatch",
            InstalledBinaryError::DescriptorInvalid => "descriptor_invalid",
        };
        GrantLaunchError {
            stage: "resolve",
            field,
        }
    })?;
    Ok((authorized, installed))
}

/// Performs one governed grant launch: channel → policy → descriptor →
/// artifact → bundle → transport → authorize → pin → resolve → stage.
///
/// The transport stage performs real external I/O against the live Kernel
/// front-door server and fails closed (including while Beauvoir's
/// `wasm_port_grant_issue` registration is absent — the server denies the
/// unknown operation). Later stages run only on a wire-accepted grant.
///
/// # Errors
///
/// Returns [`GrantLaunchError`] with the denying stage and field when any
/// check fails.
pub fn run_grant_launch(args: &GrantLaunchArgs) -> Result<GrantLaunchReceipt, GrantLaunchError> {
    let channel = launch_channel(args)?;
    let now = now_unix_ms()?;
    check_launch_policy(args, now)?;
    let (descriptor, artifact_bytes, wit_bytes) = read_launch_inputs(args)?;
    let accepted = request_accepted_grant(
        args,
        &artifact_bytes,
        &wit_bytes,
        &channel,
        &descriptor.authority_state_fence,
    )?;
    let (authorized, installed) =
        authorize_and_resolve(args, &accepted, &descriptor, &artifact_bytes, &wit_bytes)?;
    let engine = grant_engine_binding(&installed);
    Ok(GrantLaunchReceipt {
        component_id: authorized.component_id().to_owned(),
        artifact_digest: authorized.artifact_digest().as_str().to_owned(),
        interface_digest: authorized.interface_digest().as_str().to_owned(),
        host_artifact_digest: authorized
            .host_binding()
            .artifact_digest()
            .as_str()
            .to_owned(),
        engine_implementation_id: engine.implementation_id.clone(),
        engine_artifact_digest: engine.engine_artifact_digest.as_str().to_owned(),
        nonce: authorized.nonce().to_owned(),
        deadline_unix_ms: authorized.deadline_unix_ms(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cli_contract::GrantLaunchArgs;
    use crate::typed_bindings::TypedWorld;
    use eliot_wasm_runtime::Sha256Digest;

    fn launch_args() -> GrantLaunchArgs {
        launch_args_for("shared")
    }

    fn launch_args_for(tag: &str) -> GrantLaunchArgs {
        GrantLaunchArgs {
            pipe_name: "definitely-not-a-pipe-1955".to_owned(),
            kernel_sid: "S-1-5-18".to_owned(),
            kernel_session_id: 1,
            kernel_artifact_sha256: "a".repeat(64),
            connect_timeout_ms: 250,
            component_id: "component-1955".to_owned(),
            artifact_path: std::env::temp_dir()
                .join(format!("eliot-1955-grant-launch-{tag}-artifact.bin")),
            world: TypedWorld::ContextAdmission,
            descriptor_path: std::env::temp_dir()
                .join(format!("eliot-1955-grant-launch-{tag}-descriptor.json")),
            nonce: "nonce-1955".to_owned(),
            deadline_unix_ms: 9_999_999_999_999,
        }
    }

    fn component_bytes() -> Vec<u8> {
        let mut bytes = b"\x00asm\x02\x00\x00\x00".to_vec();
        bytes.extend_from_slice(b"grant-launch-component-body");
        bytes
    }

    fn descriptor_json() -> Vec<u8> {
        // Shape-exact but unvalidated records: parsing succeeds here while
        // the descriptor's own validation still rejects at auth time. Keys
        // mirror `RuntimeLaunchDescriptor` exactly (`deny_unknown_fields`).
        r#"{
            "profile": "portable_dev",
            "portable_root": null,
            "installation_epoch": {
                "installation": "installation:test",
                "lineage_id": "lineage:test",
                "sequence": 1
            },
            "generation": "generation:test",
            "authority_generation": 1,
            "authority_state_fence": {
                "authority_epoch": {
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 1
                },
                "resource_generation": 1,
                "task_revision": null,
                "policy_revision": null,
                "integration_revision": null
            },
            "authority_descriptor_path": "authority.json",
            "authority_descriptor_digest": "7777777777777777777777777777777777777777777777777777777777777777",
            "supervision_authority": {
                "state": "PENDING",
                "supervision_lease_scope_id": "test-supervision-scope"
            },
            "runtime_state_roots": {
                "profile": "portable_dev",
                "profile_anchor_root": "anchor",
                "installation_root": "installation",
                "host_state_root": "host-state",
                "kernel_ors_root": "ors",
                "kernel_work_root": "work",
                "store_data_root": "data",
                "store_work_root": "store-work",
                "store_temp_root": "temp",
                "watchdog_state_root": "watchdog",
                "roots_digest": "r"
            },
            "kernel_work_root": "work",
            "kernel_artifact_digest": "4444444444444444444444444444444444444444444444444444444444444444",
            "eliotd_executable_path": "eliotd.exe",
            "eliotd_artifact_digest": "8888888888888888888888888888888888888888888888888888888888888888",
            "eliotd_config_path": "eliotd-governor.json",
            "eliotd_config_digest": "4444444444444444444444444444444444444444444444444444444444444444",
            "protected_snapshot_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "eliotd_descriptor_path": "eliotd.json",
            "eliotd_descriptor_digest": "9999999999999999999999999999999999999999999999999999999999999999",
            "eliotd_launch_nonce": "eliotd:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "store_config_path": "generation.json",
            "store_credential_target": "eliot/store/v1/0123456789abcdef0123456789abcdef",
            "store_bridge_executable_path": "eliot-store-surreal.exe",
            "store_bridge_artifact_digest": "1111111111111111111111111111111111111111111111111111111111111111",
            "store_bootstrap_descriptor_path": "store-bootstrap.json",
            "store_bootstrap_descriptor_digest": "6666666666666666666666666666666666666666666666666666666666666666",
            "canonical_store_executable_path": "surreal.exe",
            "canonical_store_artifact_digest": "5555555555555555555555555555555555555555555555555555555555555555",
            "kernel_arguments": [],
            "store_bridge_arguments": [],
            "canonical_store_arguments": [],
            "host_executable_path": "eliot-host.exe",
            "host_artifact_digest": "8888888888888888888888888888888888888888888888888888888888888888",
            "watchdog_executable_path": "eliot-watchdog.exe",
            "watchdog_artifact_digest": "4444444444444444444444444444444444444444444444444444444444444444",
            "doctor_artifact_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "testd_artifact_digest": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "native_worker_artifact_digest": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
            "wasm_host_artifact_digest": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "doctor_executable_path": "eliot-doctor.exe",
            "testd_executable_path": "eliot-testd.exe",
            "native_worker_executable_path": "eliot-native-worker.exe",
            "wasm_host_executable_path": "eliot-wasm-host.exe",
            "descriptor_digest": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        }"#
        .as_bytes()
        .to_vec()
    }

    fn write_fixtures(args: &GrantLaunchArgs) {
        std::fs::write(&args.artifact_path, component_bytes()).expect("artifact fixture");
        std::fs::write(&args.descriptor_path, descriptor_json()).expect("descriptor fixture");
    }

    fn remove_fixtures(args: &GrantLaunchArgs) {
        let _ = std::fs::remove_file(&args.artifact_path);
        let _ = std::fs::remove_file(&args.descriptor_path);
    }

    #[test]
    fn local_policy_denies_before_any_io() {
        // Over-ceiling timeout fails before the filesystem or network is
        // touched: the fixture paths do not exist.
        let mut args = launch_args();
        args.connect_timeout_ms = GRANT_CONNECT_TIMEOUT_MAX_MS + 1;
        assert_eq!(
            run_grant_launch(&args),
            Err(GrantLaunchError {
                stage: "policy",
                field: "connect_timeout_ms"
            })
        );
        // A past deadline is already unservable: fail fast, no I/O.
        let mut args = launch_args();
        args.deadline_unix_ms = 1;
        assert_eq!(
            run_grant_launch(&args),
            Err(GrantLaunchError {
                stage: "policy",
                field: "deadline_unix_ms"
            })
        );
        // A blank pipe fails channel shape before any connect is attempted.
        let mut args = launch_args();
        args.pipe_name.clear();
        assert_eq!(
            run_grant_launch(&args),
            Err(GrantLaunchError {
                stage: "channel",
                field: "channel"
            })
        );
    }

    #[test]
    fn unreadable_descriptor_fails_closed() {
        let args = launch_args_for("unreadable");
        remove_fixtures(&args);
        assert_eq!(
            run_grant_launch(&args),
            Err(GrantLaunchError {
                stage: "descriptor",
                field: "unreadable"
            })
        );
    }

    #[test]
    fn malformed_descriptor_fails_closed() {
        let args = launch_args_for("malformed");
        remove_fixtures(&args);
        std::fs::write(&args.descriptor_path, b"{not-json").expect("descriptor fixture");
        assert_eq!(
            run_grant_launch(&args),
            Err(GrantLaunchError {
                stage: "descriptor",
                field: "parse"
            })
        );
        remove_fixtures(&args);
    }

    #[test]
    fn missing_artifact_fails_closed_after_descriptor() {
        // The descriptor parses (validation runs later at auth); the absent
        // artifact file denies at its own stage.
        let args = launch_args_for("no-artifact");
        remove_fixtures(&args);
        std::fs::write(&args.descriptor_path, descriptor_json()).expect("descriptor fixture");
        assert_eq!(
            run_grant_launch(&args),
            Err(GrantLaunchError {
                stage: "artifact",
                field: "unreadable"
            })
        );
        remove_fixtures(&args);
    }

    #[test]
    #[cfg(windows)]
    fn unconnectable_server_fails_closed_fast_at_transport() {
        // Full local pipeline through real I/O: descriptor parses, artifact
        // preflights, bundle builds — then the real front-door connect to a
        // nonexistent pipe denies at the transport stage (never hangs, never
        // fabricates). Beauvoir's registration is absent here by construction.
        let args = launch_args_for("transport");
        remove_fixtures(&args);
        write_fixtures(&args);
        let started = std::time::Instant::now();
        assert_eq!(
            run_grant_launch(&args),
            Err(GrantLaunchError {
                stage: "transport",
                field: "connect"
            })
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "transport failure must be bounded"
        );
        remove_fixtures(&args);
    }

    #[test]
    fn staged_binding_names_resolved_image_and_pinned_engine() {
        // Pure derivation: the staged engine binding carries the resolved
        // installed image digest under the pinned isolated implementation.
        use crate::installed_binary::binding_from_installation_records;
        let bytes = b"installed-wasm-host-image-bytes".to_vec();
        let digest_hex = Sha256Digest::of_bytes(&bytes).as_str().to_owned();
        let path = std::env::temp_dir().join("eliot-1955-grant-launch-staged.bin");
        std::fs::write(&path, &bytes).expect("image fixture");
        let path_text = path.to_str().expect("fixture path is unicode").to_owned();
        let binding =
            binding_from_installation_records(&path_text, &digest_hex).expect("records bind");
        let installed = resolve_installed_binary(&binding).expect("bytes match the binding");
        let engine = grant_engine_binding(&installed);
        assert_eq!(engine.implementation_id, ISOLATED_CHILD_IMPLEMENTATION_ID);
        assert_eq!(engine.exact_version, PINNED_WASMTIME_VERSION);
        assert_eq!(engine.engine_artifact_digest.as_str(), digest_hex.as_str());
        assert_eq!(
            engine.wit_interface_digest,
            Sha256Digest::of_bytes(crate::wasmtime_provider::guest_wit_bytes())
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn denial_code_is_stable() {
        let error = GrantLaunchError {
            stage: "transport",
            field: "connect",
        };
        assert_eq!(
            error.to_string(),
            "GRANT_LAUNCH_DENIED:stage=transport:field=connect"
        );
    }
}
