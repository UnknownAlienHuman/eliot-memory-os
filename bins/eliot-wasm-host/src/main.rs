#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::path::Path;

use eliot_wasm_host::{
    CliError, ContourGateError, PrototypeContourDecision, TypedWorld, admit_generation,
    admit_prototype, check_governed_admission, default_experimental_limits,
    execute_describe_experimental, experimental_manifest, parse_args, read_bounded_artifact,
    run_guest_exec, run_ordinary_request_loop, typed_wit_digest,
};

const INVALID_ARGUMENT_EXIT: i32 = 2;
const ADMISSION_REQUIRED_EXIT: i32 = 1;

/// Bounded receipt-stream budget: one terminal line never exceeds it.
const RECEIPT_MAX_BYTES: usize = 64 * 1024;

/// Emits one bounded JSON terminal line on `stderr`.
///
/// Proper bounded serialization, not string interpolation: every value is
/// escaped by the serializer and the whole line is refused when it would
/// exceed the receipt budget, so an untrusted field can never break the
/// framing or smuggle a newline into it.
fn emit_error(code: &str, detail: &str) {
    let line = serde_json::to_vec(&serde_json::json!({
        "error": code,
        "detail": detail,
    }));
    let Ok(bytes) = line else {
        return;
    };
    if bytes.len() > RECEIPT_MAX_BYTES {
        return;
    }
    let mut stderr = io::stderr().lock();
    let _ = stderr.write_all(&bytes);
    let _ = stderr.write_all(b"\n");
    let _ = stderr.flush();
}

/// Emits one bounded JSON receipt line on `stdout` from ordered key/value
/// pairs, using the same serializer the loop result uses.
fn emit_receipt(fields: &[(&str, &str)]) {
    let mut object = serde_json::Map::new();
    for (key, value) in fields {
        object.insert((*key).to_owned(), serde_json::Value::from(*value));
    }
    let Ok(bytes) = serde_json::to_vec(&serde_json::Value::Object(object)) else {
        return;
    };
    if bytes.len() > RECEIPT_MAX_BYTES {
        return;
    }
    let mut stdout = io::stdout().lock();
    let _ = stdout.write_all(&bytes);
    let _ = stdout.write_all(b"\n");
    let _ = stdout.flush();
}

/// Keep the contour denial category without echoing guest-controlled names or
/// fields from its diagnostic payload.
fn contour_gate_code(error: &ContourGateError) -> &'static str {
    match error {
        ContourGateError::MissingDecision => "CONTOUR_DECISION_REQUIRED",
        ContourGateError::StaticNativeNotFirstContour => "STATIC_NATIVE_NOT_FIRST_CONTOUR",
        ContourGateError::NativeReasonRequired => "NATIVE_REASON_REQUIRED",
        ContourGateError::UnsupportedTarget(_) => "UNSUPPORTED_TARGET",
        ContourGateError::IncompleteManifest(_) => "INCOMPLETE_MANIFEST",
        ContourGateError::UndeclaredImport(_) | ContourGateError::CapabilityNotGranted(_) => {
            "CAPABILITY_INTRODUCTION_REQUIRED"
        }
        ContourGateError::GovernorAuthorizationRequired(_) => "GOVERNOR_AUTHORIZATION_REQUIRED",
        ContourGateError::HostCallLimitExceeded(_) => "HOST_CALL_LIMIT_EXCEEDED",
        ContourGateError::ContourNotServedHere(_) => "CONTOUR_NOT_SERVED_HERE",
        ContourGateError::AdmittedDigestMismatch(_) => "ADMITTED_DIGEST_MISMATCH",
        ContourGateError::ComponentNotAdmitted(_) => "COMPONENT_NOT_ADMITTED",
        ContourGateError::InputLimitExceeded(_) => "INPUT_LIMIT_EXCEEDED",
    }
}

fn main() {
    let config = match parse_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            let (code, detail) = match error {
                CliError::MissingProfile => ("MISSING_PROFILE", "--profile is required".to_owned()),
                CliError::UnsupportedProfile(_) => {
                    ("UNSUPPORTED_PROFILE", "profile is unsupported".to_owned())
                }
                CliError::MalformedArgument(_) => {
                    ("MALFORMED_ARGUMENT", "argument is malformed".to_owned())
                }
                CliError::RemoteTransportForbidden(_) => (
                    "REMOTE_TRANSPORT_FORBIDDEN",
                    "transport must be local".to_owned(),
                ),
                CliError::MissingExperimentalComponent => (
                    "MISSING_EXPERIMENTAL_COMPONENT",
                    "--world requires --experimental-typed-component".to_owned(),
                ),
                CliError::MissingExperimentalWorld => (
                    "MISSING_EXPERIMENTAL_WORLD",
                    "--experimental-typed-component requires --world".to_owned(),
                ),
                CliError::MissingGovernedWorld => (
                    "MISSING_GOVERNED_WORLD",
                    "--governed-typed-component requires --world".to_owned(),
                ),
                CliError::UnknownWorld(_) => ("UNKNOWN_WORLD", "world is unknown".to_owned()),
            };
            emit_error(code, &detail);
            std::process::exit(INVALID_ARGUMENT_EXIT);
        }
    };

    // One-shot P03-admitted guest execution: the reaped child runs the
    // admitted guest inside containment and emits raw output bytes on
    // stdout. This branch runs before anything else once parsed: no
    // experimental describe, no grant path, and no other output may
    // contaminate stdout.
    if let Some(guest) = &config.guest_exec {
        std::process::exit(run_guest_exec(guest));
    }

    // Explicit governed typed attempt: the default lane binds no Kernel
    // admission channel, so deny with the typed admission denial before any
    // artifact acquisition, compilation, or instantiation. This lane never
    // falls back to the experimental path. Borrows only: the experimental
    // branch below moves its own selection.
    if let (Some(component_path), Some(world_name)) = (
        &config.governed_typed_component,
        &config.experimental_world,
    ) {
        run_governed_typed_denial(component_path.as_path(), world_name.as_str());
    }

    if let (Some(component_path), Some(world_name)) = (
        config.experimental_typed_component,
        config.experimental_world,
    ) {
        run_experimental_describe(&component_path, &world_name);
    }

    // The live governed path: an owner-admitted delivery set is bound, the
    // authenticated grant resolves into a local admitted port set, and the
    // bounded request loop serves it to one correlated owner-backed receipt.
    // No fallback to the experimental describe path or the guest-child
    // protocol exists here: a refusal stays a refusal.
    match run_ordinary_request_loop() {
        // The ordinary result publisher already emitted the versioned
        // result-event stream on stdout; this branch emits no second
        // summary object (#2787 step 2). Reader audit, re-run 2026-09-29
        // against this tree rather than inherited: a repository-wide search
        // for `eliot.wasm.host-result`, `WASM_HOST_RESULT_WIRE_ID` and
        // `ordinary-request-complete` still finds no process or Kernel
        // reader of the ordinary result stream — the only references remain
        // this crate's own definition, its re-export, and this removed
        // call. The Kernel demand-starts this binary
        // (`start_wasm_host_parent`) but records the child's streams as
        // process evidence, not as decoded result events. So no diagnostic
        // moved to stderr and no consumer migration was required here.
        //
        // The consequence is recorded rather than left implicit: the
        // consumer-side rejection rule (mixed versions, duplicate terminal
        // events, sequence gaps, contradictory command sequences,
        // contradictory identities) is exported from the same owner as the
        // schema, as `eliot_wasm_host::validate_result_stream`, so the first
        // external consumer of this wire family decodes with
        // `WasmHostResultFrame` and rejects with the producer's own validator
        // instead of re-deriving a weaker local check. That consumer must be
        // written against the current `WASM_HOST_RESULT_WIRE_VERSION`:
        // every event now names the command that produced it
        // (`command_sequence`, the #2785 handover token), and a control event
        // admitted from an owner delivery names that exact delivery and the
        // acknowledgement the child staged for it (`delivery_ack`, #2786).
        // `emit_receipt` stays for the separate experimental describe mode
        // only.
        Ok(_) => {}
        Err(error) => {
            emit_error("KERNEL_ADMISSION_REQUIRED", &error.to_string());
            std::process::exit(ADMISSION_REQUIRED_EXIT);
        }
    }
}

/// Denies an explicit governed typed attempt through the real admission
/// gate. No Kernel admission channel is bound in this host, so no digest is
/// bound and no admission record exists: the gate denies before any artifact
/// acquisition, compilation, or instantiation, and the caller-supplied path
/// marks this as an arbitrary-path attempt on the governed lane. The typed
/// denial propagates with the governed lane's stable code. This mode is
/// separate from the experimental lane and never stands in for it.
fn run_governed_typed_denial(component_path: &Path, world_name: &str) -> ! {
    let Some(world) = TypedWorld::parse(world_name) else {
        emit_error("UNKNOWN_WORLD", "world is unknown");
        std::process::exit(INVALID_ARGUMENT_EXIT);
    };
    match check_governed_admission(world, None, Some(component_path), None) {
        // The gate owns no live admission channel, so even a future
        // non-denial here must not execute: fail closed on the same code.
        Ok(()) => {
            emit_error("KERNEL_ADMISSION_REQUIRED", "governed admission is required");
            std::process::exit(ADMISSION_REQUIRED_EXIT);
        }
        Err(error) => {
            emit_error("KERNEL_ADMISSION_REQUIRED", &error.to_string());
            std::process::exit(ADMISSION_REQUIRED_EXIT);
        }
    }
}

/// Runs the experimental typed describe mode: preflight, prototype contour
/// admission, describe, then the full two-phase contour admission over the
/// actually observed imports. A manifest using an undeclared import is
/// rejected before any success receipt is emitted. This mode is separate
/// from the governed lane and never stands in for it.
fn run_experimental_describe(component_path: &Path, world_name: &str) -> ! {
    let Some(world) = TypedWorld::parse(world_name) else {
        emit_error("UNKNOWN_WORLD", "world is unknown");
        std::process::exit(INVALID_ARGUMENT_EXIT);
    };
    let (artifact, preflight) = match read_bounded_artifact(component_path) {
        Ok(pair) => pair,
        Err(error) => {
            emit_error("PREFLIGHT_DENIED", &error.to_string());
            std::process::exit(ADMISSION_REQUIRED_EXIT);
        }
    };
    let limits = default_experimental_limits(preflight.digest.clone());
    // Contour admission, phase one (pre-execution): the experimental
    // prototype is admitted under the automatic default-WASM decision
    // before any guest code runs. Denial exits before describe.
    let manifest = experimental_manifest(
        preflight.digest.clone(),
        world_name,
        typed_wit_digest(),
        &limits,
    );
    let decision = PrototypeContourDecision::default_for_new_prototype();
    if let Err(error) = admit_prototype(Some(&decision), &manifest) {
        emit_error("ADMISSION_DENIED", contour_gate_code(&error));
        std::process::exit(ADMISSION_REQUIRED_EXIT);
    }
    match execute_describe_experimental(world, &artifact, &limits) {
        Ok((receipt, descriptor)) => {
            // Contour admission, phase two (pre-receipt): the full admission
            // sequence runs over the actually observed imports before any
            // success receipt is emitted.
            if let Err(error) =
                admit_generation(Some(&decision), &manifest, &receipt.actual_imports)
            {
                emit_error("ADMISSION_DENIED", contour_gate_code(&error));
                std::process::exit(ADMISSION_REQUIRED_EXIT);
            }
            let output_bytes = receipt.output_bytes.to_string();
            let artifact_bytes = receipt.artifact_bytes.to_string();
            let abi_revision = descriptor.abi_revision.to_string();
            let elapsed_ms = receipt.elapsed_ms.to_string();
            emit_receipt(&[
                ("proof", &receipt.proof),
                ("world", &receipt.world),
                ("package", &receipt.package_id),
                ("artifact_digest", receipt.artifact_digest.as_str()),
                ("artifact_bytes", &artifact_bytes),
                ("engine", &receipt.engine_version),
                ("wit_digest", receipt.wit_digest.as_str()),
                ("descriptor_world", &descriptor.world_name),
                ("descriptor_package", &descriptor.package_id),
                ("abi_revision", &abi_revision),
                ("output_digest", receipt.output_digest.as_str()),
                ("output_bytes", &output_bytes),
                ("terminal", &receipt.terminal),
                ("semantic_digest", receipt.semantic_digest.as_str()),
                ("elapsed_ms", &elapsed_ms),
            ]);
        }
        Err(error) => {
            emit_error("TYPED_EXECUTION_DENIED", &error.to_string());
            std::process::exit(ADMISSION_REQUIRED_EXIT);
        }
    }
    std::process::exit(0);
}
