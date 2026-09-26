#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::path::Path;

use eliot_wasm_host::{
    CliError, PrototypeContourDecision, TypedWorld, admit_generation, admit_prototype,
    default_experimental_limits, execute_describe_experimental, experimental_manifest, parse_args,
    read_bounded_artifact, run_guest_exec, run_ordinary_request_loop, typed_wit_digest,
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

fn main() {
    let config = match parse_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(error) => {
            let (code, detail) = match error {
                CliError::MissingProfile => ("MISSING_PROFILE", "--profile is required".to_owned()),
                CliError::UnsupportedProfile(profile) => ("UNSUPPORTED_PROFILE", profile),
                CliError::MalformedArgument(argument) => ("MALFORMED_ARGUMENT", argument),
                CliError::RemoteTransportForbidden(transport) => {
                    ("REMOTE_TRANSPORT_FORBIDDEN", transport)
                }
                CliError::MissingExperimentalComponent => (
                    "MISSING_EXPERIMENTAL_COMPONENT",
                    "--world requires --experimental-typed-component".to_owned(),
                ),
                CliError::MissingExperimentalWorld => (
                    "MISSING_EXPERIMENTAL_WORLD",
                    "--experimental-typed-component requires --world".to_owned(),
                ),
                CliError::UnknownWorld(world) => ("UNKNOWN_WORLD", world),
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
        Ok(frame) => {
            emit_receipt(&[
                ("status", "ordinary-request-complete"),
                ("wire_id", frame.wire_id),
                ("operation", &frame.operation),
                ("claim", &frame.claim_id),
                ("operation_id", &frame.operation_id),
                ("invocation", &frame.invocation_id),
                ("request_digest", &frame.request_digest),
                ("grant_digest", &frame.grant_digest),
                ("component", &frame.component_id),
                ("artifact_digest", &frame.artifact_digest),
                ("input_digest", &frame.input_digest),
                ("engine", &frame.engine_implementation_id),
                ("engine_version", &frame.engine_version),
                ("disposition", &frame.disposition),
                ("error", frame.error.as_deref().unwrap_or("")),
                (
                    "output_digest",
                    frame.output_digest.as_deref().unwrap_or(""),
                ),
                ("output_bytes", &frame.output_bytes.unwrap_or(0).to_string()),
                (
                    "output_omitted",
                    if frame.output_omitted {
                        "true"
                    } else {
                        "false"
                    },
                ),
                (
                    "fuel_consumed",
                    &frame.fuel_consumed.unwrap_or(0).to_string(),
                ),
                (
                    "peak_memory_bytes",
                    &frame.peak_memory_bytes.unwrap_or(0).to_string(),
                ),
                (
                    "table_elements",
                    &frame.table_elements.unwrap_or(0).to_string(),
                ),
                ("epoch_ticks", &frame.epoch_ticks.unwrap_or(0).to_string()),
                ("verdict_shadow", &frame.verdict_shadow),
                ("verdict_canary", &frame.verdict_canary),
                ("verdict_rollback", &frame.verdict_rollback),
                ("verdict_cutover", &frame.verdict_cutover),
                ("trap", frame.trap.as_deref().unwrap_or("")),
                ("cancelled", if frame.cancelled { "true" } else { "false" }),
                ("drain", frame.drain.as_deref().unwrap_or("")),
                (
                    "rollback_candidate",
                    if frame.rollback_candidate {
                        "true"
                    } else {
                        "false"
                    },
                ),
            ]);
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
        emit_error("UNKNOWN_WORLD", world_name);
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
        emit_error("ADMISSION_DENIED", &error.to_string());
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
                emit_error("ADMISSION_DENIED", &error.to_string());
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
