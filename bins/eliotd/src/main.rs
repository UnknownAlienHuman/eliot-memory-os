#![forbid(unsafe_code)]

//! `eliotd` service entrypoint.
//!
//! Host/N1 owns the authenticated Kernel-generation transport. This binary
//! composes Governor only from that transport and never creates a local Store,
//! `ProcessExecutor`, or authority source.

mod daemon_runtime;
mod observability;

use eliotd::{PROTOCOL_VERSION, SERVICE_NAME};

fn emit_build_module_manifest() -> Option<Result<(), String>> {
    let mut arguments = std::env::args_os().skip(1);
    if arguments.next()?.to_str()? != "--emit-build-module-manifest" {
        return None;
    }
    let Some(artifact_sha256) = arguments.next().and_then(|value| value.into_string().ok()) else {
        return Some(Err(
            "--emit-build-module-manifest requires one artifact SHA-256".to_owned(),
        ));
    };
    if arguments.next().is_some() {
        return Some(Err(
            "--emit-build-module-manifest accepts exactly one artifact SHA-256".to_owned(),
        ));
    }

    #[cfg(windows)]
    {
        let executable = match std::env::current_exe() {
            Ok(value) => value,
            Err(error) => return Some(Err(format!("observe builder executable: {error}"))),
        };
        if !executable
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.eq_ignore_ascii_case("eliotd.exe"))
        {
            return Some(Err(
                "builder executable is not the staged eliotd.exe".to_owned()
            ));
        }
        let executable_bytes = match std::fs::read(&executable) {
            Ok(value) => value,
            Err(error) => return Some(Err(format!("read builder executable bytes: {error}"))),
        };
        let observed_artifact_sha256 = eliot_contracts::sha256_hex(&executable_bytes);
        if !artifact_sha256.eq_ignore_ascii_case(&observed_artifact_sha256) {
            return Some(Err(
                "supplied artifact digest does not match the executing staged eliotd.exe"
                    .to_owned(),
            ));
        }
        let manifest = match eliotd::render_build_module_manifest(&observed_artifact_sha256) {
            Ok(value) => value,
            Err(error) => return Some(Err(error.to_string())),
        };
        let Some(parent) = executable.parent() else {
            return Some(Err(
                "builder executable has no staged runtime directory".to_owned()
            ));
        };
        let module_id = match eliot_contracts::ContractId::new(SERVICE_NAME) {
            Ok(value) => value,
            Err(error) => return Some(Err(error.to_string())),
        };
        let path = parent.join(eliot_runtime_contracts::module_manifest_file_name(
            &module_id,
        ));
        let result = (|| {
            use std::io::Write as _;

            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(|error| format!("create module manifest: {error}"))?;
            file.write_all(manifest.as_bytes())
                .map_err(|error| format!("write module manifest: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("flush module manifest: {error}"))?;
            Ok(())
        })();
        Some(result)
    }

    #[cfg(not(windows))]
    {
        let _ = artifact_sha256;
        Some(Err(
            "the module manifest export is available only in the Windows release build".to_owned(),
        ))
    }
}

#[expect(
    clippy::print_stderr,
    reason = "last-resort operator stderr only after structured write_json failed; statement-level expect is unsupported here (#838)"
)]
fn main() {
    if let Some(result) = emit_build_module_manifest() {
        if let Err(error) = result {
            eprintln!("ELIOTD_MODULE_MANIFEST_EXPORT_REJECTED: {error}");
            std::process::exit(2);
        }
        return;
    }
    // #740: one bounded stderr subscriber for the process. Protocol/status
    // stdout bytes and framing stay unchanged; init failure keeps the first
    // owner's subscriber and never alters exit/control behavior.
    let _diagnostics = eliotd::diagnostics::init_daemon_diagnostics();
    // Issue #1836 (W1): install the shared observability runtime from the
    // canonical roots this binary already resolves, before the daemon run
    // loop starts. Best-effort by the same contract as the subscriber above:
    // a refused configuration leaves the daemon running on its existing
    // diagnostics and is never turned into a startup failure.
    let _observability = eliot_observability_runtime::install(&observability::daemon_config());
    let _startup = eliotd::diagnostics::emit_startup();
    if let Err(error) = daemon_runtime::run() {
        let message = daemon_runtime::ReadyMessage::Error {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            error: error.clone(),
        };
        if let Err(output_error) = daemon_runtime::write_json(&message) {
            eprintln!(
                "eliotd structured error output failed: {output_error}; original failure: {error}"
            );
        }
        std::process::exit(1);
    }
}
