use std::io::{self, Write};

const INVALID_ARGUMENT_EXIT: i32 = 2;
const PLAN_GAP_EXIT: i32 = 78;

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    if let Err(error) = validate_arguments(&arguments) {
        emit("INVALID_ARGUMENT", &error);
        std::process::exit(INVALID_ARGUMENT_EXIT);
    }

    emit(
        "PLAN_GAP",
        "G-01 admission, P-03 process executor, replay, checkpoint, and evidence providers must be injected by the Kernel composition owner",
    );
    std::process::exit(PLAN_GAP_EXIT);
}

fn validate_arguments(arguments: &[String]) -> Result<(), String> {
    let mut class_seen = false;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--class" => {
                let value = arguments
                    .get(index + 1)
                    .ok_or_else(|| "--class requires a value".to_owned())?;
                if value.trim().is_empty() {
                    return Err("--class cannot be empty".to_owned());
                }
                class_seen = true;
                index += 2;
            }
            value if value.starts_with("--class=") => {
                let value = value.trim_start_matches("--class=");
                if value.trim().is_empty() {
                    return Err("--class= requires a value".to_owned());
                }
                class_seen = true;
                index += 1;
            }
            "--stdio" => index += 1,
            value => return Err(format!("unknown argument {value}")),
        }
    }
    if class_seen {
        Ok(())
    } else {
        Err("--class is required".to_owned())
    }
}

fn emit(code: &str, detail: &str) {
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{{\"error\":\"{code}\",\"detail\":\"{detail}\"}}");
}
