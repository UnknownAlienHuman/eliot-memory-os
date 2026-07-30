use eliot_windows_ipc::test_support::isolated_operator_cursor_credentials;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage: eliot-credential-suite-guard snapshot|verify <manifest.json>",
    )
}

fn main() -> io::Result<()> {
    let mut arguments = env::args_os().skip(1);
    let action = arguments.next().ok_or_else(usage)?;
    let manifest = arguments.next().map(PathBuf::from).ok_or_else(usage)?;
    if arguments.next().is_some() {
        return Err(usage());
    }
    let current = isolated_operator_cursor_credentials()?;
    match action.to_str() {
        Some("snapshot") => {
            if let Some(parent) = manifest.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(
                manifest,
                serde_json::to_vec_pretty(&current)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
            )
        }
        Some("verify") => {
            let before = serde_json::from_slice::<Vec<String>>(&fs::read(&manifest)?)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let before = before.into_iter().collect::<BTreeSet<_>>();
            let after = current.into_iter().collect::<BTreeSet<_>>();
            let created = after.difference(&before).cloned().collect::<Vec<_>>();
            if created.is_empty() {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "isolated test suite left Windows credentials behind: {}",
                    created.join(", ")
                )))
            }
        }
        _ => Err(usage()),
    }
}
