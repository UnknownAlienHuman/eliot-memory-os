//! Smallest proof for issue #1888 Work item W6 / `I1.6:15`: the running-binary
//! observation is **path-exact**.
//!
//! `I1.6` (`docs/architecture/I01-06-windows-isolation.md:15`) requires that
//! "versioned binaries are never replaced in place while running". The
//! observation that sentence turns on is `any_running_process_executing`: it
//! compares the whole update-target path against the image path Windows reports
//! for each live process, not the executable's file name.
//!
//! This file proves exactly the two halves that can be decided without
//! inventing a fixture machine:
//!
//! 1. **Positive.** This very test binary is a live process, so the owner must
//!    report it executing *its own* exact image path — and only that path. The
//!    refusal shape (a different directory, a different file name, and a
//!    relative spelling) is refused rather than answered, which is what keeps
//!    the observation from silently degrading back into a name search.
//! 2. **Refusal.** A path that cannot be observed is refused, never answered:
//!    a relative spelling and a bare file name (not an observation this API
//!    can make) are typed `InvalidInput`, and a well-formed path that is
//!    certainly not executing must be answered `Ok(false)` rather than
//!    refused. An unreadable live candidate image is the same disposition and
//!    is documented in the owner; it cannot be forced from a test without a
//!    protected-process fixture, so it is stated rather than staged.

use std::path::Path;

use eliot_platform_windows::{WindowsAdapterError, any_running_process_executing};

/// Absolute path of the image this test binary is executing.
///
/// `std::env::current_exe` is the file Windows loaded for this process, so it
/// is the one path the owner must observe as `Ok(true)`.
fn own_image() -> Result<std::path::PathBuf, String> {
    std::env::current_exe().map_err(|error| format!("current_exe: {error}"))
}

/// The owner, rendered as this file's error type so `?` reads the answer.
fn observing(executable: &Path) -> Result<bool, String> {
    any_running_process_executing(executable).map_err(|error| format!("{error:?}"))
}

#[test]
fn the_executing_image_is_observed_at_its_exact_path_and_only_there() -> Result<(), String> {
    if !cfg!(windows) {
        // Off-Windows the owner is `Unavailable` from a `cfg` branch; there is
        // no live process walk to answer a path-exact question, and that
        // refusal is the documented platform precondition, not a defect.
        return Err("the path-exact running-binary observation is Windows-only".to_owned());
    }

    let own = own_image()?;

    // Positive: the whole exact path of the file this process is executing.
    match any_running_process_executing(&own) {
        Ok(true) => {}
        Ok(false) => {
            return Err(format!(
                "the executing image {own:?} must be observed as running"
            ));
        }
        Err(error) => {
            return Err(format!(
                "the executing image {own:?} must be readable: {error}"
            ));
        }
    }

    // Path-exactness, not basename equality. The decisive case: the SAME
    // executable file name, in a DIFFERENT directory. This is the copy that
    // `any_running_process_named` — a basename search over the whole machine —
    // cannot distinguish from the running image, and it is exactly the false
    // refusal the path-exact check exists to remove. A basename-only predicate
    // would report this as running; this one must not.
    let elsewhere_copy = std::env::temp_dir()
        .join("eliot-1888-same-name-other-directory")
        .join(
            own.file_name()
                .ok_or("own image has no file name")?
                .to_string_lossy()
                .into_owned(),
        );
    if observing(&elsewhere_copy)? {
        return Err(format!(
            "a same-named file in a different directory ({elsewhere_copy:?}) must \
             not be reported as the executing image"
        ));
    }

    // A different file name in the same directory is likewise a different
    // answer. Together the two prove neither the directory nor the file name
    // alone decides the observation: the whole path does.
    let same_directory_other_name = own.with_file_name("eliot-1888-not-the-image.exe");
    if observing(&same_directory_other_name)? {
        return Err("a different file name must not be reported as executing".to_owned());
    }

    Ok(())
}

#[test]
fn an_unobservable_or_clearly_idle_path_is_answered_not_guessed() -> Result<(), String> {
    // Refusal, first kind: a relative spelling and a bare file name are not
    // observations this API can make. Returning `Ok(false)` for them would
    // hand the caller a silent "it is idle" for a path the owner never read —
    // the exact weakening the path-exact check exists to prevent. Both are
    // refused instead, and `Ok(true)` is also refused, so a bare file name
    // cannot smuggle the old basename question back through this API.
    for unobservable in [
        Path::new("relative-only.exe"),
        Path::new("bare-file-name.exe"),
        Path::new("nested/path.exe"),
    ] {
        match any_running_process_executing(unobservable) {
            Err(WindowsAdapterError::InvalidInput) => {}
            Ok(other) => {
                return Err(format!(
                    "an unobservable path ({unobservable:?}) must be refused, got {other:?}"
                ));
            }
            Err(other) => {
                return Err(format!(
                    "an unobservable path ({unobservable:?}) must be refused as \
                     InvalidInput, got {other:?}"
                ));
            }
        }
    }

    // Refusal, second kind: a well-formed, absolute, certainly-idle path must
    // be ANSWERED `Ok(false)` from a completed walk — not refused, not
    // reported running. This distinguishes the two dispositions the owner
    // makes: "I read every candidate image and none is this file" (Ok(false))
    // versus "I could not read a candidate image" (Err, fail-closed). Only the
    // second kind is allowed to block an install, so over-refusing would be
    // just as wrong as under-refusing.
    if cfg!(windows) {
        let idle = std::env::temp_dir().join("eliot-1888-path-exact-idle-target.exe");
        match any_running_process_executing(&idle) {
            Ok(false) => {}
            Ok(true) => {
                return Err(format!(
                    "a temp-dir file that is not executing ({idle:?}) must be \
                     reported as not running"
                ));
            }
            Err(error) => {
                return Err(format!(
                    "a well-formed idle path ({idle:?}) must be answered, not \
                     refused: {error}"
                ));
            }
        }
    }
    Ok(())
}
