use eliot_windows_ipc::SuspendedJobChild;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

const TIMEOUT_EXIT_CODE: i32 = 124;
const TERMINATED_JOB_EXIT_CODE: u32 = 125;

struct GuardianArgs {
    current_directory: PathBuf,
    timeout: Duration,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    pid_file: Option<PathBuf>,
    stop_file: Option<PathBuf>,
    command: Vec<OsString>,
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn take_value(arguments: &mut impl Iterator<Item = OsString>, flag: &str) -> io::Result<OsString> {
    arguments
        .next()
        .ok_or_else(|| invalid_input(format!("missing value for {flag}")))
}

fn parse_args() -> io::Result<GuardianArgs> {
    let mut arguments = std::env::args_os().skip(1);
    let mut current_directory = None;
    let mut timeout = None;
    let mut stdout_path = None;
    let mut stderr_path = None;
    let mut pid_file = None;
    let mut stop_file = None;
    let mut command = Vec::new();

    while let Some(argument) = arguments.next() {
        let flag = argument.to_string_lossy();
        match flag.as_ref() {
            "--cwd" => {
                current_directory = Some(PathBuf::from(take_value(&mut arguments, "--cwd")?));
            }
            "--timeout-seconds" => {
                let value = take_value(&mut arguments, "--timeout-seconds")?;
                let seconds = value
                    .to_string_lossy()
                    .parse::<u64>()
                    .map_err(|_| invalid_input("--timeout-seconds must be an unsigned integer"))?;
                if seconds == 0 {
                    return Err(invalid_input("--timeout-seconds must be greater than zero"));
                }
                timeout = Some(Duration::from_secs(seconds));
            }
            "--stdout" => {
                stdout_path = Some(PathBuf::from(take_value(&mut arguments, "--stdout")?));
            }
            "--stderr" => {
                stderr_path = Some(PathBuf::from(take_value(&mut arguments, "--stderr")?));
            }
            "--pid-file" => {
                pid_file = Some(PathBuf::from(take_value(&mut arguments, "--pid-file")?));
            }
            "--stop-file" => {
                stop_file = Some(PathBuf::from(take_value(&mut arguments, "--stop-file")?));
            }
            "--" => {
                command.extend(arguments);
                break;
            }
            _ => return Err(invalid_input(format!("unknown guardian argument: {flag}"))),
        }
    }

    if command.is_empty() {
        return Err(invalid_input("guardian child command is required after --"));
    }
    Ok(GuardianArgs {
        current_directory: current_directory.ok_or_else(|| invalid_input("--cwd is required"))?,
        timeout: timeout.ok_or_else(|| invalid_input("--timeout-seconds is required"))?,
        stdout_path: stdout_path.ok_or_else(|| invalid_input("--stdout is required"))?,
        stderr_path: stderr_path.ok_or_else(|| invalid_input("--stderr is required"))?,
        pid_file,
        stop_file,
        command,
    })
}

fn drain_to_file(mut reader: File, mut writer: File) -> io::Result<u64> {
    io::copy(&mut reader, &mut writer)
}

fn join_reader(reader: thread::JoinHandle<io::Result<u64>>, stream: &str) -> io::Result<u64> {
    reader
        .join()
        .map_err(|_| io::Error::other(format!("{stream} reader thread panicked")))?
}

fn run() -> io::Result<i32> {
    let arguments = parse_args()?;
    let stdout_file = File::create(&arguments.stdout_path)?;
    let stderr_file = File::create(&arguments.stderr_path)?;
    let mut child_command = Command::new(&arguments.command[0]);
    child_command
        .args(&arguments.command[1..])
        .current_dir(&arguments.current_directory)
        .env_clear()
        .envs(std::env::vars_os());

    let mut child = SuspendedJobChild::spawn(&child_command)?;
    let root_pid = child.id();
    if let Some(pid_file) = &arguments.pid_file {
        std::fs::write(pid_file, root_pid.to_string())?;
    }
    let stdout = child
        .take_stdout()
        .ok_or_else(|| io::Error::other("guardian child stdout is unavailable"))?;
    let stderr = child
        .take_stderr()
        .ok_or_else(|| io::Error::other("guardian child stderr is unavailable"))?;
    let stdout_reader = thread::spawn(move || drain_to_file(stdout, stdout_file));
    let stderr_reader = thread::spawn(move || drain_to_file(stderr, stderr_file));

    let started = Instant::now();
    let mut root_status = None;
    let mut stop_requested = false;
    let mut timed_out = false;
    loop {
        if let Some(exit_code) = child.try_wait()? {
            root_status = Some(exit_code);
            break;
        }
        if arguments
            .stop_file
            .as_ref()
            .is_some_and(|path| path.is_file())
        {
            stop_requested = true;
            break;
        }
        if started.elapsed() >= arguments.timeout {
            timed_out = true;
            break;
        }
        thread::sleep(Duration::from_millis(50));
    }
    let observed_processes = child.observed_processes().len();

    // The root may have exited while a descendant still owns one of the pipe
    // handles. Terminating the pre-assigned Job closes those handles before the
    // reader threads are joined. On timeout this also bounds the root process.
    child.terminate(TERMINATED_JOB_EXIT_CODE)?;
    if timed_out || stop_requested {
        let _ = child.wait_timeout(Duration::from_secs(5))?;
    }
    let stdout_bytes = join_reader(stdout_reader, "stdout")?;
    let stderr_bytes = join_reader(stderr_reader, "stderr")?;
    let root_exit_code = root_status.unwrap_or_else(|| {
        if timed_out {
            TIMEOUT_EXIT_CODE
        } else {
            i32::try_from(TERMINATED_JOB_EXIT_CODE).unwrap_or(125)
        }
    });
    let guardian_exit_code = if stop_requested { 0 } else { root_exit_code };

    let mut output = io::stdout().lock();
    writeln!(
        output,
        "{{\"schema_version\":\"eliot-process-guardian-v1\",\"root_pid\":{root_pid},\"root_exit_code\":{root_exit_code},\"guardian_exit_code\":{guardian_exit_code},\"timed_out\":{timed_out},\"stop_requested\":{stop_requested},\"observed_processes\":{observed_processes},\"stdout_bytes\":{stdout_bytes},\"stderr_bytes\":{stderr_bytes}}}"
    )?;
    output.flush()?;
    Ok(guardian_exit_code)
}

fn main() {
    match run() {
        Ok(exit_code) => std::process::exit(exit_code),
        Err(error) => {
            let _ = writeln!(io::stderr().lock(), "process guardian failed: {error}");
            std::process::exit(70);
        }
    }
}
