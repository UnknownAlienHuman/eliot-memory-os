//! Stable facade for the Host launch-options parser cell.

#[path = "host_launch_options.rs"]
mod host_launch_options;

pub use self::host_launch_options::HostLaunchOptions;
pub(crate) use self::host_launch_options::valid_sha256_text;
