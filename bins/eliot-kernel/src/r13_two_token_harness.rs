#![cfg_attr(not(feature = "r13-os-harness"), allow(dead_code))]

fn main() {
    std::process::exit(eliot_kernel::r13_os_harness::run());
}
