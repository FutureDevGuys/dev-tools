pub mod cli;
pub mod engine;
pub mod filesystem;
pub mod hooks;
pub mod interrupt;
pub mod manifest;
pub mod overlay;
pub mod paths;
pub mod privilege;
pub mod privileged_target;
pub mod reconciler;
pub mod report;
pub mod run_logs;
pub mod scaffold;
pub mod standalone;

use std::ffi::OsString;

pub fn main_entry(argv0: OsString, args: Vec<OsString>) -> i32 {
    cli::main_entry(argv0, args)
}
