pub mod adapter;
pub mod artifacts;
pub mod cargo_intercept;
pub mod cli;
pub mod config;
pub mod dispatch;
pub mod entrypoint;
pub mod gc;
pub mod install;
pub mod lease;
pub mod migrate;
pub mod provenance;
pub mod repository;
pub mod resources;
pub mod root;
pub mod util;

use std::ffi::OsString;

pub fn main_entry(argv0: OsString, args: Vec<OsString>) -> i32 {
    cli::main_entry(argv0, args)
}
