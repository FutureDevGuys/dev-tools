pub mod cli;

use std::ffi::OsString;

pub fn main_entry(argv0: OsString, args: Vec<OsString>) -> i32 {
    cli::main_entry(argv0, args)
}
