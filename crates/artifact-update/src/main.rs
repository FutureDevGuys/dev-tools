fn main() {
    std::process::exit(artifact_update::main_entry(std::env::args_os().skip(1)));
}
