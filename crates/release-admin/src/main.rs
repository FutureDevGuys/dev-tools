fn main() {
    std::process::exit(release_admin::main_entry(std::env::args_os().skip(1)));
}
