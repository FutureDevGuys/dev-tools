fn main() {
    std::process::exit(skills_sync::main_entry(std::env::args().skip(1).collect()));
}
