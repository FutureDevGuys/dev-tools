mod build_info {
    include!("../../build_info_runtime.rs");
}

fn main() {
    let mut args = std::env::args_os();
    let argv0 = args.next().unwrap_or_else(|| "sync-configs".into());
    let args: Vec<_> = args.collect();
    if args
        .first()
        .and_then(|argument| argument.to_str())
        .is_some_and(|argument| argument == "--build-info")
    {
        build_info::print_build_info();
        return;
    }
    std::process::exit(sync_configs::main_entry(argv0, args));
}
