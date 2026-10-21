//! Native harmless provider. All state is disposable; no real package manager or sudo.
use std::{
    env, fs,
    io::Write,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};
fn wait(path: PathBuf) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !path.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        path.exists(),
        "fixture synchronization timed out: {}",
        path.display()
    );
}
fn main() {
    let root = PathBuf::from(env::var_os("OUTCOME_FIXTURE_ROOT").unwrap());
    let mode = env::var("OUTCOME_FIXTURE_MODE").unwrap();
    let args: Vec<String> = env::args().skip(1).collect();
    let name = env::current_exe()
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    writeln!(
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("calls"))
            .unwrap(),
        "{name} {}",
        args.join(" ")
    )
    .unwrap();
    if name == "sudo" {
        if args.iter().any(|arg| arg == "-v") || args.last().is_some_and(|arg| arg == "true") {
            return;
        }
        fs::write(
            root.join("denied-attempt"),
            "partial effect cannot be excluded",
        )
        .unwrap();
        eprintln!("the requested operation requires elevation");
        std::process::exit(1);
    }
    let installed = root.join("installed").exists();
    let version = if installed { "2.0.0" } else { "1.0.0" };
    match args.first().map(String::as_str) {
        Some("deferred") => println!("UPDATE_ALL_RESULT {{\"outcome\":\"deferred\",\"detail\":\"selected work is still pending\"}}"),
        Some("prefix") => println!("{}", root.display()),
        Some("root") => println!("{}", root.join("lib/node_modules").display()),
        Some("list") => {
            println!("{{\"dependencies\":{{\"first\":{{\"version\":\"{version}\"}}}}}}")
        }
        Some("outdated") => {
            if installed {
                println!("{{}}");
            } else {
                println!("{{\"first\":{{\"current\":\"1.0.0\",\"wanted\":\"2.0.0\",\"latest\":\"2.0.0\"}}}}");
                std::process::exit(1);
            }
        }
        Some("view") if mode == "invalid-manifest" => {
            println!("{{\"dependencies\":{{\"local-only\":\"workspace:*\"}}}}")
        }
        Some("view") => println!("{{}}"),
        Some("install") => {
            fs::write(root.join("mutation"), "attempted").unwrap();
            if mode == "blocked-concurrent" {
                wait(root.join("independent-started"));
            }
            if mode.starts_with("blocked") {
                eprintln!("npm error code EACCES: permission denied");
                std::process::exit(1);
            }
            if mode == "install-failure" {
                eprintln!("package install failed with an ordinary operational error");
                std::process::exit(1);
            }
            if mode == "warning" {
                eprintln!("npm warn EBADENGINE unsupported engine");
            }
            let dir = root.join("lib/node_modules/first");
            fs::write(
                dir.join("package.json"),
                "{\"name\":\"first\",\"version\":\"2.0.0\"}",
            )
            .unwrap();
            fs::write(root.join("installed"), "verified").unwrap();
        }
        Some("independent") => {
            fs::write(root.join("independent-started"), "started").unwrap();
            if mode == "blocked-concurrent" {
                wait(root.join("mutation"));
                thread::sleep(Duration::from_millis(250));
            }
            fs::write(root.join("independent-done"), "finished").unwrap();
        }
        Some("failure") => {
            eprintln!("ordinary operational failure");
            std::process::exit(7);
        }
        Some("after") | Some("health") | Some("elevated") => {
            fs::write(root.join(&args[0]), "executed").unwrap();
        }
        _ => {
            eprintln!("unexpected fixture args {args:?}");
            std::process::exit(8);
        }
    }
}
