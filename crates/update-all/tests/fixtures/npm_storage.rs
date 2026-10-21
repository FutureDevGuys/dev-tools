//! Harmless standalone provider for storage-failure executable acceptance.
use std::{env, fs, io::Write, path::PathBuf};

fn main() {
    let root = PathBuf::from(env::var_os("STORAGE_FIXTURE_ROOT").unwrap());
    let mode = env::var("STORAGE_FIXTURE_MODE").unwrap();
    let args: Vec<String> = env::args().skip(1).collect();
    let mut calls = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("calls"))
        .unwrap();
    writeln!(calls, "{}", args.join(" ")).unwrap();
    let installed = root.join("installed").exists();
    let version = if installed { "2.0.0" } else { "1.0.0" };
    match args.first().map(String::as_str) {
        Some("prefix") => println!("{}", root.display()),
        Some("root") => println!("{}", root.join("lib/node_modules").display()),
        Some("list") => println!("{{\"dependencies\":{{\"first\":{{\"version\":\"{version}\"}},\"second\":{{\"version\":\"{version}\"}}}}}}"),
        Some("outdated") => {
            if installed { println!("{{}}"); } else {
                println!("{{\"first\":{{\"current\":\"1.0.0\",\"wanted\":\"2.0.0\",\"latest\":\"2.0.0\"}},\"second\":{{\"current\":\"1.0.0\",\"wanted\":\"2.0.0\",\"latest\":\"2.0.0\"}}}}");
                std::process::exit(1);
            }
        }
        Some("view") => println!("{{}}"),
        Some("install" | "generic") => {
            let count = fs::read_to_string(root.join("mutation-count")).ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0) + 1;
            fs::write(root.join("mutation-count"), count.to_string()).unwrap();
            // An observed effect survives failure; the updater cannot claim rollback.
            fs::write(root.join("partial-effect"), "retained").unwrap();
            if mode == "authority" {
                eprintln!("npm error code EACCES: permission denied");
                std::process::exit(1);
            }
            if mode == "guard-storage" {
                eprintln!("npm error code ENOSPC: no space left on device");
                eprintln!("{}", "x".repeat(8192));
                std::thread::sleep(std::time::Duration::from_secs(3));
                std::process::exit(1);
            }
            if matches!(mode.as_str(), "storage" | "quota" | "disk-full" | "long-storage")
                || (mode == "late-storage" && count >= 4)
                || (mode == "health-storage" && count >= 2) {
                if mode == "long-storage" { eprintln!("{}", "unrelated diagnostic ".repeat(40)); }
                eprintln!("{}", match mode.as_str() {
                    "quota" => "npm error code EDQUOT: disk quota exceeded",
                    "disk-full" => "There is not enough space on the disk",
                    _ => "npm error code ENOSPC: no space left on device; npm install failed",
                });
                std::process::exit(1);
            }
            if matches!(mode.as_str(), "recoverable" | "late-storage") && args.iter().filter(|arg| arg.ends_with("@2.0.0")).count() > 1 {
                eprintln!("npm install failed: synthetic package-specific error");
                std::process::exit(1);
            }
            for package in ["first", "second"] {
                if mode == "health-storage" { continue; }
                let dir = root.join("lib/node_modules").join(package);
                fs::create_dir_all(&dir).unwrap();
                fs::write(dir.join("package.json"), format!("{{\"name\":\"{package}\",\"version\":\"2.0.0\"}}" )).unwrap();
            }
            fs::write(root.join("installed"), "yes").unwrap();
        }
        other => { eprintln!("unexpected fixture command: {other:?}"); std::process::exit(2); }
    }
}
