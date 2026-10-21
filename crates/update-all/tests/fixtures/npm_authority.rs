//! Disposable native provider; never invokes a package manager or shell.
use std::{env, fs, io::Write, path::PathBuf};

fn main() {
    let root = PathBuf::from(env::var_os("AUTHORITY_FIXTURE_ROOT").unwrap());
    let mode = env::var("AUTHORITY_FIXTURE_MODE").unwrap();
    let args: Vec<String> = env::args().skip(1).collect();
    let mut calls = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join("calls"))
        .unwrap();
    writeln!(calls, "{}", args.join(" ")).unwrap();
    let installed = |name: &str| root.join(format!("installed-{name}")).exists();
    match args.first().map(String::as_str) {
        Some("prefix") => println!("{}", root.display()),
        Some("root") => println!("{}", root.join("lib/node_modules").display()),
        Some("list") => println!("{{\"dependencies\":{{\"first\":{{\"version\":\"{}\"}},\"second\":{{\"version\":\"{}\"}}}}}}", if installed("first") {"2.0.0"} else {"1.0.0"}, if installed("second") {"2.0.0"} else {"1.0.0"}),
        Some("outdated") => {
            let entries: Vec<_> = ["first", "second"].into_iter().filter(|p| !installed(p)).map(|p| format!("\"{p}\":{{\"current\":\"1.0.0\",\"wanted\":\"2.0.0\",\"latest\":\"2.0.0\"}}")).collect();
            println!("{{{}}}", entries.join(","));
            if !entries.is_empty() { std::process::exit(1); }
        }
        Some("view") => {
            let package = args[1].split('@').next().unwrap();
            println!("{{\"name\":\"{package}\",\"version\":\"2.0.0\"}}");
        }
        Some("install" | "generic") => {
            let count = fs::read_to_string(root.join("mutation-count")).ok().and_then(|s| s.parse::<u32>().ok()).unwrap_or(0) + 1;
            fs::write(root.join("mutation-count"), count.to_string()).unwrap();
            fs::write(root.join("partial-effect"), "retained").unwrap();
            let batch = args.iter().filter(|a| a.ends_with("@2.0.0")).count() > 1;
            let health = mode.starts_with("health-") || mode.starts_with("lifecycle-") || mode == "individual-preserve";
            let allow = args.iter().any(|a| a.starts_with("--allow-scripts="));
            if mode == "guard" {
                eprintln!("npm error code EACCES: permission denied");
                eprintln!("{}", "x".repeat(8192));
                std::thread::sleep(std::time::Duration::from_secs(3));
                std::process::exit(1);
            }
            let fails = match mode.as_str() {
                "stderr" | "stdout" | "long" | "eperm" | "phrase" => true,
                "late-individual" => batch || args.iter().any(|a| a == "first@2.0.0"),
                "health-isolated" | "health-preserve" | "lifecycle-isolated" | "lifecycle-preserve" => !batch,
                "individual-preserve" => batch || args.iter().any(|a| a == "--loglevel=warn"),
                "health-allow" | "lifecycle-allow" => allow,
                "recoverable" | "negative-markers" | "negative-paths" => batch,
                "ordinary-retry" | "generic-authority" | "program-path" => count == 1,
                "success-history" => false,
                _ => panic!("unexpected mode {mode}"),
            };
            if fails {
                match mode.as_str() {
                    "stdout" => { println!("npm error code EACCES"); eprintln!("unrelated diagnostic"); }
                    "long" => { eprintln!("{}", "harmless preamble ".repeat(50)); eprintln!("npm error code EACCES"); }
                    "phrase" => eprintln!("npm error permission denied: rename failed"),
                    "negative-markers" => eprintln!("synthetic failure NOT_EACCES EACCES_CACHE XEPERMX"),
                    "negative-paths" => eprintln!("package failure /tmp/EACCES-cache C:\\EPERM\\cache npm-cache-eperm"),
                    "recoverable" | "ordinary-retry" | "program-path" => eprintln!("synthetic package failure"),
                    "late-individual" | "individual-preserve" if batch => eprintln!("synthetic package failure"),
                    "eperm" | "late-individual" => eprintln!("npm ERR! code EPERM"),
                    _ => eprintln!("npm error code EACCES: permission denied"),
                }
                std::process::exit(1);
            }
            if mode == "success-history" { eprintln!("npm error code EACCES was historical; operation succeeded"); }
            for package in ["first", "second"] {
                if args.iter().any(|a| a == &format!("{package}@2.0.0")) {
                    fs::write(root.join(format!("installed-{package}")), "yes").unwrap();
                    let missing_manifest = health && if mode.ends_with("-preserve") { package == "second" } else { package == "first" };
                    if !missing_manifest {
                        let dir = root.join("lib/node_modules").join(package);
                        fs::create_dir_all(&dir).unwrap();
                        fs::write(dir.join("package.json"), format!("{{\"name\":\"{package}\",\"version\":\"2.0.0\"}}")).unwrap();
                    }
                }
            }
            if (!batch && matches!(mode.as_str(), "health-allow" | "lifecycle-allow")) || (batch && mode.starts_with("lifecycle-")) {
                eprintln!("npm warn install-scripts first@2.0.0 (postinstall)");
                if mode == "lifecycle-preserve" { eprintln!("npm warn install-scripts second@2.0.0 (postinstall)"); }
            }
            if mode == "individual-preserve" { for package in ["first", "second"] { if args.iter().any(|a| a == &format!("{package}@2.0.0")) { eprintln!("npm warn install-scripts {package}@2.0.0 (postinstall)"); } } }
        }
        other => panic!("unexpected command {other:?}"),
    }
}
