//! Harmless native provider: it never removes retained entries.
use std::{env, fs, io::Write, path::PathBuf};

fn main() {
    let root = PathBuf::from(env::var_os("STAGING_FIXTURE_ROOT").unwrap());
    let mode = env::var("STAGING_FIXTURE_MODE").unwrap();
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
        Some("list") => println!(
            "{{\"dependencies\":{{\"first\":{{\"version\":\"{version}\"}},\"@scope/second\":{{\"version\":\"{version}\"}}}}}}"
        ),
        Some("outdated") => {
            if installed {
                println!("{{}}");
            } else {
                println!(
                    "{{\"first\":{{\"current\":\"1.0.0\",\"wanted\":\"2.0.0\",\"latest\":\"2.0.0\"}},\"@scope/second\":{{\"current\":\"1.0.0\",\"wanted\":\"2.0.0\",\"latest\":\"2.0.0\"}}}}"
                );
                std::process::exit(1);
            }
        }
        Some("view") => println!("{{}}"),
        Some("install") => {
            fs::write(root.join("mutation"), "started").unwrap();
            if mode == "failure" {
                eprintln!("npm error code ENOSPC: no space left on device");
                std::process::exit(1);
            }
            for package in ["first", "@scope/second"] {
                let dir = root.join("lib/node_modules").join(package);
                fs::create_dir_all(&dir).unwrap();
                fs::write(
                    dir.join("package.json"),
                    format!("{{\"name\":\"{package}\",\"version\":\"2.0.0\"}}"),
                )
                .unwrap();
            }
            fs::write(root.join("installed"), "yes").unwrap();
        }
        other => {
            eprintln!("unexpected fixture command: {other:?}");
            std::process::exit(2);
        }
    }
}
