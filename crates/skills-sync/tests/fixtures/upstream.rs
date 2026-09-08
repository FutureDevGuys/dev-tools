//! Native protocol fixture; compiled only by the public CLI contract tests.
use std::{env, fs, io::Write, path::PathBuf};

fn quoted(text: &str) -> String {
    let mut out = String::from("\"");
    for ch in text.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    let home = PathBuf::from(env::var_os("HOME").unwrap());
    let mut log = fs::OpenOptions::new().create(true).append(true)
        .open(home.join("provider-calls")).unwrap();
    writeln!(log, "{}", args.iter().map(|arg| quoted(arg)).collect::<Vec<_>>().join(" ")).unwrap();
    drop(log);
    if args == ["--version"] {
        print!("{}", fs::read_to_string(home.join("provider-version")).unwrap_or_else(|_| "1.5.25\n".into()));
        return;
    }
    let global = args.iter().any(|arg| arg == "-g" || arg == "--global");
    let root = if global { home.clone() } else { env::current_dir().unwrap() };
    let skills = root.join(".agents/skills");
    match args.first().map(String::as_str) {
        Some("list") => {
            let mut items = Vec::new();
            for entry in fs::read_dir(&skills).into_iter().flatten().flatten() {
                let path = entry.path();
                if !path.join("SKILL.md").is_file() { continue; }
                let name = entry.file_name().into_string().unwrap();
                let claude = root.join(".claude/skills").join(&name);
                let visible = fs::canonicalize(&claude).ok() == fs::canonicalize(&path).ok();
                items.push(format!("{{\"name\":{},\"path\":{},\"agents\":[{}]}}", quoted(&name), quoted(path.to_str().unwrap()), if visible { "\"claude-code\"" } else { "" }));
            }
            let app = home.join(".codex/plugins/cache/example/skills/app-bundled");
            if app.join("SKILL.md").is_file() {
                items.push(format!("{{\"name\":\"app-bundled\",\"path\":{},\"agents\":[\"codex\"]}}", quoted(app.to_str().unwrap())));
            }
            items.sort();
            println!("[{}]", items.join(","));
        }
        Some("update") => {
            if home.join("fail-update").exists() { std::process::exit(7); }
            if home.join("hang-update").exists() {
                fs::write(home.join("update-entered"), "entered").unwrap();
                std::thread::sleep(std::time::Duration::from_secs(3));
                fs::write(home.join("update-overran"), "unexpected").unwrap();
            }
            let names: Vec<_> = args.iter().skip(1).filter(|arg| !arg.starts_with('-')).collect();
            assert!(!names.is_empty(), "updates must select explicit tracked names");
            for name in names {
                fs::write(skills.join(name).join("SKILL.md"), "updated payload\n").unwrap();
            }
        }
        Some("add") => {
            if home.join("reject-add").exists() { std::process::exit(8); }
            for pair in args.windows(2).filter(|pair| pair[0] == "--skill") {
                let path = skills.join(&pair[1]);
                fs::create_dir_all(&path).unwrap();
                fs::write(path.join("SKILL.md"), "restored payload\n").unwrap();
                let links = root.join(".claude/skills");
                fs::create_dir_all(&links).unwrap();
                let link = links.join(&pair[1]);
                if fs::symlink_metadata(&link).is_err() {
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(&path, &link).unwrap();
                }
            }
        }
        _ => std::process::exit(9),
    }
}
