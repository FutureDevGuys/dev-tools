fn main() {
    if std::env::args().nth(1).as_deref() != Some("list") {
        let home = std::path::PathBuf::from(std::env::var_os("HOME").unwrap());
        if home.join("cancel-mode").exists() {
            std::fs::write(home.join("probe-started"), b"ready").unwrap();
            std::thread::sleep(std::time::Duration::from_secs(2));
            println!("Usage: completion-fixture [OPTIONS]\nOptions:\n  --help  Print help");
            return;
        }
        eprintln!("fixture audit rejected");
        std::process::exit(7);
    }
    match std::env::var("COMPLETION_FIXTURE_MODE").as_deref() {
        Ok("cancel") => println!(
            r#"{{"venvs":{{"fixture":{{"metadata":{{"main_package":{{"package":"fixture","package_version":"1.0","apps":["completion-fixture"]}}}}}}}}}}"#
        ),
        Ok("partial") => println!(r#"{{"venvs":{{"missing-metadata":{{}}}}}}"#),
        Ok("failed") => {
            eprintln!("fixture inventory failed");
            std::process::exit(7);
        }
        _ => println!(r#"{{"venvs":{{}}}}"#),
    }
}
