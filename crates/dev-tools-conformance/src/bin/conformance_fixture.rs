use serde_json::json;
use std::env;

const PRODUCT: &str = "demo-tool";
const VERSION: &str = "1.2.3";

fn main() {
    if ["PATH", "PYTHONPATH", "GIT_DIR", "RC_ROOT"]
        .into_iter()
        .any(|name| env::var_os(name).is_some())
    {
        std::process::exit(9);
    }

    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = match args.as_slice() {
        [flag] if flag == "--version" => {
            println!("{PRODUCT} {VERSION}");
            Ok(())
        }
        [command, json_flag] if command == "build-info" && json_flag == "--json" => {
            print_json(json!({
                "schema": "dev-tools-build-info-v1",
                "product": PRODUCT,
                "version": VERSION,
                "source_commit": "0123456789abcdef0123456789abcdef01234567",
                "source_state": "clean",
                "target": "x86_64-unknown-linux-gnu",
                "profile": "release",
                "built_unix": 1788000000_u64
            }))
        }
        [command, shell]
            if command == "completion"
                && ["bash", "zsh", "fish", "elvish", "powershell"].contains(&shell.as_str()) =>
        {
            println!("# completion for {PRODUCT} {shell}");
            Ok(())
        }
        [command, json_flag] if command == "doctor" && json_flag == "--json" => {
            operation("doctor", "completed")
        }
        [command, operation_name, json_flag]
            if command == "update" && operation_name == "status" && json_flag == "--json" =>
        {
            operation("update_status", "current")
        }
        [flag] if flag == "--help" => {
            println!("build-info\ncompletion\ndoctor\nupdate status check install apply rollback");
            Ok(())
        }
        _ => Err(()),
    };
    if result.is_err() {
        eprintln!("invalid invocation");
        std::process::exit(2);
    }
}

fn operation(operation: &str, outcome: &str) -> Result<(), ()> {
    print_json(json!({
        "schema": "dev-tools-operation-result-v1",
        "product": PRODUCT,
        "operation": operation,
        "outcome": outcome,
        "changed": false,
        "exit_code": 0
    }))
}

fn print_json(value: serde_json::Value) -> Result<(), ()> {
    serde_json::to_writer(std::io::stdout(), &value).map_err(|_| ())?;
    println!();
    Ok(())
}
