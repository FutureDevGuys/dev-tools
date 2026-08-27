use anyhow::Result;

fn run() -> Result<i32> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let status = dev_auth::run_gh(&arguments)?;
    Ok(status.code().unwrap_or(128))
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("gh-dev-auth: {error:#}");
            std::process::exit(2);
        }
    }
}
