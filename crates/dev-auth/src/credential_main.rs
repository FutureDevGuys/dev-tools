use anyhow::{bail, Context, Result};
use std::io::{self, Read};

const REQUEST_LIMIT: u64 = 64 * 1024;

fn read_request() -> Result<Vec<u8>> {
    let mut input = Vec::new();
    io::stdin()
        .take(REQUEST_LIMIT + 1)
        .read_to_end(&mut input)
        .context("read Git credential request")?;
    if input.len() as u64 > REQUEST_LIMIT {
        bail!("Git credential request exceeds the size limit");
    }
    Ok(input)
}

fn run() -> Result<()> {
    let operation = std::env::args()
        .nth(1)
        .context("credential-helper operation is required")?;
    let input = read_request()?;
    match operation.as_str() {
        "get" => {
            print!("{}", dev_auth::credential_get(&input)?);
            Ok(())
        }
        "store" => {
            dev_auth::CredentialRequest::parse(&input)?;
            Ok(())
        }
        "erase" => dev_auth::credential_erase(&input),
        _ => bail!("unsupported credential-helper operation"),
    }
}

fn main() {
    if let Err(error) = run() {
        if std::env::args().nth(1).as_deref() == Some("get") {
            println!("quit=true");
        }
        eprintln!("git-credential-dev-auth: {error:#}");
        std::process::exit(1);
    }
}
