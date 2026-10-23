fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("noop") => {
            println!(
                r#"{{"product":"skills-sync","version":"0.2.0","changed":false,"managed":true,"outcome":"no_op","path":"/fixture/products/skills-sync/versions/0.2.0/skills-sync"}}"#
            );
            eprintln!("warning: fixture operation diagnostic");
            eprintln!("Checking the fixture installation before returning");
            eprintln!("[download] fixture progress");
            eprintln!("[1/10] fixture progress");
        }
        Some("updated") => println!(
            r#"{{"schema":"dev-tools-operation-result-v2","product":"example-tool","operation":"update_apply","outcome":"completed","changed":true,"installed_version":"2.0","available_version":"3.0","exit_code":0}}"#
        ),
        Some("deferred") => println!(
            r#"UPDATE_ALL_RESULT {{"outcome":"deferred","detail":"close the fixture application","current":"1.0","latest":"2.0"}}"#
        ),
        Some("unknown") => println!(
            r#"{{"schema":"dev-tools-operation-result-v2","product":"uncertain-tool","operation":"update_apply","outcome":"completed","changed":null,"installed_version":null,"available_version":"4.0","exit_code":0}}"#
        ),
        _ => panic!("unknown fixture operation"),
    }
}
