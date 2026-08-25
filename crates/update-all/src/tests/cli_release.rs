use super::*;

#[test]
fn self_subcommands_are_current_release_operations() {
    use clap::CommandFactory;

    let command = RunCli::command();
    let self_command = command
        .find_subcommand("self")
        .expect("self command must exist");
    let names: Vec<_> = self_command
        .get_subcommands()
        .map(|subcommand| subcommand.get_name())
        .collect();
    assert_eq!(names, ["install", "status", "check", "update", "rollback"]);
}

#[test]
fn product_subcommands_share_the_release_engine() {
    use clap::CommandFactory;

    let command = RunCli::command();
    let product = command
        .find_subcommand("product")
        .expect("product command must exist");
    let names: Vec<_> = product
        .get_subcommands()
        .map(|subcommand| subcommand.get_name())
        .collect();
    assert_eq!(
        names,
        [
            "install",
            "status",
            "check",
            "update",
            "update-if-installed",
            "rollback",
        ]
    );
}
