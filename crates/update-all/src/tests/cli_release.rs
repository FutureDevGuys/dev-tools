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

#[test]
fn default_completion_managed_root_remains_absolute_without_home_or_xdg() {
    let _lock = crate::test_support::env_guard();
    #[cfg(not(windows))]
    {
        let original_home = std::env::var_os("HOME");
        let original_xdg_data_home = std::env::var_os("XDG_DATA_HOME");
        std::env::remove_var("HOME");
        std::env::remove_var("XDG_DATA_HOME");

        let root = default_completion_managed_root();

        match original_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        match original_xdg_data_home {
            Some(value) => std::env::set_var("XDG_DATA_HOME", value),
            None => std::env::remove_var("XDG_DATA_HOME"),
        }

        assert!(root.is_absolute());
        assert!(
            root.ends_with(".local/share/update-all/completions"),
            "unexpected managed root fallback: {}",
            root.display()
        );
    }
}

#[test]
fn resolve_managed_completion_root_rejects_relative_paths() {
    let defaults = CompletionPaths {
        rc_root: PathBuf::from("/tmp/rc-root"),
        managed_root: PathBuf::from("/tmp/managed-root"),
        powershell_root: None,
        catalog_path: PathBuf::from("/tmp/catalog.json"),
        registry_path: PathBuf::from("/tmp/registry.json"),
    };

    let error = resolve_managed_completion_root(Some(PathBuf::from("relative-root")), &defaults)
        .unwrap_err();
    assert!(format!("{error:#}").contains("managed completion root must be absolute"));
}
