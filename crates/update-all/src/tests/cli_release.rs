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

#[test]
fn completion_paths_resolve_the_managed_root_environment_override() {
    let _lock = crate::test_support::env_guard();
    let temp = tempfile::TempDir::new().unwrap();
    let managed_root = temp.path().join("managed-root");
    let original = std::env::var_os("UPDATE_ALL_COMPLETION_ROOT");
    std::env::set_var("UPDATE_ALL_COMPLETION_ROOT", &managed_root);

    let paths = resolve_completion_paths();

    match original {
        Some(value) => std::env::set_var("UPDATE_ALL_COMPLETION_ROOT", value),
        None => std::env::remove_var("UPDATE_ALL_COMPLETION_ROOT"),
    }
    assert_eq!(paths.managed_root, managed_root);
}

#[test]
fn completion_sync_help_leads_with_public_init_and_labels_the_legacy_bridge() {
    use clap::CommandFactory;

    let mut command = RunCli::command();
    let sync = command
        .find_subcommand_mut("completions")
        .unwrap()
        .find_subcommand_mut("sync")
        .unwrap();
    let help = sync.render_long_help().to_string();

    assert!(help.contains("update-all completions sync --providers <provider>"));
    assert!(help.contains("update-all completions init <shell>"));
    assert!(help.contains("`bash`, `zsh`, `fish`, `elvish`, and `powershell`"));
    assert!(help.contains("explicit `--apply --shell <shell>` bridge is legacy compatibility"));
}
