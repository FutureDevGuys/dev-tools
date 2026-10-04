use super::*;

#[test]
fn runs_prune_is_a_public_dry_run_capable_command() {
    use clap::CommandFactory;

    let command = RunCli::command();
    let runs = command
        .find_subcommand("runs")
        .expect("runs command must exist");
    let prune = runs
        .find_subcommand("prune")
        .expect("runs prune command must exist");
    assert!(prune
        .get_arguments()
        .any(|argument| argument.get_long() == Some("dry-run")));
}

#[test]
fn logging_initialization_failure_is_non_fatal() {
    let temp = tempfile::TempDir::new().unwrap();
    let occupied = temp.path().join("occupied");
    std::fs::write(&occupied, "not a directory").unwrap();

    assert!(open_run_log(&occupied, true).is_none());
}

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
fn standard_build_info_subcommand_is_exposed() {
    use clap::CommandFactory;

    let mut command = RunCli::command();
    let build_info = command
        .find_subcommand_mut("build-info")
        .expect("build-info command must exist");
    assert!(build_info
        .get_arguments()
        .any(|argument| argument.get_long() == Some("json")));
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
fn product_offline_bundle_arguments_are_all_or_none() {
    use clap::error::ErrorKind;

    let root = std::env::current_dir().unwrap().join("offline-bundle");
    let options = [
        ("--offline", None),
        ("--root-document", Some(root.join("root.json"))),
        ("--manifest", Some(root.join("manifest.json"))),
        ("--artifact", Some(root.join("artifact"))),
    ];
    for operation in ["install", "update"] {
        for included in 0..16 {
            let mut arguments = vec![
                "update-all".into(),
                "product".into(),
                operation.into(),
                "dev-cache".into(),
                "--json".into(),
            ];
            for (index, (flag, path)) in options.iter().enumerate() {
                if included & (1 << index) != 0 {
                    arguments.push(std::ffi::OsString::from(*flag));
                    if let Some(path) = path {
                        arguments.push(path.as_os_str().to_owned());
                    }
                }
            }
            let parsed = RunCli::try_parse_from(arguments);
            if included == 0 || included == 15 {
                assert!(parsed.is_ok(), "{operation} flags {included}: {parsed:?}");
            } else {
                assert_eq!(
                    parsed.unwrap_err().kind(),
                    ErrorKind::MissingRequiredArgument,
                    "{operation} flags {included} must require the complete bundle",
                );
            }
        }
    }
}

#[test]
fn product_offline_bundle_arguments_preserve_paths_and_json() {
    let root = std::env::current_dir().unwrap().join("offline bundle");
    let root_document = root.join("root.json");
    let manifest = root.join("manifest.json");
    let artifact = root.join("artifact");
    for operation in ["install", "update"] {
        let parsed = RunCli::try_parse_from([
            std::ffi::OsString::from("update-all"),
            "product".into(),
            operation.into(),
            "dev-cache".into(),
            "--offline".into(),
            "--root-document".into(),
            root_document.as_os_str().to_owned(),
            "--manifest".into(),
            manifest.as_os_str().to_owned(),
            "--artifact".into(),
            artifact.as_os_str().to_owned(),
            "--json".into(),
        ])
        .unwrap();
        let Some(RunSubcommand::Product(product)) = parsed.subcommand else {
            panic!("expected product subcommand");
        };
        let (parsed_operation, cli) = match product.cmd {
            ProductCmd::Install(cli) => ("install", cli),
            ProductCmd::Update(cli) => ("update", cli),
            _ => panic!("expected product activation subcommand"),
        };
        assert_eq!(parsed_operation, operation);
        assert!(matches!(cli.output.product, ProductName::DevCache));
        assert!(cli.output.json);
        assert!(cli.offline);
        assert_eq!(cli.root_document.as_ref(), Some(&root_document));
        assert_eq!(cli.manifest.as_ref(), Some(&manifest));
        assert_eq!(cli.artifact.as_ref(), Some(&artifact));
    }
}

#[test]
fn product_offline_bundle_flags_are_scoped_to_install_and_update() {
    use clap::{error::ErrorKind, CommandFactory};

    let command = RunCli::command();
    let product = command.find_subcommand("product").unwrap();
    for operation in ["install", "update"] {
        let activation = product.find_subcommand(operation).unwrap();
        for flag in ["offline", "root-document", "manifest", "artifact"] {
            assert!(activation
                .get_arguments()
                .any(|argument| argument.get_long() == Some(flag)));
        }
    }
    for family in ["product", "self", "update"] {
        let subcommands = command.find_subcommand(family).unwrap();
        for operation in subcommands.get_subcommands() {
            if family == "product" && matches!(operation.get_name(), "install" | "update") {
                continue;
            }
            for flag in ["offline", "root-document", "manifest", "artifact"] {
                assert!(
                    !operation
                        .get_arguments()
                        .any(|argument| argument.get_long() == Some(flag)),
                    "{family} {} must not accept --{flag}",
                    operation.get_name(),
                );
                let mut arguments = vec![
                    "update-all".to_string(),
                    family.to_string(),
                    operation.get_name().to_string(),
                ];
                if family == "product" {
                    arguments.push("dev-cache".to_string());
                }
                arguments.push(format!("--{flag}"));
                if flag != "offline" {
                    arguments.push("unused-path".to_string());
                }
                assert_eq!(
                    RunCli::try_parse_from(arguments).unwrap_err().kind(),
                    ErrorKind::UnknownArgument,
                );
            }
        }
    }
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
    let original_rc_root = std::env::var_os("RC_ROOT");
    std::env::set_var("UPDATE_ALL_COMPLETION_ROOT", &managed_root);
    std::env::set_var("RC_ROOT", temp.path().join("legacy-checkout"));

    let paths = resolve_completion_paths();

    match original {
        Some(value) => std::env::set_var("UPDATE_ALL_COMPLETION_ROOT", value),
        None => std::env::remove_var("UPDATE_ALL_COMPLETION_ROOT"),
    }
    match original_rc_root {
        Some(value) => std::env::set_var("RC_ROOT", value),
        None => std::env::remove_var("RC_ROOT"),
    }
    assert_eq!(paths.managed_root, managed_root);
    assert_eq!(
        paths.catalog_path,
        managed_root.join("cache/managed-tools.json")
    );
    assert_eq!(
        paths.registry_path,
        managed_root.join("cache/audit-registry.json")
    );
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

#[test]
fn completion_shell_selection_normalizes_deduplicates_and_keeps_all_exclusive() {
    let selected = crate::completions::resolve_completion_shells(
        &["zsh".to_string(), "BASH".to_string(), "zsh".to_string()],
        &["fish".to_string()],
    )
    .unwrap();
    assert_eq!(
        selected
            .iter()
            .map(|shell| shell.as_event_name())
            .collect::<Vec<_>>(),
        ["bash", "zsh"]
    );

    let all = crate::completions::resolve_completion_shells(&["all".to_string()], &[]).unwrap();
    assert_eq!(all.len(), 5);
    let error =
        crate::completions::resolve_completion_shells(&["all".to_string(), "zsh".to_string()], &[])
            .unwrap_err();
    assert!(format!("{error:#}").contains("mutually exclusive"));
}

#[test]
fn ordinary_completion_mode_is_public_refresh_and_rejects_the_implicit_legacy_audit() {
    assert_eq!(resolve_completion_mode(None).unwrap(), "refresh");
    assert_eq!(
        resolve_completion_mode(Some(" OFF ".to_string())).unwrap(),
        "off"
    );
    let error = resolve_completion_mode(Some("refresh+audit".to_string())).unwrap_err();
    let message = format!("{error:#}");
    assert!(message.contains("is retired"), "{message}");
    assert!(message.contains("--audit-command"), "{message}");
}
