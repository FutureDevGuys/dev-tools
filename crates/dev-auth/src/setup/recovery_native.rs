//! Complete-receipt recovery in an explicitly owned, disposable systemd root.
//! Synthetic retained provenance is not signature or release acceptance.
use super::*;

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_initial_receipt_completion() {
    let (_lease, plan, candidate) = fixture(None);
    exercise(&plan, None, &candidate);
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_upgrade_receipt_completion() {
    let (_lease, plan, candidate) = fixture(Some(0o644));
    let prior = read_receipt(&plan.paths.receipt_path()).unwrap();
    let prior_shared = retained_candidate_shared_receipt(&prior_plan(&plan), &prior, None).unwrap();
    exercise(&plan, Some((&prior, &prior_shared)), &candidate);
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_private_prior_receipt_completion() {
    let (_lease, plan, candidate) = fixture(Some(0o600));
    let prior = read_receipt(&plan.paths.receipt_path()).unwrap();
    let prior_shared = retained_candidate_shared_receipt(&prior_plan(&plan), &prior, None).unwrap();
    exercise(&plan, Some((&prior, &prior_shared)), &candidate);
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_initial_helper_completion() {
    let (_lease, plan, candidate) = fixture(None);
    exercise_helper(&plan, None, &candidate);
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_upgrade_helper_completion() {
    let (_lease, plan, candidate) = fixture(Some(0o600));
    let prior = read_receipt(&plan.paths.receipt_path()).unwrap();
    let prior_shared = retained_candidate_shared_receipt(&prior_plan(&plan), &prior, None).unwrap();
    exercise_helper(&plan, Some((&prior, &prior_shared)), &candidate);
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_initial_assets_completion() {
    let (_lease, plan, candidate) = fixture(None);
    exercise_assets(&plan, None, candidate);
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_missing_asset_parent_completion() {
    let (_lease, plan, candidate) = fixture(None);
    systemctl(&["daemon-reload"]);
    let parent = Path::new("/etc/sysusers.d");
    let path = parent.join("dev-auth.conf");
    fs::remove_file(&path).unwrap();
    fs::remove_dir(parent).unwrap();
    let proof = retained_candidate_validation(&plan, None).unwrap();
    assert!(!parent.exists());
    fs::create_dir(parent).unwrap();
    fs::set_permissions(parent, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(proof
        .finish_binary_transition(|_| panic!("late parent caused mutation"))
        .is_err());
    assert!(!path.exists());
    fs::remove_dir(parent).unwrap();
    let proof = retained_candidate_validation(&plan, None).unwrap();
    let mut changed = false;
    assert!(proof
        .finish_binary_transition(|value| {
            if value && !changed {
                changed = true;
                assert!(parent.is_dir());
                publish(&path, b"independent late definition", 0o644);
            }
        })
        .is_err());
    assert!(changed);
    assert_eq!(fs::read(&path).unwrap(), b"independent late definition");
    assert!(!plan.paths.receipt_path().exists());
    fs::remove_file(&path).unwrap();
    assert!(retained_candidate_validation(&plan, None)
        .unwrap()
        .finish_binary_transition(|_| {})
        .unwrap());
    assert_eq!(read_receipt(&plan.paths.receipt_path()).unwrap(), candidate);
    assert_eq!(parent.metadata().unwrap().mode() & 0o7777, 0o755);
    assert_eq!(parent.metadata().unwrap().uid(), 0);
    verify_at_read_only(&plan.paths).unwrap();
    assert!(!retained_candidate_validation(&plan, None)
        .unwrap()
        .finish_binary_transition(|_| panic!("completed parent retry mutated"))
        .unwrap());
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_upgrade_assets_completion() {
    let (_lease, plan, candidate) = fixture(Some(0o600));
    let mut prior = read_receipt(&plan.paths.receipt_path()).unwrap();
    for (path, content, _) in SYSTEM_ASSETS {
        let bytes = old_asset(content);
        prior
            .system_assets
            .insert(path.into(), format!("{:x}", Sha256::digest(&bytes)));
    }
    publish(
        &plan.paths.receipt_path(),
        &serde_json::to_vec_pretty(&prior).unwrap(),
        0o600,
    );
    let prior_shared = retained_candidate_shared_receipt(&prior_plan(&plan), &prior, None).unwrap();
    exercise_assets(&plan, Some((&prior, &prior_shared)), candidate);
}

fn old_asset(content: &str) -> Vec<u8> {
    // Comments produce valid prior definitions without adding execution authority.
    if content.starts_with("<?xml") {
        content
            .replace("?>", "?>\n<!-- retained prior fixture -->")
            .into_bytes()
    } else {
        format!("# retained prior fixture\n{content}").into_bytes()
    }
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_initial_launcher_completion() {
    let (_lease, plan, candidate) = fixture(None);
    exercise_launcher(&plan, None, &candidate);
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_upgrade_launcher_completion() {
    let (_lease, plan, candidate) = fixture(Some(0o600));
    let prior = read_receipt(&plan.paths.receipt_path()).unwrap();
    let prior_shared = retained_candidate_shared_receipt(&prior_plan(&plan), &prior, None).unwrap();
    exercise_launcher(&plan, Some((&prior, &prior_shared)), &candidate);
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_legacy_launcher_completion() {
    let (_lease, plan, candidate) = fixture_for_prior(Some(0o600), "0.3.11");
    let prior = read_receipt(&plan.paths.receipt_path()).unwrap();
    let prior_shared =
        retained_candidate_shared_receipt(&prior_plan_version(&plan, "0.3.11"), &prior, None)
            .unwrap();
    exercise_launcher(&plan, Some((&prior, &prior_shared)), &candidate);
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_initial_staged_binary_completion() {
    let (_lease, plan, candidate) = fixture(None);
    exercise_staged_binary(&plan, None, &candidate);
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_upgrade_staged_binary_completion() {
    let (_lease, plan, candidate) = fixture(Some(0o600));
    let prior = read_receipt(&plan.paths.receipt_path()).unwrap();
    let prior_shared = retained_candidate_shared_receipt(&prior_plan(&plan), &prior, None).unwrap();
    exercise_staged_binary(&plan, Some((&prior, &prior_shared)), &candidate);
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_initial_unstaged_binary_completion() {
    let (_lease, plan, candidate) = fixture(None);
    exercise_unstaged_binary(&plan, None, &candidate);
}

#[test]
#[ignore = "requires an explicitly owned disposable systemd container; never run on the host"]
fn native_disposable_strong_upgrade_unstaged_binary_completion() {
    let (_lease, plan, candidate) = fixture(Some(0o600));
    let prior = read_receipt(&plan.paths.receipt_path()).unwrap();
    let prior_shared = retained_candidate_shared_receipt(&prior_plan(&plan), &prior, None).unwrap();
    exercise_unstaged_binary(&plan, Some((&prior, &prior_shared)), &candidate);
}

fn exercise_unstaged_binary(
    plan: &SetupPlan,
    prior: Option<(&InstallReceipt, &dev_tools_installation::VersionedReceipt)>,
    candidate: &InstallReceipt,
) {
    let paths = &plan.paths;
    let source = if prior.is_some() {
        Path::new("/retained-running/dev-auth-linux-x86_64")
    } else {
        Path::new("/retained-running/dev-auth")
    };
    let bytes = fs::read(&candidate.executable).unwrap();
    let original_product = fs::read(paths.receipt_path()).ok();
    let layout = shared_installation_layout(paths, InstallMode::Strong);
    let shared = retained_candidate_shared_receipt(plan, candidate, prior).unwrap();
    let journal = paths.data_root.join("installation-transition-v1.json");
    let set_unstaged = |remove_layout: bool| {
        publish(source, &bytes, 0o755);
        match &original_product {
            Some(bytes) => publish(&paths.receipt_path(), bytes, 0o600),
            None => {
                if paths.receipt_path().exists() {
                    fs::remove_file(paths.receipt_path()).unwrap();
                }
            }
        }
        let shared_path = paths.data_root.join("installation-receipt-v1.json");
        match prior {
            Some((_, prior)) => publish(&shared_path, &serde_json::to_vec(prior).unwrap(), 0o600),
            None => {
                fs::remove_file(&shared_path).unwrap();
            }
        }
        publish(&journal, &serde_json::to_vec(&serde_json::json!({
            "schema": "dev-tools-versioned-transition-v1", "prior": prior.map(|(_, shared)| shared), "next": shared,
        })).unwrap(), 0o600);
        dev_tools_installation::recover_versioned_installation_transition(
            &layout,
            prior.map(|(_, shared)| shared),
            &shared,
            BINARY_LIMIT,
            |_| Ok(()),
        )
        .unwrap();
        fs::remove_file(&candidate.executable).unwrap();
        fs::remove_dir(Path::new(&candidate.executable).parent().unwrap()).unwrap();
        if remove_layout {
            assert!(prior.is_none());
            fs::remove_file(paths.data_root.join("installation.lock")).unwrap();
            fs::remove_dir(paths.data_root.join("versions")).unwrap();
            fs::remove_dir(&paths.bin_dir).unwrap();
        }
        for leaf in [
            PathBuf::from(PRIVILEGED_LAUNCHER_PATH),
            PathBuf::from(SETUP_HELPER_PATH),
            setup_helper_receipt_path(paths),
        ]
        .into_iter()
        .chain(SYSTEM_ASSETS.iter().map(|(path, _, _)| PathBuf::from(path)))
        {
            fs::remove_file(leaf).unwrap();
        }
        systemctl(&["daemon-reload"]);
    };
    for remove_layout in [false].into_iter().chain(prior.is_none().then_some(true)) {
        set_unstaged(remove_layout);
        let proof = retained_candidate_validation_from_source(plan, prior, Some(source)).unwrap();
        assert!(!Path::new(&candidate.executable).exists());
        if remove_layout {
            assert!(!paths.bin_dir.exists());
            assert!(!paths.data_root.join("versions").exists());
            assert!(!paths.data_root.join("installation.lock").exists());
        }
        assert!(proof.finish_binary_transition(|_| {}).unwrap());
        verify_at_read_only(paths).unwrap();
        assert_eq!(read_receipt(&paths.receipt_path()).unwrap(), *candidate);
        fs::remove_file(source).unwrap();
        assert!(!retained_candidate_validation(plan, prior)
            .unwrap()
            .finish_binary_transition(|_| panic!("complete unstaged retry mutated"))
            .unwrap());
    }
    set_unstaged(false);
    let proof = retained_candidate_validation_from_source(plan, prior, Some(source)).unwrap();
    publish(&journal, b"independent binary journal", 0o600);
    assert!(proof
        .finish_binary_transition(|_| panic!("unowned late journal mutated"))
        .is_err());
    assert_eq!(fs::read(&journal).unwrap(), b"independent binary journal");
    assert!(!Path::new(&candidate.executable).exists());
    fs::remove_file(&journal).unwrap();
    fs::set_permissions(source, fs::Permissions::from_mode(0o4755)).unwrap();
    assert!(retained_candidate_validation_from_source(plan, prior, Some(source)).is_err());
    fs::set_permissions(source, fs::Permissions::from_mode(0o755)).unwrap();
    fs::hard_link(source, "/extra-source-link").unwrap();
    assert!(retained_candidate_validation_from_source(plan, prior, Some(source)).is_err());
    fs::remove_file("/extra-source-link").unwrap();
    publish(source, b"independent running source", 0o755);
    assert!(proof
        .finish_binary_transition(|_| panic!("changed source published"))
        .is_err());
    assert!(!Path::new(&candidate.executable).exists());
    publish(source, &bytes, 0o755);
    let mut committed = false;
    assert!(proof
        .finish_binary_transition(|value| {
            if value && !committed {
                committed = true;
                fs::remove_file(source).unwrap();
            }
        })
        .is_err());
    assert!(committed);
    assert_eq!(
        dev_tools_installation::observe_versioned_installation(&layout, BINARY_LIMIT).unwrap(),
        Some(shared)
    );
    assert_eq!(fs::read(paths.receipt_path()).ok(), original_product);
    assert!(!Path::new(PRIVILEGED_LAUNCHER_PATH).exists());
    // After binary commit the installed immutable candidate replaces the lost
    // disposable source on a fresh proof; no original input is required.
    assert!(retained_candidate_validation(plan, prior)
        .unwrap()
        .finish_binary_transition(|_| {})
        .unwrap());
    verify_at_read_only(paths).unwrap();
}

fn exercise_staged_binary(
    plan: &SetupPlan,
    prior: Option<(&InstallReceipt, &dev_tools_installation::VersionedReceipt)>,
    candidate: &InstallReceipt,
) {
    let paths = &plan.paths;
    let layout = shared_installation_layout(paths, InstallMode::Strong);
    let shared = retained_candidate_shared_receipt(plan, candidate, prior).unwrap();
    let original_product = fs::read(paths.receipt_path()).ok();
    let journal = paths.data_root.join("installation-transition-v1.json");
    let journal_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "dev-tools-versioned-transition-v1", "prior": prior.map(|(_, shared)| shared), "next": shared,
    })).unwrap();
    let set_pending = |settle: bool| {
        match &original_product {
            Some(bytes) => publish(&paths.receipt_path(), bytes, 0o600),
            None => {
                if paths.receipt_path().exists() {
                    fs::remove_file(paths.receipt_path()).unwrap();
                }
            }
        }
        let receipt = paths.data_root.join("installation-receipt-v1.json");
        match prior {
            Some((_, prior)) => publish(&receipt, &serde_json::to_vec(prior).unwrap(), 0o600),
            None => {
                fs::remove_file(&receipt).unwrap();
            }
        }
        publish(&journal, &journal_bytes, 0o600);
        fs::remove_file(paths.bin_dir.join("git-dev-auth")).unwrap();
        fs::remove_file(paths.data_root.join("active")).unwrap();
        if settle {
            dev_tools_installation::recover_versioned_installation_transition(
                &layout,
                prior.map(|(_, shared)| shared),
                &shared,
                BINARY_LIMIT,
                |_| Ok(()),
            )
            .unwrap();
        }
        // Strong fixed leaves may also be interrupted. Their prior observations
        // must stay bound while the shared binary endpoint is restored/committed.
        for leaf in [
            PathBuf::from(PRIVILEGED_LAUNCHER_PATH),
            PathBuf::from(SETUP_HELPER_PATH),
            setup_helper_receipt_path(paths),
            PathBuf::from(SYSTEM_ASSETS[1].0),
        ] {
            fs::remove_file(leaf).unwrap();
        }
        systemctl(&["daemon-reload"]);
    };
    for settle in [false, true] {
        set_pending(settle);
        let proof = retained_candidate_validation(plan, prior).unwrap();
        let mut known_change = false;
        assert!(proof
            .finish_binary_transition(|value| known_change |= value)
            .unwrap());
        assert!(known_change);
        assert!(!journal.exists());
        assert_eq!(read_receipt(&paths.receipt_path()).unwrap(), *candidate);
        assert_eq!(
            dev_tools_installation::observe_versioned_installation(&layout, BINARY_LIMIT).unwrap(),
            Some(shared.clone())
        );
        verify_at_read_only(paths).unwrap();
        assert!(!retained_candidate_validation(plan, prior)
            .unwrap()
            .finish_binary_transition(|_| panic!("complete staged retry mutated"))
            .unwrap());
    }
    set_pending(false);
    let proof = retained_candidate_validation(plan, prior).unwrap();
    publish(
        Path::new(SETUP_HELPER_PATH),
        b"foreign helper before binary settlement",
        0o755,
    );
    assert!(proof
        .finish_binary_transition(|_| panic!("stale strong selection mutated binary"))
        .is_err());
    assert_eq!(fs::read(&journal).unwrap(), journal_bytes);
    fs::remove_file(SETUP_HELPER_PATH).unwrap();
    let alias = paths.bin_dir.join("git-dev-auth");
    publish(&alias, b"independent alias", 0o755);
    assert!(retained_candidate_validation(plan, prior).is_err());
    assert_eq!(fs::read(&alias).unwrap(), b"independent alias");
    assert_eq!(fs::read(&journal).unwrap(), journal_bytes);
    fs::remove_file(&alias).unwrap();
    let mut settled = false;
    assert!(proof
        .finish_binary_transition(|value| {
            if value && !settled {
                settled = true;
                publish(
                    &paths.receipt_path(),
                    b"independent product after binary settlement",
                    0o644,
                );
            }
        })
        .is_err());
    assert!(settled);
    assert!(!journal.exists());
    assert!(!Path::new(PRIVILEGED_LAUNCHER_PATH).exists());
    assert_eq!(
        dev_tools_installation::observe_versioned_installation(&layout, BINARY_LIMIT)
            .unwrap()
            .as_ref(),
        prior.map(|(_, shared)| shared)
    );
    assert_eq!(
        fs::read(paths.receipt_path()).unwrap(),
        b"independent product after binary settlement"
    );
    match original_product {
        Some(bytes) => publish(&paths.receipt_path(), &bytes, 0o600),
        None => fs::remove_file(paths.receipt_path()).unwrap(),
    }
    assert!(retained_candidate_validation(plan, prior)
        .unwrap()
        .finish_binary_transition(|_| {})
        .unwrap());
    verify_at_read_only(paths).unwrap();
}

fn exercise_launcher(
    plan: &SetupPlan,
    prior: Option<(&InstallReceipt, &dev_tools_installation::VersionedReceipt)>,
    candidate: &InstallReceipt,
) {
    let launcher = Path::new(PRIVILEGED_LAUNCHER_PATH);
    let helper = Path::new(SETUP_HELPER_PATH);
    let helper_bytes = fs::read(helper).unwrap();
    let product = plan.paths.receipt_path();
    let original = fs::read(&product).ok();
    let reset_product = || match &original {
        Some(bytes) => publish(&product, bytes, 0o600),
        None => {
            if product.exists() {
                fs::remove_file(&product).unwrap();
            }
        }
    };
    let immutable = std::iter::once(helper.to_path_buf())
        .chain(std::iter::once(setup_helper_receipt_path(&plan.paths)))
        .chain(SYSTEM_ASSETS.iter().map(|(path, _, _)| PathBuf::from(path)))
        .map(|path| {
            let meta = fs::metadata(&path).unwrap();
            (path, (meta.dev(), meta.ino(), meta.mode()))
        })
        .collect::<Vec<_>>();
    let bytes = fs::read(&candidate.executable).unwrap();
    let prior_bytes = prior.map(|(prior, _)| fs::read(&prior.executable).unwrap());
    let prior_mode =
        prior.map(|(prior, _)| privileged_launcher_mode_for_version(&prior.version).unwrap());
    let mut selections = vec![
        (None, 0o755),
        (Some(bytes.as_slice()), 0o755),
        (Some(bytes.as_slice()), 0o4755),
    ];
    if let Some(bytes) = &prior_bytes {
        selections.push((Some(bytes), 0o755));
        if prior_mode != Some(0o755) {
            selections.push((Some(bytes), prior_mode.unwrap()));
        }
    }
    for (selection, mode) in selections {
        reset_product();
        match selection {
            Some(bytes) => publish(launcher, bytes, mode),
            None => {
                fs::remove_file(launcher).unwrap();
            }
        }
        let old = selection
            .filter(|selected| *selected != bytes.as_slice())
            .map(|_| File::open(launcher).unwrap());
        let proof = retained_candidate_validation(plan, prior).unwrap();
        assert!(proof.finish_binary_transition(|_| {}).unwrap());
        assert_eq!(fs::read(launcher).unwrap(), bytes);
        assert_eq!(fs::metadata(launcher).unwrap().mode() & 0o7777, 0o4755);
        if let Some(old) = old {
            assert_eq!(old.metadata().unwrap().mode() & 0o7777, 0o755);
            assert_eq!(old.metadata().unwrap().nlink(), 0);
        }
        assert_eq!(read_receipt(&product).unwrap(), *candidate);
        verify_at_read_only(&plan.paths).unwrap();
        assert!(!retained_candidate_validation(plan, prior)
            .unwrap()
            .finish_binary_transition(|_| panic!("complete launcher retry mutated"))
            .unwrap());
    }
    reset_product();
    fs::remove_file(launcher).unwrap();
    let proof = retained_candidate_validation(plan, prior).unwrap();
    publish(launcher, &bytes, 0o755);
    assert!(proof
        .finish_binary_transition(|_| panic!("stale launcher proof mutated"))
        .is_err());
    assert_eq!(fs::metadata(launcher).unwrap().mode() & 0o7777, 0o755);
    fs::remove_file(launcher).unwrap();
    let mut changed = false;
    assert!(proof
        .finish_binary_transition(|value| {
            if value && !changed {
                changed = true;
                publish(launcher, b"independent launcher", 0o755);
            }
        })
        .is_err());
    assert!(changed);
    assert_eq!(fs::read(launcher).unwrap(), b"independent launcher");
    assert_eq!(fs::read(&product).ok(), original);
    assert!(retained_candidate_validation(plan, prior).is_err());
    fs::remove_file(launcher).unwrap();
    // Break the enclosing generation immediately after each available mutation
    // boundary. A fresh proof can resume only after independent correction.
    let mut interruptions = vec![
        (None, 0o755, 0o755),
        (Some(bytes.as_slice()), 0o755, 0o4755),
    ];
    if prior_mode == Some(0o4755) {
        interruptions.push((prior_bytes.as_deref(), 0o4755, 0o755));
    }
    for (selection, mode, intermediate_mode) in interruptions {
        reset_product();
        if launcher.exists() {
            fs::remove_file(launcher).unwrap();
        }
        if let Some(selected) = selection {
            publish(launcher, selected, mode);
        }
        let proof = retained_candidate_validation(plan, prior).unwrap();
        let mut changed = false;
        assert!(proof
            .finish_binary_transition(|value| {
                if value && !changed {
                    changed = true;
                    publish(helper, b"independent helper", 0o755);
                }
            })
            .is_err());
        assert!(changed);
        assert_eq!(
            fs::metadata(launcher).unwrap().mode() & 0o7777,
            intermediate_mode
        );
        assert_eq!(fs::read(helper).unwrap(), b"independent helper");
        assert_eq!(fs::read(&product).ok(), original);
        assert!(retained_candidate_validation(plan, prior).is_err());
        publish(helper, &helper_bytes, 0o755);
        assert!(retained_candidate_validation(plan, prior)
            .unwrap()
            .finish_binary_transition(|_| {})
            .unwrap());
    }
    reset_product();
    for mode in [0o6755, 0o1755, 0o777, 0o700] {
        publish(launcher, &bytes, mode);
        assert!(retained_candidate_validation(plan, prior).is_err());
        assert_eq!(fs::metadata(launcher).unwrap().mode() & 0o7777, mode);
    }
    if prior_mode == Some(0o755) {
        publish(launcher, prior_bytes.as_deref().unwrap(), 0o4755);
        assert!(
            retained_candidate_validation(plan, prior).is_err(),
            "a successor mode cannot grant privilege to legacy bytes"
        );
    }
    publish(launcher, &bytes, 0o4755);
    fs::hard_link(launcher, "/extra-launcher-link").unwrap();
    assert!(retained_candidate_validation(plan, prior).is_err());
    fs::remove_file("/extra-launcher-link").unwrap();
    fs::remove_file(launcher).unwrap();
    symlink(&candidate.executable, launcher).unwrap();
    assert!(retained_candidate_validation(plan, prior).is_err());
    fs::remove_file(launcher).unwrap();
    fs::set_permissions(&candidate.executable, fs::Permissions::from_mode(0o4755)).unwrap();
    assert!(retained_candidate_validation(plan, prior).is_err());
    fs::set_permissions(&candidate.executable, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(retained_candidate_validation(plan, prior)
        .unwrap()
        .finish_binary_transition(|_| {})
        .unwrap());
    for (path, expected) in immutable {
        let meta = fs::metadata(path).unwrap();
        assert_eq!((meta.dev(), meta.ino(), meta.mode()), expected);
    }
}

fn exercise_assets(
    plan: &SetupPlan,
    prior: Option<(&InstallReceipt, &dev_tools_installation::VersionedReceipt)>,
    mut candidate: InstallReceipt,
) {
    candidate.previous_release = prior.map(|(prior, _)| retained_release(prior));
    let product = plan.paths.receipt_path();
    let original = fs::read(&product).ok();
    let reset_product = || match &original {
        Some(bytes) => publish(&product, bytes, 0o600),
        None => {
            if product.exists() {
                fs::remove_file(&product).unwrap();
            }
        }
    };
    let helper_before = [
        PathBuf::from(PRIVILEGED_LAUNCHER_PATH),
        PathBuf::from(SETUP_HELPER_PATH),
        setup_helper_receipt_path(&plan.paths),
    ]
    .map(|path| {
        let meta = fs::metadata(&path).unwrap();
        (path, (meta.dev(), meta.ino(), meta.mode()))
    });
    // Every leaf is missing once and prior once; rotating the selections covers
    // mixed interrupted generations as well as completely absent definitions.
    for round in 0..(if prior.is_some() { 5 } else { 3 }) {
        reset_product();
        for (index, (path, content, mode)) in SYSTEM_ASSETS.into_iter().enumerate() {
            let state = if round == 0 {
                0
            } else {
                (index + round) % if prior.is_some() { 3 } else { 2 }
            };
            if state == 0 {
                fs::remove_file(path).unwrap();
            } else if state == 2 {
                publish(Path::new(path), &old_asset(content), mode);
            }
        }
        systemctl(&["daemon-reload"]);
        let proof = retained_candidate_validation(plan, prior).unwrap();
        let mut changed = false;
        assert!(proof
            .finish_binary_transition(|value| changed |= value)
            .unwrap());
        assert!(changed);
        assert_eq!(read_receipt(&product).unwrap(), candidate);
        verify_at_read_only(&plan.paths).unwrap();
        for (path, content, mode) in SYSTEM_ASSETS {
            assert_eq!(fs::read(path).unwrap(), content.as_bytes());
            assert_eq!(fs::metadata(path).unwrap().mode() & 0o7777, mode);
        }
        assert!(!retained_candidate_validation(plan, prior)
            .unwrap()
            .finish_binary_transition(|_| panic!("completed asset retry mutated"))
            .unwrap());
    }
    reset_product();
    let (first, first_bytes, _) = SYSTEM_ASSETS[0];
    let (second, second_bytes, _) = SYSTEM_ASSETS[1];
    fs::remove_file(first).unwrap();
    fs::remove_file(second).unwrap();
    systemctl(&["daemon-reload"]);
    let proof = retained_candidate_validation(plan, prior).unwrap();
    publish(Path::new(first), first_bytes.as_bytes(), 0o644);
    assert!(proof
        .finish_binary_transition(|_| panic!("stale asset proof mutated"))
        .is_err());
    assert!(!Path::new(second).exists());
    fs::remove_file(first).unwrap();
    let mut changed = false;
    assert!(proof
        .finish_binary_transition(|value| {
            if value && !changed {
                changed = true;
                publish(Path::new(second), b"independent definition", 0o644);
            }
        })
        .is_err());
    assert!(changed);
    assert_eq!(fs::read(first).unwrap(), first_bytes.as_bytes());
    assert_eq!(fs::read(second).unwrap(), b"independent definition");
    assert_eq!(fs::read(&product).ok(), original);
    assert!(retained_candidate_validation(plan, prior).is_err());
    fs::remove_file(second).unwrap();
    assert!(retained_candidate_validation(plan, prior)
        .unwrap()
        .finish_binary_transition(|_| {})
        .unwrap());
    reset_product();
    for (path, content, mode) in SYSTEM_ASSETS {
        publish(Path::new(path), b"foreign definition", mode);
        assert!(retained_candidate_validation(plan, prior).is_err());
        assert_eq!(fs::read(path).unwrap(), b"foreign definition");
        publish(Path::new(path), content.as_bytes(), mode | 0o4000);
        assert!(retained_candidate_validation(plan, prior).is_err());
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        fs::hard_link(path, "/extra-asset-link").unwrap();
        assert!(retained_candidate_validation(plan, prior).is_err());
        fs::remove_file("/extra-asset-link").unwrap();
        fs::remove_file(path).unwrap();
        symlink(&candidate.executable, path).unwrap();
        assert!(retained_candidate_validation(plan, prior).is_err());
        fs::remove_file(path).unwrap();
        publish(Path::new(path), content.as_bytes(), mode);
    }
    systemctl(&["daemon-reload"]);
    systemctl(&["start", "dev-auth-broker.socket"]);
    fs::remove_file(second).unwrap();
    assert!(retained_candidate_validation(plan, prior).is_err());
    assert_eq!(fs::read(&product).ok(), original);
    publish(Path::new(second), second_bytes.as_bytes(), 0o644);
    systemctl(&["stop", "dev-auth-broker.socket"]);
    systemctl(&["daemon-reload"]);
    assert!(retained_candidate_validation(plan, prior)
        .unwrap()
        .finish_binary_transition(|_| {})
        .unwrap());
    for (path, expected) in helper_before {
        let meta = fs::metadata(path).unwrap();
        assert_eq!((meta.dev(), meta.ino(), meta.mode()), expected);
    }
}

fn prior_plan(candidate: &SetupPlan) -> SetupPlan {
    prior_plan_version(candidate, "0.4.0")
}

fn prior_plan_version(candidate: &SetupPlan, version: &str) -> SetupPlan {
    let mut plan = candidate.clone();
    plan.request.version = version.into();
    plan.request.source_executable = PathBuf::from("/retained-prior-source");
    let identity = dev_tools_installation::ArtifactIdentity::from_file(
        &plan.paths.versioned_binary(&plan.request.version),
        BINARY_LIMIT,
    )
    .unwrap();
    plan.source_length = identity.length;
    plan.source_sha256 = identity.sha256;
    plan.verified_release = Some(provenance(&plan, 1));
    plan
}

fn provenance(
    plan: &SetupPlan,
    generation: u64,
) -> crate::release_manifest::VerifiedDevAuthRelease {
    crate::release_manifest::VerifiedDevAuthRelease {
        schema: "dev-auth-verified-release-v1".into(),
        root_path: "/unavailable-root".into(),
        manifest_path: "/unavailable-manifest".into(),
        root_generation: 1,
        manifest_generation: generation,
        version: plan.request.version.clone(),
        source_commit: "a".repeat(40),
        target: crate::release_manifest::target_id().unwrap(),
        artifact_path: plan.request.source_executable.clone(),
        artifact_url: "https://example.invalid/fixture".into(),
        artifact_length: plan.source_length,
        artifact_sha256: plan.source_sha256.clone(),
        root_sha256: "b".repeat(64),
        manifest_sha256: "c".repeat(64),
    }
}

fn fixture(
    prior_mode: Option<u32>,
) -> (
    dev_tools_installation::InstallationLock,
    SetupPlan,
    InstallReceipt,
) {
    fixture_for_prior(prior_mode, "0.4.0")
}

fn fixture_for_prior(
    prior_mode: Option<u32>,
    prior_version: &str,
) -> (
    dev_tools_installation::InstallationLock,
    SetupPlan,
    InstallReceipt,
) {
    assert_eq!(
        std::env::var("DEV_AUTH_NATIVE_SYSTEMD_FIXTURE").as_deref(),
        Ok("disposable")
    );
    assert!(nix::unistd::Uid::effective().is_root());
    assert!(Path::new("/run/.containerenv").is_file());
    assert_eq!(
        fs::read_to_string("/proc/1/comm").unwrap().trim(),
        "systemd"
    );
    let paths = SetupPaths::strong();
    for path in std::iter::once(paths.data_root.clone())
        .chain(SYSTEM_ASSETS.iter().map(|(path, _, _)| PathBuf::from(path)))
        .chain(
            PRODUCT_ALIASES
                .into_iter()
                .chain(TRANSPARENT_ALIASES)
                .map(|name| paths.bin_dir.join(name)),
        )
    {
        assert_eq!(
            fs::symlink_metadata(path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    let lock = crate::setup_transition::lock_path(crate::deployment::DeploymentMode::Strong, None)
        .unwrap();
    let lease = dev_tools_installation::InstallationLock::try_acquire(&lock)
        .unwrap()
        .unwrap();
    let source = PathBuf::from("/approved-source");
    publish(&source, b"exact synthetic candidate executable", 0o755);
    let (length, sha256) = file_identity(&source).unwrap();
    let mut plan = SetupPlan {
        schema: "dev-auth-setup-plan-v2".into(),
        paths: paths.clone(),
        request: InstallRequest {
            mode: InstallMode::Strong,
            version: if prior_mode.is_some() {
                "0.4.1"
            } else {
                "0.4.0"
            }
            .into(),
            source_executable: source.clone(),
            native_git: "/usr/bin/true".into(),
            native_gh: "/usr/bin/false".into(),
            activate_transparent_launchers: false,
        },
        source_length: length,
        source_sha256: sha256,
        verified_release: None,
    };
    plan.verified_release = Some(provenance(&plan, if prior_mode.is_some() { 2 } else { 1 }));
    let layout = shared_installation_layout(&paths, InstallMode::Strong);
    let prior = prior_mode.map(|mode| {
        let source = PathBuf::from("/retained-prior-source");
        publish(&source, b"exact synthetic prior executable", 0o755);
        let identity =
            dev_tools_installation::ArtifactIdentity::from_file(&source, BINARY_LIMIT).unwrap();
        dev_tools_installation::apply_versioned_installation(
            &dev_tools_installation::VersionedInstallRequest {
                layout: layout.clone(),
                version: prior_version.into(),
                source: source.clone(),
                identity,
                aliases: shared_product_aliases(),
            },
            |_| Ok(()),
        )
        .unwrap();
        let prior = prior_plan_version(&plan, prior_version);
        let receipt = selected_installation_receipt(
            &paths,
            &prior.request,
            prior.verified_release.as_ref(),
            None,
            &dev_tools_installation::ArtifactIdentity {
                length: prior.source_length,
                sha256: prior.source_sha256.clone(),
            },
        );
        publish(
            &paths.receipt_path(),
            &serde_json::to_vec_pretty(&receipt).unwrap(),
            mode,
        );
        fs::remove_file(source).unwrap();
        receipt
    });
    let identity = dev_tools_installation::ArtifactIdentity {
        length,
        sha256: plan.source_sha256.clone(),
    };
    dev_tools_installation::apply_versioned_installation(
        &dev_tools_installation::VersionedInstallRequest {
            layout,
            version: plan.request.version.clone(),
            source: source.clone(),
            identity: identity.clone(),
            aliases: shared_product_aliases(),
        },
        |_| Ok(()),
    )
    .unwrap();
    let candidate = selected_installation_receipt(
        &paths,
        &plan.request,
        plan.verified_release.as_ref(),
        prior.as_ref(),
        &identity,
    );
    let bytes = fs::read(&candidate.executable).unwrap();
    publish(Path::new(PRIVILEGED_LAUNCHER_PATH), &bytes, 0o4755);
    publish(Path::new(SETUP_HELPER_PATH), &bytes, 0o755);
    publish(
        &setup_helper_receipt_path(&paths),
        &serde_json::to_vec_pretty(&expected_setup_helper_receipt(
            Path::new(SETUP_HELPER_PATH),
            &candidate,
            &crate::release_manifest::target_id().unwrap(),
        ))
        .unwrap(),
        0o644,
    );
    for (path, content, mode) in SYSTEM_ASSETS {
        publish(Path::new(path), content.as_bytes(), mode);
    }
    fs::remove_file(source).unwrap();
    (lease, plan, candidate)
}

fn publish(path: &Path, bytes: &[u8], mode: u32) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn exercise(
    plan: &SetupPlan,
    prior: Option<(&InstallReceipt, &dev_tools_installation::VersionedReceipt)>,
    candidate: &InstallReceipt,
) {
    let receipt_path = plan.paths.receipt_path();
    let original_product = fs::read(&receipt_path).ok();
    let original_mode = fs::metadata(&receipt_path)
        .ok()
        .map(|metadata| metadata.mode() & 0o7777);
    let journal = plan.paths.data_root.join("installation-transition-v1.json");
    let shared = retained_candidate_shared_receipt(plan, candidate, prior).unwrap();
    let journal_bytes = serde_json::to_vec(&serde_json::json!({
        "schema": "dev-tools-versioned-transition-v1",
        "prior": prior.map(|(_, shared)| shared),
        "next": shared,
    }))
    .unwrap();
    publish(&journal, &journal_bytes, 0o600);
    let proof = retained_candidate_validation(plan, prior)
        .expect("complete strong assets permit retained receipt completion");
    if let Some(mode) = original_mode {
        let changed_mode = if mode == 0o600 { 0o644 } else { 0o600 };
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(changed_mode)).unwrap();
        assert!(proof
            .finish_binary_transition(|_| panic!("receipt mode collision caused mutation"))
            .is_err());
        assert_eq!(fs::read(&journal).unwrap(), journal_bytes);
        assert_eq!(
            fs::metadata(&receipt_path).unwrap().mode() & 0o7777,
            changed_mode
        );
        fs::set_permissions(&receipt_path, fs::Permissions::from_mode(mode)).unwrap();
    }
    let shared_path = plan.paths.data_root.join("installation-receipt-v1.json");
    let committed_shared = fs::read(&shared_path).unwrap();
    if let Some((_, shared)) = prior {
        publish(&shared_path, &serde_json::to_vec(shared).unwrap(), 0o600);
    } else {
        fs::remove_file(&shared_path).unwrap();
    }
    assert!(retained_candidate_validation(plan, prior).is_ok());
    assert!(proof
        .finish_binary_transition(|_| panic!(
            "stale committed proof recovered an uncommitted binary"
        ))
        .is_err());
    assert_eq!(fs::read(&journal).unwrap(), journal_bytes);
    assert_eq!(fs::read(&receipt_path).ok(), original_product);
    publish(&shared_path, &committed_shared, 0o600);
    let helper_bytes = fs::read(SETUP_HELPER_PATH).unwrap();
    fs::remove_file(SETUP_HELPER_PATH).unwrap();
    assert!(retained_candidate_validation(plan, prior).is_ok());
    assert!(proof
        .finish_binary_transition(|_| panic!("missing helper caused mutation"))
        .is_err());
    assert_eq!(fs::read(&journal).unwrap(), journal_bytes);
    publish(Path::new(SETUP_HELPER_PATH), &helper_bytes, 0o755);
    systemctl(&["daemon-reload"]);
    systemctl(&[
        "enable",
        "--now",
        "dev-auth-broker.socket",
        "dev-auth-broker-control.socket",
    ]);
    assert!(retained_candidate_validation(plan, prior).is_err());
    assert!(proof
        .finish_binary_transition(|_| panic!("active socket caused mutation"))
        .is_err());
    assert_eq!(fs::read(&receipt_path).ok(), original_product);
    assert_eq!(fs::read(&journal).unwrap(), journal_bytes);
    systemctl(&[
        "disable",
        "--now",
        "dev-auth-broker.socket",
        "dev-auth-broker-control.socket",
    ]);

    // Exact committed settlement is known change even if independent product
    // authority appears before the separately conditioned receipt publication.
    let mut settled = false;
    assert!(proof
        .finish_binary_transition(|changed| {
            if changed {
                settled = true;
                publish(&receipt_path, b"independent receipt bytes", 0o644);
            }
        })
        .is_err());
    assert!(settled);
    assert!(!journal.exists());
    assert_eq!(
        fs::read(&receipt_path).unwrap(),
        b"independent receipt bytes"
    );
    if let Some(bytes) = original_product {
        publish(&receipt_path, &bytes, original_mode.unwrap());
    } else {
        fs::remove_file(&receipt_path).unwrap();
    }
    let native_paths = [
        PathBuf::from(PRIVILEGED_LAUNCHER_PATH),
        PathBuf::from(SETUP_HELPER_PATH),
        setup_helper_receipt_path(&plan.paths),
    ]
    .into_iter()
    .chain(SYSTEM_ASSETS.iter().map(|(path, _, _)| PathBuf::from(path)));
    let before = native_paths
        .map(|path| {
            let metadata = fs::metadata(&path).unwrap();
            (path, (metadata.dev(), metadata.ino(), metadata.mode()))
        })
        .collect::<Vec<_>>();
    let mut changed = false;
    assert!(proof
        .finish_binary_transition(|value| changed |= value)
        .unwrap());
    assert!(changed);
    assert_eq!(
        read_receipt(&plan.paths.receipt_path()).unwrap(),
        *candidate
    );
    assert_eq!(
        fs::metadata(plan.paths.receipt_path()).unwrap().mode() & 0o7777,
        0o644
    );
    verify_at_read_only(&plan.paths).unwrap();
    assert!(!retained_candidate_validation(plan, prior)
        .unwrap()
        .finish_binary_transition(|_| panic!("completed receipt mutated"))
        .unwrap());
    for (path, expected) in before {
        let metadata = fs::metadata(path).unwrap();
        assert_eq!((metadata.dev(), metadata.ino(), metadata.mode()), expected);
    }
}

fn exercise_helper(
    plan: &SetupPlan,
    prior: Option<(&InstallReceipt, &dev_tools_installation::VersionedReceipt)>,
    candidate: &InstallReceipt,
) {
    let helper = Path::new(SETUP_HELPER_PATH);
    let sidecar = setup_helper_receipt_path(&plan.paths);
    let product_path = plan.paths.receipt_path();
    let original_product = fs::read(&product_path).ok();
    let candidate_bytes = fs::read(helper).unwrap();
    let candidate_sidecar = fs::read(&sidecar).unwrap();
    let prior_bytes = prior.map(|(prior, _)| fs::read(&prior.executable).unwrap());
    let prior_sidecar = prior.map(|(prior, _)| {
        // Semantic prior ownership does not depend on a serializer's whitespace.
        serde_json::to_vec(&expected_setup_helper_receipt(
            helper,
            prior,
            &crate::release_manifest::target_id().unwrap(),
        ))
        .unwrap()
    });
    let reset_product = || match &original_product {
        Some(bytes) => publish(&product_path, bytes, 0o600),
        None => {
            if product_path.exists() {
                fs::remove_file(&product_path).unwrap();
            }
        }
    };
    let set_leaf = |path: &Path, bytes: Option<&[u8]>, mode| match bytes {
        Some(bytes) => publish(path, bytes, mode),
        None => {
            if path.exists() {
                fs::remove_file(path).unwrap();
            }
        }
    };
    let immutable = std::iter::once(PathBuf::from(PRIVILEGED_LAUNCHER_PATH))
        .chain(SYSTEM_ASSETS.iter().map(|(path, _, _)| PathBuf::from(path)))
        .map(|path| {
            let metadata = fs::metadata(&path).unwrap();
            (path, (metadata.dev(), metadata.ino(), metadata.mode()))
        })
        .collect::<Vec<_>>();
    let helper_states = [None, Some(candidate_bytes.as_slice())]
        .into_iter()
        .chain(prior_bytes.as_deref().map(Some))
        .collect::<Vec<_>>();
    let sidecar_states = [None, Some(candidate_sidecar.as_slice())]
        .into_iter()
        .chain(prior_sidecar.as_deref().map(Some))
        .collect::<Vec<_>>();
    for helper_state in &helper_states {
        for sidecar_state in &sidecar_states {
            reset_product();
            set_leaf(helper, *helper_state, 0o755);
            set_leaf(&sidecar, *sidecar_state, 0o644);
            let proof = retained_candidate_validation(plan, prior).unwrap();
            let mut changes = 0;
            assert!(proof
                .finish_binary_transition(|changed| changes += usize::from(changed))
                .unwrap());
            assert!(changes >= 1);
            assert_eq!(fs::read(helper).unwrap(), candidate_bytes);
            assert_eq!(read_receipt(&product_path).unwrap(), *candidate);
            assert_eq!(fs::metadata(helper).unwrap().mode() & 0o7777, 0o755);
            assert_eq!(fs::metadata(&sidecar).unwrap().mode() & 0o7777, 0o644);
            verify_at_read_only(&plan.paths).unwrap();
            assert!(!retained_candidate_validation(plan, prior)
                .unwrap()
                .finish_binary_transition(|_| panic!("complete helper retry mutated"))
                .unwrap());
        }
    }
    reset_product();
    set_leaf(helper, None, 0o755);
    set_leaf(&sidecar, None, 0o644);
    let proof = retained_candidate_validation(plan, prior).unwrap();
    assert!(proof
        .binary_recovery_action()
        .ends_with("strong_installation"));
    // Even a valid independent writer invalidates a proof that selected absence.
    publish(helper, &candidate_bytes, 0o755);
    assert!(proof
        .finish_binary_transition(|_| panic!("stale helper proof mutated"))
        .is_err());
    assert!(!sidecar.exists());
    fs::remove_file(helper).unwrap();
    let mut known_change = false;
    assert!(proof
        .finish_binary_transition(|changed| {
            if changed && !known_change {
                known_change = true;
                publish(&sidecar, b"independent sidecar", 0o644);
            }
        })
        .is_err());
    assert!(known_change);
    assert_eq!(fs::read(helper).unwrap(), candidate_bytes);
    assert_eq!(fs::read(&sidecar).unwrap(), b"independent sidecar");
    assert_eq!(fs::read(&product_path).ok(), original_product);
    assert!(retained_candidate_validation(plan, prior).is_err());
    fs::remove_file(&sidecar).unwrap();
    // Interrupted mixed publication is resumable only through a fresh proof.
    assert!(retained_candidate_validation(plan, prior)
        .unwrap()
        .finish_binary_transition(|_| {})
        .unwrap());
    reset_product();
    for (path, correct, mode) in [
        (helper, &candidate_bytes, 0o755),
        (sidecar.as_path(), &candidate_sidecar, 0o644),
    ] {
        publish(path, b"foreign bytes", mode);
        assert!(retained_candidate_validation(plan, prior).is_err());
        assert_eq!(fs::read(path).unwrap(), b"foreign bytes");
        publish(path, correct, mode | 0o4000);
        assert!(retained_candidate_validation(plan, prior).is_err());
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        let extra = Path::new("/extra-helper-link");
        fs::hard_link(path, extra).unwrap();
        assert!(retained_candidate_validation(plan, prior).is_err());
        fs::remove_file(extra).unwrap();
        fs::remove_file(path).unwrap();
        symlink(&candidate.executable, path).unwrap();
        assert!(retained_candidate_validation(plan, prior).is_err());
        fs::remove_file(path).unwrap();
        publish(path, correct, mode);
    }
    // A sidecar with unknown fields cannot be adopted even with valid known fields.
    let mut extended: serde_json::Value = serde_json::from_slice(&candidate_sidecar).unwrap();
    extended["foreign_authority"] = true.into();
    publish(&sidecar, &serde_json::to_vec(&extended).unwrap(), 0o644);
    assert!(retained_candidate_validation(plan, prior).is_err());
    publish(&sidecar, &candidate_sidecar, 0o644);
    // Source custody is ordinary executable authority, never inherited set-ID.
    fs::set_permissions(&candidate.executable, fs::Permissions::from_mode(0o4755)).unwrap();
    assert!(retained_candidate_validation(plan, prior).is_err());
    fs::set_permissions(&candidate.executable, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(retained_candidate_validation(plan, prior)
        .unwrap()
        .finish_binary_transition(|_| {})
        .unwrap());
    for (path, expected) in immutable {
        let metadata = fs::metadata(path).unwrap();
        assert_eq!((metadata.dev(), metadata.ino(), metadata.mode()), expected);
    }
}

fn systemctl(arguments: &[&str]) {
    let arguments = ["--system", "--no-pager", "--no-ask-password"]
        .into_iter()
        .chain(arguments.iter().copied())
        .map(std::ffi::OsString::from)
        .collect::<Vec<_>>();
    let output = dev_tools_command::run_bounded_command(&dev_tools_command::BoundedCommand {
        executable: Path::new("/usr/bin/systemctl"),
        arguments: &arguments,
        environment: &BTreeMap::from([("LC_ALL".into(), "C".into())]),
        cwd: Some(Path::new("/")),
        timeout: Duration::from_secs(20),
        output_limit: 64 * 1024,
    })
    .unwrap();
    assert!(
        output.status.success(),
        "fixture systemctl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
