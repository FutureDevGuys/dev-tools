#![cfg(unix)]

use dev_auth::smart_binding::{
    advance_binding, classify_binding_change, require_automatic_refresh, resolve_continuation,
    validate_binding_receipt_structure, BindingAuthority, BindingChange, BindingIntent,
    BindingMode, BindingReceipt,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

fn executable(path: &Path, body: &[u8]) {
    fs::write(path, body).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn continuation_skips_owned_proxy_layers_and_preserves_the_resolution_cursor() {
    let root = tempfile::tempdir().unwrap();
    let proxy = root.path().join("proxy");
    let wrappers = root.path().join("wrappers");
    let vendor = root.path().join("vendor");
    fs::create_dir(&proxy).unwrap();
    fs::create_dir(&wrappers).unwrap();
    fs::create_dir(&vendor).unwrap();
    executable(&proxy.join("codex"), b"proxy");
    executable(&wrappers.join("codex"), b"wrapper");
    executable(&vendor.join("codex"), b"vendor");

    let search_path = std::env::join_paths([&proxy, &wrappers, &vendor]).unwrap();
    let resolved = resolve_continuation("codex", &search_path, std::slice::from_ref(&proxy))
        .expect("resolve the pre-proxy command");

    assert_eq!(resolved.visible_path, wrappers.join("codex"));
    assert_eq!(resolved.search_index, 0);
    assert_eq!(
        std::env::split_paths(&resolved.continuation_path).collect::<Vec<_>>(),
        vec![wrappers, vendor]
    );
    assert_eq!(resolved.identity.length, 7);
}

#[test]
fn continuation_preserves_a_symlinked_wrapper_directory_as_the_visible_layer() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    let real_wrappers = root.path().join("real-wrappers");
    let visible_wrappers = root.path().join("visible-wrappers");
    fs::create_dir(&real_wrappers).unwrap();
    executable(&real_wrappers.join("agent"), b"wrapper");
    symlink(&real_wrappers, &visible_wrappers).unwrap();

    let search_path = std::env::join_paths([&visible_wrappers]).unwrap();
    let resolved = resolve_continuation("agent", &search_path, &[]).unwrap();

    assert_eq!(resolved.visible_path, visible_wrappers.join("agent"));
    assert_eq!(
        std::env::split_paths(&resolved.continuation_path).collect::<Vec<_>>(),
        vec![visible_wrappers]
    );
    assert_eq!(resolved.canonical_path, real_wrappers.join("agent"));
}

#[test]
fn an_underlying_identity_change_is_a_refresh_but_a_new_target_is_a_rebind() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"version-one");
    let path = std::env::join_paths([&bin]).unwrap();
    let first = resolve_continuation("agent", &path, &[]).unwrap();
    let intent = BindingIntent::continuation("agent", "automation").unwrap();
    let active = BindingReceipt::new(intent.clone(), first.clone()).unwrap();

    assert_eq!(
        classify_binding_change(&active, &intent, &first),
        BindingChange::Unchanged
    );

    executable(&bin.join("agent"), b"version-two");
    let refreshed = resolve_continuation("agent", &path, &[]).unwrap();
    assert_eq!(
        classify_binding_change(&active, &intent, &refreshed),
        BindingChange::Refresh
    );

    let rebound_intent =
        BindingIntent::structured("agent", "automation", "/opt/agents/agent", ["--managed"])
            .unwrap();
    assert_eq!(
        classify_binding_change(&active, &rebound_intent, &refreshed),
        BindingChange::Rebind
    );
}

#[test]
fn generations_advance_once_and_retain_one_exact_rollback_generation() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"one");
    let path = std::env::join_paths([&bin]).unwrap();
    let intent = BindingIntent::continuation("agent", "automation").unwrap();
    let first = resolve_continuation("agent", &path, &[]).unwrap();
    let receipt = BindingReceipt::new(intent.clone(), first).unwrap();

    executable(&bin.join("agent"), b"two");
    let second = resolve_continuation("agent", &path, &[]).unwrap();
    let advanced = advance_binding(&receipt, intent.clone(), second.clone()).unwrap();
    assert_eq!(advanced.active.generation, 2);
    assert_eq!(advanced.previous.as_ref().unwrap().generation, 1);

    let unchanged = advance_binding(&advanced, intent, second).unwrap();
    assert_eq!(unchanged, advanced);
    assert_eq!(unchanged.active.generation, 2);
}

#[test]
fn strong_automatic_refresh_requires_independent_authority() {
    let system = resolve_continuation("true", std::ffi::OsStr::new("/usr/bin"), &[]).unwrap();
    assert_eq!(system.identity.authority, BindingAuthority::RootOwned);
    require_automatic_refresh(BindingMode::Strong, &system, false).unwrap();

    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"user-owned");
    let path = std::env::join_paths([&bin]).unwrap();
    let user_owned = resolve_continuation("agent", &path, &[]).unwrap();
    assert_eq!(user_owned.identity.authority, BindingAuthority::UserOwned);
    assert!(require_automatic_refresh(BindingMode::Strong, &user_owned, true).is_err());
    assert!(require_automatic_refresh(BindingMode::UserOnly, &user_owned, false).is_err());
    require_automatic_refresh(BindingMode::UserOnly, &user_owned, true).unwrap();
}

#[test]
fn a_tampered_receipt_lineage_cannot_be_advanced() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"one");
    let path = std::env::join_paths([&bin]).unwrap();
    let intent = BindingIntent::continuation("agent", "automation").unwrap();
    let resolution = resolve_continuation("agent", &path, &[]).unwrap();
    let mut receipt = BindingReceipt::new(intent.clone(), resolution.clone()).unwrap();
    receipt.active.generation = 4;

    assert!(validate_binding_receipt_structure(&receipt).is_err());
    assert!(advance_binding(&receipt, intent, resolution).is_err());
}

#[test]
fn a_tampered_resolution_cursor_or_identity_cannot_be_accepted() {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    executable(&bin.join("agent"), b"one");
    let path = std::env::join_paths([&bin]).unwrap();
    let intent = BindingIntent::continuation("agent", "automation").unwrap();
    let resolution = resolve_continuation("agent", &path, &[]).unwrap();
    let receipt = BindingReceipt::new(intent.clone(), resolution.clone()).unwrap();

    let mut bad_cursor = resolution.clone();
    bad_cursor.search_index = 1;
    assert!(advance_binding(&receipt, intent.clone(), bad_cursor).is_err());

    let mut bad_identity = resolution;
    bad_identity.identity.authority = BindingAuthority::RootOwned;
    assert!(advance_binding(&receipt, intent, bad_identity).is_err());
}

#[test]
fn continuation_rejects_relative_search_entries_and_proxy_only_cycles() {
    let root = tempfile::tempdir().unwrap();
    let proxy = root.path().join("proxy");
    fs::create_dir(&proxy).unwrap();
    executable(&proxy.join("agent"), b"proxy");

    assert!(resolve_continuation("agent", std::ffi::OsStr::new("relative"), &[]).is_err());
    let path = std::env::join_paths([&proxy]).unwrap();
    assert!(resolve_continuation("agent", &path, &[proxy]).is_err());
}
