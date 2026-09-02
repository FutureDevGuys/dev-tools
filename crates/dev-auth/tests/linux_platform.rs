#![cfg(target_os = "linux")]

use dev_auth::linux_platform::IdentityUserNamespace;

#[test]
fn identity_user_namespace_preserves_every_native_account_uid() {
    IdentityUserNamespace::parse(b"         0          0 4294967295\n").unwrap();
    IdentityUserNamespace::parse_maps(b"0 0 4294967295\n", b"0 0 4294967295\n").unwrap();
}

#[test]
fn identity_user_namespace_requires_one_exact_full_uid_range() {
    for invalid in [
        b"0 0 65536\n".as_slice(),
        b"0 524288 65536\n".as_slice(),
        b"0 524288 1000\n".as_slice(),
        b"1000 524288 65536\n".as_slice(),
        b"0 524288 65536\n65536 700000 1\n".as_slice(),
        b"not a map\n".as_slice(),
    ] {
        assert!(IdentityUserNamespace::parse(invalid).is_err());
    }
}

#[test]
fn identity_user_namespace_rejects_a_partial_group_map() {
    assert!(IdentityUserNamespace::parse_maps(b"0 0 4294967295\n", b"0 0 65536\n",).is_err());
}
