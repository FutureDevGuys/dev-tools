#![cfg(target_os = "linux")]

use dev_auth::linux_platform::IdentityUserNamespace;

#[test]
fn identity_user_namespace_preserves_every_native_account_uid() {
    IdentityUserNamespace::parse(b"         0          0 4294967295\n").unwrap();
    IdentityUserNamespace::parse_maps(b"0 0 4294967295\n", b"0 0 4294967295\n").unwrap();
    // systemd may separate root from the otherwise identical full mapping.
    IdentityUserNamespace::parse_maps(b"0 0 1\n1 1 4294967294\n", b"0 0 1\n1 1 4294967294\n")
        .unwrap();
    IdentityUserNamespace::parse(b"1001 1001 4294966294\n0 0 1000\n1000 1000 1\n").unwrap();
}

#[test]
fn identity_user_namespace_requires_complete_nonoverlapping_identity_ranges() {
    for invalid in [
        b"0 0 65536\n".as_slice(),
        b"0 524288 65536\n".as_slice(),
        b"0 524288 1000\n".as_slice(),
        b"1000 524288 65536\n".as_slice(),
        b"0 524288 65536\n65536 700000 1\n".as_slice(),
        b"not a map\n".as_slice(),
        b"".as_slice(),
        b"0 0 0\n0 0 4294967295\n".as_slice(),
        b"0 0 1\n2 2 4294967293\n".as_slice(),
        b"0 0 2\n1 1 4294967294\n".as_slice(),
        b"0 0 1\n1 2 4294967294\n".as_slice(),
        b"0 0 4294967295\n4294967295 4294967295 1\n".as_slice(),
    ] {
        assert!(IdentityUserNamespace::parse(invalid).is_err());
    }
}

#[test]
fn identity_user_namespace_rejects_a_partial_group_map() {
    assert!(IdentityUserNamespace::parse_maps(b"0 0 4294967295\n", b"0 0 65536\n",).is_err());
}
