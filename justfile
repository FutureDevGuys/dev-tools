# Dev Auth delivery verification. No hosted CI or release publication is configured.
# Uses Bash (including Git Bash on Windows) and the checked-out Cargo lockfile.
# Examples: just ci; just ci-target x86_64-pc-windows-gnu; just test

set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

export CARGO_PROFILE_TEST_DEBUG := "0"
export CARGO_INCREMENTAL := "0"

# List the local Dev Auth build and verification commands
default:
    @just --list

# Check formatting, strict lint, and noninteractive Dev Auth, execution, authorization, and installation tests
ci: fmt-check lint test build

# Verify formatting without rewriting Rust source
fmt-check:
    cargo fmt -p dev-auth -p dev-auth-sudo -p dev-tools-command -p dev-tools-privilege-session -p dev-tools-privilege -p dev-tools-installation -- --check

# Check Dev Auth and execution, authorization, and installation foundations with warnings treated as errors
lint:
    cargo clippy -p dev-auth -p dev-auth-sudo -p dev-tools-command -p dev-tools-privilege-session -p dev-tools-privilege -p dev-tools-installation --all-targets --locked -j 2 -- -D warnings

# Keep custody hashing representative without relaxing subprocess deadlines.
# Run noninteractive Dev Auth and changed foundation tests with bounded parallelism
test:
    cargo test -p dev-auth -p dev-auth-sudo -p dev-tools-command -p dev-tools-privilege-session -p dev-tools-privilege -p dev-tools-installation --locked -j 2 --config 'profile.test.package.sha2.opt-level=3' -- --test-threads=2

# Compile Dev Auth and embed its version/target/source-matched Linux sudo helper
build:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "$(uname -s)" == Linux ]]; then
        helper=$(cargo build -p dev-auth-sudo --locked -j 2 --message-format=json | jq -sr '[.[] | select(.reason == "compiler-artifact" and .target.name == "dev_auth_sudo") | .filenames[] | select(endswith(".so"))] | unique | if length == 1 then .[0] else error("expected one native sudo helper") end')
        export DEV_AUTH_SUDO_ARTIFACT="$helper"
    fi
    cargo build -p dev-auth --locked -j 2

# Compile Dev Auth code and test targets; missing target SDKs are failures, not skips
ci-target target:
    cargo check -p dev-auth -p dev-auth-sudo -p dev-tools-command -p dev-tools-privilege-session -p dev-tools-privilege -p dev-tools-installation --all-targets --locked -j 2 --target "$1"

# Compare the Linux sudo bridge layout against the installed upstream native header
accept-sudo-abi:
    cargo test -p dev-auth-sudo --locked -j 2 native_sudo_header_matches_plugin_layout -- --ignored --test-threads=1

# Run isolated Linux privilege/sudo/Ansible acceptance on a visible native terminal; prompts for OS approval
accept-native binary="target/debug/dev-auth":
    /usr/bin/bash tests/native_privilege/accept-linux.sh run "$1"

# Run receipt-owned Linux setup/recovery/restore in a disposable systemd image on a visible terminal
accept-installed binary library-test image scenario="privilege-setup":
    /usr/bin/bash tests/native_privilege/installed-linux.sh run "$1" "$2" "$3" "$4"
