#!/usr/bin/env bash
# One native approval for fixed, prompt-free probes. No administrator grant,
# PolicyKit action, live installation change, or general passwordless rule.
set -euo pipefail
umask 077
case ${1:-} in
    stage)
        [[ $# == 5 && $EUID != 0 ]]
        product=$(realpath -e -- "$2")
        native_test=$(realpath -e -- "$3")
        sudo_test=$(realpath -e -- "$4")
        stage=$(realpath -e -- "$5")
        [[ "$stage" =~ ^/tmp/dev-auth-preflight-stage\.[A-Za-z0-9]{8}$ ]]
        install -m 0755 -- "$product" "$stage/dev-auth"
        install -m 0755 -- "$native_test" "$stage/linux-native"
        install -m 0755 -- "$sudo_test" "$stage/sudo-native"
        install -m 0755 -- "${BASH_SOURCE[0]}" "$stage/preflight.sh"
        "$product" grant-payload "$stage/dev-auth-sudo.so"
        (cd -- "$stage" && sha256sum dev-auth linux-native sudo-native preflight.sh dev-auth-sudo.so >SHA256SUMS)
        ;;
    root)
        [[ $# == 4 && $EUID == 0 && ${PKEXEC_UID:-} =~ ^[1-9][0-9]*$ ]]
        stage=$2
        expected=$3
        [[ "$stage" =~ ^/tmp/dev-auth-preflight-stage\.[A-Za-z0-9]{8}$ && "$expected" =~ ^[a-f0-9]{64}$ ]]
        owner=$PKEXEC_UID
        group=$(id -g "$owner")
        nonce=$4
        [[ "$nonce" =~ ^[a-f0-9]{32}$ ]]
        fixture="/run/dev-auth-preflight-$nonce"
        coordinator="dev-auth-privilege-accept-$nonce.service"
        boundary="dev-tools-privilege-accept-$nonce.service"
        [[ ! -e "$fixture" && ! -L "$fixture" ]]
        actual=$(sha256sum "$stage/SHA256SUMS")
        [[ ${actual%% *} == "$expected" ]]
        install -d -m 0755 "$fixture"
        for file in dev-auth linux-native sudo-native preflight.sh dev-auth-sudo.so SHA256SUMS; do
            [[ -f "$stage/$file" && ! -L "$stage/$file" ]]
            install -m 0644 "$stage/$file" "$fixture/$file"
        done
        actual=$(sha256sum "$fixture/SHA256SUMS")
        [[ ${actual%% *} == "$expected" ]]
        (cd -- "$fixture" && sha256sum --check --strict SHA256SUMS)
        chmod 0755 "$fixture/dev-auth" "$fixture/linux-native" "$fixture/sudo-native" "$fixture/preflight.sh"
        all_passed=true
        cgroup_passed=false
        coordinator_passed=false
        setid_passed=false
        setid_credentials_passed=false
        native_sudo_passed=false
        cleanup() {
            saved=$?
            trap - EXIT INT TERM
            for owned in "$boundary" "$coordinator"; do
                if loaded=$(systemctl show "$owned" --property=LoadState --value); then
                    if [[ "$loaded" != not-found ]]; then systemctl stop "$owned" || saved=1; fi
                else saved=1; fi
            done
            jq -n --argjson exit_code "$saved" --argjson cgroup "$cgroup_passed" --argjson coordinator "$coordinator_passed" --argjson setid "$setid_passed" --argjson credentials "$setid_credentials_passed" --argjson sudo "$native_sudo_passed" '{schema:"dev-auth-single-approval-preflight-v1",exit_code:$exit_code,cgroup:$cgroup,coordinator:$coordinator,setid:$setid,native_setid_credentials:$credentials,native_sudo_passthrough:$sudo,administrator_grants_created:false,full_privilege_acceptance:false}' >"$fixture/result.json"
            chmod 0644 "$fixture/result.json"
            printf 'One-approval preflight finished: %s/result.json\n' "$fixture"
            exit "$saved"
        }
        trap cleanup EXIT
        trap 'exit 130' INT TERM
        if systemd-run --unit="$boundary" --property=KillMode=control-group --property=SendSIGKILL=yes --property=ExitType=main --property=TimeoutStopSec=5s --property=RuntimeMaxSec=45s --wait "$fixture/linux-native" --ignored --exact cgroup_enforcement --nocapture --test-threads=1; then cgroup_passed=true; else all_passed=false; fi
        if /usr/bin/setpriv --ruid="$owner" --euid=0 --regid=0 --clear-groups "$fixture/dev-auth" grant-payload "$fixture/forbidden.so"; then all_passed=false; else [[ ! -e "$fixture/forbidden.so" ]] && setid_passed=true; fi
        if /usr/bin/timeout --kill-after=5s 15s /usr/bin/setpriv --ruid="$owner" --euid=0 --rgid="$group" --egid=0 --clear-groups "$fixture/sudo-native" --ignored --exact native::tests::native_setid_messages_match_effective_peer_identity --test-threads=1 >"$fixture/native-setid.log" 2>&1; then setid_credentials_passed=true; else all_passed=false; fi
        chmod 0644 "$fixture/native-setid.log"
        install -d -m 0700 -o "$owner" -g "$group" "$fixture/user"
        "$fixture/dev-auth" setup template administrator-grant-policy >"$fixture/policy.json"
        if systemd-run --unit="$coordinator" --property=KillMode=control-group --property=SendSIGKILL=yes --property=ExitType=main --property=TimeoutStopSec=5s --property=RuntimeMaxSec=120s --property=Delegate=no "$fixture/dev-auth" grant-daemon --policy "$fixture/policy.json" --runtime "$fixture"; then
            for ((attempt=0; attempt<100; attempt++)); do [[ -S "$fixture/control.sock" && -S "$fixture/sudo.sock" ]] && break; sleep 0.1; done
            if [[ -S "$fixture/control.sock" && -S "$fixture/sudo.sock" ]]; then
                if /usr/bin/setpriv --reuid="$owner" --regid="$group" --init-groups --reset-env /usr/bin/env DEV_AUTH_GRANT_SOCKET="$fixture/control.sock" "$fixture/dev-auth" privilege grant status --format json >"$fixture/status.json" && jq -e '.error_kind == null and .changed == false' "$fixture/status.json"; then coordinator_passed=true; else all_passed=false; fi
                printf 'Plugin sudoers_policy sudoers.so\nPlugin sudoers_io sudoers.so\nPlugin dev_auth_sudo_audit %s/dev-auth-sudo.so runtime=%s frontend=%s/dev-auth\nPlugin dev_auth_sudo_approval %s/dev-auth-sudo.so\n' "$fixture" "$fixture" "$fixture" "$fixture" >"$fixture/sudo.conf"
                printf 'Defaults timestampdir="%s/timestamps"\nDefaults group_plugin="%s/dev-auth-sudo.so"\nDefaults always_query_group_plugin\n#%s ALL=(root) NOPASSWD: /usr/bin/id -u\n' "$fixture" "$fixture" "$owner" >"$fixture/sudoers"
                chmod 0440 "$fixture/sudoers"
                install -d -m 0700 "$fixture/timestamps"
                # Only fixed, noninteractive probes are captured, after the
                # outer native authorization. Never capture an approval prompt.
                if { /usr/bin/visudo -c -f "$fixture/sudoers" && /usr/bin/timeout --kill-after=5s 30s /usr/bin/unshare --mount --propagation private /usr/bin/bash "$fixture/preflight.sh" namespace "$fixture" "$owner" "$group"; } >"$fixture/native-sudo.log" 2>&1; then native_sudo_passed=true; else all_passed=false; fi
                chmod 0644 "$fixture/native-sudo.log"
            else all_passed=false; fi
        else all_passed=false; fi
        [[ "$all_passed" == true && "$setid_passed" == true ]]
        ;;
    namespace)
        [[ $# == 4 && $EUID == 0 ]]
        fixture=$2
        owner=$3
        group=$4
        [[ "$fixture" =~ ^/run/dev-auth-preflight-[a-f0-9]{32}$ && "$owner" =~ ^[1-9][0-9]*$ && "$group" =~ ^[0-9]+$ ]]
        [[ $(readlink /proc/self/ns/mnt) != "$(readlink /proc/1/ns/mnt)" ]]
        mount --bind "$fixture/sudo.conf" /etc/sudo.conf
        mount --bind "$fixture/sudoers" /etc/sudoers
        exec /usr/bin/setpriv --reuid="$owner" --regid="$group" --init-groups --reset-env /usr/bin/bash "$fixture/preflight.sh" user "$fixture"
        ;;
    user)
        [[ $# == 2 && $EUID != 0 ]]
        fixture=$2
        [[ "$fixture" =~ ^/run/dev-auth-preflight-[a-f0-9]{32}$ ]]
        cd "$fixture/user"
        export DEV_AUTH_GRANT_SOCKET="$fixture/control.sock"
        printf 'probe=unauthorized-grant\n'
        # This is an empty-policy denial probe, never an authentication request.
        # Do not inherit the outer approval terminal through timeout's separate
        # process group: no request-owned tty agent may start in this batch.
        if "$fixture/dev-auth" privilege grant request --scope user --authority administrator --duration 12h --format json </dev/null >request-denied.json; then exit 1; fi
        jq -e '.error_kind == "authority_denied" and .changed == false' request-denied.json
        printf 'probe=native-nopasswd\n'
        if sudo_output=$(/usr/bin/sudo -n -- /usr/bin/id -u); then sudo_status=0; else sudo_status=$?; fi
        printf 'native-nopasswd-status=%d output=%q\n' "$sudo_status" "$sudo_output"
        [[ "$sudo_status" == 0 && "$sudo_output" == 0 ]]
        printf 'probe=native-denied\n'
        if /usr/bin/sudo -n -- /usr/bin/false; then exit 1; fi
        printf 'probe=native-version\n'
        /usr/bin/sudo --version >/dev/null
        printf 'probe=native-passthrough-complete\n'
        ;;
    *) exit 2 ;;
esac
