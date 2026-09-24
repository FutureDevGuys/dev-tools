#!/usr/bin/env bash
# Interactive development qualification, not signed release acceptance.
# The rootful container has its own runtime storage, no host bind mounts, private
# namespaces and no network. Only native passwd/login/PolicyKit handle input.
set -euo pipefail
umask 077
settle_fixture_exit_code() {
    local status=$1 stage=$2
    if [[ $status == 0 && $stage != complete && $stage != diagnostic_complete ]]; then
        return 1
    fi
    return "$status"
}
case ${1:-} in
    self-test)
        settle_fixture_exit_code 0 complete
        settle_fixture_exit_code 0 diagnostic_complete
        for stage in container_setup installed_preparation native_password native_login_and_launch; do
            if settle_fixture_exit_code 0 "$stage"; then exit 1; fi
        done
        if settle_fixture_exit_code 137 container_setup; then exit 1; else [[ $? == 137 ]]; fi
        ;;
    run)
        [[ ( $# == 4 || $# == 5 ) && $EUID != 0 && -t 0 && -t 1 ]]
        product=$(realpath -e -- "$2")
        library_test=$(realpath -e -- "$3")
        image=$4
        scenario=${5:-launch-grant}
        [[ "$scenario" == launch-grant || "$scenario" == tty-probe || "$scenario" == password-diagnostic || "$scenario" == login-session-probe || "$scenario" == privilege-setup || "$scenario" == privilege-setup-interrupted || "$scenario" == privilege-setup-reconfigured || "$scenario" == privilege-combined || "$scenario" == binding-strong ]]
        [[ "$image" =~ ^[a-f0-9]{64}$ ]]
        stage=$(mktemp -d /tmp/dev-auth-installed-stage.XXXXXXXX)
        install -m 0755 -- "$product" "$stage/dev-auth"
        install -m 0755 -- "$library_test" "$stage/library-test"
        /usr/bin/strip --strip-debug "$stage/dev-auth" "$stage/library-test"
        install -m 0755 -- "${BASH_SOURCE[0]}" "$stage/installed-linux.sh"
        install -m 0755 -- "$(dirname -- "${BASH_SOURCE[0]}")/installed-user.sh" "$stage/installed-user.sh"
        /usr/bin/podman image save --format oci-archive --output "$stage/image.tar" "$image"
        printf '%s\n' "$image" >"$stage/image-id"
        printf '%s\n' "$scenario" >"$stage/scenario"
        (cd "$stage" && sha256sum dev-auth library-test installed-linux.sh installed-user.sh image.tar image-id scenario >SHA256SUMS)
        manifest=$(sha256sum "$stage/SHA256SUMS")
        printf 'Installed launch fixture stage: %s\n' "$stage"
        exec /usr/bin/pkexec /usr/bin/bash --noprofile --norc "$stage/installed-linux.sh" root "$stage" "${manifest%% *}"
        ;;
    root)
        [[ $# == 3 && $EUID == 0 && ${PKEXEC_UID:-} =~ ^[1-9][0-9]*$ && -t 0 && -t 1 ]]
        stage=$2
        expected=$3
        [[ "$stage" =~ ^/tmp/dev-auth-installed-stage\.[A-Za-z0-9]{8}$ && "$expected" =~ ^[a-f0-9]{64}$ ]]
        nonce=$(tr -d '-' </proc/sys/kernel/random/uuid)
        [[ "$nonce" =~ ^[a-f0-9]{32}$ ]]
        fixture="/run/dev-auth-installed-$nonce"
        [[ ! -e "$fixture" && ! -L "$fixture" ]]
        actual=$(sha256sum "$stage/SHA256SUMS")
        [[ ${actual%% *} == "$expected" ]]
        install -d -m 0755 "$fixture"
        for file in dev-auth library-test installed-linux.sh installed-user.sh image.tar image-id scenario SHA256SUMS; do
            [[ -f "$stage/$file" && ! -L "$stage/$file" ]]
            install -m 0644 -- "$stage/$file" "$fixture/$file"
        done
        actual=$(sha256sum "$fixture/SHA256SUMS")
        [[ ${actual%% *} == "$expected" ]]
        (cd "$fixture" && sha256sum --check --strict SHA256SUMS)
        chmod 0755 "$fixture/dev-auth" "$fixture/library-test" "$fixture/installed-user.sh"
        image=$(<"$fixture/image-id")
        scenario=$(<"$fixture/scenario")
        [[ "$scenario" == launch-grant || "$scenario" == tty-probe || "$scenario" == password-diagnostic || "$scenario" == login-session-probe || "$scenario" == privilege-setup || "$scenario" == privilege-setup-interrupted || "$scenario" == privilege-setup-reconfigured || "$scenario" == privilege-combined || "$scenario" == binding-strong ]]
        [[ "$image" =~ ^[a-f0-9]{64}$ ]]
        # systemd-creds deliberately rejects automatic host-key encryption on
        # tmpfs when TPM2 is unavailable in a container. Preserve that policy;
        # only the private disposable image storage lives on persistent media.
        storage_base="/var/tmp/dev-auth-installed-store-$nonce"
        [[ ! -e "$storage_base" && ! -L "$storage_base" ]]
        mkdir -m 0700 -- "$storage_base"
        install -d -m 0700 "$storage_base/storage" "$fixture/runtime"
        cgroup_manager=cgroupfs
        runtime=(/usr/bin/podman --root "$storage_base/storage" --runroot "$fixture/runtime" --storage-driver vfs --cgroup-manager "$cgroup_manager")
        container=''
        removed=false
        prepared=false
        privilege_setup=false
        progress_watcher=''
        phase=container_setup
        setup_log="$fixture/root-setup.log"
        : >"$setup_log"
        chmod 0644 "$setup_log"
        # Only fixed, prompt-free container preparation calls use this helper.
        # Never send passwd, login or workload invocation through it.
        logged() {
            "$@" >>"$setup_log" 2>&1
        }
        cleanup() {
            code=$?
            trap - EXIT INT TERM
            settle_fixture_exit_code "$code" "$phase" || code=$?
            if [[ -n "$progress_watcher" ]]; then
                kill "$progress_watcher" 2>/dev/null || true
                wait "$progress_watcher" 2>/dev/null || true
            fi
            if [[ -n "$container" ]]; then
                [[ "$container" =~ ^[a-f0-9]{64}$ ]] || exit 1
                if [[ "$prepared" == false ]]; then
                    # Before preparation no password/login step has run; only
                    # fixed image boot diagnostics can exist in these streams.
                    "${runtime[@]}" logs "$container" >"$fixture/container-start.log" 2>&1 || true
                    "${runtime[@]}" inspect "$container" --format '{{json .State}}' >"$fixture/container-state.json" 2>&1 || true
                    "${runtime[@]}" cp "$container:/fixture/setup-recovery.trace" "$fixture/setup-recovery.trace" >/dev/null 2>&1 || true
                    [[ ! -f "$fixture/setup-recovery.trace" ]] || chmod 0644 "$fixture/setup-recovery.trace"
                    chmod 0644 "$fixture/container-start.log" "$fixture/container-state.json"
                fi
                # These files contain only fixture progress and value-free results.
                for file in installed-progress.json installed-result.json login-session-initial.json login-session-after-workload.json loginctl-error.txt workload-launch-result.json user-launch-result.json user-leave.json failed-start-result.json grants.json; do
                    "${runtime[@]}" cp "$container:/home/dev-auth-recover-alpha/$file" "$fixture/$file" >/dev/null 2>&1 || true
                    [[ ! -f "$fixture/$file" ]] || chmod 0644 "$fixture/$file"
                done
                if [[ "$scenario" == login-session-probe && "$prepared" == true ]]; then
                    # No password or grant prompt runs in this diagnostic. Keep
                    # only native PAM/logind messages, never terminal output.
                    "${runtime[@]}" exec "$container" /usr/bin/journalctl -b --no-pager -o cat --grep 'pam_systemd|systemd-logind' >"$fixture/login-journal.txt" 2>&1 || true
                    chmod 0644 "$fixture/login-journal.txt"
                    "${runtime[@]}" exec "$container" /usr/bin/journalctl -b --no-pager -o cat SYSLOG_IDENTIFIER=login >"$fixture/pam-login-journal.txt" 2>&1 || true
                    chmod 0644 "$fixture/pam-login-journal.txt"
                fi
                if "${runtime[@]}" rm --force --time 5 "$container"; then removed=true; else code=1; fi
            fi
            jq -n --argjson code "$code" --argjson prepared "$prepared" --argjson removed "$removed" --argjson privilege_setup "$privilege_setup" --arg scenario "$scenario" --arg storage "$storage_base" --arg phase "$phase" --arg cgroup_manager "$cgroup_manager" '{schema:"dev-auth-installed-launch-run-v1",exit_code:$code,phase:$phase,scenario:$scenario,cgroup_manager:$cgroup_manager,prepared:$prepared,container_removed:$removed,image_storage:$storage,signed_release:false,privilege_setup_receipted:$privilege_setup}' >"$fixture/result.json"
            chmod 0644 "$fixture/result.json"
            printf 'Installed launch result: %s/result.json\n' "$fixture"
            exit "$code"
        }
        trap cleanup EXIT
        trap 'exit 130' INT TERM
        logged "${runtime[@]}" image load --input "$fixture/image.tar"
        [[ $("${runtime[@]}" image inspect "$image" --format '{{.Id}}') == "$image" ]]
        # Native user/mount namespaces and cross-UID retained process evidence
        # need these two capabilities; do not grant privileged host mode.
        container=$("${runtime[@]}" create --name "dev-auth-installed-$nonce" --pull never --network none --pid private --ipc private --uts private --cgroupns private --systemd always --cap-add SYS_ADMIN --cap-add SYS_PTRACE --security-opt seccomp=unconfined --security-opt label=disable --memory 2g --pids-limit 2048 --timeout 900 --stop-timeout 5 --entrypoint /usr/lib/systemd/systemd "$image" --system --unit=multi-user.target 2>>"$setup_log")
        [[ "$container" =~ ^[a-f0-9]{64}$ ]]
        "${runtime[@]}" inspect "$container" | jq -e 'length == 1 and .[0].HostConfig.Privileged == false and .[0].HostConfig.NetworkMode == "none" and (.[0].Mounts | all(.Type != "bind"))'
        logged "${runtime[@]}" start "$container"
        logged "${runtime[@]}" exec "$container" /usr/bin/mkdir -p /candidate /fixture
        logged "${runtime[@]}" cp "$fixture/dev-auth" "$container:/candidate/dev-auth"
        logged "${runtime[@]}" cp "$fixture/library-test" "$container:/fixture/library-test"
        logged "${runtime[@]}" cp "$fixture/installed-user.sh" "$container:/fixture/installed-user.sh"
        # ADR 0057 documents this Fedora fixture adjustment. Preserve the exact
        # vendor file inside the disposable root; production's rejection of
        # unretained service drop-ins is not relaxed or qualified by this test.
        # These variables intentionally expand only inside the container.
        # shellcheck disable=SC2016
        logged "${runtime[@]}" exec "$container" /usr/bin/bash -c '
            vendor=/usr/lib/systemd/system/service.d/10-timeout-abort.conf
            retained=/fixture/vendor-10-timeout-abort.conf
            if [[ -e "$vendor" || -L "$vendor" ]]; then
                [[ -f "$vendor" && ! -L "$vendor" && ! -e "$retained" && ! -L "$retained" ]] || exit 1
                /usr/bin/mv -- "$vendor" "$retained"
                /usr/bin/systemctl daemon-reload
            fi'
        for ((attempt=0; attempt<100; attempt++)); do
            if "${runtime[@]}" exec "$container" /usr/bin/systemctl is-active dbus.service >/dev/null 2>&1; then break; fi
            sleep 0.1
        done
        if [[ "$scenario" == launch-grant || "$scenario" == login-session-probe ]] && ! logged "${runtime[@]}" exec "$container" /usr/bin/jq --version; then
            printf '%s\n' 'Fixture image lacks native jq required by installed-user.sh' >&2
            exit 1
        fi
        if [[ "$scenario" == launch-grant || "$scenario" == login-session-probe ]] && ! logged "${runtime[@]}" exec "$container" /usr/bin/test -f /usr/lib64/security/pam_systemd.so; then
            printf '%s\n' 'Fixture image lacks Fedora systemd-pam required for logind session registration' >&2
            exit 1
        fi
        if [[ "$scenario" == tty-probe ]]; then
            # This diagnostic runs before accounts or authentication exist. It
            # reads no credential and checks the exact nested interactive PTY
            # transport later used by native passwd and login.
            phase=tty_probe
            "${runtime[@]}" exec --interactive --tty "$container" /usr/bin/bash -c '
                [[ -t 0 && -t 1 ]] || exit 41
                : </dev/tty >/dev/tty || exit 43
                /usr/bin/timeout 5 /usr/bin/cat >/dev/null
                [[ $? == 124 ]] || exit 42'
            /usr/bin/jq -n '{schema:"dev-auth-native-tty-probe-v1",tty_open:true,controlling_tty:true,no_input_timeout:true}' >"$fixture/tty-probe.json"
            chmod 0644 "$fixture/tty-probe.json"
            phase=complete
            exit 0
        fi
        # This opted-in preparer performs only fixed noninteractive synthetic
        # setup/recovery checks. Interactive launches below are never captured.
        phase=installed_preparation
        native_test=setup_v3::recovery_native::native_disposable_prepare_installed_launch_with_grant
        if [[ "$scenario" == privilege-setup ]]; then
            native_test=setup_v3::privilege::native_acceptance::native_disposable_privilege_only_recovery_and_restore
        elif [[ "$scenario" == privilege-setup-interrupted ]]; then
            native_test=setup_v3::privilege::native_acceptance::native_disposable_privilege_only_resumes_partial_withdrawal
        elif [[ "$scenario" == privilege-setup-reconfigured ]]; then
            native_test=setup_v3::privilege::native_acceptance::native_disposable_privilege_only_reconfiguration_restores_prior_inactive
        elif [[ "$scenario" == privilege-combined ]]; then
            native_test=setup_v3::recovery_native::native_disposable_combined_credential_privilege_upgrade
        elif [[ "$scenario" == binding-strong ]]; then
            native_test=setup_v3::recovery_native::native_disposable_strong_mutable_binding
        fi
        if ! "${runtime[@]}" exec --env DEV_AUTH_NATIVE_SYSTEMD_FIXTURE=disposable --env DEV_AUTH_NATIVE_TRACE_SETUP=1 "$container" /fixture/library-test --ignored --exact "$native_test" --nocapture --test-threads=1 >"$fixture/preparation.log" 2>&1; then
            chmod 0644 "$fixture/preparation.log"
            printf 'Fixture preparation failed: %s/preparation.log\n' "$fixture" >&2
            exit 1
        fi
        chmod 0644 "$fixture/preparation.log"
        if [[ "$scenario" == privilege-combined ]]; then
            "${runtime[@]}" cp "$container:/fixture/privilege-combined-result.json" "$fixture/privilege-combined-result.json"
            chmod 0644 "$fixture/privilege-combined-result.json"
            jq -e '.passed == true and .credential_preserved == true and .privilege_receipted == true and .signed_release == false' "$fixture/privilege-combined-result.json"
            privilege_setup=true
            prepared=true
            phase=complete
            exit 0
        fi
        if [[ "$scenario" == binding-strong ]]; then
            "${runtime[@]}" cp "$container:/fixture/binding-strong-result.json" "$fixture/binding-strong-result.json"
            chmod 0644 "$fixture/binding-strong-result.json"
            jq -e '.passed == true and .mutable_edit == true and .restored == true' "$fixture/binding-strong-result.json"
            prepared=true
            phase=complete
            exit 0
        fi
        if [[ "$scenario" != launch-grant && "$scenario" != password-diagnostic && "$scenario" != login-session-probe ]]; then
            "${runtime[@]}" cp "$container:/fixture/privilege-setup-result.json" "$fixture/privilege-setup-result.json"
            chmod 0644 "$fixture/privilege-setup-result.json"
            jq -e '.passed == true and .credentials_required == false' "$fixture/privilege-setup-result.json"
            if [[ "$scenario" == privilege-setup-interrupted ]]; then
                jq -e '.partial_withdrawal == true' "$fixture/privilege-setup-result.json"
            elif [[ "$scenario" == privilege-setup-reconfigured ]]; then
                jq -e '.reconfiguration == true' "$fixture/privilege-setup-result.json"
            fi
            privilege_setup=true
            prepared=true
            phase=complete
            exit 0
        fi
        "${runtime[@]}" cp "$container:/fixture/prepared.json" "$fixture/prepared.json"
        chmod 0644 "$fixture/prepared.json"
        jq -e '.prepared == true' "$fixture/prepared.json"
        prepared=true
        if [[ "$scenario" == login-session-probe ]]; then
            phase=native_login_session_probe
            printf '{"phase":"%s"}\n' "$phase" >"$fixture/progress.json"
            chmod 0644 "$fixture/progress.json"
            logged "${runtime[@]}" exec "$container" /usr/bin/touch /fixture/login-session-probe-only
            # The disposable image's default interactive class may require a
            # user manager unavailable in this isolated container. Native
            # user-light still registers an interactive tty session and ends
            # with logout; debug logging is confined to this no-password run.
            logged "${runtime[@]}" exec "$container" /usr/bin/sed -i 's/pam_systemd\.so$/pam_systemd.so debug/' /etc/pam.d/system-auth
            printf '\nDiagnosing native logind registration through login(1) without a password. This does not qualify the installed-grant gate.\n'
            # Do not interpose strace on login's foreground PTY: ptrace can
            # stop its terminal ownership transition with SIGTTOU.
            "${runtime[@]}" exec --env XDG_SESSION_CLASS=user-light --env XDG_SESSION_TYPE=tty --interactive --tty "$container" /usr/bin/login -f dev-auth-recover-alpha
            "${runtime[@]}" cp "$container:/home/dev-auth-recover-alpha/login-session-initial.json" "$fixture/login-session-initial.json"
            chmod 0644 "$fixture/login-session-initial.json"
            jq -e '.interactive == true' "$fixture/login-session-initial.json"
            phase=diagnostic_complete
            exit 0
        fi
        if [[ "$scenario" == password-diagnostic ]]; then
            phase=native_password_diagnostic
            printf '{"phase":"%s"}\n' "$phase" >"$fixture/progress.json"
            chmod 0644 "$fixture/progress.json"
            printf '\nNative passwd diagnostic: only process/file/wait syscalls are traced; no read or write payload is recorded.\n'
            passwd_status=0
            "${runtime[@]}" exec --interactive --tty "$container" /usr/bin/timeout --foreground --signal=TERM --kill-after=5s 120s \
                /usr/bin/strace -qq -f -ttt -T -o /fixture/passwd-syscalls.trace \
                -e 'trace=%process,%file,flock,poll,ppoll,fsync,fdatasync' \
                /usr/bin/passwd dev-auth-recover-alpha || passwd_status=$?
            "${runtime[@]}" cp "$container:/fixture/passwd-syscalls.trace" "$fixture/passwd-syscalls.trace"
            chmod 0644 "$fixture/passwd-syscalls.trace"
            "${runtime[@]}" exec "$container" /usr/bin/passwd -S dev-auth-recover-alpha >"$fixture/passwd-status.txt"
            chmod 0644 "$fixture/passwd-status.txt"
            /usr/bin/jq -n --argjson status "$passwd_status" \
                '{schema:"dev-auth-native-password-diagnostic-v1",passwd_exit_code:$status,signed_release:false}' >"$fixture/password-diagnostic.json"
            chmod 0644 "$fixture/password-diagnostic.json"
            phase=diagnostic_complete
            exit 0
        fi
        phase=native_password
        printf '{"phase":"%s"}\n' "$phase" >"$fixture/progress.json"
        chmod 0644 "$fixture/progress.json"
        printf '\nSet a temporary password for the disposable dev-auth-recover-alpha account below. Native passwd handles it directly; it never leaves this container and its writable filesystem is removed at the end.\n'
        "${runtime[@]}" exec --interactive --tty "$container" /usr/bin/passwd dev-auth-recover-alpha
        phase=native_login_and_launch
        printf '{"phase":"%s"}\n' "$phase" >"$fixture/progress.json"
        printf '\nStarting the isolated native login and approval checks.\n'
        watch_progress() {
            while :; do
                if "${runtime[@]}" cp "$container:/home/dev-auth-recover-alpha/installed-progress.json" "$fixture/.installed-progress.next" >/dev/null 2>&1; then
                    chmod 0644 "$fixture/.installed-progress.next"
                    mv -f -- "$fixture/.installed-progress.next" "$fixture/installed-progress.json"
                fi
                sleep 1
            done
        }
        watch_progress &
        progress_watcher=$!
        "${runtime[@]}" exec --env XDG_SESSION_CLASS=user-light --env XDG_SESSION_TYPE=tty --interactive --tty "$container" /usr/bin/login dev-auth-recover-alpha
        kill "$progress_watcher" 2>/dev/null || true
        wait "$progress_watcher" 2>/dev/null || true
        progress_watcher=''
        "${runtime[@]}" cp "$container:/home/dev-auth-recover-alpha/installed-result.json" "$fixture/installed-result.json"
        chmod 0644 "$fixture/installed-result.json"
        jq -e '.exit_code == 0 and .step == "complete"' "$fixture/installed-result.json"
        phase=complete
        ;;
    *) printf '%s\n' 'usage: installed-linux.sh run PRODUCT LIBRARY_TEST IMAGE_ID [launch-grant|tty-probe|password-diagnostic|login-session-probe|privilege-setup|privilege-setup-interrupted|privilege-setup-reconfigured|privilege-combined|binding-strong]' >&2; exit 2 ;;
esac
