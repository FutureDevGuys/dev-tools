#!/usr/bin/env bash
# Public, explicitly invoked native acceptance. Only the dedicated /run fixture
# and one absent PolicyKit action are published; installed Dev Auth is untouched.
set -euo pipefail
umask 077

case ${1:-} in
    run)
        [[ ( $# == 2 || $# == 3 ) && $EUID != 0 && -t 0 && -t 1 ]]
        product=$(realpath -e -- "$2")
        selected_scope=${3:-both}
        [[ "$selected_scope" == both || "$selected_scope" == user || "$selected_scope" == workload ]]
        repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
        command -v /usr/bin/ansible-playbook >/dev/null
        # mktemp owns this exact directory; no broad cleanup target is inferred.
        stage=$(mktemp -d /tmp/dev-auth-native-stage.XXXXXXXX)
        install -m 0755 -- "$product" "$stage/dev-auth"
        # This is a development acceptance copy, not a signed release artifact.
        /usr/bin/strip --strip-debug "$stage/dev-auth"
        install -m 0755 -- "${BASH_SOURCE[0]}" "$stage/accept-linux.sh"
        install -m 0755 -- "$repository/tests/native_privilege/user.sh" "$stage/user.sh"
        install -m 0644 -- "$repository/tests/native_privilege/become.yml" "$stage/become.yml"
        install -m 0644 -- "$repository/tests/native_privilege/ansible.cfg" "$stage/ansible.cfg"
        install -m 0644 -- "$repository/crates/dev-auth/assets/privilege/org.futuredevguys.dev-auth.privilege.policy" "$stage/approval.policy"
        "$product" privilege-payload "$stage/dev-auth-sudo.so"
        (cd -- "$stage" && sha256sum dev-auth accept-linux.sh user.sh become.yml ansible.cfg approval.policy dev-auth-sudo.so >SHA256SUMS)
        manifest=$(sha256sum "$stage/SHA256SUMS")
        manifest=${manifest%% *}
        printf 'Native acceptance source: %s\n' "$stage"
        exec /usr/bin/pkexec /usr/bin/bash --noprofile --norc "$stage/accept-linux.sh" root "$stage" "$manifest" "$selected_scope"
        ;;
    root)
        [[ $# == 4 && $EUID == 0 && ${PKEXEC_UID:-} =~ ^[1-9][0-9]*$ ]]
        stage=$2
        expected=$3
        selected_scope=$4
        [[ "$selected_scope" == both || "$selected_scope" == user || "$selected_scope" == workload ]]
        [[ "$stage" =~ ^/tmp/dev-auth-native-stage\.[A-Za-z0-9]{8}$ && "$expected" =~ ^[a-f0-9]{64}$ ]]
        owner=$PKEXEC_UID
        group=$(id -g "$owner")
        nonce=$(tr -d '-' </proc/sys/kernel/random/uuid)
        [[ "$nonce" =~ ^[a-f0-9]{32}$ ]]
        fixture="/run/dev-auth-privilege-accept-$nonce"
        unit="dev-auth-privilege-accept-$nonce.service"
        workload="dev-auth-workload-$nonce.service"
        action=/usr/share/polkit-1/actions/org.futuredevguys.dev-auth.privilege.policy
        [[ ! -e "$fixture" && ! -L "$fixture" && ! -e "$action" && ! -L "$action" ]]
        actual=$(sha256sum "$stage/SHA256SUMS")
        [[ ${actual%% *} == "$expected" ]]
        install -d -m 0755 -- "$fixture"
        for file in dev-auth accept-linux.sh user.sh become.yml ansible.cfg approval.policy dev-auth-sudo.so SHA256SUMS; do
            [[ -f "$stage/$file" && ! -L "$stage/$file" ]]
            install -m 0644 -- "$stage/$file" "$fixture/$file"
        done
        actual=$(sha256sum "$fixture/SHA256SUMS")
        [[ ${actual%% *} == "$expected" ]]
        (cd -- "$fixture" && sha256sum --check --strict SHA256SUMS)
        chmod 0755 "$fixture/dev-auth" "$fixture/accept-linux.sh" "$fixture/user.sh"
        if /usr/bin/setpriv --ruid="$owner" --euid=0 --regid=0 --clear-groups "$fixture/dev-auth" privilege-payload "$fixture/setuid-must-not-write.so"; then
            printf '%s\n' 'setuid invocation entered an ordinary payload writer' >&2
            exit 1
        fi
        [[ ! -e "$fixture/setuid-must-not-write.so" ]]
        install -d -m 0700 -- "$fixture/timestamps"
        install -d -m 0700 -o "$owner" -g "$group" -- "$fixture/user"
        jq -n --argjson uid "$owner" --arg scope "$selected_scope" --arg cwd "$fixture/user" '{schema:"dev-auth-privilege-policy-v1",sudo_program:"/usr/bin/sudo",subjects:[{account:{kind:"unix",uid:$uid},scopes:(if $scope == "both" then ["user","workload"] else [$scope] end),authorities:[{kind:"administrator"}],maximum_duration_seconds:86400,allow_delegation:true}],plans:{},operations:{"fixture-pipeline":{nodes:[{program:"/usr/bin/printf",arguments:["graph\\000bytes"],working_directory:$cwd,environment:[]},{program:"/usr/bin/cat",arguments:[],working_directory:$cwd,environment:[]}],pipes:[{from:0,to:1}],exit_policy:"pipefail"}}}' >"$fixture/policy.json"
        printf 'Plugin sudoers_policy sudoers.so\nPlugin sudoers_io sudoers.so\nPlugin dev_auth_sudo_audit %s/dev-auth-sudo.so runtime=%s frontend=%s/dev-auth\nPlugin dev_auth_sudo_approval %s/dev-auth-sudo.so\n' "$fixture" "$fixture" "$fixture" "$fixture" >"$fixture/sudo.conf"
        printf 'Defaults timestampdir="%s/timestamps"\nDefaults timestamp_timeout=15\nDefaults group_plugin="%s/dev-auth-sudo.so"\nDefaults always_query_group_plugin\nDefaults:%%:dev-auth-active !authenticate\n%%:dev-auth-active ALL=(ALL:ALL) NOPASSWD: ALL\n#%s ALL=(ALL:ALL) ALL\n' "$fixture" "$fixture" "$owner" >"$fixture/sudoers"
        chmod 0440 "$fixture/sudoers"
        /usr/bin/visudo -c -f "$fixture/sudoers"
        published=false
        published_identity=''
        cleanup() {
            saved_status=$?
            trap - EXIT INT TERM
            for owned_unit in "$workload" "$unit"; do
                if loaded=$(systemctl show "$owned_unit" --property=LoadState --value); then
                    if [[ "$loaded" != not-found ]]; then systemctl stop "$owned_unit" || saved_status=1; fi
                else saved_status=1; fi
            done
            if [[ "$published" == true ]]; then
                if [[ -f "$action" && ! -L "$action" && $(stat -c '%d:%i' "$action") == "$published_identity" ]] && cmp -s "$fixture/approval.policy" "$action"; then rm -- "$action"; else saved_status=1; fi
            fi
            printf '{"schema":"dev-auth-native-privilege-run-v1","exit_code":%d,"scope":"%s","fixture":"%s"}\n' "$saved_status" "$selected_scope" "$fixture" >"$fixture/result.json"
            chmod 0644 "$fixture/result.json"
            printf 'Native acceptance result: %s/result.json\n' "$fixture"
            exit "$saved_status"
        }
        trap cleanup EXIT
        trap 'exit 130' INT TERM
        install -m 0644 -- "$fixture/approval.policy" "$action"
        published_identity=$(stat -c '%d:%i' "$action")
        published=true
        systemd-run --unit="$unit" --property=KillMode=control-group --property=SendSIGKILL=yes --property=ExitType=main --property=TimeoutStopSec=5s --property=RuntimeMaxSec=10m --property=Delegate=no "$fixture/dev-auth" privilege-daemon --policy "$fixture/policy.json" --runtime "$fixture"
        for ((attempt = 0; attempt < 100; attempt++)); do [[ -S "$fixture/control.sock" && -S "$fixture/sudo.sock" ]] && break; sleep 0.1; done
        [[ -S "$fixture/control.sock" && -S "$fixture/sudo.sock" ]]
        if [[ "$selected_scope" == both || "$selected_scope" == user ]]; then
            /usr/bin/unshare --mount --propagation private /usr/bin/bash "$fixture/accept-linux.sh" namespace "$fixture" "$owner" "$group"
            jq -e '.passed == true' "$fixture/user/user-result.json"
        fi
        # The workload probe uses the same root-owned boundary shape and full
        # identity namespace as production, without enrollment or consumer data.
        if [[ "$selected_scope" == both || "$selected_scope" == workload ]]; then
            systemd-run --unit="$workload" --uid="$owner" --gid="$group" --pty --wait --property=PrivateUsers=full --property=PrivateMounts=yes --property=Delegate=no --property=KillMode=control-group --property=SendSIGKILL=yes --property=TimeoutStopSec=5s --property=RuntimeMaxSec=5m --property="BindReadOnlyPaths=$fixture/sudo.conf:/etc/sudo.conf $fixture/sudoers:/etc/sudoers" /usr/bin/bash "$fixture/user.sh" "$fixture" workload
            jq -e '.passed == true' "$fixture/user/workload-result.json"
        fi
        ;;
    namespace)
        [[ $# == 4 && $EUID == 0 ]]
        fixture=$2
        owner=$3
        group=$4
        [[ "$fixture" =~ ^/run/dev-auth-privilege-accept-[a-f0-9]{32}$ && "$owner" =~ ^[1-9][0-9]*$ && "$group" =~ ^[0-9]+$ ]]
        [[ $(readlink /proc/self/ns/mnt) != "$(readlink /proc/1/ns/mnt)" ]]
        mount --bind "$fixture/sudo.conf" /etc/sudo.conf
        mount --bind "$fixture/sudoers" /etc/sudoers
        exec /usr/bin/setpriv --reuid="$owner" --regid="$group" --init-groups --reset-env /usr/bin/bash "$fixture/user.sh" "$fixture" user
        ;;
    *)
        printf '%s\n' 'usage: accept-linux.sh run /absolute/path/to/embedded-dev-auth [both|user|workload]' >&2
        exit 2
        ;;
esac
