#!/usr/bin/env bash
# Runs only as the synthetic account in an owned disposable systemd container.
# Combined launches inherit the visible terminal. Never redirect their I/O:
# the native approval agent may sit behind systemd-run's forwarded PTY.
set -euo pipefail
umask 077
[[ -f /run/.containerenv && $(id -un) == dev-auth-recover-alpha && -t 0 && -t 1 ]]
[[ "$HOME" == /home/dev-auth-recover-alpha ]]
product=/usr/local/bin/dev-auth
cd "$HOME"
step=starting
# Invoked by the EXIT trap, including after a failed native assertion.
# shellcheck disable=SC2329
result() {
    status=$?
    trap - EXIT
    printf '{"schema":"dev-auth-installed-launch-acceptance-v1","step":"%s","exit_code":%d}\n' "$step" "$status" >installed-result.json
    exit "$status"
}
trap result EXIT
phase() {
    step=$1
    printf 'Installed launch acceptance: %s\n' "$step"
    printf '{"step":"%s"}\n' "$step" >installed-progress.json
}
status() {
    "$product" privilege status --format json >grants.json
}
no_active_user_grant() {
    status
    jq -e '[.grants[]? | select(.scope == "user" and .state == "active")] | length == 0' grants.json >/dev/null
}
interactive_login_session() {
    local result_file=$1
    local account_uid sessions session class kind state count=0 found=false query_ok=true
    account_uid=$(id -u)
    if [[ -e /fixture/login-session-probe-only ]]; then
        sessions=$(loginctl show-user "$account_uid" --property=Sessions --value 2>loginctl-error.txt) || { sessions=''; query_ok=false; }
    else
        sessions=$(loginctl show-user "$account_uid" --property=Sessions --value 2>/dev/null) || { sessions=''; query_ok=false; }
    fi
    class=''
    kind=''
    state=''
    for session in $sessions; do
        ((count += 1))
        class=$(loginctl show-session "$session" --property=Class --value 2>/dev/null) || class=''
        kind=$(loginctl show-session "$session" --property=Type --value 2>/dev/null) || kind=''
        state=$(loginctl show-session "$session" --property=State --value 2>/dev/null) || state=''
        case "$class:$kind:$state" in
            user:tty:online|user:tty:active|user-early:tty:online|user-early:tty:active|user-light:tty:online|user-light:tty:active|user-early-light:tty:online|user-early-light:tty:active)
                found=true
                break
                ;;
        esac
    done
    jq -n --argjson session_count "$count" --argjson interactive "$found" --argjson loginctl_query_ok "$query_ok" \
        --argjson xdg_session_id_present "$([[ -n ${XDG_SESSION_ID:-} ]] && echo true || echo false)" \
        --arg environment_class "${XDG_SESSION_CLASS:-}" --arg environment_type "${XDG_SESSION_TYPE:-}" \
        --arg class "$class" --arg type "$kind" --arg state "$state" \
        '{schema:"dev-auth-installed-login-check-v1",session_count:$session_count,interactive:$interactive,loginctl_query_ok:$loginctl_query_ok,xdg_session_id_present:$xdg_session_id_present,environment_class:$environment_class,environment_type:$environment_type,last_class:$class,last_type:$type,last_state:$state}' >"$result_file"
    [[ "$found" == true ]]
}

phase login_initial_preflight
if ! interactive_login_session login-session-initial.json; then
    printf '%s\n' 'native login has no interactive logind session; user-wide grant cannot be requested' >&2
    exit 1
fi
if [[ -e /fixture/login-session-probe-only ]]; then
    phase complete
    exit 0
fi

for scope in workload user; do
    if [[ "$scope" == user ]]; then
        phase login_after_workload_preflight
        if ! interactive_login_session login-session-after-workload.json; then
            printf '%s\n' 'interactive logind session ended during workload launch; user-wide grant cannot be requested' >&2
            exit 1
        fi
    fi
    phase "${scope}_approval"
    [[ ! -e "$HOME/payload-$scope" ]]
    "$product" workload launch worker --privilege-scope "$scope" --privilege-duration 120s --result-file "$HOME/$scope-launch-result.json" -- privilege-check "$scope"
    phase "${scope}_result"
    [[ $(<"payload-$scope") == installed-privilege-check=passed ]]
    jq -e '.exit_code == 0' "$scope-launch-result.json"
    if [[ "$scope" == user ]]; then
        status
        jq -e '[.grants[]? | select(.scope == "user" and .state == "active")] | length == 1' grants.json
        "$product" privilege leave --format json >user-leave.json
    fi
    no_active_user_grant
done

phase failed_start_approval
if "$product" workload launch broken-worker --privilege-scope user --privilege-duration 120s --result-file "$HOME/failed-start-result.json" --; then
    printf '%s\n' 'a missing interpreter incorrectly reported a successful launch' >&2
    exit 1
fi
phase failed_start_cleanup
# A failed product startup must not retain the newly issued account-wide grant.
# Observe coordinator cleanup rather than assuming a sleep means completion.
for ((attempt=0; attempt<50; attempt++)); do
    if no_active_user_grant; then
        phase complete
        exit 0
    fi
    sleep 0.1
done
printf '%s\n' 'a failed startup retained its newly approved user-wide grant' >&2
exit 1
