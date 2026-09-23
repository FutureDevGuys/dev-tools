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

for scope in workload user; do
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
