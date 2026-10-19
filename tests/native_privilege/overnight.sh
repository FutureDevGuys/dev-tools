#!/usr/bin/env bash
# Explicitly invoked 12-hour native acceptance. Approval remains in the user's
# visible PolicyKit prompt; this fixture records only value-free grant state.
set -euo pipefail
umask 077

fixture=${1:?fixture root required}
[[ "$fixture" =~ ^/run/dev-auth-privilege-accept-[a-f0-9]{32}$ && $(id -u) != 0 ]]
product="$fixture/dev-auth"
export DEV_AUTH_GRANT_SOCKET="$fixture/control.sock"
export PATH=/usr/bin:/bin
cd "$fixture/user"

grant=''
privileged=''
ordinary=''
completed=false
phase=starting
running() {
    local state
    state=$(/usr/bin/ps -o stat= -p "$1" 2>/dev/null) || return 1
    state=${state//[[:space:]]/}
    [[ -n "$state" && "$state" != Z* && "$state" != X* ]]
}
cleanup() {
    status=$?
    trap - EXIT INT TERM
    if [[ "$completed" != true && -n "$grant" ]]; then
        "$product" privilege grant revoke "$grant" --format json >overnight-cleanup.json 2>/dev/null || true
    fi
    if [[ -n "$privileged" ]]; then
        kill -TERM "$privileged" 2>/dev/null || true
        wait "$privileged" 2>/dev/null || true
    fi
    if [[ -n "$ordinary" ]]; then
        kill -TERM "$ordinary" 2>/dev/null || true
        wait "$ordinary" 2>/dev/null || true
    fi
    jq -n --arg phase "$phase" --argjson status "$status" '{schema:"dev-auth-native-overnight-progress-v1",phase:$phase,exit_code:$status}' >overnight-progress.json
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

phase=approval
"$product" privilege grant request --scope user --authority administrator --duration 12h --format json >overnight-request.json
grant=$(jq -er '.grant.id' overnight-request.json)
jq -e '.grant.state == "active" and .grant.duration_seconds == 43200 and .grant.idle_seconds == null and .grant.cleanup_failed == false' overnight-request.json
started_at=$(/usr/bin/date +%s)

phase=initial_execution
"$product" privilege exec -- /usr/bin/id -u >overnight-root-uid.txt
[[ $(<overnight-root-uid.txt) == 0 ]]
/usr/bin/sleep 46800 &
ordinary=$!
"$product" privilege exec --result-file "$fixture/user/overnight-execution-result.json" -- /usr/bin/sleep 46800 </dev/null >/dev/null 2>overnight-execution.stderr &
privileged=$!

phase=observing
previous=43200000
observations=0
while true; do
    "$product" privilege inspect "$grant" --format json >overnight-inspect.json
    state=$(jq -er '.grant.state' overnight-inspect.json)
    remaining=$(jq -er '.grant.remaining_milliseconds' overnight-inspect.json)
    jq -e '.grant.duration_seconds == 43200 and .grant.idle_seconds == null and .grant.cleanup_failed == false' overnight-inspect.json
    (( remaining <= previous ))
    previous=$remaining
    running "$ordinary"
    if [[ "$state" == terminated ]]; then
        jq -e '.grant.remaining_milliseconds == 0 and .grant.stop_reason == "HardExpired"' overnight-inspect.json
        break
    fi
    [[ "$state" == active ]]
    running "$privileged"
    observations=$((observations + 1))
    # A real 12-hour grant must survive many observations without idle expiry.
    # The coordinator's 13-hour unit cap bounds a broken hard-expiry path.
    if (( remaining <= 120000 )); then
        /usr/bin/sleep 5
    else
        /usr/bin/sleep 30
    fi
done
(( observations >= 1000 ))
elapsed=$(( $(/usr/bin/date +%s) - started_at ))
(( elapsed >= 43100 && elapsed <= 46800 ))

phase=expired_execution
if wait "$privileged"; then
    printf '%s\n' 'privileged descendant survived the hard deadline' >&2
    exit 1
fi
privileged=''
running "$ordinary"
if "$product" privilege exec --grant "$grant" -- /usr/bin/true >/dev/null 2>overnight-denial.stderr; then
    printf '%s\n' 'expired grant admitted another privileged execution' >&2
    exit 1
fi
"$product" privilege leave --format json >overnight-leave.json
phase=complete
jq -n --argjson observations "$observations" --argjson elapsed_seconds "$elapsed" '{schema:"dev-auth-native-overnight-acceptance-v1",passed:true,expired:true,non_root_survived:true,observations:$observations,elapsed_seconds:$elapsed_seconds}' >overnight-result.json
completed=true
