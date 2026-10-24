#!/usr/bin/env bash
# Native acceptance fixture only. Passwords remain with sudo/PolicyKit on the
# user's visible terminal. This script captures only public command results.
set -euo pipefail
umask 077

fixture=${1:?fixture root required}
scope=${2:?user or workload scope required}
[[ "$fixture" =~ ^/run/dev-auth-privilege-accept-[a-f0-9]{32}$ ]]
[[ "$scope" == user || "$scope" == workload ]]
[[ $(id -u) != 0 ]]
product="$fixture/dev-auth"
export DEV_AUTH_GRANT_SOCKET="$fixture/control.sock"
export PATH=/usr/bin:/bin
cd "$fixture/user"
sentinel=''
current_step=starting
phase() {
    current_step=$1
    printf 'Dev Auth acceptance: %s / %s\n' "$scope" "$current_step"
    jq -n --arg scope "$scope" --arg step "$current_step" '{schema:"dev-auth-native-privilege-progress-v1",scope:$scope,step:$step}' >"$scope-progress.json"
}
cleanup() {
    saved_status=$?
    if [[ -n "$sentinel" ]]; then
        kill -TERM "$sentinel" 2>/dev/null || true
        wait "$sentinel" 2>/dev/null || true
    fi
    jq -n --arg scope "$scope" --arg step "$current_step" --argjson status "$saved_status" '{schema:"dev-auth-native-privilege-progress-v1",scope:$scope,step:$step,exit_code:$status}' >"$scope-progress.json"
}
trap cleanup EXIT

# The fixture sudoers uses a private timestamp directory. This native approval
# cannot alter the user's normal sudo timestamp store.
phase native_timestamp_approval
# Combining -k with -v deliberately suppresses timestamp updates. Invalidate
# first, then authenticate separately to establish the warm-ticket baseline.
sudo -k
sudo -v
phase native_warm_ticket
sudo -n -- /usr/bin/true
/usr/bin/sleep 300 &
sentinel=$!

phase long_grant_approval
"$product" privilege grant request --scope "$scope" --authority administrator --duration 12h --format json >"$scope-request.json"
grant=$(jq -er '.grant.id' "$scope-request.json")
[[ $(jq -r '.grant.duration_seconds' "$scope-request.json") == 43200 ]]
[[ $(jq -r '.grant.idle_seconds' "$scope-request.json") == null ]]

phase cli_and_native_sudo
# Upstream sudo 1.9 names timestamp files by numeric native UID.
timestamp="$fixture/timestamps/$(id -u)"
phase timestamp_before
"$product" privilege exec --result-file "$fixture/user/$scope-timestamp-before-result.json" -- /usr/bin/sha256sum "$timestamp" >"$scope-timestamp-before.stdout" 2>"$scope-timestamp-before.stderr"
before=$(<"$scope-timestamp-before.stdout")
phase cli_root_identity
"$product" privilege exec --result-file "$fixture/user/$scope-cli-root-result.json" -- /usr/bin/id -u >"$scope-cli-root.stdout" 2>"$scope-cli-root.stderr"
[[ $(<"$scope-cli-root.stdout") == 0 ]]
phase approved_graph
"$product" privilege exec --operation fixture-pipeline --result-file "$fixture/user/$scope-graph-result.json" >"$scope-graph.stdout" 2>"$scope-graph.stderr"
printf 'graph\000bytes' >"$scope-graph-expected"
cmp "$scope-graph-expected" "$scope-graph.stdout"
phase delegated_graph_budget
"$product" privilege delegate "$grant" --scope "$scope" --authority typed --operation fixture-pipeline --duration 60s --uses 1 --format json >"$scope-graph-delegate.json"
graph_grant=$(jq -er '.grant.id' "$scope-graph-delegate.json")
jq -e '.grant.remaining_uses == 1' "$scope-graph-delegate.json"
"$product" privilege exec --grant "$graph_grant" --operation fixture-pipeline --result-file "$fixture/user/$scope-delegated-graph-result.json" >"$scope-delegated-graph.stdout" 2>"$scope-delegated-graph.stderr"
cmp "$scope-graph-expected" "$scope-delegated-graph.stdout"
"$product" privilege inspect "$graph_grant" --format json >"$scope-graph-budget.json"
jq -e '.grant.remaining_uses == 0' "$scope-graph-budget.json"
phase exhausted_graph_denial
if "$product" privilege exec --grant "$graph_grant" --operation fixture-pipeline --result-file "$fixture/user/$scope-exhausted-graph-result.json" >"$scope-exhausted-graph.stdout" 2>"$scope-exhausted-graph.stderr"; then
    printf '%s\n' 'exhausted graph authority incorrectly admitted another graph or used the administrator grant' >&2
    exit 1
fi
[[ ! -s "$scope-exhausted-graph.stdout" ]]
jq -e '.error_kind != null and .changed == false' "$scope-exhausted-graph-result.json"
phase native_sudo_identity
# The unprivileged fixture user intentionally owns all diagnostic redirects.
# shellcheck disable=SC2024
sudo -n -- /usr/bin/id -u >"$scope-native-root.stdout" 2>"$scope-native-root.stderr"
[[ $(<"$scope-native-root.stdout") == 0 ]]
phase absolute_sudo_identity
# shellcheck disable=SC2024
/usr/bin/sudo -n -- /usr/bin/id -u >"$scope-absolute-root.stdout" 2>"$scope-absolute-root.stderr"
[[ $(<"$scope-absolute-root.stdout") == 0 ]]
phase native_original_identity
# shellcheck disable=SC2024
/usr/bin/sudo -n -- /usr/bin/printenv SUDO_UID >"$scope-original-uid.stdout" 2>"$scope-original-uid.stderr"
[[ $(<"$scope-original-uid.stdout") == "$(id -u)" ]]
phase native_validate_no_refresh
sudo -n -v
"$product" privilege exec --result-file "$fixture/user/$scope-timestamp-after-result.json" -- /usr/bin/sha256sum "$timestamp" >"$scope-timestamp-after.stdout" 2>"$scope-timestamp-after.stderr"
after=$(<"$scope-timestamp-after.stdout")
[[ "$before" == "$after" ]]

phase ansible_become
ANSIBLE_CONFIG="$fixture/ansible.cfg" /usr/bin/ansible-playbook -i localhost, -c local "$fixture/become.yml"
phase revocation
"$product" privilege grant revoke "$grant" --format json >"$scope-revoke.json"
[[ $(jq -r '.grant.state' "$scope-revoke.json") == terminated ]]
kill -0 "$sentinel"
phase native_after_revocation
# ADR 0136: routing ends with its grant, so sudo regains its native behavior.
sudo -n -- /usr/bin/true
"$product" privilege leave --format json >"$scope-leave.json"
jq -e '.changed == false' "$scope-leave.json"

phase short_grant_approval
"$product" privilege grant request --scope "$scope" --authority administrator --duration 4s --format json >"$scope-expiry-request.json"
expiring=$(jq -er '.grant.id' "$scope-expiry-request.json")
phase hard_expiry
"$product" privilege exec -- /usr/bin/sleep 60 </dev/null >"$scope-expiry.stdout" 2>"$scope-expiry.stderr" &
privileged=$!
if wait "$privileged"; then
    printf '%s\n' 'privileged command survived its hard deadline' >&2
    exit 1
fi
kill -0 "$sentinel"
for ((attempt = 0; attempt < 50; attempt++)); do
    "$product" privilege inspect "$expiring" --format json >"$scope-expiry-result.json"
    [[ $(jq -r '.grant.state' "$scope-expiry-result.json") == terminated ]] && break
    sleep 0.1
done
[[ $(jq -r '.grant.state' "$scope-expiry-result.json") == terminated ]]
sudo -n -- /usr/bin/true
phase complete
printf '{"schema":"dev-auth-native-privilege-acceptance-v1","scope":"%s","passed":true}\n' "$scope" >"$scope-result.json"
