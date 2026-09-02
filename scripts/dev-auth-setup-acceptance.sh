#!/usr/bin/bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  dev-auth-setup-acceptance.sh --deployment PATH --mode strong|user-only [options]

Runs the standalone dev-auth setup flow twice by default: discover, plan, apply,
and verify. A stable second apply must report changed=false.

Options:
  --dev-auth PATH               Installed dev-auth executable. Default: dev-auth from PATH.
  --deployment PATH             Absolute dev-auth-deployment-v1 TOML path.
  --mode strong|user-only       Setup mode to exercise.
  --single-pass                 Run one plan/apply/verify pass instead of two.
  --skip-discover               Skip unprivileged discovery.
  --offline                     Add --offline to setup plan.
  --credential-file SLOT=PATH   Forward to setup apply. May be repeated.
  --credential-stdin SLOT       Forward to setup apply. At most one slot.
  --discover-arg ARG            Extra setup-discover argument. May be repeated.
  --plan-arg ARG                Extra setup-plan argument. May be repeated.
  --apply-arg ARG               Extra setup-apply argument. May be repeated.
  --verify-arg ARG              Extra setup-verify argument. May be repeated.
  --help                        Show this help.

Strong mode authenticates sudo once, then invokes only the canonical root-owned
dev-auth executable with noninteractive sudo from the same parent shell. The
repository script itself is never executed as root. Credential FDs are not
accepted by this harness because sudo may close them; invoke dev-auth directly
when an already-open FD is required.

The private log and plan remain under ${TMPDIR:-/tmp}; their paths are printed
before exit, including after a failed setup step.
EOF
}

die() {
  printf '%s\n' "$*" >&2
  exit 2
}

require_value() {
  [[ -n ${2-} ]] || die "$1 requires a value"
}

resolve_executable() {
  local requested=$1
  local resolved
  if [[ $requested == */* ]]; then
    resolved=$requested
  else
    resolved=$(command -v -- "$requested" || true)
  fi
  [[ -n $resolved && -x $resolved ]] || die "executable is not runnable: $requested"
  /usr/bin/readlink -f -- "$resolved"
}

require_standalone_installed_binary() {
  local executable=$1
  local expected_uid=$2
  local version_dir versions_dir owner mode kind links
  version_dir=${executable%/*}
  versions_dir=${version_dir%/*}
  [[ ${versions_dir##*/} == versions ]] || die \
    "dev-auth setup acceptance requires a standalone .../versions/<version>/dev-auth installation"
  IFS='|' read -r owner mode kind links < <(
    /usr/bin/stat -Lc '%u|%a|%F|%h' -- "$executable"
  )
  [[ $owner == "$expected_uid" ]] || die "installed dev-auth has an unexpected owner"
  [[ $kind == "regular file" && $links == 1 ]] || die \
    "installed dev-auth must be a single-link regular file"
  (( (8#$mode & 0022) == 0 )) || die "installed dev-auth is group- or other-writable"
}

require_strong_active_installation() {
  local executable=$1
  local canonical_alias=/usr/local/bin/dev-auth
  local active
  [[ -L $canonical_alias ]] || die \
    "strong acceptance requires the receipt-owned active strong installation"
  active=$(/usr/bin/readlink -f -- "$canonical_alias") || die \
    "strong acceptance could not resolve the receipt-owned active strong installation"
  [[ $active == "$executable" ]] || die \
    "strong acceptance requires the receipt-owned active strong installation"
  "$canonical_alias" setup verify --mode strong >/dev/null 2>&1 || die \
    "strong acceptance could not verify the receipt-owned active strong installation"
}

extract_line_value() {
  local key=$1 content=$2 line found=
  while IFS= read -r line; do
    if [[ $line == "$key="* ]]; then
      found=${line#*=}
    fi
  done <<<"$content"
  [[ -n $found ]] || return 1
  printf '%s\n' "$found"
}

CAPTURED_OUTPUT=
FINAL_LOG_PATH=
FINAL_PLAN_PATH=

print_evidence_paths() {
  local rc=$?
  if [[ -n $FINAL_LOG_PATH ]]; then
    printf 'log_path=%s\n' "$FINAL_LOG_PATH"
    printf 'plan_path=%s\n' "$FINAL_PLAN_PATH"
  fi
  trap - EXIT
  exit "$rc"
}

capture_step() {
  local log_path=$1 step_path=$2 label=$3
  shift 3
  local rc=0
  {
    printf '== %s ==\n' "$label"
    printf 'command:'
    printf ' %q' "$@"
    printf '\n'
  } >>"$log_path"
  : >"$step_path"
  if "$@" >"$step_path" 2>&1; then
    rc=0
  else
    rc=$?
  fi
  CAPTURED_OUTPUT=$(<"$step_path")
  printf '%s\n' "$CAPTURED_OUTPUT" | /usr/bin/tee -a "$log_path"
  printf '[%s] exit=%s\n' "$label" "$rc" >>"$log_path"
  return "$rc"
}

main() {
  local requested_dev_auth=dev-auth deployment='' mode='' passes=2
  local skip_discover=0 offline=0 stdin_slots=0 rc=0
  local -a discover_args=() plan_args=() apply_args=() verify_args=()

  while (($# > 0)); do
    case $1 in
      --dev-auth)
        shift; require_value --dev-auth "${1-}"; requested_dev_auth=$1 ;;
      --deployment)
        shift; require_value --deployment "${1-}"; deployment=$1 ;;
      --mode)
        shift; require_value --mode "${1-}"; mode=$1 ;;
      --single-pass) passes=1 ;;
      --skip-discover) skip_discover=1 ;;
      --offline) offline=1 ;;
      --credential-file)
        shift; require_value --credential-file "${1-}"; apply_args+=(--credential-file "$1") ;;
      --credential-stdin)
        shift; require_value --credential-stdin "${1-}"
        ((stdin_slots += 1)); apply_args+=(--credential-stdin "$1") ;;
      --credential-fd)
        die "--credential-fd is intentionally unsupported by this sudo-safe harness; invoke dev-auth setup apply directly" ;;
      --discover-arg)
        shift; require_value --discover-arg "${1-}"; discover_args+=("$1") ;;
      --plan-arg)
        shift; require_value --plan-arg "${1-}"; plan_args+=("$1") ;;
      --apply-arg)
        shift; require_value --apply-arg "${1-}"; apply_args+=("$1") ;;
      --verify-arg)
        shift; require_value --verify-arg "${1-}"; verify_args+=("$1") ;;
      --help) usage; return 0 ;;
      *) usage >&2; die "unsupported argument: $1" ;;
    esac
    shift
  done

  [[ -n $deployment && -n $mode ]] || { usage >&2; die "--deployment and --mode are required"; }
  [[ $deployment == /* ]] || die "deployment path must be absolute"
  [[ -f $deployment ]] || die "deployment path is not a regular file"
  [[ $mode == strong || $mode == user-only ]] || die "mode must be strong or user-only"
  ((stdin_slots <= 1)) || die "standard input may supply at most one credential slot"

  local dev_auth_bin expected_uid
  dev_auth_bin=$(resolve_executable "$requested_dev_auth")
  if [[ $mode == strong ]]; then
    require_strong_active_installation "$dev_auth_bin"
    expected_uid=0
  else
    expected_uid=$(/usr/bin/id -u)
  fi
  require_standalone_installed_binary "$dev_auth_bin" "$expected_uid"

  local temp_root log_path plan_path step_path
  temp_root=$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/dev-auth-setup-acceptance.XXXXXX")
  /usr/bin/chmod 700 "$temp_root"
  log_path=$temp_root/run.log
  plan_path=$temp_root/setup-plan.json
  step_path=$temp_root/step.out
  FINAL_LOG_PATH=$log_path
  FINAL_PLAN_PATH=$plan_path
  : >"$log_path"
  /usr/bin/chmod 600 "$log_path" "$step_path" 2>/dev/null || true
  trap print_evidence_paths EXIT

  {
    printf 'dev_auth=%s\n' "$dev_auth_bin"
    printf 'deployment=%s\n' "$deployment"
    printf 'mode=%s\n' "$mode"
    printf 'passes=%s\n' "$passes"
    printf 'timestamp=%(%FT%T%z)T\n' -1
  } >>"$log_path"

  if ((skip_discover == 0)); then
    capture_step "$log_path" "$step_path" discover \
      "$dev_auth_bin" setup discover --mode "$mode" "${discover_args[@]}"
  fi

  local -a privileged=()
  if [[ $mode == strong ]]; then
    [[ -x /usr/bin/sudo ]] || die "strong acceptance requires /usr/bin/sudo"
    /usr/bin/sudo -v
    privileged=(/usr/bin/sudo -n --)
  fi
  ((offline == 0)) || plan_args+=(--offline)

  local pass label digest changed verified apply_rc
  for ((pass = 1; pass <= passes; pass += 1)); do
    label=pass-$pass
    capture_step "$log_path" "$step_path" "$label/plan" \
      "${privileged[@]}" "$dev_auth_bin" setup plan \
      --deployment "$deployment" --mode "$mode" --output "$plan_path" \
      --format human "${plan_args[@]}"
    digest=$(extract_line_value setup_plan_sha256 "$CAPTURED_OUTPUT") || die \
      "setup plan did not emit setup_plan_sha256"

    if capture_step "$log_path" "$step_path" "$label/apply" \
      "${privileged[@]}" "$dev_auth_bin" setup apply \
      --plan "$plan_path" --sha256 "$digest" --format human "${apply_args[@]}"; then
      apply_rc=0
    else
      apply_rc=$?
    fi
    changed=$(extract_line_value changed "$CAPTURED_OUTPUT") || die \
      "setup apply did not emit changed"
    verified=$(extract_line_value verified "$CAPTURED_OUTPUT") || die \
      "setup apply did not emit verified"
    ((pass != 2)) || [[ $changed == false ]] || die \
      "second setup apply must report changed=false"
    ((apply_rc == 0)) || return "$apply_rc"
    [[ $verified == true ]] || die "setup apply did not verify the approved postcondition"

    capture_step "$log_path" "$step_path" "$label/verify" \
      "${privileged[@]}" "$dev_auth_bin" setup verify \
      --plan "$plan_path" --sha256 "$digest" --format human "${verify_args[@]}"
    verified=$(extract_line_value verified "$CAPTURED_OUTPUT") || die \
      "setup verify did not emit verified"
    [[ $verified == true ]] || die "setup verify did not confirm the approved postcondition"
  done
}

main "$@"
