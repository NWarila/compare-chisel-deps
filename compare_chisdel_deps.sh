#!/usr/bin/env bash
# compare_chisel_deps.sh – compare an app’s apt deps vs. Ubuntu Chiseled slices

# ──────────────────────────────────────────────────────────────────────────────
# Strict mode & safe IFS
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail
IFS=$'\n\t'

# ──────────────────────────────────────────────────────────────────────────────
# Globals
# ──────────────────────────────────────────────────────────────────────────────
SCRIPT_NAME="$(basename "$0")"
VERSION="1.0.0"
LOGFILE="/var/log/compare_chisel_deps.log"

RELEASE_OVERRIDE=""        # can be set via -r/--release
DRY_RUN=false              # toggled via -n/--dry-run
declare -a PACKAGES=()     # populated by parse_args()

# ──────────────────────────────────────────────────────────────────────────────
# usage [exit_code]
#   Show help & examples, then exit with the given code.
# ──────────────────────────────────────────────────────────────────────────────
usage() {
  local exit_code="${1:-1}"
  cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS] <package> [<package>...]
Compare an application's apt dependencies against Ubuntu Chiseled slices.

Options:
  -r, --release VERSION   Target Ubuntu version (format XX.XX).
                          Defaults to auto-detect from /etc/os-release.
  -n, --dry-run           Print actions only; do not install tools or write files.
  -v, --version           Show script version and exit.
  -h, --help              Show this help text and exit.

Examples:
  $SCRIPT_NAME wordpress
  $SCRIPT_NAME -r 25.04 wordpress php-fpm mariadb-server
  $SCRIPT_NAME --dry-run wordpress

EOF
  exit "$exit_code"
}

# ──────────────────────────────────────────────────────────────────────────────
# log LEVEL MESSAGE…
#   Single function: lazy-inits log file, pads fields, and prints aligned lines.
#   LEVEL must be one of DEBUG, INFO, WARN, ERROR.
# ──────────────────────────────────────────────────────────────────────────────
log() {
  local level=$1; shift
  local msg="$*"

  if [[ -z ${__LOG_INIT+x} ]]; then
    __LOG_INIT=1

    # 1) Prepare log file
    mkdir -p "$(dirname "$LOGFILE")"
    : > "$LOGFILE"

    # 2) Compute static SCRIPT:PID field (14-char name + : + 4-digit PID, padded to 20)
    local script pid
    script="$(basename "$0")"
    printf -v script '%-14.14s' "$script"
    printf -v pid '%04d' "$$"
    printf -v __LOG_SCRIPT_PID_FIELD '%-20s' "${script}:${pid}"

    # 3) Pre-pad levels to 5 chars
    declare -gA __LOG_PAD_LEVEL=(
      [DEBUG]="DEBUG"
      [INFO ]="INFO "
      [WARN ]="WARN "
      [ERROR]="ERROR"
    )

    # 4) Open logfile once on FD 3
    exec 3>>"$LOGFILE"
  fi

  # a) Timestamp (builtin, no external date)
  local ts lvl line
  printf -v ts '%(%Y-%m-%dT%H:%M:%SZ)T' -1

  # b) Lookup padded level (or pad/truncate unknown ones)
  lvl="${__LOG_PAD_LEVEL[$level]:-}"
  if [[ -z $lvl ]]; then
    printf -v lvl '%-5.5s' "$level"
  fi

  # c) Compose, write to log, and echo to console
  line="[$ts] [${__LOG_SCRIPT_PID_FIELD}] [${lvl}] ${msg}"
  printf '%s\n' "$line" >&3
  if [[ $level == "WARN" || $level == "ERROR" ]]; then
    printf '%s\n' "$line" >&2
  else
    printf '%s\n' "$line"
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# parse_args "$@"
#   Uses GNU getopt to handle -r|--release, -n|--dry-run, -v|--version, -h|--help
#   Validates the release format (XX.XX) and ensures at least one package.
# ──────────────────────────────────────────────────────────────────────────────
parse_args() {
  # require GNU getopt
  if ! command -v getopt &>/dev/null; then
    log ERROR "GNU getopt is required for argument parsing."
    exit 3
  fi

  local opts
  opts=$(getopt -o r:nvh -l release:,dry-run,version,help -n "$SCRIPT_NAME" -- "$@") \
    || usage 2
  eval set -- "$opts"

  while true; do
    case "$1" in
      -r|--release)
        shift
        RELEASE_OVERRIDE=$1
        if [[ ! $RELEASE_OVERRIDE =~ ^[0-9]{2}\.[0-9]{2}$ ]]; then
          log ERROR "Invalid release format: '$RELEASE_OVERRIDE' (expected XX.XX)"
          usage 2
        fi
        shift
        ;;
      -n|--dry-run)
        DRY_RUN=true
        shift
        ;;
      -v|--version)
        echo "$SCRIPT_NAME version $VERSION"
        exit 0
        ;;
      -h|--help)
        usage 0
        ;;
      --) shift; break ;;
      *) usage 2 ;;
    esac
  done

  PACKAGES=("$@")
  if (( ${#PACKAGES[@]} == 0 )); then
    log ERROR "No package names specified."
    usage 1
  fi

  log INFO "Settings: RELEASE_OVERRIDE='${RELEASE_OVERRIDE:-<auto>}', DRY_RUN=${DRY_RUN}, PACKAGES=(${PACKAGES[*]})"
}

###############################################################################
### check_prereqs
### Purpose   : Ensure host environment is safe before heavy logic runs.
### Inputs    : env LC_ALL / LANG, CHISEL_OFFLINE, CHISEL_PING_TIMEOUT
### Outputs   : writes diagnostics to stderr
### Side-fx   : creates & cleans a secure temp file
### Exit-codes: 2 = unmet prerequisite
###############################################################################
check_prereqs() {
  # Enforce strict-mode even if caller forgot
  [[ $- == *e* && $- == *u* ]] || set -euo pipefail

  local bash_ver chisel_ver chisel_major os_id tmpf
  # shellcheck disable=SC2155
  local prev_ret=$(trap -p RETURN | cut -d"'" -f2 || true)

  # 1. Bash ≥ 4.0
  bash_ver="${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"
  (( BASH_VERSINFO[0] >= 4 )) || { log_err "Need Bash ≥4 (got $bash_ver)"; exit 2; }

  # 2. pipefail active
  [[ $(set -o | awk '$1=="pipefail"{print $2}') == on ]] ||
    { log_err "\"set -o pipefail\" inactive – invoked via sh?"; exit 2; }

  # 3. non-root
  [[ $EUID -ne 0 ]] || { log_err "Run as non-root; sudo not required."; exit 2; }

  # 4. required tools
  command -v apt-cache >/dev/null || { log_err "\"apt-cache\" missing"; exit 2; }
  command -v chisel     >/dev/null || { log_err "\"chisel\" CLI missing"; exit 2; }

  # 5. chisel ≥1
  chisel_ver=$(chisel --version 2>/dev/null | { read -r _ v; printf '%s\n' "${v#v}"; })
  IFS=. read -r chisel_major _ <<<"$chisel_ver"
  [[ ${chisel_major:-0} =~ ^[0-9]+$ && chisel_major -ge 1 ]] ||
    { log_err "Require chisel ≥1.0 (got ${chisel_ver:-unknown})"; exit 2; }

  # 6. Ubuntu/Debian host (case-insensitive) & safe perms
  if [[ -r /etc/os-release ]]; then
    if command -v stat >/dev/null 2>&1; then
      # GNU = -c, BSD = -f
      local perms
      perms=$(stat -Lc '%u:%a' /etc/os-release 2>/dev/null ||
              stat -f '%u:%Lp' /etc/os-release)
      [[ $perms == 0:6* ]] || { log_err "/etc/os-release perms unsafe"; exit 2; }
    fi
    # shellcheck disable=SC1091
    source /etc/os-release
    # shellcheck disable=SC2076
    [[ "${ID,,}" =~ ^(ubuntu|debian)$ ]] ||
      { log_err "Unsupported OS \"$ID\" – need Ubuntu/Debian"; exit 2; }
  else
    log_err "Cannot read /etc/os-release"; exit 2
  fi

  # 7. grep features
  echo a | grep -Eq '^[[:alpha:]]' ||
    { log_err "\"grep\" lacks -E or POSIX classes"; exit 2; }

  # 8. secure tmp with trap chain
  umask 077
  tmpf=$(mktemp -t prereq.XXXXXX) || { log_err "mktemp failed"; exit 2; }
  trap "${prev_ret:+$prev_ret; }rm -f \"$tmpf\"" RETURN

  # 9. optional chisel ping
  if [[ -z ${CHISEL_OFFLINE:-} ]]; then
    if command -v timeout >/dev/null 2>&1; then
      timeout "${CHISEL_PING_TIMEOUT:-1}" chisel releases list >/dev/null 2>&1 ||
        log_warn "chisel releases list unreachable – offline?"
    else
      log_warn "\"timeout\" absent; skipping network probe"
    fi
  fi

  # 10. locale advisory
  local locale_val=${LC_ALL:-${LANG:-C}}
  [[ $locale_val =~ ^(C|POSIX)$ ]] ||
    log_warn "Consider LC_ALL=C for stable diagnostics"
}

# ──────────────────────────────────────────────────────────────────────────────
# validate_packages
#
# ──────────────────────────────────────────────────────────────────────────────
validate_packages() {
  for pkg in "${PACKAGES[@]}"; do
    # suppress locale warnings
    if ! LC_ALL=C apt-cache show "$pkg" &>/dev/null; then
      log "ERROR" "Package not found in APT repositories: '$pkg'"
      exit 1
    else
      log "INFO" "Verified package exists: $pkg"
    fi
  done
}

# ──────────────────────────────────────────────────────────────────────────────
# get_recursive_deps <package>
#   Prints a sorted, unique list of all runtime deps for $1 (excluding itself).
# ──────────────────────────────────────────────────────────────────────────────
get_recursive_deps() {
  local pkg=$1
  if [[ -z $pkg ]]; then
    log ERROR "Usage: get_recursive_deps <package>"
    return 2
  fi

  LC_ALL=C apt-rdepends "$pkg" 2>/dev/null \
    | awk '/^[^[:space:]]/ { print $1 }' \
    | tail -n +2 \
    | sort -u
}

# ──────────────────────────────────────────────────────────────────────────────
# get_available_slices
#   Fetches all *.yaml slice names (no extension) for the host/override Ubuntu.
# ──────────────────────────────────────────────────────────────────────────────
get_available_slices() {
  local version branch api_url raw names

  if [[ -n $RELEASE_OVERRIDE ]]; then
    version=$RELEASE_OVERRIDE
  else
    version=$(awk -F= '/^VERSION_ID/ { gsub(/"/,"",$2); print $2 }' /etc/os-release)
  fi
  branch="ubuntu-${version}"
  log INFO "Fetching Chisel slices for branch ${branch}"

  for tool in curl jq; do
    command -v "$tool" &>/dev/null || { log ERROR "Missing $tool"; return 3; }
  done

  api_url="https://api.github.com/repos/canonical/chisel-releases/contents/slices?ref=${branch}"
  if ! raw=$(curl -fsSL "$api_url"); then
    log ERROR "Failed to fetch slices from GitHub for ${branch}"
    return 4
  fi

  mapfile -t names < <(
    printf '%s\n' "$raw" \
      | jq -r '.[] | select(.name|endswith(".yaml")) | .name' \
      | sed 's/\.yaml$//' \
      | sort -u
  )
  printf '%s\n' "${names[@]}"
}

# ────────────────────────────────────────────────────────────────
# get_file_count <package>
#   Downloads the .deb for <package>, counts its file entries,
#   then cleans up. Prints just the number.
# ────────────────────────────────────────────────────────────────
get_file_count() {
  local pkg=$1 tmpdir debs deb provider count

  # 1) Quick sanity
  [[ -n $pkg ]] || { echo "0"; return 1; }

  # 2) If apt-file is present use it (fastest)
  if command -v apt-file &>/dev/null; then
    count=$(apt-file list "$pkg" 2>/dev/null | wc -l)
    echo "${count:-0}"
    return
  fi

  # 3) Try downloading the .deb
  tmpdir=$(mktemp -d)
  pushd "$tmpdir" >/dev/null

  if ! apt-get download "$pkg" &>/dev/null; then
    log WARN "Could not download '$pkg'. Attempting to locate real provider…"

    # 3a) Use apt-cache showpkg to find "Reverse Provides"
    mapfile -t providers < <(apt-cache showpkg "$pkg" 2>/dev/null \
      | awk '/Reverse Provides:/,/^$/' \
      | tail -n +2 \
      | awk '{print $1}')

    if (( ${#providers[@]} )); then
      provider=${providers[0]}
      log INFO "Falling back to provider package: '$provider'"
      pkg=$provider
      # retry download
      if ! apt-get download "$pkg" &>/dev/null; then
        log ERROR "Download also failed for provider '$pkg'; skipping count."
        popd >/dev/null; rm -rf "$tmpdir"
        echo "0"
        return
      fi
    else
      log ERROR "No provider found for '$pkg'; skipping count."
      popd >/dev/null; rm -rf "$tmpdir"
      echo "0"
      return
    fi
  fi

  # 4) Enable nullglob and collect .deb files
  shopt -s nullglob
  debs=( *.deb )
  shopt -u nullglob

  if (( ${#debs[@]} == 0 )); then
    log ERROR "Downloaded .deb missing for '$pkg'; skipping count."
    popd >/dev/null; rm -rf "$tmpdir"
    echo "0"
    return
  fi

  # 5) Count entries in the first .deb
  count=$(dpkg-deb -c "${debs[0]}" | wc -l)

  # 6) Cleanup and output
  popd >/dev/null
  rm -rf "$tmpdir"
  echo "$count"
}


# ──────────────────────────────────────────────────────────────────────────────
# find_missing_slices
#   Diffs recursive deps vs. available slices, counts how many are missing,
#   logs the total, and then lists each missing package along with its file count.
# ──────────────────────────────────────────────────────────────────────────────
find_missing_slices() {
  local deps slices missing_raw
  declare -a missing_pkgs

  # 1) Gather deps
  mapfile -t deps < <(
    for pkg in "${PACKAGES[@]}"; do
      get_recursive_deps "$pkg"
    done | sort -u
  )

  # 2) Gather slices
  mapfile -t slices < <(get_available_slices | sort -u)

  # 3) Initial diff
  missing_raw=$(comm -23 \
    <(printf '%s\n' "${deps[@]}") \
    <(printf '%s\n' "${slices[@]}")
  )

  # 4) Load into array
  if [[ -n $missing_raw ]]; then
    mapfile -t missing_pkgs <<<"$missing_raw"
  else
    missing_pkgs=()
  fi

  # 5) Count & log
  local total=${#missing_pkgs[@]}
  log INFO "Total missing packages: ${total}"

  # 6) Report with file counts
  if (( total == 0 )); then
    log INFO "✅ No missing Chisel slices."
  else
    log WARN "🚧 Missing slices for these ${total} packages (package: file_count):"
    for pkg in "${missing_pkgs[@]}"; do
      # get file count for each missing package
      local fc
      fc=$(get_file_count "$pkg")
      printf "  • %-20s : %4s files\n" "$pkg" "$fc"
    done
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
# main: orchestrate
# ──────────────────────────────────────────────────────────────────────────────
main() {
  parse_args "$@"
  ensure_prereqs
  validate_packages
  find_missing_slices
}

main "$@"
