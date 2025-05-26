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
### Print command synopsis, options and examples.
### Globals:
###   SCRIPT_NAME – script basename (set here if unset)
###   VERSION     – semantic version (optional)
### Arguments:
###   $1 (optional) – numeric exit code (default 0 for help)
### Outputs:
###   Help text (stdout)
### Exits:
###   Provided exit code, or returns when sourced.
# ──────────────────────────────────────────────────────────────────────────────
usage() {
  local exit_code=${1:-0}

  # fallback script name
  : "${SCRIPT_NAME:=${0##*/}}"

  # ensure numeric exit code
  [[ $exit_code =~ ^[0-9]+$ ]] || exit_code=1

  # shellcheck disable=SC2155
  local vmsg=${VERSION:+ Version ${VERSION}}

  printf '%s\n' \
"Usage: ${SCRIPT_NAME} [OPTIONS] <package> [<package>...]
Compare an application's apt dependencies against Ubuntu Chiseled slices.

Options:
  -r, --release VERSION   Target Ubuntu version (format XX.XX).
                          Defaults to auto-detect from /etc/os-release.
  -n, --dry-run           Print actions only; do not install tools or write files.
  -v, --version           Show script version and exit.
  -h, --help              Show this help text and exit.

Examples:
  \"${SCRIPT_NAME}\" wordpress
  \"${SCRIPT_NAME}\" -r 25.04 wordpress php-fpm mariadb-server
  \"${SCRIPT_NAME}\" --dry-run wordpress

${vmsg}"
  # return when sourced, otherwise exit
  return "$exit_code" 2>/dev/null || exit "$exit_code"
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
# parse_args
### Parse CLI options and positional parameters.
### Globals set:
###   RELEASE_OVERRIDE – Ubuntu version override (string or empty)
###   DRY_RUN          – true/false
###   PACKAGES         – array of package names
### Exits:
###   0  normal parsing
###   1  usage error (no packages)
###   2  getopt/format error
###   3  GNU getopt missing.
# ──────────────────────────────────────────────────────────────────────────────
parse_args() {
  # Ensure GNU getopt exists (macOS users: `brew install gnu-getopt`)
  if ! command -v getopt >/dev/null 2>&1; then
    log_err "GNU getopt is required for argument parsing."
    return 3
  fi

  # shellcheck disable=SC2155
  local _opts
  if ! _opts=$(getopt -o r:nvh -l release:,dry-run,version,help -n "$SCRIPT_NAME" -- "$@"); then
    usage 2; return 2
  fi
  eval set -- "$_opts"

  local release_override='' dry_run=false
  while true; do
    case "$1" in
      -r|--release)
        release_override=$2
        # shellcheck disable=SC2076 # intentional regex
        if [[ ! "$release_override" =~ ^[0-9]{2}\.[0-9]{2}$ ]]; then
          log_err "Invalid release format: '$release_override' (expected XX.XX)"
          usage 2; return 2
        fi
        shift 2 ;;
      -n|--dry-run) dry_run=true; shift ;;
      -v|--version) printf '%s %s\n' "$SCRIPT_NAME" "${VERSION:-unknown}"; return 0 ;;
      -h|--help)    usage 0; return 0 ;;
      --) shift; break ;;
      *)  usage 2; return 2 ;;
    esac
  done

  PACKAGES=("$@")
  if (( ${#PACKAGES[@]} == 0 )); then
    log_err "No package names specified."
    usage 1; return 1
  fi

  # Promote validated locals to globals
  RELEASE_OVERRIDE=$release_override
  DRY_RUN=$dry_run

  # Quote array for log
  log_info "Settings: RELEASE='${RELEASE_OVERRIDE:-<auto>}' DRY_RUN=$DRY_RUN PACKAGES=${PACKAGES[*]}"
  return 0
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
### get_recursive_deps
### Return a sorted, unique list of APT dependencies (recursive) for a package.
### Globals : none
### Args    : $1 – package name (non-empty string)
### Outputs : list of package names on stdout
### Exits   : 0 success
###           2 usage error (missing arg)
###           3 missing apt-rdepends
###           4 apt-rdepends failure or package not found
# ──────────────────────────────────────────────────────────────────────────────
get_recursive_deps() {
  local -r pkg=$1
  if [[ -z $pkg ]]; then
    log_err "Usage: get_recursive_deps <package>"
    return 2
  fi

  command -v apt-rdepends >/dev/null || { log_err "apt-rdepends not installed"; return 3; }

  # Use LC_ALL=C for predictable English output; NR>1 drops the queried pkg itself
  if ! LC_ALL=C apt-rdepends -- "$pkg" 2>/dev/null |
        awk 'NR>1 && /^[^[:space:]]/ {print $1}' |
        sort -u; then
    log_err "Failed to resolve dependencies for '$pkg'"
    return 4
  fi
}

# ──────────────────────────────────────────────────────────────────────────────
### get_available_slices
### Fetch list of Ubuntu-Chisel slice names for a given release branch.
### Globals read :
###   RELEASE_OVERRIDE – optional XX.XX string
###   GITHUB_TOKEN     – optional PAT to raise rate limit
### Outputs :
###   Slice names, one per line, on stdout
### Exits :
###   0 success
###   2 invalid or undetectable release
###   3 missing curl/jq
###   4 HTTP error (non-200)
###   5 zero slices returned
# ──────────────────────────────────────────────────────────────────────────────
get_available_slices() {
  local version branch etag_file api_url http raw
  local -a names

  # ---- determine release ----------------------------------------------------
  if [[ -n ${RELEASE_OVERRIDE:-} ]]; then
    version=$RELEASE_OVERRIDE
  else
    version=$(awk -F= '/^VERSION_ID/ {gsub(/"/,"",$2); print $2}' /etc/os-release 2>/dev/null)
  fi
  # shellcheck disable=SC2076
  [[ $version =~ ^[0-9]{2}\.[0-9]{2}$ ]] || { log_err "Unknown Ubuntu release"; return 2; }

  branch="ubuntu-${version}"
  log_info "Fetching Chisel slices for branch ${branch}"

  # ---- tool check -----------------------------------------------------------
  for t in curl jq; do
    command -v "$t" >/dev/null || { log_err "Missing $t"; return 3; }
  done

  # ---- caching ETag to reduce API calls -------------------------------------
  etag_file="${XDG_CACHE_HOME:-$HOME/.cache}/chisel_${branch}.etag"
  [[ -d ${etag_file%/*} ]] || mkdir -p "${etag_file%/*}"

  api_url="https://api.github.com/repos/canonical/chisel-releases/contents/slices?ref=${branch}"
  local curl_args=( -fsSL -w "%{http_code}" )
  [[ -f $etag_file ]] && curl_args+=( -H "If-None-Match: $(cat "$etag_file")" )
  [[ -n ${GITHUB_TOKEN:-} ]] && curl_args+=( -H "Authorization: Bearer ${GITHUB_TOKEN}" )

  # ---- request --------------------------------------------------------------
  # shellcheck disable=SC2155
  raw=$(curl "${curl_args[@]}" "$api_url") || { log_err "curl failed"; return 4; }
  http=${raw: -3}       # last 3 chars from -w http_code
  raw=${raw::-3}

  case $http in
    200)
      printf '%s\n' "$(grep -Fi ETag -m1 < <(curl -I -s "$api_url") | awk '{print $2}')" >"$etag_file" 2>/dev/null || true
      ;;
    304) log_info "ETag match – using cached slice list"; raw=$(cat "$etag_file.cache");;
    404) log_err "Branch ${branch} not found (404)"; return 4 ;;
    403) log_err "GitHub API rate-limited (403). Set GITHUB_TOKEN."; return 4 ;;
    *)   log_err "GitHub API returned HTTP $http"; return 4 ;;
  esac

  mapfile -t names < <(
    printf '%s\n' "$raw" |
      jq -r '.[]|.name|select(endswith(".yaml"))|rtrimstr(".yaml")' |
      sort -u
  )
  ((${#names[@]})) || { log_err "No slices found for $branch"; return 5; }

  printf '%s\n' "${names[@]}"
  log_info "Fetched ${#names[@]} slices for $branch"
  return 0
}

# ────────────────────────────────────────────────────────────────
# get_file_count <package>
#   Downloads the .deb for <package>, counts its file entries,
#   then cleans up. Prints just the number.
# ────────────────────────────────────────────────────────────────
### get_file_count
### Count files contained in a Debian package (or its provider).
### Globals  : log_err log_warn log_info helpers
### Args     : $1 – package name (string, required)
### Outputs  : file count to stdout
### Exits    : 0 success
###            1 usage error
###            2 non-Debian host or missing tools
###            3 download failed & no provider
###            4 corrupt deb or zero files
get_file_count() {
  local -r pkg=$1
  [[ -n $pkg ]] || { log_err "Usage: get_file_count <package>"; echo 0; return 1; }

  # Debian/Ubuntu-specific tools
  for t in apt-get dpkg-deb; do
    command -v "$t" >/dev/null || { log_err "$t not found"; echo 0; return 2; }
  done

  # Fast path: apt-file
  if command -v apt-file >/dev/null 2>&1; then
    local count
    count=$(apt-file list "$pkg" 2>/dev/null | wc -l || true)
    log_info "File count for $pkg via apt-file: $count"
    printf '%s\n' "${count:-0}"
    return 0
  fi

  # Slow path: download .deb
  umask 077
  local tmpdir
  tmpdir=$(mktemp -d) || { log_err "mktemp failed"; echo 0; return 2; }

  # Ensure cleanup even on error
  trap 'rm -rf "$tmpdir"' RETURN

  (
    cd "$tmpdir" || exit 1

    LC_ALL=C apt-get -qq download -- "$pkg" || {
      log_warn "Download failed for '$pkg' – trying provider"
      local provider
      provider=$(apt-cache showpkg "$pkg" |
                   awk '/Reverse Provides:/{f=1;next}f && NF{print $1; exit}')
      [[ -n $provider ]] || { log_err "No provider for $pkg"; echo 0; exit 3; }
      log_info "Falling back to provider '$provider'"
      LC_ALL=C apt-get -qq download -- "$provider" || { echo 0; exit 3; }
    }

    shopt -s nullglob
    local debs=( *.deb )
    shopt -u nullglob
    (( ${#debs[@]} )) || { log_err "No .deb found for $pkg"; echo 0; exit 4; }

    local count
    count=$(dpkg-deb -c "${debs[0]}" | wc -l || true)
    [[ $count =~ ^[0-9]+$ && $count -gt 0 ]] || { log_err "Corrupt deb for $pkg"; echo 0; exit 4; }

    log_info "File count for $pkg: $count"
    printf '%s\n' "$count"
  )
  local rc=$?
  trap - RETURN
  rm -rf "$tmpdir"
  return "$rc"
}

# ──────────────────────────────────────────────────────────────────────────────
### find_missing_slices
### Determine which apt dependencies lack a corresponding Chisel slice.
### Globals  : PACKAGES (array), log_* helpers
### Outputs  : human-readable list and counts to stdout/stderr
### Exits    : 0 success, 4 helper failure
# ──────────────────────────────────────────────────────────────────────────────
find_missing_slices() {
  local -a deps slices missing_pkgs
  local missing_raw total fc

  # 1) Gather unique deps for all requested packages
  if ! mapfile -t deps < <(
        for pkg in "${PACKAGES[@]}"; do
          get_recursive_deps "$pkg" || exit 4
        done | sort -u
      ); then
    log_err "Dependency resolution failed"; return 4
  fi

  # 2) Fetch slice catalogue (sorted in helper)
  if ! mapfile -t slices < <(get_available_slices | sort -u); then
    log_err "Slice catalogue fetch failed"; return 4
  fi

  # 3) Diff deps-vs-slices (comm requires both inputs sorted)
  missing_raw=$(comm -23 \
      <(printf '%s\n' "${deps[@]}") \
      <(printf '%s\n' "${slices[@]}"))

  # 4) Load into array
  if [[ -n $missing_raw ]]; then
    mapfile -t missing_pkgs <<<"$missing_raw"
  fi

  # 5) Summary log
  total=${#missing_pkgs[@]}
  log_info "Total missing packages: $total"

  # 6) Detailed report
  if (( total == 0 )); then
    log_info "✅ All dependencies have Chisel slices."
  else
    log_warn "🚧 Missing slices (${total}) – package : file_count"
    for pkg in "${missing_pkgs[@]}"; do
      fc=$(get_file_count "$pkg") || fc="err"
      [[ $fc =~ ^[0-9]+$ ]] || fc="err"
      printf '  • %-22s : %5s files\n' "$pkg" "$fc"
    done
  fi
  return 0
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
