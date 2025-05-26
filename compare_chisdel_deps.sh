#!/usr/bin/env bash
###############################################################################
#  compare_chisel_deps.sh – compare apt runtime deps with Ubuntu-Chisel slices
#  Version 1.1.0
###############################################################################
set -euo pipefail
IFS=$'\n\t'

# ──────────────────────────── configurable paths ─────────────────────────────
SCRIPT_NAME=${0##*/}
VERSION="1.1.0"
STATE_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/compare_chisel_deps"
mkdir -p "$STATE_DIR"

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

  cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS] <package> [<package>...]
Compare an application's apt dependencies against Ubuntu Chiseled slices.

Options:
  -r, --release VERSION   Ubuntu version (format XX.XX). Default: auto-detect.
  -n, --dry-run           Print actions only; do not install tools or write
                          files or download packages.
  -v, --version           Show script version and exit.
  -h, --help              Show this help text and exit.

Examples:
  ${SCRIPT_NAME} wordpress
  ${SCRIPT_NAME} -r 25.04 wordpress php-fpm mariadb-server
  ${SCRIPT_NAME} --dry-run curl

${vmsg}
EOF

  # return when sourced, otherwise exit
  return "$exit_code" 2>/dev/null || exit "$exit_code"
}

#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# log LEVEL MESSAGE...
# Logs a message at the given LEVEL (DEBUG, INFO, WARN, or ERROR).
# On first use, initializes the log file and configuration.
#
# Log file: $LOGFILE (auto-set to XDG state dir or /tmp on first call if unset)
# Console output: Colored by level (red=ERROR, yellow=WARN, cyan=INFO; DEBUG uncolored),
#                 suppressed if $NO_COLOR is set (follows NO_COLOR standard:contentReference[oaicite:2]{index=2}).
# Console verbosity: Controlled by $LOG_LEVEL (DEBUG, INFO, WARN, ERROR).
#                   - Default: INFO (shows INFO, WARN, ERROR; hides DEBUG)
#                   - LOG_LEVEL=DEBUG or --verbose: show all levels (including DEBUG)
#                   - LOG_LEVEL=ERROR or --quiet: show only errors (hide INFO/WARN)
#
# The log file always receives all messages (regardless of console level), with timestamp,
# script name & PID, level, and message. File is opened append-only (FD 3) for efficiency.
# ─────────────────────────────────────────────────────────────────────────────
log() {
  local level="$1"; shift
  local msg="$*"

  # Initialize logging on first call
  if [[ -z ${__LOG_INIT+x} ]]; then
    __LOG_INIT=1   # mark initialized

    # Determine log file path (use XDG_STATE_HOME or ~/.local/state, else /tmp)
    local script="${0##*/}"
    local base_dir="${XDG_STATE_HOME:-$HOME/.local/state}"
    [[ -z "$base_dir" ]] && base_dir="/tmp"    # fallback to /tmp if no home directory
    LOGFILE="${LOGFILE:-$base_dir/$script/$script.log}"  # default log file path
    if ! mkdir -p "$(dirname "$LOGFILE")"; then
      # If state dir not writable, use /tmp as last resort
      LOGFILE="/tmp/${script}.log"
      mkdir -p "/tmp" 2>/dev/null
    fi

    # Create/truncate log file and set secure permissions (only user can read/write)
    : > "$LOGFILE"
    chmod 600 "$LOGFILE" 2>/dev/null || true

    # Prepare fixed-width script:PID field for log entries (14-char name + 4-digit PID)
    local pid
    printf -v __LOG_SCRIPT_NAME '%-14.14s' "$script"
    printf -v pid '%04d' "$$"
    printf -v __LOG_SCRIPT_PID_FIELD '%-20s' "${__LOG_SCRIPT_NAME}:${pid}"

    # Predefine padded level strings (for alignment)
    declare -gA __LOG_PAD_LEVEL=([DEBUG]="DEBUG" [INFO]="INFO" [WARN]="WARN" [ERROR]="ERROR")

    # Set up color codes (ANSI escapes) for console, unless NO_COLOR is set:contentReference[oaicite:3]{index=3}
    if [[ -z ${NO_COLOR+x} ]]; then
      __LOG_RED=$'\e[31m'; __LOG_YEL=$'\e[33m'; __LOG_CYN=$'\e[36m'; __LOG_MAG=$'\e[35m'; __LOG_RST=$'\e[0m'
    else
      __LOG_RED=""; __LOG_YEL=""; __LOG_CYN=""; __LOG_MAG=""; __LOG_RST=""
    fi

    # Map log levels to numeric severity for comparison (DEBUG=0, INFO=1, WARN=2, ERROR=3)
    declare -gA __LOG_LEVEL_VALUES=([DEBUG]=0 [INFO]=1 [WARN]=2 [ERROR]=3)

    # Open log file on FD 3 for efficient appending (use exec to keep it open)
    exec 3>>"$LOGFILE"
  fi

  # Format current timestamp in UTC ISO8601 (YYYY-MM-DDTHH:MM:SSZ)
  local ts
  if ! printf -v ts '%(%Y-%m-%dT%H:%M:%SZ)T' -1 2>/dev/null; then
    # Fallback to external date if built-in fails (for older Bash)
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fi

  # Ensure level tag is padded to 5 characters (or truncate if longer)
  local lvl="${__LOG_PAD_LEVEL[$level]:-}"
  [[ -z "$lvl" ]] && printf -v lvl '%-5.5s' "$level"

  # Compose the log line
  local line="[$ts] [${__LOG_SCRIPT_PID_FIELD}] [${lvl}] ${msg}"

  # Write to log file (always append). If FD 3 is unavailable (should not happen after init),
  # fall back to direct append.
  printf '%s\n' "$line" >&3 2>/dev/null || printf '%s\n' "$line" >> "$LOGFILE"

  # Determine numeric severity of this message and current console threshold
  local sev="${__LOG_LEVEL_VALUES[$level]:-1}"
  local threshold="${__LOG_LEVEL_VALUES[${LOG_LEVEL:-INFO}]:-1}"
  [[ -z "$sev" ]] && sev=1         # treat unknown levels as INFO
  [[ -z "$threshold" ]] && threshold=1

  # Echo to console if message severity is >= current $LOG_LEVEL severity
  if (( sev >= threshold )); then
    local color=""
    if [[ -z ${NO_COLOR+x} ]]; then
      case "$level" in
        DEBUG) color="$__LOG_MAG" ;;
        INFO)  color="$__LOG_CYN" ;;
        WARN)  color="$__LOG_YEL" ;;
        ERROR) color="$__LOG_RED" ;;
      esac
    fi
    # Print to stderr for WARN/ERROR, stdout otherwise, with color reset after each line
    if [[ "$level" == "WARN" || "$level" == "ERROR" ]]; then
      printf '%s\n' "${color}${line}${__LOG_RST}" >&2
    else
      printf '%s\n' "${color}${line}${__LOG_RST}"
    fi
  fi
}

# Convenience wrapper functions for each log level:
log_debug() { log "DEBUG" "$@"; }
log_info()  { log "INFO"  "$@"; }
log_warn()  { log "WARN"  "$@"; }
log_err()   { log "ERROR" "$@"; }

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
  ALLOW_ROOT=0  # default: block root unless overridden

  if ! command -v getopt >/dev/null 2>&1; then
    log_err "GNU getopt is required for argument parsing."
    return 3
  fi

  local _opts
  if ! _opts=$(getopt -o r:nvh -l release:,dry-run,version,help,allow-root -n "$SCRIPT_NAME" -- "$@"); then
    usage 2; return 2
  fi
  eval set -- "$_opts"

  local release_override='' dry_run=false
  while true; do
    case "$1" in
      -r|--release)    release_override=$2; shift 2 ;;
      -n|--dry-run)    dry_run=true; shift ;;
      -v|--version)    printf '%s %s\n' "$SCRIPT_NAME" "${VERSION:-unknown}"; return 0 ;;
      -h|--help)       usage 0; return 0 ;;
      --allow-root)    ALLOW_ROOT=1; shift ;;
      --)              shift; break ;;
      *)               usage 2; return 2 ;;
    esac
  done

  PACKAGES=("$@")
  if (( ${#PACKAGES[@]} == 0 )); then
    log_err "No package names specified."
    usage 1; return 1
  fi

  RELEASE_OVERRIDE=$release_override
  DRY_RUN=$dry_run

  log_info "Settings: RELEASE='${RELEASE_OVERRIDE:-<auto>}' DRY_RUN=$DRY_RUN ALLOW_ROOT=$ALLOW_ROOT PACKAGES=${PACKAGES[*]}"
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
###############################################################################
### check_prereqs
### Verify host environment before any heavy work.
### Exits 2 on unrecoverable problems, otherwise 0.
###############################################################################
check_prereqs() {

  # ── 1. Bash & strict-mode --------------------------------------------------
  local bash_ver="${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"
  (( BASH_VERSINFO[0] >= 4 )) || {
    log_err "Bash ≥ 4.0 required (found ${bash_ver})"; exit 2; }
  [[ $(set -o | awk '$1=="pipefail"{print $2}') == on ]] || {
    log_err "\"set -o pipefail\" not active – invoked via /bin/sh?"; exit 2; }

  # ── 2. Least-privilege (unless --allow-root) ------------------------------
  if [[ $EUID -eq 0 ]]; then
    if [[ ${ALLOW_ROOT:-0} -eq 1 ]]; then
      log_warn "Running as root is discouraged, but continuing due to --allow-root."
    else
      log_err "Run as non-root; use --allow-root to override."
      exit 2
    fi
  fi

  # ── 3. Core CLI tools ------------------------------------------------------
  for t in apt-cache apt-rdepends curl jq apt-file; do
    command -v "$t" >/dev/null 2>&1 || {
      log_err "\"$t\" command not found. Install: sudo apt install $t"
      exit 2
    }
  done

  # ── 3a. APT package lists exist (handle .lz4, .gz, etc.) ------------------
  local list_count
  list_count=$(
    find /var/lib/apt/lists -maxdepth 1 -type f \
         ! -name 'lock' ! -path '*/partial/*' -print 2>/dev/null | wc -l
  )
  if (( list_count == 0 )); then
    log_err "APT index cache empty (found 0 files) – run: sudo apt-get update"
    exit 2
  fi
  log_debug "APT list files detected: ${list_count}"

  # ── 3b. apt-file cache (Contents index) present ---------------------------
  local apt_file_msg
  if ! apt_file_msg=$(apt-file --non-interactive list bash 2>&1 >/dev/null); then
    if grep -qi "cache is empty" <<<"$apt_file_msg"; then
      if [[ $EUID -eq 0 && ${ALLOW_ROOT:-0} -eq 1 ]]; then
        log_warn "apt-file cache empty, running 'apt-file update' automatically"
        if ! apt-file --non-interactive update >/dev/null 2>&1; then
          log_err "'apt-file update' failed – check network/repo"
          exit 2
        fi
      else
        log_err "apt-file cache empty – run: sudo apt-file update"
        exit 2
      fi
    fi
  fi

  # ── 3c. Sanity: apt-get can resolve a package -----------------------------
  if ! LC_ALL=C apt-get -qq download bash >/dev/null 2>&1; then
    log_err "APT cannot download packages – check network / sources"
    exit 2
  fi

  # ── 4. Supported distro (Ubuntu/Debian) -----------------------------------
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ ${ID,,} =~ ^(ubuntu|debian)$ ]] || {
      log_err "Unsupported OS \"$ID\" — Debian/Ubuntu required"; exit 2; }
  else
    log_err "Cannot read /etc/os-release to determine OS"; exit 2
  fi

  # ── 5. grep supports –E & POSIX classes -----------------------------------
  echo a | grep -Eq '^[[:alpha:]]' || {
    log_err "\"grep\" lacks -E or POSIX character-class support"; exit 2; }

  # ── 6. Secure temp-file creation ------------------------------------------
  umask 077
  if ! tmpf=$(mktemp -t prereq.XXXXXX 2>/dev/null); then
    log_err "mktemp failed — cannot create secure temp file"; exit 2
  fi
  rm -f "$tmpf"

  # ── 7. Locale advice (non-fatal) ------------------------------------------
  [[ ${LC_ALL:-} =~ ^(C|POSIX)$ ]] || \
    log_warn "Consider LC_ALL=C for predictable diagnostics"

  return 0
}

# ──────────────────────────────────────────────────────────────────────────────
# validate_packages
#
# ──────────────────────────────────────────────────────────────────────────────
validate_packages() {
  for pkg in "${PACKAGES[@]}"; do
    # suppress locale warnings
    if ! LC_ALL=C apt-cache show "$pkg" &>/dev/null; then
      log_err "Package not found in APT repositories: '$pkg'"
      exit 1
    else
      log_info "Verified package exists: $pkg"
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

  if [[ ${DRY_RUN:-false} == true ]]; then
    log_info "[DRY-RUN] Would query $api_url"
    return 0
  fi

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
      printf '%s\n' "$raw" >"${etag_file}.cache"
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

###############################################################################
### get_file_count
### Return the number of files contained in the binary package corresponding
### to $1.  Fast-path uses `apt-file list`, falling back to downloading the
### `.deb` and running `dpkg-deb -c` when apt-file draws a blank (e.g. virtual
### packages).  If both paths fail, prints "err" and returns 4.
###
### Globals read : DRY_RUN, LOG_LEVEL
### Globals used : log_*
### Returns      : 0 on success, >0 on failure
### Output       : file-count (integer) or "err" on stdout
###############################################################################
get_file_count() {
  local pkg=$1
  [[ -n $pkg ]] || { log_err "get_file_count: package name required"; echo "err"; return 2; }

  # Dry-run short-circuit
  if [[ ${DRY_RUN:-false} == true ]]; then
    log_info "[DRY-RUN] skip file-count for $pkg"
    echo "0"; return 0
  fi

  # fast path via apt-file
  if apt_file_out=$(apt-file --non-interactive list "$pkg" 2>/dev/null); then
    local c; c=$(wc -l <<<"$apt_file_out")
    (( c > 0 )) && { echo "$c"; return 0; }
  fi

  # slow path: download .deb
  local tmpdir
  tmpdir=$(mktemp -d) || { log_err "mktemp failed"; echo "err"; return 3; }
  chmod 0755 "$tmpdir"              # allow _apt sandbox to write here
  mkdir -p "$tmpdir/partial"        # apt may need it
  trap 'rm -rf "$tmpdir"' RETURN

  _get_deb() {
    if apt-get help | grep -q "^\\s*download "; then
      (cd "$tmpdir" && apt-get -qq download "$1")
    else
      LC_ALL=C apt-get -qq --download-only --reinstall \
        -o Dir::Cache="$tmpdir" \
        -o Dir::Cache::archives="$tmpdir/" \
        install -- "$1"
    fi
  }

  if ! _get_deb "$pkg" 2>"$tmpdir/apt_err"; then
    if grep -q "no candidate" "$tmpdir/apt_err"; then
      log_warn "'$pkg' is virtual – count set to 0"
      echo "0"; return 0
    fi
    mapfile -t providers < <(apt-cache showpkg "$pkg" |
      awk '/Reverse Provides:/,/^$/' | tail -n +2 | awk '{print $1}')
    if (( ${#providers[@]} )); then
      pkg=${providers[0]}
      log_info "Provider fallback '$pkg'"
      _get_deb "$pkg" 2>>"$tmpdir/apt_err" || {
        log_warn "Download failed: $(head -1 "$tmpdir/apt_err")"
        echo "err"; return 4; }
    else
      log_warn "Download failed: $(head -1 "$tmpdir/apt_err")"
      echo "err"; return 4
    fi
  fi

  shopt -s nullglob
  local debs=( "$tmpdir"/*.deb )
  shopt -u nullglob
  (( ${#debs[@]} )) || { log_warn "No .deb for '$pkg'"; echo "err"; return 4; }

  local count
  count=$(dpkg-deb -c "${debs[0]}" | wc -l) || { echo "err"; return 4; }
  echo "$count"
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────
### find_missing_slices
### Determine which apt dependencies lack a corresponding Chisel slice.
### Globals  : PACKAGES (array), log_* helpers
### Outputs  : human-readable list and counts to stdout/stderr
### Exits    : 0 success, 4 helper failure
# ──────────────────────────────────────────────────────────────────────────────
find_missing_slices() {
  declare -A SEEN_DEPS=()
  local -a deps slices missing_pkgs
  local dep_list missing_raw total fc

  mapfile -t deps < <(
    for pkg in "${PACKAGES[@]}"; do
      [[ -n ${SEEN_DEPS[$pkg]-} ]] && continue
      dep_list=$(get_recursive_deps "$pkg") || exit 4
      while read -r d; do
        [[ -z ${SEEN_DEPS[$d]-} ]] && { SEEN_DEPS[$d]=1; printf '%s\n' "$d"; }
      done <<<"$dep_list"
    done | sort -u
  ) || { log_err "dependency resolution failed"; return 4; }

  mapfile -t slices < <(get_available_slices | sort -u) || {
    log_err "slice catalogue fetch failed"; return 4; }

  missing_raw=$(comm -23 \
      <(printf '%s\n' "${deps[@]}") \
      <(printf '%s\n' "${slices[@]}"))

  [[ -n $missing_raw ]] && mapfile -t missing_pkgs <<<"$missing_raw"
  total=${#missing_pkgs[@]}
  log_info "Total missing packages: $total"

  if (( total == 0 )); then
    log_info "✅ All dependencies have Chisel slices"
  else
    log_warn "🚧  Missing slices (${total}) – package : file_count"
    for pkg in "${missing_pkgs[@]}"; do
      fc=$(get_file_count "$pkg") || fc="err"
      [[ $fc =~ ^[0-9]+$ ]] || fc="err"
      printf '  • %-22s : %5s files\n' "$pkg" "$fc"
    done
  fi
}

###############################################################################
### main – top-level orchestrator
### Phases
###   • Environment sanity   (check_prereqs)
###   • CLI parsing          (parse_args)
###   • Package validation   (validate_packages)
###   • Slice gap analysis   (find_missing_slices)
### Globals : VERSION, SCRIPT_NAME, DRY_RUN, PACKAGES
###############################################################################
main() {
  local start=$SECONDS
  trap 'log_warn "Interrupted"; exit 130' INT TERM

  log_info "${SCRIPT_NAME} ${VERSION} starting"

  # CLI
  parse_args "$@"      || return $?
  log_info "Packages: ${PACKAGES[*]}  |  DRY_RUN=${DRY_RUN:-false}"

  # Environment
  check_prereqs        || return $?

  # Sanity on resolved package names
  validate_packages    || return $?

  # Core analysis
  find_missing_slices  || return $?

  local runtime=$(( SECONDS - start ))
  log_info "Run completed ✔ (elapsed ${runtime}s)"
  return 0
}

# ---- script entrypoint ------------------------------------------------------
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
