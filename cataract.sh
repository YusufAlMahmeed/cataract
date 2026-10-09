#!/usr/bin/env bash
# ============================================================================
#  cataract.sh  --  Cataract
#  Multi-target, recursive, tiered web enumeration for authorized web pentesting
# ============================================================================
#  Version:  7.1.0
#  Author:   Yusuf AlMahmeed  (github.com/YusufAlMahmeed)
#  License:  MIT (see LICENSE)
#
#  "Cataract" = a great waterfall: the scan cascades down through escalating
#  wordlist tiers until you find what you need.
#
#  Purpose:  Automates the "which wordlist, when" decision for web content
#            discovery, adds recursion (which gobuster lacks), runs a full
#            port scan in parallel, and can drive several targets at once --
#            each in its own tmux TAB inside a single window -- while
#            preserving feroxbuster's colorized live output and logging it.
#
#  ------------------------------------------------------------------------
#  Usage:
#    Interactive:  ./cataract.sh
#    Direct:       ./cataract.sh -o <output_dir> <target1> [target2] ...
#    From file:    ./cataract.sh -o <output_dir> -f <targets_file>
#    Help:         ./cataract.sh -h
#
#    Targets accept any of:
#        192.168.51.77          (bare IP        -> http://192.168.51.77)
#        192.168.51.77:8080     (host:port      -> http://192.168.51.77:8080)
#        http://192.168.51.77   (full URL, used as-is)
#        https://host:8443/path (full URL, used as-is; -k auto-enabled)
#    In INTERACTIVE mode you are asked for the service (http/https) and port
#    for each bare target, so you control exactly what gets scanned.
#
#  ------------------------------------------------------------------------
#  Pause / cancel / navigate:
#    - Pause/cancel the CURRENT feroxbuster tier: press ENTER (opens ferox's
#      Scan Management Menu).
#    - Switch tabs:  Ctrl+b n/p  or  Ctrl+b <number>   (mouse click works too)
#    - Detach (keep running): Ctrl+b d   Reattach: tmux attach -t <session>
#    - Stop everything: tmux kill-session -t <session>
#    - Stopping (Ctrl+C / closing a tab / kill-session) still SAVES whatever
#      the in-progress target has found so far (results + summary + index).
#
#  Authorized testing only. Run this only against systems you own or have
#  explicit written permission to test.
# ============================================================================

set -uo pipefail

# ============================================================================
#  TUNABLES  --  each honors an environment override (so the launchers can
#  propagate flag-set values into tmux/GUI worker tabs). `: "${VAR:=default}"`
#  assigns the default only when VAR is unset, so an inherited/exported value
#  wins.
# ============================================================================
: "${THREADS:=50}"                                   # feroxbuster threads
: "${DEPTH:=2}"                                        # recursion depth (raise with -d)
: "${EXTENSIONS:=php,html,txt,js,json,bak,zip}"        # appended to each word
# NMAP_OPTS default is root-aware: as root nmap can do a fast SYN scan, so we
# add --min-rate 1000; as non-root nmap falls back to a slower connect scan
# (warned about at startup). An explicit NMAP_OPTS from the environment is
# always respected as-is (so this stays overridable).
if [[ -z "${NMAP_OPTS:-}" ]]; then
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        NMAP_OPTS="-p- -sV -sC -Pn --min-rate 1000"
    else
        NMAP_OPTS="-p- -sV -sC -Pn"
    fi
fi
: "${RATE_LIMIT:=0}"                                   # ferox req/sec (0 = off)
: "${INSECURE:=0}"                                     # 1 = always add ferox -k
: "${AUTO:=0}"                                         # 1 = no tier prompts
: "${NO_EXT:=0}"                                       # 1 = never append --extensions
: "${DRY_RUN:=0}"                                      # 1 = print plan and exit
: "${USE_GUI_TERM:=0}"                                 # 1 = GUI windows opt-in
: "${EXTRA_PORT_MAX_TIER:=2}"                          # tier cap for discovered
                                                       #   extra web ports

# Tier wordlist candidate paths (first existing wins; absorbs distro casing).
#
# Tiers 3/4 use the SecLists raft *directories* lists, not the *files* lists:
#   - directory words have no extension, so appending EXTENSIONS is correct
#     (the files lists already include extensions -> e.g. index.php.php waste),
#   - directories are what feroxbuster's recursion descends into.
# The matching raft *files* lists are resolved separately and run as an extra
# pass WITHOUT --extensions (see run_cascade), so filenames are still covered.
TIER1_CANDIDATES=( "/usr/share/wordlists/dirb/common.txt" )
TIER2_CANDIDATES=( "/usr/share/wordlists/dirb/big.txt" )
TIER3_CANDIDATES=(
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    "/usr/share/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
    "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
    "/opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt"
)
TIER4_CANDIDATES=(
    "/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt"
    "/usr/share/SecLists/Discovery/Web-Content/raft-large-directories.txt"
    "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt"
    "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt"
    "/opt/SecLists/Discovery/Web-Content/raft-large-directories.txt"
)
# raft *files* lists for the no-extension filename pass (optional; skipped if absent).
TIER3_FILES_CANDIDATES=(
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt"
    "/usr/share/SecLists/Discovery/Web-Content/raft-medium-files.txt"
    "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt"
    "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-files.txt"
    "/opt/SecLists/Discovery/Web-Content/raft-medium-files.txt"
)
TIER4_FILES_CANDIDATES=(
    "/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt"
    "/usr/share/SecLists/Discovery/Web-Content/raft-large-files.txt"
    "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt"
    "/usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-files.txt"
    "/opt/SecLists/Discovery/Web-Content/raft-large-files.txt"
)

# Extra HTTP headers passed to feroxbuster (-H). Populated by the -H flag, and
# re-hydrated in worker tabs from the exported CATARACT_HEADERS (newline-join).
# Arrays cannot be exported directly, hence the encode/decode dance.
HEADERS=()
if [[ -n "${CATARACT_HEADERS:-}" ]]; then
    mapfile -t HEADERS <<< "$CATARACT_HEADERS"
    # printf '%s\n' + here-string leaves a trailing empty element; drop it.
    [[ ${#HEADERS[@]} -gt 0 && -z "${HEADERS[-1]}" ]] && unset 'HEADERS[-1]'
fi

# Custom wordlists (-w, repeatable). When non-empty they REPLACE the tier
# cascade and run in the exact order given. Re-hydrated in worker tabs from the
# exported CATARACT_CUSTOM_WORDLISTS (newline-joined, same trick as HEADERS).
CUSTOM_WORDLISTS=()
if [[ -n "${CATARACT_CUSTOM_WORDLISTS:-}" ]]; then
    mapfile -t CUSTOM_WORDLISTS <<< "$CATARACT_CUSTOM_WORDLISTS"
    [[ ${#CUSTOM_WORDLISTS[@]} -gt 0 && -z "${CUSTOM_WORDLISTS[-1]}" ]] && unset 'CUSTOM_WORDLISTS[-1]'
fi

# ============================================================================
#  Colors + logging helpers
# ============================================================================
C_RESET='\033[0m'; C_BOLD='\033[1m'
C_GREEN='\033[1;32m'; C_YELLOW='\033[1;33m'; C_CYAN='\033[1;36m'; C_RED='\033[1;31m'
banner()   { echo -e "${C_CYAN}${C_BOLD}[*]${C_RESET} $1"; }
done_msg() { echo -e "${C_GREEN}${C_BOLD}[+]${C_RESET} $1"; }
warn_msg() { echo -e "${C_YELLOW}${C_BOLD}[!]${C_RESET} $1"; }
err_msg()  { echo -e "${C_RED}${C_BOLD}[x]${C_RESET} $1"; }

# ============================================================================
#  Runtime state
# ============================================================================
OUTDIR=""; TARGETS_FILE=""; TARGETS=(); WORKER_MODE=0
WORKER_TARGET=""; WORKER_DIR=""; norm=""
TIER1_WORDLIST=""; TIER2_WORDLIST=""; TIER3_WORDLIST=""; TIER4_WORDLIST=""
TIER3_FILES_WORDLIST=""; TIER4_FILES_WORDLIST=""
BG_PIDS=()   # background nmap PIDs, so the trap can reap them
# Set by run_target so an interrupt can save the in-progress target's results.
CURRENT_TARGET=""; CURRENT_TDIR=""; CURRENT_NMAP_TXT=""; CURRENT_OUTDIR=""
SALVAGING=0

# ---- Clean shutdown: never orphan a background nmap scan --------------------
cleanup() {
    local p
    for p in ${BG_PIDS[@]+"${BG_PIDS[@]}"}; do
        kill "$p" 2>/dev/null
    done
}

# on_interrupt: on Ctrl+C / terminal close / tmux kill, SAVE whatever the
# in-progress target has produced so far -- de-duplicate the partial JSON/logs,
# write all_unique_results.txt + summary.md, and refresh index.md -- before
# exiting. (finalize_target/build_index are defined later; a bash trap resolves
# them at fire time, and the CURRENT_* guards keep it safe if a signal arrives
# before any scanning has started.)
on_interrupt() {
    [[ "$SALVAGING" == "1" ]] && exit 130     # ignore repeat signals while saving
    SALVAGING=1
    trap - INT TERM HUP
    echo
    warn_msg "Interrupted -- saving results collected so far..."
    cleanup
    if [[ -n "$CURRENT_TDIR" && -d "$CURRENT_TDIR" ]]; then
        finalize_target "$CURRENT_TARGET" "$CURRENT_TDIR" "$CURRENT_NMAP_TXT" 2>/dev/null
        done_msg "Saved partial results: $CURRENT_TDIR/all_unique_results.txt"
    fi
    [[ -n "$CURRENT_OUTDIR" ]] && build_index "$CURRENT_OUTDIR" 2>/dev/null
    exit 130
}
trap cleanup EXIT
trap on_interrupt INT TERM HUP

usage() {
    cat <<EOF
cataract.sh -- tiered, recursive, multi-target web enumeration

USAGE:
  $0                                   Interactive prompts (asks service+port).
  $0 -o <output_dir> <target> [...]    One or more targets on the CLI.
  $0 -o <output_dir> -f <targets_file> Targets from a file (one per line).
  $0 -h | --help                       This help.

OPTIONS:
  -o <dir>        Output directory (required in non-interactive mode).
  -f <file>       Read targets from a file (one per line; # comments ok).
  -t <n>          feroxbuster threads          (default: $THREADS)
  -d <n>          Recursion depth              (default: $DEPTH)
  -x <exts>       Comma-separated extensions   (default: $EXTENSIONS)
  -w <wordlist>   Use a custom wordlist instead of the tier cascade. Repeatable:
                  pass -w multiple times to run several lists in the given order.
                  Each path is checked to exist before scanning starts.
  --no-ext        Do not append extensions on any pass (filenames-only).
  --dry-run       Print the resolved targets, wordlists, settings and per-list
                  request estimates, then exit without scanning.
  -k, --insecure  Disable TLS cert validation (feroxbuster -k). Auto-enabled
                  for https:// targets.
  -a, --auto      Non-interactive: run all tiers without between-tier prompts,
                  and auto-enumerate discovered web ports.
  -H <header>     Extra HTTP header, e.g. -H 'Cookie: session=...'. Repeatable.
  --rate-limit <n>  Limit feroxbuster to n requests/sec (be gentle on fragile
                  targets).
  -h, --help      Show this help.

TARGETS may be bare IPs, host:port, or full URLs (bare -> http://).
MULTI-TARGET opens one tmux TAB per target in a single window (default).

ENV:
  USE_GUI_TERM=1  Opt in to GUI-terminal windows instead of tmux.

Authorized testing only.
EOF
    exit "${1:-1}"
}

# ============================================================================
#  Target helpers
# ============================================================================

# normalize_target: bare IP/host/host:port -> http://... ; full URLs pass through.
# Characters allowed in a target. Anything else is rejected, so a crafted line
# in a targets file (e.g. containing a quote, ';', '$(...)', backtick, space)
# cannot be smuggled into a launcher command. Covers IPs, hostnames, ports,
# paths, query strings and IPv6 brackets.  ']' and '[' lead the class; '-' is
# last so it is a literal, not a range.
TARGET_ALLOWED_RE='^[][A-Za-z0-9._:/%?=&~-]+$'
normalize_target() {
    local t="$1"; t="$(echo "$t" | xargs)"
    [[ -z "$t" ]] && { echo ""; return 1; }
    if [[ ! "$t" =~ $TARGET_ALLOWED_RE ]]; then
        err_msg "Rejected target (illegal characters): $t" >&2
        return 1
    fi
    if [[ "$t" =~ ^https?:// ]]; then echo "$t"; else echo "http://$t"; fi
}

# safe_name: filesystem-safe dir name from a URL (scheme stripped, :/ -> _).
safe_name() { echo "$1" | sed -E 's~^https?://~~; s~[/:]~_~g; s~_+~_~g; s~_+$~~'; }

# host_only: just the host/IP (nmap scans a host, not a URL).
host_only() {
    local h="${1#http://}"; h="${h#https://}"; h="${h%%/*}"; h="${h%%:*}"; echo "$h"
}

# scheme_of: http or https.
scheme_of() { [[ "$1" == https://* ]] && echo https || echo http; }

# port_of: explicit port from a URL, else the scheme default (80/443).
port_of() {
    local u="$1" hp="${1#*://}"; hp="${hp%%/*}"
    if [[ "$hp" == *:* ]]; then echo "${hp##*:}"
    else [[ "$u" == https://* ]] && echo 443 || echo 80; fi
}

# build_target_interactive: ask the user for service + port for a bare target.
# Full URLs are accepted verbatim. This is the "choose service and port for
# each target" flow -- the composed URL is exactly what feroxbuster will hit.
build_target_interactive() {
    local raw; raw="$(echo "$1" | xargs)"
    [[ -z "$raw" ]] && { echo ""; return 1; }
    if [[ "$raw" =~ ^https?:// ]]; then echo "$raw"; return 0; fi

    local svc=""
    while :; do
        read -rp "    Service for '$raw' [http/https] (default http): " svc
        svc="${svc:-http}"
        [[ "$svc" == http || "$svc" == https ]] && break
        warn_msg "    Please enter 'http' or 'https'."
    done

    if [[ "$raw" == *:* ]]; then
        # Port already supplied as host:port; keep it, just apply the scheme.
        echo "$svc://$raw"
    else
        local defport=80; [[ "$svc" == https ]] && defport=443
        local port=""
        read -rp "    Port for '$raw' (default $defport): " port
        port="${port:-$defport}"
        echo "$svc://$raw:$port"
    fi
}

# ============================================================================
#  Wordlist discovery
# ============================================================================
first_existing() { local c; for c in "$@"; do [[ -f "$c" ]] && { echo "$c"; return 0; }; done; return 1; }

resolve_wordlists() {
    TIER1_WORDLIST="$(first_existing "${TIER1_CANDIDATES[@]}")" || TIER1_WORDLIST=""
    TIER2_WORDLIST="$(first_existing "${TIER2_CANDIDATES[@]}")" || TIER2_WORDLIST=""
    TIER3_WORDLIST="$(first_existing "${TIER3_CANDIDATES[@]}")" || TIER3_WORDLIST=""
    TIER4_WORDLIST="$(first_existing "${TIER4_CANDIDATES[@]}")" || TIER4_WORDLIST=""
    TIER3_FILES_WORDLIST="$(first_existing "${TIER3_FILES_CANDIDATES[@]}")" || TIER3_FILES_WORDLIST=""
    TIER4_FILES_WORDLIST="$(first_existing "${TIER4_FILES_CANDIDATES[@]}")" || TIER4_FILES_WORDLIST=""
}

check_wordlists() {
    # Custom wordlists (-w, one or more) bypass the tier system entirely and
    # run in the given order. Validate EVERY path up front (fail-fast) so a
    # typo in list #3 doesn't surface 20 minutes into a scan.
    if [[ ${#CUSTOM_WORDLISTS[@]} -gt 0 ]]; then
        banner "Custom wordlists (tier cascade disabled), in order:"
        local wl missing=()
        for wl in "${CUSTOM_WORDLISTS[@]}"; do
            if [[ -f "$wl" && -r "$wl" ]]; then done_msg "  $wl"
            else err_msg "  MISSING or unreadable: $wl"; missing+=("$wl"); fi
        done
        if [[ ${#missing[@]} -gt 0 ]]; then
            err_msg "${#missing[@]} custom wordlist(s) not found -- fix the path(s) before continuing."
            exit 1
        fi
        echo; return
    fi
    resolve_wordlists
    local ok=1
    banner "Checking wordlist availability..."
    [[ -n "$TIER1_WORDLIST" ]] && done_msg "Tier 1: $TIER1_WORDLIST" \
        || { err_msg "Tier 1 (dirb common.txt) missing.  sudo apt install dirb"; ok=0; }
    [[ -n "$TIER2_WORDLIST" ]] && done_msg "Tier 2: $TIER2_WORDLIST" \
        || { err_msg "Tier 2 (dirb big.txt) missing.     sudo apt install dirb"; ok=0; }
    [[ -n "$TIER3_WORDLIST" ]] && done_msg "Tier 3: $TIER3_WORDLIST" \
        || warn_msg "Tier 3 (SecLists raft-medium-directories) not found. sudo apt install seclists"
    [[ -n "$TIER4_WORDLIST" ]] && done_msg "Tier 4: $TIER4_WORDLIST" \
        || warn_msg "Tier 4 (SecLists raft-large-directories) not found.  sudo apt install seclists"
    [[ -n "$TIER3_FILES_WORDLIST" ]] && done_msg "Tier 3 files pass: $TIER3_FILES_WORDLIST (no extensions)"
    [[ -n "$TIER4_FILES_WORDLIST" ]] && done_msg "Tier 4 files pass: $TIER4_FILES_WORDLIST (no extensions)"
    [[ $ok -eq 0 ]] && { err_msg "Required Tier 1/2 wordlists missing -- fix before continuing."; exit 1; }
    echo
}

# ============================================================================
#  Tool prerequisite check
# ============================================================================
# check_platform: Cataract relies on util-linux `script -qec "<cmd>"` to keep
# feroxbuster colorized while logging. That syntax is util-linux-specific and
# fails on macOS/BSD (whose `script` is `script [-q] file cmd ...`). Bail early
# with a clear message rather than failing cryptically mid-scan.
check_platform() {
    local os; os="$(uname -s 2>/dev/null || echo unknown)"
    if [[ "$os" != "Linux" ]]; then
        err_msg "Cataract is Linux-only (tested on Kali/Debian/Ubuntu). Detected: $os."
        err_msg "    It uses util-linux 'script -qec' for colorized logging, which is not"
        err_msg "    available on macOS/BSD. Please run it on a Linux host."
        exit 1
    fi
}

check_tools() {
    local missing=() t
    for t in nmap feroxbuster script; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        err_msg "Missing required tools: ${missing[*]}"
        echo    "    nmap        : sudo apt install nmap"
        echo    "    feroxbuster : sudo apt install feroxbuster   (or: cargo install feroxbuster)"
        echo    "    script      : sudo apt install bsdutils util-linux"
        exit 1
    fi
    command -v tmux >/dev/null 2>&1 || {
        warn_msg "tmux not found. Multi-target runs will be SEQUENTIAL."
        warn_msg "For one window with a tab per target: sudo apt install tmux"
    }
    command -v jq >/dev/null 2>&1 || \
        warn_msg "jq not found -- results will be parsed from logs instead of JSON. sudo apt install jq"
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        warn_msg "Not running as root: nmap will use a slower TCP connect scan (-sT) and"
        warn_msg "    skips the --min-rate speed-up. Run with sudo for a faster SYN scan."
    fi
}

# ============================================================================
#  Interactive mode
# ============================================================================
run_interactive() {
    echo -e "${C_CYAN}${C_BOLD}=== cataract.sh interactive mode ===${C_RESET}\n"
    read -rp "Output directory [./cataract_$(date +%Y%m%d_%H%M%S)]: " OUTDIR
    [[ -z "$OUTDIR" ]] && OUTDIR="./cataract_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUTDIR"; echo
    echo "Enter targets one per line (bare IP/host is fine)."
    echo "You'll be asked for the service (http/https) and port for each."
    echo "Blank line to finish."
    local raw url
    while true; do
        read -rp "Target: " raw
        [[ -z "$raw" ]] && break
        url="$(build_target_interactive "$raw")" && [[ -n "$url" ]] && TARGETS+=("$url")
    done
    [[ ${#TARGETS[@]} -eq 0 ]] && { err_msg "No targets entered."; exit 1; }

    # Optional: custom wordlists, in run order. Blank line keeps the tier cascade.
    echo
    echo "Custom wordlists: enter full paths one per line, in the order to run them."
    echo "Blank line = use the default tier cascade."
    local wlp
    while true; do
        read -rp "Wordlist path (blank to finish): " wlp
        [[ -z "$wlp" ]] && break
        wlp="$(echo "$wlp" | xargs)"      # trim
        wlp="${wlp/#\~/$HOME}"            # expand a leading ~
        if [[ -f "$wlp" && -r "$wlp" ]]; then CUSTOM_WORDLISTS+=("$wlp"); done_msg "  added: $wlp"
        else warn_msg "  not found/readable, skipped: $wlp"; fi
    done

    echo; done_msg "Output dir: $OUTDIR"; done_msg "Targets (${#TARGETS[@]}):"
    local t; for t in "${TARGETS[@]}"; do echo "    - $t"; done
    echo
    local c; read -rp "$(echo -e "${C_YELLOW}Proceed? [Y/n] ${C_RESET}")" c
    [[ "$c" =~ ^[Nn]$ ]] && { err_msg "Cancelled."; exit 1; }
    echo
}

# ============================================================================
#  Argument parsing
# ============================================================================
# Linux-only; exits early on macOS/BSD with a clear message. '-h/--help' is
# allowed through so usage is readable on any platform.
case "${1:-}" in -h|--help) ;; *) check_platform ;; esac

if [[ "${1:-}" == "--worker" ]]; then
    WORKER_MODE=1; WORKER_TARGET="${2:-}"; WORKER_DIR="${3:-}"; resolve_wordlists
elif [[ $# -eq 0 ]]; then
    check_tools; run_interactive; check_wordlists
else
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o) OUTDIR="${2:-}"; shift 2 ;;
            -f) TARGETS_FILE="${2:-}"; shift 2 ;;
            -t) THREADS="${2:-}"; shift 2 ;;
            -d) DEPTH="${2:-}"; shift 2 ;;
            -x) EXTENSIONS="${2:-}"; shift 2 ;;
            -w) CUSTOM_WORDLISTS+=("${2:-}"); shift 2 ;;
            --no-ext) NO_EXT=1; shift ;;
            --dry-run) DRY_RUN=1; shift ;;
            -k|--insecure) INSECURE=1; shift ;;
            -a|--auto) AUTO=1; shift ;;
            -H) HEADERS+=("${2:-}"); shift 2 ;;
            --rate-limit) RATE_LIMIT="${2:-}"; shift 2 ;;
            -h|--help) usage 0 ;;
            --) shift; break ;;
            -*) err_msg "Unknown option: $1"; usage ;;
            *)  norm="$(normalize_target "$1")" && [[ -n "$norm" ]] && TARGETS+=("$norm"); shift ;;
        esac
    done
    while [[ $# -gt 0 ]]; do
        norm="$(normalize_target "$1")" && [[ -n "$norm" ]] && TARGETS+=("$norm"); shift
    done

    [[ -z "$OUTDIR" ]] && { err_msg "Output directory (-o) is required in non-interactive mode."; usage; }
    if [[ -n "$TARGETS_FILE" ]]; then
        [[ -f "$TARGETS_FILE" ]] || { err_msg "Targets file not found: $TARGETS_FILE"; exit 1; }
        while IFS= read -r line || [[ -n "$line" ]]; do
            [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
            norm="$(normalize_target "$line")" && [[ -n "$norm" ]] && TARGETS+=("$norm")
        done < "$TARGETS_FILE"
    fi
    [[ ${#TARGETS[@]} -eq 0 ]] && { err_msg "No targets provided."; usage; }
    mkdir -p "$OUTDIR"
    # --dry-run previews the plan without scanning, so the scanning tools are
    # not required; wordlists are still validated so the preview is honest.
    [[ "$DRY_RUN" == "1" ]] || check_tools
    check_wordlists
fi

# ============================================================================
#  feroxbuster invocation
# ============================================================================
# ferox_run: one feroxbuster pass, colorized on screen AND logged, plus a JSON
# artifact for robust parsing.
#
# Why `script -qec "<cmd>" /dev/null | tee <log>` ?
#   feroxbuster only emits ANSI colors to a TTY. `script` allocates a PTY so
#   ferox stays colorized; we `tee` that into the log. `-q` quiets script,
#   `-e` returns the child's exit code, `-c` runs the command string.
# Why build the command with `printf '%q'` ?
#   `script -c` takes a SINGLE command string. We assemble the argv as a bash
#   array (so optional flags/headers are added cleanly and quoting is correct)
#   and then shell-quote it with printf '%q' into that one string -- this keeps
#   header values with spaces/quotes intact.
# Why `--json --output <file>` ?
#   feroxbuster writes JSON to --output (NOT to stdout), so the live colored
#   view is preserved while we get machine-parseable results in the file.
# print_estimate: rough base-request count for a tier =
#   wordlist lines x (1 + number of extensions), or x1 when run without exts.
# It is a BASE figure: feroxbuster recursion re-runs the list under every
# discovered directory, so the real total grows with each directory found.
print_estimate() {
    local wordlist="$1" no_ext="$2" lines ext_count mult est
    # Global --no-ext (NO_EXT=1) disables extensions for every pass.
    [[ "${NO_EXT:-0}" == "1" ]] && no_ext=1
    lines="$(wc -l < "$wordlist" 2>/dev/null | tr -d ' ')"
    [[ -z "$lines" || "$lines" -eq 0 ]] && return 0
    if [[ "$no_ext" == "1" ]]; then
        est=$(( lines ))
        warn_msg "[est] ~$est base requests ($lines words, no extensions); recursion multiplies this per discovered directory."
    else
        # Count non-empty comma-separated extensions (0 if EXTENSIONS is empty).
        ext_count="$(awk -F, '{c=0; for(i=1;i<=NF;i++) if(length($i)) c++; print c}' <<< "$EXTENSIONS")"
        mult=$(( 1 + ext_count ))
        est=$(( lines * mult ))
        warn_msg "[est] ~$est base requests ($lines words x (1 + $ext_count exts)); recursion multiplies this per discovered directory."
    fi
}

# The optional 6th arg (no_ext=1) runs the pass WITHOUT --extensions; used for
# the raft *files* lists, whose words already include their own extensions.
ferox_run() {
    local url="$1" log="$2" json="$3" wordlist="$4" label="$5" no_ext="${6:-0}"
    # Global --no-ext (NO_EXT=1) forces every pass to skip --extensions.
    [[ "${NO_EXT:-0}" == "1" ]] && no_ext=1
    banner "[$url] $label - $wordlist"
    print_estimate "$wordlist" "$no_ext"

    local -a a=( feroxbuster
        --url "$url"
        --wordlist "$wordlist"
        --threads "$THREADS"
        --depth "$DEPTH"
    )
    [[ "$no_ext" != "1" ]] && a+=( --extensions "$EXTENSIONS" )
    a+=( --json --output "$json" )
    # Self-signed / lab TLS: -k for https targets or when forced with -k/--insecure.
    [[ "$url" == https://* || "$INSECURE" == "1" ]] && a+=( -k )
    # Optional rate limiting.
    [[ "${RATE_LIMIT:-0}" != "0" ]] && a+=( --rate-limit "$RATE_LIMIT" )
    # Optional extra headers (auth cookies, custom UA, etc.). The ${arr[@]+...}
    # guard keeps `set -u` happy when HEADERS is empty.
    local h; for h in ${HEADERS[@]+"${HEADERS[@]}"}; do a+=( -H "$h" ); done

    local cmd; printf -v cmd '%q ' "${a[@]}"
    script -qec "$cmd" /dev/null | tee "$log"
    done_msg "[$url] $label done. Log: $log"
}

# dedup_dir: build <dir>/results.txt from that dir's JSON (preferred) or, if
# jq/JSON is unavailable, from the ANSI-stripped tier logs.
dedup_dir() {
    local dir="$1" out="$1/results.txt"
    : > "$out"
    if command -v jq >/dev/null 2>&1 && compgen -G "$dir/*.json" >/dev/null 2>&1; then
        # Each JSON line is an event; keep response events as: status <TAB> len <TAB> url.
        # -R + fromjson? reads line-by-line and skips any malformed line, so a
        # truncated final line from an interrupted scan still parses cleanly.
        cat "$dir"/*.json 2>/dev/null \
            | jq -rR 'fromjson? | select(.type=="response") | [.status, .content_length, .url] | @tsv' 2>/dev/null \
            | sort -u > "$out"
    fi
    if [[ ! -s "$out" ]]; then
        cat "$dir"/*.log 2>/dev/null \
            | sed -E 's/\x1B\[[0-9;]*[mGKHF]//g' \
            | grep -E '^[[:space:]]*[0-9]{3}[[:space:]]' \
            | sort -u > "$out"
    fi
}

# prompt_continue: y/N gate between tiers/ports. In --auto mode always yes.
prompt_continue() {
    local label="$1"
    [[ "$AUTO" == "1" ]] && { banner "[auto] continuing: $label"; return 0; }
    local ans; read -rp "$(echo -e "${C_YELLOW}Continue to $label? [y/N] ${C_RESET}")" ans
    [[ "$ans" =~ ^[Yy]$ ]]
}

# ============================================================================
#  Tier cascade
# ============================================================================
# run_cascade <url> <dir> <max_tier>
#   Runs feroxbuster tiers into <dir>, gated by prompts (or auto), up to
#   <max_tier> (1-4). A custom wordlist (-w) collapses this to a single pass.
run_cascade() {
    local url="$1" dir="$2" max_tier="${3:-4}"
    mkdir -p "$dir"

    # Custom wordlists replace the tier cascade and run in insertion order.
    if [[ ${#CUSTOM_WORDLISTS[@]} -gt 0 ]]; then
        local i wl count=${#CUSTOM_WORDLISTS[@]}
        # On discovered extra ports (max_tier < 4) run only the first list to
        # keep those secondary scans light.
        [[ $max_tier -lt 4 ]] && count=1
        for (( i=0; i<count; i++ )); do
            wl="${CUSTOM_WORDLISTS[$i]}"
            # Prompt between lists (not before the first); --auto skips prompts.
            if [[ $i -gt 0 ]] && ! prompt_continue "custom wordlist $((i+1)) ($(basename "$wl"))"; then break; fi
            ferox_run "$url" "$dir/custom$((i+1)).log" "$dir/custom$((i+1)).json" \
                "$wl" "CUSTOM $((i+1)) ($(basename "$wl"))"
        done
        dedup_dir "$dir"; return
    fi

    ferox_run "$url" "$dir/tier1.log" "$dir/tier1.json" "$TIER1_WORDLIST" "TIER 1 (dirb common)"

    if [[ $max_tier -ge 2 ]] && prompt_continue "TIER 2 (dirb big.txt)"; then
        ferox_run "$url" "$dir/tier2.log" "$dir/tier2.json" "$TIER2_WORDLIST" "TIER 2 (dirb big)"

        if [[ $max_tier -ge 3 ]] && prompt_continue "TIER 3 (SecLists raft-medium)"; then
            if [[ -z "$TIER3_WORDLIST" ]]; then
                err_msg "Tier 3 wordlist missing -- skipping. (sudo apt install seclists)"
            else
                ferox_run "$url" "$dir/tier3.log" "$dir/tier3.json" "$TIER3_WORDLIST" "TIER 3 (raft-medium dirs)"
                # Optional filename pass (no extensions) using the raft files list.
                [[ -n "$TIER3_FILES_WORDLIST" ]] && \
                    ferox_run "$url" "$dir/tier3_files.log" "$dir/tier3_files.json" \
                        "$TIER3_FILES_WORDLIST" "TIER 3 files (raft-medium, no ext)" 1

                if [[ $max_tier -ge 4 ]] && prompt_continue "TIER 4 (SecLists raft-large)"; then
                    if [[ -z "$TIER4_WORDLIST" ]]; then
                        err_msg "Tier 4 wordlist missing -- skipping. (sudo apt install seclists)"
                    else
                        ferox_run "$url" "$dir/tier4.log" "$dir/tier4.json" "$TIER4_WORDLIST" "TIER 4 (raft-large dirs)"
                        [[ -n "$TIER4_FILES_WORDLIST" ]] && \
                            ferox_run "$url" "$dir/tier4_files.log" "$dir/tier4_files.json" \
                                "$TIER4_FILES_WORDLIST" "TIER 4 files (raft-large, no ext)" 1
                    fi
                fi
            fi
        fi
    fi
    dedup_dir "$dir"
}

# discover_web_ports: parse nmap -oN output for open http/https services and
# echo scheme://host:port for each, EXCLUDING the port we already scanned.
# nmap labels vary ("http", "http-proxy", "http-alt", "ssl/http", "https"),
# so we classify https first (its string contains "http") then plain http.
discover_web_ports() {
    local nmap_txt="$1" host="$2" primary_port="$3"
    [[ -f "$nmap_txt" ]] || return 0
    local line port
    while read -r line; do
        port="${line%%/*}"
        [[ "$port" == "$primary_port" ]] && continue
        if echo "$line" | grep -qiE 'ssl/https|(^| )https|ssl/http'; then
            echo "https://$host:$port"
        elif echo "$line" | grep -qiE 'http'; then
            echo "http://$host:$port"
        fi
    done < <(grep -E '^[0-9]+/tcp[[:space:]]+open' "$nmap_txt")
}

# write_summary: a readable per-target summary.md (open ports + notable hits).
write_summary() {
    local target="$1" tdir="$2" nmap_txt="$3" s="$2/summary.md"
    {
        echo "# Cataract summary -- $target"
        echo
        echo "_Generated: $(date)_"
        echo
        echo "## Open ports (nmap)"
        echo '```'
        grep -E '^[0-9]+/tcp[[:space:]]+open' "$nmap_txt" 2>/dev/null || echo "(no nmap results)"
        echo '```'
        echo
        echo "## Content discovery"
        local combined="$tdir/all_unique_results.txt"
        if [[ -s "$combined" ]]; then
            echo "Total unique responses: $(wc -l < "$combined")"
            echo
            echo "### Notable (2xx / 401 / 403)"
            echo '```'
            grep -E '^[[:space:]]*(2[0-9]{2}|401|403)([[:space:]]|$)' "$combined" | head -60
            echo '```'
        else
            echo "No content-discovery hits recorded."
        fi
    } > "$s"
    done_msg "[$target] Summary: $s"
}

# host_nmap_path: deterministic shared nmap output path for a host, so every
# target/worker for that host reads the same file.
host_nmap_path() {
    local host="$1" nmap_dir="$2" hsafe
    hsafe="$(printf '%s' "$host" | sed 's/[^A-Za-z0-9._-]/_/g')"
    printf '%s/%s.txt' "$nmap_dir" "$hsafe"
}

# ensure_host_nmap: run ONE full-port nmap per unique host, shared across all
# targets/workers for that host. A flock on <host>.lock serializes it: the
# first caller runs the scan while any concurrent tmux workers block on the
# lock, then see the <host>.done marker and reuse the result instead of
# launching a second -p- scan. (If flock is unavailable, falls back to a
# best-effort .done check.)
ensure_host_nmap() {
    local host="$1" nmap_dir="$2" hsafe
    hsafe="$(printf '%s' "$host" | sed 's/[^A-Za-z0-9._-]/_/g')"
    local txt="$nmap_dir/$hsafe.txt" log="$nmap_dir/$hsafe.log"
    local lock="$nmap_dir/$hsafe.lock" marker="$nmap_dir/$hsafe.done"
    mkdir -p "$nmap_dir"
    if command -v flock >/dev/null 2>&1; then
        (
            flock 9
            if [[ ! -f "$marker" ]]; then
                # shellcheck disable=SC2086  # NMAP_OPTS is intentionally word-split
                nmap $NMAP_OPTS "$host" -oN "$txt" > "$log" 2>&1
                touch "$marker"
            fi
        ) 9>"$lock"
    elif [[ ! -f "$marker" ]]; then
        # shellcheck disable=SC2086  # NMAP_OPTS is intentionally word-split
        nmap $NMAP_OPTS "$host" -oN "$txt" > "$log" 2>&1
        touch "$marker"
    fi
}

# finalize_target: de-duplicate every result dir for a target (primary + any
# port_* subdirs), aggregate into all_unique_results.txt, and write summary.md.
# Safe to call mid-scan from the interrupt handler -- dedup_dir tolerates the
# partial JSON/logs left behind when a scan is cut short.
finalize_target() {
    local target="$1" tdir="$2" nmap_txt="$3" p
    dedup_dir "$tdir"
    for p in "$tdir"/port_*/; do [[ -d "$p" ]] && dedup_dir "$p"; done
    cat "$tdir/results.txt" "$tdir"/port_*/results.txt 2>/dev/null | sort -u > "$tdir/all_unique_results.txt"
    write_summary "$target" "$tdir" "$nmap_txt"
}

# ============================================================================
#  Per-target orchestration
# ============================================================================
run_target() {
    local TARGET="$1" TDIR="$2"
    mkdir -p "$TDIR"
    local HOST; HOST="$(host_only "$TARGET")"
    local PPORT; PPORT="$(port_of "$TARGET")"
    # Record for the interrupt handler so a stop still saves this target.
    CURRENT_TARGET="$TARGET"; CURRENT_TDIR="$TDIR"; CURRENT_OUTDIR="$(dirname "$TDIR")"

    banner "[$TARGET] Starting enumeration. Output: $TDIR"
    banner "[$TARGET] Press ENTER during a feroxbuster tier to pause/cancel it."

    # Background: full-port service/script scan, shared per host (scan-once).
    # The shared dir lives alongside the per-target dirs, so tmux workers for
    # the same host share one scan via the flock inside ensure_host_nmap.
    local NMAP_DIR; NMAP_DIR="$(dirname "$TDIR")/_nmap"; mkdir -p "$NMAP_DIR"
    local FULLSCAN_OUT; FULLSCAN_OUT="$(host_nmap_path "$HOST" "$NMAP_DIR")"
    CURRENT_NMAP_TXT="$FULLSCAN_OUT"
    banner "[$TARGET] Full-port nmap for $HOST (shared, scan-once) -> $FULLSCAN_OUT"
    ensure_host_nmap "$HOST" "$NMAP_DIR" &
    local FULLSCAN_PID=$!; BG_PIDS+=("$FULLSCAN_PID")

    # Foreground: tier cascade against the chosen service/port.
    run_cascade "$TARGET" "$TDIR" 4

    if kill -0 "$FULLSCAN_PID" 2>/dev/null; then
        banner "[$TARGET] Waiting for the full-port scan to finish..."; wait "$FULLSCAN_PID"
    fi
    done_msg "[$TARGET] Full-port scan complete: $FULLSCAN_OUT"

    # Discover extra web ports from nmap and (auto or on prompt) enumerate them.
    local extra=() e p
    mapfile -t extra < <(discover_web_ports "$FULLSCAN_OUT" "$HOST" "$PPORT")
    if [[ ${#extra[@]} -gt 0 ]]; then
        banner "[$TARGET] Extra web services found by nmap:"
        for e in "${extra[@]}"; do echo "      - $e"; done
        for e in "${extra[@]}"; do
            if prompt_continue "enumerate discovered service $e"; then
                p="$(port_of "$e")"
                run_cascade "$e" "$TDIR/port_$p" "$EXTRA_PORT_MAX_TIER"
            fi
        done
    fi

    # Aggregate + summarize (the same routine the interrupt handler uses).
    finalize_target "$TARGET" "$TDIR" "$FULLSCAN_OUT"
    done_msg "[$TARGET] Combined results: $TDIR/all_unique_results.txt"
    done_msg "[$TARGET] ALL DONE. Everything is in $TDIR"
}

# build_index: (re)write <out>/index.md linking every target's summary.md.
# Called by the single/sequential paths AND by each tmux/GUI worker when it
# finishes, so the index is always current. A flock on <out>/.index.lock keeps
# concurrent workers from clobbering each other's write (the whole generate +
# write runs inside the locked subshell). Falls back to an unlocked write if
# flock is unavailable.
build_index() {
    local out="${1:-$OUTDIR}" idx lock
    idx="$out/index.md"; lock="$out/.index.lock"
    (
        command -v flock >/dev/null 2>&1 && flock 9
        {
            echo "# Cataract run index"
            echo
            echo "_Generated: $(date)_"
            echo
            local d name
            for d in "$out"/*/; do
                [[ -f "${d}summary.md" ]] || continue
                name="$(basename "$d")"
                [[ "$name" == "_nmap" ]] && continue
                echo "- [$name](${name}/summary.md)"
            done
        } > "$idx"
    ) 9>"$lock"
    done_msg "Run index: $idx"
}

# do_dry_run: print the plan (targets, settings, wordlists + per-list request
# estimates) and return. Invoked from the launch section when --dry-run is set;
# no scanning happens. print_estimate honors the global NO_EXT internally.
do_dry_run() {
    banner "DRY RUN -- nothing will be scanned."
    echo "  Output dir : $OUTDIR"
    echo "  Targets (${#TARGETS[@]}):"
    local t; for t in "${TARGETS[@]}"; do echo "      - $t"; done
    echo "  Settings   : threads=$THREADS depth=$DEPTH exts=[$EXTENSIONS] no_ext=$NO_EXT auto=$AUTO insecure=$INSECURE rate_limit=$RATE_LIMIT"
    if [[ ${#HEADERS[@]} -gt 0 ]]; then
        echo "  Headers    :"; local h; for h in "${HEADERS[@]}"; do echo "      -H $h"; done
    fi
    echo
    if [[ ${#CUSTOM_WORDLISTS[@]} -gt 0 ]]; then
        banner "Planned wordlists (custom, in order):"
        local i wl
        for i in "${!CUSTOM_WORDLISTS[@]}"; do
            wl="${CUSTOM_WORDLISTS[$i]}"
            echo "  [$((i+1))] $wl"
            print_estimate "$wl" 0
        done
    else
        banner "Planned wordlists (tier cascade):"
        local row name wl nx
        for row in "TIER1|$TIER1_WORDLIST|0" "TIER2|$TIER2_WORDLIST|0" \
                   "TIER3|$TIER3_WORDLIST|0" "TIER3-files|$TIER3_FILES_WORDLIST|1" \
                   "TIER4|$TIER4_WORDLIST|0" "TIER4-files|$TIER4_FILES_WORDLIST|1"; do
            IFS='|' read -r name wl nx <<< "$row"
            [[ -z "$wl" ]] && continue
            echo "  $name: $wl"
            print_estimate "$wl" "$nx"
        done
    fi
    echo
    warn_msg "Dry run complete -- re-run without --dry-run to scan."
}

# ============================================================================
#  Worker mode (one target inside a tmux tab / GUI window)
# ============================================================================
if [[ $WORKER_MODE -eq 1 ]]; then
    if [[ -n "${TMUX:-}" ]]; then
        echo -e "${C_CYAN}${C_BOLD}[tmux]${C_RESET} Switch tabs: Ctrl+b n/p or Ctrl+b <number>  |  Detach: Ctrl+b d  |  Pause tier: ENTER"
    fi
    run_target "$WORKER_TARGET" "$WORKER_DIR"
    # Rebuild the shared index.md (OUTDIR is the parent of this worker's dir).
    build_index "$(dirname "$WORKER_DIR")"
    echo -e "${C_GREEN}Press Enter to close this tab...${C_RESET}"; read -r
    exit 0
fi

SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

# Propagate flag-set settings into worker tabs (they are separate bash procs).
export_settings() {
    export THREADS DEPTH EXTENSIONS NMAP_OPTS RATE_LIMIT INSECURE AUTO \
           NO_EXT USE_GUI_TERM EXTRA_PORT_MAX_TIER
    # Declare then assign separately (SC2155): keep printf's exit status visible.
    local hdrs=""
    [[ ${#HEADERS[@]} -gt 0 ]] && hdrs="$(printf '%s\n' "${HEADERS[@]}")"
    [[ -n "$hdrs" ]] && export CATARACT_HEADERS="$hdrs"
    local cwl=""
    [[ ${#CUSTOM_WORDLISTS[@]} -gt 0 ]] && cwl="$(printf '%s\n' "${CUSTOM_WORDLISTS[@]}")"
    [[ -n "$cwl" ]] && export CATARACT_CUSTOM_WORDLISTS="$cwl"
}

# worker_cmd: build a safely-quoted "bash <script> --worker <target> <dir>"
# command string for `tmux` / `sh -c`. printf '%q' escapes every argument, so a
# single quote or any odd character in a target or output path can neither
# break the command nor inject shell (the same approach ferox_run uses).
worker_cmd() {
    local c
    printf -v c '%q ' bash "$SCRIPT_PATH" --worker "$1" "$2"
    printf '%s' "$c"
}

# --dry-run: show the plan and stop before any scanning (all functions are now
# defined, so the estimates are available).
if [[ "$DRY_RUN" == "1" ]]; then
    do_dry_run
    exit 0
fi

# ============================================================================
#  Single target: run right here (no tmux needed)
# ============================================================================
if [[ ${#TARGETS[@]} -eq 1 ]]; then
    run_target "${TARGETS[0]}" "$OUTDIR/$(safe_name "${TARGETS[0]}")"
    build_index "$OUTDIR"
    exit 0
fi

# ============================================================================
#  Multiple targets -- launchers
# ============================================================================

# launch_tmux (DEFAULT): one session, one TAB (window) per target. All styling
# is session-scoped (set-option -t "$S"); the user's ~/.tmux.conf is untouched.
launch_tmux() {
    export_settings
    local S="cataract_$$"
    banner "Launching tmux session '$S' -- one tab per target (${#TARGETS[@]})."

    local first_name; first_name="$(safe_name "${TARGETS[0]}")"
    local first_dir; first_dir="$OUTDIR/$(safe_name "${TARGETS[0]}")"
    local first_cmd; first_cmd="$(worker_cmd "${TARGETS[0]}" "$first_dir")"
    tmux new-session -d -s "$S" -n "$first_name" "$first_cmd"

    tmux set-option -t "$S" base-index 1 \; set-window-option -t "$S" pane-base-index 1 \
        \; set-option -t "$S" renumber-windows on

    local i T name tdir wcmd
    for (( i=1; i<${#TARGETS[@]}; i++ )); do
        T="${TARGETS[$i]}"; name="$(safe_name "$T")"; tdir="$OUTDIR/$(safe_name "$T")"
        wcmd="$(worker_cmd "$T" "$tdir")"
        tmux new-window -t "$S" -n "$name" "$wcmd"
    done
    tmux move-window -r -t "$S"

    # --- Tab-bar styling (session-scoped only) ------------------------------
    tmux set-option -t "$S" mouse on
    tmux set-option -t "$S" status on
    tmux set-option -t "$S" status-position top
    tmux set-option -t "$S" status-justify left
    tmux set-option -t "$S" status-interval 5
    tmux set-option -t "$S" status-style "bg=colour236,fg=colour250"
    tmux set-option -t "$S" status-left "#[bg=colour33,fg=colour231,bold] CATARACT #[bg=colour236] "
    tmux set-option -t "$S" status-left-length 40
    tmux set-option -t "$S" status-right "#[fg=colour45]Ctrl+b n/p or 1-9: switch  #[fg=colour250]| #[fg=colour45]Ctrl+b d: detach "
    tmux set-option -t "$S" status-right-length 80
    tmux set-window-option -t "$S" window-status-format " #I:#W "
    tmux set-window-option -t "$S" window-status-current-format "#[bg=colour33,fg=colour231,bold] #I:#W #[default]"
    tmux set-window-option -t "$S" window-status-separator ""

    echo; done_msg "tmux session '$S' is ready."
    echo    "    Switch tabs : Ctrl+b then n/p, or Ctrl+b then a number (1-${#TARGETS[@]})"
    echo    "    Detach      : Ctrl+b then d      (scans keep running)"
    echo    "    Reattach    : tmux attach -t $S"
    echo    "    Kill it all : tmux kill-session -t $S"
    echo    "    Per-target summary.md is written in each target's output dir."
    echo; banner "Attaching now..."; sleep 1

    if [[ -n "${TMUX:-}" ]]; then tmux switch-client -t "$S"; else tmux attach-session -t "$S"; fi
}

# launch_gui (OPT-IN, USE_GUI_TERM=1): one GUI terminal window per target.
launch_gui() {
    export_settings
    warn_msg "USE_GUI_TERM=1: opening one GUI terminal WINDOW per target (opt-in)."
    warn_msg "This does NOT give a single tabbed window. Unset USE_GUI_TERM for tmux."
    local term="" T name tdir cmd
    for term in x-terminal-emulator gnome-terminal xfce4-terminal konsole xterm; do
        command -v "$term" >/dev/null 2>&1 && break || term=""
    done
    [[ -z "$term" ]] && { err_msg "No supported GUI terminal found. Unset USE_GUI_TERM to use tmux."; return 1; }
    for T in "${TARGETS[@]}"; do
        name="$(safe_name "$T")"; tdir="$OUTDIR/$name"
        cmd="$(worker_cmd "$T" "$tdir"); exec bash"
        case "$term" in
            gnome-terminal|xfce4-terminal) "$term" --title="$T" -- bash -c "$cmd" & ;;
            konsole)                        "$term" -p tabtitle="$T" -e bash -c "$cmd" & ;;
            *)                              "$term" -T "$T" -e bash -c "$cmd" & ;;
        esac
        sleep 0.2
    done
    done_msg "Launched ${#TARGETS[@]} GUI windows (one per target)."
}

# launch_sequential (last resort): run targets one after another, here.
launch_sequential() {
    warn_msg "Running ${#TARGETS[@]} targets SEQUENTIALLY in this terminal."
    warn_msg "For one window with a tab per target: sudo apt install tmux"
    local T
    for T in "${TARGETS[@]}"; do run_target "$T" "$OUTDIR/$(safe_name "$T")"; done
    build_index "$OUTDIR"
}

# --- Launcher selection ------------------------------------------------------
if [[ "$USE_GUI_TERM" == "1" ]]; then
    launch_gui || launch_sequential
elif command -v tmux >/dev/null 2>&1; then
    launch_tmux
else
    launch_sequential
fi
