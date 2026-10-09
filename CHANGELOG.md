# Changelog

All notable changes to Cataract are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Versions before **7.0.0** were private development iterations and are not published here.

## [7.2.0] - 2026-10-09

### Added
- **Scan-first vs known-service flow** — a **bare host/IP** is now scanned first and whatever
  serves http/https (on any port) is enumerated, instead of guessing port 80. A **full URL** or
  **host:port** is treated as a known service and enumerated as-is (its port scan runs in the
  background). Interactive mode asks, per bare host, whether you already know the service(s)/
  port(s); if yes you supply one or more, if no it scans first. Fixes the old illogical prompt
  that asked for service/port before any scan.
- **Two-phase scan** — a fast all-ports sweep finds every open port, then a deep `nmap -sV -sC`
  scan (`NMAP_DEEP_OPTS`) runs on just those ports. Both outputs are kept (`<host>_fast.txt`
  and `<host>_deep.txt`). This runs **before** web enumeration, so the open ports and the web
  services found (even on non-standard ports) are shown first and enumerated — not just the
  port you guessed.
- **Pluggable fast engine** (`FAST_SCANNER`) — phase 1 defaults to **nmap** for accuracy;
  **RustScan** (`FAST_SCANNER=rustscan`, or `auto` = rustscan-if-installed) is much faster but
  can under-report ports on high-latency/rate-limited links, so it's best on low-latency
  lab/internal networks. Whichever engine finds the ports, **phase 2 always re-scans them with
  `nmap -sV -sC`**, so service identification is nmap-accurate regardless.
- **Multiple custom wordlists** — `-w` is now repeatable and the lists run in the order
  given, replacing the tier cascade. Interactive mode prompts for the paths too. Every path
  is validated **before any scanning starts** (fail-fast, listing any that are missing).
- **`--no-ext`** — don't append `--extensions` on any pass (filenames-only).
- **`--udp` / `UDP_SCAN=1`** — optional top-100 UDP scan (`nmap -sU --top-ports 100 -sV`), off by
  default. It runs in the background during web enumeration (UDP is slow), is shared per host,
  needs root, and its open ports are added to `summary.md` and saved to `_nmap/<host>_udp.txt`.
- **`--dry-run`** — print the resolved targets, settings, planned wordlists and each list's
  base request estimate, then exit without scanning. Skips the scanning-tool check but still
  validates wordlists, so the preview is honest and catches typos early.
- **Save-on-stop** — stopping the tool (Ctrl+C, closing a tab, or `tmux kill-session`) now
  saves whatever the in-progress target has found so far: a de-duplicated `results.txt`,
  `all_unique_results.txt`, `summary.md`, and a refreshed `index.md`.

### Changed
- **nmap shows live progress** — its output is streamed to the screen (and logged) with
  `--stats-every` (default 15s, `NMAP_STATS_INTERVAL`), plus clear phase banners, so a long
  all-ports sweep visibly reports `% done` / ETC instead of sitting silently.
- **Web-enumeration result files are named after the wordlist** (e.g. `common.log` /
  `common.json`, `raft-medium-directories.json`) instead of `tierN` / `customN`.
- nmap runs up front (two-phase) rather than in the background during the first cascade, so
  web enumeration can target the ports that actually serve http/https.
- Result de-duplication parses JSON tolerantly (`jq -R 'fromjson?'`), so a truncated file
  left by a cut-short scan still yields every complete hit.
- `NMAP_OPTS` is replaced by `NMAP_FAST_OPTS` + `NMAP_DEEP_OPTS`.

### Fixed
- The "scan each host once" marker is now **per-run** (`CATARACT_RUN_ID`), so re-running into
  the same output directory rescans with the current engine instead of silently reusing a
  previous run's output (which could make a freshly installed RustScan appear unused).
- Scan banner is engine-accurate (no longer always says "nmap"), the tool now says when it
  reuses a scan, and RustScan falls back to the nmap sweep if it returns no ports or errors.
- RustScan now actually finds ports: dropped the `--tries` default flag (unsupported on some
  RustScan versions, which made the call error out and fall back to nmap), and the port parser
  handles both RustScan output formats (greppable `[22,80]` and plain `Open ip:port`).
- The "Open ports" line (and the stray "no open ports" warning) now reads the deep nmap file,
  which is always nmap format, instead of mis-parsing RustScan's fast-file format.

## [7.1.0] - 2026-10-02

### Changed
- **Tiers 3/4 use the SecLists raft _directories_ lists** (`raft-medium-directories.txt`,
  `raft-large-directories.txt`) instead of the files lists. The files lists already
  contain extensions, so appending the extension set produced waste like `index.php.php`
  and missed the directories that recursion depends on.
- **Default recursion depth lowered from 3 to 2** — fewer, faster requests by default;
  raise it with `-d` when you need to go deeper.
- **nmap defaults are root-aware** — as root, `--min-rate 1000` is added for a faster SYN
  scan; an explicit `NMAP_OPTS` is always respected.

### Added
- **Optional no-extension filename pass** for tiers 3/4 using the matching
  `raft-*-files.txt` list, so real filenames are still covered.
- **Estimated request count** printed before each tier (`wordlist lines x (1 + extensions)`),
  with a note that recursion multiplies it per discovered directory.
- **Non-root warning** that nmap will fall back to a slower TCP connect scan.
- **`index.md` is rebuilt by every worker** when it finishes (flock-guarded), so multi-target
  tmux/GUI runs always get a current combined index — not just single/sequential runs.
- **Platform guard** — Cataract now detects non-Linux hosts at startup and exits with a clear
  message (the `script -qec` logging is util-linux-specific). `-h/--help` still works anywhere.
- **ShellCheck CI** (GitHub Actions) running `shellcheck -S warning cataract.sh` on push and
  pull request, plus ShellCheck and MIT badges in the README.

### Security
- **Launcher command injection hardened** — the tmux/GUI worker commands are now built with
  `printf '%q'`, so a target or output path containing a single quote can no longer break
  the command or inject shell.
- **Target input validation** — `normalize_target` rejects any target containing characters
  outside `[A-Za-z0-9._:/%?=&~[]-]`, closing off injection from a crafted targets file.

### Fixed
- **Duplicate nmap scans eliminated** — each unique host is now scanned once into
  `<output_dir>/_nmap/<host>.txt` behind a per-host `flock`, and every target/worker for that
  host reuses the result.
- **ShellCheck SC2155 warnings** resolved (declare and assign separately); the script passes
  `shellcheck -S warning` cleanly.

## [7.0.0] - 2026-09-29

First public release.

### Added
- Tiered, recursive `feroxbuster` cascade (dirb `common`/`big`, SecLists raft) with a
  *continue?* prompt between tiers, or `--auto` to run every tier unattended.
- Per-target **service/port selection** in interactive mode — pick `http`/`https` and the
  port for each target; feroxbuster hits that exact URL.
- Full-port `nmap` scan running in parallel per target, with discovered extra web ports
  offered for enumeration.
- **One tmux window with a tab per target** (session-scoped styling only; `~/.tmux.conf`
  untouched); GUI terminals available as an opt-in.
- Colorized live output preserved via util-linux `script`, plus JSON output for `jq`-based
  de-duplication, a per-target `summary.md`, and a combined `index.md`.
- CLI flags: `-o`, `-f`, `-t`, `-d`, `-x`, `-w`, `-k`, `-a`, `-H`, `--rate-limit`.
- `-k` auto-enabled for `https://` targets; clean Ctrl+C handling that kills background scans;
  upfront tool/wordlist checks with install hints; graceful fallbacks when tmux/jq are absent.

[7.2.0]: https://github.com/YusufAlMahmeed/cataract/releases/tag/v7.2.0
[7.1.0]: https://github.com/YusufAlMahmeed/cataract/releases/tag/v7.1.0
[7.0.0]: https://github.com/YusufAlMahmeed/cataract/releases/tag/v7.0.0
