# Changelog

All notable changes to Cataract are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Versions before **7.0.0** were private development iterations and are not published here.

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

[7.1.0]: https://github.com/YusufAlMahmeed/cataract/releases/tag/v7.1.0
[7.0.0]: https://github.com/YusufAlMahmeed/cataract/releases/tag/v7.0.0
