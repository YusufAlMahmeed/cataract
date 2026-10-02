# Cataract v7.1.0

Correctness, safety and polish release. Draft notes for the GitHub release of
tag `v7.1.0` — not yet published.

## Highlights

- **Better results out of the box.** Tiers 3/4 now use the SecLists raft
  **directories** lists, so your extensions are appended correctly (no more
  `index.php.php`) and recursion has directories to descend into. The matching
  raft **files** lists run as an extra pass **without** `--extensions`, so
  filenames are still covered.
- **Faster, safer defaults.** Recursion depth now defaults to **2** (raise with
  `-d`). As root, nmap gets `--min-rate 1000`; as non-root you're warned that
  nmap falls back to a slower connect scan.
- **Hardened against injection.** Worker commands for tmux/GUI tabs are built
  with `printf '%q'`, and targets are validated against a strict character
  allow-list — a crafted line in a targets file can no longer inject shell.
- **No duplicate port scans.** Each unique host is scanned once into
  `<output_dir>/_nmap/<host>.txt` behind a `flock`; every target/worker for
  that host reuses it.
- **Always-current index.** Multi-target tmux/GUI runs now rebuild `index.md`
  as each worker finishes (flock-guarded).
- **Clear platform support.** Linux-only (Kali/Debian/Ubuntu tested); exits with
  a helpful message on macOS/BSD.
- **CI.** ShellCheck runs on every push and PR; the script passes
  `shellcheck -S warning` cleanly.

## Upgrade notes

- **Output layout changed:** nmap output moved from each target directory
  (`<target>/nmap_full_ports.txt`) to a shared `<output_dir>/_nmap/<host>.txt`.
  Any scripts that read the old path should be updated.
- **Deeper recursion is now opt-in:** pass `-d 3` to restore the previous depth.
- **Tier 3/4 wordlists changed** from `raft-*-files.txt` to
  `raft-*-directories.txt` (plus the optional no-extension files pass). Install
  `seclists` to get both.

## Full changelog

See [CHANGELOG.md](CHANGELOG.md).

## Verify

```bash
bash -n cataract.sh
shellcheck -S warning cataract.sh
./cataract.sh -h
```

Authorized testing only.
