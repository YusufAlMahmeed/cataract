# Contributing to Cataract

Thanks for your interest in improving Cataract. Contributions of all
kinds are welcome — bug reports, fixes, new tiers/wordlist paths, documentation,
and portability improvements across distros.

## Ground rules

- **Authorized use only.** This is a tool for authorized security testing and
  education. Do not open issues or PRs that request or add features whose only
  purpose is unauthorized access, evasion of detection, or attacking systems
  you don't own or have permission to test. See [SECURITY.md](SECURITY.md).
- Be respectful. See the [Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting bugs

Open a [bug report](../../issues/new?template=bug_report.md) and include:

- Your OS/distro and versions of `bash`, `nmap`, `feroxbuster`, `tmux`.
- The exact command you ran (redact real target IPs/hostnames).
- What you expected vs. what happened, including any error text.

## Development setup

```bash
git clone https://github.com/YusufAlMahmeed/cataract.git
cd cataract
chmod +x cataract.sh
```

Recommended tooling:

- **`shellcheck`** — please run it and address findings before submitting:
  ```bash
  shellcheck cataract.sh
  ```
- **`bash -n cataract.sh`** — syntax check; must pass.
- Test any change to the multi-target path against 2+ safe targets
  (e.g. `scanme.nmap.org` and `45.33.32.156`) and confirm the tmux tabs,
  `Ctrl+b n/p` navigation, and the ENTER pause menu still work.

## Coding style

- POSIX-friendly `bash`; keep dependencies minimal (`bash`, `nmap`,
  `feroxbuster`, util-linux `script`, `tmux`).
- Keep user-tunable values in the **TUNABLES** block at the top of the script.
- Quote variables (`"$var"`), and comment any non-obvious quoting or
  subprocess choice (the `script -qec ... | tee` PTY trick is the canonical
  example).
- Apply tmux styling to the script's **own session only** — never write to a
  user's `~/.tmux.conf` or change global tmux options.

## Pull requests

1. Fork and create a topic branch: `git checkout -b fix/short-description`.
2. Keep PRs focused; one logical change per PR.
3. Update `README.md` and the in-script changelog when behavior changes.
4. Confirm `bash -n` and `shellcheck` pass, and describe how you tested.

Thanks again!
