# Security & Responsible Use

## Authorized testing only

Cataract is a reconnaissance tool intended **solely for authorized
security testing and education** — systems you own, lab environments you
are entitled to use, or targets for which you hold
explicit written permission. Unauthorized scanning or access is illegal in
most jurisdictions. You are solely responsible for how you use this tool.

## Reporting a vulnerability in this tool

If you find a security issue in Cataract itself (for example, a way the
script could be made to execute unintended commands via a crafted target
string or wordlist path), please report it privately rather than opening a
public issue:

- Use GitHub's **[Report a vulnerability](../../security/advisories/new)**
  (Security → Advisories) to open a private advisory, **or**
- Contact the maintainer listed on the repository profile.

Please include a description, reproduction steps, and the impact. We aim to
acknowledge reports promptly and will credit reporters who wish to be named.

## Scope

In scope: command injection, path traversal, or unsafe handling of
user-supplied input within the script.

Out of scope: the behavior of the underlying tools (`nmap`, `feroxbuster`,
`tmux`), and any misuse of the tool against systems you are not authorized to
test.
