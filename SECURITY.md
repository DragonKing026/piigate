# Security policy

piigate is a safety net that keeps personal data (PII/PHI) out of an AI agent's context. A way to get
protected data past it is a security issue, even when it looks like a "trick" rather than a bug.

## Reporting

**Do not open a public issue for a bypass.** Report it privately through
[GitHub Security Advisories](https://github.com/DragonKing026/piigate/security/advisories/new)
("Report a vulnerability").

Please include:

- the piigate version (`piigate status`) and Claude Code version (`claude --version`);
- the tool call or command that got through (gate bypass) or the output that leaked (filter miss);
- **synthetic data only** — never send real personal data, even redacted by hand.

You can expect an acknowledgement within 7 days. Fixes are released as a new tag; the advisory is
published after the release.

## Scope

In scope: gate bypasses (a tool call that reads a protected source without going through the filter),
filter misses for formats the README lists as supported, pseudonym map or key exposure, the
`reverse`/`project approve` human-confirmation checks.

Known limitations (see README, "Limitations") are not vulnerabilities: e.g. code that assembles a path at
run time, nicknames, names written in lower case, data inside images. Reports that show a cheap way to
close one of them are still welcome as regular issues.
