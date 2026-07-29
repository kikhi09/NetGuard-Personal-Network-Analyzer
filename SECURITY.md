# Security Policy

## Supported version

Security fixes are currently considered for the latest `1.x` release only.
This is a small educational project, not a commercially supported security
product.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature on the repository
Security tab if it is enabled. Please allow time for investigation before
publishing technical details. If private reporting is unavailable, open a
minimal public issue asking the maintainer to enable a private channel; do not
include exploit details in that issue.

Never attach packet captures, NetGuard databases, private logs, credentials,
adapter GUIDs, usernames, personal paths, or unredacted network addresses to a
public issue.

## Security model and scope

NetGuard is designed for one authorized user on a local computer. Browser mode
binds to loopback by default and has no authentication. It must not be exposed
to an untrusted network.

NetGuard analyzes selected-interface packet metadata with rule-based
thresholds. It does not guarantee complete attack detection, inspect encrypted
HTTPS content, scan files, or block traffic. Optional socket-to-process mapping
is best-effort and cannot identify browser tabs, websites, or encrypted
content. Reports and the Security Score are monitoring aids, not guarantees of
safety.
