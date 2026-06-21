# Changelog

All notable changes are recorded here. From the next release onward this file is
maintained automatically by [release-please](https://github.com/googleapis/release-please)
from [Conventional Commits](https://www.conventionalcommits.org/).

## [0.3.0] — baseline

Baseline before automated releases. Highlights of the 0.x hardening line:

- Security: fixed `stripWellKnown` truncation; admin-configured redirect URI
  (no longer trusts the `Host` header); random local placeholder passwords;
  SSRF/DoS-hardened icon proxy.
- Identity: bind logins to the verified `sub` + `iss` with an account-takeover
  guard; email-local-part username fallback (e.g. Entra ID).
- Groups: live group-membership sync from a configurable claim.
- Dependency: migrated the OIDC client to `JakubOnderka/OpenID-Connect-PHP`,
  vendored + checksum-tracked with an automated update bot.
- Delivery: RSA-signed pkg feed on GitHub Pages + GitHub Release on tag.
