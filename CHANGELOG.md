# Changelog

All notable changes are recorded here. From the next release onward this file is
maintained automatically by [release-please](https://github.com/googleapis/release-please)
from [Conventional Commits](https://www.conventionalcommits.org/).

## [0.3.1](https://github.com/alphyriver/opnsense-oidc/compare/os-oidc-v0.3.0...os-oidc-v0.3.1) (2026-06-21)


### Features

* **auth:** RP-initiated single logout (opt-in) ([92ecbe1](https://github.com/alphyriver/opnsense-oidc/commit/92ecbe1936984683ad9ad455255b78b3db7e0f74))
* **auth:** RP-initiated single logout (opt-in) ([6c2c584](https://github.com/alphyriver/opnsense-oidc/commit/6c2c584e382752b0a07d2f2954355a4a9faa8fe2))
* **groups:** live group-membership sync from a configurable claim (E2) ([101c48e](https://github.com/alphyriver/opnsense-oidc/commit/101c48ee4c3109eaddcce83fd76ce50ab802edc3))
* migrate OIDC client to maintained JakubOnderka fork + vendor automation ([4cf4935](https://github.com/alphyriver/opnsense-oidc/commit/4cf49354f38518af45b78d6d35142c6be0dfb71a))
* **perf,ux:** server-side icon cache + bounded fetch + default login button ([b7d6635](https://github.com/alphyriver/opnsense-oidc/commit/b7d663519fee58514285a75e7a8d407fc814a6a7))
* **security:** bind logins to verified OIDC sub+iss (C6/E1) ([b3215c9](https://github.com/alphyriver/opnsense-oidc/commit/b3215c93de009453deab9c9ef326f5a8cdee775c))
* **security:** Phase 1 hardening — redirect URL, icon SSRF/DoS, username fallback, password, dead fields ([c1d3ff8](https://github.com/alphyriver/opnsense-oidc/commit/c1d3ff85024a8cfde51a60a44068d1c9d175ea35))


### Bug Fixes

* **ci:** disable broken FreeBSD-kmods repo before pkg install ([4c1c9dd](https://github.com/alphyriver/opnsense-oidc/commit/4c1c9dd4b57e0dbb4d740a61e8c90ffa464dda66))
* **ci:** disable broken FreeBSD-kmods repo before pkg install ([5218b32](https://github.com/alphyriver/opnsense-oidc/commit/5218b329e68dbfbadb26d62231382a095a2908e0))

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
