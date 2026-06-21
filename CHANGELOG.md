# Changelog

All notable changes are recorded here. From the next release onward this file is
maintained automatically by [release-please](https://github.com/googleapis/release-please)
from [Conventional Commits](https://www.conventionalcommits.org/).

## [1.0.0](https://github.com/alphyriver/opnsense-oidc/compare/v0.3...v1.0.0) (2026-06-21)

First stable release of the hardened OPNsense OpenID Connect login plugin —
everything landed since `v0.3`.

### Security

* Phase 1 hardening: admin-configured **Redirect URL** (no longer trusts the
  inbound `Host` header), **SSRF/DoS-hardened** icon proxy, randomised local
  placeholder passwords, and removal of dead config fields.
* Bind logins to the verified OIDC **`sub` + `iss`** with an account-takeover
  guard.
* **PKCE (S256)** is always on; the one known limitation (session fixation, a
  core-level gap) is documented in [`docs/security.md`](docs/security.md).

### Features

* **RP-initiated single logout** — `/api/oidc/auth/logout` clears the local
  session and redirects to the provider's `end_session_endpoint` when advertised
  (opt-in).
* **Live group-membership sync** from a configurable claim.
* **Server-side icon cache** + bounded fetch + a sane default login button.

### Dependencies

* Migrate the OIDC client to the maintained **`JakubOnderka/OpenID-Connect-PHP`**
  fork — vendored, checksum-tracked, and watched by an automated update bot.

### CI / Release

* GitHub-canonical CI; a real-IdP **integration test** against Keycloak
  (discovery, PAR, PKCE, JWKS signature verification, claim/group extraction);
  **release-please** automation with signed **release-candidate** support.

### Docs

* Authentik provider setup + acceptance matrix in
  [`docs/testing-idps.md`](docs/testing-idps.md).

## v0.3 and earlier

Pre-release history predates this changelog; see the git log.
