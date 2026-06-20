# Contributing

This is the homelab-cosmos fork of the OPNsense OIDC plugin. It is hosted on
Forgejo (`forgejo.eridanus-talos.com/homelab-cosmos/opnsense-oidc`) and mirrored
to GitHub (`github.com/Lachee/opnsense-oidc`).

## Branching

`main` is the integration branch and the mirror source. Do all work on a feature
branch and open a PR into `main`:

```sh
git checkout main && git pull
git checkout -b feat/short-description
# ...changes...
git push -u origin feat/short-description
```

Never push directly to `main`; pushing `main` triggers the GitHub mirror.

## What ships in the package

The OPNsense package build (`make package`, via `Mk/plugins.mk`) only copies
`Makefile`, `pkg-descr`, and `src/`. Everything else in this repo
(`composer.json`, `phpunit.xml`, `tests/`, CI workflows, this file) is
**development tooling and is never installed on the firewall.**

## Running the tests

Pure-logic code with no OPNsense/Phalcon runtime dependency lives in
`src/.../library/OPNsense/Oidc/OidcHelpers.php` so it can be unit-tested
directly. Requires PHP 8.3+ and Composer:

```sh
composer install
composer test
```

No local PHP? Run it in Docker:

```sh
docker run --rm -v "$PWD":/app -w /app composer:2 composer install
docker run --rm -v "$PWD":/app -w /app php:8.3-cli vendor/bin/phpunit
```

Add new pure helpers to `OidcHelpers` (keep it free of `OPNsense\*` imports) and
cover them in `tests/`. The CI `test` job runs on every PR.

## CI

Two functionally identical workflows build the FreeBSD package and run the unit
tests:

- `.forgejo/workflows/build.yml` — runs on Forgejo
- `.github/workflows/build.yml` — runs on the GitHub mirror

Each job is guarded on `github.server_url` so the pipeline runs **exactly once
per platform** (Forgejo also reads `.github/workflows`, hence the guard). The
package build boots a FreeBSD 14.3 VM via `vmactions/freebsd-vm`, which needs
nested virtualization (`/dev/kvm`) on the runner.
