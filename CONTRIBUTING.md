# Contributing

This is a hardened fork of the OPNsense OIDC plugin, hosted on GitHub
(`github.com/alphyriver/opnsense-oidc`) — the source of truth for code, CI, and
releases.

## Branching

`main` is the integration branch. Do all work on a feature branch and open a PR
into `main`:

```sh
git checkout main && git pull
git checkout -b feat/short-description
# ...changes...
git push -u origin feat/short-description
```

Never push directly to `main`.

## What ships in the package

The OPNsense package build (`make package`, via `Mk/plugins.mk`) only copies
`Makefile`, `pkg-descr`, and `src/`. Everything else in this repo
(`composer.json`, `phpunit.xml`, `tests/`, CI workflows, this file) is
**development tooling and is never installed on the firewall.**

## Vendored OIDC library

The OIDC protocol client is the third-party
[`jakub-onderka/openid-connect-php`](https://github.com/JakubOnderka/OpenID-Connect-PHP),
vendored under `src/.../OPNsense/Oidc/lib/` because OPNsense's plugin build has
no Composer-fetch step. It depends only on `phpseclib`, which OPNsense already
ships as a system port at `/usr/local/share/phpseclib` (so phpseclib is **not**
vendored). `OidcClient.php` registers the phpseclib autoloaders before requiring
`lib/` (one of the files composes a phpseclib trait at load time).

**Do not hand-edit the files in `lib/`.** They must stay byte-identical to
upstream so their checksums in `/vendor-lock.json` verify. To update:

```sh
sh scripts/vendor-update.sh   # bumps to the latest upstream release if newer
```

CI runs this weekly (`.github/workflows/vendor-update.yml`) and opens a PR when
upstream moves; a human reviews and merges. To have the build/test workflow run
automatically on that PR, set a `VENDOR_UPDATE_TOKEN` secret (a fine-grained PAT
with contents + pull-requests write) — a PR opened with the default `GITHUB_TOKEN`
does not trigger other workflows. If a new upstream release adds or renames
files, the `require_once` list in `OidcClient.php` may need a manual follow-up
(PR CI lint will flag it).

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

GitHub is the canonical CI platform. Workflows under `.github/workflows/`:

- `build.yml` — **PHP lint + unit tests** (Linux) **and** the authoritative
  **FreeBSD `make package` build + artifact**. The build boots a FreeBSD 14.3 VM
  via `vmactions/freebsd-vm` (which needs `sudo` + `qemu` + `/dev/kvm`), provided
  by GitHub's hosted `ubuntu-latest` runners.
- `vendor-update.yml` — the weekly vendored-library tracker (see above).
- `release.yml` — on a `v*` tag: clean package build, RSA-signed pkg feed, and
  GitHub Release + Pages publish.

The read-only Forgejo mirror does **not** run CI.

`.gitea/workflows/build-pkg.yml` is retained from the upstream fork: a simple
`make package` build for anyone running this on a Gitea/self-hosted FreeBSD
runner (`runs-on: freebsd`). It is not used by this repo's canonical pipeline.
