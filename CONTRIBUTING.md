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

CI runs this weekly (`.forgejo/workflows/vendor-update.yml`) and opens a PR when
upstream moves; a human reviews and merges. The job needs a token with repo + PR
write — set the `VENDOR_UPDATE_TOKEN` secret if the automatic job token can't
create PRs. If a new upstream release adds or renames files, the
`require_once` list in `OidcClient.php` may need a manual follow-up (PR CI lint
will flag it).

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

CI is split by platform capability:

- `.forgejo/workflows/build.yml` (Forgejo) — **PHP lint + unit tests** only.
- `.github/workflows/build.yml` (GitHub mirror) — lint + unit tests **and** the
  authoritative **FreeBSD `make package` build + artifact**.

Every job is guarded on `github.server_url` so the pipeline runs **exactly once
per platform** (Forgejo also reads `.github/workflows`, hence the guard).

Why the split: the package build boots a FreeBSD 14.3 VM via
`vmactions/freebsd-vm`, which needs `sudo` + `qemu` + `/dev/kvm` in a privileged
container. GitHub's hosted `ubuntu-latest` runners provide this; the stock
Forgejo `act_runner` (jobs in an unprivileged `node:*` container) does not, so
the build is done on the mirror side.

Also note: Forgejo resolves `uses:` from `code.forgejo.org` by default (only
`actions/*` is mirrored there), so GitHub-hosted actions are referenced by full
`https://github.com/...` URL in the `.forgejo` file; the `.github` file uses the
short `owner/repo@ref` form GitHub requires.

### Enabling FreeBSD builds on Forgejo (optional, later)

To build the package on Forgejo too, register a **dedicated KVM-capable runner**:

1. Host with (nested) virtualization — `/dev/kvm` present.
2. `act_runner` config running the build job privileged with KVM, e.g. in
   `config.yaml`:
   ```yaml
   container:
     privileged: true
     options: --device /dev/kvm
   ```
   and a runner image that has `sudo` + `qemu` (or install them in a `prepare`
   step), labelled distinctly (e.g. `freebsd-builder`).
3. Re-add a `build` job to `.forgejo/workflows/build.yml` mirroring the
   `.github` build job, with `runs-on: freebsd-builder`.
