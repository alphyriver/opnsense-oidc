# Release & package feed

Releases are cut by [`.github/workflows/release.yml`](../../.github/workflows/release.yml)
when a `v*` tag is pushed. The workflow builds the OPNsense package on FreeBSD,
(re)generates an **RSA-signed pkg repository**, publishes it to **GitHub Pages**
(`gh-pages` branch), and creates a **GitHub Release** with the `.pkg` attached.

GitHub is the source of truth for releases; Forgejo is a pull mirror, so the
release workflow lives only under `.github`.

## Files here

| File | Purpose |
|------|---------|
| `oidc.pub` | Public half of the repo signing key. **Committed.** Pinned on nodes as `/usr/local/etc/pkg/keys/oidc.pub`. |
| `oidc.conf.in` | OPNsense repo conf template. CI substitutes `@PAGES_URL@` and publishes the result at `<pages-url>/oidc.conf`. |

The private signing key is **never** committed — it lives only in the
`PKG_SIGNING_KEY` repository secret.

## One-time setup

1. **Signing key.** Generate an RSA keypair and keep the private key safe:
   ```sh
   openssl genrsa -out oidc-pkg-signing.key 4096
   openssl rsa -in oidc-pkg-signing.key -pubout -out deploy/repo/oidc.pub
   ```
   Commit `deploy/repo/oidc.pub`; add the **private** key as the
   `PKG_SIGNING_KEY` Actions secret (Settings → Secrets and variables → Actions).
   To rotate, replace both and re-publish the public key to every node.

2. **GitHub Pages.** Settings → Pages → Source: **Deploy from a branch** →
   `gh-pages` / `root`. (The branch is created by the first release.)

## Cutting a release

Versioning is automated by **release-please** (`.github/workflows/release-please.yml`).
You do not bump the version by hand.

1. **Merge feature PRs** to `main` using Conventional Commits (`feat:`, `fix:`,
   `feat!:` …). release-please keeps a **release PR** open that bumps
   `version.txt` + the `Makefile` `PLUGIN_VERSION` (via the
   `x-release-please-version` marker) and updates `CHANGELOG.md`.
2. **Merge the release PR** when ready. release-please creates the `vX.Y.Z` tag,
   which triggers `release.yml` to build + sign + publish (steps below).

> **First 1.0.0:** to jump from 0.x to 1.0.0, land an empty commit with a
> `Release-As: 1.0.0` footer on `main`
> (`git commit --allow-empty -m "chore: release 1.0.0" -m "Release-As: 1.0.0"`);
> release-please will target the release PR at 1.0.0.

> **Token:** for the release-please tag to auto-trigger `release.yml`, set a
> `RELEASE_PLEASE_TOKEN` PAT (contents + PR write). Without it, push the tag
> manually after merging the release PR (a `GITHUB_TOKEN`-created tag does not
> trigger other workflows).

On a `vX.Y.Z` tag, `release.yml` verifies the tag matches `PLUGIN_VERSION`, then:

1. builds the clean `os-oidc-X.Y.Z.pkg` (`make PLUGIN_DEVEL=`),
2. adds it to `gh-pages:/<ABI>/` and re-signs the catalogue over **all** versions
   (older releases stay installable for upgrades),
3. publishes `oidc.conf` + `pkg-repo.pub` + a landing page at the Pages root,
4. attaches the `.pkg` to a GitHub Release with auto-generated notes.

### Release candidates

To validate the **real signed package** on the firewall before blessing a
stable version, cut a prerelease tag from the release-please PR branch (which
already carries the bumped `PLUGIN_VERSION`):

```sh
git fetch origin
git checkout release-please--branches--main   # the open release PR branch
git tag v1.0.0-rc.1
git push origin v1.0.0-rc.1
```

`release.yml` treats a tag with a `-suffix` as a release candidate: it validates
the **base** version against `PLUGIN_VERSION` (so `1.0.0-rc.1` ↔ `1.0.0`), builds
+ signs the package, and ships it as a **GitHub pre-release** — but **does not
touch the production feed**, so the live feed only ever carries stable versions.
Install the candidate on the firewall directly:

```sh
fetch -o /tmp/os-oidc-rc.pkg https://github.com/<owner>/opnsense-oidc/releases/download/v1.0.0-rc.1/os-oidc-1.0.0.pkg
pkg add /tmp/os-oidc-rc.pkg
```

Run the acceptance matrix (`docs/testing-idps.md`). When it passes, **merge the
release-please PR** to cut the stable `v1.0.0` (feed + Release). `pkg delete
os-oidc` before installing stable if you want a clean upgrade (the RC shares the
`1.0.0` base version).

## Notes

- The feed directory is keyed by pkg ABI (e.g. `FreeBSD:14:amd64`). Bump the
  `ABI`/`release` values in the workflow when targeting a new FreeBSD base.
- The repo conf uses `signature_type: pubkey`; a node only trusts packages whose
  catalogue verifies against the pinned `oidc.pub`.
