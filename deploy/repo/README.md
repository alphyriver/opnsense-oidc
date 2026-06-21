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

```sh
# bump the version (must match the tag)
$EDITOR Makefile          # PLUGIN_VERSION = 0.3
git commit -am "release: v0.3"
git tag v0.3
git push origin main --tags
```

The workflow guards that the tag (`vX.Y`) matches `PLUGIN_VERSION`, then:

1. builds the clean `os-oidc-X.Y.pkg` (`make PLUGIN_DEVEL=`),
2. adds it to `gh-pages:/<ABI>/` and re-signs the catalogue over **all** versions
   (older releases stay installable for upgrades),
3. publishes `oidc.conf` + `pkg-repo.pub` + a landing page at the Pages root,
4. attaches the `.pkg` to a GitHub Release with auto-generated notes.

## Notes

- The feed directory is keyed by pkg ABI (e.g. `FreeBSD:14:amd64`). Bump the
  `ABI`/`release` values in the workflow when targeting a new FreeBSD base.
- The repo conf uses `signature_type: pubkey`; a node only trusts packages whose
  catalogue verifies against the pinned `oidc.pub`.
