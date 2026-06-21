# Testing against identity providers

This plugin has two automated test layers plus a documented manual acceptance
pass for the real IdPs you deploy against.

| Layer | What it covers | Where |
|-------|----------------|-------|
| **Unit** (`composer test`) | Pure logic — username/group derivation, account-resolution state machine, blocked-address (SSRF) checks, cache keys. No IdP needed. | `tests/` |
| **Integration** (`composer test:integration`) | A real authorization-code + PKCE handshake through the *same vendored client the plugin ships*: discovery, PAR, PKCE (S256), token exchange, JWKS signature verification, ID-token + claim/group extraction. | `tests/integration/` |
| **Manual acceptance** | End-to-end through the actual OPNsense login page against your real IdP (Authentik, etc.). The browser flow the automated layers don't drive. | this doc |

## Automated integration test (CI: Keycloak)

CI boots Keycloak with `tests/integration/keycloak-realm.json` (a confidential
client with PKCE S256 enforced, a `groups` claim mapper, and a `testuser` in the
`admins` group) and runs the handshake. This is the always-on guard that catches
**protocol regressions when the vendored OIDC library is bumped** — and protocol
behavior is IdP-agnostic, so one well-behaved IdP is enough for that axis.

Run it locally with Docker:

```sh
docker network create oidc-it
docker run -d --name kc --network oidc-it -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  -v "$PWD/tests/integration/keycloak-realm.json:/opt/keycloak/data/import/realm.json:ro" \
  quay.io/keycloak/keycloak:26.0 start-dev --import-realm
# wait for http://localhost:8080/realms/test/.well-known/openid-configuration
docker run --rm --network oidc-it -v "$PWD":/app -w /app \
  -e OIDC_PROVIDER_URL=http://kc:8080/realms/test \
  -e OIDC_CLIENT_ID=oidc-test -e OIDC_CLIENT_SECRET=test-secret \
  -e OIDC_USERNAME=testuser -e OIDC_PASSWORD=testpass \
  php:8.3-cli vendor/bin/phpunit --testsuite integration
```

## Running the integration test against any IdP (manual flavor)

We deliberately do **not** put Authentik (or any second IdP) in CI — Authentik is
heavy to bootstrap headless (Postgres + Redis + blueprints) and its login is a
JS flow with no plain form to script, which would add boot time and flakiness to
an auth component. Instead the same harness can be pointed at *any* OIDC IdP —
including your live Authentik — on demand:

```sh
composer install
OIDC_LOGIN_FLAVOR=manual \
OIDC_PROVIDER_URL=https://auth.example.com/application/o/opnsense/ \
OIDC_CLIENT_ID=<client-id> \
OIDC_CLIENT_SECRET=<client-secret> \
OIDC_REDIRECT_URI=https://<opnsense>/api/oidc/auth/callback \
OIDC_EXPECT_USERNAME=<your-test-user> \
OIDC_EXPECT_GROUP=<a-group-the-user-has> \
vendor/bin/phpunit --testsuite integration
```

The test prints the authorization URL; open it in a browser, log in, and paste
the full redirected callback URL back at the prompt (or pre-supply it via
`OIDC_CALLBACK_URL`). It then completes the token exchange and asserts the
issuer, audience, `sub`, and any `OIDC_EXPECT_*` values you set. With no TTY and
no `OIDC_CALLBACK_URL`, the manual flavor **skips** (so it is safe in CI).

> The redirect URI must be registered on the IdP and match `OIDC_REDIRECT_URI`.
> The browser will land on that URL (likely an error page) — only its query
> string (`?code=…&state=…`) matters; copy the whole URL.

## Authentik provider setup

Create these in the Authentik admin UI, then validate with the manual flavor
above and the acceptance checklist below.

1. **Group** — *Directory → Groups* → e.g. `opnsense-admins`. Add a test user.
2. **Groups scope mapping** — *Customization → Property Mappings → Create →
   Scope Mapping*:
   - Name `OIDC groups`, Scope name `groups`
   - Expression: `return [g.name for g in request.user.ak_groups.all()]`
3. **Provider** — *Applications → Providers → Create → OAuth2/OpenID Provider*:
   - Authorization flow: `default-provider-authorization-implicit-consent`
     (or explicit)
   - Client type **Confidential**; note the **Client ID / Client Secret**
   - Redirect URIs: `https://<opnsense>/api/oidc/auth/callback` (Strict)
   - Signing Key: any RSA key (Authentik's default certificate)
   - Scopes: `openid`, `email`, `profile`, **and the `groups` mapping above**
4. **Application** — *Applications → Create* → bind it to the provider; restrict
   access to the group if desired.

OPNsense side (*System → Access → Servers →* add an OIDC server):

| Setting | Value |
|---------|-------|
| Provider URL | `https://auth.example.com/application/o/<app-slug>/` |
| Client ID / Secret | from the provider |
| Username claim | `preferred_username` |
| Scopes | `openid,email,profile,groups` |
| Group claim | `groups` |
| Redirect URL | `https://<opnsense>/api/oidc/auth/callback` |

> PKCE is always on (S256) and cannot be disabled — an Authentik provider with
> "PKCE required" is fine. Public clients are not supported (a client secret is
> required).

## Manual acceptance checklist

Run once per real IdP (at least Authentik) before a release. Record results in
`docs/acceptance-<date>.md`.

- [ ] **Login** — existing local user matched, lands authenticated in the GUI.
- [ ] **Auto-create** (if enabled) — a new IdP user is created locally with the
      default groups.
- [ ] **Group sync** — add the user to a group in the IdP → that OPNsense group
      is granted on next login; remove it → it is revoked.
- [ ] **`sub`+`iss` binding** — log in, rename the IdP username, log in again →
      still matched to the same local account (bound by subject, not name).
- [ ] **Redirect mismatch** — set a wrong **Redirect URL** → the IdP rejects the
      `redirect_uri` (proves it isn't trusting the Host header).
- [ ] **Icon + custom button** — the provider icon proxies and the login-page
      button renders.
