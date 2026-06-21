# Security

A note on the plugin's security posture and one documented limitation.

## What is hardened

- **PKCE (S256) is always on** and cannot be disabled; public clients are not
  supported (a client secret is required).
- **ID tokens are fully validated** — signature against the provider's JWKS, plus
  `iss` / `aud` / `exp` / `nonce`.
- **Accounts bind to the verified `sub` + `iss`**, not to a mutable
  username/email, with an account-takeover guard (see
  `OidcHelpers::decideAccountResolution()`).
- **Redirect URI** prefers an admin-configured value and does not trust the
  inbound `Host` header when set.
- **The icon proxy is SSRF/DoS-hardened** — http(s)-only, redirect cap, response
  size cap, and rejection of internal/reserved final addresses.
- **Local placeholder passwords are random** (`random_bytes`), not a shared
  constant, and accounts are flagged scrambled.

## Known limitation: session fixation (CWE-384)

### The weakness

OPNsense issues a PHP session cookie to the browser **before** authentication
(the login page is served on a session). On a successful OIDC callback the plugin
elevates that *same* session to authenticated by writing `Username` into it
(`AuthController::callbackAction()`), **without rotating the session ID**. If an
attacker can plant or fix a known session ID in the victim's browser before they
log in — e.g. via a cookie-injection vector (a shared sub-domain that can set a
cookie for the parent domain), a MITM on a non-HTTPS hop, or an XSS — that
attacker's pre-known ID becomes an authenticated admin session once the victim
completes login.

### The fix (what *would* change)

Immediately after auth succeeds and **before** `Username` is written, the session
ID should be rotated so the authenticated session gets a fresh, never-before-seen
ID and the pre-auth ID is invalidated. The PHP primitive is
`session_regenerate_id(true)` (the `true` deletes the old session file). The
desired call site is the top of the session-elevation block in
`callbackAction()`:

```php
// after successful OIDC auth, before elevating the session:
$this->session->regenerateId();   // wrapper around session_regenerate_id(true)
$this->session->set('Username', …);
```

### Why it is not fixed in the plugin

`OPNsense\Mvc\Session` — the only session handle the controller is given
(`$this->session`) — exposes `get()` / `set()` / `has()` / `remove()` /
`destroy()` / `close()` but **no `regenerateId()`**. Calling raw
`session_regenerate_id()` from the plugin is unsafe: the wrapper owns the session
lifecycle and the response cookie. OPNsense reads the session, **aborts it**
(releasing the lock so the long IdP round-trip doesn't hold it), then re-opens and
`close()`s (writes) at the end. Regenerating the ID mid-flight from outside the
wrapper risks the wrapper re-emitting the **old** cookie — an id/cookie mismatch
within the request that would silently break the just-created login. In addition,
**OPNsense core's own local-password login does not regenerate the session ID
either**, so this is a framework-wide gap, not OIDC-specific; fixing only this
plugin would be inconsistent and would still leave the wrapper without a safe
primitive.

### Correct remediation (upstream)

Add a `regenerateId()` method to `OPNsense\Mvc\Session` that wraps
`session_regenerate_id(true)` *and* updates the wrapper's tracked id + response
cookie atomically, then call it on every privilege elevation (the OIDC callback
**and** core local login). The plugin is ready to adopt such a method as soon as
core ships one. Filing/championing that core change is left to the maintainer's
discretion.

### Residual-risk assessment

Practically, exploitation requires fixing a victim's session ID **pre-auth on the
same origin** — non-trivial given OPNsense sets the session cookie `HttpOnly` +
`Secure` over HTTPS and there is no public sub-domain cookie surface by default.
Severity here is **low-to-moderate / defense-in-depth**, not a remotely
exploitable hole — but it should be closed once core exposes the primitive.
**Interim mitigation:** keep the GUI HTTPS-only with HSTS.
