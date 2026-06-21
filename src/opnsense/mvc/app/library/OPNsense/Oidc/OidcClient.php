<?php

/**
 * Wrapper around the vendored JakubOnderka\OpenIDConnectClient.
 *
 * It subclasses the protocol client so that:
 *  - OIDC state/nonce/PKCE values are stored in OPNsense's own Session object
 *    instead of native $_SESSION (the start/commit/get/set/unsetSessionKey
 *    overrides below), and
 *  - HTTP redirects go through OPNsense's Response object (redirect override).
 *
 * The library is vendored in lib/ and tracked against upstream by
 * scripts/vendor-update.sh + the vendor-update CI job; its exact version lives
 * in /vendor-lock.json. Do not hand-edit the files in lib/.
 */

namespace OPNsense\Oidc;

use JakubOnderka\OpenIDConnectClient;
use OPNsense\Auth\OIDC;
use OPNsense\Mvc\Controller;
use OPNsense\Mvc\Request;
use OPNsense\Mvc\Response;
use OPNsense\Mvc\Session;

/*
 * phpseclib ships with OPNsense as a system port at /usr/local/share/phpseclib
 * and is not vendored. Register its autoloaders BEFORE requiring the vendored
 * OIDC library below: lib/Jwks.php composes a phpseclib trait at
 * class-definition time, so phpseclib must be resolvable as the files load.
 */
(static function (): void {
    $register = static function (string $namespace, string $dir): void {
        spl_autoload_register(static function (string $class) use ($namespace, $dir): void {
            $prefix = trim($namespace, '\\') . '\\';
            $len = strlen($prefix);
            if (strncmp($prefix, $class, $len) !== 0) {
                return;
            }
            $file = rtrim($dir, '/') . '/' . str_replace('\\', '/', substr($class, $len)) . '.php';
            if (is_file($file)) {
                require_once $file;
            }
        });
    };
    $register('ParagonIE\\ConstantTime', '/usr/local/share/phpseclib/paragonie');
    $register('phpseclib3', '/usr/local/share/phpseclib');
})();

require_once __DIR__ . '/lib/Jwt.php';
require_once __DIR__ . '/lib/Jwks.php';
require_once __DIR__ . '/lib/Jwe.php';
require_once __DIR__ . '/lib/OpenIDConnectClient.php';

class OidcClient extends OpenIDConnectClient
{
    /** @var OIDC $auth */
    protected $auth;
    /** @var Session $session */
    protected $session;
    /** @var Request $request */
    protected $request;
    /** @var Response $response */
    protected $response;
    /** @var \stdClass|null cached discovery document for getWellKnown* helpers */
    private $wellKnownCache = null;

    public function __construct(OIDC $auth, Controller $controller, string $callback = '/api/oidc/auth/callback')
    {
        parent::__construct(OidcHelpers::stripWellKnown($auth->oidcProviderUrl), $auth->oidcClientId, $auth->oidcClientSecret);

        $this->auth = $auth;
        $this->session = $controller->session;
        $this->request = $controller->request;
        $this->response = $controller->response;

        // Prefer the admin-configured redirect URL. The Host-header-derived
        // fallback is kept for backward compatibility, but the Host header is
        // client-supplied: relying on it lets an attacker who can influence it
        // (e.g. behind a misconfigured reverse proxy or catch-all vhost) steer
        // the redirect_uri sent to the IdP. Setting the field explicitly closes
        // that off; see the "Redirect URL" help text in OIDC.php.
        $redirectUrl = $auth->oidcRedirectUrl
            ?: "{$this->request->getScheme()}://{$this->request->getHeader('HOST')}{$callback}";
        $this->setRedirectURL($redirectUrl);
    }

    /**
     * Fetch and cache the provider's discovery document. Used by the settings
     * "Test" button (DiscoverController). The library's own discovery accessors
     * (getWellKnownConfigValue / fetchProviderMetadata) are private, so we read
     * the document ourselves via the library's public HTTP helper, reusing its
     * configured TLS settings.
     */
    private function discover(): \stdClass
    {
        if ($this->wellKnownCache === null) {
            $url = rtrim($this->getProviderURL(), '/') . '/.well-known/openid-configuration';
            $this->wellKnownCache = $this->fetchURL($url)->json(true);
        }
        return $this->wellKnownCache;
    }

    /**
     * The provider's RP-initiated-logout endpoint, or null if it doesn't
     * advertise one. Read from the cached discovery document so the caller can
     * decide whether single logout is possible without the base client throwing
     * (getWellKnownConfigValue() throws on a missing key). See AuthController::logoutAction().
     */
    public function endSessionEndpoint(): ?string
    {
        $url = $this->discover()->end_session_endpoint ?? null;
        return is_string($url) && $url !== '' ? $url : null;
    }

    public function getWellKnownClaims()
    {
        return $this->discover()->claims_supported ?? [];
    }

    public function getWellKnownScopes()
    {
        return $this->discover()->scopes_supported ?? [];
    }

    // --- Route the library's session storage through OPNsense's Session -------
    // OPNsense manages the session lifecycle, so start/commit are no-ops; the
    // library only ever stores plain strings (state, nonce, PKCE verifier).

    protected function startSession() {}

    protected function commitSession() {}

    protected function getSessionKey(string $key)
    {
        return $this->session->get($key, null);
    }

    protected function setSessionKey(string $key, string $value)
    {
        $this->session->set($key, $value);
    }

    protected function unsetSessionKey(string $key)
    {
        $this->session->remove($key);
    }

    protected function redirect(string $url)
    {
        $this->response->redirect($url);
    }
}
