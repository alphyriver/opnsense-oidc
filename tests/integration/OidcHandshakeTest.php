<?php

/**
 * Integration test: drives a real OpenID Connect authorization-code + PKCE
 * handshake against a live IdP, through the SAME vendored client the plugin
 * ships.
 *
 * It exercises the parts that actually regress when the vendored library is
 * bumped — provider discovery, PAR, the PKCE challenge, the token exchange,
 * JWKS-based ID-token signature verification, and claim/group extraction — none
 * of which the pure-helper unit tests can cover.
 *
 * The harness subclasses JakubOnderka\OpenIDConnectClient and overrides exactly
 * the same five session methods + redirect that the plugin's OidcClient does, so
 * the session-storage contract the plugin depends on is covered too. We require
 * the lib files directly (rather than the plugin's OidcClient.php, which hard-
 * codes OPNsense's /usr/local/share/phpseclib path); phpseclib here comes from
 * Composer (vendor/), autoloaded by the phpunit bootstrap.
 *
 * Login is pluggable via OIDC_LOGIN_FLAVOR so the same test runs against any IdP:
 *   keycloak (default, used in CI) — scripts the Keycloak login form headlessly.
 *   manual                        — for any other IdP (e.g. a live Authentik):
 *                                    open the printed URL, log in, and paste the
 *                                    redirected callback URL back (via STDIN or
 *                                    OIDC_CALLBACK_URL). See docs/testing-idps.md.
 *
 * Env:
 *   OIDC_PROVIDER_URL   required, e.g. http://keycloak:8080/realms/test
 *   OIDC_CLIENT_ID      required
 *   OIDC_CLIENT_SECRET  required
 *   OIDC_REDIRECT_URI   optional (default http://localhost/callback)
 *   OIDC_LOGIN_FLAVOR   optional (default keycloak)
 *   OIDC_USERNAME       required for the keycloak flavor
 *   OIDC_PASSWORD       required for the keycloak flavor
 *   OIDC_CALLBACK_URL   optional for the manual flavor (else read from STDIN)
 *   OIDC_EXPECT_USERNAME / OIDC_EXPECT_EMAIL / OIDC_EXPECT_GROUP
 *                       optional exact-match assertions (defaulted for keycloak)
 */

declare(strict_types=1);

namespace OPNsense\Oidc\Tests\Integration;

use JakubOnderka\OpenIDConnectClient;
use PHPUnit\Framework\TestCase;

// The vendored client lives under the plugin's library namespace (JakubOnderka).
// Composer autoloads phpseclib; require the lib in dependency order (Jwks composes
// a phpseclib trait at class-definition time, so phpseclib must already resolve).
$lib = dirname(__DIR__, 2) . '/src/opnsense/mvc/app/library/OPNsense/Oidc/lib';
require_once $lib . '/Jwt.php';
require_once $lib . '/Jwks.php';
require_once $lib . '/Jwe.php';
require_once $lib . '/OpenIDConnectClient.php';

/**
 * Test double mirroring OPNsense\Oidc\OidcClient's overrides: session storage in
 * a plain array, and redirect captured instead of sent.
 */
final class HarnessClient extends OpenIDConnectClient
{
    /** @var array<string,string> */
    public array $store = [];
    public ?string $capturedRedirect = null;

    protected function startSession() {}
    protected function commitSession() {}

    protected function getSessionKey(string $key)
    {
        return $this->store[$key] ?? null;
    }

    protected function setSessionKey(string $key, string $value)
    {
        $this->store[$key] = $value;
    }

    protected function unsetSessionKey(string $key)
    {
        unset($this->store[$key]);
    }

    protected function redirect(string $url)
    {
        $this->capturedRedirect = $url;
    }
}

class OidcHandshakeTest extends TestCase
{
    private string $issuer;
    private string $clientId;
    private string $clientSecret;
    private string $redirectUri;
    private string $flavor;

    protected function setUp(): void
    {
        foreach (['OIDC_PROVIDER_URL', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET'] as $req) {
            if ((string)getenv($req) === '') {
                $this->markTestSkipped("$req not set — integration test needs a live IdP");
            }
        }
        $this->issuer       = rtrim((string)getenv('OIDC_PROVIDER_URL'), '/');
        $this->clientId     = (string)getenv('OIDC_CLIENT_ID');
        $this->clientSecret = (string)getenv('OIDC_CLIENT_SECRET');
        $this->redirectUri  = (string)(getenv('OIDC_REDIRECT_URI') ?: 'http://localhost/callback');
        $this->flavor       = (string)(getenv('OIDC_LOGIN_FLAVOR') ?: 'keycloak');
    }

    public function testAuthorizationCodePkceFlowYieldsVerifiedClaims(): void
    {
        $client = new HarnessClient($this->issuer, $this->clientId, $this->clientSecret);
        $client->setRedirectURL($this->redirectUri);
        $client->addScope(['openid', 'email', 'profile']);

        // Step 1 — build the authorization request. With no `code` present,
        // authenticate() runs discovery, stores state/nonce/PKCE verifier in the
        // session, and "redirects" (captured here), returning false.
        $this->assertFalse($client->authenticate(), 'authenticate() should return false on the initial leg');
        $authUrl = $client->capturedRedirect;
        $this->assertNotNull($authUrl, 'authorization redirect was not produced');

        // PKCE: a code verifier must have been generated and stashed in the
        // session. (IdPs that advertise a PAR endpoint — e.g. Keycloak — push the
        // S256 challenge there rather than on the front-channel URL, so we assert
        // the stored verifier, not the URL.) The token exchange in step 3 only
        // succeeds if a valid challenge was sent, proving PKCE end-to-end.
        $this->assertArrayHasKey('openid_connect_code_verifier', $client->store, 'PKCE code verifier was not generated/stored');
        $this->assertNotEmpty($client->store['openid_connect_code_verifier']);

        // Step 2 — complete the login at the IdP and capture the callback URL.
        $callbackUrl = $this->obtainCallbackUrl($authUrl);
        [$code, $state] = $this->extractCodeState($callbackUrl);
        $this->assertNotEmpty($code, 'no authorization code returned from IdP');

        // Step 3 — feed the callback back through the client (token exchange +
        // JWKS signature verify + ID-token claim validation).
        $_REQUEST['code']  = $_GET['code']  = $code;
        $_REQUEST['state'] = $_GET['state'] = $state;
        try {
            $this->assertTrue($client->authenticate(), 'authenticate() should succeed on the callback leg');

            $claims = $client->getVerifiedClaims();

            // Structural assertions hold for every conformant IdP.
            $this->assertSame($this->issuer, rtrim((string)$claims->iss, '/'), 'issuer mismatch');
            $this->assertSame($this->clientId, $this->audAsString($claims->aud), 'audience mismatch');
            $this->assertNotEmpty($claims->sub, 'sub (subject) must be present for account binding');

            // Exact-value assertions: defaulted for the keycloak fixture, optional
            // (env-driven) for any other IdP so the same test works against a live
            // Authentik/PocketID/Entra without hard-coding that tenant's data.
            if (($u = $this->expect('OIDC_EXPECT_USERNAME', 'testuser')) !== null) {
                $this->assertSame($u, $claims->preferred_username ?? null, 'preferred_username mismatch');
            }
            if (($e = $this->expect('OIDC_EXPECT_EMAIL', 'testuser@example.com')) !== null) {
                $this->assertSame($e, $claims->email ?? null, 'email mismatch');
            }
            if (($g = $this->expect('OIDC_EXPECT_GROUP', 'admins')) !== null) {
                $this->assertContains($g, (array)($claims->groups ?? []), "group claim should carry \"$g\"");
            }
        } finally {
            unset($_REQUEST['code'], $_REQUEST['state'], $_GET['code'], $_GET['state']);
        }
    }

    /** Default expectation only applies to the keycloak fixture; otherwise env-driven or skipped. */
    private function expect(string $env, string $keycloakDefault): ?string
    {
        $val = getenv($env);
        if ($val !== false && $val !== '') {
            return $val;
        }
        return $this->flavor === 'keycloak' ? $keycloakDefault : null;
    }

    /** Keycloak may emit `aud` as a string or an array; normalise for assertion. */
    private function audAsString(mixed $aud): string
    {
        return is_array($aud) ? (string)reset($aud) : (string)$aud;
    }

    private function obtainCallbackUrl(string $authUrl): string
    {
        return match ($this->flavor) {
            'keycloak' => $this->keycloakLogin($authUrl),
            'manual'   => $this->manualLogin($authUrl),
            default    => throw new \RuntimeException("unknown OIDC_LOGIN_FLAVOR: {$this->flavor}"),
        };
    }

    /** @return array{0:string,1:string} [code, state] parsed from a callback URL. */
    private function extractCodeState(string $callbackUrl): array
    {
        parse_str((string)parse_url($callbackUrl, PHP_URL_QUERY), $q);
        return [(string)($q['code'] ?? ''), (string)($q['state'] ?? '')];
    }

    /**
     * Manual flavor: works against any IdP. Print the authorization URL, let the
     * operator log in via a browser, and read the redirected callback URL back
     * (from OIDC_CALLBACK_URL, or interactively from STDIN). Skips cleanly in CI
     * (no env, no TTY) so it never blocks the pipeline.
     */
    private function manualLogin(string $authUrl): string
    {
        $env = getenv('OIDC_CALLBACK_URL');
        if ($env !== false && $env !== '') {
            return $env;
        }
        if (!stream_isatty(STDIN)) {
            $this->markTestSkipped('manual flavor needs OIDC_CALLBACK_URL or an interactive TTY');
        }
        fwrite(STDERR, "\n\nOpen this URL, log in, then paste the full redirected URL here:\n\n  $authUrl\n\n> ");
        return trim((string)fgets(STDIN));
    }

    /**
     * Keycloak flavor: script the browser login headlessly — fetch the login
     * page (cookie jar), submit credentials to the form's action, and return the
     * redirect URL carrying the authorization code.
     */
    private function keycloakLogin(string $authUrl): string
    {
        foreach (['OIDC_USERNAME', 'OIDC_PASSWORD'] as $req) {
            if ((string)getenv($req) === '') {
                $this->markTestSkipped("$req required for the keycloak login flavor");
            }
        }
        $jar = tempnam(sys_get_temp_dir(), 'kcjar');

        $loginPage = $this->httpGet($authUrl, $jar);
        if (!preg_match('/id="kc-form-login"[^>]*?action="([^"]+)"/s', $loginPage, $m)) {
            $this->fail("Keycloak login form (id=kc-form-login) not found:\n" . substr($loginPage, 0, 800));
        }
        $action = html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5);

        $location = $this->httpPostCaptureLocation($action, $jar, [
            'username'     => (string)getenv('OIDC_USERNAME'),
            'password'     => (string)getenv('OIDC_PASSWORD'),
            'credentialId' => '',
        ]);
        @unlink($jar);

        $this->assertNotEmpty($location, 'Keycloak did not redirect after login (bad credentials or flow change)');
        return $location;
    }

    private function httpGet(string $url, string $jar): string
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_COOKIEJAR      => $jar,
            CURLOPT_COOKIEFILE     => $jar,
            CURLOPT_TIMEOUT        => 30,
        ]);
        $body = curl_exec($ch);
        $this->assertNotFalse($body, 'GET failed: ' . curl_error($ch));
        curl_close($ch);
        return (string)$body;
    }

    /** POST form, do NOT follow the redirect, return the Location header. */
    private function httpPostCaptureLocation(string $url, string $jar, array $fields): string
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => http_build_query($fields),
            CURLOPT_COOKIEJAR      => $jar,
            CURLOPT_COOKIEFILE     => $jar,
            CURLOPT_TIMEOUT        => 30,
        ]);
        $resp = (string)curl_exec($ch);
        curl_close($ch);
        if (preg_match('/^location:\s*(\S+)/im', $resp, $m)) {
            return trim($m[1]);
        }
        return '';
    }
}
