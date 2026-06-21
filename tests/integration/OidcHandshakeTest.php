<?php

/**
 * Integration test: drives a real OpenID Connect authorization-code + PKCE
 * handshake against a live Keycloak (booted by CI / docker), through the SAME
 * vendored client the plugin ships.
 *
 * It exercises the parts that actually regress when the vendored library is
 * bumped — provider discovery, the PKCE code_challenge, the token exchange,
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
 * Env (set by the workflow / local docker run):
 *   OIDC_PROVIDER_URL  e.g. http://keycloak:8080/realms/test
 *   OIDC_CLIENT_ID     oidc-test
 *   OIDC_CLIENT_SECRET test-secret
 *   OIDC_USERNAME      testuser
 *   OIDC_PASSWORD      testpass
 *   OIDC_REDIRECT_URI  http://localhost/callback
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
    private string $username;
    private string $password;
    private string $redirectUri;

    protected function setUp(): void
    {
        foreach (['OIDC_PROVIDER_URL', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_USERNAME', 'OIDC_PASSWORD'] as $req) {
            if (getenv($req) === false || getenv($req) === '') {
                $this->markTestSkipped("$req not set — integration test needs a live IdP");
            }
        }
        $this->issuer       = rtrim((string)getenv('OIDC_PROVIDER_URL'), '/');
        $this->clientId     = (string)getenv('OIDC_CLIENT_ID');
        $this->clientSecret = (string)getenv('OIDC_CLIENT_SECRET');
        $this->username     = (string)getenv('OIDC_USERNAME');
        $this->password     = (string)getenv('OIDC_PASSWORD');
        $this->redirectUri  = (string)(getenv('OIDC_REDIRECT_URI') ?: 'http://localhost/callback');
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
        // session. (Keycloak advertises a PAR endpoint, so the client pushes the
        // S256 challenge there rather than on the front-channel URL — hence we
        // assert the stored verifier, not the URL.) The realm enforces
        // pkce.code.challenge.method=S256, so the token exchange in step 3 only
        // succeeds if a valid S256 challenge was sent — proving S256 end-to-end.
        $this->assertArrayHasKey('openid_connect_code_verifier', $client->store, 'PKCE code verifier was not generated/stored');
        $this->assertNotEmpty($client->store['openid_connect_code_verifier']);

        // Step 2 — complete the login at Keycloak and capture the callback code.
        [$code, $state] = $this->loginAndCaptureCode($authUrl);
        $this->assertNotEmpty($code, 'no authorization code returned from IdP');

        // Step 3 — feed the callback back through the client (token exchange +
        // JWKS signature verify + ID-token claim validation).
        $_REQUEST['code']  = $_GET['code']  = $code;
        $_REQUEST['state'] = $_GET['state'] = $state;
        try {
            $this->assertTrue($client->authenticate(), 'authenticate() should succeed on the callback leg');

            $claims = $client->getVerifiedClaims();
            $this->assertSame($this->issuer, rtrim((string)$claims->iss, '/'), 'issuer mismatch');
            $this->assertSame($this->clientId, $this->audAsString($claims->aud), 'audience mismatch');
            $this->assertNotEmpty($claims->sub, 'sub (subject) must be present for account binding');
            $this->assertSame('testuser', $claims->preferred_username ?? null);
            $this->assertSame('testuser@example.com', $claims->email ?? null);
            $this->assertContains('admins', (array)($claims->groups ?? []), 'group claim should carry "admins"');
        } finally {
            unset($_REQUEST['code'], $_REQUEST['state'], $_GET['code'], $_GET['state']);
        }
    }

    /** Keycloak may emit `aud` as a string or an array; normalise for assertion. */
    private function audAsString(mixed $aud): string
    {
        return is_array($aud) ? (string)reset($aud) : (string)$aud;
    }

    /**
     * Script the Keycloak browser login: fetch the login page (cookie jar),
     * submit credentials to the form's action, and read the authorization code
     * from the redirect back to the client.
     *
     * @return array{0:string,1:string} [code, state]
     */
    private function loginAndCaptureCode(string $authUrl): array
    {
        $jar = tempnam(sys_get_temp_dir(), 'kcjar');

        $loginPage = $this->httpGet($authUrl, $jar);
        if (!preg_match('/id="kc-form-login"[^>]*?action="([^"]+)"/s', $loginPage, $m)) {
            $this->fail("Keycloak login form (id=kc-form-login) not found:\n" . substr($loginPage, 0, 800));
        }
        $action = html_entity_decode($m[1], ENT_QUOTES | ENT_HTML5);

        $location = $this->httpPostCaptureLocation($action, $jar, [
            'username'     => $this->username,
            'password'     => $this->password,
            'credentialId' => '',
        ]);
        @unlink($jar);

        $this->assertNotEmpty($location, 'Keycloak did not redirect after login (bad credentials or flow change)');
        parse_str((string)parse_url($location, PHP_URL_QUERY), $q);
        return [(string)($q['code'] ?? ''), (string)($q['state'] ?? '')];
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
