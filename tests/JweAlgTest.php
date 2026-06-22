<?php

/**
 * Unit tests for the JWE key-management algorithm allowlist (Jwe.php).
 *
 * RSA1_5 (RSAES-PKCS1-v1_5) is vulnerable to the Bleichenbacher / padding-oracle
 * class of attacks and must be rejected on both the decrypt and encrypt paths;
 * only the RSA-OAEP variants are permitted.
 */

declare(strict_types=1);

namespace OPNsense\Oidc\Tests;

use JakubOnderka\OpenIDConnectClient\Jwe;
use JakubOnderka\OpenIDConnectClient\Jwt;
use PHPUnit\Framework\TestCase;
use phpseclib3\Crypt\RSA;

use function JakubOnderka\base64url_encode;

// The vendored client lives under the plugin's library namespace (JakubOnderka).
// Composer autoloads phpseclib; require the lib in dependency order (matches the
// integration harness).
$lib = dirname(__DIR__) . '/src/opnsense/mvc/app/library/OPNsense/Oidc/lib';
require_once $lib . '/Jwt.php';
require_once $lib . '/Jwks.php';
require_once $lib . '/Jwe.php';
require_once $lib . '/OpenIDConnectClient.php';

final class JweAlgTest extends TestCase
{
    public function testAllowlistContainsOnlyOaepVariants(): void
    {
        $this->assertSame(
            ['RSA-OAEP', 'RSA-OAEP-256'],
            Jwe::SUPPORTED_KEY_MANAGEMENT_ALGS
        );
        $this->assertNotContains('RSA1_5', Jwe::SUPPORTED_KEY_MANAGEMENT_ALGS);
    }

    /**
     * A JWE whose `alg` header is RSA1_5 must be rejected at the allowlist gate,
     * before any RSA decryption is attempted.
     */
    public function testDecryptRejectsRsa15(): void
    {
        $header = base64url_encode('{"alg":"RSA1_5","enc":"A256GCM"}');
        // Four further (decodable) placeholder segments — the allowlist gate
        // fires before any of them are used.
        $token = $header . '.AA.AA.AA.AA';

        $key = RSA::createKey(2048);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('forbidden JWE key-management algo RSA1_5');
        (new Jwe($token))->decrypt($key);
    }

    /**
     * The encrypt path must likewise refuse to emit an RSA1_5-wrapped JWE.
     */
    public function testCreateRejectsRsa15(): void
    {
        $publicKey = RSA::createKey(2048)->getPublicKey();
        $jwt = new Jwt('eyJhbGciOiJub25lIn0.e30.');

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('Unsupported algo RSA1_5');
        Jwe::create($jwt, $publicKey, 'A256GCM', 'RSA1_5');
    }

    /**
     * Positive control: an allowed alg (RSA-OAEP) passes the allowlist gate.
     * The placeholder ciphertext then fails inside phpseclib, so we assert the
     * failure is NOT the allowlist rejection — i.e. the gate let it through.
     */
    public function testDecryptAllowsOaepPastGate(): void
    {
        $header = base64url_encode('{"alg":"RSA-OAEP","enc":"A256GCM"}');
        $token = $header . '.AA.AA.AA.AA';
        $key = RSA::createKey(2048);

        try {
            (new Jwe($token))->decrypt($key);
            $this->fail('Expected decryption of placeholder ciphertext to fail');
        } catch (\Throwable $e) {
            $this->assertStringNotContainsString('forbidden JWE key-management', $e->getMessage());
        }
    }
}
