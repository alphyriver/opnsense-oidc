<?php

namespace OPNsense\Oidc\Tests;

use OPNsense\Oidc\OidcHelpers;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class OidcHelpersTest extends TestCase
{
    /**
     * A provider URL without a ".well-known/" segment must be returned
     * unchanged. This is the regression that the old `>= 0` check broke:
     * strpos() returns false, and `false >= 0` is true in PHP, so such URLs
     * were truncated to "".
     */
    #[DataProvider('rootUrls')]
    public function testRootUrlsAreReturnedUnchanged(string $url): void
    {
        $this->assertSame($url, OidcHelpers::stripWellKnown($url));
    }

    public static function rootUrls(): array
    {
        return [
            'plain host'        => ['https://idp.example.com/'],
            'no trailing slash' => ['https://idp.example.com'],
            'with path'         => ['https://idp.example.com/realms/main'],
            'empty string'      => [''],
        ];
    }

    /**
     * A provider URL that includes the discovery path must be truncated back
     * to the issuer root.
     */
    #[DataProvider('discoveryUrls')]
    public function testDiscoveryPathIsStripped(string $url, string $expected): void
    {
        $this->assertSame($expected, OidcHelpers::stripWellKnown($url));
    }

    public static function discoveryUrls(): array
    {
        return [
            'openid-configuration' => [
                'https://idp.example.com/.well-known/openid-configuration',
                'https://idp.example.com/',
            ],
            'realm discovery' => [
                'https://idp.example.com/realms/main/.well-known/openid-configuration',
                'https://idp.example.com/realms/main/',
            ],
        ];
    }

    #[DataProvider('usernameCases')]
    public function testDeriveUsername(?string $claim, ?string $email, ?string $expected): void
    {
        $this->assertSame($expected, OidcHelpers::deriveUsername($claim, $email));
    }

    public static function usernameCases(): array
    {
        return [
            'claim present'                 => ['alice', 'alice@example.com', 'alice'],
            'claim wins over email'         => ['bob', 'other@example.com', 'bob'],
            'empty claim falls back'        => ['', 'carol@example.com', 'carol'],
            'null claim falls back'         => [null, 'dave@sub.example.com', 'dave'],
            'no claim, no email'            => [null, null, null],
            'no claim, empty email'         => ['', '', null],
            'email without local-part'      => [null, '@example.com', null],
            'email without at-sign'         => [null, 'not-an-email', null],
        ];
    }

    #[DataProvider('addressCases')]
    public function testIsBlockedAddress(string $ip, bool $blocked): void
    {
        $this->assertSame($blocked, OidcHelpers::isBlockedAddress($ip));
    }

    public static function addressCases(): array
    {
        return [
            'public v4'        => ['8.8.8.8', false],
            'loopback v4'      => ['127.0.0.1', true],
            'rfc1918 10'       => ['10.0.0.5', true],
            'rfc1918 192.168'  => ['192.168.1.1', true],
            'rfc1918 172.16'   => ['172.16.0.1', true],
            'link-local v4'    => ['169.254.169.254', true],
            'loopback v6'      => ['::1', true],
            'ula v6'           => ['fd00::1', true],
            'public v6'        => ['2606:4700:4700::1111', false],
            'not an ip'        => ['example.com', false],
        ];
    }

    public function testIconCacheKeyIsStableAndFilesystemSafe(): void
    {
        $key = OidcHelpers::iconCacheKey('keycloak');
        $this->assertSame('icon_' . sha1('keycloak'), $key);
        // A malicious provider name must not produce path-traversal characters.
        $evil = OidcHelpers::iconCacheKey('../../etc/passwd');
        $this->assertMatchesRegularExpression('/^icon_[0-9a-f]{40}$/', $evil);
        $this->assertStringNotContainsString('/', $evil);
        $this->assertStringNotContainsString('.', substr($evil, 5));
    }

    /**
     * @param array{bool,bool,bool,bool,bool} $facts ordered as the method args:
     *   verified, haveBoundLink, boundUserExists, fallbackUserExists, fallbackBoundElsewhere
     */
    #[DataProvider('resolutionCases')]
    public function testDecideAccountResolution(array $facts, string $expected): void
    {
        $this->assertSame($expected, OidcHelpers::decideAccountResolution(...$facts));
    }

    public static function resolutionCases(): array
    {
        return [
            // A live verified binding always wins, even when a different account
            // matches by username/email (the takeover case the binding defends).
            'bound live account' =>
                [[true, true, true, true, true], OidcHelpers::RESOLVE_USE_BOUND],
            'bound live account, no fallback' =>
                [[true, true, true, false, false], OidcHelpers::RESOLVE_USE_BOUND],

            // Bound link whose account was deleted -> treat as unbound, fall back.
            'stale bound link, fallback exists' =>
                [[true, true, false, true, false], OidcHelpers::RESOLVE_USE_FALLBACK],
            'stale bound link, no fallback -> create' =>
                [[true, true, false, false, false], OidcHelpers::RESOLVE_CREATE],

            // Unbound verified identity matching an account already owned by a
            // different identity must be refused (account-takeover guard).
            'unbound, fallback owned elsewhere -> deny' =>
                [[true, false, false, true, true], OidcHelpers::RESOLVE_DENY_CONFLICT],
            'unbound, fallback free -> use + link' =>
                [[true, false, false, true, false], OidcHelpers::RESOLVE_USE_FALLBACK],
            'unbound, no fallback -> create + link' =>
                [[true, false, false, false, false], OidcHelpers::RESOLVE_CREATE],

            // Without a verified identity we cannot bind; legacy username/email
            // behavior, and the conflict guard does not apply (no identity to own).
            'unverified, fallback exists' =>
                [[false, false, false, true, true], OidcHelpers::RESOLVE_USE_FALLBACK],
            'unverified, no fallback -> create' =>
                [[false, false, false, false, false], OidcHelpers::RESOLVE_CREATE],
        ];
    }
}
