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
}
