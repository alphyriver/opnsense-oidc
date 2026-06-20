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
}
