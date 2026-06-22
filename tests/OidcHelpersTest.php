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
     * @param array{bool,bool,bool,bool,bool,4?:bool} $facts ordered as the method args:
     *   verified, haveBoundLink, boundUserExists, fallbackUserExists,
     *   fallbackBoundElsewhere, [strictBinding]
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

            // --- Strict binding (defense-in-depth, on by default) ---------------
            // A live verified binding still wins under strict binding.
            'strict: bound live account wins' =>
                [[true, true, true, true, true, true], OidcHelpers::RESOLVE_USE_BOUND],
            // An unbound verified identity colliding with a pre-existing local
            // account is refused (not silently linked) when strict binding is on.
            'strict: unbound verified fallback -> deny' =>
                [[true, false, false, true, false, true], OidcHelpers::RESOLVE_DENY_STRICT],
            // A stale bound link plus a fallback collision is likewise refused.
            'strict: stale bound link, fallback -> deny' =>
                [[true, true, false, true, false, true], OidcHelpers::RESOLVE_DENY_STRICT],
            // No collision -> still free to create a brand-new account.
            'strict: no fallback -> create' =>
                [[true, false, false, false, false, true], OidcHelpers::RESOLVE_CREATE],
            // Strict binding refuses adoption even for an unverified login.
            'strict: unverified fallback -> deny' =>
                [[false, false, false, true, false, true], OidcHelpers::RESOLVE_DENY_STRICT],
            // The "owned by a different identity" conflict still takes precedence
            // over the generic strict refusal (more specific error first).
            'strict: fallback owned elsewhere -> deny conflict' =>
                [[true, false, false, true, true, true], OidcHelpers::RESOLVE_DENY_CONFLICT],
        ];
    }

    #[DataProvider('groupClaimCases')]
    public function testNormalizeGroupClaim($value, array $expected): void
    {
        $this->assertSame($expected, OidcHelpers::normalizeGroupClaim($value));
    }

    public static function groupClaimCases(): array
    {
        return [
            'json array'        => [['admins', 'users'], ['admins', 'users']],
            'comma string'      => ['admins,users', ['admins', 'users']],
            'space string'      => ['admins users', ['admins', 'users']],
            'mixed whitespace'  => ["admins,  users\tops", ['admins', 'users', 'ops']],
            'trims and drops'   => [[' admins ', '', 'users'], ['admins', 'users']],
            'nested dropped'    => [['admins', ['x'], 'users'], ['admins', 'users']],
            'null'              => [null, []],
            'empty string'      => ['', []],
            'scalar int'        => [42, ['42']],
        ];
    }

    /**
     * @param array{0:string[],1:string[],2:string[],3:string[]} $args
     *   claimGroups, defaultGroups, existingGroups, currentGroups
     */
    #[DataProvider('reconcileCases')]
    public function testReconcileGroups(array $args, array $expectedAdd, array $expectedRemove): void
    {
        $plan = OidcHelpers::reconcileGroups(...$args);
        // Order is not contractual; compare as sets.
        sort($plan['add']);
        sort($plan['remove']);
        sort($expectedAdd);
        sort($expectedRemove);
        $this->assertSame($expectedAdd, $plan['add'], 'add set');
        $this->assertSame($expectedRemove, $plan['remove'], 'remove set');
    }

    public static function reconcileCases(): array
    {
        return [
            // Add the claimed group, remove the one no longer claimed.
            'add and remove' => [
                [['admins'], [], ['admins', 'users', 'ops'], ['users']],
                ['admins'], ['users'],
            ],
            // Default groups are part of "desired" and are never removed.
            'default kept' => [
                [[], ['users'], ['admins', 'users'], ['users']],
                [], [],
            ],
            // A claim naming a nonexistent group cannot grant membership.
            'nonexistent claim ignored' => [
                [['nope'], [], ['admins', 'users'], ['users']],
                [], ['users'],
            ],
            // Case-insensitive matching against canonical local casing.
            'case insensitive' => [
                [['ADMINS'], [], ['admins', 'users'], []],
                ['admins'], [],
            ],
            // Already correct -> no changes (the no-op / no-write path).
            'no change' => [
                [['admins', 'users'], [], ['admins', 'users'], ['admins', 'users']],
                [], [],
            ],
            // Empty claim with no defaults strips all current memberships
            // (authoritative provider with the user in no claimed groups).
            'empty claim strips' => [
                [[], [], ['admins', 'users'], ['admins', 'users']],
                [], ['admins', 'users'],
            ],
        ];
    }
}
