<?php

namespace OPNsense\Oidc;

/**
 * Pure, dependency-free helpers for the OIDC plugin.
 *
 * Logic that has no OPNsense/Phalcon runtime dependency lives here so it can be
 * unit-tested directly (see tests/). Keep this class free of `use` imports of
 * OPNsense\* classes — that is what makes it testable without the firewall
 * runtime.
 */
class OidcHelpers
{
    /**
     * Normalize a configured provider URL to its issuer root by stripping a
     * trailing `.well-known/...` discovery path if present.
     *
     * NOTE: strpos() returns false (not -1) when the needle is absent; PHP
     * coerces `false >= 0` to true, so an earlier `>= 0` check truncated every
     * URL that did not literally contain ".well-known/" to an empty string.
     * The `!== false` check is the correct guard.
     */
    public static function stripWellKnown(string $providerUrl): string
    {
        $position = strpos($providerUrl, '.well-known/');
        if ($position !== false) {
            return substr($providerUrl, 0, $position);
        }
        return $providerUrl;
    }
}
