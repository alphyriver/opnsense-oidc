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

    /**
     * Derive the local username from the configured username claim, falling back
     * to the local-part of the email when the claim is empty/absent (e.g.
     * Microsoft Entra ID v2.0 UserInfo omits preferred_username).
     *
     * Computing this before the local-user lookup means an existing account is
     * matched via the fallback, not only created. Returns null when neither
     * input yields a usable value.
     */
    public static function deriveUsername(?string $claimValue, ?string $email): ?string
    {
        if (!empty($claimValue)) {
            return $claimValue;
        }
        if (!empty($email) && strpos($email, '@') !== false) {
            $local = strstr($email, '@', true);
            return ($local !== false && $local !== '') ? $local : null;
        }
        return null;
    }

    /**
     * True if the given address is a literal IP that an icon proxy running on a
     * firewall should refuse to fetch from: loopback, link-local, RFC1918/ULA
     * and other reserved ranges. Used to reject SSRF targets after cURL has
     * resolved redirects. Non-IP input returns false (hostnames are checked by
     * their resolved IP via CURLINFO_PRIMARY_IP).
     */
    public static function isBlockedAddress(string $ip): bool
    {
        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        // A valid IP that fails validation with the no-private/no-reserved flags
        // is, by definition, in a private or reserved range — block it.
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }

    /**
     * Filesystem-safe cache key for a provider's icon. A hash guarantees no path
     * traversal regardless of the provider name's contents.
     */
    public static function iconCacheKey(string $provider): string
    {
        return 'icon_' . sha1($provider);
    }
}
