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

    /** Log in as the live account bound to this (issuer, subject). */
    public const RESOLVE_USE_BOUND = 'use_bound';
    /** Refuse: the username/email match belongs to a different federated identity. */
    public const RESOLVE_DENY_CONFLICT = 'deny_conflict';
    /** Use the username/email match (and link it to this identity when verified). */
    public const RESOLVE_USE_FALLBACK = 'use_fallback';
    /** No match: create the account (and link it when verified). */
    public const RESOLVE_CREATE = 'create';

    /**
     * Decide how to resolve an OIDC login to a local account. Pure so the
     * security-critical branching is unit-testable in isolation from the config
     * store and user database; the controller gathers the facts and applies the
     * returned action (which account to use, and whether to persist a link).
     *
     * Precedence: a verified (issuer, subject) binding to a live account always
     * wins — it is the IdP-asserted identity and cannot be displaced by a
     * username/email collision. Only when there is no usable binding do we fall
     * back to username/email matching, and then a verified identity must not
     * attach to an account already owned by a different (issuer, subject).
     *
     * @param bool $verified              we have a non-empty, verified issuer+subject
     * @param bool $haveBoundLink         a stored link exists for this (issuer, subject)
     * @param bool $boundUserExists       the bound link's local account still exists
     * @param bool $fallbackUserExists    username/email matched an existing local account
     * @param bool $fallbackBoundElsewhere that matched account is bound to a different identity
     * @return string one of the RESOLVE_* constants
     */
    public static function decideAccountResolution(
        bool $verified,
        bool $haveBoundLink,
        bool $boundUserExists,
        bool $fallbackUserExists,
        bool $fallbackBoundElsewhere
    ): string {
        if ($verified && $haveBoundLink && $boundUserExists) {
            return self::RESOLVE_USE_BOUND;
        }
        if ($fallbackUserExists) {
            if ($verified && $fallbackBoundElsewhere) {
                return self::RESOLVE_DENY_CONFLICT;
            }
            return self::RESOLVE_USE_FALLBACK;
        }
        return self::RESOLVE_CREATE;
    }

    /**
     * Normalize a group claim value into a flat list of non-empty group names.
     * IdPs send groups either as a JSON array or as a single delimited string
     * (space- or comma-separated, e.g. SAML-style or a scope-like string), so
     * accept both. Non-string scalars are stringified; anything else is dropped.
     *
     * @param mixed $value the raw claim value from the token/userinfo
     * @return string[] trimmed, non-empty group names (order preserved, as-sent)
     */
    public static function normalizeGroupClaim($value): array
    {
        if ($value === null) {
            return [];
        }
        $items = is_array($value) ? $value : preg_split('/[,\s]+/', (string)$value);
        $groups = [];
        foreach ($items as $item) {
            if (is_array($item) || is_object($item)) {
                continue;
            }
            $name = trim((string)$item);
            if ($name !== '') {
                $groups[] = $name;
            }
        }
        return $groups;
    }

    /**
     * Compute the group-membership changes for a user when the provider is
     * authoritative over groups. Pure so the reconcile logic is unit-testable
     * apart from the OPNsense config store.
     *
     * Desired membership = local groups whose name matches a claim group OR a
     * configured default group (matched case-insensitively). The user is added to
     * desired groups they lack and removed from any other group they are in
     * (default groups are part of "desired" and so are never removed). Only
     * groups that actually exist locally are ever granted; the claim cannot
     * conjure new groups.
     *
     * @param string[] $claimGroups    group names asserted by the provider
     * @param string[] $defaultGroups  admin-configured default groups (always kept)
     * @param string[] $existingGroups all local group names (canonical casing)
     * @param string[] $currentGroups  the user's current local group names
     * @return array{add: string[], remove: string[]} canonical group names to add / remove
     */
    public static function reconcileGroups(
        array $claimGroups,
        array $defaultGroups,
        array $existingGroups,
        array $currentGroups
    ): array {
        // Map lowercased name -> canonical local name (existing groups only).
        $canonical = [];
        foreach ($existingGroups as $name) {
            $name = (string)$name;
            if ($name !== '') {
                $canonical[strtolower($name)] = $name;
            }
        }

        // Desired lowercased keys = (claim ∪ defaults) restricted to existing groups.
        $desired = [];
        foreach (array_merge($claimGroups, $defaultGroups) as $name) {
            $key = strtolower(trim((string)$name));
            if ($key !== '' && isset($canonical[$key])) {
                $desired[$key] = $canonical[$key];
            }
        }

        $currentKeys = [];
        foreach ($currentGroups as $name) {
            $currentKeys[strtolower((string)$name)] = (string)$name;
        }

        $add = [];
        foreach ($desired as $key => $name) {
            if (!isset($currentKeys[$key])) {
                $add[] = $name;
            }
        }

        $remove = [];
        foreach ($currentKeys as $key => $name) {
            if (!isset($desired[$key])) {
                $remove[] = $name;
            }
        }

        return ['add' => $add, 'remove' => $remove];
    }
}
