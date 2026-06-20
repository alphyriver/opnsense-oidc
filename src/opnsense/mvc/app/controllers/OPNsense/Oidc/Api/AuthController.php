<?php

namespace OPNsense\Oidc\Api;

use InvalidArgumentException;
use OPNsense\Auth\AuthenticationFactory;
use OPNsense\Auth\OIDC;
use OPNsense\Auth\User;
use OPNsense\Base\ApiControllerBase;
use OPNsense\Base\FieldTypes\ArrayField;
use OPNsense\Core\Backend;
use OPNsense\Core\Config;
use OPNsense\Oidc\AccountLinks;
use OPNsense\Oidc\OidcClient;
use OPNsense\Oidc\OidcHelpers;
use RuntimeException;

/**
 * Class ServiceController
 * @package OPNsense\Cron
 */
class AuthController extends ApiControllerBase
{
    const ALLOW_USER_CREATION = true;
    const SESSION_AUTH_PROVIDER = 'openid_connect_provider';
    const ICON_CACHE_DIR = '/var/cache/oidc-icons';
    const ICON_CACHE_TTL = 86400;   // 24h server-side freshness
    const ICON_FETCH_TIMEOUT = 3;   // seconds; bound login-page latency on a cold fetch

    /** @var OidcClient|null last client used by authenticate(); holds the verified ID token */
    protected $oidcClient = null;

    public function doAuth()
    {
        return true;
    }

    public function iconAction()
    {
        $provider = $this->request->get('provider');
        if (empty($provider)) {
            $this->response->setStatusCode(400, "Bad Request");
            return "Missing authentication provider.";
        }

        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth == null || $auth->getType() !== 'oidc') {
            $this->response->setStatusCode(404, "Not Found");
            return "Authentication provider not found.";
        }

        $url = $auth->oidcIconUrl;
        if (empty($url) || !filter_var($url, FILTER_VALIDATE_URL)) {
            $this->response->setStatusCode(404, "Not Found");
            return "Invalid icon URL.";
        }

        // Explicit scheme allowlist (defense in depth on top of FILTER_VALIDATE_URL).
        $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
        if (!in_array($scheme, ['http', 'https'], true)) {
            $this->response->setStatusCode(404, "Not Found");
            return "Invalid icon URL.";
        }

        $cacheFile = self::ICON_CACHE_DIR . '/' . OidcHelpers::iconCacheKey($provider);

        // Serve a fresh cached icon with no network round-trip, so the login page
        // render isn't tied to a third-party host on every load.
        $cached = $this->readIconCache($cacheFile, self::ICON_CACHE_TTL);
        if ($cached !== null) {
            return $this->emitIcon($cached['mime'], $cached['data']);
        }

        // Cold fetch with a short timeout to bound login-page latency. On failure,
        // serve a stale cache if we have one, otherwise fail to no icon (the login
        // button degrades to text) rather than blocking the page render.
        $fetched = $this->fetchIcon($url);
        if ($fetched === null) {
            $stale = $this->readIconCache($cacheFile, PHP_INT_MAX);
            if ($stale !== null) {
                return $this->emitIcon($stale['mime'], $stale['data']);
            }
            $this->response->setStatusCode(404, "Not Found");
            return "Unable to fetch icon.";
        }

        $this->writeIconCache($cacheFile, $fetched['mime'], $fetched['data']);
        return $this->emitIcon($fetched['mime'], $fetched['data']);
    }

    /**
     * Fetch an icon URL with SSRF/DoS hardening (admin-configured, unauthenticated
     * endpoint, runs on a firewall). Returns ['mime','data'] or null on any failure.
     *  - cap redirects and restrict (redirect) protocols to http/https,
     *  - cap the response size to avoid a memory-pressure DoS,
     *  - reject responses resolved from internal/reserved addresses, so a
     *    configured https URL can't redirect to an internal target.
     */
    private function fetchIcon(string $url): ?array
    {
        $maxBytes = 1024 * 1024; // 1 MB
        $buffer = '';
        $tooLarge = false;
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
        curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        curl_setopt($ch, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        curl_setopt($ch, CURLOPT_TIMEOUT, self::ICON_FETCH_TIMEOUT);
        curl_setopt($ch, CURLOPT_WRITEFUNCTION, function ($ch, $chunk) use (&$buffer, &$tooLarge, $maxBytes) {
            $buffer .= $chunk;
            if (strlen($buffer) > $maxBytes) {
                $tooLarge = true;
                return 0; // abort the transfer
            }
            return strlen($chunk);
        });
        curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $mimeType = curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $finalIp = (string)curl_getinfo($ch, CURLINFO_PRIMARY_IP);
        curl_close($ch);

        if ($tooLarge) {
            return null;
        }
        if ($finalIp !== '' && OidcHelpers::isBlockedAddress($finalIp)) {
            return null;
        }
        if ($buffer === '' || $httpCode !== 200) {
            return null;
        }
        return ['mime' => ($mimeType ?: 'application/octet-stream'), 'data' => $buffer];
    }

    /** Read a cached icon if present and newer than $ttl seconds, else null. */
    private function readIconCache(string $cacheFile, int $ttl): ?array
    {
        if (!is_file($cacheFile) || (time() - (int)@filemtime($cacheFile)) >= $ttl) {
            return null;
        }
        $raw = @file_get_contents($cacheFile);
        if ($raw === false) {
            return null;
        }
        $data = @unserialize($raw, ['allowed_classes' => false]);
        if (!is_array($data) || !isset($data['mime'], $data['data'])) {
            return null;
        }
        return $data;
    }

    /** Atomically write an icon to the cache (best-effort). */
    private function writeIconCache(string $cacheFile, string $mime, string $data): void
    {
        if (!is_dir(self::ICON_CACHE_DIR)) {
            @mkdir(self::ICON_CACHE_DIR, 0750, true);
        }
        $tmp = $cacheFile . '.' . getmypid() . '.tmp';
        if (@file_put_contents($tmp, serialize(['mime' => $mime, 'data' => $data]), LOCK_EX) !== false) {
            @rename($tmp, $cacheFile);
        }
    }

    /** Emit an icon response with caching headers. */
    private function emitIcon(string $mime, string $data): string
    {
        $this->response->setHeader('Content-Type', $mime);
        // The server-side cache (ICON_CACHE_TTL) is the source of truth; allow a
        // modest browser cache so icon changes still propagate within a day.
        $this->response->setHeader('Cache-Control', 'public, max-age=86400');
        return $data;
    }

    /**
     * reconfigure HelloWorld
     */
    public function loginAction()
    {
        if ($this->session->get('Username') != null) {
            $this->response->setStatusCode(400, "Bad Request");
            return "Already logged in.";
        }

        // Set the provider in the session
        $provider = $this->request->get('provider');
        if (empty($provider)) {
            $this->response->setStatusCode(400, "Bad Request");
            return "Missing authentication provider.";
        }
        $this->session->set(self::SESSION_AUTH_PROVIDER, $provider);

        // Authenticate
        try {
            $auth = $this->getAuthProvider($provider);
            $user = $this->authenticate($auth);
        } catch (\Exception $e) {
            $this->response->setStatusCode(500, "Server Error");
            return "Unable to authenticate: " . $e->getMessage();
        }

        $this->session->close();
        if ($user === false)
            return 'Redirecting...';

        return "Already logged in but session not setup. Please try again";
    }


    public function callbackAction()
    {
        if ($this->session->get('Username') != null) {
            $this->response->setStatusCode(400, "Bad Request");
            return "Already logged in.";
        }

        // Get the provider from the session
        $provider = $this->session->get(self::SESSION_AUTH_PROVIDER);
        if (empty($provider)) {
            $this->response->setStatusCode(404, "Authentication not found");
            return "Missing authentication provider. Please try the flow again.";
        }
        $this->session->remove(self::SESSION_AUTH_PROVIDER);

        // Check the OIDC flow
        $auth = $this->getAuthProvider($provider);
        if ($auth === null)
            return "Authentication provider not found. Please try the flow again.";

        try {
            $user = $this->authenticate($auth);
            if ($user === false) {
                $this->response->setStatusCode(400, "Authentication not found");
                return "Something went wrong while trying to login you in";
            }
        } catch (\Exception $e) {
            $this->response->setStatusCode(500, "Server Error");
            return "Unable to authenticate: " . $e->getMessage();
        }

        // Resolve the local account. Prefer the verified (issuer, subject) binding
        // from the ID token: it is the stable, IdP-asserted identity and cannot be
        // displaced by a username/email collision. Fall back to username/email
        // matching only for identities not yet bound. See
        // OidcHelpers::decideAccountResolution() for the (pure, tested) branching.
        $subject = '';
        $issuer  = '';
        try {
            $subject = (string)($this->oidcClient->getVerifiedClaims('sub') ?? '');
            $issuer  = (string)($this->oidcClient->getVerifiedClaims('iss') ?? '');
        } catch (\Exception $e) {
            // No verified ID token claims available; fall back to legacy matching.
        }
        $verified = ($subject !== '' && $issuer !== '');

        $links         = new AccountLinks();
        $boundUsername = $verified ? $links->findUsername($issuer, $subject) : null;
        $boundUser     = $boundUsername !== null ? $this->findLocalUserByName($boundUsername) : false;

        // Drop a stale binding whose account was deleted, so the identity can be
        // re-provisioned below rather than failing forever.
        if ($boundUsername !== null && $boundUser === false) {
            if ($links->unlink($issuer, $subject)) {
                $links->serializeToConfig();
                Config::getInstance()->save();
            }
        }

        // Username/email fallback facts (with email-local-part fallback, e.g.
        // Microsoft Entra ID v2.0 UserInfo omits preferred_username).
        $claimValue     = $user->{$auth->oidcUsernameClaim} ?? null;
        $lookupEmail    = $user->email ?? null;
        $lookupUsername = OidcHelpers::deriveUsername(
            is_string($claimValue) ? $claimValue : null,
            is_string($lookupEmail) ? $lookupEmail : null
        );
        $fallbackUser   = $this->findLocalUser($lookupUsername, $lookupEmail);
        $fallbackBoundElsewhere = ($fallbackUser !== false && $verified)
            ? $links->isUsernameBoundElsewhere((string)$fallbackUser->name, $issuer, $subject)
            : false;

        $action = OidcHelpers::decideAccountResolution(
            $verified,
            $boundUsername !== null,
            $boundUser !== false,
            $fallbackUser !== false,
            $fallbackBoundElsewhere
        );

        switch ($action) {
            case OidcHelpers::RESOLVE_USE_BOUND:
                $localUser = $boundUser;
                break;
            case OidcHelpers::RESOLVE_DENY_CONFLICT:
                $this->response->setStatusCode(403, "Account conflict");
                return "This local account is already linked to a different identity.";
            case OidcHelpers::RESOLVE_USE_FALLBACK:
                $localUser = $fallbackUser;
                $this->bindIdentity($links, $issuer, $subject, (string)$localUser->name, $provider);
                break;
            case OidcHelpers::RESOLVE_CREATE:
            default:
                if (!self::ALLOW_USER_CREATION || !$auth->oidcCreateUsers) {
                    $this->response->setStatusCode(403, "User not found");
                    return "No matching local account, and user creation disabled.";
                }
                $localUser = $this->createLocalUser($lookupUsername, $lookupEmail, $user->name ?? '', $auth->oidcDefaultGroups);
                if ($localUser === false) {
                    $this->response->setStatusCode(500, "User creation failed");
                    return "Unable to create local account.";
                }
                $this->bindIdentity($links, $issuer, $subject, (string)$localUser->name, $provider);
                break;
        }

        // Live group synchronization (opt-in). When a group claim is configured the
        // provider is authoritative over the user's group membership: reconcile it
        // to the claim (plus the configured default groups) on every login. Disabled
        // when the field is blank, preserving the create-time-only group behavior.
        $groupClaim = (string)$auth->oidcGroupClaim;
        if ($groupClaim !== '') {
            $claimValue = $user->{$groupClaim} ?? null;
            if ($claimValue === null) {
                try {
                    $claimValue = $this->oidcClient->getVerifiedClaims($groupClaim);
                } catch (\Exception $e) {
                    $claimValue = null;
                }
            }
            $this->syncUserGroups(
                $localUser,
                OidcHelpers::normalizeGroupClaim($claimValue),
                $auth->oidcDefaultGroups
            );
        }

        // SECURITY NOTE (session fixation): ideally the session ID would be
        // regenerated here on privilege elevation. OPNsense's Session wrapper
        // (OPNsense\Mvc\Session) exposes no regeneration API, and its
        // read-then-abort / write-on-close lifecycle makes a safe in-plugin
        // rotation fragile (cookie/id mismatch within one request). OPNsense
        // core's own local-password login does not regenerate the session ID
        // either, so this is a core-level gap that affects every auth backend,
        // not something this plugin should work around in isolation. Tracked for
        // an upstream fix to OPNsense\Mvc\Session rather than a fragile local hack.

        // Create the main login session and log the user in.
        $username = (string)$localUser->name;
        $cnf = Config::getInstance()->object();
        $this->session->set('Username', strval($username));
        $this->session->set('last_access', time());
        $this->session->set('protocol', strval($cnf->system->webgui->protocol));
        $this->session->set('oidc_user', $user);
        $this->session->close();
        $this->response->redirect('/');
        return 'Redirecting home...';
    }

    protected function getAuthProvider($provider): OIDC|null
    {
        $auth = (new AuthenticationFactory())->get($provider);
        if ($auth == null || $auth->getType() !== 'oidc') {
            $this->response->setStatusCode(404, "Authentication not found");
            return null;
        }
        return $auth;
    }

    protected function authenticate($auth)
    {
        /** @var OIDC $auth */
        $client = new OidcClient($auth, $this);
        $this->oidcClient = $client;
        $client->addScope($auth->oidcScopes);

        if (!$client->authenticate())
            return false;

        $user = $client->requestUserInfo();
        return $user;
    }

    /** Finds the local user that best matches the given username or email. */
    protected function findLocalUser($username, $email)
    {
        $cnf = Config::getInstance()->object();
        if (empty($cnf->system) || empty($cnf->system->user)) {
            return false;
        }

        foreach ($cnf->system->user as $user) {
            if (($username && (string)$user->name === $username) ||
                ($email && isset($user->email) && (string)$user->email === $email)
            ) {
                return $user;
            }
        }

        return false;
    }

    /** Finds the local user with exactly this username (used for binding lookups). */
    protected function findLocalUserByName(string $username)
    {
        if ($username === '') {
            return false;
        }
        $cnf = Config::getInstance()->object();
        if (empty($cnf->system) || empty($cnf->system->user)) {
            return false;
        }
        foreach ($cnf->system->user as $user) {
            if ((string)$user->name === $username) {
                return $user;
            }
        }
        return false;
    }

    /**
     * Persist a verified (issuer, subject) -> username binding, but only when the
     * identity is verified and the stored link actually changes — so a normal
     * login of an already-bound account performs no config write (honors the
     * write-only-on-change discipline).
     */
    protected function bindIdentity(AccountLinks $links, string $issuer, string $subject, string $username, string $provider): void
    {
        if ($issuer === '' || $subject === '') {
            return;
        }
        if ($links->link($issuer, $subject, $username, $provider)) {
            $links->serializeToConfig();
            Config::getInstance()->save();
        }
    }

    /**
     * Reconcile a user's local group membership to the provider-asserted groups
     * (plus configured defaults). Writes config only when membership actually
     * changes, so a login that matches the current state is a no-op (honors the
     * write-only-on-change discipline). Only existing local groups are ever
     * granted; the claim cannot create groups.
     */
    protected function syncUserGroups($localUser, array $claimGroups, array $defaultGroups): void
    {
        $cnf = Config::getInstance()->object();
        if (empty($cnf->system) || empty($cnf->system->group)) {
            return;
        }

        // Resolve the uid (a freshly created user model may not expose it yet;
        // fall back to a name lookup against the reloaded config).
        $uid   = (string)$localUser->uid;
        $uname = (string)$localUser->name;
        if ($uid === '' && $uname !== '') {
            $byName = $this->findLocalUserByName($uname);
            if ($byName !== false) {
                $uid = (string)$byName->uid;
            }
        }
        if ($uid === '') {
            return;
        }

        $existing = [];
        $current  = [];
        foreach ($cnf->system->group as $group) {
            $gname      = (string)$group->name;
            $existing[] = $gname;
            if (in_array($uid, $this->groupMembers($group), true)) {
                $current[] = $gname;
            }
        }

        $plan = OidcHelpers::reconcileGroups($claimGroups, $defaultGroups, $existing, $current);
        if (empty($plan['add']) && empty($plan['remove'])) {
            return;
        }

        $addLower    = array_map('strtolower', $plan['add']);
        $removeLower = array_map('strtolower', $plan['remove']);
        foreach ($cnf->system->group as $group) {
            $glower   = strtolower((string)$group->name);
            $inAdd    = in_array($glower, $addLower, true);
            $inRemove = in_array($glower, $removeLower, true);
            if (!$inAdd && !$inRemove) {
                continue;
            }
            $members = $this->groupMembers($group);
            if ($inAdd) {
                if (!in_array($uid, $members, true)) {
                    $members[] = $uid;
                }
            } else {
                $members = array_values(array_filter($members, fn($m) => $m !== $uid));
            }
            // Rewrite as a single comma-joined <member> element, matching the
            // format OPNsense stores group memberships in.
            unset($group->member);
            if (!empty($members)) {
                $group->addChild('member', implode(',', $members));
            }
        }

        Config::getInstance()->save();
        (new Backend())->configdpRun('auth user changed', [$uname]);
    }

    /** Flatten a group's member element(s) into a list of uid strings. */
    private function groupMembers($group): array
    {
        $members = [];
        foreach ($group->member as $member) {
            $members = array_merge($members, array_filter(explode(',', (string)$member)));
        }
        return $members;
    }


    /** Creates a new local user. */
    protected function createLocalUser($username, $email, $displayName = '', $sync_groups = [])
    {
        if (!self::ALLOW_USER_CREATION)
            return false;

        if (empty($username))
            return false;

        // Create the user using a Model
        $mdl = new User();

        /** @var ArrayField $users */
        $users = $mdl->user;
        $user = $users->add();
        $user->name     = $username;
        $user->email    = $email ?? '';
        $user->descr    = $displayName ?? $username;
        $user->comment  = "Created with OpenID Connect";
        // "scrambled_password" is OPNsense's documented mechanism for accounts
        // that exist for authorization but cannot authenticate locally (the same
        // mechanism used for API-only / externally-authenticated users), so this
        // user can only ever log in via OIDC. Generate a random local password
        // too (instead of a shared constant) so that even if the scramble flag is
        // ever cleared elsewhere, these accounts don't collapse to one known
        // password. Do NOT leave this empty or remove the scramble flag.
        $user->password = bin2hex(random_bytes(16));
        $user->scrambled_password = "1";
        $user->scope    = "user";
        $user->disabled = "0";

        if (!$mdl->serializeToConfig())
            return false;

        Config::getInstance()->save();
        (new Backend())->configdpRun('auth sync user', [$user->name]);

        // Set the group
        if (count($sync_groups) > 0) {
            $cnf = Config::getInstance()->object();
            foreach ($cnf->system->group as $group) {
                $groupName = strtolower((string)$group->name);
                if (!in_array($groupName, $sync_groups))
                    continue;

                $members = [];
                foreach ($group->member as $member) {
                    $members = array_merge($members, explode(',', $member));
                }

                if (in_array((string)$user->uid, $members)) {
                    // Already in group
                } else {
                    syslog(LOG_NOTICE, sprintf(
                        'User: policy change for %s link group %s',
                        $username,
                        (string)$group->name
                    ));
                    $group->member = implode(',', array_merge($members, [(string)$user->uid]));
                }
            }
            Config::getInstance()->save();
            (new Backend())->configdpRun("auth user changed", [$user->name]);
        }

        Config::getInstance()->forceReload();
        return $user;
    }
}
