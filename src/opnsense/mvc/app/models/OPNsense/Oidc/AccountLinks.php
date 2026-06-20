<?php

namespace OPNsense\Oidc;

use OPNsense\Base\BaseModel;

/**
 * Stores bindings from a verified OIDC (issuer, subject) identity to a local
 * OPNsense username. The auth callback consults this first so a federated
 * identity always resolves to the same account it was provisioned for, immune to
 * a later username/email collision being used to take over another account.
 *
 * Persistence is the caller's responsibility: the mutating methods report whether
 * anything changed so the controller can serializeToConfig()/save() only on a
 * real change (avoid a config write on every login).
 */
class AccountLinks extends BaseModel
{
    /**
     * Local username bound to (issuer, subject), or null when unbound. Empty
     * inputs never match (a token without sub/iss must not resolve a binding).
     */
    public function findUsername(string $issuer, string $subject): ?string
    {
        if ($issuer === '' || $subject === '') {
            return null;
        }
        foreach ($this->links->link->iterateItems() as $link) {
            if ((string)$link->issuer === $issuer && (string)$link->subject === $subject) {
                $name = (string)$link->username;
                return $name !== '' ? $name : null;
            }
        }
        return null;
    }

    /**
     * True if $username is already bound to a DIFFERENT (issuer, subject) than the
     * one supplied — the signal used to refuse silently attaching this identity to
     * an account another federated identity already owns.
     */
    public function isUsernameBoundElsewhere(string $username, string $issuer, string $subject): bool
    {
        foreach ($this->links->link->iterateItems() as $link) {
            if ((string)$link->username !== $username) {
                continue;
            }
            if ((string)$link->issuer !== $issuer || (string)$link->subject !== $subject) {
                return true;
            }
        }
        return false;
    }

    /**
     * Idempotently bind (issuer, subject) to $username. Returns true when the
     * stored config changed (caller should persist), false when already current.
     */
    public function link(string $issuer, string $subject, string $username, string $provider = ''): bool
    {
        foreach ($this->links->link->iterateItems() as $link) {
            if ((string)$link->issuer === $issuer && (string)$link->subject === $subject) {
                if ((string)$link->username === $username && (string)$link->provider === $provider) {
                    return false;
                }
                $link->username = $username;
                $link->provider = $provider;
                return true;
            }
        }
        $node = $this->links->link->add();
        $node->issuer = $issuer;
        $node->subject = $subject;
        $node->username = $username;
        $node->provider = $provider;
        $node->created = (string)time();
        return true;
    }

    /** Remove any link for (issuer, subject). Returns true if something was removed. */
    public function unlink(string $issuer, string $subject): bool
    {
        $removed = false;
        foreach ($this->links->link->iterateItems() as $uuid => $link) {
            if ((string)$link->issuer === $issuer && (string)$link->subject === $subject) {
                $this->links->link->del($uuid);
                $removed = true;
            }
        }
        return $removed;
    }
}
