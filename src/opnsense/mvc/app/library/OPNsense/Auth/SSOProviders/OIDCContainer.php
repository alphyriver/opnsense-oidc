<?php

namespace OPNsense\Auth\SSOProviders;

use OPNsense\Core\Config;
use Generator;

class OIDCContainer implements ISSOContainer
{
    public function listProviders(): \Generator
    {
        $cnf = Config::getInstance()->object();
        if (!isset($cnf->system->authserver))
            return;

        foreach ($cnf->system->authserver as $server) {
            if ((string)$server->type !== 'oidc')
                continue;

            $name = (string)$server->name;
            $opts = [
                'service' => 'WebGui',
                'name' => $name,
                'login_uri' => "/api/oidc/auth/login?provider={$name}",
            ];

            // Use the admin's custom button if set, otherwise a sane built-in
            // default so multi-provider login pages look consistent without every
            // admin hand-writing CSS. Fully overridable via the Custom Button field.
            $customButton = (string)$server->oidc_custom_button;
            if ($customButton === '') {
                $hasIcon = !empty((string)$server->oidc_icon_url);
                $customButton = self::defaultButton($hasIcon);
            }

            $iconUrl = "/api/oidc/auth/icon?provider={$name}";
            $opts['html_content'] = strtr($customButton, [
                '%icon%' => $iconUrl,
                '%name%' => htmlspecialchars($name, ENT_QUOTES),
                '%url%'  => $opts['login_uri'],
            ]);

            yield new OIDC($opts);
        }
    }

    /**
     * Built-in login button used when no Custom Button is configured. Full-width
     * primary button with the provider icon (when set) on a white chip so colored
     * logos stay visible. Overridable via the Custom Button setting.
     */
    private static function defaultButton(bool $hasIcon): string
    {
        $icon = $hasIcon
            ? '<img src="%icon%" alt="" style="height:1.3em;width:1.3em;margin-right:8px;'
                . 'background:#fff;border-radius:3px;padding:2px;vertical-align:middle;object-fit:contain;">'
            : '';
        return '<a href="%url%" class="btn btn-primary btn-block" '
            . 'style="margin-top:10px;display:flex;align-items:center;justify-content:center;">'
            . $icon . 'Login with %name%</a>';
    }
}
