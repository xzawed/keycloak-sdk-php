<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

interface TokenProvider
{
    /** A valid bearer access token string (reused before it expires). @throws \Xzawed\Keycloak\Exception\KeycloakException */
    public function getToken(): string;
}
