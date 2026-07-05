<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

interface TokenProvider
{
    /** 유효한 bearer access token 문자열(만료 전 재사용). @throws \Xzawed\Keycloak\Exception\KeycloakException */
    public function getToken(): string;
}
