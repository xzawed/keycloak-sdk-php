<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Internal;

use Stevenmaguire\OAuth2\Client\Provider\Keycloak;

/**
 * stevenmaguire Keycloak 프로바이더는 pkceMethod 옵션을 무시한다(getPkceMethod()가 null 반환).
 * 이 서브클래스가 S256 PKCE를 강제한다. @internal
 */
final class PkceKeycloakProvider extends Keycloak
{
    protected function getPkceMethod(): string
    {
        return self::PKCE_METHOD_S256;
    }
}
