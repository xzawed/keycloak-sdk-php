<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Exception;

final class KeycloakAuthError extends KeycloakException
{
    public function __construct(string $message, public readonly ?string $oauthError = null, ?\Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }
}
