<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Exception;

class KeycloakAdminError extends KeycloakException
{
    public function __construct(string $message, private readonly ?int $statusCode = null, ?\Throwable $previous = null)
    {
        parent::__construct($message, $statusCode ?? 0, $previous);
    }
    public function getStatusCode(): ?int
    {
        return $this->statusCode;
    }
}
