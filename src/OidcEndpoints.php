<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

final class OidcEndpoints
{
    private string $base;

    public function __construct(KeycloakConfig $config)
    {
        $this->base = $config->serverUrl . '/realms/' . $config->realm;
    }

    public function issuer(): string
    {
        return $this->base;
    }

    public function token(): string
    {
        return $this->base . '/protocol/openid-connect/token';
    }

    public function authorization(): string
    {
        return $this->base . '/protocol/openid-connect/auth';
    }

    public function introspection(): string
    {
        return $this->base . '/protocol/openid-connect/token/introspect';
    }

    public function endSession(): string
    {
        return $this->base . '/protocol/openid-connect/logout';
    }

    public function jwks(): string
    {
        return $this->base . '/protocol/openid-connect/certs';
    }
}
