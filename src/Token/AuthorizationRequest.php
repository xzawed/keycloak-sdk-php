<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Token;

final readonly class AuthorizationRequest
{
    public function __construct(
        public string $url,
        public string $state,
        #[\SensitiveParameter] public string $codeVerifier,
    ) {}
}
