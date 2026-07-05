<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Token;

final readonly class ValidatedToken
{
    /**
     * @param list<string>        $audience
     * @param array<string,mixed> $claims
     */
    public function __construct(
        public string $subject,
        public array $audience,
        public string $issuer,
        public ?int $expiresAt,
        public ?int $issuedAt,
        public array $claims,
    ) {}
}
