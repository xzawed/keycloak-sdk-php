<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Token;

final readonly class IntrospectionResult
{
    /** @param array<string,mixed> $claims */
    public function __construct(
        public bool $active,
        public ?string $username = null,
        public ?string $clientId = null,
        public array $claims = [],
    ) {}

    /** @param array<string,mixed> $r RFC 7662 introspection 응답 */
    public static function fromArray(array $r): self
    {
        return new self(
            active: (bool) ($r['active'] ?? false),
            username: isset($r['username']) ? self::toStr($r['username']) : null,
            clientId: isset($r['client_id']) ? self::toStr($r['client_id']) : null,
            claims: $r,
        );
    }

    /** mixed 값을 문자열로 안전하게 좁힌다(신뢰된 introspection 응답의 스칼라 값만 통과). */
    private static function toStr(mixed $v, string $default = ''): string
    {
        return match (true) {
            \is_string($v) => $v,
            \is_int($v), \is_float($v), \is_bool($v) => (string) $v,
            default => $default,
        };
    }
}
