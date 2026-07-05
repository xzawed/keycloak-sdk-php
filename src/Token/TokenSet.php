<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Token;

use Xzawed\Keycloak\Masking;

final readonly class TokenSet
{
    public function __construct(
        #[\SensitiveParameter] public string $accessToken,
        public string $tokenType = 'Bearer',
        public int $expiresIn = 0,
        #[\SensitiveParameter] public ?string $refreshToken = null,
        public ?string $idToken = null,
        public ?string $scope = null,
        public ?int $expiresAt = null,
    ) {}

    /** @param array<string,mixed> $r OAuth 토큰 응답 */
    public static function fromArray(array $r, ?int $now = null): self
    {
        $now ??= \time();
        $expiresIn = isset($r['expires_in']) ? self::toInt($r['expires_in']) : 0;

        return new self(
            accessToken: self::toStr($r['access_token'] ?? null),
            tokenType: isset($r['token_type']) ? self::toStr($r['token_type']) : 'Bearer',
            expiresIn: $expiresIn,
            refreshToken: isset($r['refresh_token']) ? self::toStr($r['refresh_token']) : null,
            idToken: isset($r['id_token']) ? self::toStr($r['id_token']) : null,
            scope: isset($r['scope']) ? self::toStr($r['scope']) : null,
            expiresAt: $expiresIn > 0 ? $now + $expiresIn : null,
        );
    }

    /** mixed 값을 문자열로 안전하게 좁힌다(신뢰된 OAuth 응답의 스칼라 값만 통과). */
    private static function toStr(mixed $v, string $default = ''): string
    {
        return match (true) {
            \is_string($v) => $v,
            \is_int($v), \is_float($v), \is_bool($v) => (string) $v,
            default => $default,
        };
    }

    /** mixed 값을 정수로 안전하게 좁힌다. */
    private static function toInt(mixed $v, int $default = 0): int
    {
        return match (true) {
            \is_int($v) => $v,
            \is_float($v) => (int) $v,
            \is_string($v) && \is_numeric($v) => (int) $v,
            default => $default,
        };
    }

    public function isExpired(?int $now = null, int $skew = 30): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }
        $now ??= \time();

        return $now >= ($this->expiresAt - $skew);
    }

    public function __toString(): string
    {
        return sprintf(
            'TokenSet(tokenType=%s, expiresIn=%d, accessToken=%s, refreshToken=%s)',
            $this->tokenType,
            $this->expiresIn,
            Masking::mask($this->accessToken),
            Masking::mask($this->refreshToken),
        );
    }
}
