<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Token;

use Xzawed\Keycloak\Masking;

/**
 * ⚠️ 마스킹을 __toString 에만 걸면 PHP 의 **기본 직렬화기**가 그것을 우회한다 — 승격된
 * 프로퍼티가 public 이라 json_encode() 가 원문을 뱉는다. 그래서 JsonSerializable 을 함께 구현한다.
 * 한계: var_dump()/print_r()/var_export() 는 여전히 프로퍼티를 직접 읽는다(언어 차원의 경계다 —
 * .NET 의 Serilog {@} 파괴적 로깅, Node 의 구조분해와 같은 부류). 과대광고하지 말 것.
 */
final readonly class TokenSet implements \JsonSerializable
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

    /**
     * ⚠️ **만료 시각을 모르면 "만료됨"이다**(fail-safe — 자매 여덟과 동형, Java 의 M.6).
     *
     * `false`(=아직 살아있다)를 돌려주면 `ClientCredentialsTokenProvider` 가 만료 시각 미상인
     * 토큰을 **영원히 캐시에서 재사용**한다(그 자리의 조건이 `!$this->cached->isExpired(...)` 다).
     * `expiresAt` 이 null 인 경우는 서버가 `expires_in` 을 안 보냈을 때뿐이라 정상 경로가 아니고,
     * 그때 취할 안전한 쪽은 "재발급"이다.
     */
    public function isExpired(?int $now = null, int $skew = 30): bool
    {
        if ($this->expiresAt === null) {
            return true;
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

    /** @return array<string,mixed> */
    public function jsonSerialize(): array
    {
        return [
            'tokenType' => $this->tokenType,
            'expiresIn' => $this->expiresIn,
            'expiresAt' => $this->expiresAt,
            'scope' => $this->scope,
            'accessToken' => Masking::mask($this->accessToken),
            'refreshToken' => Masking::mask($this->refreshToken),
            'idToken' => Masking::mask($this->idToken),
        ];
    }
}
