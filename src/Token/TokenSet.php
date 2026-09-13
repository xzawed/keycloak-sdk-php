<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Token;

use Xzawed\Keycloak\Exception\KeycloakAuthError;
use Xzawed\Keycloak\Masking;

/**
 * ⚠️ 마스킹을 __toString 에만 걸면 PHP 의 **기본 직렬화기**가 그것을 우회한다 — 승격된
 * 프로퍼티가 public 이라 json_encode() 가 원문을 뱉는다. 그래서 JsonSerializable 을 함께 구현한다.
 * 한계: __debugInfo() 가 var_dump()/print_r()/debug_zval_dump() 를 덮지만 **var_export() 는
 * 덮지 못한다**(PHP 8.3.32 실측 — private 프로퍼티까지 원문으로 찍는다). get_object_vars()·
 * (array) 캐스트·foreach·공개 프로퍼티 읽기도 경계 밖이다. 과대광고하지 말 것 — 이것은
 * 우발적 로깅에 대한 심층 방어이지 기밀 경계가 아니다.
 */
final readonly class TokenSet implements \JsonSerializable
{
    public function __construct(
        #[\SensitiveParameter] public string $accessToken,
        public string $tokenType = 'Bearer',
        public int $expiresIn = 0,
        #[\SensitiveParameter] public ?string $refreshToken = null,
        #[\SensitiveParameter] public ?string $idToken = null,
        public ?string $scope = null,
        public ?int $expiresAt = null,
    ) {
        // ⚠️ **검증은 팩토리가 아니라 생성자에 있다.** `fromArray` 에만 두면 `AuthClient`
        // 의 `toTokenSet()` 이 `new TokenSet(...)` 를 직접 불러 그것을 통째로 우회한다
        // (독립 레그가 지목한 구멍). 타입은 PHP 가 강제하므로 여기서 막는 것은 **빈 값**이다.
        if ('' === $this->accessToken) {
            throw new KeycloakAuthError('token response has no usable access_token');
        }
    }

    /** @param array<string,mixed> $r OAuth 토큰 응답 */
    public static function fromArray(array $r, ?int $now = null): self
    {
        $now ??= \time();

        // ⚠️ **존재 검사는 타입 검사가 아니다.** `toStr` 가 스칼라를 강제변환해 `12345` 가
        // `"12345"` 라는 **쓸 수 없는 토큰**으로 통과했고, 소비자는 그것을 Bearer 로 실어
        // 보내 매번 401 을 받았다(조용한 반복 실패). `expires_in` 의 문자열 허용은
        // **의도된 것**이라 그대로 둔다 — 좁히는 것은 `access_token` 하나다.
        $accessToken = $r['access_token'] ?? null;
        if (!\is_string($accessToken) || '' === $accessToken) {
            throw new KeycloakAuthError('token response has no usable access_token');
        }

        $expiresIn = isset($r['expires_in']) ? self::toInt($r['expires_in']) : 0;

        return new self(
            accessToken: $accessToken,
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

    /**
     * ⚠️ 덤프 계열(`var_dump`·`print_r`·`debug_zval_dump`)은 `__toString` 과 `jsonSerialize` 를
     * **우회해 프로퍼티를 직접 읽는다**. 이 훅이 그 경로를 덮는다(PHP 8.3.32 실측 — `print_r` 도
     * 이 훅을 존중한다. ⚠️ **`var_export` 는 존중하지 않고 private 까지 원문으로 찍는다** —
     * 그것은 훅으로 막을 수 없는 경계다).
     *
     * 마스킹 정의를 두 곳에 두지 않는다 — 이미 마스킹된 `jsonSerialize()` 에 위임한다.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }
}
