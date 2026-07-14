<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Jwks;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Xzawed\Keycloak\Exception\KeycloakTransportError;
use Xzawed\Keycloak\Exception\TokenValidationError;

/**
 * DoS-safe JWKS 스토어: kid로 캐시, 미해결 kid에만 재조회, 재조회는 rate-limit.
 * 위조 서명(잘못된 kid) 스팸이 IdP를 때리는 미인증 DoS 증폭을 차단한다.
 */
final class JwksStore
{
    /** @var array<string,array<string,mixed>> kid → JWK */
    private array $keys = [];
    private bool $loadedOnce = false;
    private ?int $lastRefetchAt = null;

    public function __construct(
        private readonly string $jwksUri,
        private readonly ClientInterface $http,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly int $minRefetchIntervalSeconds = 60,
    ) {}

    /**
     * @return array<string,mixed> 선택된 JWK
     *
     * @throws TokenValidationError  kid 미해결(재조회 후에도)
     * @throws KeycloakTransportError 네트워크 오류
     */
    public function getKeyByKid(string $kid): array
    {
        if (!$this->loadedOnce) {
            $this->fetch();   // 초기 로드는 rate-limit 소모하지 않음(첫 키회전 허용)
        }
        if (isset($this->keys[$kid])) {
            return $this->keys[$kid];
        }
        // 미해결 kid → 조건부 재조회(rate-limit)
        $now = \time();
        if ($this->lastRefetchAt !== null && ($now - $this->lastRefetchAt) < $this->minRefetchIntervalSeconds) {
            throw new TokenValidationError(sprintf('unknown kid "%s" (refetch rate-limited)', $kid));
        }
        // 재조회 *결정 시점*에 stamp — fetch가 실패(IdP 장애)해도 게이트가 소모되도록 한다.
        // stamp-after-fetch면 실패한 fetch가 lastRefetchAt을 갱신하지 못해, 위조 kid 스팸이
        // IdP를 무제한 때린다(미인증 DoS 증폭). Rust/Go/Python/Ruby 동형.
        $this->lastRefetchAt = $now;
        $this->fetch();
        if (isset($this->keys[$kid])) {
            return $this->keys[$kid];
        }
        throw new TokenValidationError(sprintf('unknown kid "%s"', $kid));
    }

    private function fetch(): void
    {
        $request = $this->requestFactory->createRequest('GET', $this->jwksUri);
        try {
            $response = $this->http->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new KeycloakTransportError('JWKS fetch failed', previous: $e);
        }
        $json = json_decode((string) $response->getBody(), true);
        if ($response->getStatusCode() !== 200 || !is_array($json) || !isset($json['keys']) || !is_array($json['keys'])) {
            throw new KeycloakTransportError('JWKS response invalid');
        }
        $map = [];
        foreach ($json['keys'] as $key) {
            if (!is_array($key)) {
                continue;
            }
            $jwk = self::stringKeyed($key);
            $kid = $jwk['kid'] ?? null;
            if (is_string($kid)) {
                $map[$kid] = $jwk;
            }
        }
        $this->keys = $map;
        $this->loadedOnce = true;
    }

    /**
     * json_decode(..., true)의 배열은 키 타입이 array-key(int|string)로만 추론된다.
     * 신뢰된 JWKS 키 객체는 항상 문자열 키이므로 정수 키(있다면)를 걸러 string-keyed로 좁힌다.
     *
     * @param array<array-key, mixed> $a
     * @return array<string, mixed>
     */
    private static function stringKeyed(array $a): array
    {
        $out = [];
        foreach ($a as $k => $v) {
            if (is_string($k)) {
                $out[$k] = $v;
            }
        }
        return $out;
    }
}
