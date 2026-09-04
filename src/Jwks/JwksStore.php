<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Jwks;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Xzawed\Keycloak\Exception\KeycloakTransportError;
use Xzawed\Keycloak\KeycloakConfig;
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

    /**
     * 실패한 fetch 의 백오프 — 위 30초 게이트와 **다른 축**이다(콜드 캐시 + IdP 장애).
     * 상태 기계와 그 근거는 {@see FailureBackoff} 가 소유한다.
     */
    private readonly FailureBackoff $backoff;

    public function __construct(
        private readonly string $jwksUri,
        private readonly ClientInterface $http,
        private readonly RequestFactoryInterface $requestFactory,
        // ⚠️ 기본값을 여기 숫자로 적지 말 것 — `KeycloakConfig`가 유일한 정의 자리다. 이 클래스는
        // `final class` + public 생성자라 소비자가 파사드를 거치지 않고 직접 생성할 수 있고,
        // 예전에는 그 경로가 문서의 30이 아니라 60을 받았다(2026-08-13 Task D1).
        private readonly int $minRefetchIntervalSeconds = KeycloakConfig::DEFAULT_JWKS_MIN_REFETCH_SECONDS,
    ) {
        $this->backoff = new FailureBackoff();
    }

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

    /**
     * ⚠️ 백오프 검사는 fetch **직전**이자 30초 게이트 **이후**다. 콜드 캐시에서는 `getKeyByKid`
     * 의 두 분기가 통째로 건너뛰어지므로, 이 게이트가 없으면 매 조회가 IdP 로 나간다(원래 결함).
     */
    private function fetch(): void
    {
        $remaining = $this->backoff->remaining();
        if ($remaining > 0) {
            throw new KeycloakTransportError(sprintf(
                'JWKS fetch backing off after %d consecutive failures (retry in %.2fs)',
                $this->backoff->failures(),
                $remaining,
            ));
        }
        try {
            $this->fetchOnce();
        } catch (\Throwable $e) {
            $this->backoff->recordFailure();

            throw $e;
        }
        $this->backoff->recordSuccess();
    }

    private function fetchOnce(): void
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
