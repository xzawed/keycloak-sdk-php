<?php

declare(strict_types=1);

namespace Xzawed\Keycloak\Jwks;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Xzawed\Keycloak\Exception\KeycloakTransportError;
use Xzawed\Keycloak\Exception\SanitizedCause;
use Xzawed\Keycloak\KeycloakConfig;
use Xzawed\Keycloak\Exception\TokenValidationError;

/**
 * DoS-safe JWKS 스토어: kid로 캐시, 미해결 kid에만 재조회, 재조회는 rate-limit.
 * 위조 서명(잘못된 kid) 스팸이 IdP를 때리는 미인증 DoS 증폭을 차단한다.
 */
final class JwksStore
{
    /**
     * JWKS 응답 본문의 바이트 상한. 51200 은 Nimbus `RemoteJWKSet.DEFAULT_HTTP_SIZE_LIMIT` 이고
     * go(`jwksMaxBytes`)·rust(`JWKS_MAX_BYTES`)·ruby·java·kotlin 이 같은 수를 쓴다.
     *
     * ⚠️ 예전에는 상한이 없었고, 게다가 **상태 검사보다 먼저** `(string) $response->getBody()` 로
     * 본문을 통째로 슬러프했다 — 손상된 IdP 의 500 거대 본문도 그대로 메모리에 올렸다.
     */
    public const JWKS_MAX_BYTES = 51200;

    /**
     * 스트림을 읽는 청크 크기. ⚠️ `Content-Length` 로만 판정하면 그 헤더가 없거나 거짓인 응답을
     * 놓친다 — 청크를 받으며 누적치가 상한을 넘는 순간 읽기를 끊는다.
     */
    public const JWKS_READ_CHUNK_BYTES = 8192;

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
            throw new KeycloakTransportError('JWKS fetch failed', previous: SanitizedCause::of($e));
        } catch (\Throwable $e) {
            // PSR-18 밖 예외도 `validate()` 를 미분류로 빠져나가지 않는다(Grok 레그 실측: 원본이 그대로 샜다).
            throw new KeycloakTransportError('JWKS fetch failed unexpectedly', previous: SanitizedCause::of($e));
        }
        // ⚠️ 상한은 **상태와 무관하게** 건다. 200 만 겨누면 오류 응답의 거대 본문이 그대로
        // 들어온다 — 그게 수정 전의 순서였다(상태 검사 전에 전체 슬러프 + `json_decode`).
        $body = $response->getBody();
        $buf = '';
        while (!$body->eof()) {
            $buf .= $body->read(self::JWKS_READ_CHUNK_BYTES);
            if (strlen($buf) > self::JWKS_MAX_BYTES) {
                throw new KeycloakTransportError(
                    sprintf('JWKS response exceeds %d bytes', self::JWKS_MAX_BYTES),
                );
            }
        }
        $json = json_decode($buf, true);
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
        // ⚠️ **올릴 것이 0 개면 쓰지 않는다**(go/jwt.go 와 동형 — 그쪽 #380 픽스의 나머지 절반).
        // `[]` 는 배열이라 위 shape 검사를 그대로 통과하고, kid 없는 항목만 담긴 **비어 있지 않은**
        // 배열도 여기서 빈 맵이 된다 — 둘 다 같은 실패다. 200 + 빈 키셋을 주는 것은 키를 전부
        // 회수한 IdP 가 아니라 프록시·WAF·반쯤 뜬 realm 이고, 좋은 캐시를 덮으면 방금 검증되던
        // 토큰이 거부되며 refetch 게이트가 복구까지 막는다. 덮기 전에 전송 오류로 끊는다
        // (그러지 않으면 「unknown kid」로 **오분류**되어 전송 문제가 토큰 탓이 된다 — 실측).
        // ⚠️ 여기서 멈춘다 — `kty`·`n`·`e` 검증으로 번지면 JWKS 스키마 검사가 된다.
        if ($map === []) {
            throw new KeycloakTransportError('JWKS response contains no keys');
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
