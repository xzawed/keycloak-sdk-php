<?php

declare(strict_types=1);

namespace Xzawed\Keycloak;

use Xzawed\Keycloak\Exception\KeycloakConfigError;

/**
 * 불변 설정. 시크릿은 PHP 관용상 string이며 마스킹으로 심층방어(char[] 소거는 PHP에서 불가 — 과대광고 금지).
 */
final readonly class KeycloakConfig
{
    /**
     * JWKS 최소 재조회 간격 기본값의 **유일한 정의 자리**(초). DoS 증폭 상한이고 아홉 언어가
     * 같은 값으로 정렬돼 있다 — `scripts/test/test-security-defaults.sh`가 아홉 언어 코드와
     * 소비자 문서를 함께 대조한다.
     *
     * ⚠️ 이 숫자를 다른 곳에 다시 적지 말 것. 예전에는 여기 30, `Jwks\JwksStore` 생성자에 60으로
     * **두 번** 적혀 있었고, `JwksStore`는 `final class`에 public 생성자라 소비자가 직접 생성하면
     * (파사드를 거치지 않으면) 문서가 말하는 30이 아니라 60을 받았다.
     */
    public const DEFAULT_JWKS_MIN_REFETCH_SECONDS = 30;

    public string $serverUrl;

    /** @var list<string> */
    public array $scopes;

    /** @var list<string> JWT 서명 검증 허용 알고리즘 핀(기본 RS256, ES256/PS256 realm용 설정 가능). */
    public array $signatureAlgorithms;

    /**
     * @param array<int, string> $scopes
     * @param array<int, string> $signatureAlgorithms
     */
    public function __construct(
        string $serverUrl,
        public string $realm,
        public string $clientId,
        #[\SensitiveParameter] public ?string $clientSecret = null,
        array $scopes = ['openid'],
        public float $connectTimeout = 5.0,
        public float $readTimeout = 10.0,
        public int $clockSkew = 30,
        public ?string $redirectUri = null,
        array $signatureAlgorithms = ['RS256'],
        /** 미해결 kid로 인한 JWKS 재조회의 최소 간격(초) — DoS 증폭 상한. 기본값은 위 상수. */
        public int $jwksMinRefetchSeconds = self::DEFAULT_JWKS_MIN_REFETCH_SECONDS,
        /**
         * 토큰 aud에 들어있어야 할 값(기본 null = clientId). 기본 realm은 client-credentials 토큰의
         * aud에 clientId를 넣지 않으므로, realm이 실제로 발급하는 리소스/오디언스를 지정하거나
         * Keycloak 클라이언트에 audience 매퍼를 추가한다.
         */
        public ?string $expectedAudience = null,
    ) {
        if (trim($serverUrl) === '') {
            throw new KeycloakConfigError('serverUrl is required');
        }
        if (trim($this->realm) === '') {
            throw new KeycloakConfigError('realm is required');
        }
        if (trim($this->clientId) === '') {
            throw new KeycloakConfigError('clientId is required');
        }
        if ($signatureAlgorithms === []) {
            // 빈 집합은 alg 핀을 무력화한다(핀 없이는 alg 혼동에 노출) — 거부한다.
            throw new KeycloakConfigError('signatureAlgorithms must be non-empty');
        }
        if ($this->jwksMinRefetchSeconds < 0) {
            throw new KeycloakConfigError('jwksMinRefetchSeconds must be >= 0');
        }
        // 후행 슬래시 제거(엔드포인트 조립 규약)
        $this->serverUrl = rtrim($serverUrl, '/');
        $this->scopes = array_values($scopes);
        $this->signatureAlgorithms = array_values($signatureAlgorithms);
    }

    public function __toString(): string
    {
        return sprintf(
            'KeycloakConfig(serverUrl=%s, realm=%s, clientId=%s, clientSecret=%s)',
            $this->serverUrl,
            $this->realm,
            $this->clientId,
            Masking::mask($this->clientSecret),
        );
    }
}
